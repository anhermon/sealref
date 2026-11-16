"""Secret storage backends: get/set/delete of one value by (group, key).

Group/key listing is NOT a backend concern: names live in ~/.vaultlet/index.json
(same layout on every platform), values live in the backend. Service name stays
"vaultlet:<group>", account "<key>" on every backend, so existing items resolve.

macos   -> Keychain via `security` (default on darwin, stdlib only)
keyring -> the optional `keyring` lib: Linux Secret Service (GNOME Keyring /
           KWallet), Windows Credential Manager (default elsewhere)
Override with SEALREF_BACKEND=macos|keyring.

ponytail: no encrypted-file fallback. Safe file crypto needs an AEAD + KDF
(not in the stdlib) plus a passphrase prompt that `run` can't do unattended;
a weak/plaintext fallback is worse than a clear error."""
import os
import subprocess
import sys


def _service(group: str) -> str:
    return f"vaultlet:{group}"


class MacKeychain:
    name = "macos"

    def get(self, group, key):
        r = subprocess.run(
            ["security", "find-generic-password", "-a", key, "-s", _service(group), "-w"],
            check=True, capture_output=True, text=True)
        return r.stdout.rstrip("\n")

    def set(self, group, key, value):
        # Value goes to `security -i` on stdin, not argv, so it never shows in `ps`.
        # security's parser takes double-quoted strings with backslash escapes.
        esc = lambda x: x.replace("\\", "\\\\").replace('"', '\\"')
        cmd = f'add-generic-password -a "{esc(key)}" -s "{esc(_service(group))}" -w "{esc(value)}" -U\n'
        r = subprocess.run(["security", "-i"], input=cmd, capture_output=True, text=True)
        if r.returncode != 0 or "returned -" in r.stdout + r.stderr:
            raise RuntimeError("keychain write failed (security exit %d)" % r.returncode)

    def delete(self, group, key):
        subprocess.run(
            ["security", "delete-generic-password", "-a", key, "-s", _service(group)],
            capture_output=True)


# Only OS-backed stores are accepted. keyring also ships (via the separate
# keyrings.alt package) plaintext/file backends and can be pointed at them with
# PYTHON_KEYRING_BACKEND; storing a secret there would break the no-plaintext
# invariant, so anything outside this allow-list is refused, never used.
SECURE_KEYRING_MODULES = (
    "keyring.backends.SecretService",
    "keyring.backends.libsecret",
    "keyring.backends.kwallet",
    "keyring.backends.macOS",
    "keyring.backends.Windows",
)

NO_KEYRING_MSG = (
    "no usable OS keyring ({detail}). {prog} stores secrets only in the OS keystore and "
    "never falls back to a plaintext file. On Linux install and unlock a Secret Service "
    "provider (GNOME Keyring or KWallet; a desktop login session provides one). Headless "
    "hosts, CI, containers and WSL without a keyring daemon are not supported: use the "
    "environment's own secret store there."
)


class KeystoreUnavailable(RuntimeError):
    """No OS keystore (or only an insecure one) is available."""


def _checked_keyring(kr):
    """Return kr only if its active backend is an OS keystore; else RuntimeError."""
    prog = os.environ.get("SEALREF_PROG", "sealref")
    try:
        active = kr.get_keyring()
    except Exception as e:
        raise KeystoreUnavailable(NO_KEYRING_MSG.format(detail=type(e).__name__, prog=prog)) from None
    module = type(active).__module__
    if not module.startswith(SECURE_KEYRING_MODULES):
        detail = "keyring backend %s.%s is not an OS keystore" % (module, type(active).__name__)
        raise KeystoreUnavailable(NO_KEYRING_MSG.format(detail=detail, prog=prog))
    return kr


class Keyring:
    name = "keyring"

    def __init__(self, kr=None):
        injected = kr
        if kr is None:
            try:
                import keyring as kr
            except ImportError:
                raise RuntimeError(
                    "this platform needs the optional keyring library: pip install 'sealref[keyring]'")
        self.kr = kr
        self._real = injected is None  # injected fakes (tests) have no backend class to vet

    def _kr(self):
        return _checked_keyring(self.kr) if self._real else self.kr

    def get(self, group, key):
        try:
            v = self._kr().get_password(_service(group), key)
        except KeystoreUnavailable:
            raise
        except Exception as e:
            raise RuntimeError(f"keyring read failed ({type(e).__name__})") from None
        if v is None:
            raise KeyError(f"{group}/{key} not found in keyring")
        return v

    def set(self, group, key, value):
        try:
            self._kr().set_password(_service(group), key, value)
        except KeystoreUnavailable:
            raise
        except Exception as e:  # keyring raises backend-specific types; don't echo the value
            raise RuntimeError(f"keyring write failed ({type(e).__name__})") from None

    def delete(self, group, key):
        try:
            self._kr().delete_password(_service(group), key)
        except KeystoreUnavailable:
            raise  # no usable keyring is an error, "already absent" is not
        except Exception:
            pass  # already absent, same as the macOS path


def get_backend():
    choice = os.environ.get("SEALREF_BACKEND") or ("macos" if sys.platform == "darwin" else "keyring")
    if choice == "macos":
        return MacKeychain()
    if choice == "keyring":
        return Keyring()
    raise ValueError(f"SEALREF_BACKEND must be macos or keyring, got {choice!r}")
