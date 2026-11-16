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

try:
    from keyring.errors import PasswordDeleteError
except ImportError:  # keyring is optional; stand-in so fakes and the except clause still work
    class PasswordDeleteError(Exception):
        pass


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
# PYTHON_KEYRING_BACKEND or keyringrc.cfg; storing a secret there would break the
# no-plaintext invariant, so anything outside this allow-list is refused, never used.
# Matched as an exact module name or a submodule ("<module>."), not a bare prefix.
SECURE_KEYRING_MODULES = (
    "keyring.backends.SecretService",
    "keyring.backends.libsecret",
    "keyring.backends.kwallet",
    "keyring.backends.macOS",
    "keyring.backends.Windows",
)
CHAINER_MODULE = "keyring.backends.chainer"

NO_KEYRING_MSG = (
    "no usable OS keyring ({detail}). {prog} stores secrets only in the OS keystore and "
    "never falls back to a plaintext file. On Linux install and unlock a Secret Service "
    "provider (GNOME Keyring or KWallet; a desktop login session provides one). Headless "
    "hosts, CI, containers and WSL without a keyring daemon are not supported: use the "
    "environment's own secret store there."
)


class KeystoreUnavailable(RuntimeError):
    """No OS keystore (or only an insecure one) is available."""


def _backend_name(b):
    return "%s.%s" % (type(b).__module__, type(b).__name__)


def _is_secure_backend(b):
    module = type(b).__module__
    return any(module == m or module.startswith(m + ".") for m in SECURE_KEYRING_MODULES)


def _checked_keyring(kr):
    """Return the highest-priority allow-listed backend object, or raise.

    keyring hands back a ChainerBackend whenever several backends are viable
    (e.g. Secret Service next to keyrings.alt). A chain as a whole is never
    accepted, because it can fall through to a plaintext member; instead its
    members are searched in priority order and the first OS keystore is used
    directly. A backend the user forced (PYTHON_KEYRING_BACKEND, keyringrc.cfg)
    arrives as itself, not as a chain, so a forced non-allow-listed backend is
    refused even when a secure one exists."""
    prog = os.environ.get("SEALREF_PROG", "sealref")
    try:
        active = kr.get_keyring()
        chained = type(active).__module__ == CHAINER_MODULE
        candidates = list(active.backends) if chained else [active]
    except Exception as e:
        raise KeystoreUnavailable(NO_KEYRING_MSG.format(detail=type(e).__name__, prog=prog)) from None
    for b in candidates:
        if _is_secure_backend(b):
            return b
    detail = "keyring backend %s is not an OS keystore" % _backend_name(active)
    if chained:
        detail = "none of the chained keyring backends is an OS keystore: %s" % (
            ", ".join(_backend_name(b) for b in candidates) or "none")
    raise KeystoreUnavailable(NO_KEYRING_MSG.format(detail=detail, prog=prog))


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
        # The vetted backend object itself, never the keyring module (whose
        # active backend could be a chain with an insecure member).
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
        except PasswordDeleteError:
            pass  # entry not found: already absent, same as the macOS path
        except Exception as e:  # locked keyring, D-Bus error: do not report a delete that did not happen
            raise RuntimeError(f"keyring delete failed ({type(e).__name__})") from None


def get_backend():
    choice = os.environ.get("SEALREF_BACKEND") or ("macos" if sys.platform == "darwin" else "keyring")
    if choice == "macos":
        return MacKeychain()
    if choice == "keyring":
        return Keyring()
    raise ValueError(f"SEALREF_BACKEND must be macos or keyring, got {choice!r}")
