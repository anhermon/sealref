"""Secret storage backends: get/set/delete of one value by (group, key).

Group/key listing is NOT a backend concern: names live in ~/.vaultlet/index.json
(same layout on every platform), values live in the backend. Service name stays
"vaultlet:<group>", account "<key>" on every backend, so existing items resolve.

macos   -> Keychain via /usr/bin/security (default on darwin, stdlib only)
keyring -> the optional `keyring` lib, restricted to OS keystores: Linux Secret
           Service (GNOME Keyring/KWallet), Windows Credential Manager
           (default elsewhere)
Override with SEALREF_BACKEND=macos|keyring.

ponytail: no encrypted-file fallback. Safe file crypto needs an AEAD + KDF
(not in the stdlib) plus a passphrase prompt that `run` can't do unattended;
a weak/plaintext fallback is worse than a clear error."""
import os
import subprocess
import sys

# Absolute path: a `security` earlier on PATH (a repo's bin/, a direnv
# .envrc) would otherwise receive every value set() writes.
SECURITY = "/usr/bin/security"

# `security -i` reads stdin in fixed-size chunks and runs each chunk as its own
# command line once a line passes ~4 KB (measured), so a long value would no
# longer be one quoted argument. Keep the whole line well under that.
MAX_COMMAND_BYTES = 3000

RESOLVE_TIMEOUT = 120  # long enough to answer a Keychain approval dialog
CONTROL_ERR = "must not contain control characters (newline, tab, NUL, ...)"


def _service(group: str) -> str:
    return f"vaultlet:{group}"


def _has_control(s: str) -> bool:
    return any(ord(c) < 0x20 or ord(c) == 0x7F for c in s)


class MacKeychain:
    name = "macos"

    def __init__(self):
        # SEALREF_KEYCHAIN=<file> targets that keychain file instead of the
        # default search list (used by tests; also lets you keep sealref items
        # in a keychain of their own).
        self.keychain = os.environ.get("SEALREF_KEYCHAIN") or None
        if self.keychain and _has_control(self.keychain):
            raise ValueError(f"SEALREF_KEYCHAIN {CONTROL_ERR}")

    def _kc_argv(self):
        return [self.keychain] if self.keychain else []

    def _run(self, args, **kw):
        return subprocess.run([SECURITY, *args, *self._kc_argv()], capture_output=True, **kw)

    def _exists(self, group, key):
        # Attributes only (no -w/-g): no decrypt, so no approval dialog.
        r = self._run(["find-generic-password", "-a", key, "-s", _service(group)])
        return r.returncode == 0

    def get(self, group, key):
        try:
            r = self._run(["find-generic-password", "-a", key, "-s", _service(group), "-w"],
                          text=True, timeout=RESOLVE_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"keychain read of {group}/{key} timed out; "
                               "approve the macOS Keychain dialog to use this secret") from None
        if r.returncode != 0:
            # stderr from find-generic-password names the item, never the value.
            raise RuntimeError(f"keychain read of {group}/{key} failed or was denied "
                               f"(security exit {r.returncode})")
        return r.stdout.rstrip("\n")

    def set(self, group, key, value, require_approval=False):
        # The value goes to `security -i` on stdin, not argv, so it never
        # appears in `ps`. security's command parser takes double-quoted
        # strings with backslash escapes.
        esc = lambda x: x.replace("\\", "\\\\").replace('"', '\\"')
        item = f'-a "{esc(key)}" -s "{esc(_service(group))}"'
        kc = f' "{esc(self.keychain)}"' if self.keychain else ""
        # -T "" = no app is trusted to read the item without asking, so every
        # read (sealref's own and anyone else's `security find-generic-password`)
        # raises a macOS approval dialog.
        acl = ' -T ""' if require_approval else ""
        add = f'add-generic-password {item} -w "{esc(value)}"{acl}{kc}'
        # Replace = delete then add (`add -U` raises a dialog on an item whose
        # ACL trusts no app, and cannot switch the ACL). Only delete when there
        # is something to delete, so a first-time save that fails loses nothing.
        if len(add.encode()) > MAX_COMMAND_BYTES:  # the add line is the longest
            raise ValueError("value too long (sealref stores values up to about 2900 bytes)")
        existed = self._exists(group, key)
        lines = ([f"delete-generic-password {item}{kc}"] if existed else []) + [add]
        r = subprocess.run([SECURITY, "-i"], input="\n".join(lines) + "\n",
                           capture_output=True, text=True)
        # A missing item makes the delete line report "returned -25300"; only
        # the add line decides success.
        if r.returncode != 0 or "add-generic-password: returned" in r.stdout + r.stderr:
            msg = "keychain write failed (security exit %d)" % r.returncode
            if existed:
                msg += ("; the previous value of %s/%s was kept" % (group, key)
                        if self._exists(group, key)
                        else "; the previous value of %s/%s was deleted and could not be "
                             "replaced, set it again" % (group, key))
            err = RuntimeError(msg)
            err.old_value_lost = existed and "was deleted" in msg
            raise err

    def delete(self, group, key):
        r = self._run(["delete-generic-password", "-a", key, "-s", _service(group)])
        # 44 = errSecItemNotFound: already gone. Anything else means the value
        # may still be in the Keychain, so the caller keeps its index entry.
        if r.returncode not in (0, 44):
            raise RuntimeError(f"keychain delete of {group}/{key} failed (security exit {r.returncode})")


# Backends the `keyring` library may resolve to that are real OS keystores.
# Matched on the implementing module; WinVaultKeyring also by class name
# because keyring.backends.Windows has an insecure RegistryKeyring too.
_SECURE_MODULES = (
    "keyring.backends.SecretService",
    "keyring.backends.libsecret",
    "keyring.backends.kwallet",
    "keyring.backends.macOS",
)
WIN_BLOB_MAX = 2560  # CRED_MAX_CREDENTIAL_BLOB_SIZE, bytes of UTF-16


def _is_secure(b) -> bool:
    mod, cls = type(b).__module__, type(b).__name__
    if mod == "keyring.backends.Windows":
        return cls == "WinVaultKeyring"
    return mod in _SECURE_MODULES


def _leaves(b):
    """The concrete backends behind b (a ChainerBackend wraps several)."""
    if type(b).__name__ == "ChainerBackend":
        return list(b.backends)
    return [b]


class Keyring:
    name = "keyring"

    def __init__(self, kr=None):
        if kr is None:
            try:
                import keyring as kr
                import keyring.errors  # noqa: F401
            except ImportError:
                raise RuntimeError(
                    "this platform needs the optional keyring library: pip install 'sealref[keyring]'")
        self.kr = kr
        # First allow-listed backend in priority order, used directly (never
        # via the chainer, which would write to / read from whatever else is
        # installed, e.g. keyrings.alt plaintext). No allow-listed one: refuse.
        leaves = _leaves(kr.get_keyring())
        self.backend = next((b for b in leaves if _is_secure(b)), None)
        if self.backend is None:
            found = ", ".join(f"{type(b).__module__}.{type(b).__name__}" for b in leaves) or "none"
            raise RuntimeError(
                "no secure OS keyring available (found: %s). sealref never falls back to a "
                "plaintext or file keyring. Linux: install and unlock gnome-keyring (or KWallet) "
                "and run inside a desktop/D-Bus session; Windows: Credential Manager." % found)

    def _check_size(self, value):
        if type(self.backend).__name__ == "WinVaultKeyring" or sys.platform == "win32":
            n = len(value.encode("utf-16-le"))
            if n > WIN_BLOB_MAX:
                raise ValueError(
                    "value too long for Windows Credential Manager (%d of %d bytes as UTF-16, "
                    "about 1280 characters)" % (n, WIN_BLOB_MAX))

    def get(self, group, key):
        try:
            v = self.backend.get_password(_service(group), key)
        except Exception as e:
            raise RuntimeError(f"keyring read of {group}/{key} failed ({type(e).__name__})") from None
        if v is None:
            raise RuntimeError(f"keyring read of {group}/{key} failed: not found")
        return v

    def set(self, group, key, value, require_approval=False):
        # set_password replaces in place on every allow-listed backend (Secret
        # Service replace=True, CredWrite, KWallet writePassword), so there is
        # no delete-then-add window here. Per-item approval is a macOS Keychain
        # feature; the keyring backends cannot offer it.
        if require_approval:
            raise ValueError("Keychain approval is macOS-only; this backend cannot require it")
        self._check_size(value)
        try:
            self.backend.set_password(_service(group), key, value)
        except Exception as e:  # keyring raises backend-specific types; never echo the value
            raise RuntimeError(f"keyring write failed ({type(e).__name__})") from None

    def delete(self, group, key):
        try:
            self.backend.delete_password(_service(group), key)
        except self.kr.errors.PasswordDeleteError:
            pass  # already absent
        except Exception as e:
            raise RuntimeError(f"keyring delete of {group}/{key} failed ({type(e).__name__})") from None


def get_backend():
    choice = os.environ.get("SEALREF_BACKEND") or ("macos" if sys.platform == "darwin" else "keyring")
    if choice == "macos":
        return MacKeychain()
    if choice == "keyring":
        return Keyring()
    raise ValueError(f"SEALREF_BACKEND must be macos or keyring, got {choice!r}")
