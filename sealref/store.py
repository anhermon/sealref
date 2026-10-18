"""Index (~/.vaultlet/index.json) + macOS Keychain storage.

Storage names stay "vaultlet" (dir ~/.vaultlet, Keychain service "vaultlet:<group>")
so existing installs need no migration."""
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone

VAULT_DIR = os.path.expanduser("~/.vaultlet")
INDEX_PATH = os.path.join(VAULT_DIR, "index.json")

# Absolute path: a `security` earlier on PATH (a repo's bin/, a direnv
# .envrc) would otherwise receive every value set_secret writes.
SECURITY = "/usr/bin/security"

GROUP_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _validate_group(group: str) -> None:
    if not GROUP_RE.match(group):
        raise ValueError(f"invalid group name: {group!r} (must match {GROUP_RE.pattern})")


def _validate_key(key: str) -> None:
    if not KEY_RE.match(key):
        raise ValueError(f"invalid key name: {key!r} (must match {KEY_RE.pattern}, valid as env var)")


def _load_index() -> dict:
    if not os.path.exists(INDEX_PATH):
        return {"groups": {}}
    with open(INDEX_PATH, "r") as f:
        return json.load(f)


def _save_index(index: dict) -> None:
    os.makedirs(VAULT_DIR, mode=0o700, exist_ok=True)
    os.chmod(VAULT_DIR, 0o700)  # also repairs dirs made 0755 by old versions
    # Unique, O_EXCL, 0600: no fixed name to pre-plant a symlink at, and two
    # writers (UI thread + MCP) never share a temp file.
    fd, tmp_path = tempfile.mkstemp(dir=VAULT_DIR, prefix=".index.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(index, f, indent=2)
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise
    os.replace(tmp_path, INDEX_PATH)


def list_groups() -> list:
    return sorted(_load_index()["groups"].keys())


def list_keys(group: str) -> list:
    return sorted(_load_index()["groups"].get(group, {}).get("keys", {}).keys())


def has(group: str, key: str) -> bool:
    return key in _load_index()["groups"].get(group, {}).get("keys", {})


def create_group(group: str) -> None:
    _validate_group(group)
    index = _load_index()
    index["groups"].setdefault(group, {"keys": {}})
    _save_index(index)


SCHEMES = ("sealref", "vaultlet")


def ref(group: str, key: str) -> str:
    # Output defaults to sealref://. SEALREF_REF_SCHEME=vaultlet (or
    # --ref-scheme vaultlet) prints the legacy scheme for tools that still
    # expect it. Input accepts both schemes regardless (see parse_ref).
    scheme = os.environ.get("SEALREF_REF_SCHEME", "sealref")
    if scheme not in SCHEMES:
        raise ValueError(f"SEALREF_REF_SCHEME must be one of {SCHEMES}, got {scheme!r}")
    return f"{scheme}://{group}/{key}"


def parse_ref(s: str) -> tuple:
    m = re.match(r"^(?:sealref|vaultlet)://([^/]+)/([^/]+)$", s)
    if not m:
        raise ValueError(f"not a sealref/vaultlet ref: {s!r}")
    group, key = m.group(1), m.group(2)
    _validate_group(group)
    _validate_key(key)
    return group, key


# `security -i` reads stdin in fixed-size chunks and runs each chunk as its own
# command line once a line passes ~4 KB (measured), so a long value would no
# longer be one quoted argument. Keep the whole line well under that.
MAX_COMMAND_BYTES = 3000


def set_secret(group: str, key: str, value: str, require_approval: bool = False) -> str:
    _validate_group(group)
    _validate_key(key)
    if not isinstance(value, str) or not value:
        raise ValueError("value must be a non-empty string")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise ValueError("value must not contain control characters (newline, tab, NUL, ...)")
    # The value goes to `security -i` on stdin, not argv, so it never appears
    # in `ps` output. security's command parser takes double-quoted strings
    # with backslash escapes.
    esc = lambda x: x.replace("\\", "\\\\").replace('"', '\\"')
    # -T "" = no app is trusted to read the item without asking, so every
    # read (sealref's own and anyone else's `security find-generic-password`)
    # raises a macOS approval dialog.
    acl = ' -T ""' if require_approval else ""
    item = f'-a "{esc(key)}" -s "vaultlet:{esc(group)}"'
    # Delete then add, not `add -U`: updating an item whose ACL trusts no app
    # raises a Keychain dialog, and -U cannot switch an item's ACL either way.
    cmd = (f'delete-generic-password {item}\n'
           f'add-generic-password {item} -w "{esc(value)}"{acl}\n')
    if max(len(line.encode()) for line in cmd.splitlines()) > MAX_COMMAND_BYTES:
        raise ValueError("value too long (sealref stores values up to about 2900 bytes)")
    r = subprocess.run([SECURITY, "-i"], input=cmd, capture_output=True, text=True)
    # A missing item makes the delete line report "returned -25300"; only the
    # add line decides success.
    if r.returncode != 0 or "add-generic-password: returned" in r.stdout + r.stderr:
        raise RuntimeError("keychain write failed (security exit %d)" % r.returncode)
    index = _load_index()
    index["groups"].setdefault(group, {"keys": {}})
    index["groups"][group]["keys"][key] = {
        "created": datetime.now(timezone.utc).isoformat()
    }
    _save_index(index)
    return ref(group, key)


def delete(group: str, key: str) -> None:
    _validate_group(group)
    _validate_key(key)
    r = subprocess.run(
        [SECURITY, "delete-generic-password", "-a", key, "-s", f"vaultlet:{group}"],
        capture_output=True,
    )
    # 44 = errSecItemNotFound: already gone. Anything else means the value may
    # still be in the Keychain, so keep its index entry visible.
    if r.returncode not in (0, 44):
        raise RuntimeError(f"keychain delete of {group}/{key} failed (security exit {r.returncode})")
    index = _load_index()
    if group in index["groups"]:
        index["groups"][group]["keys"].pop(key, None)
        _save_index(index)


def delete_group(group: str) -> None:
    _validate_group(group)
    for key in list_keys(group):
        delete(group, key)
    index = _load_index()
    index["groups"].pop(group, None)
    _save_index(index)


RESOLVE_TIMEOUT = 120  # long enough to answer a Keychain approval dialog


def _resolve(group: str, key: str) -> str:
    try:
        result = subprocess.run(
            [SECURITY, "find-generic-password", "-a", key, "-s", f"vaultlet:{group}", "-w"],
            capture_output=True,
            text=True,
            timeout=RESOLVE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"keychain read of {group}/{key} timed out; "
                           "approve the macOS Keychain dialog to use this secret") from None
    if result.returncode != 0:
        # stderr from find-generic-password names the item, never the value.
        raise RuntimeError(f"keychain read of {group}/{key} failed or was denied "
                           f"(security exit {result.returncode})")
    return result.stdout.rstrip("\n")


def _resolve_group(group: str) -> dict:
    return {key: _resolve(group, key) for key in list_keys(group)}
