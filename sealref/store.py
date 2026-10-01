"""Index (~/.vaultlet/index.json) + pluggable secret backend (see backends.py).

Storage names stay "vaultlet" (dir ~/.vaultlet, Keychain service "vaultlet:<group>")
so existing installs need no migration."""
import json
import os
import re
import subprocess  # noqa: F401  (tests patch store.subprocess.run; same module backends uses)
from datetime import datetime, timezone

from .backends import get_backend

VAULT_DIR = os.path.expanduser("~/.vaultlet")
INDEX_PATH = os.path.join(VAULT_DIR, "index.json")

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
    tmp_path = INDEX_PATH + ".tmp"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
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
    # Default output stays vaultlet:// so existing tools keep working;
    # SEALREF_REF_SCHEME=sealref (or --ref-scheme sealref) switches it.
    scheme = os.environ.get("SEALREF_REF_SCHEME", "vaultlet")
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


def set_secret(group: str, key: str, value: str) -> str:
    _validate_group(group)
    _validate_key(key)
    if not value or any(c in value for c in "\n\r\0"):
        raise ValueError("value must be non-empty and contain no newline or NUL")
    get_backend().set(group, key, value)
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
    get_backend().delete(group, key)
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


def _resolve(group: str, key: str) -> str:
    return get_backend().get(group, key)


def _resolve_group(group: str) -> dict:
    return {key: _resolve(group, key) for key in list_keys(group)}
