#!/bin/sh
# Runs inside the container (see Dockerfile). Exits non-zero on any failure.
set -eu
export HOME=$(mktemp -d)
fail() { echo "FAIL: $*" >&2; exit 1; }

echo "== 1. unit suite (plain python, fakes only)"
python -m unittest test_sealref 2>&1 | tail -4

echo "== 2. refuse insecure keyrings (no D-Bus session: only fail/plaintext candidates)"
for venv in sec alt; do
  rc=0; out=$(echo dummy-value | /opt/venv-$venv/bin/sealref set refuse K 2>&1) || rc=$?
  [ "$rc" -ne 0 ] || fail "venv-$venv stored a secret without a secure keyring"
  echo "$out" | grep -q "no secure OS keyring available" || fail "venv-$venv: unexpected error: $out"
  echo "venv-$venv: refused -> $out" | cut -c1-200
done
[ ! -e "$HOME/.local/share/python_keyring" ] || fail "plaintext keyring file was created"
[ ! -e "$HOME/.vaultlet/index.json" ] || fail "index written although the write was refused"

echo "== 3. end-to-end on a real Secret Service (gnome-keyring under dbus-run-session)"
dbus-run-session -- sh -c '
  set -eu
  echo dummy | gnome-keyring-daemon --unlock --components=secrets >/dev/null
  export PATH=/opt/venv-sec/bin:$PATH
  python tests/linux/e2e.py
  echo "-- bin/ launcher (POSIX shim, python3 -I) still works"
  bin/sealref groups >/dev/null && bin/vaultlet --help | head -1
  echo "-- installed package in a fresh venv + MCP e2e (real Secret Service)"
  bash tests/installed_e2e.sh ".[keyring]"
  echo "-- keyrings.alt installed next to gnome-keyring: Secret Service is used, plaintext file never"
  PATH=/opt/venv-alt/bin:$PATH sh -c "echo dummy-alt-value | sealref set altcheck ALT_KEY && sealref run --ref sealref://altcheck/ALT_KEY -- python -c \"import os; print(os.environ[\\\"ALT_KEY\\\"])\""
  [ ! -e "$HOME/.local/share/python_keyring" ] || { echo "FAIL: plaintext keyring file created" >&2; exit 1; }
  echo "-- plaintext backend forced via PYTHON_KEYRING_BACKEND, even with a live Secret Service: refused"
  if echo dummy | PYTHON_KEYRING_BACKEND=keyrings.alt.file.PlaintextKeyring PATH=/opt/venv-alt/bin:$PATH sealref set forced K 2>/tmp/err; then echo "FAIL: stored" >&2; exit 1; fi
  grep -q "no secure OS keyring" /tmp/err && echo refused
  [ ! -e "$HOME/.local/share/python_keyring" ] || { echo "FAIL: plaintext keyring file created" >&2; exit 1; }
'
echo "ALL LINUX CHECKS OK"
