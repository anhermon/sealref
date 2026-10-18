#!/bin/bash
# Installs the checkout into a FRESH venv and drives the INSTALLED commands
# (the Windows .exe wrappers, `sealref`/`vaultlet` on PATH) plus the MCP server
# through a real stdio client. Dummy values only.
# usage: tests/installed_e2e.sh '.[keyring]'     (macOS: '.')
# macOS uses a throwaway keychain FILE (never on the search list); Linux needs
# an unlocked Secret Service (run under dbus-run-session).
set -eu
SPEC=${1:-.[keyring]}
SRC=$(pwd)
WORK=$(mktemp -d)
cleanup() { [ -n "${SEALREF_KEYCHAIN:-}" ] && /usr/bin/security delete-keychain "$SEALREF_KEYCHAIN" >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

python -m venv "$WORK/venv"
BIN="$WORK/venv/bin"; [ -d "$WORK/venv/Scripts" ] && BIN="$WORK/venv/Scripts"
"$BIN/python" -m pip install -q "$SPEC"
export PATH="$BIN:$PATH"
case $(uname -s) in
  Darwin) export SEALREF_KEYCHAIN="$WORK/t.keychain-db"; /usr/bin/security create-keychain -p dummy "$SEALREF_KEYCHAIN" ;;
esac
case $(uname -s) in MINGW*|MSYS*|CYGWIN*) ;; *) export HOME="$WORK/home"; mkdir "$HOME" ;; esac
cd "$WORK"   # away from the checkout: nothing may import from it

for c in sealref vaultlet; do
  p=$(command -v $c); echo "$c -> $p"
  case $p in "$BIN"/*) ;; *) fail "$c is not the installed one: $p" ;; esac
  $c --help | head -1
done

V="dummy-installed-0123456789"
for c in sealref vaultlet; do
  printf %s "$V" | $c set inst "K_$c" || fail "$c set"
  $c keys inst | grep -q "K_$c" || fail "$c keys"
  out=$($c run --ref "sealref://inst/K_$c" -- python -c "import os; print(os.environ['K_$c'])" 2>&1)
  echo "$c run -> $out"
  if echo "$out" | grep -q "$V"; then fail "$c run leaked the value"; fi
  echo "$out" | grep -q "redacted" || fail "$c run output not redacted: $out"
  python -c "from sealref import store; store.delete('inst', 'K_$c')"
  if $c keys inst | grep -q "K_$c"; then fail "$c key still listed after delete"; fi
done

if python -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
  python -m pip install -q 'mcp==1.29.0'
  python "$SRC/tests/mcp_e2e.py"
else
  echo "python < 3.10: mcp 1.x does not support it, MCP e2e skipped"
fi
echo "INSTALLED E2E OK"
