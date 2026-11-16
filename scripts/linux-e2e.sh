#!/bin/bash
# Runs INSIDE the Linux container: scripts/linux-docker.sh <desktop|headless|keyrings-alt>.
# desktop      = gnome-keyring (Secret Service) under dbus-run-session
# headless     = no D-Bus session, no keyring daemon
# keyrings-alt = the desktop flow with keyrings.alt installed next to Secret
#                Service, so keyring hands back a chain that includes a plaintext
#                backend; the value must land in Secret Service and in no file
# All secret values are fake.
set -u
MODE=${1:?desktop|headless|keyrings-alt}
cp -r /src /work && cd /work
export PYTHONPATH=/work HOME=/root
FAKE="fake-e2e-value-0000-NOT-A-REAL-KEY"
fail() { echo "E2E FAIL: $*"; exit 1; }

desktop() {
  # Unlock a throwaway keyring with a fake password so no prompt is needed.
  eval "$(printf '%s' 'fake-keyring-password' | gnome-keyring-daemon --unlock --components=secrets)"
  eval "$(gnome-keyring-daemon --start --components=secrets)"
  export GNOME_KEYRING_CONTROL SSH_AUTH_SOCK
  export SEALREF_LIVE_KEYRING=1
  if [ "$MODE" = keyrings-alt ]; then
    echo "--- precondition: keyring returns a chain that contains a plaintext backend"
    python - <<'PY' || fail "keyrings.alt chain precondition"
import keyring
from keyring.backends import chainer
active = keyring.get_keyring()
members = ["%s.%s" % (type(b).__module__, type(b).__name__) for b in active.backends]
print("active:", type(active).__module__, "members:", members)
assert isinstance(active, chainer.ChainerBackend), "expected a chain"
assert any(m.startswith("keyrings.alt.") for m in members), "keyrings.alt not in the chain"
assert any(m.startswith("keyring.backends.SecretService") for m in members), "no Secret Service in the chain"
PY
  fi
  echo "--- unit tests (+ live keyring round trip)"
  python -m unittest -v test_sealref test_crossplatform 2>&1 | grep -E "skipped|Live|^Ran|^OK|FAIL"
  echo "--- store via CLI (piped stdin)"
  printf '%s\n' "$FAKE" | python -m sealref set e2e API_KEY || fail set
  echo "--- stored in Secret Service?"
  secret-tool lookup service vaultlet:e2e username API_KEY | grep -q "$FAKE" && echo "yes (secret-tool sees it)" || fail "not in keyring"
  echo "--- index.json holds no value"
  grep -rq "$FAKE" /root/.vaultlet && fail "plaintext on disk" || echo "no plaintext under ~/.vaultlet"
  echo "--- no file anywhere under HOME holds the value"
  grep -rIl "$FAKE" "$HOME" 2>/dev/null && fail "value found in a file under HOME" || echo "no file under $HOME holds it"
  if [ "$MODE" = keyrings-alt ]; then
    [ -e "$HOME/.local/share/python_keyring" ] && fail "keyrings.alt wrote its file store" || echo "no keyrings.alt file store created"
    echo "--- forced plaintext backend is refused (error, not silently overridden)"
    printf '%s\n' "$FAKE" | PYTHON_KEYRING_BACKEND=keyrings.alt.file.PlaintextKeyring \
      python -m sealref set e2e FORCED_KEY > out.txt 2> err.txt; rc=$?
    echo "exit code: $rc"; cat err.txt
    [ "$rc" -ne 0 ] || fail "forced plaintext backend was accepted"
    grep -q "not an OS keystore" err.txt || fail "unexpected refusal message"
    grep -rIl "$FAKE" "$HOME" 2>/dev/null | grep -q . && fail "forced backend wrote the value to a file"
    echo "forced plaintext refused, nothing written"
  fi
  echo "--- run: child env gets the value, output scrubbed"
  OUT=$(python -m sealref run --ref sealref://e2e/API_KEY -- python -c 'import os,sys;v=os.environ["API_KEY"];print("len",len(v));print(v);print(v,file=sys.stderr)' 2>&1)
  echo "$OUT"
  echo "$OUT" | grep -q "$FAKE" && fail "value leaked in output"
  echo "$OUT" | grep -q "len ${#FAKE}" || fail "child did not receive value"
  echo "$OUT" | grep -q "redacted:e2e/API_KEY" || fail "no redaction marker"
  echo "--- MCP stdio: initialize + has_secret + list_keys"
  python - <<'PY' || fail mcp
import json, subprocess, sys, threading
p = subprocess.Popen([sys.executable, "-m", "vaultlet.mcp_server"], stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
threading.Timer(60, p.kill).start()
msgs = [{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}},
        {"jsonrpc":"2.0","method":"notifications/initialized"},
        {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"has_secret","arguments":{"group":"e2e","key":"API_KEY"}}},
        {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_keys","arguments":{"group":"e2e"}}}]
for m in msgs: p.stdin.write(json.dumps(m)+"\n")
p.stdin.flush()
seen = {}
while 3 not in seen:
    line = p.stdout.readline(); assert line, "server closed"
    seen[json.loads(line).get("id")] = line
p.kill()
blob = "".join(seen.values())
assert "serverInfo" in seen[1], seen[1]
assert "fake-e2e-value" not in blob, "value in MCP output"
print("initialize ok:", json.loads(seen[1])["result"]["serverInfo"])
print("has_secret ->", json.loads(seen[2])["result"]["structuredContent"])
print("list_keys  ->", json.loads(seen[3])["result"]["content"][0]["text"])
PY
  python -m sealref run --ref sealref://e2e/API_KEY -- true; python - <<'PY'
from sealref import store; store.delete_group("e2e")
PY
  echo "E2E $MODE PASS"
}

headless() {
  unset DBUS_SESSION_BUS_ADDRESS
  export SEALREF_EXPECT_HEADLESS=1
  echo "--- unit tests (+ headless expectation)"
  python -m unittest -v test_sealref test_crossplatform 2>&1 | grep -E "skipped|Live|^Ran|^OK|FAIL"
  echo "--- sealref set with no keyring daemon"
  printf '%s\n' "$FAKE" | python -m sealref set e2e API_KEY > out.txt 2> err.txt; rc=$?
  echo "exit code: $rc"; echo "stderr:"; cat err.txt; echo "stdout: [$(cat out.txt)]"
  [ "$rc" -ne 0 ] || fail "set succeeded without a keyring"
  grep -q Traceback err.txt && fail "traceback shown"
  grep -q "$FAKE" err.txt out.txt && fail "value echoed"
  [ -e /root/.vaultlet ] && grep -rq "$FAKE" /root/.vaultlet && fail "plaintext on disk"
  find / -xdev -type f -newer /work/pyproject.toml -not -path '/proc/*' -not -path '/work/*' -not -path '/sys/*' \
     -exec grep -l "$FAKE" {} + 2>/dev/null && fail "value found on disk" || echo "value found nowhere on the filesystem"
  echo "--- run with no keyring"
  python -m sealref run --ref sealref://e2e/API_KEY -- true; echo "exit code: $?"
  echo "E2E headless PASS"
}

case "$MODE" in
  desktop|keyrings-alt) desktop ;;
  headless) headless ;;
  *) fail "unknown mode $MODE" ;;
esac
