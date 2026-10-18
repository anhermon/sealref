#!/bin/sh
# Reproducible sealref demo. Throwaway group + FAKE key; cleaned up on exit.
#   sh demo/demo.sh            (macOS: uses the login Keychain; Linux/Windows: needs sealref[keyring])
set -u
cd "$(dirname "$0")/.." || exit 1
SR="./bin/sealref --ref-scheme sealref"
G=${DEMO_GROUP:-demo}
FAKE='sk-demo-FAKE-9f3a1c7e5b2d4806a1f0'

if $SR keys "$G" 2>/dev/null | grep -q .; then
  echo "group '$G' already exists; set DEMO_GROUP=something-else to avoid touching it" >&2; exit 1
fi
cleanup() { python3 -c "import sys; sys.path.insert(0,'.'); from sealref import store; store.delete_group('$G')" ; }
trap cleanup EXIT INT TERM

h() { printf '\n\033[1;36m== %s\033[0m\n' "$1"; }
run() { printf '\033[33m$ %s\033[0m\n' "$*"; }

h "1. Human stores the secret ONCE (hidden prompt; never typed into chat)"
run "sealref set $G API_KEY      # prompt hidden; demo pipes the fake value"
printf '%s\n' "$FAKE" | $SR set "$G" API_KEY

h "2. The agent only ever sees the ref"
run "sealref keys $G"
$SR keys "$G"

h "3+4. 'sealref run' injects it into the command's env; output is scrubbed"
run "sealref run --ref sealref://$G/API_KEY -- sh -c 'echo \"Authorization: Bearer \$API_KEY\"; env | grep API_KEY'"
$SR run --ref "sealref://$G/API_KEY" -- sh -c 'echo "Authorization: Bearer $API_KEY"; env | grep API_KEY'
run "# the command really had the value (length only):"
$SR run --ref "sealref://$G/API_KEY" -- sh -c 'echo "len=${#API_KEY}"'
run "# the base64 form is scrubbed too (URL-encoded as well):"
$SR run --ref "sealref://$G/API_KEY" -- sh -c 'printf "%s" "$API_KEY" | base64'

h "5. What lands in the transcript"
cat <<TXT
  PASTE IN CHAT                              (all of this is in the transcript)
    user : here is my key: $FAKE
    agent: curl -H "Authorization: Bearer $FAKE" ...
    tool : {"auth":"$FAKE"}
    + shell history, logs, context window re-sent every turn, provider logs

  SEALREF                                    (the value appears nowhere)
    user : (typed into a hidden prompt, not chat)
    agent: sealref run --ref sealref://$G/API_KEY -- curl ...
    tool : {"auth":"«redacted:$G/API_KEY»"}
    value lives only in the OS keystore
TXT

h "6. Agent usage (MCP, Claude Code)"
cat <<'TXT'
  claude mcp add sealref --scope user -- uv run --directory /path/to/sealref \
      --with "mcp==1.29.0" python -m sealref.mcp_server
  agent calls: has_secret("stripe","API_KEY") -> true
               request_secret("stripe","API_KEY","charge test") -> "sealref://stripe/API_KEY"
  agent runs : sealref run --ref sealref://stripe/API_KEY -- ./charge.sh
TXT

h "7. Honest limit: scrubbing is exact-match, not magic"
run "sealref run ... -- sh -c 'echo \$API_KEY | rev'"
$SR run --ref "sealref://$G/API_KEY" -- sh -c 'echo $API_KEY | rev'
echo "  ^ a transformed value gets through. sealref stops accidents, not a hostile agent."

h "Cleanup"
cleanup; trap - EXIT
$SR keys "$G" | grep -c . | sed 's/^/remaining demo keys: /'
