"""End-to-end against the real Secret Service. Needs a D-Bus session with an
unlocked gnome-keyring (see run.sh). Dummy values only."""
import json
import re
import subprocess
import sys
import urllib.request

import keyring

GROUP, KEY, VALUE = "e2e", "E2E_DUMMY_KEY", "dummy-e2e-0123456789"
REF = f"sealref://{GROUP}/{KEY}"


def sealref(*args, **kw):
    return subprocess.run(["sealref", *args], capture_output=True, text=True, **kw)


def check(cond, msg):
    if not cond:
        print("FAIL:", msg, file=sys.stderr)
        sys.exit(1)
    print("ok:", msg)


def has_secret():
    r = subprocess.run([sys.executable, "-c", f"from sealref import store; print(store.has({GROUP!r}, {KEY!r}))"],
                       capture_output=True, text=True)
    return r.stdout.strip() == "True"


kr = keyring.get_keyring()
check("SecretService" in type(kr).__module__ or "ChainerBackend" in type(kr).__name__, f"real backend: {type(kr).__module__}.{type(kr).__name__}")

ui = subprocess.Popen(["sealref", "ui", "--port", "0", "--no-browser"], stderr=subprocess.PIPE, text=True)
url = ui.stderr.readline()
m = re.search(r"http://127\.0\.0\.1:(\d+)/#t=(\S+)", url)
check(m, "ui started and printed a tokenised URL")
port, token = m.group(1), m.group(2)


def api(method, path, body=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"X-Vaultlet": token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


page = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read().decode()
check("const APPROVAL = false;" in page, "page hides the macOS-only approval checkbox")
check(api("POST", "/api/groups", {"group": GROUP}) == 200, "create group via API")
check(api("POST", "/api/keys", {"group": GROUP, "key": KEY, "value": VALUE}) == 200, "POST dummy secret via API with token")
check(api("POST", "/api/keys", {"group": GROUP, "key": KEY, "value": VALUE, "require_approval": True}) == 400,
      "Keychain approval is refused on this backend (macOS-only)")
check(keyring.get_password(f"vaultlet:{GROUP}", KEY) == VALUE, "value is in the real Secret Service under vaultlet:<group>/<key>")

keys = sealref("keys", GROUP).stdout
check(REF in keys, f"ref printed: {REF}")
check(VALUE not in keys, "no value in `keys` output")
check(has_secret(), "has_secret true")

r = sealref("run", "--ref", REF, "--", "python", "-c", f"import os; print(os.environ[{KEY!r}])")
check(r.returncode == 0 and r.stdout.strip() == f"«redacted:{GROUP}/{KEY}»" and VALUE not in r.stdout + r.stderr,
      f"run output redacted: {r.stdout.strip()!r}")
r = sealref("run", "--ref", REF, "--", "python", "-c", f"import os; print(len(os.environ[{KEY!r}]))")
check(r.stdout.strip() == str(len(VALUE)), "child really received the value (length matches)")

check(api("POST", "/api/keys", {"group": GROUP, "key": KEY, "value": "dummy-replaced-value"}) == 200, "overwrite in place")
check(keyring.get_password(f"vaultlet:{GROUP}", KEY) == "dummy-replaced-value", "overwritten value stored")
check(api("POST", "/api/keys", {"group": GROUP, "key": KEY, "value": "x" * 70000}) == 400, "oversized request refused (64 KiB cap)")

check(api("DELETE", f"/api/keys/{GROUP}/{KEY}") == 200, "delete via API")
check(keyring.get_password(f"vaultlet:{GROUP}", KEY) is None, "gone from the real keyring")
check(not has_secret(), "has_secret false")
check(api("DELETE", f"/api/keys/{GROUP}/{KEY}") == 200, "deleting an absent key is not an error")

check(api("POST", "/api/quit") == 200, "quit")
check(ui.wait(timeout=10) == 0, "ui exited")
print("E2E OK")
