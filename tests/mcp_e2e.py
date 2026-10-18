"""MCP end to end through a real stdio client (mcp 1.x, Python >= 3.10).

Spawns the INSTALLED sealref MCP server (`<this python> -m sealref.mcp_server`
from the current environment; run it from a venv with sealref installed, not
from the checkout), then: initialize, tools/list, request_secret (a fake
browser posts a dummy value through the UI API), has_secret, list_*, and
`sealref run` consumption. Asserts no value, prefix or value parameter ever
crosses MCP and that the server's stdout carried only JSON-RPC.

macOS: refuses to run unless SEALREF_KEYCHAIN points at a throwaway keychain
file, so the login keychain is never touched. Dummy values only."""
import asyncio
import json
import os
import subprocess
import sys
import tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

GROUP, KEY = "mcpe2e", "MCP_DUMMY_KEY"
REF = f"sealref://{GROUP}/{KEY}"
VALUE = "Zq7Xk9-dummy-mcp-e2e-0123456789"
EXPECTED_TOOLS = {"list_groups", "list_keys", "has_secret", "request_secret", "usage_hint"}
VALUE_PARAM_NAMES = {"value", "secret", "password", "token", "data"}


def check(cond, msg):
    print(("ok: " if cond else "FAIL: ") + msg, flush=True)
    if not cond:
        sys.exit(1)


# Stand-in browser: gets the token URL, POSTs the dummy value through the UI API.
BROWSER_PY = r'''
import json, os, sys, time, urllib.parse, urllib.request
url = sys.argv[1]
open(os.environ["E2E_URL_FILE"], "w").write(url)
u = urllib.parse.urlparse(url)
q = urllib.parse.parse_qs(u.query)
token = u.fragment[len("t="):]
body = json.dumps({"group": q["group"][0], "key": q["key"][0], "value": os.environ["E2E_VALUE"]}).encode()
for _ in range(50):
    try:
        req = urllib.request.Request(f"http://{u.netloc}/api/keys", data=body, method="POST",
                                     headers={"X-Vaultlet": token, "Content-Type": "application/json"})
        urllib.request.urlopen(req).read()
        break
    except OSError:
        time.sleep(0.2)
'''

# Runs the server and copies its stdout to a file, so we can prove it was only JSON-RPC.
TEE_PY = r'''
import subprocess, sys, threading
log = open(sys.argv[1], "wb")
p = subprocess.Popen([sys.executable, "-m", "sealref.mcp_server"], stdout=subprocess.PIPE)
def pump():
    for line in p.stdout:
        log.write(line); log.flush()
        sys.stdout.buffer.write(line); sys.stdout.buffer.flush()
threading.Thread(target=pump, daemon=True).start()
sys.exit(p.wait())
'''


def texts(result):
    return [c.text for c in result.content if getattr(c, "text", None) is not None]


async def main():
    if sys.platform == "darwin" and not os.environ.get("SEALREF_KEYCHAIN"):
        sys.exit("refusing to run on macOS without SEALREF_KEYCHAIN (a throwaway keychain file)")
    tmp = tempfile.mkdtemp()
    fwd = lambda p: p.replace("\\", "/")  # webbrowser's BROWSER parsing is POSIX shlex
    for name, src in (("browser.py", BROWSER_PY), ("tee.py", TEE_PY)):
        with open(os.path.join(tmp, name), "w") as f:
            f.write(src)
    stdout_log = os.path.join(tmp, "server-stdout.log")
    home = os.path.join(tmp, "home")
    os.mkdir(home)
    env = {**os.environ, "HOME": home, "USERPROFILE": home, 
           "E2E_VALUE": VALUE, "E2E_URL_FILE": os.path.join(tmp, "url"),
           "BROWSER": f"{fwd(sys.executable)} {fwd(os.path.join(tmp, 'browser.py'))} %s"}
    where = subprocess.run([sys.executable, "-c", "import sealref; print(sealref.__file__)"],
                           capture_output=True, text=True, cwd=tmp, env=env).stdout.strip()
    print("sealref imported from:", where)
    check("site-packages" in where or "dist-packages" in where, "server runs from the INSTALLED package, not a checkout")

    params = StdioServerParameters(command=sys.executable, args=[os.path.join(tmp, "tee.py"), stdout_log],
                                   env=env, cwd=tmp)
    seen = []  # everything the server returned, for leak checks
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as s:
                init = await s.initialize()
                check(init.serverInfo.name == "sealref", f"initialize ok, server {init.serverInfo.name!r}")
                tools = (await s.list_tools()).tools
                names = {t.name for t in tools}
                check(names == EXPECTED_TOOLS, f"tools/list = {sorted(names)}")
                for t in tools:
                    props = set((t.inputSchema or {}).get("properties", {}))
                    check(not (props & VALUE_PARAM_NAMES) and props <= {"group", "key", "reason"},
                          f"{t.name}: params {sorted(props)} (no value parameter)")
                seen.append(json.dumps([t.model_dump(mode="json") for t in tools]))

                r = await s.call_tool("has_secret", {"group": GROUP, "key": KEY})
                seen.append(r.model_dump_json())
                check("false" in "".join(texts(r)).lower(), "has_secret false before the request")

                r = await asyncio.wait_for(
                    s.call_tool("request_secret", {"group": GROUP, "key": KEY, "reason": "mcp e2e"}), 120)
                seen.append(r.model_dump_json())
                check(not r.isError and "".join(texts(r)) == REF, f"request_secret returned only the ref: {texts(r)}")
                check(os.path.exists(env["E2E_URL_FILE"]) and "#t=" in open(env["E2E_URL_FILE"]).read(),
                      "fake browser received the token URL and posted the value")

                for name, args in (("has_secret", {"group": GROUP, "key": KEY}), ("list_groups", {}),
                                   ("list_keys", {"group": GROUP}), ("usage_hint", {})):
                    r = await s.call_tool(name, args)
                    seen.append(r.model_dump_json())
                    check(not r.isError, f"{name} ok")
                    if name == "has_secret":
                        check("true" in "".join(texts(r)).lower(), "has_secret true after the request")
                    if name == "list_keys":
                        check(REF in "".join(texts(r)), "list_keys shows the ref")
    finally:
        pass

    blob = "\n".join(seen)
    check(VALUE not in blob and VALUE[:4] not in blob, "no value or prefix in any MCP response")
    check(str(len(VALUE)) not in blob.replace(REF, ""), f"no length ({len(VALUE)}) in any MCP response")

    with open(stdout_log, "rb") as f:
        lines = [l for l in f.read().splitlines() if l.strip()]
    ok = bool(lines)
    for l in lines:
        try:
            ok = ok and json.loads(l).get("jsonrpc") == "2.0"
        except ValueError:
            ok = False
    check(ok, f"server stdout carried only JSON-RPC ({len(lines)} messages)")
    check(VALUE.encode() not in open(stdout_log, "rb").read(), "value absent from server stdout")

    # Consume the ref the way an agent would, then clean up.
    r = subprocess.run([sys.executable, "-m", "sealref", "run", "--ref", REF, "--", sys.executable, "-c",
                        f"import os; print(os.environ[{KEY!r}])"], capture_output=True, text=True, env=env, cwd=tmp)
    check(r.returncode == 0 and r.stdout.strip() == f"«redacted:{GROUP}/{KEY}»".strip()
          and VALUE not in r.stdout + r.stderr, "sealref run --ref: value redacted in output")
    r = subprocess.run([sys.executable, "-c", f"from sealref import store; store.delete({GROUP!r}, {KEY!r}); "
                        f"store.delete_group({GROUP!r}); print(store.has({GROUP!r}, {KEY!r}))"],
                       capture_output=True, text=True, env=env, cwd=tmp)
    check(r.stdout.strip() == "False", "deleted")
    print("MCP E2E OK")


asyncio.run(main())
