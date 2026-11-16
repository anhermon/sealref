#!/usr/bin/env python3
"""Cross-platform and security-invariant tests. No real keystore is touched
except in the opt-in live test (SEALREF_LIVE_KEYRING=1, used in the Linux
container runs). Secret values here are obviously fake."""
import contextlib
import importlib.metadata
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from sealref import backends, cli, store
from test_sealref import FakeKeyring

ROOT = os.path.dirname(os.path.abspath(__file__))
FAKE_VALUE = "fake-test-value-0000-NOT-A-REAL-KEY"
MCP_MIN_PYTHON = (3, 10)  # `mcp` 1.x requires 3.10+; this is what broke the server
MCP_TIMEOUT_S = 90
HAS_MCP = importlib.util.find_spec("mcp") is not None


def _floor(spec):
    m = re.search(r">=\s*(\d+)\.(\d+)", spec)
    return (int(m.group(1)), int(m.group(2)))


class PythonFloorTest(unittest.TestCase):
    def _declared(self):
        with open(os.path.join(ROOT, "pyproject.toml")) as f:
            return _floor(re.search(r'requires-python\s*=\s*"([^"]+)"', f.read()).group(1))

    def test_floor_not_below_mcp_floor(self):
        self.assertGreaterEqual(self._declared(), MCP_MIN_PYTHON)

    @unittest.skipUnless(HAS_MCP, "mcp not installed")
    def test_floor_not_below_installed_mcp_requirement(self):
        req = importlib.metadata.metadata("mcp")["Requires-Python"]
        self.assertGreaterEqual(self._declared(), _floor(req))


class _Isolated(unittest.TestCase):
    """Temp vault dir + the keyring backend over an in-memory fake."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.fake = FakeKeyring()
        for p in (mock.patch.multiple(store, VAULT_DIR=self.tmp,
                                      INDEX_PATH=os.path.join(self.tmp, "index.json")),
                  mock.patch.object(store, "get_backend",
                                    lambda: backends.Keyring(self.fake))):
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)


@unittest.skipUnless(HAS_MCP, "mcp not installed")
class McpSmokeTest(unittest.TestCase):
    def test_stdio_initialize_and_tool_call_without_value(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "t", "version": "0"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "has_secret", "arguments": {"group": "g", "key": "K"}}},
        ]
        env = dict(os.environ, HOME=tmp, USERPROFILE=tmp, PYTHONPATH=ROOT)
        p = subprocess.Popen([sys.executable, "-m", "vaultlet.mcp_server"], cwd=ROOT, env=env,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True)
        watchdog = threading.Timer(MCP_TIMEOUT_S, p.kill)
        watchdog.start()
        self.addCleanup(watchdog.cancel)
        out = {}
        try:
            for m in msgs:
                p.stdin.write(json.dumps(m) + "\n")
            p.stdin.flush()
            while 3 not in out:  # keep stdin open until the last reply: EOF would end the server early
                line = p.stdout.readline()
                self.assertTrue(line, "server closed stdout before answering")
                out[json.loads(line).get("id")] = json.loads(line)  # stdout must be pure JSON-RPC
        finally:
            p.kill()
            p.wait()
        self.assertIn("serverInfo", out[1]["result"])
        names = {t["name"] for t in out[2]["result"]["tools"]}
        self.assertEqual(names, {"list_groups", "list_keys", "has_secret", "request_secret", "usage_hint"})
        self.assertFalse(out[3]["result"].get("isError"))


class SecurityInvariantTest(_Isolated):
    def test_no_plaintext_on_disk(self):
        store.set_secret("g", "API_KEY", FAKE_VALUE)
        for dirpath, _, files in os.walk(self.tmp):
            for f in files:
                with open(os.path.join(dirpath, f), "rb") as fh:
                    self.assertNotIn(FAKE_VALUE.encode(), fh.read())
        self.assertEqual(os.listdir(self.tmp), ["index.json"])

    def test_scrub_applies_on_keyring_backend(self):
        store.set_secret("g", "API_KEY", FAKE_VALUE)
        buf, err = io.StringIO(), io.StringIO()
        code = "import os,sys;v=os.environ['API_KEY'];print(v);print(v,file=sys.stderr)"
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            rc = cli.main(["run", "--ref", "sealref://g/API_KEY", "--", sys.executable, "-c", code])
        self.assertEqual(rc, 0)
        self.assertNotIn(FAKE_VALUE, buf.getvalue() + err.getvalue())
        self.assertEqual(buf.getvalue().count("«redacted:g/API_KEY»"), 2)  # stdout + merged stderr

    def test_set_does_not_print_value(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch("sys.stdin", io.StringIO(FAKE_VALUE + "\n")):
            cli.main(["set", "g", "API_KEY"])
        self.assertNotIn(FAKE_VALUE, out.getvalue() + err.getvalue())

    @unittest.skipUnless(HAS_MCP, "mcp not installed")
    def test_mcp_tools_never_return_value(self):
        from sealref import mcp_server
        store.set_secret("g", "API_KEY", FAKE_VALUE)
        results = [mcp_server.list_groups(), mcp_server.list_keys("g"),
                   mcp_server.has_secret("g", "API_KEY"), mcp_server.usage_hint()]
        self.assertNotIn(FAKE_VALUE, json.dumps(results))

    def test_entry_page_binds_loopback_only(self):
        from sealref import ui
        server = ui._make_server(0)
        self.addCleanup(server.server_close)
        self.assertEqual(server.server_address[0], "127.0.0.1")


class HeadlessErrorTest(_Isolated):
    class _Fake(FakeKeyring):
        def __init__(self, active):
            super().__init__()
            self._active = active
        def get_keyring(self):
            return self._active

    def _backend_with(self, module_name, cls_name):
        cls = type(cls_name, (), {"__module__": module_name})
        return backends.Keyring(self._Fake(cls()))

    def test_real_wrapper_refuses_fail_backend(self):
        fail = type("Keyring", (), {"__module__": "keyring.backends.fail"})
        fake = self._Fake(fail())
        with self.assertRaisesRegex(RuntimeError, "no usable OS keyring"):
            backends._checked_keyring(fake)

    def test_real_wrapper_refuses_plaintext_backend(self):
        alt = type("PlaintextKeyring", (), {"__module__": "keyrings.alt.file"})
        with self.assertRaisesRegex(RuntimeError, "not an OS keystore"):
            backends._checked_keyring(self._Fake(alt()))

    def test_real_wrapper_accepts_secret_service(self):
        ss = type("Keyring", (), {"__module__": "keyring.backends.SecretService"})
        fake = self._Fake(ss())
        self.assertIs(backends._checked_keyring(fake), fake)

    def test_cli_error_is_one_line_no_traceback_and_no_index_entry(self):
        fail = type("Keyring", (), {"__module__": "keyring.backends.fail"})
        broken = backends.Keyring(self._Fake(fail()))
        broken._real = True
        err = io.StringIO()
        with mock.patch.object(store, "get_backend", lambda: broken), \
                mock.patch("sys.stdin", io.StringIO(FAKE_VALUE + "\n")), \
                contextlib.redirect_stderr(err):
            rc = cli.main(["set", "g", "API_KEY"])
        self.assertEqual(rc, cli.EXIT_STORE_ERROR)
        self.assertEqual(len(err.getvalue().strip().splitlines()), 1)
        self.assertNotIn("Traceback", err.getvalue())
        self.assertNotIn(FAKE_VALUE, err.getvalue())
        self.assertFalse(store.has("g", "API_KEY"))
        self.assertEqual(os.listdir(self.tmp), [])  # nothing written anywhere


@unittest.skipUnless(os.environ.get("SEALREF_LIVE_KEYRING") == "1",
                     "set SEALREF_LIVE_KEYRING=1 inside a session with a real keyring")
class LiveKeyringTest(unittest.TestCase):
    """Real OS keystore round trip (Linux Secret Service in the container run)."""

    def test_round_trip(self):
        be = backends.Keyring()
        be.set("sealref-live", "LIVE_KEY", FAKE_VALUE)
        try:
            self.assertEqual(be.get("sealref-live", "LIVE_KEY"), FAKE_VALUE)
        finally:
            be.delete("sealref-live", "LIVE_KEY")
        with self.assertRaises(KeyError):
            be.get("sealref-live", "LIVE_KEY")


@unittest.skipUnless(os.environ.get("SEALREF_EXPECT_HEADLESS") == "1",
                     "set SEALREF_EXPECT_HEADLESS=1 in a session with no keyring daemon")
class LiveHeadlessTest(unittest.TestCase):
    def test_fails_clearly(self):
        with self.assertRaisesRegex(RuntimeError, "no usable OS keyring|not an OS keystore"):
            backends.Keyring().set("g", "K", FAKE_VALUE)


if __name__ == "__main__":
    unittest.main()
