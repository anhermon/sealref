#!/usr/bin/env python3
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import subprocess
import sys

from sealref import store
from sealref.cli import _build_needles, _redact_line


class RefTest(unittest.TestCase):
    def test_round_trip(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("SEALREF_REF_SCHEME", None)
            r = store.ref("myapp", "API_KEY")
        self.assertEqual(r, "sealref://myapp/API_KEY")
        self.assertEqual(store.parse_ref(r), ("myapp", "API_KEY"))

    def test_parse_rejects_garbage(self):
        for bad in ["not-a-ref", "vaultlet://onlygroup", "http://g/k", "vaultlet://g/k/extra", ""]:
            with self.assertRaises(ValueError):
                store.parse_ref(bad)


class SchemeTest(unittest.TestCase):
    def test_accepts_both_schemes(self):
        for scheme in ("sealref", "vaultlet"):
            self.assertEqual(store.parse_ref(f"{scheme}://g/K"), ("g", "K"))
        with self.assertRaises(ValueError):
            store.parse_ref("other://g/K")

    def test_output_default_sealref_and_env_switch(self):
        with mock.patch.dict(os.environ, clear=False):
            os.environ.pop("SEALREF_REF_SCHEME", None)
            self.assertEqual(store.ref("g", "K"), "sealref://g/K")
            os.environ["SEALREF_REF_SCHEME"] = "vaultlet"
            self.assertEqual(store.ref("g", "K"), "vaultlet://g/K")
            os.environ["SEALREF_REF_SCHEME"] = "sealref"
            self.assertEqual(store.ref("g", "K"), "sealref://g/K")
            os.environ["SEALREF_REF_SCHEME"] = "bogus"
            with self.assertRaises(ValueError):
                store.ref("g", "K")

    def test_keychain_service_name_unchanged(self):
        with mock.patch("sealref.store.subprocess.run") as run:
            run.return_value.stdout = "v\n"
            store._resolve("g", "K")
            self.assertIn("vaultlet:g", run.call_args[0][0])


class CommandNameTest(unittest.TestCase):
    """Both entry points work; the ref scheme in `run --ref` works either way."""

    ROOT = os.path.dirname(os.path.abspath(__file__))

    def _run(self, *args, env=None):
        e = {**os.environ, "PYTHONPATH": self.ROOT, **(env or {})}
        e.pop("SEALREF_PROG", None)
        e.pop("SEALREF_REF_SCHEME", None)
        e.update(env or {})
        return subprocess.run([sys.executable, *args], capture_output=True, text=True, env=e)

    def test_both_module_names_print_usage(self):
        for mod, prog in (("sealref", "sealref"), ("vaultlet", "vaultlet")):
            r = self._run("-m", mod, "--help")
            self.assertEqual(r.returncode, 0)
            self.assertIn(f"usage: {prog} ", r.stdout)

    def test_bin_scripts(self):
        for name in ("sealref", "vaultlet"):
            r = subprocess.run([os.path.join(self.ROOT, "bin", name), "--help"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)
            self.assertIn(f"usage: {name} ", r.stdout)

    def test_ref_scheme_flag(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("SEALREF_REF_SCHEME", None)
            from sealref import cli
            with mock.patch.object(cli, "COMMANDS", {"x": lambda rest: print(store.ref("g", "K")) or 0}):
                import io, contextlib
                for argv, want in ((["x"], "sealref://g/K"),
                                   (["--ref-scheme", "vaultlet", "x"], "vaultlet://g/K"),
                                   (["--ref-scheme=sealref", "x"], "sealref://g/K")):
                    os.environ.pop("SEALREF_REF_SCHEME", None)
                    buf = io.StringIO()
                    with contextlib.redirect_stdout(buf):
                        cli.main(argv)
                    self.assertEqual(buf.getvalue().strip(), want, argv)

    def test_bogus_ref_scheme_flag_names_the_flag(self):
        import contextlib
        import io
        from sealref import cli
        with mock.patch.dict(os.environ):
            os.environ.pop("SEALREF_REF_SCHEME", None)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = cli.main(["--ref-scheme", "bogus", "keys", "g"])
            self.assertEqual(rc, 2)
            self.assertIn("--ref-scheme must be one of sealref, vaultlet, got 'bogus'", err.getvalue())
            self.assertNotIn("SEALREF_REF_SCHEME", err.getvalue())
            self.assertNotIn("SEALREF_REF_SCHEME", os.environ)
            os.environ["SEALREF_REF_SCHEME"] = "bogus"  # env as the source: names the env var
            with self.assertRaisesRegex(ValueError, "SEALREF_REF_SCHEME"):
                store.ref("g", "K")

    def test_keys_default_scheme_both_commands(self):
        """`keys` prints sealref:// by default from both entry points, and
        vaultlet:// when SEALREF_REF_SCHEME=vaultlet."""
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, True)
        os.makedirs(os.path.join(home, ".vaultlet"))
        with open(os.path.join(home, ".vaultlet", "index.json"), "w") as f:
            json.dump({"groups": {"g": {"keys": {"API_KEY": {}}}}}, f)
        for mod in ("sealref", "vaultlet"):
            r = self._run("-m", mod, "keys", "g", env={"HOME": home})
            self.assertEqual(r.stdout, "API_KEY  sealref://g/API_KEY\n", mod)
            r = self._run("-m", mod, "keys", "g", env={"HOME": home, "SEALREF_REF_SCHEME": "vaultlet"})
            self.assertEqual(r.stdout, "API_KEY  vaultlet://g/API_KEY\n", mod)

    def test_mcp_alias_module_importable(self):
        try:
            import mcp  # noqa: F401
        except ImportError:
            self.skipTest("mcp not installed")
        r = self._run("-c", "import vaultlet.mcp_server as v, sealref.mcp_server as s; print(v.mcp.name, s.mcp is v.mcp)")
        self.assertEqual(r.stdout.split()[1], "True")


class NameValidationTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._patch = mock.patch.multiple(
            store, VAULT_DIR=self.tmpdir, INDEX_PATH=os.path.join(self.tmpdir, "index.json")
        )
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_create_group_rejects_bad_name(self):
        for bad in ["has space", "has/slash", "has:colon", ""]:
            with self.assertRaises(ValueError):
                store.create_group(bad)

    def test_create_group_accepts_good_name(self):
        store.create_group("my-group_1.0")
        self.assertIn("my-group_1.0", store.list_groups())

    @mock.patch("sealref.store.subprocess.run")
    def test_set_secret_rejects_bad_key(self, mock_run):
        for bad in ["1starts_with_digit", "has-dash", "has space", ""]:
            with self.assertRaises(ValueError):
                store.set_secret("g", bad, "value")
        mock_run.assert_not_called()

    @mock.patch("sealref.store.subprocess.run")
    def test_set_secret_accepts_good_key(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.dict(os.environ):
            os.environ.pop("SEALREF_REF_SCHEME", None)
            r = store.set_secret("g", "API_KEY", "secretvalue")
        self.assertEqual(r, "sealref://g/API_KEY")
        self.assertIn("API_KEY", store.list_keys("g"))
        argv = mock_run.call_args[0][0]
        self.assertEqual(argv, ["security", "-i"])
        self.assertNotIn("secretvalue", " ".join(argv))  # never in argv
        self.assertIn('-w "secretvalue"', mock_run.call_args[1]["input"])

    @mock.patch("sealref.store.subprocess.run")
    def test_set_secret_escapes_and_rejects(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        store.set_secret("g", "K", 'a"b\\c')
        self.assertIn('-w "a\\"b\\\\c"', mock_run.call_args[1]["input"])
        for bad in ["", "a\nb", "a\0b"]:
            with self.assertRaises(ValueError):
                store.set_secret("g", "K", bad)

    def test_delete_validates_names(self):
        with self.assertRaises(ValueError):
            store.delete("g", "../x")
        with self.assertRaises(ValueError):
            store.delete_group("a b")


class IndexAtomicWriteTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.index_path = os.path.join(self.tmpdir, "index.json")
        self._patch = mock.patch.multiple(store, VAULT_DIR=self.tmpdir, INDEX_PATH=self.index_path)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_save_writes_via_tmp_then_replace(self):
        store.create_group("g1")
        self.assertTrue(os.path.exists(self.index_path))
        self.assertFalse(os.path.exists(self.index_path + ".tmp"))
        with open(self.index_path) as f:
            data = json.load(f)
        self.assertIn("g1", data["groups"])

    def test_save_sets_mode_0600(self):
        store.create_group("g1")
        mode = os.stat(self.index_path).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_no_stray_tmp_file_left_behind(self):
        store.create_group("g1")
        store.create_group("g2")
        files = os.listdir(self.tmpdir)
        self.assertEqual(files, ["index.json"])


class RedactionFilterTest(unittest.TestCase):
    def test_value_replaced_in_output(self):
        needles = _build_needles([("myapp", "API_KEY", "sekrit123")])
        line = "connecting with token sekrit123 now\n"
        out = _redact_line(line, needles)
        self.assertNotIn("sekrit123", out)
        self.assertIn("«redacted:myapp/API_KEY»", out)

    def test_longest_first_ordering(self):
        # "sekrit" is a substring of "sekrit123" - if the short one were
        # replaced first it would mangle the long one's match.
        needles = _build_needles([
            ("g", "SHORT", "sekrit"),
            ("g", "LONG", "sekrit123"),
        ])
        line = "value=sekrit123 other=sekrit\n"
        out = _redact_line(line, needles)
        self.assertNotIn("sekrit123", out)
        self.assertNotIn("sekrit", out.replace("«redacted:g/SHORT»", "").replace("«redacted:g/LONG»", ""))
        self.assertIn("«redacted:g/LONG»", out)
        self.assertIn("«redacted:g/SHORT»", out)

    def test_short_values_skipped(self):
        needles = _build_needles([("g", "TINY", "ab")])
        self.assertEqual(needles, [])
        line = "ab is not redacted\n"
        self.assertEqual(_redact_line(line, needles), line)

    def test_base64_and_urlquoted_forms_redacted(self):
        import base64
        import urllib.parse

        value = "sekrit!value"
        needles = _build_needles([("g", "K", value)])
        b64 = base64.b64encode(value.encode()).decode()
        quoted = urllib.parse.quote(value, safe="")
        self.assertNotIn(_redact_line(f"auth: {b64}\n", needles), f"auth: {b64}\n")
        self.assertNotIn(value, _redact_line(f"auth: {b64}\n", needles).replace(b64, ""))
        out_b64 = _redact_line(f"Authorization: Basic {b64}\n", needles)
        self.assertNotIn(b64, out_b64)
        out_quoted = _redact_line(f"curl -u user:{quoted}\n", needles)
        self.assertNotIn(quoted, out_quoted)


class UiGuardTest(unittest.TestCase):
    def setUp(self):
        import threading
        from sealref import ui
        self.tmpdir = tempfile.mkdtemp()
        self._patch = mock.patch.multiple(
            store, VAULT_DIR=self.tmpdir, INDEX_PATH=os.path.join(self.tmpdir, "index.json")
        )
        self._patch.start()
        self.server = ui._make_server(0)
        self.port = self.server.server_port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self._patch.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _req(self, method, path, body=None, headers=None):
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        h = {"Host": f"127.0.0.1:{self.port}", "X-Vaultlet": "1"}
        h.update(headers or {})
        h = {k: v for k, v in h.items() if v is not None}
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        r.read()
        return r.status

    def test_same_origin_ok(self):
        self.assertEqual(self._req("GET", "/api/groups"), 200)
        self.assertEqual(self._req("POST", "/api/groups", '{"group":"ok"}'), 200)
        self.assertIn("ok", store.list_groups())

    def test_rebinding_host_rejected(self):
        self.assertEqual(self._req("GET", "/api/groups", headers={"Host": "evil.example"}), 403)

    def test_cross_origin_rejected(self):
        self.assertEqual(
            self._req("POST", "/api/groups", '{"group":"x"}', {"Origin": "http://evil.example"}), 403)
        self.assertNotIn("x", store.list_groups())

    def test_missing_custom_header_rejected(self):
        self.assertEqual(self._req("POST", "/api/groups", '{"group":"x"}', {"X-Vaultlet": None}), 403)
        self.assertEqual(self._req("POST", "/api/quit", "{}", {"X-Vaultlet": None}), 403)

    def test_request_banner_is_agent_neutral(self):
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request("GET", "/", headers={"Host": f"127.0.0.1:{self.port}"})
        page = c.getresponse().read().decode()
        self.assertIn("Your agent needs a secret: ", page)
        self.assertNotIn("Claude", page)

    def test_delete_bad_name_is_400(self):
        self.assertEqual(self._req("DELETE", "/api/groups/a%20b"), 400)


class RunAcceptsBothSchemesTest(unittest.TestCase):
    """`run --ref` resolves sealref:// and legacy vaultlet:// refs to the same
    Keychain item and injects the value."""

    def test_both_schemes_resolve(self):
        import contextlib
        import gc
        import io
        import warnings
        from sealref import cli
        for scheme in ("sealref", "vaultlet"):
            with mock.patch.object(store, "_resolve", return_value="sk-test-EXAMPLE") as res, \
                    warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", ResourceWarning)
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = cli.cmd_run(["--ref", f"{scheme}://stripe/API_KEY", "--",
                                      "sh", "-c", 'echo "len=${#API_KEY} val=$API_KEY"'])
                gc.collect()
            self.assertEqual([w for w in caught if issubclass(w.category, ResourceWarning)], [],
                             "child output pipe left open")
            self.assertEqual(rc, 0)
            res.assert_called_once_with("stripe", "API_KEY")
            self.assertEqual(buf.getvalue(), "len=15 val=«redacted:stripe/API_KEY»\n", scheme)


class McpStdoutCleanTest(unittest.TestCase):
    """request_secret runs ui.serve_until() inside the MCP server, where stdin
    and stdout are the JSON-RPC channel. Nothing on that path may write to
    stdout or read stdin, including the program that opens the browser."""

    ROOT = os.path.dirname(os.path.abspath(__file__))

    def test_serve_until_keeps_stdio_clean(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        marker = os.path.join(tmp, "browser-ran")
        # Stands in for the browser launcher: prints to stdout, the way some
        # launchers do, and tries to read stdin.
        browser = os.path.join(tmp, "noisy-browser")
        with open(browser, "w") as f:
            f.write("#!/bin/sh\n"
                    'echo "BROWSER-STDOUT $1"\n'
                    'if read -r line; then echo "BROWSER-READ-STDIN $line" >&2; fi\n'
                    f'touch "{marker}"\n')
        os.chmod(browser, 0o755)
        # HTTPServer.server_bind() calls socket.getfqdn(), whose reverse DNS
        # lookup can take ~30s on GitHub's macOS runners; it is irrelevant here.
        code = ("import socket, sys, time; socket.getfqdn = lambda name='': name; "
                "from sealref import ui; "
                f"ui._BROWSER_HELPER = [{browser!r}]; "
                "ok = ui.serve_until('g', 'API_KEY', 'test', timeout=1.5); "
                "time.sleep(0.5); "
                "raise SystemExit(0 if ok is False else 3)")
        env = {**os.environ, "PYTHONPATH": self.ROOT, "HOME": tmp}
        # Files, not pipes, so a lingering grandchild cannot stall the test.
        with open(os.path.join(tmp, "in"), "w+") as fin, \
                open(os.path.join(tmp, "out"), "w+") as fout, \
                open(os.path.join(tmp, "err"), "w+") as ferr:
            fin.write('{"jsonrpc": "2.0", "method": "ping"}\n')
            fin.seek(0)
            rc = subprocess.run([sys.executable, "-c", code], stdin=fin, stdout=fout,
                                stderr=ferr, env=env, timeout=60).returncode
            fout.seek(0)
            ferr.seek(0)
            out, err = fout.read(), ferr.read()
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "")
        self.assertIn("sealref: serving on http://127.0.0.1:", err)
        self.assertTrue(os.path.exists(marker), "browser command did not run")
        self.assertIn("BROWSER-STDOUT http://127.0.0.1:", err)
        self.assertNotIn("BROWSER-READ-STDIN", err)

    def test_browser_launch_failure_is_not_fatal(self):
        import contextlib
        import io
        from sealref import ui
        err = io.StringIO()
        with mock.patch.object(ui, "_BROWSER_HELPER", ["/nonexistent/sealref-no-such-browser"]), \
                contextlib.redirect_stderr(err):
            ui._open_browser("http://127.0.0.1:1/")  # must not raise
        self.assertIn("could not open a browser", err.getvalue())
        self.assertIn("open http://127.0.0.1:1/ manually", err.getvalue())

    def test_default_helper_uses_webbrowser(self):
        from sealref import ui
        self.assertEqual(ui._BROWSER_HELPER[0], sys.executable)
        self.assertIn("webbrowser.open(sys.argv[1])", ui._BROWSER_HELPER[-1])


class GetSecretIntegrationTest(unittest.TestCase):
    """Real keychain round trip, cleaned up in tearDown. Skipped if `security`
    is unavailable (non-macOS)."""

    GROUP = "sealref-test-integration"
    KEY = "TEST_KEY"

    def setUp(self):
        if shutil.which("security") is None or (os.environ.get("VAULTLET_SKIP_KEYCHAIN") or os.environ.get("SEALREF_SKIP_KEYCHAIN")):
            self.skipTest("no usable keychain (not macOS, or VAULTLET_SKIP_KEYCHAIN set)")
        self.tmpdir = tempfile.mkdtemp()
        self._patch = mock.patch.multiple(
            store, VAULT_DIR=self.tmpdir, INDEX_PATH=os.path.join(self.tmpdir, "index.json")
        )
        self._patch.start()

    def tearDown(self):
        try:
            store.delete(self.GROUP, self.KEY)
        except Exception:
            pass
        self._patch.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_set_resolve_delete_round_trip(self):
        store.set_secret(self.GROUP, self.KEY, 'integration "test" \\value')
        self.assertTrue(store.has(self.GROUP, self.KEY))
        self.assertEqual(store._resolve(self.GROUP, self.KEY), 'integration "test" \\value')
        store.delete(self.GROUP, self.KEY)
        self.assertFalse(store.has(self.GROUP, self.KEY))


if __name__ == "__main__":
    unittest.main()
