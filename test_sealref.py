#!/usr/bin/env python3
import json
import os
import re
import shutil
import tempfile
import types
import unittest
from unittest import mock

import subprocess
import sys

os.environ.setdefault("SEALREF_BACKEND", "macos")  # most tests mock `security`
os.environ.pop("SEALREF_KEYCHAIN", None)  # never inherit a keychain file into the mocked tests
from sealref import store, backends
from sealref.cli import _build_needles, _redact_line


# sh launchers, chmod modes, symlinks and `sh -c` children have no Windows equivalent.
# These are skipped there (unverified on Windows either way; see README Limits).
POSIX_ONLY = unittest.skipIf(sys.platform == "win32", "POSIX-only mechanics")


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
            run.return_value.stderr = 'password: "v"\n'
            run.return_value.returncode = 0
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

    @POSIX_ONLY
    def test_bin_script_ignores_cwd_modules_and_relative_symlink(self):
        tmp = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        os.makedirs(os.path.join(tmp, "work", "sealref"))
        with open(os.path.join(tmp, "work", "json.py"), "w") as f:
            f.write('raise SystemExit("PLANTED json.py RAN")\n')
        with open(os.path.join(tmp, "work", "sealref", "__init__.py"), "w") as f:
            f.write('raise SystemExit("PLANTED sealref RAN")\n')
        os.makedirs(os.path.join(tmp, "links"))
        link = os.path.join(tmp, "links", "sealref")
        os.symlink(os.path.relpath(os.path.join(self.ROOT, "bin", "sealref"), os.path.dirname(link)), link)
        for exe in (os.path.join(self.ROOT, "bin", "sealref"), link):
            r = subprocess.run([exe, "--help"], capture_output=True, text=True,
                               cwd=os.path.join(tmp, "work"))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("usage: sealref ", r.stdout)
            self.assertNotIn("PLANTED", r.stdout + r.stderr)

    @POSIX_ONLY
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
            r = self._run("-m", mod, "keys", "g", env={"HOME": home, "USERPROFILE": home})
            self.assertEqual(r.stdout, "API_KEY  sealref://g/API_KEY\n", mod)
            r = self._run("-m", mod, "keys", "g", env={"HOME": home, "USERPROFILE": home, "SEALREF_REF_SCHEME": "vaultlet"})
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
        self.assertEqual(argv, ["/usr/bin/security", "-i"])  # never PATH-resolved
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

    @mock.patch("sealref.store.subprocess.run")
    def test_set_secret_one_command_per_line(self, mock_run):
        """security -i runs each ~4 KB chunk of an over-long line as its own
        command, and splits on control characters: reject both before
        anything reaches it."""
        for bad in ["x" * 3000, "é" * 1500, "a\tb", "a\x0bb", "a\x1bb", "a\x7fb", 42, None]:
            with self.assertRaises(ValueError):
                store.set_secret("g", "K", bad)
        mock_run.assert_not_called()
        mock_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        store.set_secret("g", "K", "v" * 2800)
        script = mock_run.call_args[1]["input"]
        lines = script.splitlines()
        self.assertEqual([l.split()[0] for l in lines],
                         ["delete-generic-password", "add-generic-password"])
        self.assertTrue(all(len(l.encode()) <= backends.MAX_COMMAND_BYTES for l in lines))
        self.assertNotIn(' -T ""', script)

    @mock.patch("sealref.store.subprocess.run")
    def test_set_secret_require_approval_empty_acl(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        store.set_secret("g", "K", "value", require_approval=True)
        add = mock_run.call_args[1]["input"].splitlines()[1]
        self.assertTrue(add.endswith(' -w "value" -T ""'), add)

    @mock.patch("sealref.store.subprocess.run")
    def test_set_secret_missing_item_delete_is_not_failure(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="", stderr="delete-generic-password: returned -25300\n")
        store.set_secret("g", "K", "value")
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="", stderr="add-generic-password: returned -128\n")
        with self.assertRaises(RuntimeError):
            store.set_secret("g", "K", "value")

    def test_keychain_calls_use_absolute_security_path(self):
        with mock.patch("sealref.store.subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="", stderr='password: "v"\n')
            store.set_secret("g", "K", "value")
            store._resolve("g", "K")
            store.delete("g", "K")
        self.assertEqual({c[0][0][0] for c in run.call_args_list}, {"/usr/bin/security"})

    def test_failed_keychain_delete_keeps_index_entry(self):
        with mock.patch("sealref.store.subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
            store.set_secret("g", "K", "value")
            run.return_value = mock.Mock(returncode=1, stdout=b"", stderr=b"")
            with self.assertRaises(RuntimeError):
                store.delete("g", "K")
            self.assertIn("K", store.list_keys("g"))  # value may still exist: stay visible
            run.return_value = mock.Mock(returncode=44, stdout=b"", stderr=b"")  # not found
            store.delete("g", "K")
            self.assertNotIn("K", store.list_keys("g"))

    @POSIX_ONLY
    def test_index_temp_file_is_unique_and_not_followed(self):
        victim = os.path.join(self.tmpdir, "victim")
        open(victim, "w").close()
        os.symlink(victim, os.path.join(self.tmpdir, "index.json.tmp"))
        store.create_group("g")
        self.assertEqual(os.path.getsize(victim), 0)
        self.assertIn("g", store.list_groups())

    @POSIX_ONLY
    def test_vault_dir_mode_repaired(self):
        os.chmod(self.tmpdir, 0o755)
        store.create_group("g")
        self.assertEqual(os.stat(self.tmpdir).st_mode & 0o777, 0o700)

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

    @POSIX_ONLY
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
        h = {"Host": f"127.0.0.1:{self.port}", "X-Vaultlet": self.server.token}
        h.update(headers or {})
        h = {k: v for k, v in h.items() if v is not None}
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        r.read()
        self.last_headers = r.headers
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

    def test_wrong_or_legacy_token_rejected(self):
        """Any local program or other macOS user can reach 127.0.0.1 and set
        headers; without this server's token they get nothing."""
        for tok in ("1", "", self.server.token[:-1] + "x"):
            self.assertEqual(self._req("GET", "/api/groups", headers={"X-Vaultlet": tok}), 403)
            self.assertEqual(self._req("POST", "/api/keys", '{"group":"g","key":"K","value":"v"}',
                                       {"X-Vaultlet": tok}), 403)
            self.assertEqual(self._req("DELETE", "/api/keys/g/K", headers={"X-Vaultlet": tok}), 403)
            self.assertEqual(self._req("POST", "/api/quit", "{}", {"X-Vaultlet": tok}), 403)
        self.assertEqual(self._req("POST", "/", "{}"), 403)

    def test_not_frameable(self):
        for path in ("/", "/api/groups"):
            self.assertEqual(self._req("GET", path), 200)
            self.assertEqual(self.last_headers["X-Frame-Options"], "DENY")
            self.assertIn("frame-ancestors 'none'", self.last_headers["Content-Security-Policy"])
            self.assertEqual(self.last_headers["X-Content-Type-Options"], "nosniff")

    def test_value_field_not_spellchecked_or_autofilled(self):
        from sealref import ui
        tag = ui.PAGE[ui.PAGE.index('class="val-input"') - 60:ui.PAGE.index('class="val-input"') + 200]
        self.assertIn('spellcheck="false"', tag)
        self.assertIn('autocomplete="off"', tag)

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

    def test_approval_checkbox_only_when_backend_is_macos(self):
        import http.client
        for backend, want in (("macos", "true"), ("keyring", "false")):
            with mock.patch.dict(os.environ, {"SEALREF_BACKEND": backend}):
                c = http.client.HTTPConnection("127.0.0.1", self.port)
                c.request("GET", "/", headers={"Host": f"127.0.0.1:{self.port}"})
                page = c.getresponse().read().decode()
            self.assertIn(f"const APPROVAL = {want};", page)
            self.assertNotIn("__APPROVAL__", page)

    def test_ui_no_browser_flag_skips_the_launcher(self):
        from sealref import cli, ui
        with mock.patch.object(ui, "serve") as serve:
            cli.main(["ui", "--port", "0", "--no-browser"])
            cli.main(["ui", "--port", "0"])
        self.assertEqual([c.kwargs["open_browser"] for c in serve.call_args_list], [False, True])
        with mock.patch.object(ui, "_open_browser") as ob, \
                mock.patch.object(ui, "_make_server") as mk:
            mk.return_value.server_port = 1
            mk.return_value.token = "t"
            mk.return_value.serve_forever.side_effect = KeyboardInterrupt
            with self.assertRaises(KeyboardInterrupt):
                ui.serve(0, open_browser=False)
        ob.assert_not_called()

    def test_r210_stalled_body_is_dropped(self):
        import socket
        import time
        from sealref import ui
        self.assertIsNotNone(ui.Handler.timeout)
        with mock.patch.object(ui.Handler, "timeout", 1):
            s = socket.create_connection(("127.0.0.1", self.port))
            s.settimeout(8)
            s.sendall((f"POST /api/keys HTTP/1.0\r\nHost: 127.0.0.1:{self.port}\r\n"
                       f"X-Vaultlet: {self.server.token}\r\nContent-Length: 100\r\n\r\n").encode())
            t0 = time.time()
            try:
                while s.recv(4096):  # server gives up and closes (maybe after an error reply)
                    pass
            except socket.timeout:
                self.fail("server kept waiting for the body")
            finally:
                s.close()
            self.assertLess(time.time() - t0, 6)

    def test_oversized_body_refused(self):
        big = json.dumps({"group": "g", "key": "K", "value": "x" * (ui_max() + 1)})
        self.assertEqual(self._req("POST", "/api/keys", body=big,
                                   headers={"Content-Length": str(len(big))}), 400)
        self.assertEqual(self._req("POST", "/api/groups", body=json.dumps({"group": "ok"})), 200)

    def test_quit_ends_pending_request_at_once(self):
        import threading
        import time
        from sealref import ui
        res = {}
        t = threading.Thread(target=lambda: res.update(
            ok=ui.serve_until("g", "API_KEY", "r", timeout=60)), daemon=True)
        with mock.patch.object(ui, "_open_browser", lambda url: res.update(url=url)):
            t.start()
            for _ in range(100):
                if "url" in res:
                    break
                time.sleep(0.05)
        import http.client
        import re
        port = int(re.search(r"127\.0\.0\.1:(\d+)/", res["url"]).group(1))
        token = res["url"].split("#t=")[1]
        c = http.client.HTTPConnection("127.0.0.1", port)
        c.request("POST", "/api/quit", body=b"{}",
                  headers={"Host": f"127.0.0.1:{port}", "X-Vaultlet": token})
        self.assertEqual(c.getresponse().status, 200)
        t0 = time.time()
        t.join(timeout=10)
        self.assertFalse(t.is_alive())
        self.assertLess(time.time() - t0, 5)
        self.assertIs(res["ok"], False)


class RedactionGapsTest(unittest.TestCase):
    def test_basic_auth_base64_any_alignment_and_hex(self):
        import base64
        value = "sk-test-DUMMY0123456789"
        needles = _build_needles([("g", "K", value)])
        for user in ("", "x", "ab", "user", "someone@example.com"):
            for enc in (base64.b64encode, base64.urlsafe_b64encode):
                line = enc(f"{user}:{value}".encode()).decode() + "\n"
                self.assertIn("«redacted:g/K»", _redact_line(line, needles), user)
        for h in (value.encode().hex(), value.encode().hex().upper()):
            self.assertNotIn(h, _redact_line(f"hex {h}\n", needles))

    def _run_child(self, script):
        import contextlib
        import io
        from sealref import cli
        buf = io.StringIO()
        with mock.patch.object(store, "_resolve", return_value="sk-test-DUMMY0123456789"), \
                contextlib.redirect_stdout(buf):
            rc = cli.cmd_run(["--ref", "sealref://g/K", "--", "sh", "-c", script])
        return rc, buf.getvalue()

    def test_long_line_and_missing_final_newline(self):
        rc, out = self._run_child('head -c 70000 /dev/zero | tr "\\0" x; printf %s "$K"')
        self.assertNotIn("DUMMY", out)
        self.assertIn("«redacted:g/K»", out)

    def test_ref_alias_must_be_an_env_name(self):
        import contextlib
        import io
        from sealref import cli
        err = io.StringIO()
        with mock.patch.object(store, "_resolve", return_value="sk-test-DUMMY") as res, \
                contextlib.redirect_stderr(err):
            for alias in ("A=B", "1X", "A-B", "A B"):
                self.assertEqual(cli.main(["run", "--ref", f"sealref://g/K={alias}", "--", "true"]), 2)
        res.assert_not_called()
        self.assertIn("invalid key name", err.getvalue())

    def test_keychain_read_failure_is_a_clean_error(self):
        import contextlib
        import io
        from sealref import cli
        failed = mock.Mock(returncode=128, stdout="", stderr="")
        err = io.StringIO()
        with mock.patch("sealref.store.subprocess.run", return_value=failed), \
                contextlib.redirect_stderr(err):
            rc = cli.main(["run", "--ref", "sealref://g/K", "--", "true"])
        self.assertEqual(rc, 2)
        self.assertIn("keychain read of g/K failed or was denied", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())


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
                    rc = cli.cmd_run(["--ref", f"{scheme}://stripe/API_KEY", "--", sys.executable, "-c",
                                      'import os; v = os.environ["API_KEY"]; print("len=%d val=%s" % (len(v), v))'])
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
        # launchers do, and tries to read stdin. A Python script so it runs on
        # Windows too.
        browser = os.path.join(tmp, "noisy_browser.py")
        with open(browser, "w") as f:
            f.write("import sys\n"
                    "print('BROWSER-STDOUT ' + sys.argv[1], flush=True)\n"
                    "line = sys.stdin.readline()\n"
                    "if line:\n"
                    "    print('BROWSER-READ-STDIN ' + line, file=sys.stderr, flush=True)\n"
                    f"open({marker!r}, 'w').close()\n")
        # HTTPServer.server_bind() calls socket.getfqdn(), whose reverse DNS
        # lookup can take ~30s on GitHub's macOS runners; it is irrelevant here.
        code = ("import socket, sys, time; socket.getfqdn = lambda name='': name; "
                "from sealref import ui; "
                f"ui._BROWSER_HELPER = [{sys.executable!r}, {browser!r}]; "
                "ok = ui.serve_until('g', 'API_KEY', 'test', timeout=1.5); "
                "time.sleep(0.5); "
                "raise SystemExit(0 if ok is False else 3)")
        env = {**os.environ, "PYTHONPATH": self.ROOT, "HOME": tmp, "USERPROFILE": tmp}
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


class FakeKeyringBackend:
    """In-memory keyring backend. `module`/`name` are what the allow-list sees."""
    priority = 1

    _classes = {}

    def __init__(self, module, name, store=None):
        key = (module, name)
        if key not in self._classes:
            self._classes[key] = type(name, (FakeKeyringBackend,), {"__module__": module})
        cls = self._classes[key]
        self.__class__ = cls
        # The allow-list checks the class object really lives in that module
        # (tests run under mock.patch.dict(sys.modules): see FakeKeyringCase).
        mod = sys.modules.get(module)
        if mod is None or not getattr(mod, "_is_fake", False):
            mod = types.ModuleType(module)
            mod._is_fake = True
            sys.modules[module] = mod
        setattr(mod, name, cls)
        self.d = store if store is not None else {}
        self.calls = []

    def get_password(self, svc, user):
        self.calls.append("get")
        return self.d.get((svc, user))

    def set_password(self, svc, user, pw):
        self.calls.append("set")
        self.d[(svc, user)] = pw

    def delete_password(self, svc, user):
        self.calls.append("delete")
        if (svc, user) not in self.d:
            raise FakeErrors.PasswordDeleteError("not found")
        del self.d[(svc, user)]


class FakeErrors:
    class PasswordDeleteError(Exception):
        pass


class FakeChainer:
    def __init__(self, backends):
        self.__class__ = type("ChainerBackend", (FakeChainer,), {"__module__": "keyring.backends.chainer"})
        self.backends = backends


def fake_kr(current):
    return mock.Mock(get_keyring=lambda: current, errors=FakeErrors)


SECURE = [("keyring.backends.SecretService", "Keyring"), ("keyring.backends.libsecret", "Keyring"),
          ("keyring.backends.kwallet", "DBusKeyring"), ("keyring.backends.Windows", "WinVaultKeyring"),
          ("keyring.backends.macOS", "Keyring")]
INSECURE = [("keyring.backends.fail", "Keyring"), ("keyring.backends.null", "Keyring"),
            ("keyrings.alt.file", "PlaintextKeyring"), ("keyrings.alt.file", "EncryptedKeyring"),
            ("keyrings.alt.Gnome", "Keyring"), ("keyring.backends.Windows", "RegistryKeyring"),
            ("some.other.pkg", "Keyring")]


class FakeKeyringCase(unittest.TestCase):
    def setUp(self):
        p = mock.patch.dict(sys.modules)  # fakes register fake keyring.* modules; restore after
        p.start()
        self.addCleanup(p.stop)


class KeyringAllowListTest(FakeKeyringCase):
    def test_secure_backends_accepted(self):
        for mod, name in SECURE:
            b = backends.Keyring(fake_kr(FakeKeyringBackend(mod, name)))
            self.assertEqual(type(b.backend).__module__, mod)

    def test_insecure_backends_refused_with_clear_error(self):
        for mod, name in INSECURE:
            with self.assertRaisesRegex(RuntimeError, r"no secure OS keyring available.*gnome-keyring") as c:
                backends.Keyring(fake_kr(FakeKeyringBackend(mod, name)))
            self.assertIn(f"{mod}.{name}", str(c.exception))

    def test_chainer_uses_only_allowed_member_never_plaintext(self):
        plain = FakeKeyringBackend("keyrings.alt.file", "PlaintextKeyring")
        ss = FakeKeyringBackend("keyring.backends.SecretService", "Keyring")
        # plaintext listed first (higher priority): still never used
        b = backends.Keyring(fake_kr(FakeChainer([plain, ss])))
        b.set("g", "K", "dummy-value")
        self.assertEqual(b.get("g", "K"), "dummy-value")
        b.delete("g", "K")
        self.assertEqual(plain.calls, [])
        self.assertEqual(ss.calls, ["set", "get", "delete"])

    def test_chainer_with_only_insecure_members_refused(self):
        plain = FakeKeyringBackend("keyrings.alt.file", "PlaintextKeyring")
        enc = FakeKeyringBackend("keyrings.alt.file", "EncryptedKeyring")
        with self.assertRaisesRegex(RuntimeError, "no secure OS keyring"):
            backends.Keyring(fake_kr(FakeChainer([plain, enc])))
        with self.assertRaisesRegex(RuntimeError, "no secure OS keyring"):
            backends.Keyring(fake_kr(FakeChainer([])))
        self.assertEqual(plain.calls + enc.calls, [])

    def test_get_backend_refuses_via_store_with_no_fallback(self):
        kr = fake_kr(FakeKeyringBackend("keyrings.alt.file", "PlaintextKeyring"))
        with mock.patch.dict(os.environ, {"SEALREF_BACKEND": "keyring"}), \
                mock.patch.dict(sys.modules, {"keyring": kr, "keyring.errors": FakeErrors}):
            with self.assertRaisesRegex(RuntimeError, "no secure OS keyring"):
                store.set_secret("g", "K", "dummy")
        self.assertEqual(kr.get_keyring().d, {})

    def test_lookalike_class_claiming_a_keyring_module_is_refused(self):
        """A class loaded via keyringrc.cfg can set __module__ to anything."""
        real = FakeKeyringBackend("keyring.backends.SecretService", "Keyring")
        spoof = type("Keyring", (), {"__module__": "keyring.backends.SecretService",
                                     "priority": 9})()
        self.assertIsNot(type(spoof), type(real))
        with self.assertRaisesRegex(RuntimeError, "no secure OS keyring"):
            backends.Keyring(fake_kr(spoof))
        # a subclass of the real class is not the real class either
        sub = object.__new__(type("Keyring", (type(real),), {"__module__": "keyring.backends.SecretService"}))
        with self.assertRaisesRegex(RuntimeError, "no secure OS keyring"):
            backends.Keyring(fake_kr(sub))
        backends.Keyring(fake_kr(real))  # the real one still passes

    def test_missing_lib_message(self):
        with mock.patch.dict(sys.modules, {"keyring": None}):
            with self.assertRaisesRegex(RuntimeError, r"sealref\[keyring\]"):
                backends.Keyring()

    def test_selection(self):
        with mock.patch.dict(os.environ, {"SEALREF_BACKEND": "macos"}):
            self.assertIsInstance(backends.get_backend(), backends.MacKeychain)
        with mock.patch.dict(os.environ, {"SEALREF_BACKEND": "nope"}):
            with self.assertRaises(ValueError):
                backends.get_backend()
        env = {k: v for k, v in os.environ.items() if k != "SEALREF_BACKEND"}
        for plat, want in (("darwin", "macos"), ("linux", "keyring"), ("win32", "keyring")):
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(sys, "platform", plat), \
                    mock.patch.object(backends, "Keyring", lambda: type("K", (), {"name": "keyring"})()):
                self.assertEqual(backends.get_backend().name, want)


class KeyringBehaviourTest(FakeKeyringCase):
    def setUp(self):
        super().setUp()
        self.inner = FakeKeyringBackend("keyring.backends.SecretService", "Keyring")
        self.b = backends.Keyring(fake_kr(self.inner))

    def test_roundtrip_and_service_name(self):
        self.b.set("g", "K", 'v"al\\ue')
        self.assertIn(("vaultlet:g", "K"), self.inner.d)  # same naming as the Keychain backend
        self.assertEqual(self.b.get("g", "K"), 'v"al\\ue')

    def test_delete_absent_is_ok_but_other_errors_propagate_value_free(self):
        self.b.delete("g", "K")  # PasswordDeleteError: absent
        self.inner.delete_password = mock.Mock(side_effect=OSError("locked, sk-leak-123"))
        with self.assertRaises(RuntimeError) as c:
            self.b.delete("g", "K")
        self.assertNotIn("sk-leak-123", str(c.exception))
        self.assertIn("OSError", str(c.exception))

    def test_store_delete_keeps_index_when_keyring_delete_fails(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        with mock.patch.multiple(store, VAULT_DIR=tmp, INDEX_PATH=os.path.join(tmp, "index.json")), \
                mock.patch.object(store, "get_backend", lambda: self.b):
            store.set_secret("g", "K", "dummy-value")
            self.inner.delete_password = mock.Mock(side_effect=OSError("locked"))
            with self.assertRaises(RuntimeError):
                store.delete("g", "K")
            self.assertIn("K", store.list_keys("g"))
            del self.inner.delete_password
            store.delete("g", "K")
            self.assertNotIn("K", store.list_keys("g"))
            self.assertEqual(self.inner.d, {})

    def test_read_errors_are_clean_and_missing_is_error(self):
        with self.assertRaisesRegex(RuntimeError, "not found"):
            self.b.get("g", "K")
        self.inner.get_password = mock.Mock(side_effect=OSError("boom sk-leak-123"))
        with self.assertRaises(RuntimeError) as c:
            self.b.get("g", "K")
        self.assertNotIn("sk-leak-123", str(c.exception))

    def test_write_error_does_not_leak_value(self):
        self.inner.set_password = mock.Mock(side_effect=RuntimeError("boom sk-leak-123"))
        with self.assertRaises(RuntimeError) as c:
            self.b.set("g", "K", "sk-leak-123")
        self.assertNotIn("sk-leak-123", str(c.exception))

    def test_overwrite_is_in_place_so_failed_write_keeps_old_value(self):
        self.b.set("g", "K", "old-value")
        self.inner.set_password = mock.Mock(side_effect=OSError("denied"))
        with self.assertRaises(RuntimeError):
            self.b.set("g", "K", "new-value")
        self.assertEqual(self.b.get("g", "K"), "old-value")  # never deleted first
        self.assertNotIn("delete", self.inner.calls)

    def test_approval_is_macos_only(self):
        with self.assertRaisesRegex(ValueError, "macOS-only"):
            self.b.set("g", "K", "dummy", require_approval=True)

    def test_windows_blob_cap_fails_before_writing(self):
        win = FakeKeyringBackend("keyring.backends.Windows", "WinVaultKeyring")
        b = backends.Keyring(fake_kr(win))
        b.set("g", "K", "x" * 1280)  # exactly 2560 bytes as UTF-16
        win.calls.clear()
        for bad in ("x" * 1281, "é" * 1281, "\U0001F600" * 641):  # 641 astral = 2564 bytes
            with self.assertRaisesRegex(ValueError, "Windows Credential Manager"):
                b.set("g", "K", bad)
        self.assertEqual(win.calls, [])
        self.assertEqual(win.d[("vaultlet:g", "K")], "x" * 1280)  # old value untouched
        self.b.set("g", "K", "x" * 5000)  # no cap on Secret Service, on any OS


class MacSavePathTest(unittest.TestCase):
    """The replace path (delete then add) must not silently lose data."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._patch = mock.patch.multiple(
            store, VAULT_DIR=self.tmpdir, INDEX_PATH=os.path.join(self.tmpdir, "index.json"))
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @staticmethod
    def _fake(exists_seq, write_rc=0, write_err=""):
        """subprocess.run double: find-generic-password answers from exists_seq."""
        seq = list(exists_seq)
        calls = []

        def run(argv, **kw):
            calls.append((argv, kw))
            if argv[1] == "find-generic-password":
                return mock.Mock(returncode=0 if seq.pop(0) else 44, stdout="", stderr='password: "v"')
            return mock.Mock(returncode=write_rc, stdout="", stderr=write_err or 'password: "v"')
        return run, calls

    def test_first_save_has_no_delete_line(self):
        run, calls = self._fake([False])
        with mock.patch("sealref.store.subprocess.run", run):
            store.set_secret("g", "K", "value")
        script = calls[-1][1]["input"]
        self.assertEqual([l.split()[0] for l in script.splitlines()], ["add-generic-password"])

    def test_failed_first_save_loses_nothing_and_is_not_indexed(self):
        run, calls = self._fake([False], write_rc=1, write_err="add-generic-password: returned -128")
        with mock.patch("sealref.store.subprocess.run", run):
            with self.assertRaises(RuntimeError) as c:
                store.set_secret("g", "K", "value")
        self.assertNotIn("previous", str(c.exception))
        self.assertNotIn("delete-generic-password", calls[-1][1]["input"])
        self.assertEqual(store.list_keys("g"), [])

    def test_failed_replace_after_delete_says_so_and_drops_index_entry(self):
        run, _ = self._fake([False], write_rc=0)
        with mock.patch("sealref.store.subprocess.run", run):
            store.set_secret("g", "K", "old")
        self.assertIn("K", store.list_keys("g"))
        # exists before; add fails; item gone afterwards
        run, _ = self._fake([True, False], write_err="add-generic-password: returned -128")
        with mock.patch("sealref.store.subprocess.run", run):
            with self.assertRaisesRegex(RuntimeError, "previous value of g/K was deleted"):
                store.set_secret("g", "K", "new")
        self.assertNotIn("K", store.list_keys("g"))  # has_secret stays truthful

    def test_failed_replace_that_kept_the_item_keeps_index_entry(self):
        run, _ = self._fake([False])
        with mock.patch("sealref.store.subprocess.run", run):
            store.set_secret("g", "K", "old")
        run, _ = self._fake([True, True], write_rc=1)
        with mock.patch("sealref.store.subprocess.run", run):
            with self.assertRaisesRegex(RuntimeError, "previous value of g/K was kept"):
                store.set_secret("g", "K", "new")
        self.assertIn("K", store.list_keys("g"))

    def test_keychain_file_option_is_appended_to_every_command(self):
        run, calls = self._fake([True, True])
        kcpath = os.path.join(self.tmpdir, "x y.keychain-db")
        open(kcpath, "w").close()
        with mock.patch.dict(os.environ, {"SEALREF_KEYCHAIN": kcpath}), \
                mock.patch("sealref.store.subprocess.run", run):
            store.set_secret("g", "K", "value")
            store._resolve("g", "K")
            store.delete("g", "K")
        script = [c for c in calls if c[0][1] == "-i"][0][1]["input"]
        self.assertTrue(all(l.endswith(' "%s"' % kcpath) for l in script.splitlines()), script)
        others = [c[0] for c in calls if c[0][1] != "-i"]
        self.assertTrue(others and all(a[-1] == kcpath for a in others), others)
        with mock.patch.dict(os.environ, {"SEALREF_KEYCHAIN": "a\nb"}):
            with self.assertRaises(ValueError):
                backends.MacKeychain()


class EntryPointTest(unittest.TestCase):
    ROOT = os.path.dirname(os.path.abspath(__file__))

    def test_console_scripts_declared_and_importable(self):
        import importlib
        import re
        with open(os.path.join(self.ROOT, "pyproject.toml")) as f:
            text = f.read()
        scripts = dict(re.findall(r'^(\w+)\s*=\s*"([\w.]+:\w+)"', text.split("[project.scripts]")[1], re.M))
        self.assertEqual(set(scripts), {"sealref", "vaultlet"})
        self.assertIn("keyring", text.split("[project.optional-dependencies]")[1])
        for target in scripts.values():
            mod, attr = target.split(":")
            self.assertTrue(callable(getattr(importlib.import_module(mod), attr)))

    def test_vaultlet_entry_point_reports_legacy_prog(self):
        env = {k: v for k, v in os.environ.items() if k != "SEALREF_PROG"}
        env["PYTHONPATH"] = self.ROOT
        for target, prog in (("sealref.cli", "sealref"), ("vaultlet.__main__", "vaultlet")):
            r = subprocess.run([sys.executable, "-c",
                                f"import sys; from {target} import main; sys.exit(main(['--help']))"],
                               capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(f"usage: {prog} ", r.stdout)


class RunExitCodeTest(unittest.TestCase):
    def _run(self, *argv):
        import contextlib
        import io
        from sealref import cli
        err = io.StringIO()
        with mock.patch.object(store, "_resolve", return_value="dummy-value"), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            return cli.cmd_run(["--ref", "sealref://g/K", "--", *argv]), err.getvalue()

    @unittest.skipIf(sys.platform == "win32", "POSIX signals")
    def test_signal_death_is_128_plus_n_and_missing_command_is_127(self):
        self.assertEqual(self._run("sh", "-c", "kill -TERM $$")[0], 128 + 15)
        rc, err = self._run("/nonexistent/sealref-no-such-cmd")
        self.assertEqual(rc, 127)
        self.assertNotIn("Traceback", err)
        self.assertNotIn("dummy-value", err)


def ui_max():
    from sealref import ui
    return ui.MAX_BODY


def _mac_acl_apps(dump, acct):
    """Number of apps trusted to decrypt the item (None if not found)."""
    for block in dump.split("\nkeychain:"):
        if f'"acct"<blob>="{acct}"' in block:
            m = re.search(r"authorizations \(\d+\): decrypt[^\n]*\n(?:[^\n]*\n)*?\s*applications \((\d+)\)", block)
            return int(m.group(1)) if m else None


@unittest.skipUnless(sys.platform == "darwin" and os.path.exists("/usr/bin/security"), "macOS only")
class MacThrowawayKeychainTest(unittest.TestCase):
    """Real round trip through /usr/bin/security against a throwaway keychain
    FILE created here. It is never added to the search list, so the login
    keychain is untouched; dummy values only."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.kc = os.path.join(self.tmpdir, "throwaway.keychain-db")
        before = subprocess.run(["/usr/bin/security", "list-keychains"], capture_output=True, text=True).stdout
        self.addCleanup(self._cleanup, before)
        subprocess.run(["/usr/bin/security", "create-keychain", "-p", "dummy", self.kc],
                       check=True, capture_output=True)
        env = mock.patch.dict(os.environ, {"SEALREF_KEYCHAIN": self.kc, "SEALREF_BACKEND": "macos"})
        env.start()
        self.addCleanup(env.stop)
        p = mock.patch.multiple(store, VAULT_DIR=self.tmpdir, INDEX_PATH=os.path.join(self.tmpdir, "index.json"))
        p.start()
        self.addCleanup(p.stop)

    def _cleanup(self, before):
        subprocess.run(["/usr/bin/security", "delete-keychain", self.kc], capture_output=True)
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        after = subprocess.run(["/usr/bin/security", "list-keychains"], capture_output=True, text=True).stdout
        assert after == before, "search list changed"

    def test_round_trip_ref_run_redaction_delete(self):
        import contextlib
        import io
        from sealref import cli
        value = 'dummy "quoted" \\value-12345'
        r = store.set_secret("rt", "DUMMY_KEY", value)
        self.assertEqual(r, "sealref://rt/DUMMY_KEY")
        self.assertTrue(store.has("rt", "DUMMY_KEY"))
        self.assertEqual(store._resolve("rt", "DUMMY_KEY"), value)
        # overwrite in place
        store.set_secret("rt", "DUMMY_KEY", "second-dummy-value")
        self.assertEqual(store._resolve("rt", "DUMMY_KEY"), "second-dummy-value")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.cmd_run(["--ref", r, "--", "sh", "-c", 'echo "got=$DUMMY_KEY"'])
        self.assertEqual((rc, buf.getvalue()), (0, "got=«redacted:rt/DUMMY_KEY»\n"))
        # the item is in the throwaway file and only there
        dump = subprocess.run(["/usr/bin/security", "dump-keychain", self.kc],
                              capture_output=True, text=True).stdout
        self.assertIn('"svce"<blob>="vaultlet:rt"', dump)
        store.delete("rt", "DUMMY_KEY")
        self.assertFalse(store.has("rt", "DUMMY_KEY"))
        with self.assertRaises(RuntimeError):
            store._resolve("rt", "DUMMY_KEY")
        store.delete("rt", "DUMMY_KEY")  # already gone: fine

    def test_r26_non_ascii_and_hexlike_values_round_trip_and_run(self):
        import contextlib
        import io
        from sealref import cli
        for key, value in (("NA", "pässwörd-ключ-🔑-dummy"), ("HEXLIKE", "abcdef0123456789"),
                           ("QUOTES", 'q"uo\\te\' dummy')):
            store.set_secret("na", key, value)
            self.assertEqual(store._resolve("na", key), value, key)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.cmd_run(["--ref", "sealref://na/NA", "--", sys.executable, "-c",
                              "import os, sys; sys.stdout.buffer.write(os.environ['NA'].encode('utf-8') + b'\\n')"])
        self.assertEqual((rc, buf.getvalue()), (0, "«redacted:na/NA»\n"))  # child got the real value

    def test_r27_delete_with_missing_keychain_keeps_item_and_index(self):
        store.set_secret("mk", "K", "dummy-value")
        with mock.patch.dict(os.environ, {"SEALREF_KEYCHAIN": self.kc + ".missing"}):
            with self.assertRaises(RuntimeError):
                store.delete("mk", "K")
        self.assertIn("K", store.list_keys("mk"))
        self.assertEqual(store._resolve("mk", "K"), "dummy-value")  # still in the real throwaway keychain

    def test_approval_acl_present_only_when_opted_in(self):
        store.set_secret("acl", "OPEN_KEY", "dummy-open-value")
        store.set_secret("acl", "GATED_KEY", "dummy-gated-value", require_approval=True)
        dump = subprocess.run(["/usr/bin/security", "dump-keychain", "-a", self.kc],
                              capture_output=True, text=True).stdout
        self.assertEqual(_mac_acl_apps(dump, "OPEN_KEY"), 1)   # /usr/bin/security trusted: silent reads
        self.assertEqual(_mac_acl_apps(dump, "GATED_KEY"), 0)  # nobody trusted: every read asks
        # deleting the gated item needs no dialog and works through sealref
        store.delete("acl", "GATED_KEY")
        self.assertFalse(store.has("acl", "GATED_KEY"))

    def test_replace_over_gated_item_keeps_working(self):
        store.set_secret("acl", "K", "dummy-one", require_approval=True)
        store.set_secret("acl", "K", "dummy-two")  # replace and drop the gate
        self.assertEqual(store._resolve("acl", "K"), "dummy-two")

class R2RegressionTest(unittest.TestCase):
    """Findings from the second review; each fails on the code before the fix."""
    ROOT = os.path.dirname(os.path.abspath(__file__))

    @unittest.skipIf(sys.platform == "win32", "BROWSER parsing is POSIX shlex")
    def test_r21_real_browser_helper_ignores_planted_webbrowser_module(self):
        import time
        from sealref import ui
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        plant, ran, hijacked = (os.path.join(tmp, n) for n in ("plant", "ran", "hijacked"))
        os.mkdir(plant)
        with open(os.path.join(plant, "webbrowser.py"), "w") as f:
            f.write(f"open({hijacked!r}, 'w').close()\ndef open(url): pass\n")
        with open(os.path.join(tmp, "br.py"), "w") as f:  # the "browser" the real helper launches
            f.write(f"import sys; open({ran!r}, 'w').write(sys.argv[1])\n")
        env = {"BROWSER": f"{sys.executable} {os.path.join(tmp, 'br.py')} %s"}
        old = os.getcwd()
        os.chdir(plant)  # the "untrusted repo" sealref is run from
        self.addCleanup(os.chdir, old)
        with mock.patch.dict(os.environ, env):
            ui._open_browser("http://127.0.0.1:1/#t=tok")  # the REAL helper, not a stub
            for _ in range(100):
                if os.path.exists(ran):
                    break
                time.sleep(0.1)
        self.assertTrue(os.path.exists(ran), "real helper did not launch the browser command")
        self.assertFalse(os.path.exists(hijacked), "helper imported webbrowser.py from the cwd")
        self.assertIn("-I", ui._BROWSER_HELPER)

    def test_r22_url_quoting_variants_redacted(self):
        from urllib.parse import quote, quote_plus
        v = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY+x y&z="
        needles = _build_needles([("g", "K", v)])
        lowhex = lambda s: re.sub(r"%[0-9A-F]{2}", lambda m: m.group().lower(), s)
        forms = [quote(v, safe=""), quote(v), quote_plus(v), quote_plus(v, safe="/"),
                 lowhex(quote(v)), lowhex(quote_plus(v))]
        for f in forms:
            out = _redact_line(f"x {f} y\n", needles)
            self.assertNotIn(f, out, f)
            self.assertIn("«redacted:g/K»", out, f)

    def test_r24_windows_lookup_ignores_cwd_and_relative_path_entries(self):
        from sealref import cli
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        cwd, bindir = os.path.join(tmp, "cwd"), os.path.join(tmp, "bin")
        os.mkdir(cwd)
        os.mkdir(bindir)
        open(os.path.join(cwd, "tool.cmd"), "w").close()
        old = os.getcwd()
        os.chdir(cwd)
        self.addCleanup(os.chdir, old)
        path = os.pathsep.join(["", ".", "bin-relative", bindir])
        self.assertIsNone(cli._which_path_only("tool", path, [".EXE", ".CMD"]))  # only in cwd
        open(os.path.join(bindir, "tool.CMD"), "w").close()
        self.assertEqual(cli._which_path_only("tool", path, [".EXE", ".CMD"]),
                         os.path.join(bindir, "tool.CMD"))
        self.assertEqual(cli._which_path_only(os.path.join(".", "tool"), path, [".CMD"]),
                         os.path.join(".", "tool"))  # explicit path is the user's choice

    def test_r26_parse_g_output(self):
        p = backends._parse_g_password
        self.assertEqual(p('keychain: "x"\npassword: "plain value"\n', "g", "K"), "plain value")
        self.assertEqual(p('password: 0x70C3A4  "p\\303\\244"\n', "g", "K"), "pä")
        self.assertEqual(p('password: "abcdef012345"\n', "g", "K"), "abcdef012345")  # hex-looking text stays text
        for bad in ("", "password: 0xZZ\n", "nothing\n"):
            with self.assertRaises(RuntimeError):
                p(bad, "g", "K")

    def test_r27_missing_keychain_file_is_not_item_not_found(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        with mock.patch.multiple(store, VAULT_DIR=tmp, INDEX_PATH=os.path.join(tmp, "index.json")), \
                mock.patch.dict(os.environ, {"SEALREF_BACKEND": "macos", "SEALREF_KEYCHAIN": ""}):
            with mock.patch("sealref.store.subprocess.run") as run:
                run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
                store.set_secret("g", "K", "dummy-value")
            os.environ["SEALREF_KEYCHAIN"] = os.path.join(tmp, "no-such.keychain-db")
            with mock.patch("sealref.store.subprocess.run", return_value=mock.Mock(returncode=44)) as run:
                with self.assertRaisesRegex(RuntimeError, "does not exist"):
                    store.delete("g", "K")
                run.assert_not_called()
            self.assertIn("K", store.list_keys("g"))


if __name__ == "__main__":
    unittest.main()
