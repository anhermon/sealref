#!/usr/bin/env python3
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from vaultlet import store
from vaultlet.cli import _build_needles, _redact_line


class RefTest(unittest.TestCase):
    def test_round_trip(self):
        r = store.ref("myapp", "API_KEY")
        self.assertEqual(r, "vaultlet://myapp/API_KEY")
        self.assertEqual(store.parse_ref(r), ("myapp", "API_KEY"))

    def test_parse_rejects_garbage(self):
        for bad in ["not-a-ref", "vaultlet://onlygroup", "http://g/k", "vaultlet://g/k/extra", ""]:
            with self.assertRaises(ValueError):
                store.parse_ref(bad)


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

    @mock.patch("vaultlet.store.subprocess.run")
    def test_set_secret_rejects_bad_key(self, mock_run):
        for bad in ["1starts_with_digit", "has-dash", "has space", ""]:
            with self.assertRaises(ValueError):
                store.set_secret("g", bad, "value")
        mock_run.assert_not_called()

    @mock.patch("vaultlet.store.subprocess.run")
    def test_set_secret_accepts_good_key(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=0)
        r = store.set_secret("g", "API_KEY", "secretvalue")
        self.assertEqual(r, "vaultlet://g/API_KEY")
        self.assertIn("API_KEY", store.list_keys("g"))
        args = mock_run.call_args[0][0]
        self.assertEqual(
            args,
            ["security", "add-generic-password", "-a", "API_KEY", "-s", "vaultlet:g", "-w", "secretvalue", "-U"],
        )


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


class GetSecretIntegrationTest(unittest.TestCase):
    """Real keychain round trip, cleaned up in tearDown. Skipped if `security`
    is unavailable (non-macOS)."""

    GROUP = "vaultlet-test-integration"
    KEY = "TEST_KEY"

    def setUp(self):
        if shutil.which("security") is None:
            self.skipTest("no `security` binary (not macOS)")
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
        store.set_secret(self.GROUP, self.KEY, "integration-test-value")
        self.assertTrue(store.has(self.GROUP, self.KEY))
        self.assertEqual(store._resolve(self.GROUP, self.KEY), "integration-test-value")
        store.delete(self.GROUP, self.KEY)
        self.assertFalse(store.has(self.GROUP, self.KEY))


if __name__ == "__main__":
    unittest.main()
