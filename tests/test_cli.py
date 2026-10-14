import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from botpolice.cli import main
from botpolice.decoys import load_identity
from botpolice.eventlog import EventLog


def _run(argv):
    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class CliCanaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = self.root / "canaries.json"
        self.out = self.root / "canaries"

    def test_canary_new_json_output(self) -> None:
        code, out, _ = _run(
            [
                "canary", "new",
                "--placement", "lab-web",
                "--type", "env",
                "--store", str(self.store),
                "--out-dir", str(self.out),
                "--listener-url", "http://10.0.0.5:8080",
                "--json",
            ]
        )
        self.assertEqual(code, 0)
        record = json.loads(out)
        self.assertTrue(record["token"].startswith("bp-lab-web-"))
        self.assertTrue(Path(record["file"]).exists())
        content = Path(record["file"]).read_text(encoding="utf-8")
        self.assertIn(record["token"], content)
        self.assertIn("http://10.0.0.5:8080", content)
        self.assertTrue(self.store.exists())

    def test_canary_list(self) -> None:
        _run(
            [
                "canary", "new", "--placement", "lab-web", "--type", "json",
                "--store", str(self.store), "--out-dir", str(self.out),
            ]
        )
        code, out, _ = _run(["canary", "list", "--store", str(self.store)])
        self.assertEqual(code, 0)
        self.assertIn("placement=lab-web", out)


class CliVerifyLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "events.jsonl"

    def test_verify_ok(self) -> None:
        log = EventLog(self.path)
        log.append({"event": "one"})
        log.append({"event": "two"})
        code, out, _ = _run(["verify-log", "--path", str(self.path)])
        self.assertEqual(code, 0)
        self.assertIn("intact", out)

    def test_verify_broken_exit_code(self) -> None:
        log = EventLog(self.path)
        log.append({"event": "one"})
        log.append({"event": "two"})
        lines = self.path.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[0])
        entry["event"] = "tampered"
        lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        code, out, _ = _run(["verify-log", "--path", str(self.path), "--json"])
        self.assertEqual(code, 1)
        result = json.loads(out)
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_broken_line"], 1)


class CliRunTests(unittest.TestCase):
    def test_run_missing_config_returns_2(self) -> None:
        code, _, err = _run(["run", "--config", "definitely-not-here.json"])
        self.assertEqual(code, 2)
        self.assertIn("config not found", err)


class CliDecoyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config_path = self.root / "config.json"
        self.config_path.write_text(json.dumps({}), encoding="utf-8")

    def test_rotate_decoys_writes_identity(self) -> None:
        code, out, _ = _run(["rotate-decoys", "--config", str(self.config_path), "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertTrue(Path(payload["file"]).exists())
        self.assertTrue(payload["ssh_banner"].startswith("SSH-2.0-"))
        self.assertIn("ro.product.name", payload["adb_identity"])

    def test_rotate_decoys_persists(self) -> None:
        _, out, _ = _run(["rotate-decoys", "--config", str(self.config_path), "--json"])
        payload = json.loads(out)
        loaded = load_identity(payload["file"])
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.ssh_banner, payload["ssh_banner"])


class CliAnchorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config_path = self.root / "config.json"
        self.config_path.write_text(
            json.dumps({"log_path": "events.jsonl"}), encoding="utf-8"
        )

    def test_anchor_missing_config_returns_2(self) -> None:
        code, _, err = _run(["anchor", "--config", "definitely-not-here.json"])
        self.assertEqual(code, 2)
        self.assertIn("config not found", err)

    def test_anchor_empty_log_returns_1(self) -> None:
        code, _, err = _run(["anchor", "--config", str(self.config_path)])
        self.assertEqual(code, 1)
        self.assertIn("empty", err)

    def test_anchor_ok(self) -> None:
        EventLog(self.root / "events.jsonl").append({"event": "one"})
        code, out, _ = _run(["anchor", "--config", str(self.config_path), "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["seq"], 1)
        self.assertFalse(payload["delivered"])


if __name__ == "__main__":
    unittest.main()
