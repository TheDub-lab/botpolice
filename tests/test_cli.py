import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from botpolice.cli import main
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


if __name__ == "__main__":
    unittest.main()
