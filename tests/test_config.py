import json
import tempfile
import unittest
from pathlib import Path

from botpolice.config import Config, load_config_with_source


class ConfigTests(unittest.TestCase):
    def test_example_config_is_valid(self) -> None:
        example = Path(__file__).resolve().parent.parent / "config.example.json"
        self.assertTrue(example.exists())
        config, source = load_config_with_source(example)
        self.assertEqual(config.bind, "127.0.0.1")
        self.assertEqual(config.services["ssh"].port, 2222)
        self.assertEqual(config.services["http"].port, 8080)
        self.assertEqual(config.services["compute"].port, 11435)
        self.assertEqual(config.services["database"].port, 15432)
        self.assertEqual(config.services["adb"].port, 5555)
        self.assertEqual(config.alerts.min_severity, "medium")
        self.assertEqual(source, example)

    def test_adb_defaults(self) -> None:
        config = Config.from_dict({})
        self.assertEqual(config.services["adb"].port, 5555)
        self.assertEqual(config.adb.max_message_bytes, 65536)
        self.assertEqual(config.adb.max_commands_per_session, 64)
        self.assertEqual(config.adb.responses_file, "adb_responses.example.json")
        self.assertEqual(config.adb.identity["ro.product.name"], "tvbox")

    def test_adb_overrides_and_identity_fallback(self) -> None:
        config = Config.from_dict(
            {
                "adb": {
                    "bind": "127.0.0.2",
                    "identity": {},
                    "max_commands_per_session": 3,
                    "responses_file": "custom.json",
                }
            }
        )
        self.assertEqual(config.adb.bind, "127.0.0.2")
        self.assertEqual(config.adb.max_commands_per_session, 3)
        self.assertEqual(config.adb.responses_file, "custom.json")
        self.assertEqual(config.adb.identity["ro.product.name"], "tvbox")

    def test_defaults_when_keys_missing(self) -> None:
        config = Config.from_dict({})
        self.assertEqual(config.bind, "127.0.0.1")
        self.assertTrue(config.services["http"].enabled)
        self.assertEqual(config.limits.max_read_bytes, 4096)
        self.assertEqual(config.alerts.dedupe_window_seconds, 120.0)

    def test_invalid_severity_falls_back(self) -> None:
        config = Config.from_dict({"alerts": {"min_severity": "bogus"}})
        self.assertEqual(config.alerts.min_severity, "medium")

    def test_relative_paths_resolve_to_config_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({"log_path": "logs/events.jsonl"}), encoding="utf-8")
            config, _ = load_config_with_source(path)
            resolved = config.resolve(config.log_path)
            self.assertEqual(resolved, Path(tmp) / "logs" / "events.jsonl")

    def test_listener_url_override(self) -> None:
        config = Config.from_dict({"advertise_url": "http://10.0.0.5:8080"})
        self.assertEqual(config.listener_url(), "http://10.0.0.5:8080")

    def test_non_object_root_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text("[1, 2, 3]", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config_with_source(path)


if __name__ == "__main__":
    unittest.main()
