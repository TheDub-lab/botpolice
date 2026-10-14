import json
import tempfile
import unittest
from pathlib import Path

from botpolice.eventlog import (
    GENESIS_HASH,
    EventLog,
    cap_payload,
    compute_hash,
    verify_log,
)


class EventLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "events.jsonl"

    def test_empty_log_verifies(self) -> None:
        result = verify_log(self.path)
        self.assertTrue(result.ok)
        self.assertEqual(result.entries, 0)

    def test_append_and_verify_ok(self) -> None:
        log = EventLog(self.path)
        log.append({"event": "http_request", "service": "http", "src_ip": "127.0.0.1"})
        log.append({"event": "ssh_connection", "service": "ssh", "src_ip": "127.0.0.1"})

        result = verify_log(self.path)
        self.assertTrue(result.ok)
        self.assertEqual(result.entries, 2)

        entries = list(log.read_all())
        self.assertEqual(entries[0]["prev_hash"], GENESIS_HASH)
        self.assertEqual(entries[1]["prev_hash"], entries[0]["hash"])
        self.assertEqual(entries[1]["hash"], compute_hash({k: v for k, v in entries[1].items() if k != "hash"}))

    def test_chain_continues_across_instances(self) -> None:
        EventLog(self.path).append({"event": "one"})
        EventLog(self.path).append({"event": "two"})
        result = verify_log(self.path)
        self.assertTrue(result.ok)
        self.assertEqual(result.entries, 2)

    def test_tamper_detected_by_hash_mismatch(self) -> None:
        log = EventLog(self.path)
        log.append({"event": "one"})
        log.append({"event": "two"})
        log.append({"event": "three"})

        lines = self.path.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[1])
        tampered["src_ip"] = "10.0.0.9"
        lines[1] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify_log(self.path)
        self.assertFalse(result.ok)
        self.assertEqual(result.first_broken_line, 2)
        self.assertIn("hash mismatch", result.reason)

    def test_deletion_detected_by_prev_hash_mismatch(self) -> None:
        log = EventLog(self.path)
        log.append({"event": "one"})
        log.append({"event": "two"})
        log.append({"event": "three"})

        lines = self.path.read_text(encoding="utf-8").splitlines()
        del lines[1]
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify_log(self.path)
        self.assertFalse(result.ok)
        self.assertEqual(result.first_broken_line, 2)
        self.assertIn("prev_hash mismatch", result.reason)

    def test_invalid_json_reported(self) -> None:
        self.path.write_text("not json\n", encoding="utf-8")
        result = verify_log(self.path)
        self.assertFalse(result.ok)
        self.assertEqual(result.first_broken_line, 1)

    def test_payload_cap(self) -> None:
        data = b"A" * 10000
        text, original_len, truncated = cap_payload(data, 4096)
        self.assertEqual(len(text), 4096)
        self.assertEqual(original_len, 10000)
        self.assertTrue(truncated)
        self.assertEqual(text, "A" * 4096)

    def test_payload_cap_preserves_binary_safely(self) -> None:
        data = bytes(range(256))
        text, original_len, truncated = cap_payload(data, 64)
        self.assertEqual(original_len, 256)
        self.assertTrue(truncated)
        self.assertEqual(len(text.encode("utf-8")), len(text))
        json.dumps({"raw": text})


if __name__ == "__main__":
    unittest.main()
