import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from botpolice.anchor import ChainAnchor, format_anchor_text
from botpolice.config import AlertConfig, AnchorConfig
from botpolice.eventlog import EventLog


class _Receiver(BaseHTTPRequestHandler):
    received: list[dict] = []
    lock = threading.Lock()

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        with _Receiver.lock:
            _Receiver.received.append(json.loads(body))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):  # silence
        return


class AnchorRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = EventLog(Path(self.tmp.name) / "events.jsonl")

    def test_empty_log_returns_none(self) -> None:
        anchor = ChainAnchor(AnchorConfig(), AlertConfig(), self.log, deliver=False)
        self.assertIsNone(anchor.anchor_once())

    def test_anchor_records_head_and_event(self) -> None:
        self.log.append({"event": "x"})
        head = self.log.head()
        anchor = ChainAnchor(AnchorConfig(), AlertConfig(), self.log, deliver=False)
        payload = anchor.anchor_once()

        self.assertIsNotNone(payload)
        assert payload is not None
        self.assertEqual(payload["head"], head)
        self.assertEqual(payload["seq"], 1)
        self.assertFalse(payload["delivered"])

        events = [e for e in self.log.read_all() if e["event"] == "chain_anchor"]
        self.assertTrue(events)
        self.assertEqual(events[-1]["extra"]["head"], head)
        self.assertFalse(events[-1]["extra"]["delivered"])

    def test_seq_increments(self) -> None:
        self.log.append({"event": "x"})
        anchor = ChainAnchor(AnchorConfig(), AlertConfig(), self.log, deliver=False)
        self.assertEqual(anchor.anchor_once()["seq"], 1)
        self.assertEqual(anchor.anchor_once()["seq"], 2)

    def test_format_anchor_text(self) -> None:
        text = format_anchor_text({"head": "abc123", "seq": 3, "log": "e.jsonl", "ts": "t"})
        self.assertIn("abc123", text)
        self.assertIn("seq: 3", text)


class AnchorDeliveryTests(unittest.TestCase):
    def setUp(self) -> None:
        _Receiver.received = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Receiver)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/anchor"
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = EventLog(Path(self.tmp.name) / "events.jsonl")

    def _stop(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def test_anchor_delivers_to_webhook(self) -> None:
        self.log.append({"event": "x"})
        anchor = ChainAnchor(
            AnchorConfig(webhook_url=self.url), AlertConfig(), self.log, deliver=True
        )
        payload = anchor.anchor_once()
        self.assertTrue(payload["delivered"])
        self.assertEqual(len(_Receiver.received), 1)
        self.assertEqual(_Receiver.received[0]["event"], "chain_anchor")
        self.assertEqual(_Receiver.received[0]["head"], payload["head"])

    def test_dead_destination_never_raises(self) -> None:
        self.log.append({"event": "x"})
        anchor = ChainAnchor(
            AnchorConfig(webhook_url="http://127.0.0.1:1/anchor"),
            AlertConfig(),
            self.log,
            deliver=True,
        )
        payload = anchor.anchor_once()
        self.assertFalse(payload["delivered"])


if __name__ == "__main__":
    unittest.main()
