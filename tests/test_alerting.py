import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from botpolice.alerting import Alerter, format_alert_text
from botpolice.config import AlertConfig


def _alert(severity="medium", event="http_request", source_ip="127.0.0.1"):
    return {
        "severity": severity,
        "event": event,
        "service": "http",
        "source_ip": source_ip,
        "placement": None,
        "summary": "test",
        "timestamp": "2026-10-13T00:00:00+00:00",
    }


class AlertFilterTests(unittest.TestCase):
    def test_severity_below_minimum_is_rejected(self) -> None:
        alerter = Alerter(AlertConfig(min_severity="medium"), deliver=False)
        self.assertFalse(alerter.notify(_alert(severity="info")))
        self.assertEqual(alerter.rejected, 1)
        self.assertEqual(alerter.sent, [])

    def test_high_severity_is_accepted(self) -> None:
        alerter = Alerter(AlertConfig(min_severity="medium"), deliver=False)
        self.assertTrue(alerter.notify(_alert(severity="high")))
        self.assertEqual(len(alerter.sent), 1)

    def test_duplicate_within_window_suppressed(self) -> None:
        alerter = Alerter(AlertConfig(dedupe_window_seconds=120), deliver=False)
        self.assertTrue(alerter.notify(_alert()))
        self.assertFalse(alerter.notify(_alert()))
        self.assertEqual(len(alerter.sent), 1)
        self.assertEqual(alerter.suppressed, 1)

    def test_distinct_events_not_deduped(self) -> None:
        alerter = Alerter(AlertConfig(dedupe_window_seconds=120), deliver=False)
        self.assertTrue(alerter.notify(_alert(event="http_request")))
        self.assertTrue(alerter.notify(_alert(event="ssh_connection")))
        self.assertEqual(len(alerter.sent), 2)

    def test_distinct_ips_not_deduped(self) -> None:
        alerter = Alerter(AlertConfig(dedupe_window_seconds=120), deliver=False)
        self.assertTrue(alerter.notify(_alert(source_ip="10.0.0.1")))
        self.assertTrue(alerter.notify(_alert(source_ip="10.0.0.2")))
        self.assertEqual(len(alerter.sent), 2)

    def test_per_ip_rate_limit(self) -> None:
        alerter = Alerter(
            AlertConfig(dedupe_window_seconds=120, per_ip_max_per_window=2), deliver=False
        )
        self.assertTrue(alerter.notify(_alert(event="e1")))
        self.assertTrue(alerter.notify(_alert(event="e2")))
        self.assertFalse(alerter.notify(_alert(event="e3")))
        self.assertEqual(len(alerter.sent), 2)
        self.assertEqual(alerter.suppressed, 1)

    def test_format_alert_text(self) -> None:
        text = format_alert_text(_alert(severity="high"))
        self.assertIn("[HIGH]", text)
        self.assertIn("http_request", text)
        self.assertIn("127.0.0.1", text)


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


class AlertDeliveryTests(unittest.TestCase):
    def setUp(self) -> None:
        _Receiver.received = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Receiver)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/hook"

    def _stop(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def test_webhook_receives_json(self) -> None:
        alerter = Alerter(AlertConfig(webhook_url=self.url), deliver=True)
        self.assertTrue(alerter.notify(_alert(severity="high")))
        alerter.flush(timeout=5)
        self.assertEqual(len(_Receiver.received), 1)
        self.assertEqual(_Receiver.received[0]["event"], "http_request")

    def test_dead_webhook_never_raises(self) -> None:
        alerter = Alerter(AlertConfig(webhook_url="http://127.0.0.1:1/hook"), deliver=True)
        self.assertTrue(alerter.notify(_alert(severity="high")))
        alerter.flush(timeout=5)  # must not raise


if __name__ == "__main__":
    unittest.main()
