"""Tests for the real-time monitoring engine (ids_engine.live).

Covers the window-context feature derivation, both capture backends'
record building, the LiveDetector loop (with a fake monitor), the JSONL
alert log, and the Flask live endpoints.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from ids_engine import ModelStore  # noqa: E402
from ids_engine.live import (  # noqa: E402
    CaptureUnavailable,
    LiveDetector,
    ScapyFlowMonitor,
    SystemFlowMonitor,
    alert_fingerprint,
    build_monitor,
    enrich_window,
)
from ids_engine.synthetic import generate_flows  # noqa: E402

try:
    from scapy.layers.inet import IP, TCP
    SCAPY_OK = True
except ImportError:  # pragma: no cover
    SCAPY_OK = False


def make_store() -> ModelStore:
    store = ModelStore(os.path.join(ROOT, "models"))
    store.ensure()
    return store


class EnrichWindowTests(unittest.TestCase):
    """Window-context features drive the scan/flood rules."""

    def _record(self, dst, port):
        return {"dst_ip": dst, "_port": port, "protocol_type": "tcp",
                "flag": "SF", "timestamp": time.time()}

    def test_count_and_service_rates(self):
        records = [
            self._record("10.0.0.9", 80),    # same host:port x2
            self._record("10.0.0.9", 80),
            self._record("10.0.0.9", 22),    # scan! second port on same host
            self._record("10.0.0.7", 443),
        ]
        enrich_window(records)
        self.assertEqual(records[0]["count"], 2)             # host:port hits
        self.assertEqual(records[0]["dst_host_count"], 3)    # conns to that host
        self.assertEqual(records[0]["dst_host_srv_count"], 2)
        self.assertAlmostEqual(records[0]["same_srv_rate"], round(2 / 3, 4))
        self.assertAlmostEqual(records[0]["dst_host_diff_srv_rate"], round(2 / 3, 4))
        self.assertEqual(records[2]["count"], 1)
        self.assertEqual(records[2]["dst_host_serror_rate"], 0.0)

    def test_error_rates_follow_flags(self):
        records = [self._record("10.0.0.9", 80),
                   self._record("10.0.0.9", 80)]
        records[0]["flag"] = "S0"
        records[1]["flag"] = "SF"
        enrich_window(records)
        self.assertAlmostEqual(records[0]["dst_host_serror_rate"], 0.5)
        self.assertAlmostEqual(records[1]["dst_host_rerror_rate"], 0.0)


class FingerprintTests(unittest.TestCase):
    def test_stable_and_distinct(self):
        a = {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "timestamp": 123,
             "protocol": "tcp", "service": "http", "risk_level": "high"}
        b = dict(a)
        self.assertEqual(alert_fingerprint(a), alert_fingerprint(b))
        b["risk_level"] = "critical"
        self.assertNotEqual(alert_fingerprint(a), alert_fingerprint(b))


class BackendTests(unittest.TestCase):
    def test_build_system_backend(self):
        monitor = build_monitor("system", interval=2)
        self.assertIsInstance(monitor, SystemFlowMonitor)

    def test_build_scapy_backend(self):
        monitor = build_monitor("scapy", interval=2)
        self.assertIsInstance(monitor, ScapyFlowMonitor)

    def test_unknown_backend_raises(self):
        with self.assertRaises(CaptureUnavailable):
            build_monitor("carrier-pigeon")

    def test_system_poll_sees_connections(self):
        monitor = SystemFlowMonitor(interval=2)
        records, conns = monitor.poll()
        self.assertIsInstance(records, list)
        self.assertIsInstance(conns, list)
        for conn in conns[:3]:
            self.assertIn("remote", conn)
            self.assertIn("process", conn)


@unittest.skipUnless(SCAPY_OK, "scapy not installed")
class ScapyFoldTests(unittest.TestCase):
    """Packets are folded into flow windows without any live capture."""

    def test_unanswered_syn_becomes_s0(self):
        monitor = ScapyFlowMonitor(interval=1)
        monitor._on_packet(IP(src="10.0.0.5", dst="93.184.216.34")
                           / TCP(sport=51000, dport=80, flags="S", seq=1))
        records, conns = monitor.poll()
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["flag"], "S0")          # SYN with no reply
        self.assertEqual(record["service"], "http")
        self.assertGreater(record["src_bytes"], 0)
        self.assertEqual(record["dst_bytes"], 0)
        self.assertTrue(record["_failed"])
        self.assertEqual(conns[0]["remote"], "93.184.216.34:80")

    def test_completed_handshake_becomes_sf(self):
        monitor = ScapyFlowMonitor(interval=1)
        monitor._on_packet(IP(src="10.0.0.5", dst="93.184.216.34")
                           / TCP(sport=51000, dport=80, flags="S", seq=1))
        monitor._on_packet(IP(src="93.184.216.34", dst="10.0.0.5")
                           / TCP(sport=80, dport=51000, flags="SA", seq=100, ack=2))
        monitor._on_packet(IP(src="10.0.0.5", dst="93.184.216.34")
                           / TCP(sport=51000, dport=80, flags="A", seq=2, ack=101)
                           / (b"x" * 100))
        records, _ = monitor.poll()
        self.assertEqual(len(records), 1)               # all three folded into one flow
        record = records[0]
        self.assertEqual(record["flag"], "SF")
        self.assertGreater(record["dst_bytes"], 0)      # SYN-ACK counted as reply
        self.assertFalse(record["_failed"])

    def test_land_attack_detected(self):
        monitor = ScapyFlowMonitor(interval=1)
        monitor._on_packet(IP(src="10.0.0.5", dst="10.0.0.5")
                           / TCP(sport=80, dport=80, flags="S", seq=1))
        records, _ = monitor.poll()
        self.assertEqual(records[0]["land"], 1)


class FakeMonitor:
    """Deterministic stand-in for a capture backend."""

    name = "fake"
    note = "test monitor"

    def __init__(self, batches):
        self.batches = [list(batch) for batch in batches]
        self.started = False

    def start(self):
        self.started = True

    def stop(self):
        self.started = False

    def poll(self):
        return (self.batches.pop(0) if self.batches else []), []


class LiveDetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = make_store()

    def _detector(self, batches, log_dir=None):
        fake = FakeMonitor(batches)
        detector = LiveDetector(self.store, backend="system", interval=0.25,
                                log_dir=log_dir)
        patcher = mock.patch("ids_engine.live.build_monitor",
                             return_value=fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        return detector, fake

    def test_tick_produces_report_and_dedupes(self):
        flows = generate_flows(n=30, seed=5)
        single, _ = self._detector([flows])
        try:
            single.start()
            time.sleep(1.5)
        finally:
            single.stop()
        self.assertGreater(single.alerts_total, 0)
        baseline = single.alerts_total

        # the same three batches again: duplicates must not re-alert
        detector, _ = self._detector([flows, flows, flows])
        try:
            detector.start()
            self.assertTrue(detector.running)
            time.sleep(2.0)   # several 0.25s ticks
        finally:
            detector.stop()
        self.assertFalse(detector.running)
        self.assertGreaterEqual(detector.ticks, 2)
        self.assertEqual(detector.flows_seen, 90)         # 3 batches x 30
        self.assertIsNotNone(detector.last_report)
        self.assertEqual(detector.last_report["source"], "live")
        self.assertEqual(detector.last_report["summary"]["flows"], 90)
        # identical batches re-alert nothing thanks to fingerprints
        self.assertEqual(detector.alerts_total, baseline)

    def test_new_flows_raise_new_alerts_and_are_logged(self):
        batch_a = generate_flows(n=25, seed=1)
        batch_b = generate_flows(n=25, seed=2)
        with tempfile.TemporaryDirectory() as tmp:
            detector, _ = self._detector([batch_a, batch_b], log_dir=tmp)
            try:
                detector.start()
                time.sleep(2.0)
            finally:
                detector.stop()
            self.assertGreater(detector.flows_seen, 25)
            self.assertGreater(detector.alerts_total, 0)
            files = [name for name in os.listdir(tmp)
                     if name.startswith("live-alerts-") and name.endswith(".jsonl")]
            self.assertTrue(files, "alert log not written")
            with open(os.path.join(tmp, files[0]), encoding="utf-8") as handle:
                lines = [json.loads(line) for line in handle if line.strip()]
            self.assertGreaterEqual(len(lines), 1)
            self.assertIn(lines[0]["risk_level"],
                          {"low", "medium", "high", "critical"})
            self.assertIn("reasons", lines[0])

    def test_snapshot_shape_and_broadcast(self):
        detector, _ = self._detector([generate_flows(n=10, seed=3)])
        events = detector.subscribe()
        try:
            status = detector.start()
            for key in ("running", "backend", "interval_s", "ticks",
                        "flows_seen", "alerts_total", "conns", "last_error"):
                self.assertIn(key, status)
            self.assertTrue(status["running"])
            deadline = time.time() + 3.0
            message = None
            while time.time() < deadline:
                try:
                    candidate = events.get(timeout=0.5)
                except Exception:
                    continue
                if candidate["type"] == "tick":
                    message = candidate
                    break
            self.assertIsNotNone(message, "no tick broadcast received")
            self.assertIn("report", message["data"])
            self.assertIn("status", message["data"])
            self.assertIn("new_alerts", message["data"])
        finally:
            detector.stop()
            detector.unsubscribe(events)

    def test_capture_unavailable_propagates(self):
        detector = LiveDetector(self.store, backend="scapy", interval=1)
        with mock.patch("ids_engine.live.build_monitor",
                        side_effect=CaptureUnavailable("no driver")):
            with self.assertRaises(CaptureUnavailable):
                detector.start()
        self.assertFalse(detector.running)


class LiveApiTests(unittest.TestCase):
    """Flask endpoints for the live monitor."""

    @classmethod
    def setUpClass(cls):
        import app as app_module
        cls.app = app_module.app
        cls.live = app_module.LIVE

    def setUp(self):
        self.client = self.app.test_client()
        if self.live.running:
            self.live.stop()

    def tearDown(self):
        if self.live.running:
            self.live.stop()

    def test_status_reports_idle(self):
        response = self.client.get("/api/live/status")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertFalse(payload["running"])
        self.assertIn(payload["backend"], ("auto", "system", "scapy"))

    def test_unknown_backend_rejected(self):
        response = self.client.post("/api/live/start",
                                    json={"backend": "bluetooth"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_start_and_stop(self):
        response = self.client.post("/api/live/start",
                                    json={"backend": "system", "interval": 2})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["running"])

        status = self.client.get("/api/live/status").get_json()
        self.assertTrue(status["running"])

        stopped = self.client.post("/api/live/stop").get_json()
        self.assertFalse(stopped["running"])

    def test_stream_rejects_when_idle(self):
        response = self.client.get("/api/live/stream")
        self.assertEqual(response.status_code, 409)

    def test_stream_emits_tick_then_stopped(self):
        started = self.client.post("/api/live/start",
                                   json={"backend": "system", "interval": 1})
        self.assertEqual(started.status_code, 200)
        try:
            response = self.client.get("/api/live/stream", buffered=False)
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.mimetype.startswith("text/event-stream"))
            # stop mid-stream -> the generator must end with a 'stopped' event
            self.live.stop()
            body = response.get_data(as_text=True)
        finally:
            if self.live.running:
                self.live.stop()
        self.assertTrue("event: tick" in body or ": heartbeat" in body,
                        body[:200])
        self.assertIn("event: stopped", body)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
