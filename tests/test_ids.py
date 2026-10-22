"""Unit and API tests for SentinelIDS.

Run from the project root::

    python -m unittest discover -s tests -v
    python -m pytest -q
"""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from ids_engine import ModelStore, analyze_records, demo_flows  # noqa: E402
from ids_engine.dataset import load_csv, records_to_frame  # noqa: E402
from ids_engine.detector import LEVELS, evaluate_flow, score_flow  # noqa: E402
from ids_engine.features import (  # noqa: E402
    FEATURE_COLUMNS,
    map_label,
    resolve_column,
)
from ids_engine.synthetic import generate_flows  # noqa: E402


# --------------------------------------------------------------------------
# Feature schema
# --------------------------------------------------------------------------

class FeatureTests(unittest.TestCase):
    def test_label_mapping_covers_published_attack_names(self):
        cases = {
            "normal": "normal", "BENIGN": "normal", "benign": "normal",
            "neptune": "dos", "DDoS": "dos", "smurf": "dos", "DoS Hulk": "dos",
            "portsweep": "probe", "PortScan": "probe", "nmap": "probe",
            "guess_passwd": "r2l", "Web Attack Brute Force": "r2l",
            "buffer_overflow": "u2r", "Infiltration": "u2r", "rootkit": "u2r",
            "malicious": "unknown", "something-new": "unknown",
        }
        for raw, expected in cases.items():
            self.assertEqual(map_label(raw), expected, f"label {raw!r}")

    def test_empty_labels_are_ignored(self):
        self.assertIsNone(map_label(None))
        self.assertIsNone(map_label(""))
        self.assertIsNone(map_label("  "))
        self.assertIsNone(map_label("NaN"))

    def test_column_aliasing(self):
        self.assertEqual(resolve_column("duration"), "duration")
        self.assertEqual(resolve_column("protocol_type"), "protocol_type")
        self.assertEqual(resolve_column("Src Bytes"), "src_bytes")
        self.assertEqual(resolve_column("sourcebytes"), "src_bytes")
        self.assertEqual(resolve_column("Total Length of Fwd Packets"), "src_bytes")
        self.assertEqual(resolve_column("Total Length of Bwd Packets"), "dst_bytes")
        self.assertEqual(resolve_column("Label"), "label")
        self.assertEqual(resolve_column("class"), "label")
        self.assertEqual(resolve_column("Source IP"), "src_ip")
        self.assertIsNone(resolve_column("definitely_not_a_column"))

    def test_every_canonical_feature_resolves_to_itself(self):
        for name in FEATURE_COLUMNS:
            self.assertEqual(resolve_column(name), name)


# --------------------------------------------------------------------------
# Dataset normalisation
# --------------------------------------------------------------------------

class DatasetTests(unittest.TestCase):
    def test_records_to_frame_maps_aliases_and_labels(self):
        frame, info = records_to_frame([
            {"Duration": 1.5, "Protocol": "tcp", "Src Bytes": 100,
             "Total Bwd Packets": 200, "Class": "normal"},
            {"duration": 0.0, "protocol": "tcp", "src_bytes": 0,
             "dst_bytes": 0, "class": "neptune"},
        ])
        self.assertEqual(info["rows"], 2)
        self.assertTrue(info["has_labels"])
        for column in FEATURE_COLUMNS:
            self.assertIn(column, frame.columns)
        self.assertEqual(frame["label"].tolist(), ["normal", "dos"])
        self.assertEqual(info["feature_count"], 4)

    def test_missing_columns_do_not_break_the_frame(self):
        frame, info = records_to_frame([{"duration": 0.5, "protocol_type": "udp"}])
        self.assertEqual(list(frame["label"]) if "label" in frame else [], [])
        self.assertAlmostEqual(float(frame["_coverage"].iloc[0]), 2 / len(FEATURE_COLUMNS))
        self.assertLess(info["coverage"], 0.2)

    def test_unrecognised_records_are_rejected(self):
        with self.assertRaises(ValueError):
            records_to_frame([{"colour": "red", "size": "large"}])

    def test_load_csv_roundtrip(self):
        csv_text = (
            "duration,protocol_type,src_bytes,dst_bytes,label\n"
            "0.1,tcp,100,200,normal\n"
            "0.0,tcp,0,0,neptune\n"
        )
        records = load_csv(io.StringIO(csv_text))
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["label"], "normal")

    def test_load_csv_rejects_empty_file(self):
        with self.assertRaises(ValueError):
            load_csv(io.StringIO(""))

    def test_load_csv_rejects_header_only(self):
        with self.assertRaises(ValueError):
            load_csv(io.StringIO("duration,label\n"))


# --------------------------------------------------------------------------
# Rules and scoring
# --------------------------------------------------------------------------

def _flow(**overrides) -> dict:
    row = {name: 0.0 for name in FEATURE_COLUMNS}
    row.update({
        "duration": 0.01, "protocol_type": "tcp", "service": "http", "flag": "sf",
        "src_bytes": 100.0, "dst_bytes": 200.0, "count": 3.0, "logged_in": 1.0,
        "same_srv_rate": 1.0, "dst_host_count": 5.0, "dst_host_same_srv_rate": 1.0,
    })
    row.update(overrides)
    return row


class RuleTests(unittest.TestCase):
    def test_syn_flood_signature(self):
        findings = evaluate_flow(_flow(serror_rate=1.0, srv_serror_rate=1.0,
                                       count=400, dst_host_serror_rate=1.0))
        codes = [f.code for f in findings]
        self.assertIn("syn_flood", codes)
        self.assertIn("connection_flood", codes)

    def test_port_scan_signature(self):
        findings = evaluate_flow(_flow(count=60, same_srv_rate=0.05,
                                       diff_srv_rate=0.9, dst_host_count=250,
                                       dst_host_same_srv_rate=0.02))
        codes = [f.code for f in findings]
        self.assertIn("service_sweep", codes)
        self.assertIn("host_scan", codes)

    def test_brute_force_and_privilege_escalation(self):
        findings = evaluate_flow(_flow(num_failed_logins=6, root_shell=1,
                                       num_compromised=2))
        codes = [f.code for f in findings]
        self.assertIn("brute_force", codes)
        self.assertIn("privilege_escalation", codes)

    def test_clean_flow_has_no_findings(self):
        self.assertEqual(evaluate_flow(_flow()), [])

    def test_partial_coverage_is_reported(self):
        findings = evaluate_flow(_flow(), coverage=0.3)
        self.assertIn("partial_data", [f.code for f in findings])

    def test_confident_attack_gets_a_severity_floor(self):
        prediction = {"label": "u2r", "confidence": 0.95,
                      "probabilities": {"u2r": 0.95, "normal": 0.05},
                      "anomaly_score": 0.5}
        score = score_flow(prediction, [])
        self.assertIn(score["risk_level"], {"high", "critical"})

    def test_clean_benign_flow_is_not_an_alert(self):
        prediction = {"label": "normal", "confidence": 0.99,
                      "probabilities": {"normal": 0.99},
                      "anomaly_score": 0.2}
        score = score_flow(prediction, [])
        self.assertEqual(score["risk_level"], "info")


# --------------------------------------------------------------------------
# Model + full analysis (one training run for the whole class)
# --------------------------------------------------------------------------

class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="ids-test-")
        cls.store = ModelStore(cls.tmp)
        cls.store.ensure()
        cls.report = analyze_records(demo_flows(n=500), cls.store, source="test")

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_model_trains_with_good_metrics(self):
        metrics = self.store.model.metrics
        self.assertTrue(self.store.model.trained)
        self.assertGreaterEqual(metrics["accuracy"], 0.9)
        self.assertGreaterEqual(metrics["macro_f1"], 0.9)
        self.assertGreaterEqual(metrics.get("anomaly_auc", 0), 0.8)
        self.assertEqual(metrics["feature_count"], len(FEATURE_COLUMNS))

    def test_report_structure(self):
        report = self.report
        for key in ("summary", "charts", "model", "dataset", "alerts", "evaluation"):
            self.assertIn(key, report)
        self.assertEqual(report["summary"]["flows"], 500)
        levels = report["charts"]["risk"]
        self.assertEqual(sum(entry["count"] for entry in levels), 500)
        self.assertGreater(report["summary"]["alerts"], 0)
        self.assertGreater(report["alerts_total"], 0)
        self.assertLessEqual(len(report["alerts"]), report["alerts_total"])

    def test_every_alert_has_a_valid_risk_level(self):
        for alert in self.report["alerts"]:
            self.assertIn(alert["risk_level"], LEVELS)
            self.assertNotEqual(alert["risk_level"], "info")
            self.assertTrue(alert["reasons"])
            self.assertGreaterEqual(alert["risk_score"], 0)
            self.assertLessEqual(alert["risk_score"], 100)

    def test_majority_of_benign_flows_are_not_alerts(self):
        summary = self.report["summary"]
        if summary["benign"]:
            self.assertGreaterEqual(summary["info"] / summary["benign"], 0.6)

    def test_explanations_are_provided_for_logreg(self):
        with_signs = [a for a in self.report["alerts"] if a["ml_signs"]]
        self.assertTrue(with_signs, "expected local model contributions")

    def test_chart_aggregates_are_complete(self):
        charts = self.report["charts"]
        self.assertEqual(len(charts["timeline"]), 12)
        self.assertTrue(charts["categories"])
        self.assertTrue(charts["protocols"])
        self.assertTrue(charts["services"])
        protocol_total = sum(p["benign"] + p["attack"] for p in charts["protocols"])
        self.assertEqual(protocol_total, 500)

    def test_ground_truth_evaluation_present_for_labelled_data(self):
        evaluation = self.report["evaluation"]
        self.assertIsNotNone(evaluation)
        self.assertEqual(evaluation["rows"], 500)
        self.assertGreaterEqual(evaluation["accuracy"], 0.9)
        self.assertIn("normal", evaluation["labels"])

    def test_alert_cap_is_stratified(self):
        report = analyze_records(generate_flows(n=4000, seed=9), self.store, source="big")
        self.assertLessEqual(len(report["alerts"]), 500)
        self.assertLessEqual(report["alerts_returned"], report["alerts_total"])
        if report["alerts_returned"] < report["alerts_total"]:
            shown = {alert["risk_level"] for alert in report["alerts"]}
            self.assertGreater(len(shown), 1, "cap must keep several levels visible")


# --------------------------------------------------------------------------
# Flask API
# --------------------------------------------------------------------------

class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as app_module
        cls.app_module = app_module
        cls.client = app_module.app.test_client()
        app_module.STORE.ensure()

    def test_health(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["trained"])

    def test_index_page(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SentinelIDS", response.data)

    def test_demo_endpoint(self):
        response = self.client.get("/api/demo?rows=120")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["summary"]["flows"], 120)
        self.assertIn("alerts", payload)

    def test_analyze_requires_flows(self):
        response = self.client.post("/api/analyze", json={})
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_analyze_rejects_unknown_columns(self):
        response = self.client.post("/api/analyze", json={"flows": [{"colour": "red"}]})
        self.assertEqual(response.status_code, 400)

    def test_analyze_accepts_valid_flows(self):
        flows = [
            {"duration": 0.02, "protocol_type": "tcp", "service": "http",
             "src_bytes": 200, "dst_bytes": 4000, "count": 4, "label": "normal"},
            {"duration": 0.0, "protocol_type": "tcp", "service": "private",
             "src_bytes": 0, "dst_bytes": 0, "count": 400, "serror_rate": 1.0,
             "label": "neptune"},
        ]
        response = self.client.post("/api/analyze", json={"flows": flows})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["summary"]["flows"], 2)
        self.assertGreaterEqual(payload["alerts_total"], 1)

    def test_csv_upload(self):
        csv_text = (
            "duration,protocol_type,service,flag,src_bytes,dst_bytes,count,"
            "serror_rate,dst_host_count,label\n"
            "0.01,tcp,http,SF,250,4000,4,0.0,6,normal\n"
            "0.00,tcp,private,S0,0,0,320,1.0,255,neptune\n"
        )
        data = {"file": (io.BytesIO(csv_text.encode()), "sample.csv")}
        response = self.client.post("/api/analyze-csv", data=data,
                                    content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["summary"]["flows"], 2)

    def test_csv_upload_requires_csv_extension(self):
        data = {"file": (io.BytesIO(b"a,b\n1,2\n"), "notes.txt")}
        response = self.client.post("/api/analyze-csv", data=data,
                                    content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)

    def test_csv_upload_requires_a_file(self):
        response = self.client.post("/api/analyze-csv", data={},
                                    content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)

    def test_unknown_route_returns_json_404(self):
        response = self.client.get("/nope")
        self.assertEqual(response.status_code, 404)
        self.assertIn("error", response.get_json())


if __name__ == "__main__":
    unittest.main(verbosity=2)
