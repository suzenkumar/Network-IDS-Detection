#!/usr/bin/env python3
"""Flask web application for SentinelIDS — AI-powered intrusion detection.

Run:
    python app.py
then open http://127.0.0.1:5000

Endpoints
---------
GET  /                 dashboard (Chart.js, alerts table)
GET  /api/health       model status + metrics
GET  /api/demo         analyse the bundled synthetic flow corpus
GET  /api/examples     sample flow records (for curl / experiments)
POST /api/analyze      JSON  { "flows": [ {...}, ... ] }  -> full report
POST /api/analyze-csv  multipart CSV upload               -> full report

Real-time monitoring (this computer's own traffic):
GET  /api/live/status   backend, uptime, counts, active connections
POST /api/live/start    { "backend": "auto|scapy|system", "interval": 3 }
POST /api/live/stop
GET  /api/live/stream   Server-Sent Events: tick {report,status,new_alerts}

Every analysis returns the same report: summary KPIs, chart aggregates,
ground-truth evaluation (when labels exist) and ranked alerts with risk
levels, behavioural reasons and model contributions.
"""

from __future__ import annotations

import atexit
import json
import os
import queue as queue_module

from flask import Flask, Response, jsonify, render_template, request

from ids_engine import ModelStore, analyze_records, load_csv
from ids_engine.live import BACKENDS, CaptureUnavailable, LiveDetector
from ids_engine.synthetic import demo_flows

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MAX_PAYLOAD_BYTES = 64 * 1024 * 1024   # CSV exports get big fast
MAX_JSON_FLOWS = 200_000
MAX_DEMO_ROWS = 20_000

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_PAYLOAD_BYTES

#: Model artefacts live next to this file in ``models/``.
STORE = ModelStore(os.path.join(BASE_DIR, "models"))

#: One live detector shared by the API (started/stopped from the dashboard).
LIVE = LiveDetector(STORE, log_dir=os.path.join(BASE_DIR, "logs"))

atexit.register(LIVE.stop)


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

@app.get("/")
def index():
    return render_template("index.html")


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------

@app.get("/api/health")
def health():
    status = STORE.status()
    status["ok"] = True
    status["version"] = "1.0.0"
    return jsonify(status)


@app.get("/api/examples")
def examples():
    """A handful of demo flows so the API is usable without real data."""
    return jsonify({"flows": demo_flows(n=5, seed=11)})


@app.get("/api/demo")
def demo():
    """Analyse the bundled synthetic corpus (offline, one click)."""
    rows = max(50, min(MAX_DEMO_ROWS, int(request.args.get("rows", 800))))
    try:
        report = analyze_records(demo_flows(n=rows), STORE, source="demo")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # pragma: no cover - defensive
        return jsonify({"error": f"Analysis failed: {exc}"}), 500
    return jsonify(report)


@app.post("/api/analyze")
def analyze_json():
    payload = request.get_json(silent=True) or {}
    flows = payload.get("flows")
    if isinstance(flows, dict):          # accept {"flows": {...}} as well
        flows = [flows]
    if not isinstance(flows, list) or not flows:
        return jsonify({"error": "Provide a JSON body like {\"flows\": [ ... ]}."}), 400
    if len(flows) > MAX_JSON_FLOWS:
        return jsonify({"error": f"Too many flows (max {MAX_JSON_FLOWS})."}), 400

    try:
        report = analyze_records(flows, STORE, source="json")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # pragma: no cover - defensive
        return jsonify({"error": f"Analysis failed: {exc}"}), 500
    return jsonify(report)


@app.post("/api/analyze-csv")
def analyze_csv():
    upload = request.files.get("file") or request.files.get("csv")
    if upload is None or not upload.filename:
        return jsonify({"error": "Attach a CSV file in the 'file' field."}), 400
    if not upload.filename.lower().endswith(".csv"):
        return jsonify({"error": "Only .csv files are supported."}), 400

    try:
        records = load_csv(upload.stream)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    try:
        report = analyze_records(records, STORE, source=os.path.basename(upload.filename))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # pragma: no cover - defensive
        return jsonify({"error": f"Analysis failed: {exc}"}), 500
    return jsonify(report)


# --------------------------------------------------------------------------
# Real-time monitoring
# --------------------------------------------------------------------------

@app.get("/api/live/status")
def live_status():
    return jsonify(LIVE.snapshot())


@app.post("/api/live/start")
def live_start():
    payload = request.get_json(silent=True) or {}
    backend = str(payload.get("backend", "auto")).lower()
    if backend not in BACKENDS:
        return jsonify({"error": f"Unknown backend '{backend}'. "
                                 f"Choose one of: {', '.join(BACKENDS)}."}), 400
    try:
        interval = float(payload.get("interval", 3.0))
    except (TypeError, ValueError):
        interval = 3.0
    interval = max(1.0, min(30.0, interval))

    try:
        status = LIVE.configure_and_start(backend=backend, interval=interval)
    except CaptureUnavailable as exc:
        return jsonify({"error": str(exc),
                        "hint": "Try the 'system' backend — it needs no driver."}), 503
    if status["last_error"]:
        return jsonify({"error": status["last_error"],
                        "hint": "Try the 'system' backend — it needs no driver."}), 503
    return jsonify(status)


@app.post("/api/live/stop")
def live_stop():
    return jsonify(LIVE.stop())


@app.get("/api/live/stream")
def live_stream():
    """Server-Sent Events: one 'tick' per detection window."""
    if not LIVE.running:
        return jsonify({"error": "Live monitor is not running."}), 409
    events = LIVE.subscribe()

    def generate():
        try:
            yield "retry: 3000\n\n: connected\n\n"
            while True:
                if not LIVE.running and events.empty():
                    yield "event: stopped\ndata: {}\n\n"
                    break
                try:
                    message = events.get(timeout=10)
                except queue_module.Empty:
                    yield ": heartbeat\n\n"
                    continue
                yield (f"event: {message['type']}\n"
                       f"data: {json.dumps(message['data'])}\n\n")
        except GeneratorExit:
            pass
        finally:
            LIVE.unsubscribe(events)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "File too large (max 64 MB)."}), 413


@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Not found."}), 404


if __name__ == "__main__":
    # Warm the model up on first launch so the first request is fast.
    try:
        STORE.ensure()
        print("[ok] model ready")
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[warn] could not load/train the model: {exc}")

    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=bool(os.environ.get("FLASK_DEBUG")))
