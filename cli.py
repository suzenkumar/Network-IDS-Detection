#!/usr/bin/env python3
"""Command-line interface for SentinelIDS (same engine as the dashboard).

    python cli.py demo                     analyse the built-in demo corpus
    python cli.py csv data/nsl-kdd.csv     analyse a flow CSV file
    python cli.py live                     watch this computer's live traffic
    python cli.py status                   model file, kind and metrics

Use ``python train_model.py`` to (re)train.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from queue import Empty

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# Windows consoles default to cp1252, which cannot encode '→' or the ANSI
# block characters used in the risk bar — never let that crash a report.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from ids_engine import ModelStore, analyze_records, demo_flows, load_csv  # noqa: E402

MODEL_DIR = os.path.join(BASE_DIR, "models")

LEVEL_TAG = {
    "info": "\033[32mINFO\033[0m",
    "low": "\033[36mLOW\033[0m",
    "medium": "\033[33mMED\033[0m",
    "high": "\033[38;5;208mHIGH\033[0m",
    "critical": "\033[31mCRIT\033[0m",
}


def risk_bar(score: int) -> str:
    filled = max(0, min(10, round(score / 10)))
    return "\033[90m" + "█" * filled + "\033[37m" + "░" * (10 - filled) + "\033[0m"


def print_report(report: dict, limit: int = 15) -> None:
    summary = report["summary"]
    print("=" * 74)
    print(f"ANALYSED {summary['flows']} flows from {report['source']}")
    print(f"  malicious: {summary['malicious']} ({summary['malicious_pct']}%)   "
          f"alerts: {summary['alerts']}   avg risk: {summary['avg_risk']}/100")
    print(f"  levels: info={summary['info']}  low={summary['low']}  "
          f"medium={summary['medium']}  high={summary['high']}  "
          f"critical={summary['critical']}")
    metrics = report["model"].get("metrics") or {}
    if metrics:
        print(f"  model: {report['model']['kind']}  "
              f"accuracy={metrics.get('accuracy', '-')}  "
              f"macro_f1={metrics.get('macro_f1', '-')}  "
              f"anomaly_auc={metrics.get('anomaly_auc', '-')}")
    print("=" * 74)

    if not report["alerts"]:
        print("No alerts raised.")
        return

    print(f"\nTop {min(limit, len(report['alerts']))} alerts "
          f"({report['alerts_total']} total)\n")
    for alert in report["alerts"][:limit]:
        tag = LEVEL_TAG.get(alert["risk_level"], alert["risk_level"].upper())
        print(f"  [{tag}] {risk_bar(alert['risk_score'])} {alert['risk_score']:>3}/100  "
              f"{alert['src_ip']} → {alert['dst_ip']}  {alert['protocol']}/{alert['service']}")
        print(f"          {alert['category_label']}  "
              f"confidence={alert['confidence']:.2f}  "
              f"anomaly={alert['anomaly_score']:.2f}")
        for reason in alert["reasons"][:2]:
            print(f"          • {reason}")
        print()


def run_live(store, args) -> int:
    """Terminal live feed — same engine as the dashboard's live monitor."""
    from ids_engine.live import CaptureUnavailable, LiveDetector

    detector = LiveDetector(store, backend=args.backend,
                            interval=args.interval,
                            log_dir=os.path.join(BASE_DIR, "logs"))
    try:
        status = detector.start()
    except CaptureUnavailable as exc:
        print(f"[error] {exc}", file=sys.stderr)
        print("Hint: use --backend system (no driver needed).", file=sys.stderr)
        return 1

    print(f"LIVE · backend={status['backend']}  interval={detector.interval}s")
    print(f"      {status['backend_note']}")
    print("Watching this computer's traffic — Ctrl+C to stop.\n")

    events = detector.subscribe()
    started = time.time()
    try:
        while True:
            if args.duration and time.time() - started > args.duration:
                break
            try:
                message = events.get(timeout=1.0)
            except Empty:
                continue
            if message["type"] != "tick":
                continue
            data = message["data"]
            report, tick = data["report"], data["status"]
            if report:
                summary = report["summary"]
                print(f"[tick {tick['ticks']:>3}] window: {summary['flows']:>4} flows  "
                      f"{summary['alerts']:>3} alerts  "
                      f"({tick['flows_seen']} flows seen · "
                      f"{tick['alerts_total']} alerts total)")
            for alert in data["new_alerts"][:args.limit]:
                tag = LEVEL_TAG.get(alert["risk_level"],
                                    alert["risk_level"].upper())
                print(f"  [{tag}] {risk_bar(alert['risk_score'])} "
                      f"{alert['risk_score']:>3}/100  "
                      f"{alert['src_ip']} → {alert['dst_ip']}  "
                      f"{alert['protocol']}/{alert['service']}  "
                      f"{alert['category_label']}")
                for reason in alert["reasons"][:2]:
                    print(f"          • {reason}")
    except KeyboardInterrupt:
        print("\nstopping …")
    finally:
        final = detector.stop()
        print(f"stopped · {final['ticks']} ticks · "
              f"{final['flows_seen']} flows · {final['alerts_total']} alerts")
        if detector.last_error:
            print(f"[warn] {detector.last_error}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SentinelIDS command-line interface.")
    sub = parser.add_subparsers(dest="command")

    demo = sub.add_parser("demo", help="analyse the built-in synthetic corpus")
    demo.add_argument("--rows", type=int, default=800)
    demo.add_argument("--limit", type=int, default=15, help="alerts to print")

    csv_cmd = sub.add_parser("csv", help="analyse a flow CSV file")
    csv_cmd.add_argument("path")
    csv_cmd.add_argument("--limit", type=int, default=15)

    live_cmd = sub.add_parser("live", help="watch this computer's live network traffic")
    live_cmd.add_argument("--backend", choices=["auto", "system", "scapy"],
                          default="auto")
    live_cmd.add_argument("--interval", type=float, default=3.0,
                          help="seconds per detection window")
    live_cmd.add_argument("--duration", type=float, default=0.0,
                          help="stop after N seconds (0 = run until Ctrl+C)")
    live_cmd.add_argument("--limit", type=int, default=5,
                          help="new alerts to print per tick")

    sub.add_parser("status", help="show model status")

    args = parser.parse_args(argv)
    if args.command in (None, "status"):
        store = ModelStore(MODEL_DIR)
        status = store.status()
        print(f"model file : {'present' if status['model_file'] else 'MISSING'}")
        print(f"trained    : {status['trained']}")
        if status.get("kind"):
            print(f"classifier : {status['kind']}")
        if status.get("feature_count"):
            print(f"features   : {status['feature_count']}")
        if status.get("metrics"):
            metrics = status["metrics"]
            print(f"accuracy   : {metrics.get('accuracy')}   macro_f1: {metrics.get('macro_f1')}")
            print(f"source     : {metrics.get('source')}")
        if not status["model_file"]:
            print("\nRun `python train_model.py` to create it.")
        return 0

    store = ModelStore(MODEL_DIR)

    if args.command == "live":
        return run_live(store, args)

    try:
        if args.command == "demo":
            records = demo_flows(n=max(50, args.rows))
            source = f"demo ({args.rows} rows)"
        else:
            if not os.path.exists(args.path):
                print(f"[error] file not found: {args.path}", file=sys.stderr)
                return 1
            records = load_csv(args.path)
            source = args.path
        report = analyze_records(records, store, source=source)
    except (ValueError, FileNotFoundError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1

    print_report(report, limit=args.limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
