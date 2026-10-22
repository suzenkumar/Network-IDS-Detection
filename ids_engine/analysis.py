"""End-to-end analysis: raw flows -> ML verdicts -> alerts -> dashboard stats.

:func:`analyze_records` is the single entry point used by the Flask API, the
CLI and the tests.  It normalises the records, runs the classifier and the
IsolationForest, applies the behavioural rules, scores every flow, and
returns one JSON-serialisable report containing:

* per-flow **alerts** with risk levels, reasons and model contributions, and
* pre-aggregated **chart data** (risk mix, attack categories, timeline,
  protocol split, top targeted services) so Chart.js never has to churn
  through the raw rows, and
* an **evaluation** block whenever the dataset carries ground-truth labels.
"""

from __future__ import annotations

from datetime import datetime, timezone

import numpy as np
import pandas as pd

from .dataset import records_to_frame
from .detector import (
    LEVELS,
    evaluate_flow,
    findings_payload,
    score_flow,
    summarise,
)
from .features import CATEGORICAL_FEATURES, CATEGORY_LABELS
from .model import ModelStore

#: Alerts returned in the payload (full statistics always cover every row).
#: Selection is stratified per risk level — see ``analyze_records``.
MAX_ALERTS = 500

#: Values shown in the alert detail drawer.
FEATURE_PREVIEW = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "count", "serror_rate", "rerror_rate", "same_srv_rate",
    "dst_host_count", "dst_host_same_srv_rate", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell",
]

TIMELINE_BUCKETS = 12


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _preview_features(row: dict) -> dict:
    """A compact, human-readable slice of the flow's raw feature values."""
    out: dict = {}
    for name in FEATURE_PREVIEW:
        if name not in row:
            continue
        value = row[name]
        if isinstance(value, float):
            if value != value:  # NaN
                continue
            value = round(value, 3) if abs(value) < 1000 else int(value)
        if name in CATEGORICAL_FEATURES:
            value = str(value)
            if value in {"", "nan", "unknown"}:
                continue
        out[name] = value
    return out


def _timeline(frame: pd.DataFrame, levels: list[str]) -> list[dict]:
    """Bucket alerts into ~12 time slices (falls back to row order)."""
    timestamps = None
    if "timestamp" in frame.columns:
        series = frame["timestamp"]
        numeric = pd.to_numeric(series, errors="coerce")
        if numeric.notna().mean() >= 0.8:
            timestamps = pd.to_datetime(numeric, unit="s", errors="coerce", utc=True)
        else:
            parsed = pd.to_datetime(series.astype(str), errors="coerce",
                                    utc=True, format="mixed")
            if parsed.notna().mean() >= 0.8:
                timestamps = parsed

    buckets: list[dict] = []
    if timestamps is not None:
        edges = pd.qcut(timestamps.rank(method="first"), TIMELINE_BUCKETS,
                        labels=False, duplicates="drop").to_numpy()
        for bucket in range(int(np.nanmax(edges)) + 1):
            positions = np.where(edges == bucket)[0]
            if len(positions) == 0:
                continue
            entry = {"t": timestamps.iloc[positions].min().strftime("%H:%M")}
            for level in LEVELS[1:]:
                entry[level] = int(sum(1 for pos in positions
                                       if levels[pos] == level))
            buckets.append(entry)
    else:
        for part in np.array_split(np.arange(len(levels)), TIMELINE_BUCKETS):
            if len(part) == 0:
                continue
            entry = {"t": f"#{int(part[0]) + 1}"}
            for level in LEVELS[1:]:
                entry[level] = int(sum(1 for pos in part if levels[pos] == level))
            buckets.append(entry)
    return buckets


def _evaluation(frame: pd.DataFrame, predicted: list[str]) -> dict | None:
    """Compare predictions with ground truth when the dataset is labelled."""
    if "label" not in frame.columns or frame["label"].isna().all():
        return None
    y_true = frame["label"].astype(str).tolist()
    y_pred = [str(p) for p in predicted]
    labels = sorted(set(y_true) | set(y_pred))

    matrix = [[0 for _ in labels] for _ in labels]
    correct = 0
    for truth, guess in zip(y_true, y_pred):
        matrix[labels.index(truth)][labels.index(guess)] += 1
        if truth == guess:
            correct += 1

    per_class = {}
    for index, label in enumerate(labels):
        tp = matrix[index][index]
        support = sum(matrix[index])
        predicted_as = sum(matrix[row][index] for row in range(len(labels)))
        precision = tp / predicted_as if predicted_as else 0.0
        recall = tp / support if support else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if precision + recall else 0.0)
        per_class[label] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": support,
        }

    return {
        "rows": len(y_true),
        "accuracy": round(correct / len(y_true), 4),
        "labels": labels,
        "per_class": per_class,
        "confusion": {"labels": labels, "matrix": matrix},
    }


def _format_timestamp(value):
    """Render unix seconds as a readable UTC stamp; pass strings through."""
    if value is None:
        return None
    if isinstance(value, float) and value != value:  # NaN
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        text = str(value).strip()
        return text or None
    try:
        return datetime.fromtimestamp(number, tz=timezone.utc) \
            .strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return str(value)


def analyze_records(records, store: ModelStore, source: str = "api",
                    max_alerts: int = MAX_ALERTS) -> dict:
    """Full pipeline. Raises ``ValueError`` with a user-facing message."""
    frame, info = records_to_frame(records)
    model = store.model

    predictions = model.predict_frame(frame)
    labels = [p["label"] for p in predictions]
    contributions = model.contributions(frame, labels, top_k=6)

    rows = frame.to_dict(orient="records")
    alerts: list[dict] = []
    levels: list[str] = []
    risk_scores: list[int] = []
    malicious = 0

    for index, (row, prediction, signs) in enumerate(
        zip(rows, predictions, contributions)
    ):
        coverage = float(row.get("_coverage", 1.0) or 0.0)
        findings = evaluate_flow(row, coverage=coverage)
        score = score_flow(prediction, findings)
        level = score["risk_level"]
        levels.append(level)
        risk_scores.append(score["risk_score"])

        if prediction["label"] != "normal":
            malicious += 1
        if level == "info":
            continue

        meta = {key: row.get(key) for key in ("src_ip", "dst_ip", "timestamp")}
        alerts.append({
            "id": index,
            "src_ip": meta["src_ip"] or f"flow-{index}",
            "dst_ip": meta["dst_ip"] or "unknown",
            "timestamp": _format_timestamp(meta["timestamp"]),
            "protocol": str(row.get("protocol_type", "unknown")),
            "service": str(row.get("service", "unknown")),
            "flag": str(row.get("flag", "")),
            "label": prediction["label"],
            "category_label": CATEGORY_LABELS.get(
                prediction["label"], prediction["label"]
            ),
            "confidence": round(prediction["confidence"], 4),
            "probabilities": prediction["probabilities"],
            "anomaly_score": prediction["anomaly_score"],
            "risk_score": score["risk_score"],
            "risk_level": level,
            "ml_score": score["ml_score"],
            "rule_score": score["rule_score"],
            "reasons": summarise(findings, prediction, level),
            "findings": findings_payload(findings),
            "ml_signs": [
                {"token": sign["token"],
                 "value": sign["value"],
                 "contribution": sign["contribution"]}
                for sign in signs
            ],
            "features": _preview_features(row),
            "coverage": round(coverage, 3),
        })

    alerts.sort(key=lambda item: (-item["risk_score"], -item["confidence"]))
    alerts_total = len(alerts)
    if len(alerts) > max_alerts:
        # Keep a stratified sample so every risk level stays represented in
        # the table — otherwise a strict "top N by score" would hide all the
        # medium/low alerts and the risk filter would contradict the chart.
        per_level = max(1, max_alerts // len(LEVELS))
        kept: list[dict] = []
        seen: dict[str, int] = {}
        for item in alerts:
            level = item["risk_level"]
            if seen.get(level, 0) >= per_level:
                continue
            seen[level] = seen.get(level, 0) + 1
            kept.append(item)
        alerts = kept

    # -- chart aggregates -------------------------------------------------
    level_counts = {level: 0 for level in LEVELS}
    for level in levels:
        level_counts[level] += 1

    category_series = pd.Series(labels).value_counts()
    categories = [
        {
            "category": category,
            "label": CATEGORY_LABELS.get(category, category),
            "count": int(count),
            "malicious": category != "normal",
        }
        for category, count in category_series.items()
    ]

    protocol_rows = []
    for protocol in sorted(frame["protocol_type"].astype(str).unique()):
        mask = frame["protocol_type"].astype(str) == protocol
        protocol_labels = [labels[i] for i in np.where(mask.to_numpy())[0]]
        protocol_rows.append({
            "protocol": protocol,
            "benign": int(sum(1 for label in protocol_labels if label == "normal")),
            "attack": int(sum(1 for label in protocol_labels if label != "normal")),
        })

    attack_mask = [label != "normal" for label in labels]
    service_counter: dict[str, int] = {}
    for index, is_attack in enumerate(attack_mask):
        if not is_attack:
            continue
        service = str(rows[index].get("service", "unknown"))
        service_counter[service] = service_counter.get(service, 0) + 1
    services = [
        {"service": service, "count": count}
        for service, count in sorted(service_counter.items(),
                                     key=lambda item: -item[1])[:8]
    ]

    summary = {
        "flows": int(len(frame)),
        "alerts": alerts_total,
        "benign": int(len(frame) - malicious),
        "malicious": int(malicious),
        "malicious_pct": round(100.0 * malicious / len(frame), 1),
        "critical": level_counts["critical"],
        "high": level_counts["high"],
        "medium": level_counts["medium"],
        "low": level_counts["low"],
        "info": level_counts["info"],
        "avg_risk": int(round(float(np.mean(risk_scores))) if risk_scores else 0),
        "max_risk": int(max(risk_scores) if risk_scores else 0),
    }

    return {
        "source": source,
        "generated_at": _iso_now(),
        "dataset": {
            "rows": info["rows"],
            "feature_count": info["feature_count"],
            "coverage": info["coverage"],
            "has_labels": info["has_labels"],
            "ignored_columns": info["ignored_columns"],
            "dropped_rows": info["dropped_rows"],
        },
        "model": {
            "kind": model.kind,
            "classes": model.classes_,
            "feature_count": len(model.feature_columns),
            "trained_at": model.trained_at,
            "metrics": {
                key: model.metrics.get(key)
                for key in ("accuracy", "macro_f1", "anomaly_auc", "source")
                if model.metrics.get(key) is not None
            },
        },
        "summary": summary,
        "charts": {
            "risk": [
                {"level": level, "count": level_counts[level]}
                for level in LEVELS
            ],
            "categories": categories,
            "timeline": _timeline(frame, levels),
            "protocols": protocol_rows,
            "services": services,
        },
        "evaluation": _evaluation(frame, labels),
        "alerts": alerts,
        "alerts_total": alerts_total,
        "alerts_returned": len(alerts),
    }
