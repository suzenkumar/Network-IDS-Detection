"""Training, evaluation and persistence.

``train_model.py`` (and the auto-train path in :class:`ids_engine.model.ModelStore`)
both funnel through :func:`train_and_save`.

Two data sources are supported:

* the bundled synthetic corpus (default, offline), or
* **any labelled flow CSV** — ``python train_model.py --csv data/nsl-kdd.csv``.
  Columns are matched through :mod:`ids_engine.features`, so NSL-KDD headers
  work as-is.

Reported metrics: hold-out accuracy, macro F1, per-class precision / recall /
F1, the confusion matrix, and an ROC-AUC for the unsupervised anomaly
detector (normal vs. attack) — because accuracy alone is misleading on
imbalanced security data.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from .dataset import aligned_features, load_csv, records_to_frame
from .features import CATEGORICAL_FEATURES, FEATURE_COLUMNS, NUMERIC_FEATURES
from .model import IdsModel

MODEL_FILENAME = "ids_model.joblib"

#: Features must be filled in at least this many rows to be trainable.
MIN_FILL_ROWS = 5


def usable_feature_columns(frame) -> list[str]:
    """Keep only columns the dataset actually populates.

    A CICIDS-style export will not have ``dst_host_*`` columns and a
    synthetic corpus always will — training on the intersection keeps the
    imputer statistics honest instead of filling whole columns with zeros.
    """
    usable: list[str] = []
    for column in NUMERIC_FEATURES:
        if column in frame.columns and int(frame[column].notna().sum()) >= MIN_FILL_ROWS:
            usable.append(column)
    for column in CATEGORICAL_FEATURES:
        if column in frame.columns and (frame[column] != "unknown").any():
            usable.append(column)
    # Preserve canonical ordering.
    return [c for c in FEATURE_COLUMNS if c in usable]


def evaluate(model: IdsModel, X_test, y_test, y_pred) -> dict:
    """Hold-out metrics + anomaly-detector ROC-AUC."""
    y_test = np.asarray(y_test)
    y_pred = np.asarray(y_pred)
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    labels = sorted(set(y_test) | set(y_pred))

    metrics: dict = {
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "macro_f1": round(float(f1_score(y_test, y_pred, average="macro", zero_division=0)), 4),
        "n_test": int(len(y_test)),
        "labels": labels,
        "per_class": {
            label: {
                "precision": round(float(report[label]["precision"]), 4),
                "recall": round(float(report[label]["recall"]), 4),
                "f1": round(float(report[label]["f1-score"]), 4),
                "support": int(report[label]["support"]),
            }
            for label in labels if label in report
        },
        "confusion": {
            "labels": labels,
            "matrix": confusion_matrix(y_test, y_pred, labels=labels).tolist(),
        },
    }

    # Unsupervised companion evaluated as a binary normal/attack detector.
    try:
        transformed = model.anomaly_pipeline.named_steps["prep"].transform(X_test)
        scores = model.anomaly_pipeline.named_steps["iforest"].score_samples(transformed)
        binary = np.asarray([0 if str(label) == "normal" else 1 for label in y_test])
        if len(set(binary.tolist())) == 2:
            metrics["anomaly_auc"] = round(float(roc_auc_score(binary, -scores)), 4)
    except Exception:  # pragma: no cover - metric is best effort
        pass
    return metrics


def train_and_save(model_dir: str = "models",
                   csv_path: str | None = None,
                   kind: str = "logreg",
                   seed: int = 42,
                   rows: int = 6000,
                   test_size: float = 0.25,
                   verbose: bool = False) -> dict:
    """Train on a labelled CSV (or the synthetic corpus) and persist it."""
    started = time.time()

    if csv_path:
        records = load_csv(csv_path)
        source = os.path.basename(csv_path)
    else:
        from .synthetic import generate_flows
        records = generate_flows(n=rows, seed=seed)
        source = f"synthetic(seed={seed}, n={rows})"

    frame, info = records_to_frame(records)
    if not info["has_labels"]:
        raise ValueError(
            "The dataset has no usable label column. Expected a column named "
            "label / class / attack / category (values such as normal, neptune, "
            "portsweep, DDoS, BENIGN …)."
        )

    label_present = frame["label"].notna()
    frame = frame[label_present].reset_index(drop=True)
    feature_columns = usable_feature_columns(frame)
    if len(feature_columns) < 3:
        raise ValueError(
            f"Only {len(feature_columns)} usable feature columns were found. "
            "Check that the CSV uses network-flow headers (duration, protocol, "
            "src_bytes, count, serror_rate, dst_host_count …)."
        )

    y = frame["label"].astype(str)
    X = frame
    # Stratification needs >= 2 samples per class; fall back gracefully.
    stratify = y if y.value_counts().min() >= 2 else None
    if len(frame) < 20:
        raise ValueError(f"Dataset too small to train on ({len(frame)} rows).")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=stratify
    )

    model = IdsModel(kind=kind)
    model.train(X_train, y_train, feature_columns)
    y_pred = model.pipeline.predict(aligned_features(X_test, feature_columns))
    metrics = evaluate(model, X_test, y_test, y_pred)

    metrics.update({
        "kind": kind,
        "source": source,
        "rows": int(len(frame)),
        "n_train": int(len(X_train)),
        "feature_count": len(feature_columns),
        "features": feature_columns,
        "dataset_coverage": info["coverage"],
        "ignored_columns": info["ignored_columns"],
        "classes": sorted(set(y.astype(str))),
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "train_seconds": round(time.time() - started, 2),
    })
    model.metrics = metrics
    model.trained_at = metrics["trained_at"]

    os.makedirs(model_dir, exist_ok=True)
    model.save(os.path.join(model_dir, MODEL_FILENAME))
    with open(os.path.join(model_dir, "metrics.json"), "w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2)

    if verbose:
        print(f"  [{kind}] accuracy={metrics['accuracy']:.3f}  "
              f"macro_f1={metrics['macro_f1']:.3f}  "
              f"(train={metrics['n_train']}, test={metrics['n_test']}, "
              f"features={len(feature_columns)})")
        if "anomaly_auc" in metrics:
            print(f"  [iforest] anomaly ROC-AUC={metrics['anomaly_auc']:.3f}")
        print(f"  classes: {', '.join(metrics['classes'])}")
    return metrics
