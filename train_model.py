#!/usr/bin/env python3
"""Train the SentinelIDS models.

Offline (bundled synthetic corpus)::

    python train_model.py
    python train_model.py --model rf --rows 8000

On a real labelled flow dataset (NSL-KDD, KDD Cup '99, CICIDS-style CSV)::

    python train_model.py --csv data/nsl-kdd/train.csv

The result is written to ``models/ids_model.joblib`` plus
``models/metrics.json``.  If the file is missing, the web app trains it
automatically on first launch.
"""

from __future__ import annotations

import argparse
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from ids_engine.model import CLASSIFIER_KINDS  # noqa: E402
from ids_engine.training import MODEL_FILENAME, train_and_save  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Train the SentinelIDS intrusion-detection models."
    )
    parser.add_argument("--csv", help="labelled flow CSV (default: synthetic corpus)")
    parser.add_argument("--model", choices=CLASSIFIER_KINDS, default="logreg",
                        help="classifier kind (default: logreg, explainable)")
    parser.add_argument("--rows", type=int, default=6000,
                        help="synthetic corpus size (default: 6000)")
    parser.add_argument("--seed", type=int, default=42,
                        help="synthetic corpus seed (default: 42)")
    parser.add_argument("--test-size", type=float, default=0.25,
                        help="hold-out fraction (default: 0.25)")
    parser.add_argument("--out", default=os.path.join(BASE_DIR, "models"),
                        help="output directory (default: ./models)")
    args = parser.parse_args(argv)

    source = args.csv or "the synthetic corpus"
    print(f"Training SentinelIDS ({args.model}) on {source} ...")
    try:
        metrics = train_and_save(
            model_dir=args.out,
            csv_path=args.csv,
            kind=args.model,
            seed=args.seed,
            rows=args.rows,
            test_size=args.test_size,
            verbose=True,
        )
    except (ValueError, FileNotFoundError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1

    print(f"Saved model to {os.path.join(args.out, MODEL_FILENAME)}")
    print(f"  accuracy={metrics['accuracy']:.3f}  macro_f1={metrics['macro_f1']:.3f}  "
          f"anomaly_auc={metrics.get('anomaly_auc', 0):.3f}")
    print(f"  features={metrics['feature_count']}  rows={metrics['rows']}  "
          f"trained_at={metrics['trained_at']}")
    print("Run `python app.py` to open the dashboard.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
