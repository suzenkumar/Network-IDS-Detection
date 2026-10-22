"""Machine-learning pipelines for intrusion detection.

Two estimators are trained side by side on the same preprocessing step:

**Supervised classifier** (the "AI" verdict)
    ``ColumnTransformer`` =
      * numeric features  -> median imputer + ``StandardScaler``
      * categorical       -> most-frequent imputer + one-hot encoding
    followed by class-balanced **Logistic Regression** (default, fully
    explainable as ``coefficient x value``) or a **Random Forest**
    (``kind="rf"``, usually a little more accurate, globally explainable).

    It predicts the attack *category*
    (``normal | probe | dos | r2l | u2r | unknown``) plus per-class
    probabilities.

**Unsupervised anomaly detector** (the "unusual traffic" signal)
    An ``IsolationForest`` on the same transformed matrix.  Its
    ``score_samples`` output is standardised with statistics captured at
    fit time, then squashed through a logistic function, giving an
    ``anomaly_score`` in ``[0, 1]`` that is high when a flow looks unlike
    anything seen during training — even for attack types the classifier
    never learned.

Both estimators travel together in one ``.joblib`` file
(:class:`IdsModel` / :class:`ModelStore`).
"""

from __future__ import annotations

import os
from typing import Sequence

import joblib
import numpy as np
from scipy.special import expit
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from .features import CATEGORICAL_FEATURES, NUMERIC_FEATURES
from .dataset import aligned_features

CLASSIFIER_KINDS = ("logreg", "rf")


# --------------------------------------------------------------------------
# Preprocessing
# --------------------------------------------------------------------------

def build_preprocessor(feature_columns: Sequence[str]) -> ColumnTransformer:
    """Impute + scale numerics, impute + one-hot encode categoricals."""
    numeric = [c for c in feature_columns if c in NUMERIC_FEATURES]
    categorical = [c for c in feature_columns if c in CATEGORICAL_FEATURES]
    return ColumnTransformer(
        transformers=[
            ("num", Pipeline([
                ("impute", SimpleImputer(strategy="median")),
                ("scale", StandardScaler()),
            ]), numeric),
            ("cat", Pipeline([
                ("impute", SimpleImputer(strategy="most_frequent")),
                ("onehot", OneHotEncoder(
                    handle_unknown="ignore",
                    sparse_output=False,
                    max_categories=64,
                )),
            ]), categorical),
        ],
        remainder="drop",
    )


def build_classifier(kind: str = "logreg"):
    if kind == "rf":
        return RandomForestClassifier(
            n_estimators=300,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
        )
    if kind == "logreg":
        return LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=42,
        )
    raise ValueError(f"Unknown model kind '{kind}'. Choose from {CLASSIFIER_KINDS}.")


def build_anomaly_detector() -> IsolationForest:
    return IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )


# --------------------------------------------------------------------------
# Model wrapper
# --------------------------------------------------------------------------

def _display_name(raw: str) -> str:
    """``num__dst_host_serror_rate`` -> ``dst_host_serror_rate``."""
    return raw.split("__", 1)[1] if "__" in raw else raw


class IdsModel:
    """Trained classifier + anomaly detector with local explanations."""

    def __init__(self, kind: str = "logreg"):
        self.kind = kind
        self.feature_columns: list[str] = []
        self.pipeline: Pipeline | None = None
        self.anomaly_pipeline: Pipeline | None = None
        self.anomaly_mu: float = 0.0
        self.anomaly_sigma: float = 1.0
        self.classes_: list[str] = []
        self.metrics: dict = {}
        self.trained_at: str | None = None
        self._feature_names: list[str] | None = None

    # -- training ---------------------------------------------------------
    def train(self, frame, labels: Sequence[str], feature_columns: Sequence[str],
              metrics: dict | None = None) -> "IdsModel":
        """Fit both estimators on a prepared DataFrame of canonical features."""
        feature_columns = list(feature_columns)
        if len(feature_columns) < 3:
            raise ValueError(
                "Not enough recognised features to train "
                f"(found {len(feature_columns)}, need at least 3)."
            )
        y = np.asarray([str(v) for v in labels])
        if len(set(y)) < 2:
            raise ValueError("Training data must contain at least two classes.")

        X = aligned_features(frame, feature_columns)

        self.feature_columns = feature_columns
        self.pipeline = Pipeline([
            ("prep", build_preprocessor(feature_columns)),
            ("clf", build_classifier(self.kind)),
        ])
        self.pipeline.fit(X, y)
        self.classes_ = [str(c) for c in self.pipeline.named_steps["clf"].classes_]

        # Unsupervised companion: its own preprocessor copy keeps the two
        # estimators independent (safe to pickle, safe to refit later).
        self.anomaly_pipeline = Pipeline([
            ("prep", build_preprocessor(feature_columns)),
            ("iforest", build_anomaly_detector()),
        ])
        self.anomaly_pipeline.fit(X, y)
        raw_scores = self.anomaly_pipeline.named_steps["iforest"].score_samples(
            self.anomaly_pipeline.named_steps["prep"].transform(X)
        )
        self.anomaly_mu = float(np.mean(raw_scores))
        self.anomaly_sigma = float(np.std(raw_scores) or 1.0)

        self._feature_names = None
        self.metrics = metrics or {}
        return self

    @property
    def trained(self) -> bool:
        return self.pipeline is not None and hasattr(
            self.pipeline.named_steps["clf"], "classes_"
        )

    def _check_trained(self) -> None:
        if not self.trained:
            raise RuntimeError(
                "The IDS model is not trained yet — run `python train_model.py`."
            )

    # -- prediction -------------------------------------------------------
    def predict_frame(self, frame) -> list[dict]:
        """Classify every row of a prepared frame.

        Returns one dict per row::

            {"label", "confidence", "probabilities", "anomaly_score"}
        """
        self._check_trained()
        X = aligned_features(frame, self.feature_columns)
        clf = self.pipeline.named_steps["clf"]
        transformed = self.pipeline.named_steps["prep"].transform(X)

        probabilities = clf.predict_proba(transformed)
        best = probabilities.argmax(axis=1)

        if_scores = self.anomaly_pipeline.named_steps["iforest"].score_samples(
            self.anomaly_pipeline.named_steps["prep"].transform(X)
        )
        # Lower isolation score == more anomalous; standardise with the
        # training distribution, then squash to (0, 1).
        anomaly = expit(-(if_scores - self.anomaly_mu) / (self.anomaly_sigma or 1.0))

        results: list[dict] = []
        for row_index in range(len(X)):
            class_index = int(best[row_index])
            results.append({
                "label": str(clf.classes_[class_index]),
                "confidence": float(probabilities[row_index, class_index]),
                "probabilities": {
                    str(cls): round(float(probabilities[row_index, idx]), 4)
                    for idx, cls in enumerate(clf.classes_)
                },
                "anomaly_score": round(float(anomaly[row_index]), 4),
            })
        return results

    # -- explanation ------------------------------------------------------
    def contributions(self, frame, labels: Sequence[str], top_k: int = 6) -> list[list[dict]]:
        """Local ``coefficient x value`` explanations (logistic regression only).

        Positive contribution -> pushes the verdict *toward* the predicted
        attack category; negative -> toward the other classes.  Random
        forests have no linear coefficients, so an empty list is returned
        and the dashboard falls back to rule-based reasons.
        """
        self._check_trained()
        if self.kind != "logreg":
            return [[] for _ in range(len(frame))]

        X = aligned_features(frame, self.feature_columns)
        transformed = self.pipeline.named_steps["prep"].transform(X)
        clf = self.pipeline.named_steps["clf"]
        names = self.feature_names()

        class_indexes = np.asarray(
            [list(clf.classes_).index(str(label)) for label in labels], dtype=int
        )
        coefficients = clf.coef_[class_indexes]          # (rows, features)
        values = np.asarray(transformed)                 # (rows, features)
        contribs = coefficients * values

        out: list[list[dict]] = []
        for row_index in range(contribs.shape[0]):
            row = contribs[row_index]
            order = np.argsort(-np.abs(row))
            signs: list[dict] = []
            for column in order:
                if len(signs) >= top_k:
                    break
                if row[column] == 0 or values[row_index, column] == 0:
                    continue
                signs.append({
                    "token": names[column],
                    "contribution": round(float(row[column]), 4),
                    "value": round(float(values[row_index, column]), 4),
                })
            out.append(signs)
        return out

    def feature_names(self) -> list[str]:
        if self._feature_names is not None:
            return self._feature_names
        self._check_trained()
        raw = self.pipeline.named_steps["prep"].get_feature_names_out()
        self._feature_names = [_display_name(name) for name in raw]
        return self._feature_names

    # -- persistence ------------------------------------------------------
    def save(self, path: str) -> None:
        self._check_trained()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        joblib.dump({
            "name": "ids",
            "kind": self.kind,
            "feature_columns": self.feature_columns,
            "pipeline": self.pipeline,
            "anomaly_pipeline": self.anomaly_pipeline,
            "anomaly_mu": self.anomaly_mu,
            "anomaly_sigma": self.anomaly_sigma,
            "classes": self.classes_,
            "metrics": self.metrics,
            "trained_at": self.trained_at,
        }, path)

    @classmethod
    def load(cls, path: str) -> "IdsModel":
        payload = joblib.load(path)
        model = cls(payload.get("kind", "logreg"))
        model.feature_columns = list(payload["feature_columns"])
        model.pipeline = payload["pipeline"]
        model.anomaly_pipeline = payload.get("anomaly_pipeline")
        model.anomaly_mu = float(payload.get("anomaly_mu", 0.0))
        model.anomaly_sigma = float(payload.get("anomaly_sigma", 1.0)) or 1.0
        model.classes_ = list(payload.get("classes", []))
        model.metrics = payload.get("metrics", {})
        model.trained_at = payload.get("trained_at")
        return model


# --------------------------------------------------------------------------
# Model store (lazy loading + auto-training)
# --------------------------------------------------------------------------

class ModelStore:
    """Loads the persisted model from ``model_dir``, training on demand."""

    MODEL_FILE = "ids_model.joblib"
    METRICS_FILE = "metrics.json"

    def __init__(self, model_dir: str = "models", data_seed: int = 42):
        self.model_dir = model_dir
        self.data_seed = data_seed
        self._model: IdsModel | None = None

    def _path(self, filename: str) -> str:
        return os.path.join(self.model_dir, filename)

    def ensure(self) -> "ModelStore":
        """Train a model on first launch so the dashboard always works."""
        if not os.path.exists(self._path(self.MODEL_FILE)):
            from .training import train_and_save
            train_and_save(self.model_dir, seed=self.data_seed)
        if self._model is None:
            self._model = IdsModel.load(self._path(self.MODEL_FILE))
        return self

    @property
    def model(self) -> IdsModel:
        self.ensure()
        assert self._model is not None
        return self._model

    @property
    def path(self) -> str:
        return self._path(self.MODEL_FILE)

    def status(self) -> dict:
        exists = os.path.exists(self._path(self.MODEL_FILE))
        info = {
            "model_dir": self.model_dir,
            "model_file": exists,
            "trained": False,
            "kind": None,
            "metrics": {},
        }
        if exists:
            try:
                model = IdsModel.load(self._path(self.MODEL_FILE))
                info["trained"] = model.trained
                info["kind"] = model.kind
                info["metrics"] = model.metrics
                info["feature_count"] = len(model.feature_columns)
                info["classes"] = model.classes_
                info["trained_at"] = model.trained_at
            except Exception:  # pragma: no cover - corrupt file
                info["error"] = "model file could not be read"
        return info
