"""Dataset loading and normalisation (pandas).

Turns three different inputs into one shape:

* ``list[dict]``          — JSON flows posted to the API
* ``path``                — a CSV file on disk (``train_model.py --csv``)
* ``file storage``        — a CSV uploaded through the dashboard

The result of :func:`prepare` is a tidy :class:`pandas.DataFrame` with the
canonical feature columns plus metadata and (when available) mapped labels.

Per-row *coverage* is tracked: how many canonical features the raw record
actually supplied.  The detector uses it to mark partially observed flows
instead of silently pretending a missing column means zero.
"""

from __future__ import annotations

import io
from typing import Iterable

import pandas as pd

from .features import (
    CATEGORICAL_FEATURES,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    META_COLUMNS,
    NUMERIC_FEATURES,
    map_label,
    resolve_column,
)

#: Anything that parses as a number counts as an observed feature.
def _coerce_number(value) -> float:
    if value is None:
        return float("nan")
    if isinstance(value, bool):
        return float(value)
    try:
        return float(str(value).strip().strip('"'))
    except (TypeError, ValueError):
        return float("nan")


def records_to_frame(records: Iterable[dict]) -> tuple[pd.DataFrame, dict]:
    """Normalise raw records onto the canonical schema.

    Returns ``(frame, info)`` where ``frame`` contains the canonical feature
    columns, metadata columns, an optional ``label`` column and a
    ``_coverage`` column (0-1), and ``info`` summarises the mapping.
    """
    rows: list[dict] = []
    used_canonical: set[str] = set()
    used_meta: set[str] = set()
    used_label = False
    ignored: list[str] = []
    unknown_columns: list[str] = []
    seen_ignored: set[str] = set()

    for raw in records:
        if not isinstance(raw, dict):
            continue
        row: dict = {}
        supplied: set[str] = set()
        for key, value in raw.items():
            if str(key).startswith("_"):      # internal keys (_category, …)
                continue
            target = resolve_column(key)
            if target is None:
                if key not in seen_ignored:
                    seen_ignored.add(key)
                    unknown_columns.append(str(key))
                continue
            if target in NUMERIC_FEATURES:
                row[target] = _coerce_number(value)
                used_canonical.add(target)
                supplied.add(target)
            elif target in CATEGORICAL_FEATURES:
                text = str(value).strip().lower()
                if text and text not in {"nan", "none", "null", "?"}:
                    row[target] = text
                    used_canonical.add(target)
                    supplied.add(target)
            elif target == LABEL_COLUMN:
                mapped = map_label(value)
                if mapped is not None:
                    row[LABEL_COLUMN] = mapped
                    used_label = True
                    supplied.add(LABEL_COLUMN)
            elif target in META_COLUMNS:
                if target == "timestamp":
                    # Keep unix timestamps numeric so the timeline chart can
                    # bucket them without guessing a date format.
                    number = _coerce_number(value)
                    if number == number:
                        row[target] = number
                        used_meta.add(target)
                        supplied.add(target)
                        continue
                text = str(value).strip()
                if text and text not in {"nan", "none", "null"}:
                    row[target] = text
                    used_meta.add(target)
                    supplied.add(target)
        if not supplied:
            ignored.append("row-with-no-recognised-columns")
            continue
        row["_coverage"] = len(supplied & set(FEATURE_COLUMNS)) / len(FEATURE_COLUMNS)
        rows.append(row)

    if not rows:
        raise ValueError(
            "No usable flows found. Expected records with network-flow columns "
            "such as duration, protocol, src_bytes, count, serror_rate … "
            "(NSL-KDD / KDD Cup style headers are supported)."
        )

    frame = pd.DataFrame(rows)
    for column in NUMERIC_FEATURES:
        if column not in frame.columns:
            frame[column] = float("nan")
    for column in CATEGORICAL_FEATURES:
        if column not in frame.columns:
            frame[column] = "unknown"
    if used_label and LABEL_COLUMN not in frame.columns:
        frame[LABEL_COLUMN] = "unknown"
    for column in META_COLUMNS:
        if column not in frame.columns:
            frame[column] = None
    if "_coverage" not in frame.columns:
        frame["_coverage"] = 0.0

    frame["_coverage"] = frame["_coverage"].astype(float)
    if LABEL_COLUMN in frame.columns:
        frame[LABEL_COLUMN] = frame[LABEL_COLUMN].astype(str)

    info = {
        "rows": int(len(frame)),
        "features_found": sorted(used_canonical),
        "feature_count": len(used_canonical),
        "meta_found": sorted(used_meta),
        "has_labels": bool(used_label),
        "ignored_columns": sorted(unknown_columns),
        "dropped_rows": len(ignored),
        "coverage": round(float(len(used_canonical) / len(FEATURE_COLUMNS)), 3),
    }
    return frame, info


def load_csv(source, max_bytes: int = 64 * 1024 * 1024) -> list[dict]:
    """Read a CSV from a path, file object or :class:`werkzeug.FileStorage`.

    A missing/blank header cell, duplicate headers or an unreadable file all
    raise :class:`ValueError` with a message that is safe to show in the UI.
    """
    if hasattr(source, "read"):
        payload = source.read(max_bytes + 1)
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8-sig", errors="replace")
        if len(payload) > max_bytes:
            raise ValueError("CSV file is larger than 64 MB.")
        text = payload
    else:
        with open(str(source), "r", encoding="utf-8-sig", errors="replace") as handle:
            text = handle.read(max_bytes + 1)
        if len(text) > max_bytes:
            raise ValueError("CSV file is larger than 64 MB.")

    if not text.strip():
        raise ValueError("The CSV file is empty.")

    try:
        frame = pd.read_csv(io.StringIO(text))
    except Exception as exc:  # pandas raises many parser subtypes
        raise ValueError(f"Could not parse the CSV: {exc}") from exc

    if frame.empty:
        raise ValueError("The CSV contains a header but no data rows.")
    if len(frame.columns) < 2:
        raise ValueError(
            "The CSV needs at least two columns (features plus a label column)."
        )
    frame = frame.dropna(how="all")
    return frame.to_dict(orient="records")


def prepare(records: Iterable[dict]) -> tuple[pd.DataFrame, dict]:
    """Alias for :func:`records_to_frame` (used by app.py and cli.py)."""
    return records_to_frame(records)


def aligned_features(frame: pd.DataFrame, feature_columns: list[str]) -> pd.DataFrame:
    """Reindex onto the model's training columns.

    Columns the model expects but the dataset lacks become ``NaN`` (the
    pipeline's imputer fills them with the training median / most frequent
    value), which is far safer than assuming a hard zero.
    """
    ordered = frame.reindex(columns=list(feature_columns))
    for column in CATEGORICAL_FEATURES:
        if column in ordered.columns:
            ordered[column] = ordered[column].fillna("unknown")
    return ordered
