"""SentinelIDS — AI-powered intrusion detection engine (defensive security).

Public entry points::

    from ids_engine import analyze_records, ModelStore

* :mod:`ids_engine.features`   — canonical flow schema, column aliasing, label mapping
* :mod:`ids_engine.dataset`    — pandas loading & normalisation (CSV, JSON, uploads)
* :mod:`ids_engine.synthetic`  — seeded offline demo corpus
* :mod:`ids_engine.model`      — scikit-learn pipelines (classifier + IsolationForest)
* :mod:`ids_engine.training`   — train / evaluate / persist
* :mod:`ids_engine.detector`   — behavioural rules & risk scoring
* :mod:`ids_engine.analysis`   — end-to-end report builder for the dashboard
"""

__version__ = "1.0.0"

from .analysis import analyze_records
from .dataset import load_csv, prepare
from .live import CaptureUnavailable, LiveDetector
from .model import ModelStore
from .synthetic import demo_flows, generate_flows

__all__ = [
    "analyze_records",
    "load_csv",
    "prepare",
    "ModelStore",
    "LiveDetector",
    "CaptureUnavailable",
    "demo_flows",
    "generate_flows",
    "__version__",
]
