# SentinelIDS — AI-Powered Intrusion Detection System

> **Made by Er-Suzen Kumar Mohanty** · **IBM Cyber Security Project**

A beginner-to-intermediate **defensive security** project that ingests
**network-flow datasets**, classifies every flow with **machine learning**,
raises **alerts with risk levels**, and **visualises attack patterns** on a
live dashboard — explaining *why* each verdict was reached.

> **Defensive use only.** SentinelIDS analyses recorded flow data. It does not
> capture live traffic, exploit anything, or send your datasets anywhere —
> every request is handled locally by the Flask app.

---

## Table of contents

1. [What it does](#what-it-does)
2. [Step-by-step usage](#step-by-step-usage)
3. [Sample output](#sample-output)
4. [Architecture](#architecture)
5. [Quick start](#quick-start)
6. [How the detection works](#how-the-detection-works)
7. [Project layout](#project-layout)
8. [Web API](#web-api)
9. [CLI usage](#cli-usage)
10. [Training on real datasets](#training-on-real-datasets)
11. [Testing](#testing)
12. [Skills demonstrated](#skills-demonstrated)
13. [Limitations & responsible use](#limitations--responsible-use)
14. [Roadmap / extensions](#roadmap--extensions)
15. [Credits](#credits)

---

## What it does

| Capability | Details |
|---|---|
| **Dataset ingestion** | CSV upload (drag & drop), JSON API, or the built-in demo corpus. NSL-KDD / KDD Cup headers work as-is; CICIDS-style names (`Total Length of Fwd Packets` …) are mapped through an alias table |
| **Attack classification** | scikit-learn classifier predicts `normal · probe · dos · r2l · u2r` with per-class probabilities |
| **Anomaly detection** | A second, *unsupervised* IsolationForest scores how unusual each flow looks — it can flag attack types the classifier never saw |
| **Behavioural rules** | 20 signatures (SYN floods, sweeps, brute force, privilege escalation, exfiltration …) turn a probability into a readable reason |
| **Risk levels** | Every flow gets `info · low · medium · high · critical` plus a 0–100 score blending ML, anomaly and rule evidence |
| **Dashboard** | KPI cards, five Chart.js visualisations (risk mix, attack patterns, timeline, protocol split, targeted services), a per-class model-quality chart, and a filterable alert table with expandable, explained rows — rendered in a **3D perspective view** (corner-cut HUD panels, extruded 3D bars and a 3D doughnut) with a **3D ⇄ 2D toggle** in the header |
| **Ground truth** | Upload a labelled dataset and the dashboard reports accuracy, per-class precision/recall/F1 against it |
| **Real-time monitoring** | The **Live monitor** panel watches *this computer's* actual network traffic — packet capture via scapy/Npcap or the OS connection table via psutil — and pushes each detection window through the same models & rules. New alerts stream in over Server-Sent Events with a flash highlight, live connection/process table, and a JSONL alert log in `logs/` |
| **Explainability** | Every alert shows the exact model features (`coefficient × value`) and rule findings behind the verdict |

---

## Step-by-step usage

### Path A — Web dashboard (recommended for beginners)

**Step 1 · Install Python & dependencies**

Open a terminal in the `intrusion-detection` folder:

```bash
cd intrusion-detection
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux
pip install -r requirements.txt
```

**Step 2 · Train the model (optional)**

```bash
python train_model.py
```

This creates `models/ids_model.joblib` and `models/metrics.json`.
Skip it if you like — the app trains the model automatically on first launch
(about 20 seconds).

**Step 3 · Start the dashboard**

```bash
python app.py
```

Open **http://127.0.0.1:5000**. The demo dataset is analysed automatically and
the badge in the header turns green with **"model ready · logreg"**.

> If port 5000 is already taken by another local app (for example the
> *phishing-detector* project running side by side), pick another port:
> ```bat
> set PORT=5050          :: Windows
> export PORT=5050       :: macOS / Linux
> python app.py
> ```

**Step 4 · Explore the demo, then use your own data**

1. The demo corpus (800 synthetic flows) loads on start-up.
2. Press **Load demo dataset** any time to re-run it.
3. Drag a CSV into the **drop zone** (or press **Upload CSV**) to analyse a
   real dataset — e.g. `NLS-KDD` test set.
4. Watch the KPI cards, then the five charts: risk mix, attack categories,
   alerts over time, protocol split and targeted services.

**Step 5 · Read an alert**

Click any row in the **Alerts** table — it expands to show:

| Section | What it tells you |
|---|---|
| **Why this alert** | The plain-language reasons, in one line each |
| **Behavioural findings** | Every triggered rule, colour-coded by severity, with the numbers behind it |
| **What the model noticed** | The exact features that pushed the verdict (`coefficient × value`) |
| **Class probabilities** | Confidence per attack category, plus the anomaly score and feature coverage |
| **Flow features / score breakdown** | Raw values and how ML, rules and anomaly evidence were weighted |

**Step 6 · Filter and triage**

Use the **Critical / High / Medium / Low** chips or the search box (IP,
service, category or reason text) to narrow the list. The charts always cover
*every* analysed flow, even when the table shows a capped sample.

**Step 7 · 3D ⇄ 2D**

The dashboard ships in a 3D presentation — tilted chart panels, extruded
bars/doughnuts, layered shadows. Press the **3D** button in the header to
flatten everything into a clean 2D layout (and back again).

**Step 8 · Real-time monitoring (live mode)**

In the **Real-time monitor** panel, press **Start live monitoring**:

1. Pick a backend: *auto* (packet capture when scapy + Npcap are available),
   *packet capture*, or *OS connection table* (needs nothing).
2. Choose the window length (seconds per detection window, default 3).
3. The KPIs, charts and alert table switch to the live window; every new
   alert streams in instantly (flashing row + live feed), the **Active
   connections** table shows who this computer is talking to right now
   (address, state, process), and alerts are appended to
   `logs/live-alerts-YYYYMMDD.jsonl`.
4. **Stop** freezes the view; **Load demo** / a CSV upload also exits live
   mode automatically.

> Packet capture observes only connection metadata — addresses, ports, byte
> counts and TCP flags — never packet contents. On Windows it needs the free
> [Npcap](https://npcap.com) driver (the one Wireshark uses). Run as
> Administrator to see other processes' connections too.

### Path B — Command line (same engine)

```bash
python cli.py demo                       # built-in synthetic corpus
python cli.py csv data/nsl-kdd.csv       # analyse a flow CSV
python cli.py live                       # watch this computer's live traffic
python cli.py status                     # model file, kind and metrics
```

---

## Sample output

```
$ python cli.py demo --rows 300
==========================================================================
ANALYSED 300 flows from demo (300 rows)
  malicious: 165 (55.0%)   alerts: 182   avg risk: 45/100
  levels: info=118  low=17  medium=3  high=159  critical=3
  model: logreg  accuracy=0.994  macro_f1=0.9928  anomaly_auc=0.9599
==========================================================================

Top 3 alerts (182 total)

  [CRIT] █████████░  86/100  10.0.95.247 → 10.0.88.189  icmp/ftp_data
          Probe / scan  confidence=1.00  anomaly=0.80
          • Extreme connection rate
          • ICMP echo flood

  [CRIT] █████████░  86/100  10.0.233.12 → 10.0.145.86  icmp/private
          Probe / scan  confidence=1.00  anomaly=0.81
          • Extreme connection rate
          • ICMP echo flood

  [CRIT] ████████░░  85/100  10.0.27.22 → 10.0.65.144  icmp/http
          Probe / scan  confidence=1.00  anomaly=0.74
          • Extreme connection rate
          • ICMP echo flood
```

---

## Architecture

```
        ┌──────────────────────────── Flask (app.py) ────────────────────────────┐
        │  /            dashboard (templates/index.html + static/, Chart.js)     │
        │  /api/demo   /api/analyze   /api/analyze-csv   /api/health  /examples  │
        └───────────────────────────────┬────────────────────────────────────────┘
                                        │
                              ┌─────────▼──────────┐
                              │  ids_engine/       │
                              │  analysis.py       │  end-to-end report builder
                              └─────────┬──────────┘
             ┌──────────────────────────┼───────────────────────────────┐
             │                          │                               │
   ┌─────────▼─────────┐    ┌───────────▼───────────┐    ┌──────────────▼─────────┐
   │  dataset.py       │    │  model.py             │    │  detector.py           │
   │  pandas load +    │    │  ColumnTransformer →  │    │  20 behavioural rules  │
   │  column aliasing  │    │  • LogisticRegression │    │  + risk scoring        │
   │  (features.py)    │    │  • IsolationForest    │    │  (info→critical)       │
   └───────────────────┘    └───────────┬───────────┘    └────────────────────────┘
                                        │
                             train_model.py / training.py
                             synthetic.py (offline corpus)
                             → models/ids_model.joblib + metrics.json
```

**One score, three signals.** For every flow:

```
risk_score = 0.50 × ML attack score        (1 − P(normal)) × 100
           + 0.25 × anomaly score          IsolationForest, squashed to 0–100
           + 0.25 × rule score             Σ rule points, capped at 100
```

| Score | Risk level | Meaning |
|---|---|---|
| — | **info** | Benign flow, no evidence against it (not an alert) |
| < 40 | **low** | Weak or unusual signals — worth a look |
| 40 – 64 | **medium** | Credible suspicious activity |
| 65 – 84 | **high** | Likely attack activity |
| ≥ 85 | **critical** | Strong attack evidence — respond now |

Two safeguards keep the levels honest:

* **Severity floors** — a prediction the model is ≥ 75 % confident about can
  never be filed below its category's floor (`dos`/`probe` → medium,
  `r2l`/`u2r` → high).
* **Benign-but-unusual** — a flow classified `normal` that still trips rules
  or looks anomalous is raised to `low`/`medium` instead of being silently
  ignored.

---

## Quick start

### 1. Requirements

| Item | Requirement |
|---|---|
| Operating system | Windows / macOS / Linux |
| Python | **3.10 or newer** (developed on 3.14.7) |
| RAM | ~1 GB free (demo model is small; large CSVs need more) |
| Disk | ~120 MB including dependencies |
| Browser | Any modern browser (Chrome, Edge, Firefox, Safari) |
| Internet | **Not required** — Chart.js is bundled in `static/vendor/` |

**Python packages** — all in [`requirements.txt`](requirements.txt):

| Package | Version | Purpose |
|---|---|---|
| `Flask` | ≥ 3.0, < 4.0 | Dashboard + JSON API |
| `scikit-learn` | ≥ 1.4 | Classifier, IsolationForest, metrics |
| `pandas` | ≥ 2.1 | CSV parsing, normalisation, chart aggregation |
| `numpy` | ≥ 1.26 | Feature matrices |
| `scipy` | ≥ 1.11 | Logistic squash for anomaly scores |
| `joblib` | ≥ 1.3 | Model persistence |
| `psutil` | ≥ 5.9 | Real-time monitor: OS connection-table backend |
| `scapy` *(optional)* | ≥ 2.5 | Real-time monitor: full packet capture (Windows/macOS also need [Npcap](https://npcap.com)) |

### 2. Install, train, run

```bash
pip install -r requirements.txt
python train_model.py        # optional — auto-runs on first launch
python app.py                # open http://127.0.0.1:5000
```

Expected training output on the bundled corpus:

```
Training SentinelIDS (logreg) on the synthetic corpus ...
  [logreg] accuracy=0.994  macro_f1=0.993  (train=4500, test=1500, features=30)
  [iforest] anomaly ROC-AUC=0.960
  classes: dos, normal, probe, r2l, u2r
Saved model to .../models/ids_model.joblib
```

> The synthetic corpus mirrors the rule signatures, so near-perfect scores are
> expected here. Real-world numbers are covered in
> [Training on real datasets](#training-on-real-datasets).

---

## How the detection works

### Features (`features.py`, 30 total)

| Group | Features |
|---|---|
| Connection | `duration`, `protocol_type`, `service`, `flag`, `src_bytes`, `dst_bytes`, `land`, `wrong_fragment`, `urgent` |
| Content | `num_failed_logins`, `logged_in`, `num_compromised`, `root_shell`, `su_attempted`, `num_root`, `num_file_creations` |
| Window stats (2 s) | `count`, `srv_count`, `serror_rate`, `srv_serror_rate`, `rerror_rate`, `srv_rerror_rate`, `same_srv_rate`, `diff_srv_rate` |
| Host stats (last 100) | `dst_host_count`, `dst_host_srv_count`, `dst_host_same_srv_rate`, `dst_host_diff_srv_rate`, `dst_host_serror_rate`, `dst_host_rerror_rate` |

Unknown columns are ignored (and listed in the report); missing columns are
simply absent from the model when you retrain on that dataset. `src_ip`,
`dst_ip` and `timestamp` are kept as metadata for the alert table.

### Label mapping

Raw dataset labels are folded into five NSL-KDD style categories:

| Category | Examples mapped |
|---|---|
| `normal` | normal, benign, legitimate, 0 |
| `dos` | neptune, smurf, back, teardrop, DDoS, DoS Hulk, Slowloris |
| `probe` | portsweep, ipsweep, nmap, satan, PortScan, Recon |
| `r2l` | guess_passwd, warezclient, phf, httptunnel, Web Attack Brute Force |
| `u2r` | buffer_overflow, rootkit, perl, Infiltration, Backdoor, Ransomware |
| `unknown` | anything unrecognised (still flagged as an attack) |

### The two models (`model.py`)

* **Classifier** — `ColumnTransformer` (median impute + `StandardScaler` for
  numerics, most-frequent impute + one-hot for categoricals) followed by
  class-balanced **Logistic Regression**. Multinomial probabilities per class
  keep every verdict explainable as `coefficient × value`.
  Prefer accuracy over explainability? `python train_model.py --model rf`
  swaps in a class-balanced **Random Forest** (0.998 hold-out accuracy on the
  synthetic corpus).
* **IsolationForest** — unsupervised companion on the same features. Its raw
  isolation score is standardised against training statistics, then squashed
  to a 0–1 *anomaly score*. Because it never sees labels, it still reacts to
  attack patterns the classifier was never trained on.

### The rules (`detector.py`, 20 signatures)

*Denial of service:* `syn_flood`, `host_syn_flood`, `connection_flood`,
`connection_spike`, `icmp_flood`, `land_attack`
*Reconnaissance:* `service_sweep`, `host_scan`, `host_probe`,
`rejected_storm`, `odd_flags`, `payloadless_burst`
*Credential / privilege:* `brute_force`, `failed_logins`,
`privilege_escalation`, `persistence_activity`
*Data movement:* `data_exfiltration`, `bulk_download`
*Other:* `malformed_packets`, `long_session` (possible beaconing)
*Observability:* `partial_data` — fires when the dataset only supplied a
fraction of the schema, so the analyst knows the verdict is thin.

### Explainability

For logistic regression, each alert lists the top features by
`coefficient × scaled value`. Positive values pushed the verdict toward the
predicted attack class; negative values pushed back. Combined with the rule
findings, no alert is a black box — a core requirement for security tooling.

---

## Project layout

```
intrusion-detection/            ← C:\Users\suzen\Documents\Default Project\intrusion-detection
├── app.py                      # Flask app + JSON API
├── cli.py                      # command-line interface
├── train_model.py              # training entry point (--csv / --model / --rows)
├── requirements.txt            # Python dependencies
├── README.md                   # this file
├── .gitignore
├── ids_engine/                 # the importable package (core logic)
│   ├── __init__.py
│   ├── features.py             # canonical schema, column aliasing, label mapping
│   ├── dataset.py              # pandas loading & normalisation
│   ├── synthetic.py            # seeded offline corpus (with class overlap)
│   ├── model.py                # pipelines, IdsModel, ModelStore
│   ├── training.py             # train + evaluate + persist
│   ├── detector.py             # 20 rules + risk scoring
│   ├── live.py                 # real-time capture (scapy + psutil) & detector loop
│   └── analysis.py             # report builder (alerts + chart aggregates)
├── templates/
│   └── index.html              # dashboard
├── static/
│   ├── style.css               # styling + responsive system
│   ├── app.js                  # Chart.js visualisations + alert table UI + live stream
│   └── vendor/chart.umd.min.js # Chart.js 4.4.1 (bundled, offline)
├── tests/
│   ├── test_ids.py             # 35 unit + API tests
│   └── test_live.py            # 19 real-time monitoring tests
├── logs/                       # generated: live alert JSONL logs
├── data/                       # optional: drop real datasets here
└── models/                     # generated: ids_model.joblib, metrics.json
```

---

## Web API

All endpoints return JSON.

### `GET /api/demo?rows=800`

Analyses the bundled synthetic corpus. Returns the full report described below.

### `POST /api/analyze-csv`

```bash
curl -X POST http://127.0.0.1:5000/api/analyze-csv \
  -F "file=@data/nsl-kdd.csv"
```

### `POST /api/analyze`

```bash
curl -X POST http://127.0.0.1:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"flows": [
        {"duration": 0.0, "protocol_type": "tcp", "service": "private",
         "flag": "S0", "src_bytes": 0, "dst_bytes": 0, "count": 318,
         "serror_rate": 1.0, "dst_host_serror_rate": 1.0, "label": "neptune"}
      ]}'
```

### `GET /api/health` · `GET /api/examples`

Model status/metrics, and five sample flow records for experiments.

### Real-time monitoring endpoints

```bash
curl -X POST http://127.0.0.1:5000/api/live/start \
  -H "Content-Type: application/json" \
  -d '{"backend": "auto", "interval": 3}'      # auto | scapy | system
curl http://127.0.0.1:5000/api/live/status      # uptime, counts, connections
curl -N http://127.0.0.1:5000/api/live/stream   # SSE: tick events (report+status+new alerts)
curl -X POST http://127.0.0.1:5000/api/live/stop
```

`GET /api/live/stream` is a `text/event-stream` of `tick` events, one per
detection window: `{ "report": <full report>, "status": <live status>,
"new_alerts": [<alerts not seen before>] }`, ending with a `stopped` event.

### Report shape (abridged)

```json
{
  "source": "demo",
  "generated_at": "2026-10-20T07:58:32+00:00",
  "dataset":   { "rows": 800, "feature_count": 30, "coverage": 1.0,
                 "has_labels": true, "ignored_columns": [] },
  "model":     { "kind": "logreg", "classes": ["dos","normal","probe","r2l","u2r"],
                 "feature_count": 30,
                 "metrics": { "accuracy": 0.994, "macro_f1": 0.9928, "anomaly_auc": 0.96 } },
  "summary":   { "flows": 800, "alerts": 491, "benign": 362, "malicious": 438,
                 "malicious_pct": 54.8, "critical": 12, "high": 413,
                 "medium": 14, "low": 52, "info": 309,
                 "avg_risk": 45, "max_risk": 87 },
  "charts":    { "risk": [...], "categories": [...], "timeline": [...],
                 "protocols": [...], "services": [...] },
  "evaluation": { "accuracy": 0.9975, "labels": [...], "per_class": {...},
                  "confusion": { "labels": [...], "matrix": [[...]] } },
  "alerts": [
    {
      "id": 520, "src_ip": "10.0.181.108", "dst_ip": "10.0.229.82",
      "timestamp": "2026-10-20 10:54:19",
      "protocol": "icmp", "service": "smtp", "flag": "sh",
      "label": "probe", "category_label": "Probe / scan",
      "confidence": 1.0, "probabilities": { "probe": 1.0, "normal": 0.0 },
      "anomaly_score": 0.8891,
      "risk_level": "critical", "risk_score": 87, "ml_score": 100, "rule_score": 59,
      "reasons": ["Very high connection rate", "ICMP echo flood",
                  "Connections fanning out across many services"],
      "findings": [ { "code": "connection_spike", "severity": "medium",
                      "title": "Very high connection rate",
                      "detail": "137 connections in a two-second window — worth watching for denial-of-service activity.",
                      "points": 10 } ],
      "ml_signs": [ { "token": "diff_srv_rate", "value": 2.4027, "contribution": 4.2725 } ],
      "features": { "count": 137, "serror_rate": 0.003, "...": 0 },
      "coverage": 1.0
    }
  ],
  "alerts_total": 491,
  "alerts_returned": 491
}
```

Errors always come back as `{"error": "human-readable message"}` with a 4xx/5xx
status.

---

## CLI usage

```
python cli.py demo [--rows N] [--limit N]    # built-in corpus
python cli.py csv <path> [--limit N]         # analyse a flow CSV
python cli.py live [--backend auto|scapy|system]
                  [--interval S] [--duration S] [--limit N]
                                          # watch live traffic (Ctrl+C to stop)
python cli.py status                         # model artefact + metrics
```

---

## Training on real datasets

The bundled synthetic corpus makes the project runnable offline; for
believable evaluation, retrain on public data.

### A. Retrain from CSV

```bash
python train_model.py --csv data/nsl-kdd.csv
python train_model.py --csv data/cicids2017.csv --model rf --test-size 0.3
```

* The CSV needs a label column (`label` / `class` / `attack` / `category`).
* Columns are matched by the alias table; **columns the dataset does not
  provide are excluded from the model** (a 22-feature subset trains happily).
* At least 20 labelled rows and 3 usable features are required.
* Only the features your dataset actually fills are used, so the imputer
  statistics stay honest.

### B. Suggested public sources

| Dataset | Where | Fit |
|---|---|---|
| **NSL-KDD** | UNB CSE / Kaggle | ★★★ headers match the canonical schema exactly |
| KDD Cup '99 | UCI KDD Archive | ★★★ same columns as NSL-KDD |
| CICIDS2017 | Canadian Institute for Cybersecurity | ★★ several columns map via the alias table, the rest are ignored |
| UNSW-NB15 | UNSW Canberra | ★★ rich data, but rename columns first |

**Report honestly.** On NSL-KDD with logistic regression you should expect
roughly **macro-F1 0.75 – 0.85**, far below the synthetic numbers above —
attacks overlap heavily in feature space. Track **per-class precision, recall
and F1** (`evaluation` in the report and the dashboard's model-quality chart),
because with imbalanced security data accuracy alone is misleading. Swap in
`--model rf` for a fair comparison: `model.py` only requires a scikit-learn
estimator with `predict_proba`.

---

## Testing

```bash
python -m unittest discover -s tests -v
# or:  python -m pytest -q
```

54 tests cover feature schema & aliasing, pandas normalisation, CSV error
handling, the behavioural rules, risk scoring and severity floors, model
training metrics, report structure & chart aggregates, the stratified alert
cap, every Flask endpoint (including CSV upload and rejection paths), and
the real-time engine (window-context features, packet folding into flows,
alert de-duplication, the live detector loop, the JSONL alert log and the
live API + SSE stream).

---

## Skills demonstrated

`Python` · `machine learning` (scikit-learn pipelines, logistic regression,
random forest, IsolationForest, class imbalance, ROC-AUC) · `pandas` (CSV
normalisation, feature alignment, aggregation) · `Flask` (REST API + JSON
reports) · `Chart.js` (dashboard visualisation) · `defensive security`
(network-attack signatures, NSL-KDD/CICIDS datasets, alert triage UX) ·
`testing` · `explainable AI`.

---

## Limitations & responsible use

* **Synthetic training data** mirrors the rule signatures — near-perfect
  hold-out scores are expected. Retrain on NSL-KDD/CICIDS before trusting it
  on real traffic, and report the real numbers.
* **Flow-level view.** SentinelIDS classifies recorded flows (live capture
  observes connection metadata only); it does not decrypt payloads or
  correlate sessions across hosts.
* **Not a production NIDS.** Live mode monitors *this computer*; there is no
  inline blocking, no multi-host sensor fleet, no authentication — treat it
  as an analyst workbench.
* **Live byte counts are estimates** on the `system` backend (attributed
  from OS-wide counters); the `scapy` backend measures them per flow. Rules
  that only need connection counts, ports and states work on both.
* **Dataset coverage matters.** A CSV that supplies only a few recognised
  columns produces thin verdicts; the report flags these flows with
  `partial_data` instead of pretending otherwise.
* **Class imbalance** in real data will skew precision per class — always
  check the per-class metrics the dashboard shows for your dataset.
* Models are only as fresh as the last training run; retrain periodically as
  attack patterns drift.
* Use this tool to **defend** networks. Never deploy it to generate, guide or
  conceal attacks.

---

## Roadmap / extensions

1. ~~**Live capture** — read PCAP (Scapy) or an interface and score flows in
   real time.~~ ✅ **Done** — dashboard *Real-time monitor*, `cli.py live`,
   `/api/live/*` endpoints; packet capture (scapy/Npcap) with an automatic
   OS-connection-table (psutil) fallback.
2. **Feedback loop** — "mark as false positive" button that appends labelled
   flows to `data/` for retraining.
3. **Model comparison view** — logistic regression vs. random forest vs. SVM
   side by side on the same dataset.
4. **Confidence calibration** — isotonic regression so the displayed
   probabilities are trustworthy.
5. **IP reputation & geo enrichment** (offline, optional flag).
6. **Docker + REST deployment** with rate limiting and auth.
7. **Alert export** — CSV / STIX for SIEM ingestion.
8. **Multi-host sensors & response actions** — remote agents, firewall rule
   suggestions (always analyst-approved, never auto-executed).

---

## Credits

| | |
|---|---|
| **Author** | **Er-Suzen Kumar Mohanty** |
| **Project** | SentinelIDS — AI-Powered Intrusion Detection System |
| **Programme** | **IBM Cyber Security Project** |
| **Stack** | Python · scikit-learn · pandas · Flask · Chart.js |
| **Purpose** | Defensive security · Educational use only |
| **Version** | 1.0 |

The web interface footer displays:

```
Made by  Er-Suzen Kumar Mohanty
         IBM Cyber Security Project
```

---

*Educational project — Level: Beginner–Intermediate.*
