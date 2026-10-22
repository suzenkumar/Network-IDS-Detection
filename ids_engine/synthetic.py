"""Seeded synthetic network-flow dataset.

A self-contained demo corpus so the IDS runs **offline on first launch**, the
same way :mod:`phishing_detector.synthetic` does for PhishGuard.  Flows are
generated per attack category with distributions that mirror the published
signatures:

===========  ==========================================================
``normal``   Balanced sessions, moderate byte counts, few errors
``probe``    Many destination hosts, many services, low byte counts
``dos``      Huge connection counts, saturated SYN-error rates, short flows
``r2l``      Failed logins, longer sessions, credential-guessing patterns
``u2r``      Long silent sessions with root/compromise indicators
===========  ==========================================================

The raw labels use real attack names (``neptune``, ``portsweep``,
``guess_passwd`` …) so :func:`ids_engine.features.map_label` is exercised
exactly as it would be on NSL-KDD.

Re-run with a different ``seed`` for a different corpus::

    generate_flows(n=4000, seed=7)
"""

from __future__ import annotations

import random
import time

from .features import LABEL_ALIASES  # noqa: F401  (ensures label table is filled)

PROTOCOLS = ["tcp", "tcp", "tcp", "tcp", "udp", "icmp"]
SERVICES = ["http", "http", "http", "ftp", "ftp_data", "smtp", "ssh",
            "domain_u", "private", "other"]
FLAGS = ["SF", "SF", "SF", "S0", "REJ", "RSTR", "SH"]

#: Raw attack name per category (chosen so NSL-KDD names appear in the data).
RAW_LABELS: dict[str, list[str]] = {
    "normal": ["normal"],
    "probe": ["portsweep", "ipsweep", "nmap", "satan"],
    "dos": ["neptune", "smurf", "teardrop", "back"],
    "r2l": ["guess_passwd", "warezclient", "phf", "imap"],
    "u2r": ["buffer_overflow", "rootkit", "loadmodule", "perl"],
}

#: Relative share of each category in the corpus.
MIX: list[tuple[str, int]] = [
    ("normal", 45),
    ("probe", 20),
    ("dos", 20),
    ("r2l", 8),
    ("u2r", 7),
]

_IP_PREFIX = "10.0"


def _rand_ip(rng: random.Random) -> str:
    return f"{_IP_PREFIX}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _base_flow(rng: random.Random) -> dict:
    """A plausible benign-looking flow, mutated per category afterwards."""
    return {
        "duration": round(rng.expovariate(1 / 4.0), 3),
        "protocol_type": rng.choice(PROTOCOLS),
        "service": rng.choice(SERVICES),
        "flag": rng.choice(FLAGS[:3]),           # mostly SF
        "src_bytes": int(rng.expovariate(1 / 900.0)) + 40,
        "dst_bytes": int(rng.expovariate(1 / 1400.0)) + 80,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "num_failed_logins": 0,
        "logged_in": 1 if rng.random() < 0.7 else 0,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "count": max(1, int(rng.expovariate(1 / 6.0))),
        "srv_count": max(1, int(rng.expovariate(1 / 4.0))),
        "serror_rate": round(min(1.0, rng.betavariate(1.2, 14.0)), 3),
        "srv_serror_rate": round(min(1.0, rng.betavariate(1.2, 14.0)), 3),
        "rerror_rate": round(min(1.0, rng.betavariate(1.1, 16.0)), 3),
        "srv_rerror_rate": round(min(1.0, rng.betavariate(1.1, 16.0)), 3),
        "same_srv_rate": round(min(1.0, rng.betavariate(6.0, 2.0)), 3),
        "diff_srv_rate": round(min(1.0, rng.betavariate(1.5, 8.0)), 3),
        "dst_host_count": max(1, int(rng.expovariate(1 / 30.0))),
        "dst_host_srv_count": max(1, int(rng.expovariate(1 / 22.0))),
        "dst_host_same_srv_rate": round(min(1.0, rng.betavariate(5.0, 2.5)), 3),
        "dst_host_diff_srv_rate": round(min(1.0, rng.betavariate(1.5, 7.0)), 3),
        "dst_host_serror_rate": round(min(1.0, rng.betavariate(1.2, 14.0)), 3),
        "dst_host_rerror_rate": round(min(1.0, rng.betavariate(1.1, 16.0)), 3),
    }


def _mutate(category: str, flow: dict, rng: random.Random) -> None:
    """Push a generic flow toward the signature of its attack category."""
    if category == "probe":
        # Sweeps touch hundreds of hosts / services but transfer almost nothing.
        flow["count"] = rng.randint(40, 300)
        flow["srv_count"] = rng.randint(1, max(2, flow["count"] // 6))
        flow["same_srv_rate"] = round(rng.uniform(0.02, 0.25), 3)
        flow["diff_srv_rate"] = round(rng.uniform(0.5, 0.98), 3)
        flow["dst_host_count"] = rng.randint(150, 255)
        flow["dst_host_srv_count"] = rng.randint(1, 12)
        flow["dst_host_same_srv_rate"] = round(rng.uniform(0.01, 0.15), 3)
        flow["dst_host_diff_srv_rate"] = round(rng.uniform(0.6, 0.99), 3)
        flow["src_bytes"] = rng.randint(8, 120)
        flow["dst_bytes"] = rng.randint(0, 400)
        flow["flag"] = rng.choice(["RSTO", "RSTR", "REJ", "SH"])
        flow["duration"] = round(rng.uniform(0.0, 0.4), 3)

    elif category == "dos":
        # Half-open floods: enormous connection counts, saturated SYN errors.
        flow["count"] = rng.randint(120, 580)
        flow["srv_count"] = rng.randint(60, flow["count"])
        flow["serror_rate"] = round(rng.uniform(0.85, 1.0), 3)
        flow["srv_serror_rate"] = round(rng.uniform(0.85, 1.0), 3)
        flow["dst_host_serror_rate"] = round(rng.uniform(0.8, 1.0), 3)
        flow["same_srv_rate"] = round(rng.uniform(0.7, 1.0), 3)
        flow["dst_host_same_srv_rate"] = round(rng.uniform(0.7, 1.0), 3)
        flow["dst_host_count"] = rng.randint(120, 255)
        flow["dst_host_srv_count"] = rng.randint(60, 255)
        flow["flag"] = rng.choice(["S0", "S0", "REJ"])
        flow["duration"] = round(rng.uniform(0.0, 0.05), 3)
        flow["src_bytes"] = rng.randint(0, 60)
        flow["dst_bytes"] = 0
        flow["logged_in"] = 0

    elif category == "r2l":
        # Credential guessing / staged downloads inside one session.
        flow["num_failed_logins"] = rng.randint(2, 9)
        flow["duration"] = round(rng.uniform(4.0, 900.0), 3)
        flow["logged_in"] = 1
        flow["src_bytes"] = rng.randint(120, 5000)
        flow["dst_bytes"] = rng.randint(2_000, 400_000)
        flow["count"] = rng.randint(1, 12)
        flow["srv_count"] = flow["count"]
        flow["same_srv_rate"] = round(rng.uniform(0.8, 1.0), 3)
        flow["service"] = rng.choice(["ftp", "ftp_data", "smtp", "ssh", "private"])
        flow["flag"] = rng.choice(["SF", "SF", "REJ"])

    elif category == "u2r":
        # Tiny, quiet sessions that quietly escalate privileges.
        flow["duration"] = round(rng.uniform(30.0, 5400.0), 3)
        flow["num_compromised"] = rng.randint(1, 6)
        flow["root_shell"] = 1 if rng.random() < 0.75 else 0
        flow["su_attempted"] = 1 if rng.random() < 0.5 else 0
        flow["num_root"] = rng.randint(1, 4)
        flow["num_file_creations"] = rng.randint(1, 9)
        flow["src_bytes"] = rng.randint(60, 1200)
        flow["dst_bytes"] = rng.randint(40, 3000)
        flow["count"] = rng.randint(1, 6)
        flow["srv_count"] = 1
        flow["same_srv_rate"] = 1.0
        flow["diff_srv_rate"] = 0.0
        flow["dst_host_count"] = rng.randint(1, 8)
        flow["dst_host_srv_count"] = flow["dst_host_count"]
        flow["dst_host_same_srv_rate"] = 1.0
        flow["service"] = rng.choice(["ftp", "http", "other", "private"])
        flow["flag"] = "SF"


def _busy_server(flow: dict, rng: random.Random) -> None:
    """A legitimately busy server: dense traffic that *resembles* a flood.

    Real networks are full of this — a viral API or a public DNS resolver
    generates connection counts and handshake errors that look like a scan
    or a DoS.  Teaching the model about it is what produces genuinely
    useful *medium/low* alerts instead of a two-state verdict.
    """
    flow["count"] = rng.randint(70, 320)
    flow["srv_count"] = rng.randint(40, flow["count"])
    flow["same_srv_rate"] = round(rng.uniform(0.7, 1.0), 3)
    flow["diff_srv_rate"] = round(max(0.0, 1.0 - flow["same_srv_rate"]), 3)
    flow["serror_rate"] = round(rng.uniform(0.05, 0.55), 3)
    flow["srv_serror_rate"] = round(flow["serror_rate"] * rng.uniform(0.7, 1.0), 3)
    flow["dst_host_count"] = rng.randint(80, 250)
    flow["dst_host_srv_count"] = rng.randint(20, 150)
    flow["dst_host_same_srv_rate"] = round(rng.uniform(0.5, 1.0), 3)
    flow["dst_host_serror_rate"] = round(rng.uniform(0.05, 0.5), 3)
    flow["dst_bytes"] = max(int(flow["dst_bytes"]), rng.randint(5_000, 900_000))
    flow["logged_in"] = 1


def generate_flows(n: int = 6000, seed: int = 42, start_ts: int | None = None,
                   noise: float = 0.15) -> list[dict]:
    """Return ``n`` labelled synthetic flow records.

    Each record carries the canonical features plus ``label`` (raw attack
    name), ``src_ip``, ``dst_ip`` and ``timestamp`` metadata so the alert
    table has something to show.

    ``noise`` controls how much the classes overlap: that fraction of attack
    flows keeps several benign-looking dimensions (stealthy scans, slow
    credential guessing), and the same fraction of normal flows gets
    busy-server characteristics.  Some overlap is what real datasets look
    like and what makes calibrated risk levels possible.
    """
    rng = random.Random(seed)
    now = int(time.time()) if start_ts is None else start_ts
    total_weight = sum(weight for _, weight in MIX)

    categories: list[str] = []
    for category, weight in MIX:
        categories.extend([category] * max(1, round(n * weight / total_weight)))
    rng.shuffle(categories)
    categories = categories[:n]

    flows: list[dict] = []
    for index, category in enumerate(categories):
        flow = _base_flow(rng)
        original = dict(flow)
        _mutate(category, flow, rng)

        if category != "normal" and noise > 0 and rng.random() < noise:
            # Partially stealthy attack: roughly half the dimensions still
            # look benign, so the classifier stays appropriately uncertain.
            keys = list(original)
            rng.shuffle(keys)
            for key in keys[: rng.randint(1, max(1, len(keys) // 2))]:
                flow[key] = original[key]
        elif category == "normal" and noise > 0 and rng.random() < noise:
            _busy_server(flow, rng)

        flow["label"] = rng.choice(RAW_LABELS[category])
        flow["src_ip"] = _rand_ip(rng)
        flow["dst_ip"] = _rand_ip(rng)
        # Spread over the last 90 minutes, oldest first.
        flow["timestamp"] = now - (n - index) * max(1, (90 * 60) // max(1, n))
        flow["_category"] = category
        flows.append(flow)
    return flows


def demo_flows(n: int = 800, seed: int = 42) -> list[dict]:
    """Small on-the-fly corpus for the dashboard's *Load demo* button."""
    flows = generate_flows(n=n, seed=seed)
    for flow in flows:
        flow.pop("_category", None)
    return flows
