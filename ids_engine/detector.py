"""Behavioural rules, risk scoring and alert construction.

The ML model says *what kind* of traffic this is; this module says *why a
human analyst should care*.  Rules encode well-known network attack
signatures (SYN floods, sweeps, brute-force logins, privilege escalation,
exfiltration …) in plain language, exactly like the rule engine in
PhishGuard, and every finding carries a severity and a point weight.

Final score (documented in the README)::

    risk_score = 0.50 * ML attack score      (1 - P(normal)) * 100
               + 0.25 * anomaly score        IsolationForest, 0-100
               + 0.25 * rule score           sum of finding points, capped

Score -> level:  <40 low · <65 medium · <85 high · >=85 critical.
Benign traffic with a clean bill of health is ``info`` (not an alert).
Confident attack predictions get a severity *floor* so a 0.95-confident
U2R flow can never be filed as "low".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

LEVELS = ["info", "low", "medium", "high", "critical"]

#: Attack category -> minimum level once confidence reaches ``FLOOR_CONFIDENCE``.
CATEGORY_FLOOR = {
    "probe": "medium",
    "dos": "medium",
    "r2l": "high",
    "u2r": "high",
    "unknown": "medium",
}
FLOOR_CONFIDENCE = 0.75

SCORE_WEIGHTS = {"ml": 0.50, "anomaly": 0.25, "rules": 0.25}


@dataclass
class Finding:
    code: str
    title: str
    detail: str
    severity: str   # low | medium | high | critical
    points: int


def _get(row, key: str, default: float = 0.0) -> float:
    try:
        value = row.get(key, default)
    except AttributeError:  # pandas Series
        value = row[key] if key in row else default
    if value is None:
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if number != number:  # NaN
        return default
    return number


# --------------------------------------------------------------------------
# Rule set
# --------------------------------------------------------------------------

def evaluate_flow(row, coverage: float = 1.0) -> list[Finding]:
    """Run every behavioural rule against one normalised flow record."""
    findings: list[Finding] = []

    serror = _get(row, "serror_rate")
    host_serror = _get(row, "dst_host_serror_rate")
    rerror = _get(row, "rerror_rate")
    count = _get(row, "count")
    same_srv = _get(row, "same_srv_rate")
    diff_srv = _get(row, "diff_srv_rate")
    host_count = _get(row, "dst_host_count")
    host_same = _get(row, "dst_host_same_srv_rate")
    failed_logins = _get(row, "num_failed_logins")
    compromised = _get(row, "num_compromised")
    root_shell = _get(row, "root_shell")
    src_bytes = _get(row, "src_bytes")
    dst_bytes = _get(row, "dst_bytes")
    duration = _get(row, "duration")
    protocol = str(row.get("protocol_type", "") or "").lower()
    flag = str(row.get("flag", "") or "").lower()

    # --- denial-of-service signatures -----------------------------------
    if serror >= 0.7:
        findings.append(Finding(
            "syn_flood",
            "Saturated SYN error rate",
            f"{serror:.0%} of connections in this window failed the TCP "
            "handshake — the classic signature of a half-open (SYN) flood.",
            "high", 18,
        ))
    elif host_serror >= 0.8:
        findings.append(Finding(
            "host_syn_flood",
            "Repeated handshake failures to one host",
            f"{host_serror:.0%} of recent connections to the destination host "
            "never completed — consistent with service exhaustion.",
            "high", 14,
        ))

    if count >= 200:
        findings.append(Finding(
            "connection_flood",
            "Extreme connection rate",
            f"{int(count)} connections inside a two-second window is far beyond "
            "normal application traffic and suggests a flood.",
            "high", 16,
        ))
    elif count >= 100:
        findings.append(Finding(
            "connection_spike",
            "Very high connection rate",
            f"{int(count)} connections in a two-second window — worth watching "
            "for denial-of-service activity.",
            "medium", 10,
        ))

    if protocol == "icmp" and count >= 60:
        findings.append(Finding(
            "icmp_flood",
            "ICMP echo flood",
            f"{int(count)} ICMP packets in one window matches smurf / ping-flood "
            "denial-of-service patterns.",
            "medium", 12,
        ))

    # --- reconnaissance / scanning --------------------------------------
    if count >= 20 and same_srv <= 0.25 and diff_srv >= 0.4:
        findings.append(Finding(
            "service_sweep",
            "Connections fanning out across many services",
            f"Only {same_srv:.0%} of {int(count)} connections used the same "
            "service — traffic is enumerating services on the target.",
            "high", 16,
        ))

    if host_count >= 150 and host_same <= 0.2:
        findings.append(Finding(
            "host_scan",
            "Wide scan across destination hosts",
            f"{int(host_count)} distinct destination hosts were contacted with "
            f"only {host_same:.0%} sharing one service — a horizontal port scan.",
            "high", 16,
        ))
    elif host_count >= 200 and _get(row, "dst_host_srv_count") <= 5:
        findings.append(Finding(
            "host_probe",
            "Probing many hosts for one service",
            f"{int(host_count)} hosts contacted but only "
            f"{int(_get(row, 'dst_host_srv_count'))} connections reused a "
            "service — targeted vulnerability probing.",
            "medium", 10,
        ))

    if rerror >= 0.7 and count >= 20:
        findings.append(Finding(
            "rejected_storm",
            "Storm of rejected connections",
            f"{rerror:.0%} of connections were rejected (RST) across "
            f"{int(count)} attempts — typical of aggressive sweeping.",
            "medium", 8,
        ))

    # --- credential / privilege attacks ---------------------------------
    if failed_logins >= 4:
        findings.append(Finding(
            "brute_force",
            "Repeated failed logins",
            f"{int(failed_logins)} failed authentication attempts in one flow — "
            "credential guessing or a brute-force attempt.",
            "high", 16,
        ))
    elif failed_logins >= 2:
        findings.append(Finding(
            "failed_logins",
            "Multiple failed logins",
            f"{int(failed_logins)} failed authentication attempts; verify the "
            "account and source address.",
            "medium", 10,
        ))

    if root_shell >= 1 or compromised >= 1:
        findings.append(Finding(
            "privilege_escalation",
            "Privilege-escalation indicators",
            "The flow shows a root shell or compromised process counters — "
            "behaviour associated with local privilege-escalation exploits.",
            "critical", 22,
        ))

    if _get(row, "num_file_creations") >= 3 or _get(row, "num_root") >= 2:
        findings.append(Finding(
            "persistence_activity",
            "Account / file manipulation",
            f"{int(_get(row, 'num_file_creations'))} file creations and "
            f"{int(_get(row, 'num_root'))} root account uses — possible "
            "persistence after a compromise.",
            "medium", 8,
        ))

    # --- data movement ---------------------------------------------------
    if src_bytes > 500_000 and src_bytes > 5 * dst_bytes + 10_000:
        findings.append(Finding(
            "data_exfiltration",
            "Large outbound data transfer",
            f"{src_bytes / 1_000_000:.1f} MB uploaded with almost no reply "
            "traffic — the shape of data exfiltration.",
            "high", 14,
        ))
    elif dst_bytes > 5_000_000:
        findings.append(Finding(
            "bulk_download",
            "Very large download",
            f"{dst_bytes / 1_000_000:.1f} MB received in a single flow; confirm "
            "the destination is an expected service.",
            "medium", 6,
        ))

    # --- protocol oddities ----------------------------------------------
    if _get(row, "land") >= 1:
        findings.append(Finding(
            "land_attack",
            "Source and destination identical",
            "A flow whose source and destination match is the classic 'land' "
            "denial-of-service pattern.",
            "medium", 10,
        ))

    if _get(row, "wrong_fragment") > 0 or _get(row, "urgent") > 0:
        findings.append(Finding(
            "malformed_packets",
            "Malformed fragments or urgent pointers",
            "Out-of-band urgent data or malformed fragments are used to crash "
            "or bypass naive packet handlers.",
            "medium", 10,
        ))

    if flag in {"sh", "rsto", "rstr"} and count >= 10:
        findings.append(Finding(
            "odd_flags",
            "Abnormal TCP flag combination",
            f"Connection state '{row.get('flag')}' with {int(count)} hits is a "
            "flag-scan / stealth-probe signature.",
            "low", 5,
        ))

    if count >= 50 and src_bytes == 0 and dst_bytes == 0:
        findings.append(Finding(
            "payloadless_burst",
            "Connection burst with no payload",
            f"{int(count)} connections with zero bytes transferred — probing "
            "for open ports rather than using the service.",
            "medium", 10,
        ))

    if duration >= 1800 and same_srv >= 0.8 and count <= 5:
        findings.append(Finding(
            "long_session",
            "Long-lived single-service session",
            f"{duration / 60:.0f} minutes on one service with almost no new "
            "connections — check for command-and-control beaconing.",
            "medium", 10,
        ))

    # --- observability ---------------------------------------------------
    if coverage < 0.6:
        findings.append(Finding(
            "partial_data",
            "Only partially observed flow",
            f"Just {coverage:.0%} of the expected flow features were present in "
            "the dataset, so the verdict rests on limited evidence.",
            "low", 0,
        ))

    return findings


# --------------------------------------------------------------------------
# Risk scoring
# --------------------------------------------------------------------------

def _level_for(score: float) -> str:
    if score < 40:
        return "low"
    if score < 65:
        return "medium"
    if score < 85:
        return "high"
    return "critical"


def _max_level(a: str, b: str) -> str:
    return a if LEVELS.index(a) >= LEVELS.index(b) else b


def score_flow(prediction: dict, findings: list[Finding]) -> dict:
    """Blend ML, anomaly and rule evidence into a level + score."""
    probabilities = prediction.get("probabilities", {}) or {}
    p_normal = float(probabilities.get("normal", 0.0))
    if not p_normal and prediction.get("label") == "normal":
        p_normal = float(prediction.get("confidence", 0.0))

    ml_score = max(0.0, min(1.0, 1.0 - p_normal)) * 100.0
    anomaly_score = max(0.0, min(1.0, float(prediction.get("anomaly_score", 0.0)))) * 100.0
    rule_score = min(100.0, float(sum(f.points for f in findings)))

    risk_score = int(round(
        SCORE_WEIGHTS["ml"] * ml_score
        + SCORE_WEIGHTS["anomaly"] * anomaly_score
        + SCORE_WEIGHTS["rules"] * rule_score
    ))
    risk_score = max(0, min(100, risk_score))

    label = str(prediction.get("label", "normal"))
    confidence = float(prediction.get("confidence", 0.0))
    level = _level_for(risk_score)

    if label == "normal" and level == "low" and not findings and risk_score < 25:
        level = "info"          # clean benign traffic — not an alert
    elif label != "normal" and confidence >= FLOOR_CONFIDENCE:
        level = _max_level(level, CATEGORY_FLOOR.get(label, "medium"))
    elif label == "normal" and findings and risk_score >= 40:
        level = _max_level(level, "low")   # benign, but evidence is on file

    return {
        "risk_score": risk_score,
        "risk_level": level,
        "ml_score": int(round(ml_score)),
        "anomaly_score": int(round(anomaly_score)),
        "rule_score": int(round(rule_score)),
        "component_weights": dict(SCORE_WEIGHTS),
        "severity": max((LEVELS.index(f.severity) for f in findings), default=0),
    }


def summarise(findings: list[Finding], prediction: dict, risk_level: str) -> list[str]:
    """Short human-readable reasons shown at the top of an alert."""
    reasons = [f.title for f in findings[:3]]
    if not reasons:
        label = prediction.get("label", "normal")
        if label == "normal" and risk_level in {"low", "medium", "high", "critical"}:
            reasons.append("Unusual behaviour profile despite a benign classification")
        elif label == "normal":
            reasons.append("No behavioural indicators triggered")
        else:
            reasons.append(f"Classified as {label} by the model")
    return reasons


def findings_payload(findings: list[Finding]) -> list[dict]:
    return [asdict(f) for f in findings]
