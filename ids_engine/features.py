"""Canonical network-flow feature schema.

An IDS has to cope with many dataset formats.  NSL-KDD, KDD Cup '99 and
CICIDS-style exports all describe the same *kind* of thing — a network flow —
but spell the columns differently (``src_bytes`` vs ``Total Length of Fwd
Packets``).  This module defines one canonical schema and an alias table so
every supported CSV lands on the same feature names.

Canonical schema
----------------
30 model features (27 numeric + 3 categorical) plus three *metadata* columns
(``src_ip``, ``dst_ip``, ``timestamp``) that are shown in the alert table but
never fed to the model.

Label mapping
-------------
Raw attack names (``neptune``, ``portsweep``, ``BENIGN``, ``DDoS`` …) are
folded into five NSL-KDD style categories:

    normal | probe | dos | r2l | u2r | unknown
"""

from __future__ import annotations

import re
from functools import lru_cache

# --------------------------------------------------------------------------
# Canonical feature schema (ordered)
# --------------------------------------------------------------------------

#: Numeric flow features fed to the model.
NUMERIC_FEATURES: list[str] = [
    # connection
    "duration",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    # content / intrusion indicators
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    # two-second window traffic statistics
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    # last 100 connection statistics to the same host
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_serror_rate",
    "dst_host_rerror_rate",
]

#: Categorical flow features (one-hot encoded inside the pipeline).
CATEGORICAL_FEATURES: list[str] = ["protocol_type", "service", "flag"]

#: Everything the model sees.
FEATURE_COLUMNS: list[str] = NUMERIC_FEATURES + CATEGORICAL_FEATURES

#: Display-only columns (never used for prediction).
META_COLUMNS: list[str] = ["src_ip", "dst_ip", "timestamp"]

#: The label column after normalisation.
LABEL_COLUMN = "label"

#: Filler for categorical values when a dataset does not provide them.
UNKNOWN_CATEGORY = "unknown"

#: Model feature-coverage (fraction of canonical features a row supplies)
#: below which a flow is reported as *partially observed*.
COVERAGE_WARN_FRACTION = 0.6


# --------------------------------------------------------------------------
# Column aliasing
# --------------------------------------------------------------------------

@lru_cache(maxsize=8192)
def _norm(name: str) -> str:
    """Lower-case and strip every non-alphanumeric character.

    ``"Src Bytes"`` -> ``"srcbytes"``, ``"Total Fwd Packets"`` -> ``"totalfwdpackets"``.
    """
    return re.sub(r"[^a-z0-9]", "", str(name).strip().lower())


#: ``normalised incoming column name`` -> ``canonical column name``.
#: The canonical names themselves are always accepted (see :func:`resolve_column`).
COLUMN_ALIASES: dict[str, str] = {
    # --- connection -------------------------------------------------------
    "duration": "duration",
    "flowduration": "duration",
    "flowdurationms": "duration",
    "durationms": "duration",
    "protocol": "protocol_type",
    "protocoltype": "protocol_type",
    "proto": "protocol_type",
    "service": "service",
    "flag": "flag",
    "state": "flag",
    "flowflags": "flag",
    # --- bytes ------------------------------------------------------------
    "srcbytes": "src_bytes",
    "sourcebytes": "src_bytes",
    "totalbytes": "src_bytes",
    "totallengthoffwdpackets": "src_bytes",
    "fwdpacketlengthtotal": "src_bytes",
    "totalfwdpacketlength": "src_bytes",
    "dstbytes": "dst_bytes",
    "destinationbytes": "dst_bytes",
    "totallengthofbwdpackets": "dst_bytes",
    "bwdpacketlengthtotal": "dst_bytes",
    "totalbwdpacketlength": "dst_bytes",
    # --- classic KDD flags ------------------------------------------------
    "land": "land",
    "wrongfragment": "wrong_fragment",
    "urgent": "urgent",
    "numfailedlogins": "num_failed_logins",
    "failedlogins": "num_failed_logins",
    "loggedin": "logged_in",
    "numcompromised": "num_compromised",
    "rootshell": "root_shell",
    "suattempted": "su_attempted",
    "numroot": "num_root",
    "numfilecreations": "num_file_creations",
    # --- window statistics ------------------------------------------------
    "count": "count",
    "connectioncount": "count",
    "srvcount": "srv_count",
    "servicecount": "srv_count",
    "serrorrate": "serror_rate",
    "srvserrorrate": "srv_serror_rate",
    "rerrorrate": "rerror_rate",
    "srvrerrorrate": "srv_rerror_rate",
    "samesrvrate": "same_srv_rate",
    "diffsrvrate": "diff_srv_rate",
    # --- host statistics --------------------------------------------------
    "dsthostcount": "dst_host_count",
    "destinationhostcount": "dst_host_count",
    "dsthostsrvcount": "dst_host_srv_count",
    "dsthostsamesrvrate": "dst_host_same_srv_rate",
    "dsthostdiffsrvrate": "dst_host_diff_srv_rate",
    "dsthostserrorrate": "dst_host_serror_rate",
    "dsthostrerrorrate": "dst_host_rerror_rate",
    # --- labels -----------------------------------------------------------
    "label": LABEL_COLUMN,
    "labels": LABEL_COLUMN,
    "class": LABEL_COLUMN,
    "attack": LABEL_COLUMN,
    "attacktype": LABEL_COLUMN,
    "attackname": LABEL_COLUMN,
    "category": LABEL_COLUMN,
    "target": LABEL_COLUMN,
    "result": LABEL_COLUMN,
    "threat": LABEL_COLUMN,
    # --- metadata ---------------------------------------------------------
    "srcip": "src_ip",
    "sourceip": "src_ip",
    "sourceaddress": "src_ip",
    "srcaddress": "src_ip",
    "src": "src_ip",
    "dstip": "dst_ip",
    "destinationip": "dst_ip",
    "destinationaddress": "dst_ip",
    "dstaddress": "dst_ip",
    "dst": "dst_ip",
    "dest": "dst_ip",
    "timestamp": "timestamp",
    "time": "timestamp",
    "datetime": "timestamp",
    "flowtimestamp": "timestamp",
    "flowstart": "timestamp",
    "starttime": "timestamp",
    "ts": "timestamp",
}

#: Alias table for raw attack names -> canonical category.
LABEL_ALIASES: dict[str, str] = {}


def _fill_label_aliases() -> None:
    """Map a large vocabulary of published attack names to five categories."""
    normal = ["normal", "benign", "legit", "legitimate", "nonattack", "noflow", "0"]
    dos = [
        "dos", "ddos", "neptune", "smurf", "back", "land", "pod", "teardrop",
        "apache2", "udpstorm", "processtable", "mailbomb", "worm", "httptorment",
        "slowloris", "hulk", "goldeneye", "slowhttptest", "ricochet",
        "dos.syn", "dos.udp", "dos.http", "dos goldeneye", "dos hulk",
        "dos slowloris", "dos slowhttptest", "bot",
    ]
    probe = [
        "probe", "portsweep", "ipsweep", "nmap", "satan", "saint", "mscan",
        "networkscan", "recon", "reconnaissance", "portscan", "ipscan",
        "hostdiscovery", "discoveryscan", "wardialing",
    ]
    r2l = [
        "r2l", "remotetolocal", "guess_passwd", "ftp_write", "imap", "phf",
        "multihop", "warezmaster", "warezclient", "spy", "xlock", "xsnoop",
        "snmpguess", "snmpgetattack", "httptunnel", "sendmail", "named",
        "guesspassword", "bruteforce", "brute_force", "credentialattack",
        "webattack", "web attack bruce force", "web attack brute force",
        "web attack sqli", "web attack xss", "sqli", "xss", "sql injection",
        "passwordattack", "sessionhijacking", "maninthe middle",
    ]
    u2r = [
        "u2r", "usertoroot", "buffervoverflow", "buffer_overflow", "loadmodule",
        "rootkit", "perl", "sqlattack", "xterm", "ps", "privilegeescalation",
        "privilege escalation", "infiltration", "backdoor", "trojan", "exploit",
        "ransomware", "keylogger", "spyware", "shellshock",
    ]
    for names, category in (
        (normal, "normal"),
        (dos, "dos"),
        (probe, "probe"),
        (r2l, "r2l"),
        (u2r, "u2r"),
    ):
        for name in names:
            LABEL_ALIASES[_norm(name)] = category


_fill_label_aliases()


#: Pre-computed lookup tables (built once; ``resolve_column`` runs per cell).
_CANONICAL_BY_NORM: dict[str, str] = {_norm(c): c for c in FEATURE_COLUMNS}
_LABEL_KEY: str = _norm(LABEL_COLUMN)


def resolve_column(name: str) -> str | None:
    """Return the canonical name for an incoming column, or ``None``."""
    key = _norm(name)
    canonical = _CANONICAL_BY_NORM.get(key)
    if canonical is not None:
        return canonical
    if key == _LABEL_KEY:
        return LABEL_COLUMN
    return COLUMN_ALIASES.get(key)


def map_label(raw) -> str | None:
    """Fold a raw dataset label into ``normal|probe|dos|r2l|u2r|unknown``.

    Returns ``None`` when the label cell is empty.
    """
    if raw is None:
        return None
    text = str(raw).strip()
    if not text or text.lower() in {"nan", "none", "null", "?"}:
        return None
    key = _norm(text)
    if key in LABEL_ALIASES:
        return LABEL_ALIASES[key]
    # "dos.udp", "Web Attack: Brute Force", "Infiltration" style strings
    head = re.split(r"[._:/\-]", text, maxsplit=1)[0]
    head_key = _norm(head)
    if head_key in LABEL_ALIASES:
        return LABEL_ALIASES[head_key]
    if key in {"attack", "attacker", "malicious", "threat", "anomaly", "1", "true"}:
        return "unknown"
    return "unknown"


#: Category -> human label used by the dashboard.
CATEGORY_LABELS: dict[str, str] = {
    "normal": "Normal traffic",
    "probe": "Probe / scan",
    "dos": "Denial of service",
    "r2l": "Remote access (R2L)",
    "u2r": "Privilege escalation (U2R)",
    "unknown": "Unclassified attack",
}
