"""Real-time monitoring: watch this computer's live network traffic.

SentinelIDS started as a *batch* tool (analyse a flow CSV).  This module
makes it a **live IDS**: it observes the machine's own network activity in
real time, folds it into the canonical flow schema, and pushes every window
through exactly the same pipeline as a CSV upload — ML classifier, Isolation
Forest, behavioural rules, risk levels, alerts and dashboard charts.

Two interchangeable capture backends:

* **scapy** — true packet capture through Npcap/WinPcap.  Packets are folded
  into per-connection windows with real byte counts and TCP flag ratios, so
  SYN-flood and scan signatures fire exactly as they do on NSL-KDD data.
* **system** — a driver-free fallback that polls the OS connection table
  (``psutil.net_connections``) plus network counters.  Works without Npcap
  and without admin rights; byte counts are estimated, not measured.

Only connection *metadata* (addresses, ports, byte counts, states) is
observed — never packet contents.  Everything runs locally.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import time
from collections import deque
from datetime import datetime, timezone
from queue import Empty, Full, Queue

from .analysis import analyze_records
from .model import ModelStore

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is in requirements.txt
    psutil = None


class CaptureUnavailable(RuntimeError):
    """Raised when a capture backend cannot start (e.g. Npcap missing)."""


BACKENDS = ("auto", "system", "scapy")

#: Rolling window kept in memory (connection events / aggregated flows).
WINDOW_FLOWS = 1500

#: Alerts remembered for de-duplication across ticks.
MAX_FINGERPRINTS = 50_000

#: Active connections shown in snapshots.
MAX_SNAPSHOT_CONNS = 14

#: Alerts forwarded to subscribers in one tick.
MAX_NEW_ALERTS = 50

_LOOPBACK = {"127.0.0.1", "::1", "0.0.0.0", "::"}


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _service_name(port: int, proto: str) -> str:
    try:
        return socket.getservbyport(int(port), proto if proto in ("tcp", "udp") else "tcp")
    except OSError:
        return str(port)


def _is_loopback(address: str) -> bool:
    return str(address) in _LOOPBACK or str(address).startswith("127.")


def alert_fingerprint(alert: dict) -> str:
    """Stable identity of one alert across re-analyses of the same window."""
    basis = "|".join(str(alert.get(key, "")) for key in
                     ("src_ip", "dst_ip", "timestamp", "protocol",
                      "service", "risk_level"))
    return hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()


# ---------------------------------------------------------------------------
# Window-context features (shared by both backends)
# ---------------------------------------------------------------------------

def enrich_window(records: list[dict], now: float | None = None) -> list[dict]:
    """Fill the window-context features for one detection window.

    The canonical schema has features that describe *traffic around* a flow
    (``count``, ``same_srv_rate``, ``dst_host_*``).  On live data we derive
    them from the flows observed in the current window — the same way KDD
    derives them from its 2-second connection windows.  This is what lets
    scan / sweep / flood rules fire on live traffic.
    """
    now = time.time() if now is None else now

    host_conns: dict[str, list[dict]] = {}
    host_ports: dict[str, set[int]] = {}
    hostport_count: dict[tuple[str, int], int] = {}
    service_count: dict[int, int] = {}
    hostport_errors: dict[tuple[str, int], int] = {}
    hostport_resets: dict[tuple[str, int], int] = {}

    for record in records:
        host = str(record.get("dst_ip") or "unknown")
        try:
            port = int(record.get("_port") or 0)
        except (TypeError, ValueError):
            port = 0
        record.setdefault("timestamp", now)
        record["_port"] = port
        host_conns.setdefault(host, []).append(record)
        host_ports.setdefault(host, set()).add(port)
        hostport_count[(host, port)] = hostport_count.get((host, port), 0) + 1
        service_count[port] = service_count.get(port, 0) + 1
        failed = record.get("_failed")
        if failed is None:
            failed = str(record.get("flag")) in {"S0", "REJ", "RSTO", "RSTOS0"}
        if failed:
            hostport_errors[(host, port)] = hostport_errors.get((host, port), 0) + 1
            if str(record.get("flag")).startswith("RST"):
                hostport_resets[(host, port)] = hostport_resets.get((host, port), 0) + 1

    for record in records:
        host = str(record.get("dst_ip") or "unknown")
        port = record["_port"]
        key = (host, port)
        host_total = max(1, len(host_conns[host]))
        host_port_total = max(1, hostport_count[key])
        distinct = len(host_ports[host])
        error_rate = hostport_errors.get(key, 0) / host_port_total
        reset_rate = hostport_resets.get(key, 0) / host_port_total

        record.update({
            "count": hostport_count[key],
            "srv_count": service_count.get(port, 1),
            "same_srv_rate": round(host_port_total / host_total, 4),
            "diff_srv_rate": round(distinct / host_total, 4),
            "dst_host_count": len(host_conns[host]),
            "dst_host_srv_count": hostport_count[key],
            "dst_host_same_srv_rate": round(host_port_total / host_total, 4),
            "dst_host_diff_srv_rate": round(distinct / host_total, 4),
            "dst_host_serror_rate": round(error_rate, 4),
            "dst_host_rerror_rate": round(reset_rate, 4),
        })
    return records


# ---------------------------------------------------------------------------
# Backend 1 — packet capture (scapy / Npcap)
# ---------------------------------------------------------------------------

class ScapyFlowMonitor:
    """Folds a live packet capture into per-connection flow windows."""

    name = "scapy"

    def __init__(self, interval: float = 3.0, iface=None):
        self.interval = float(interval)
        self.iface = iface
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._flows: dict[tuple, dict] = {}
        self.note = ""

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        try:
            from scapy.all import conf, sniff  # noqa: F401
        except ImportError as exc:
            raise CaptureUnavailable(
                "scapy is not installed — pip install scapy (Windows also "
                "needs the Npcap driver)."
            ) from exc

        if self.iface is None:
            self.iface = conf.iface
        try:
            probe = sniff(count=0, timeout=1, iface=self.iface)
            del probe
        except Exception as exc:
            raise CaptureUnavailable(
                f"packet capture unavailable on {self.iface}: {exc}"
            ) from exc

        self.note = f"capturing on {self.iface}"
        self._stop.clear()
        self._thread = threading.Thread(target=self._run,
                                        name="ids-capture-scapy", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=4.0)
        self._thread = None

    # -- capture -----------------------------------------------------------
    def _run(self) -> None:
        from scapy.all import sniff
        while not self._stop.is_set():
            try:
                sniff(prn=self._on_packet, store=0, iface=self.iface, timeout=1)
            except Exception:
                if self._stop.is_set():
                    break
                time.sleep(1.0)

    def _on_packet(self, packet) -> None:  # pragma: no cover - needs live traffic
        from scapy.layers.inet import IP, TCP, UDP

        ip = packet.getlayer(IP)
        if ip is None:
            return
        tcp = packet.getlayer(TCP)
        udp = packet.getlayer(UDP)
        if tcp is not None:
            proto, sport, dport = "tcp", int(tcp.sport), int(tcp.dport)
            flags = int(tcp.flags)
        elif udp is not None:
            proto, sport, dport = "udp", int(udp.sport), int(udp.dport)
            flags = 0
        else:
            proto, sport, dport, flags = "icmp", 0, 0, 0

        length = int(ip.len or 0) or len(bytes(ip))
        src, dst = str(ip.src), str(ip.dst)
        now = time.time()
        key = (proto, src, sport, dst, dport)
        reverse = (proto, dst, dport, src, sport)

        with self._lock:
            record = self._flows.get(key)
            forward = True
            if record is None:
                record = self._flows.get(reverse)
                if record is not None:
                    forward = False   # only replies flip the direction
            if record is None:
                record = {
                    "protocol_type": proto,
                    "service": _service_name(dport, proto),
                    "flag": "",
                    "src_ip": src, "dst_ip": dst, "_port": dport,
                    "src_bytes": 0, "dst_bytes": 0, "packets": 0,
                    "syn": 0, "fin": 0, "rst": 0, "ack": 0,
                    "ts_first": now, "ts_last": now,
                    "land": 1 if (src == dst and sport == dport) else 0,
                    "timestamp": now,
                }
                self._flows[key] = record
            record["ts_last"] = now
            record["packets"] += 1
            if forward:
                record["src_bytes"] += length
            else:
                record["dst_bytes"] += length
            if proto == "tcp":
                if flags & 0x02:
                    record["syn"] += 1
                if flags & 0x01:
                    record["fin"] += 1
                if flags & 0x04:
                    record["rst"] += 1
                if flags & 0x10:
                    record["ack"] += 1

    # -- window hand-off ---------------------------------------------------
    def poll(self) -> tuple[list[dict], list[dict]]:
        with self._lock:
            flows, self._flows = self._flows, {}

        now = time.time()
        records: list[dict] = []
        snapshot: list[dict] = []
        for record in flows.values():
            proto = record["protocol_type"]
            tcp = proto == "tcp"
            answered = record["dst_bytes"] > 0
            syn, rst = record["syn"], record["rst"]
            if tcp:
                if syn and answered and not rst:
                    flag = "SF"
                elif syn and rst and not answered:
                    flag = "REJ"
                elif syn and not answered:
                    flag = "S0"
                elif rst:
                    flag = "RSTO"
                else:
                    flag = "SF" if record["ack"] else "OTH"
            else:
                flag = "SF"
            record["flag"] = flag
            failed = tcp and bool(syn) and not answered

            records.append({
                "protocol_type": proto,
                "service": record["service"],
                "flag": flag,
                "duration": round(max(0.0, record["ts_last"] - record["ts_first"]), 3),
                "src_bytes": record["src_bytes"],
                "dst_bytes": record["dst_bytes"],
                "land": record["land"],
                "wrong_fragment": 0, "urgent": 0,
                "num_failed_logins": 0, "logged_in": 0,
                "num_compromised": 0, "root_shell": 0, "su_attempted": 0,
                "num_root": 0, "num_file_creations": 0,
                "timestamp": record["ts_first"],
                "src_ip": record["src_ip"], "dst_ip": record["dst_ip"],
                "_port": record["_port"], "_failed": failed,
            })
            snapshot.append({
                "proto": proto,
                "local": f"{record['src_ip']}:{record.get('_port', '')}" if _is_loopback(record["src_ip"]) else f"{record['src_ip']}*",
                "remote": f"{record['dst_ip']}:{record['_port']}",
                "state": flag,
                "process": record["service"],
                "pid": "—",
            })

        records.sort(key=lambda item: item["timestamp"])
        return records, snapshot[:MAX_SNAPSHOT_CONNS]


# ---------------------------------------------------------------------------
# Backend 2 — OS connection table (psutil, no driver needed)
# ---------------------------------------------------------------------------

_STATE_FLAG = {
    "ESTABLISHED": "SF", "SYN_SENT": "S0", "SYN_RECEIVED": "S1",
    "TIME_WAIT": "RSTO", "CLOSE_WAIT": "REJ", "FIN_WAIT_1": "SF",
    "FIN_WAIT_2": "SF", "CLOSE": "SF", "LAST_ACK": "SF", "NONE": "OTH",
}


class SystemFlowMonitor:
    """Polls the OS connection table into flow-creation events."""

    name = "system"

    def __init__(self, interval: float = 3.0):
        if psutil is None:
            raise CaptureUnavailable(
                "psutil is not installed — pip install psutil."
            )
        self.interval = float(interval)
        self._first_seen: dict[tuple, float] = {}
        self._prev_counters: tuple[float, float] | None = None
        self.note = "polling the OS connection table (psutil)"

    def start(self) -> None:
        return  # polling begins at the first poll()

    def stop(self) -> None:
        return

    def _process_name(self, pid) -> str:
        if pid is None:
            return "—"
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            return f"pid:{pid}"

    def poll(self) -> tuple[list[dict], list[dict]]:
        now = time.time()
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            raise CaptureUnavailable(f"connection table unavailable: {exc}") from exc

        # system-wide byte counters -> coarse per-flow estimates
        bytes_sent = bytes_recv = 0.0
        try:
            counters = psutil.net_io_counters()
            if counters is not None and self._prev_counters is not None:
                bytes_sent = max(0.0, counters.bytes_sent - self._prev_counters[0])
                bytes_recv = max(0.0, counters.bytes_recv - self._prev_counters[1])
            if counters is not None:
                self._prev_counters = (counters.bytes_sent, counters.bytes_recv)
        except OSError:
            pass

        active: list[tuple] = []
        snapshot: list[dict] = []
        new_keys: list[tuple] = []
        key_info: dict[tuple, dict] = {}

        for conn in connections:
            # raddr may be None or an empty tuple () when psutil cannot
            # resolve the peer — both are falsy, the namedtuple is not.
            if conn.status == "LISTEN" or not conn.raddr:
                continue
            local_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
            local_port = conn.laddr.port if conn.laddr else 0
            remote_ip, remote_port = conn.raddr.ip, conn.raddr.port
            if _is_loopback(local_ip) and _is_loopback(remote_ip):
                continue  # this machine talking to itself — not "the network"
            try:
                proto = "tcp" if int(conn.type) == socket.SOCK_STREAM else "udp"
            except (TypeError, ValueError):
                proto = "tcp"
            key = (proto, local_ip, local_port, remote_ip, remote_port, conn.pid)
            active.append(key)
            key_info[key] = {
                "proto": proto, "local": f"{local_ip}:{local_port}",
                "remote": f"{remote_ip}:{remote_port}",
                "state": _STATE_FLAG.get(conn.status, "OTH"),
                "process": self._process_name(conn.pid), "pid": conn.pid or "—",
            }
            if key not in self._first_seen:
                self._first_seen[key] = now
                new_keys.append(key)
            if len(snapshot) < MAX_SNAPSHOT_CONNS:
                snapshot.append(dict(key_info[key]))

        # forget closed connections
        for key in list(self._first_seen):
            if key not in key_info:
                self._first_seen.pop(key, None)

        share_sent = bytes_sent / max(1, len(active))
        share_recv = bytes_recv / max(1, len(active))
        records: list[dict] = []
        for key in new_keys:
            proto, local_ip, local_port, remote_ip, remote_port, _pid = key
            info = key_info[key]
            flag = info["state"]
            service = _service_name(remote_port, proto)
            records.append({
                "protocol_type": proto,
                "service": service,
                "flag": flag,
                "duration": 0.0,
                "src_bytes": int(share_sent), "dst_bytes": int(share_recv),
                "land": 1 if (local_ip == remote_ip and local_port == remote_port) else 0,
                "wrong_fragment": 0, "urgent": 0,
                "num_failed_logins": 0, "logged_in": 0,
                "num_compromised": 0, "root_shell": 0, "su_attempted": 0,
                "num_root": 0, "num_file_creations": 0,
                "timestamp": self._first_seen[key],
                "src_ip": local_ip, "dst_ip": remote_ip,
                "_port": remote_port,
                "_failed": flag in {"S0", "REJ", "RSTO", "RSTOS0"},
            })
        return records, snapshot


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------

def build_monitor(backend: str = "auto", interval: float = 3.0):
    """Create (but do not start) the requested capture backend."""
    backend = str(backend or "auto").lower()
    if backend not in BACKENDS:
        raise CaptureUnavailable(
            f"unknown backend '{backend}' — choose one of {', '.join(BACKENDS)}"
        )

    if backend in ("auto", "scapy"):
        try:
            monitor = ScapyFlowMonitor(interval=interval)
            if backend == "scapy":
                return monitor
            # auto: probe capture silently, fall back to the system table
            try:
                monitor.start()
                monitor.stop()
                return ScapyFlowMonitor(interval=interval)
            except CaptureUnavailable:
                if backend == "scapy":
                    raise
        except CaptureUnavailable:
            if backend == "scapy":
                raise
    return SystemFlowMonitor(interval=interval)


# ---------------------------------------------------------------------------
# The live detector loop
# ---------------------------------------------------------------------------

class LiveDetector:
    """Captures traffic, analyses every window and broadcasts reports.

    A background thread runs ``monitor.poll()`` every *interval* seconds,
    feeds the accumulated window through :func:`analyze_records`, de-duplicates
    alerts across ticks, appends them to an optional JSONL log, and pushes
    ``{"report", "status", "new_alerts"}`` to every subscriber queue (the
    dashboard's Server-Sent-Events stream).
    """

    def __init__(self, store: ModelStore, backend: str = "auto",
                 interval: float = 3.0, window_flows: int = WINDOW_FLOWS,
                 log_dir: str | None = None):
        self.store = store
        self.backend = backend
        self.interval = float(interval)
        self.window_flows = int(window_flows)
        self.log_dir = log_dir

        self.monitor = None
        self._flows: deque[dict] = deque(maxlen=self.window_flows)
        self._fingerprints: deque[str] = deque(maxlen=MAX_FINGERPRINTS)
        self._fp_set: set[str] = set()
        self._subscribers: list[Queue] = []
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._conns: list[dict] = []

        self.started_at: str | None = None
        self._started_monotonic = 0.0
        self.ticks = 0
        self.flows_seen = 0
        self.alerts_total = 0
        self.last_error: str | None = None
        self.last_report: dict | None = None
        self.last_tick_at: float | None = None

    # -- lifecycle ---------------------------------------------------------
    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def configure(self, backend: str | None = None, interval: float | None = None,
                  restart: bool = True) -> None:
        was_running = self.running
        if was_running and restart:
            self.stop()
        if backend is not None:
            self.backend = backend
        if interval is not None:
            self.interval = float(interval)
        if was_running and restart:
            self.start()

    def start(self) -> dict:
        with self._lock:
            if self.running:
                return self.snapshot()
            monitor = build_monitor(self.backend, self.interval)
            monitor.start()
            self.monitor = monitor
            self._stop.clear()
            # fresh session: drop the previous window and its counters so the
            # dashboard never shows "stale" totals from before the restart
            self.last_error = None
            self._flows.clear()
            self._fingerprints.clear()
            self._fp_set.clear()
            self._conns = []
            self.ticks = 0
            self.flows_seen = 0
            self.alerts_total = 0
            self.last_report = None
            self.last_tick_at = None
            self.started_at = _iso_now()
            self._started_monotonic = time.monotonic()
            self._thread = threading.Thread(target=self._run,
                                            name="ids-live-detector", daemon=True)
            self._thread.start()
            return self.snapshot()

    def stop(self) -> dict:
        with self._lock:
            self._stop.set()
            monitor, self.monitor = self.monitor, None
            thread, self._thread = self._thread, None
        if monitor is not None:
            try:
                monitor.stop()
            except Exception:  # pragma: no cover - defensive
                pass
        if thread and thread.is_alive():
            thread.join(timeout=5.0)
        self.broadcast({"type": "stopped", "data": {}})
        return self.snapshot()

    def configure_and_start(self, backend: str = "auto", interval: float = 3.0) -> dict:
        self.backend = backend
        self.interval = float(interval)
        return self.start()

    # -- subscribers (Server-Sent Events) ----------------------------------
    def subscribe(self, maxsize: int = 200) -> Queue:
        queue_: Queue = Queue(maxsize=maxsize)
        with self._lock:
            self._subscribers.append(queue_)
        return queue_

    def unsubscribe(self, queue_: Queue) -> None:
        with self._lock:
            if queue_ in self._subscribers:
                self._subscribers.remove(queue_)

    def broadcast(self, message: dict) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        for queue_ in subscribers:
            try:
                queue_.put_nowait(message)
            except Full:
                try:
                    queue_.get_nowait()      # drop the oldest, keep the newest
                    queue_.put_nowait(message)
                except Empty:
                    pass

    # -- the loop ----------------------------------------------------------
    def _run(self) -> None:
        while not self._stop.is_set():
            tick_start = time.monotonic()
            try:
                records, conns = self.monitor.poll()
            except CaptureUnavailable as exc:
                self.last_error = str(exc)
                records, conns = [], []
            except Exception as exc:  # pragma: no cover - defensive
                self.last_error = f"capture failed: {exc}"
                records, conns = [], []
            try:
                self._tick(records, conns)
            except Exception as exc:  # pragma: no cover - defensive
                self.last_error = f"analysis failed: {exc}"
            elapsed = time.monotonic() - tick_start
            self._stop.wait(max(0.2, self.interval - elapsed))

    def _tick(self, records: list[dict], conns: list[dict]) -> None:
        now = time.time()
        self.ticks += 1
        self._conns = conns
        if records:
            enrich_window(records, now)
            self._flows.extend(records)
            self.flows_seen += len(records)

        report = None
        new_alerts: list[dict] = []
        with self._lock:
            if self._flows:
                report = analyze_records(list(self._flows), self.store,
                                         source="live")
                for alert in report["alerts"]:
                    fingerprint = alert_fingerprint(alert)
                    if fingerprint in self._fp_set:
                        continue
                    self._fp_set.add(fingerprint)
                    self._fingerprints.append(fingerprint)
                    alert["_fp"] = fingerprint
                    new_alerts.append(alert)
                new_alerts.sort(key=lambda item: -item["risk_score"])
                new_alerts = new_alerts[:MAX_NEW_ALERTS]
                self.alerts_total += len(new_alerts)
                self.last_report = report

        self.last_tick_at = now
        if new_alerts:
            self._append_alert_log(new_alerts)

        self.broadcast({
            "type": "tick",
            "data": {
                "report": report,
                "status": self.snapshot(),
                "new_alerts": new_alerts,
            },
        })

    def _append_alert_log(self, alerts: list[dict]) -> None:
        if not self.log_dir:
            return
        try:
            os.makedirs(self.log_dir, exist_ok=True)
            day = datetime.now(timezone.utc).strftime("%Y%m%d")
            path = os.path.join(self.log_dir, f"live-alerts-{day}.jsonl")
            with open(path, "a", encoding="utf-8") as handle:
                for alert in alerts:
                    handle.write(json.dumps({
                        "logged_at": _iso_now(),
                        "risk_level": alert["risk_level"],
                        "risk_score": alert["risk_score"],
                        "src_ip": alert["src_ip"],
                        "dst_ip": alert["dst_ip"],
                        "protocol": alert["protocol"],
                        "service": alert["service"],
                        "category": alert["label"],
                        "reasons": alert["reasons"],
                    }) + "\n")
        except OSError:  # pragma: no cover - disk issues must not kill the loop
            pass

    # -- introspection -----------------------------------------------------
    def snapshot(self) -> dict:
        with self._lock:
            uptime = (time.monotonic() - self._started_monotonic
                      if self.running and self._started_monotonic else 0.0)
            window_alerts = (self.last_report["summary"]["alerts"]
                             if self.last_report else 0)
            return {
                "running": self.running,
                "backend": self.monitor.name if self.monitor else self.backend,
                "backend_note": getattr(self.monitor, "note", "") or "",
                "interval_s": self.interval,
                "started_at": self.started_at,
                "uptime_s": round(uptime, 1),
                "ticks": self.ticks,
                "flows_in_window": len(self._flows),
                "flows_seen": self.flows_seen,
                "alerts_total": self.alerts_total,
                "window_alerts": window_alerts,
                "last_tick_at": (datetime.fromtimestamp(self.last_tick_at, timezone.utc)
                                 .isoformat(timespec="seconds")
                                 if self.last_tick_at else None),
                "last_error": self.last_error,
                "conns": list(self._conns),
            }
