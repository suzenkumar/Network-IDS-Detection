/* ============================================================
   SentinelIDS — dashboard logic (Chart.js + fetch API)
   IBM Cyber Security Project · Er-Suzen Kumar Mohanty
   ============================================================ */

"use strict";

const $ = (selector) => document.querySelector(selector);

const LEVELS = ["info", "low", "medium", "high", "critical"];
const LEVEL_COLORS = {
  info: "#4ade80",
  low: "#2de2e6",
  medium: "#ffb02e",
  high: "#ff7a29",
  critical: "#ff3d5a",
};
const CAT_COLORS = {
  normal: "#4ade80",
  probe: "#2de2e6",
  dos: "#ff7a29",
  r2l: "#ffb02e",
  u2r: "#ff3d5a",
  unknown: "#b5a4d0",
};

const state = {
  report: null, level: "all", query: "", charts: {},
  flashKeys: null,
  live: { running: false, es: null, ticks: 0 },
};

/* ---------------- helpers ---------------- */

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function pct(value, digits = 1) {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return `${(Number(value) * 100).toFixed(digits)}%`;
}

function alertKey(alert) {
  return `${alert.src_ip}|${alert.dst_ip}|${alert.timestamp}|${alert.risk_level}`;
}

function busy(flag, label) {
  const demo = $("#btnDemo");
  demo.disabled = flag;
  const textNode = demo.childNodes[demo.childNodes.length - 1];
  textNode.textContent = flag ? label : "Load demo dataset";
}

function showError(message) {
  const box = $("#errorBox");
  if (!message) { box.hidden = true; box.textContent = ""; return; }
  box.hidden = false;
  box.textContent = message;
}

async function getJSON(url, options) {
  const response = await fetch(url, options);
  let payload = null;
  try { payload = await response.json(); } catch (_) { /* non-JSON error page */ }
  if (!response.ok) {
    throw new Error((payload && payload.error) || `Request failed (${response.status})`);
  }
  return payload;
}

/* ---------------- health badge ---------------- */

async function loadHealth() {
  const badge = $("#modelStatus");
  try {
    const health = await getJSON("/api/health");
    if (health.trained) {
      const kind = health.kind || "model";
      const acc = health.metrics && health.metrics.accuracy;
      badge.className = "badge ok";
      badge.innerHTML = `<span class="dot"></span> model ready · ${esc(kind)}` +
        (acc !== undefined && acc !== null ? ` · ${(acc * 100).toFixed(1)}% hold-out acc` : "");
    } else {
      badge.className = "badge bad";
      badge.innerHTML = `<span class="dot"></span> model missing — run train_model.py`;
    }
  } catch (_) {
    badge.className = "badge bad";
    badge.innerHTML = `<span class="dot"></span> API unreachable`;
  }
}

/* ---------------- charts ---------------- */

function chartDefaults() {
  if (!window.Chart) return;
  Chart.defaults.color = "#b5a4d0";
  Chart.defaults.borderColor = "rgba(170, 130, 255, .13)";
  Chart.defaults.font.family = '"Outfit", "Segoe UI", system-ui, sans-serif';
  Chart.defaults.font.size = 12;
}

/* ---------------- pseudo-3D chart plugins ----------------
   Chart.js has no real 3D engine, so we fake an isometric
   extrusion: a darker "side face" + lighter "top face" drawn
   behind every bar, and a cylinder wall under the doughnut.
   Toggling body.flat makes both plugins a no-op (pure 2D). */

function isFlat() {
  return document.body.classList.contains("flat");
}

function shade(hex, factor) {
  if (typeof hex !== "string" || hex[0] !== "#" || hex.length !== 7) return hex;
  const n = parseInt(hex.slice(1), 16);
  const r = Math.min(255, Math.round(((n >> 16) & 255) * factor));
  const g = Math.min(255, Math.round(((n >> 8) & 255) * factor));
  const b = Math.min(255, Math.round((n & 255) * factor));
  return `rgb(${r}, ${g}, ${b})`;
}

const DEPTH_X = 11;
const DEPTH_Y = -6;
const DOUTH_DEPTH = 13;

const bar3D = {
  id: "bar3D",
  beforeDatasetsDraw(chart) {
    if (isFlat()) return;
    const horizontal = chart.options.indexAxis === "y";
    const ctx = chart.ctx;
    ctx.save();
    chart.data.datasets.forEach((ds, i) => {
      if (ds.hidden) return;
      const meta = chart.getDatasetMeta(i);
      if (meta.hidden || !meta.data.length) return;
      const colors = ds.backgroundColor;
      meta.data.forEach((el, j) => {
        const color = Array.isArray(colors) ? colors[j] : colors;
        if (typeof color !== "string" || color[0] !== "#") return;
        let x, y, w, h;
        if (horizontal) {
          x = Math.min(el.x, el.base);
          w = Math.abs(el.base - el.x);
          y = el.y - (el.height || 12) / 2;
          h = el.height || 12;
        } else {
          x = el.x - el.width / 2;
          w = el.width;
          y = Math.min(el.y, el.base);
          h = Math.abs(el.base - el.y);
        }
        if (w < 2 || h < 2) return;
        // side face
        ctx.fillStyle = shade(color, 0.5);
        ctx.beginPath();
        ctx.moveTo(x + w, y);
        ctx.lineTo(x + w + DEPTH_X, y + DEPTH_Y);
        ctx.lineTo(x + w + DEPTH_X, y + h + DEPTH_Y);
        ctx.lineTo(x + w, y + h);
        ctx.closePath();
        ctx.fill();
        // top face
        ctx.fillStyle = shade(color, 0.72);
        ctx.beginPath();
        ctx.moveTo(x, y);
        ctx.lineTo(x + DEPTH_X, y + DEPTH_Y);
        ctx.lineTo(x + w + DEPTH_X, y + DEPTH_Y);
        ctx.lineTo(x + w, y);
        ctx.closePath();
        ctx.fill();
      });
    });
    ctx.restore();
  },
};

const doughnut3D = {
  id: "doughnut3D",
  beforeDatasetDraw(chart, args) {
    if (isFlat()) return;
    const meta = args.meta;
    if (!meta || !meta.data.length) return;
    const colors = (chart.data.datasets[args.index] || {}).backgroundColor;
    const ctx = chart.ctx;
    ctx.save();
    // draw the cylinder wall from the bottom up; Chart.js then
    // paints the top ring over it
    for (let off = DOUTH_DEPTH; off >= 1; off--) {
      const light = 0.38 + 0.2 * (1 - off / DOUTH_DEPTH);
      meta.data.forEach((arc, i) => {
        const color = Array.isArray(colors) ? colors[i] : colors;
        if (typeof color !== "string" || color[0] !== "#") return;
        ctx.fillStyle = shade(color, light);
        ctx.beginPath();
        ctx.translate(0, off);
        ctx.arc(arc.x, arc.y, arc.outerRadius, arc.startAngle, arc.endAngle);
        ctx.arc(arc.x, arc.y, arc.innerRadius, arc.endAngle, arc.startAngle, true);
        ctx.closePath();
        ctx.translate(0, -off);
        ctx.fill();
      });
    }
    ctx.restore();
  },
};

function makeChart(id, config) {
  const canvas = document.getElementById(id);
  if (!canvas || !window.Chart) return;
  if (state.charts[id]) state.charts[id].destroy();
  state.charts[id] = new Chart(canvas.getContext("2d"), config);
}

function renderCharts(report) {
  const charts = report.charts || {};

  /* 1 — risk levels (doughnut) */
  const risk = charts.risk || [];
  makeChart("chartRisk", {
    type: "doughnut",
    data: {
      labels: risk.map((r) => r.level[0].toUpperCase() + r.level.slice(1)),
      datasets: [{
        data: risk.map((r) => r.count),
        backgroundColor: risk.map((r) => LEVEL_COLORS[r.level]),
        borderColor: "#1d1233",
        borderWidth: 2,
      }],
    },
    plugins: [doughnut3D],
    options: {
      responsive: true, maintainAspectRatio: true, aspectRatio: 1.5, cutout: "58%",
      hoverOffset: 0,
      plugins: {
        legend: { position: "bottom", labels: { boxWidth: 12, padding: 12 } },
        tooltip: { callbacks: { label: (c) => ` ${c.label}: ${c.raw} flows` } },
      },
    },
  });

  /* 2 — attack categories (horizontal bar) */
  const cats = (charts.categories || []).slice().sort((a, b) => a.count - b.count);
  makeChart("chartCategories", {
    type: "bar",
    data: {
      labels: cats.map((c) => c.label),
      datasets: [{
        label: "Flows",
        data: cats.map((c) => c.count),
        backgroundColor: cats.map((c) => CAT_COLORS[c.category] || "#b5a4d0"),
        borderRadius: 4, barThickness: 18,
      }],
    },
    plugins: [bar3D],
    options: {
      indexAxis: "y", responsive: true, maintainAspectRatio: true, aspectRatio: 1.5,
      plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true, ticks: { precision: 0 } }, y: { grid: { display: false } } },
    },
  });

  /* 3 — alerts over time (stacked bar) */
  const timeline = charts.timeline || [];
  const timeLevels = ["low", "medium", "high", "critical"];
  makeChart("chartTimeline", {
    type: "bar",
    data: {
      labels: timeline.map((t) => t.t),
      datasets: timeLevels.map((level) => ({
        label: level,
        data: timeline.map((t) => t[level] || 0),
        backgroundColor: LEVEL_COLORS[level],
        borderRadius: 3,
      })),
    },
    plugins: [bar3D],
    options: {
      responsive: true, maintainAspectRatio: true, aspectRatio: 2.6,
      plugins: { legend: { position: "bottom", labels: { boxWidth: 12, padding: 10 } } },
      scales: {
        x: { stacked: true, grid: { display: false } },
        y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } },
      },
    },
  });

  /* 4 — protocol split (stacked bar) */
  const protocols = charts.protocols || [];
  makeChart("chartProtocols", {
    type: "bar",
    data: {
      labels: protocols.map((p) => p.protocol),
      datasets: [
        { label: "Benign", data: protocols.map((p) => p.benign), backgroundColor: "#4ade80", borderRadius: 4 },
        { label: "Malicious", data: protocols.map((p) => p.attack), backgroundColor: "#ff3d5a", borderRadius: 4 },
      ],
    },
    plugins: [bar3D],
    options: {
      responsive: true, maintainAspectRatio: true, aspectRatio: 1.5,
      plugins: { legend: { position: "bottom", labels: { boxWidth: 12, padding: 10 } } },
      scales: {
        x: { stacked: true, grid: { display: false } },
        y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } },
      },
    },
  });

  /* 5 — targeted services */
  const services = charts.services || [];
  makeChart("chartServices", {
    type: "bar",
    data: {
      labels: services.map((s) => s.service),
      datasets: [{
        label: "Attacks",
        data: services.map((s) => s.count),
        backgroundColor: "#a78bfa", borderRadius: 4, barThickness: 16,
      }],
    },
    plugins: [bar3D],
    options: {
      indexAxis: "y", responsive: true, maintainAspectRatio: true, aspectRatio: 1.5,
      plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true, ticks: { precision: 0 } }, y: { grid: { display: false } } },
    },
  });

  /* 6 — model quality vs. ground truth (only for labelled datasets) */
  const evaluation = report.evaluation;
  const evalCard = $("#evalCard");
  if (evaluation) {
    evalCard.hidden = false;
    const labels = evaluation.labels.filter((l) => evaluation.per_class[l]);
    makeChart("chartEval", {
      type: "bar",
      data: {
        labels: labels.map((l) => l),
        datasets: [
          { label: "Precision", data: labels.map((l) => evaluation.per_class[l].precision), backgroundColor: "#ff9d2e", borderRadius: 4 },
          { label: "Recall", data: labels.map((l) => evaluation.per_class[l].recall), backgroundColor: "#2de2e6", borderRadius: 4 },
          { label: "F1", data: labels.map((l) => evaluation.per_class[l].f1), backgroundColor: "#4ade80", borderRadius: 4 },
        ],
      },
      plugins: [bar3D],
      options: {
        responsive: true, maintainAspectRatio: true, aspectRatio: 2.6,
        plugins: { legend: { position: "bottom", labels: { boxWidth: 12, padding: 10 } } },
        scales: {
          x: { grid: { display: false } },
          y: { beginAtZero: true, max: 1, ticks: { callback: (v) => `${Math.round(v * 100)}%` } },
        },
      },
    });
  } else {
    evalCard.hidden = true;
  }
}

/* ---------------- KPIs ---------------- */

function renderKpis(report) {
  const s = report.summary;
  $("#kpis").hidden = false;
  $("#kpiFlows").textContent = s.flows.toLocaleString();
  $("#kpiFlowsSub").textContent = `${report.dataset.feature_count} features · ${pct(report.dataset.coverage, 0)} schema`;
  $("#kpiAlerts").textContent = s.alerts.toLocaleString();
  $("#kpiAlertsSub").textContent = `${s.low} low · ${s.medium} medium`;
  $("#kpiMalicious").textContent = `${s.malicious_pct}%`;
  $("#kpiMaliciousSub").textContent = `${s.malicious.toLocaleString()} flows flagged`;
  $("#kpiSevere").textContent = (s.critical + s.high).toLocaleString();

  const metrics = report.model.metrics || {};
  if (metrics.macro_f1 !== undefined && metrics.macro_f1 !== null) {
    $("#kpiF1").textContent = pct(metrics.macro_f1, 1);
    const bits = [];
    if (metrics.accuracy !== undefined) bits.push(`acc ${pct(metrics.accuracy, 1)}`);
    if (metrics.anomaly_auc !== undefined) bits.push(`AUC ${metrics.anomaly_auc}`);
    bits.push(report.model.kind);
    $("#kpiF1Sub").textContent = bits.join(" · ");
  } else {
    $("#kpiF1").textContent = "—";
    $("#kpiF1Sub").textContent = "run train_model.py";
  }
}

/* ---------------- alerts table ---------------- */

function detailHtml(alert) {
  const reasons = alert.reasons.map((r) => `<li>${esc(r)}</li>`).join("");
  const findings = (alert.findings || []).map((f) => `
    <div class="finding">
      <b>${esc(f.title)}<span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span></b>
      <span class="detail-txt">${esc(f.detail)}</span>
    </div>`).join("") || `<p class="cell-dim">No behavioural rule fired on this flow.</p>`;

  const signs = (alert.ml_signs || []).map((s) => `
    <div class="contrib">
      <span class="tok">${esc(s.token)}</span>
      <span class="val">value ${esc(s.value)}</span>
      <span class="${s.contribution >= 0 ? "pos" : "neg"}">${s.contribution >= 0 ? "+" : ""}${s.contribution}</span>
    </div>`).join("") || `<p class="cell-dim">No single feature dominated this verdict.</p>`;

  const features = Object.entries(alert.features || {}).map(([key, value]) =>
    `<span class="feat">${esc(key)} <b>${esc(value)}</b></span>`).join("");

  const probs = Object.entries(alert.probabilities || {})
    .sort((a, b) => b[1] - a[1])
    .map(([label, value]) => `<span class="feat">${esc(label)} <b>${pct(value, 1)}</b></span>`).join("");

  return `
    <div class="detail-grid">
      <div class="detail-block">
        <h5>Why this alert</h5>
        <ul class="reason-list">${reasons}</ul>
        <h5 style="margin-top:14px">Behavioural findings</h5>
        ${findings}
      </div>
      <div class="detail-block">
        <h5>What the model noticed</h5>
        ${signs}
        <h5 style="margin-top:14px">Class probabilities</h5>
        <div class="feat-grid">${probs}</div>
        <p class="pct" style="margin:10px 0 0">
          anomaly score ${pct(alert.anomaly_score, 1)} · coverage ${pct(alert.coverage, 0)}
        </p>
      </div>
      <div class="detail-block">
        <h5>Flow features</h5>
        <div class="feat-grid">${features}</div>
        <h5 style="margin-top:14px">Score breakdown</h5>
        <div class="feat-grid">
          <span class="feat">ML ${esc(alert.ml_score)}</span>
          <span class="feat">rules ${esc(alert.rule_score)}</span>
          <span class="feat">risk <b>${esc(alert.risk_score)}</b></span>
        </div>
      </div>
    </div>`;
}

function alertRowHtml(alert) {
  const color = LEVEL_COLORS[alert.risk_level] || "#b5a4d0";
  return `
    <tr class="alert-row" data-id="${alert.id}" data-key="${esc(alertKey(alert))}" tabindex="0" aria-expanded="false">
      <td><span class="risk-pill risk-${esc(alert.risk_level)}">${esc(alert.risk_level)}</span></td>
      <td>
        <div class="score-bar">
          <div class="score-track"><div class="score-fill" style="width:${alert.risk_score}%;background:${color}"></div></div>
          <span class="score-num">${alert.risk_score}</span>
        </div>
      </td>
      <td class="cell-dim mono">${esc(alert.timestamp || "—")}</td>
      <td><span class="mono">${esc(alert.src_ip)}</span><span class="arrow">→</span><span class="mono">${esc(alert.dst_ip)}</span></td>
      <td>${esc(alert.protocol)}</td>
      <td class="cell-dim">${esc(alert.service)}</td>
      <td><span class="cat-tag">${esc(alert.category_label)}</span></td>
      <td>${pct(alert.confidence, 1)}<div class="pct">model</div></td>
      <td>${pct(alert.anomaly_score, 1)}<div class="pct">unusual</div></td>
    </tr>`;
}

/* Details are built on demand: pre-rendering an explainability block for
   every alert created ~60k DOM nodes and made the page crawl. */
function toggleDetail(row) {
  const next = row.nextElementSibling;
  if (next && next.classList.contains("detail-row")) {
    next.remove();
    row.classList.remove("open");
    row.setAttribute("aria-expanded", "false");
    return;
  }
  const alert = (state.report?.alerts || []).find((a) => String(a.id) === String(row.dataset.id));
  if (!alert) return;
  const detail = document.createElement("tr");
  detail.className = "detail-row";
  detail.dataset.detail = row.dataset.id;
  detail.innerHTML = `<td colspan="9">${detailHtml(alert)}</td>`;
  row.after(detail);
  row.classList.add("open");
  row.setAttribute("aria-expanded", "true");
}

function matchesFilter(alert) {
  if (state.level !== "all" && alert.risk_level !== state.level) return false;
  if (!state.query) return true;
  const haystack = [
    alert.src_ip, alert.dst_ip, alert.service, alert.protocol,
    alert.category_label, alert.label, alert.risk_level,
    ...(alert.reasons || []),
  ].join(" ").toLowerCase();
  return haystack.includes(state.query);
}

function renderAlerts(report) {
  $("#alertsPanel").hidden = false;

  const visible = report.alerts.filter(matchesFilter);
  const body = $("#alertsBody");

  if (!visible.length) {
    body.innerHTML = `<tr><td colspan="9" class="empty">No alerts match this filter.</td></tr>`;
  } else {
    body.innerHTML = visible.map(alertRowHtml).join("");
  }

  // Highlight freshly-captured live alerts once
  if (state.flashKeys && state.flashKeys.size) {
    body.querySelectorAll("tr.alert-row").forEach((row) => {
      if (state.flashKeys.has(row.dataset.key)) row.classList.add("flash-row");
    });
    state.flashKeys = null;
  }

  $("#alertsNote").textContent =
    `${report.alerts_total.toLocaleString()} alert(s) across ${report.summary.flows.toLocaleString()} flows` +
    (state.level !== "all" || state.query ? ` · ${visible.length} shown after filtering` : "");

  const foot = $("#tableFoot");
  if (report.alerts_returned < report.alerts_total) {
    foot.hidden = false;
    foot.textContent =
      `Showing ${report.alerts_returned} of ${report.alerts_total} alerts (top entries per risk level). ` +
      `The KPI cards and charts above always cover every analysed flow.`;
  } else {
    foot.hidden = true;
  }
}

/* ---------------- report rendering ---------------- */

function render(report) {
  state.report = report;
  showError(null);
  renderKpis(report);
  $("#charts").hidden = false;
  renderCharts(report);
  renderAlerts(report);

  $("#sourceInfo").textContent =
    `${report.source} · ${report.summary.flows.toLocaleString()} flows · ${report.generated_at}`;
}

/* ---------------- data loading ---------------- */

async function loadDemo() {
  if (state.live.running) stopLive();   // live and batch views take turns
  showError(null);
  busy(true, "Analysing…");
  try {
    const report = await getJSON("/api/demo?rows=800");
    render(report);
  } catch (error) {
    showError(error.message);
  } finally {
    busy(false);
  }
}

async function loadFile(file) {
  if (!file) return;
  if (state.live.running) stopLive();   // live and batch views take turns
  if (!file.name.toLowerCase().endsWith(".csv")) {
    showError("Only .csv files are supported.");
    return;
  }
  if (file.size > 64 * 1024 * 1024) {
    showError("File is larger than 64 MB.");
    return;
  }
  showError(null);
  busy(true, "Uploading…");
  const form = new FormData();
  form.append("file", file);
  try {
    const report = await getJSON("/api/analyze-csv", { method: "POST", body: form });
    render(report);
  } catch (error) {
    showError(error.message);
  } finally {
    busy(false);
    $("#fileInput").value = "";
  }
}

/* ---------------- real-time monitor ---------------- */

function fmtUptime(seconds) {
  const s = Math.floor(seconds % 60);
  const m = Math.floor(seconds / 60) % 60;
  const h = Math.floor(seconds / 3600);
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}

function updateLiveUi(status) {
  const badge = $("#liveStatus");
  if (status.last_error) {
    badge.className = "badge bad";
    badge.innerHTML = `<span class="dot"></span> ${esc(status.last_error)}`;
  } else if (status.running) {
    badge.className = "badge ok live-badge";
    badge.innerHTML = `<span class="dot"></span> live · ${esc(status.backend)} · tick #${status.ticks}`;
  } else {
    badge.className = "badge";
    badge.innerHTML = `<span class="dot"></span> idle`;
  }

  $("#liveStats").hidden = !status.running;
  $("#liveGrid").hidden = !status.running;
  $("#liveStart").hidden = !!status.running;
  $("#liveStop").hidden = !status.running;
  if (!status.running) return;

  $("#liveBackendName").textContent = status.backend;
  $("#liveBackendName").title = status.backend_note || "";
  $("#liveUptime").textContent = fmtUptime(status.uptime_s);
  $("#liveWindow").textContent = Number(status.flows_in_window || 0).toLocaleString();
  $("#liveSeen").textContent = Number(status.flows_seen || 0).toLocaleString();
  $("#liveAlertCount").textContent = Number(status.alerts_total || 0).toLocaleString();
  $("#livePriv").textContent = status.backend === "scapy" ? "packet capture" : "user-level";
  renderConns(status.conns || []);
}

function renderConns(conns) {
  const body = $("#connBody");
  if (!conns.length) {
    body.innerHTML = `<tr><td colspan="5" class="empty">No active connections visible.</td></tr>`;
    return;
  }
  body.innerHTML = conns.map((c) => `
    <tr>
      <td>${esc(c.proto)}</td>
      <td class="mono cell-dim">${esc(c.local)}</td>
      <td class="mono">${esc(c.remote)}</td>
      <td><span class="conn-state">${esc(c.state)}</span></td>
      <td class="cell-dim">${esc(c.process)}</td>
    </tr>`).join("");
}

function renderFeed(newAlerts) {
  const feed = $("#liveFeed");
  if (!newAlerts.length) return;
  if (feed.querySelector(".feed-empty")) feed.innerHTML = "";
  const items = newAlerts.slice(0, 12).map((a) => `
    <li>
      <span class="feed-level lvl-text-${esc(a.risk_level)}">${esc(a.risk_level)}</span>
      <span class="feed-ips"><span class="mono">${esc(a.src_ip)}</span>
        <span class="arrow">→</span><span class="mono">${esc(a.dst_ip)}</span></span>
      <span class="feed-cat">${esc(a.category_label)} · ${a.risk_score}/100</span>
    </li>`);
  feed.innerHTML = items.join("") + feed.innerHTML;
  while (feed.children.length > 15) feed.removeChild(feed.lastChild);
}

function openLiveStream(status) {
  state.live.running = true;
  updateLiveUi(status);
  Chart.defaults.animation.duration = 350;   // snappier redraws while live

  const es = new EventSource("/api/live/stream");
  state.live.es = es;

  es.addEventListener("tick", (event) => {
    // a tick already queued when the user pressed Stop must not
    // resurrect the live panel after closeLiveStream() ran
    if (!state.live.running) return;
    let data;
    try { data = JSON.parse(event.data); } catch (_) { return; }
    if (data.report) {
      state.flashKeys = new Set((data.new_alerts || []).map(alertKey));
      render(data.report);
      renderFeed(data.new_alerts || []);
    }
    updateLiveUi(data.status || {});
  });
  es.addEventListener("stopped", () => closeLiveStream());
  es.onerror = () => {
    if (!state.live.running) es.close();
  };
}

function closeLiveStream() {
  if (state.live.es) { state.live.es.close(); state.live.es = null; }
  state.live.running = false;
  Chart.defaults.animation.duration = 600;
  $("#liveStart").hidden = false;
  $("#liveStop").hidden = true;
  $("#liveStats").hidden = true;   // stop must fully reset the panel,
  $("#liveGrid").hidden = true;    // not just badge + buttons
  const badge = $("#liveStatus");
  badge.className = "badge";
  badge.innerHTML = `<span class="dot"></span> idle`;
}

async function startLive() {
  showError(null);
  const backend = $("#liveBackend").value;
  const interval = Math.min(30, Math.max(1, Number($("#liveInterval").value) || 3));
  try {
    const status = await getJSON("/api/live/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ backend, interval }),
    });
    openLiveStream(status);
  } catch (error) {
    showError(error.message);
  }
}

async function stopLive() {
  try { await getJSON("/api/live/stop", { method: "POST" }); } catch (_) { /* already stopped */ }
  closeLiveStream();
}

/* ---------------- events ---------------- */

function bindEvents() {
  $("#btnDemo").addEventListener("click", loadDemo);
  $("#fileInput").addEventListener("change", (event) => loadFile(event.target.files[0]));
  $("#liveStart").addEventListener("click", startLive);
  $("#liveStop").addEventListener("click", stopLive);

  // 3D ⇄ 2D view toggle (CSS perspective + chart extrusion plugins)
  const btn3d = $("#btn3d");
  btn3d.addEventListener("click", () => {
    const flat = document.body.classList.toggle("flat");
    btn3d.classList.toggle("active", !flat);
    btn3d.setAttribute("aria-pressed", String(!flat));
    if (state.report) renderCharts(state.report);
  });

  const dropzone = $("#dropzone");
  ["dragenter", "dragover"].forEach((type) =>
    dropzone.addEventListener(type, (event) => {
      event.preventDefault();
      dropzone.classList.add("over");
    }));
  ["dragleave", "drop"].forEach((type) =>
    dropzone.addEventListener(type, (event) => {
      event.preventDefault();
      dropzone.classList.remove("over");
    }));
  dropzone.addEventListener("drop", (event) => loadFile(event.dataTransfer.files[0]));

  document.querySelectorAll(".chip-btn").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".chip-btn").forEach((b) => b.classList.remove("active"));
      button.classList.add("active");
      state.level = button.dataset.level;
      if (state.report) renderAlerts(state.report);
    });
  });

  $("#alertSearch").addEventListener("input", (event) => {
    state.query = event.target.value.trim().toLowerCase();
    if (state.report) renderAlerts(state.report);
  });

  // Row expansion (delegated — rows are re-rendered on every filter change)
  $("#alertsBody").addEventListener("click", (event) => {
    const row = event.target.closest("tr.alert-row");
    if (row) toggleDetail(row);
  });
  $("#alertsBody").addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    const row = event.target.closest("tr.alert-row");
    if (!row) return;
    event.preventDefault();
    row.click();
  });
}

/* ---------------- boot ---------------- */

document.addEventListener("DOMContentLoaded", () => {
  if (window.Chart) chartDefaults();
  $("#year").textContent = String(new Date().getFullYear());
  bindEvents();
  loadHealth();
  loadDemo();
});
