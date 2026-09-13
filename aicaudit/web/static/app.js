/* AICAudit web UI — vanilla JS, zero dependencies, offline-first. */
"use strict";

/* ─── helpers ─────────────────────────────────────────── */

const $ = (sel, el) => (el || document).querySelector(sel);
const $$ = (sel, el) => Array.from((el || document).querySelectorAll(sel));

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

async function api(url, opts) {
  const resp = await fetch(url, opts);
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.detail || resp.statusText);
  return data;
}

function toast(msg, kind) {
  let el = $("#toast");
  if (!el) {
    el = document.createElement("div");
    el.id = "toast";
    el.className = "toast";
    document.body.appendChild(el);
  }
  el.className = "toast show " + (kind || "");
  el.textContent = msg;
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.className = "toast " + (kind || ""); }, 3200);
}

function basename(p) { return String(p).replace(/\\/g, "/").split("/").pop(); }

const SEV_ORDER = { critical: 0, error: 1, warning: 2, info: 3 };

/* ─── dashboard ───────────────────────────────────────── */

async function initDashboard() {
  const wrap = $("#sessions");
  if (!wrap) return;
  try {
    const data = await api("/api/sessions");
    const items = data.sessions || [];
    const tot = { critical: 0, error: 0, warning: 0, info: 0 };
    let scans = 0;
    items.forEach(s => {
      Object.keys(tot).forEach(k => { tot[k] += (s.counts[k] || 0); });
      scans += 1;
    });
    $("#stat-scans").textContent = scans;
    $("#stat-critical").textContent = tot.critical;
    $("#stat-error").textContent = tot.error;
    $("#stat-warning").textContent = tot.warning;
    if (!items.length) {
      wrap.innerHTML = '<div class="empty"><div class="icon"> Shields Up </div>No scans yet — run your first scan.</div>';
      return;
    }
    wrap.innerHTML = items.map(s => `
      <a class="session-item" href="/results/${esc(s.session_id)}" style="text-decoration:none">
        <span class="ts">${esc(s.timestamp || "")}</span>
        <span class="path" title="${esc((s.paths || []).join(" "))}">${esc((s.paths || []).join(" ") || "—")}</span>
        <span style="margin-left:auto;display:flex;gap:6px">
          ${s.counts.critical ? `<span class="badge critical">${s.counts.critical} crit</span>` : ""}
          ${s.counts.error ? `<span class="badge error">${s.counts.error} err</span>` : ""}
          ${s.counts.warning ? `<span class="badge warning">${s.counts.warning} warn</span>` : ""}
          ${!s.total ? '<span class="badge ok">clean</span>' : ""}
        </span>
      </a>`).join("");
  } catch (e) {
    wrap.innerHTML = `<div class="empty">Failed to load history: ${esc(e.message)}</div>`;
  }
}

/* ─── scan page (SSE progress) ────────────────────────── */

function initScan() {
  const form = $("#scan-form");
  if (!form) return;
  const chips = $$(".chip[data-rule]");
  chips.forEach(c => c.addEventListener("click", () => c.classList.toggle("on")));

  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const paths = $("#paths").value.trim();
    if (!paths) { toast("Enter a path to scan", "err"); return; }
    const rules = chips.filter(c => c.classList.contains("on")).map(c => c.dataset.rule).join(",");
    const lang = $("#lang").value;
    const sev = $("#min-severity").value;
    const q = new URLSearchParams({ paths, lang });
    if (rules) q.set("rules", rules);
    if (sev) q.set("min_severity", sev);

    const btn = $("#scan-btn");
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Scanning…';
    $("#progress-card").classList.remove("hidden");
    $("#progress-fill").style.width = "0%";
    const log = $("#progress-log");
    log.textContent = "";

    const es = new EventSource(`/api/scan/stream?${q.toString()}`);
    const push = (line) => { log.textContent += line + "\n"; log.scrollTop = log.scrollHeight; };

    es.onmessage = (ev) => {
      const m = JSON.parse(ev.data);
      if (m.type === "progress") {
        const pct = m.total ? Math.round((m.current / m.total) * 100) : 0;
        $("#progress-fill").style.width = pct + "%";
        if (m.phase === "taint") push(`[taint] ${m.detail}`);
        else push(`[${m.current + 1}/${m.total}] ${basename(m.detail)}`);
      } else if (m.type === "done") {
        es.close();
        push(`done — ${m.total} finding(s)`);
        setTimeout(() => { window.location.href = "/results/" + m.session_id; }, 400);
      } else if (m.type === "error") {
        es.close();
        btn.disabled = false; btn.textContent = "Scan";
        toast("Scan failed: " + m.message, "err");
        push("ERROR: " + m.message);
      }
    };
    es.onerror = () => { es.close(); };
  });
}

/* ─── results page ────────────────────────────────────── */

let RESULTS = null;
let SELECTED = -1;

async function initResults() {
  const root = $("#results-root");
  if (!root) return;
  const sid = root.dataset.session;
  try {
    RESULTS = await api(`/api/results/${sid}`);
  } catch (e) {
    root.innerHTML = `<div class="empty">Session not found. <a href="/scan">Run a scan</a>.</div>`;
    return;
  }
  renderSummary();
  renderFilters();
  renderList();
  initExport();
  initVerify();
}

function renderSummary() {
  const c = { critical: 0, error: 0, warning: 0, info: 0 };
  RESULTS.findings.forEach(f => { c[f.severity] = (c[f.severity] || 0) + 1; });
  $("#sum").innerHTML = `
    <div class="stat ok"><span class="num">${RESULTS.total}</span><span class="label">total findings</span></div>
    <div class="stat critical"><span class="num">${c.critical}</span><span class="label">critical</span></div>
    <div class="stat error"><span class="num">${c.error}</span><span class="label">error</span></div>
    <div class="stat warning"><span class="num">${c.warning}</span><span class="label">warning</span></div>
    <div class="stat info"><span class="num">${c.info}</span><span class="label">info</span></div>
    <div class="card" style="display:flex;flex-direction:column;justify-content:center">
      <div class="small muted">scanned in <b class="mono">${esc(RESULTS.duration)}s</b></div>
      <div class="small muted">${esc(RESULTS.timestamp || "")}</div>
    </div>`;
}

function renderFilters() {
  const rules = [...new Set(RESULTS.findings.map(f => f.rule_id))].sort();
  $("#f-rule").innerHTML = '<option value="">all rules</option>' +
    rules.map(r => `<option>${esc(r)}</option>`).join("");
  ["#f-sev", "#f-rule", "#f-search"].forEach(sel =>
    $(sel).addEventListener("input", renderList));
}

function visibleFindings() {
  const sev = $("#f-sev").value;
  const rule = $("#f-rule").value;
  const q = $("#f-search").value.toLowerCase();
  return RESULTS.findings
    .filter(f => (!sev || f.severity === sev) && (!rule || f.rule_id === rule))
    .filter(f => !q || (f.message + " " + f.file + " " + f.rule_id).toLowerCase().includes(q))
    .sort((a, b) => (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]) || a.rule_id.localeCompare(b.rule_id));
}

function renderList() {
  const items = visibleFindings();
  const wrap = $("#findings");
  $("#count").textContent = items.length + " shown";
  if (!items.length) {
    wrap.innerHTML = '<div class="empty"><div class="icon">✓</div>No findings match the filter.</div>';
    return;
  }
  wrap.innerHTML = items.map((f, i) => `
    <div class="finding-item ${f.severity} ${i === SELECTED ? "selected" : ""}" data-i="${i}">
      <div class="row1">
        <span class="badge ${f.severity}">${esc(f.severity)}</span>
        <span class="badge brand">${esc(f.rule_id)}</span>
        ${f.cwe ? `<span class="badge dim">${esc(f.cwe)}</span>` : ""}
        ${f.taint_path ? '<span class="badge dim" title="taint path traced">⛓ path</span>' : ""}
        ${f.ai ? `<span class="badge ${f.ai.status === "confirmed" ? "ok" : f.ai.status === "false_positive" ? "" : "info"}">AI:${esc(f.ai.status)}</span>` : ""}
        <span class="loc">${esc(basename(f.file))}:${f.line}</span>
      </div>
      <div class="msg">${esc(f.message)}</div>
    </div>`).join("");
  $$(".finding-item", wrap).forEach(el =>
    el.addEventListener("click", () => { SELECTED = +el.dataset.i; renderList(); renderDetail(visibleFindings()[SELECTED]); }));
}

async function renderDetail(f) {
  if (!f) { $("#detail").innerHTML = '<div class="empty">Select a finding.</div>'; return; }
  const d = $("#detail");
  d.innerHTML = `
    <div class="detail-head">
      <h3>${esc(f.rule_id)} — ${esc(f.message)}</h3>
      <span class="badge ${f.severity}">${esc(f.severity)}</span>
      ${f.cwe ? `<span class="badge dim">${esc(f.cwe)}</span>` : ""}
    </div>
    <div class="detail-loc">${esc(f.file)} : line ${f.line}</div>
    <div id="detail-body"><div class="empty"><span class="spinner"></span> loading code…</div></div>`;

  const body = $("#detail-body");
  const [code, aiHtml, taintHtml] = await Promise.all([
    api(`/api/file-content?path=${encodeURIComponent(f.file)}&line=${f.line}`).catch(() => null),
    Promise.resolve(renderAiCard(f)),
    Promise.resolve(renderTaint(f)),
  ]);

  let html = "";
  if (code && code.html) {
    html += `<div class="card-title">Code context</div>
      <div class="code-window">${code.html}</div>`;
  } else if (f.snippet) {
    html += `<div class="snippet-inline">${esc(f.snippet)}</div>`;
  }
  html += taintHtml;
  html += aiHtml;
  if (f.fix) html += renderFixSection(f);
  body.innerHTML = html;

  if (f.fix) initFixActions(f);
}

function renderTaint(f) {
  if (!f.taint_path || !f.taint_path.length) {
    return `<div class="card-title mt">Taint path</div>
      <div class="small muted">None traced by the static engine
      (source unresolved — the finding fires on dynamic input).</div>`;
  }
  const p = f.taint_path[0];
  const steps = [];
  steps.push(stepHtml(p.source, "source", "source"));
  (p.hops || []).forEach(h => steps.push(stepHtml(h, "", "propagation")));
  if (p.sink) steps.push(stepHtml(p.sink, "sink", "sink"));
  return `<div class="card-title mt">Taint path (engine-verified)</div>
    <div class="taint-stepper">${steps.join("")}</div>`;
}

function stepHtml(node, cls, label) {
  return `<div class="taint-step ${cls}">
    <div class="rail"><div class="dot"></div><div class="line"></div></div>
    <div class="body">
      <div class="desc">${esc(node.desc)}${label !== "propagation" ? ` <span class="badge ${label === "source" ? "warning" : "critical"}">${label}</span>` : ""}</div>
      <div class="loc">${esc(basename(node.file))}:${node.line}</div>
    </div>
  </div>`;
}

function renderAiCard(f) {
  if (!f.ai) {
    return `<div class="card-title mt">AI verdict</div>
      <div class="small muted">Not verified yet.</div>
      <button class="btn sm mt" id="verify-inline">Verify with AI</button>`;
  }
  const a = f.ai;
  const pct = Math.round((a.confidence || 0) * 100);
  const cls = a.status === "confirmed" ? "ok" : a.status === "false_positive" ? "" : "info";
  return `<div class="card-title mt">AI verdict</div>
    <div class="ai-card ${a.status}">
      <div class="ai-head">
        <span class="badge ${cls}">AI: ${esc(a.status)}</span>
        ${a.cwe ? `<span class="badge dim">${esc(a.cwe)}</span>` : ""}
        <span class="confidence"><span class="bar"><i style="width:${pct}%"></i></span>
        <span class="pct">${pct}%</span></span>
      </div>
      <div class="ai-reason">${esc(a.reason || "")}</div>
      ${a.suggested_fix ? `<div class="ai-fix"><b>Suggested fix:</b> ${esc(a.suggested_fix)}</div>` : ""}
    </div>`;
}

function renderFixSection(f) {
  return `<div class="card-title mt">Auto-fix</div>
    <div class="small muted">${esc(f.fix)}</div>
    <div class="chip-row mt">
      <button class="btn sm" id="fix-preview-btn">Preview diff</button>
      <button class="btn sm primary" id="fix-apply-btn">Apply (backs up)</button>
    </div>
    <div id="fix-result" class="mt"></div>`;
}

async function initFixActions(f) {
  const pv = $("#fix-preview-btn");
  const ap = $("#fix-apply-btn");
  const out = $("#fix-result");
  if (pv) pv.addEventListener("click", async () => {
    out.innerHTML = '<span class="spinner"></span> computing diff…';
    try {
      const r = await api("/api/fix-preview", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ file: f.file, rule_id: f.rule_id, line: f.line,
                               fix: f.fix, severity: f.severity, message: f.message }),
      });
      if (!r.changed) { out.innerHTML = '<div class="small muted">No automated change for this rule.</div>'; return; }
      const lines = r.diff.split("\n").map(l =>
        l.startsWith("+") ? `<div class="dl add">${esc(l)}</div>` :
        l.startsWith("-") ? `<div class="dl del">${esc(l)}</div>` :
        l.startsWith("@") ? `<div class="dl hunk">${esc(l)}</div>` :
        `<div class="dl">${esc(l)}</div>`).join("");
      out.innerHTML = `<div class="diff">${lines}</div>`;
    } catch (e) { out.innerHTML = `<div class="small" style="color:var(--critical)">${esc(e.message)}</div>`; }
  });
  if (ap) ap.addEventListener("click", async () => {
    ap.disabled = true;
    try {
      const r = await api("/api/apply-fix", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ file: f.file, rule_id: f.rule_id, line: f.line,
                               fix: f.fix, severity: f.severity, message: f.message }),
      });
      if (r.status === "applied" && r.verified && r.backup) {
        toast("Fix applied — backup saved", "ok");
        out.innerHTML += `<div class="chip-row mt"><button class="btn sm danger" id="fix-rollback-btn">Rollback</button></div>`;
        $("#fix-rollback-btn").addEventListener("click", async () => {
          try {
            await api("/api/fix-rollback", {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ backup: r.backup }),
            });
            toast("Rolled back", "ok");
            renderDetail(f);
          } catch (e) { toast(e.message, "err"); }
        });
      } else {
        toast("Fix not applied: " + (r.message || r.status), "err");
      }
    } catch (e) { toast(e.message, "err"); }
    ap.disabled = false;
  });
}

function initExport() {
  const sid = $("#results-root").dataset.session;
  const dl = (fmt) => {
    api("/api/export", { method: "POST", headers: { "Content-Type": "application/json" },
                         body: JSON.stringify({ session_id: sid, format: fmt }) })
      .then(data => {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `aicaudit-${sid}.${fmt === "sarif" ? "sarif.json" : "json"}`;
        a.click();
        toast("Exported " + fmt.toUpperCase(), "ok");
      })
      .catch(e => toast(e.message, "err"));
  };
  $("#export-json").addEventListener("click", () => dl("json"));
  $("#export-sarif").addEventListener("click", () => dl("sarif"));
}

async function initVerify() {
  const btn = $("#verify-btn");
  if (!btn) return;
  const sid = $("#results-root").dataset.session;
  btn.addEventListener("click", async () => {
    btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Verifying…';
    try {
      const r = await api("/api/verify", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: sid }),
      });
      if (r.error) { toast(r.error, "err"); }
      else {
        toast(`AI: ${r.confirmed} confirmed / ${r.false_positive} FP / ${r.unverified} unverified`, "ok");
        RESULTS = await api(`/api/results/${sid}`);
        renderList();
      }
    } catch (e) { toast(e.message, "err"); }
    btn.disabled = false; btn.textContent = "Verify with AI";
  });
}

/* ─── rules page ──────────────────────────────────────── */

function initRules() {
  const filter = $("#rule-search");
  if (!filter) return;
  filter.addEventListener("input", () => {
    const q = filter.value.toLowerCase();
    $$("[data-rule-row]").forEach(row => {
      row.style.display = row.dataset.ruleRow.toLowerCase().includes(q) ? "" : "none";
    });
  });
}

/* ─── config page ─────────────────────────────────────── */

function initConfig() {
  const form = $("#config-form");
  if (!form) return;
  $$(".chip[data-provider]").forEach(c => c.addEventListener("click", () => {
    $$(".chip[data-provider]").forEach(x => x.classList.remove("on"));
    c.classList.add("on");
    $("#provider").value = c.dataset.provider;
  }));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const body = {
      ai_provider: $("#provider").value || "mock",
      ai_key: $("#ai_key").value.trim(),
      ai_base: $("#ai_base").value.trim(),
      ai_model: $("#ai_model").value.trim(),
    };
    try {
      await api("/api/config", { method: "POST",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const st = await api("/api/config/status");
      toast(`Saved — provider: ${st.provider}${st.model ? " (" + st.model + ")" : ""}`, "ok");
    } catch (e) { toast(e.message, "err"); }
  });
}

/* ─── boot ────────────────────────────────────────────── */

document.addEventListener("DOMContentLoaded", () => {
  const page = document.body.dataset.page;
  if (page === "dashboard") initDashboard();
  else if (page === "scan") initScan();
  else if (page === "results") initResults();
  else if (page === "rules") initRules();
  else if (page === "config") initConfig();
});
