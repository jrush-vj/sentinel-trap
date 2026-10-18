/* SENTINEL-TRAP dashboard — vanilla JS, no build step, no CDN. */
"use strict";
const $ = (id) => document.getElementById(id);
const api = (p, opts) => fetch(p, opts).then((r) => (r.ok ? r.json() : Promise.reject(r)));
const adminToken = () => localStorage.getItem("st_admin_token") || "dev-admin-token";
const adminHeaders = () => ({ "Content-Type": "application/json", "X-Admin-Token": adminToken() });
const SEV = { clean: "clean", suspicious: "suspicious", malicious: "malicious" };
const ICON = { web: "🌐", prompt: "💬", shell: "🖥️", system: "⚙️" };

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.add("hidden"), 2600);
}

/* ---------- classification for colour ---------- */
function evClass(ev) {
  if (ev.action === "rule_learned" || ev.action === "learned_rule_caught") return "learned";
  if (ev.action === "blocked") return "blocked";
  if (ev.action === "canary_hit") return "malicious";
  return SEV[ev.verdict] || "clean";
}

/* ---------- live feed ---------- */
const feed = $("feed");
function addFeed(ev) {
  const li = document.createElement("li");
  li.className = "ev " + evClass(ev);
  const t = new Date(ev.ts).toLocaleTimeString();
  li.innerHTML = `<div class="ev-top"><span class="act">${ev.action.replace(/_/g, " ")}</span>
    <span class="ts">${t}</span></div>
    ${ev.payload ? `<div class="pl">${esc(ev.payload)}</div>` : ""}
    <div class="meta">${ICON[ev.channel] || ""} ${ev.channel} · risk ${ev.risk}${ev.rule_id ? " · " + esc(ev.rule_id) : ""}${ev.detail ? " · " + esc(ev.detail) : ""}</div>`;
  feed.prepend(li);
  while (feed.children.length > 120) feed.lastChild.remove();
  flashFlow(ev);
  updateSplit(ev);
}
function esc(s) { return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

/* ---------- counters ---------- */
async function refreshStats() {
  try {
    const s = await api("/api/stats");
    $("c-requests").textContent = s.requests;
    $("c-attacks").textContent = s.attacks_detected;
    $("c-trapped").textContent = s.attackers_trapped;
    $("c-banned").textContent = s.attackers_banned;
    $("c-rules").textContent = s.rules_learned;
    $("c-fixed").textContent = s.false_positives_fixed;
    if (s.learned_catches > 0) $("beforeafter").classList.remove("hidden");
  } catch (e) { /* ignore */ }
}

/* ---------- legit vs attacker split ---------- */
function updateSplit(ev) {
  if (ev.action === "request") $("split-legit").textContent = ev.payload || "—";
  else if (["routed_to_honeypot", "honeypot_interaction", "canary_hit", "blocked"].includes(ev.action))
    $("split-attacker").textContent = ev.payload || ev.action;
}

/* ---------- honeypot session cards ---------- */
async function refreshSessions() {
  try {
    const sessions = await api("/api/sessions");
    const box = $("sessions");
    $("sessions-empty").classList.toggle("hidden", sessions.length > 0);
    box.innerHTML = sessions.map(sessionCard).join("");
  } catch (e) { /* ignore */ }
}
function sessionCard(s) {
  const badge = s.status === "trapped" ? '<span class="badge trapped">● TRAPPED</span>'
    : s.status === "banned" ? '<span class="badge banned">⛔ BANNED</span>'
    : '<span class="badge ended">ENDED</span>';
  const tl = s.timeline.map((t) => `<li class="${t.action}"><span class="ic">${ICON[t.channel] || ""}</span>
      <span class="tpl">${esc(t.payload || t.action)}</span></li>`).join("");
  return `<div class="scard ${s.canary ? "canary" : ""}">
    <div class="scard-head"><span class="scard-id">${esc(s.fingerprint)} · ${esc(s.attacker_ip)}</span>${badge}</div>
    <div class="counter-pill">${s.actions}/${s.max_actions} before ejection · risk ${s.risk}</div>
    <ul class="timeline">${tl}</ul></div>`;
}

/* ---------- analyst stream (typewriter) ---------- */
const stream = $("analyst-stream");
function typeLine(el, text, done) {
  let i = 0;
  el.classList.add("cursor");
  (function tick() {
    el.textContent = text.slice(0, i++);
    if (i <= text.length) setTimeout(tick, 12);
    else { el.classList.remove("cursor"); if (done) done(); }
  })();
}
function addCommentary(a, instant) {
  setAnalystSource(a.source);
  const div = document.createElement("div");
  div.className = "cmt";
  const line = document.createElement("div");
  line.className = "line";
  div.appendChild(line);
  const tags = document.createElement("div");
  tags.className = "tags" + (instant ? "" : " hidden");
  tags.innerHTML = `${a.intent ? `<span class="pill2 intent">${esc(a.intent)}</span>` : ""}
    ${a.technique ? `<span class="pill2">${esc(a.technique)}</span>` : ""}
    ${a.mitre ? `<span class="pill2 mitre">${esc(a.mitre)}</span>` : ""}
    <span class="rmeter"><i style="width:${(a.risk || 0) * 10}%"></i></span>`;
  div.appendChild(tags);
  stream.prepend(div);
  if (instant) line.textContent = a.commentary || "(no commentary)";
  else typeLine(line, a.commentary || "(no commentary)", () => tags.classList.remove("hidden"));
  while (stream.children.length > 30) stream.lastChild.remove();
}
function setAnalystSource(src) {
  const el = $("analyst-src");
  if (src === "llm") { el.textContent = (window.__llmLabel || "LLM") + " live"; el.className = "src-tag live"; }
  else { el.textContent = "offline analyst"; el.className = "src-tag offline"; }
}
function showReport(r) {
  const card = $("report-card");
  card.classList.remove("hidden");
  card.innerHTML = `<h4>SESSION REPORT — ${esc(r.attacker_goal || "attack")}</h4>
    <div>${esc(r.summary || "")}</div>
    ${list("Techniques", r.techniques)}${list("IOCs", r.iocs)}${list("Recommended", r.recommended_actions)}
    <div class="muted">risk ${r.risk ?? "?"} · ${r.source === "llm" ? "LLM" : "offline analyst"}</div>`;
}
function list(label, arr) {
  if (!arr || !arr.length) return "";
  return `<div><b>${label}:</b><ul>${arr.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>`;
}

/* ---------- memory & learning ---------- */
async function refreshMemory() {
  try {
    const [bans, rules] = await Promise.all([api("/api/bans"), api("/api/rules")]);
    $("bans-body").innerHTML = bans.map((b) => `<tr>
      <td>${esc(b.fingerprint || "")}</td><td>${esc(b.ip || "")}</td><td>${esc(b.reason || "")}</td>
      <td><button class="mark-safe" data-fp="${esc(b.fingerprint || "")}">MARK SAFE</button></td></tr>`).join("")
      || `<tr><td colspan="4" class="muted">No bans yet.</td></tr>`;
    $("rules-body").innerHTML = rules.map((r) => `<tr>
      <td class="src-${r.source === "learned" ? "l" : "b"}">${esc(r.id)}</td><td>${esc(r.category)}</td>
      <td class="pat">${esc(r.regex)}</td><td>${r.hits || 0}</td>
      <td><span class="toggle ${r.enabled ? "on" : "off"}" data-rule="${esc(r.id)}">${r.enabled ? "◉" : "○"}</span></td></tr>`).join("");
  } catch (e) { /* ignore */ }
}
document.addEventListener("click", async (e) => {
  const ms = e.target.closest(".mark-safe");
  if (ms) {
    await api("/api/mark-safe", { method: "POST", headers: adminHeaders(), body: JSON.stringify({ fingerprint: ms.dataset.fp }) })
      .then(() => { toast("Marked safe — attacker unbanned"); refreshMemory(); refreshStats(); })
      .catch(() => toast("Mark-safe failed (check admin token)"));
  }
  const tg = e.target.closest(".toggle");
  if (tg) {
    await api(`/api/rules/${tg.dataset.rule}/toggle`, { method: "POST", headers: adminHeaders() })
      .then(() => { refreshMemory(); }).catch(() => toast("Toggle failed (admin token)"));
  }
});

/* ---------- attack-flow SVG ---------- */
const FLOW = `<svg viewBox="0 0 560 220" preserveAspectRatio="xMidYMid meet">
  <defs></defs>
  <path id="e-ag" class="edge" d="M90,110 H200"/>
  <path id="e-app" class="edge" d="M300,80 H420"/>
  <path id="e-hp" class="edge" d="M300,150 H420"/>
  <path id="e-mon" class="edge" d="M255,135 C255,200 480,205 490,175"/>
  <g id="n-att"><rect class="node-box" x="10" y="85" width="80" height="50" rx="10"/><text class="node-label" x="50" y="114" text-anchor="middle">Attacker</text></g>
  <g id="n-gw"><rect class="node-box" x="200" y="82" width="100" height="56" rx="10"/><text class="node-label" x="250" y="107" text-anchor="middle">Gateway</text><text class="node-label" x="250" y="124" text-anchor="middle" font-size="9" fill="#8aa0bd">rules+bans</text></g>
  <g id="n-app"><rect class="node-box" x="420" y="55" width="100" height="48" rx="10"/><text class="node-label" x="470" y="84" text-anchor="middle">Real App</text></g>
  <g id="n-hp"><rect class="node-box" x="420" y="125" width="100" height="48" rx="10"/><text class="node-label" x="470" y="154" text-anchor="middle">Honeypot</text></g>
  <g id="n-mon"><rect class="node-box" x="430" y="178" width="110" height="34" rx="8"/><text class="node-label" x="485" y="200" text-anchor="middle" font-size="10">Monitor / AI</text></g>
</svg>`;
function flashFlow(ev) {
  $("flow-svg").querySelectorAll(".edge").forEach((e) => (e.className.baseVal = "edge"));
  const hot = ["routed_to_honeypot", "honeypot_interaction", "canary_hit", "blocked"].includes(ev.action);
  const cls = hot ? "edge hot" : "edge active";
  setEdge("e-ag", cls);
  if (ev.action === "request") setEdge("e-app", "edge active");
  else if (hot) setEdge("e-hp", "edge hot");
  setEdge("e-mon", "edge active");
  const n = $("n-hp").querySelector("rect");
  if (ev.action === "canary_hit") { n.classList.add("hot"); setTimeout(() => n.classList.remove("hot"), 1500); }
  clearTimeout(flashFlow._t);
  flashFlow._t = setTimeout(() => $("flow-svg").querySelectorAll(".edge").forEach((e) => (e.className.baseVal = "edge")), 1400);
}
function setEdge(id, cls) { const el = $(id); if (el) el.className.baseVal = cls; }

/* ---------- LLM status chip + settings ---------- */
async function refreshLLM() {
  try {
    const s = await api("/api/llm/status");
    window.__llmLabel = s.label;
    const chip = $("llm-chip");
    const txt = $("llm-chip-text");
    chip.className = "chip " + (s.state === "online" ? "online" : (s.state === "unreachable" || s.state === "circuit_open") ? "error" : s.state === "unconfigured" ? "warn" : "offline");
    if (s.state === "online") txt.textContent = `${s.label} live · ${s.last_latency_ms ?? "?"}ms`;
    else if (s.state === "disabled") txt.textContent = "offline analyst";
    else if (s.state === "unconfigured") txt.textContent = "LLM not configured";
    else if (s.state === "circuit_open") txt.textContent = `LLM paused ${s.circuit_open_for_s}s`;
    else if (s.state === "unreachable") txt.textContent = "LLM unreachable";
    else txt.textContent = `${s.label} (idle)`;
  } catch (e) { /* ignore */ }
}
function openGear() {
  $("f-token").value = localStorage.getItem("st_admin_token") || "";
  api("/api/llm/config").then((c) => {
    $("f-url").value = c.base_url || "";
    $("f-key").value = "";
    $("f-key").placeholder = c.api_key ? "keep current (" + c.api_key + ")" : "api key";
    $("f-model").value = c.model || "";
    $("f-enabled").checked = !!c.enabled;
  });
  $("f-result").textContent = "";
  $("gear-modal").classList.remove("hidden");
}
function closeGear() { $("gear-modal").classList.add("hidden"); }
function collectCfg() {
  localStorage.setItem("st_admin_token", $("f-token").value || "dev-admin-token");
  return { base_url: $("f-url").value, api_key: $("f-key").value, model: $("f-model").value, enabled: $("f-enabled").checked };
}
$("gear-btn").onclick = openGear;
$("f-cancel").onclick = closeGear;
$("f-save").onclick = async () => {
  try {
    await api("/api/llm/config", { method: "POST", headers: adminHeaders(), body: JSON.stringify(collectCfg()) });
    toast("LLM settings saved"); refreshLLM(); closeGear();
  } catch (e) { $("f-result").textContent = "Save failed — check admin token."; }
};
$("f-test").onclick = async () => {
  $("f-result").textContent = "Testing… (saving first)";
  try {
    await api("/api/llm/config", { method: "POST", headers: adminHeaders(), body: JSON.stringify(collectCfg()) });
    const r = await api("/api/llm/test", { method: "POST", headers: adminHeaders() });
    $("f-result").textContent = JSON.stringify(r, null, 2);
    refreshLLM();
  } catch (e) { $("f-result").textContent = "Test failed — check admin token / URL."; }
};
$("llm-chip").onclick = openGear;
$("reset-btn").onclick = async () => {
  if (!confirm("Clear all bans, events, learned rules and attackers?")) return;
  try {
    await api("/api/reset", { method: "POST", headers: adminHeaders() });
    feed.innerHTML = ""; stream.innerHTML = ""; $("report-card").classList.add("hidden");
    $("beforeafter").classList.add("hidden");
    toast("Demo reset"); refreshAll();
  } catch (e) { toast("Reset failed — check admin token"); }
};

/* presentation mode */
document.addEventListener("keydown", (e) => {
  if (e.key === "p" || e.key === "P") {
    if (document.activeElement && /input|textarea/i.test(document.activeElement.tagName)) return;
    document.body.classList.toggle("present");
  }
});

/* ---------- WebSocket ---------- */
function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen = () => ($("ws-state").textContent = "● live");
  ws.onclose = () => { $("ws-state").textContent = "reconnecting…"; setTimeout(connectWS, 1500); };
  ws.onmessage = (msg) => {
    const m = JSON.parse(msg.data);
    if (m.type === "event") { addFeed(m.event); scheduleRefresh(); }
    else if (m.type === "analysis") addCommentary(m);
    else if (m.type === "report") showReport(m);
    else if (m.type === "llm") refreshLLM();
    else if (m.type === "reset") { feed.innerHTML = ""; stream.innerHTML = ""; refreshAll(); }
  };
}
let _refreshTimer = null;
function scheduleRefresh() {
  clearTimeout(_refreshTimer);
  _refreshTimer = setTimeout(() => { refreshStats(); refreshSessions(); refreshMemory(); }, 350);
}
function refreshAll() { refreshStats(); refreshSessions(); refreshMemory(); refreshLLM(); }

/* ---------- boot ---------- */
$("flow-svg").innerHTML = FLOW;
async function loadAnalyses() {
  const items = await api("/api/analyses?limit=40").catch(() => []);
  // oldest first so prepend() leaves newest on top, matching live order; instant (no typewriter)
  items.reverse().forEach((a) => {
    if (a.kind === "commentary") addCommentary(a, true);
    else if (a.kind === "report") showReport(a);
  });
}
(async function boot() {
  const evs = await api("/api/events?limit=80").catch(() => []);
  evs.reverse().forEach(addFeed);
  await loadAnalyses();
  refreshAll();
  connectWS();
  setInterval(refreshLLM, 5000);
})();
