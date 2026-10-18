/* NovaMind Support Desk UI — vanilla JS. Same file serves the honeypot, so the two are identical. */
"use strict";
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const BLOCKED = "⛔ Blocked by NovaMind's security policy.";

/* ---- views ---- */
function show(view) {
  for (const v of ["auth-view", "denied-view", "app-view"]) $("#" + v).hidden = v !== view;
}
const GREETING = $("#chat").innerHTML;
function showApp(name) {
  // a different account must not see the previous account's results or chat
  $("#chat").innerHTML = GREETING;
  $("#results").innerHTML = "";
  for (const id of ["#search-meta", "#fb-meta"]) $(id).textContent = "";
  $("#user-name").textContent = name;
  $("#hello-name").textContent = name;
  $("#avatar").textContent = name.slice(0, 2).toUpperCase();
  $("#user-box").hidden = false;
  show("app-view");
  loadLogs();
}
function showAuth(msg) {
  $("#user-box").hidden = true;
  $("#avatar").textContent = "NM";
  $("#auth-msg").textContent = msg || "";
  show("auth-view");
}
function showDenied() {
  $("#user-box").hidden = true;
  show("denied-view");
}

/* fetch wrapper: 401 -> sign in again, 403 page -> account suspended, 403 JSON -> this request blocked */
async function call(path, opts) {
  const r = await fetch(path, opts);
  if (r.status === 401) { showAuth("Please sign in."); throw new Error("signed out"); }
  if (r.status === 403) {
    const data = await r.json().catch(() => null);
    if (data && data.error === "blocked") return { blocked: true, ...data };
    showDenied();
    throw new Error("denied");
  }
  return r.json();
}
const post = (path, body) => call(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

/* ---- sign in / create account ---- */
let mode = "login";
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
  mode = t.dataset.mode;
  document.querySelectorAll(".tab").forEach((x) => { x.classList.toggle("on", x === t); x.setAttribute("aria-selected", x === t); });
  $("#auth-submit").textContent = mode === "login" ? "Sign in" : "Create account";
  $("#auth-pass").autocomplete = mode === "login" ? "current-password" : "new-password";
  $("#auth-msg").textContent = "";
}));
$("#auth-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#auth-msg").textContent = "";
  // username first: the gateway logs the first body field, never the password
  const r = await fetch(`/api/${mode}`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: $("#auth-user").value.trim().toLowerCase(), password: $("#auth-pass").value }),
  }).catch(() => null);
  if (!r) { $("#auth-msg").textContent = "Couldn't reach NovaMind."; return; }
  const data = await r.json().catch(() => ({}));
  if (r.status === 403 && data.error === "blocked") { $("#auth-msg").textContent = BLOCKED; return; }
  if (r.status === 403) { showDenied(); return; }
  if (!r.ok) { $("#auth-msg").textContent = data.detail || "Sign in failed."; return; }
  $("#auth-pass").value = "";
  showApp(data.username);
});
$("#logout").addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST" }).catch(() => {});
  showAuth();
});
$("#denied-back").addEventListener("click", () => showAuth());

/* ---- customer lookup ---- */
$("#search-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const term = $("#search").value.trim();
  const meta = $("#search-meta");
  const tbody = $("#results");
  meta.textContent = "Searching…";
  try {
    const data = await call(`/api/customers?search=${encodeURIComponent(term)}`);
    if (data.blocked) { meta.textContent = BLOCKED; tbody.innerHTML = ""; return; }
    const rows = data.results || [];
    meta.textContent = `${data.count ?? rows.length} result(s)` + (data.error ? ` · ${data.error}` : "");
    tbody.innerHTML = rows.length
      ? rows.map((c) => `<tr><td>${esc(c.id)}</td><td>${esc(c.name)}</td><td class="mono">${esc(c.email)}</td>
          <td>${esc(c.plan)}</td><td>${esc(c.country)}</td></tr>`).join("")
      : `<tr><td colspan="5" class="muted">No customers found.</td></tr>`;
  } catch (err) {
    meta.textContent = "Lookup failed.";
  }
});

/* ---- AI assistant ---- */
const chat = $("#chat");
function bubble(text, cls) {
  const d = document.createElement("div");
  d.className = "msg " + cls;
  d.textContent = text;
  chat.appendChild(d);
  chat.scrollTop = chat.scrollHeight;
  return d;
}
async function send(message) {
  if (!message) return;
  bubble(message, "me");
  const typing = bubble("NovaMind is typing…", "bot typing");
  try {
    const data = await post("/api/chat", { message });
    typing.remove();
    if (data.blocked) { bubble(BLOCKED, "bot blocked"); return; }
    bubble(data.reply || "(no reply)", "bot");
    $("#chat-src").textContent = data.source === "llm" ? `${data.model}` : "offline";
  } catch (err) {
    typing.remove();
    bubble("Sorry, I couldn't reach support right now.", "bot");
  }
}
$("#chat-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const msg = $("#chat-input").value.trim();
  $("#chat-input").value = "";
  send(msg);
});
document.querySelectorAll(".chip-s").forEach((b) =>
  b.addEventListener("click", () => { $("#chat-input").value = b.textContent; send(b.textContent); }));

/* ---- report an issue -> team activity log ---- */
async function loadLogs() {
  try {
    const data = await call("/api/logs");
    if (data.blocked) return;
    $("#log-lines").innerHTML = (data.lines || []).map((l) => `<li>${esc(l)}</li>`).join("") || '<li class="muted">No activity yet.</li>';
  } catch (err) { /* view already switched */ }
}
$("#fb-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const message = $("#fb-input").value;
  if (!message.trim()) return;
  $("#fb-meta").textContent = "Sending…";
  try {
    const data = await post("/api/feedback", { message });
    if (data.blocked) { $("#fb-meta").textContent = BLOCKED; return; }
    $("#fb-input").value = "";
    $("#fb-meta").textContent = "Thanks! Your report was added to the team log.";
    loadLogs();
  } catch (err) {
    $("#fb-meta").textContent = "Couldn't send the report.";
  }
});

/* ---- boot ---- */
(async function boot() {
  const r = await fetch("/api/me").catch(() => null);
  if (r && r.status === 403) return showDenied();
  const data = r && r.ok ? await r.json().catch(() => null) : null;
  if (data && data.username) showApp(data.username);
  else showAuth();
})();
