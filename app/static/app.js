/* NovaMind Support Desk UI — vanilla JS. Same file serves the honeypot, so the two are identical. */
"use strict";
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

/* ---- customer lookup ---- */
$("#search-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const term = $("#search").value.trim();
  const meta = $("#search-meta");
  const tbody = $("#results");
  meta.textContent = "Searching…";
  try {
    const r = await fetch(`/api/customers?search=${encodeURIComponent(term)}`);
    const data = await r.json();
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
    const r = await fetch("/api/chat", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ message }),
    });
    const data = await r.json();
    typing.remove();
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
