/* Sentinel-Trap console. Vanilla JS, no build step, no CDN. */
"use strict";

/* ================================================================ helpers */
const $ = (id) => document.getElementById(id);
const api = (p, opts) => fetch(p, opts).then((r) => (r.ok ? r.json() : Promise.reject(r)));
const adminToken = () => localStorage.getItem("st_admin_token") || "dev-admin-token";
const adminHeaders = () => ({ "Content-Type": "application/json", "X-Admin-Token": adminToken() });
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const time = (ts) => (ts ? new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "");
const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)");

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.add("hidden"), 3000);
}

const LABEL = {
  request: "Allowed to app", blocked: "Blocked · 403", routed_to_honeypot: "Sent to honeypot",
  honeypot_interaction: "Honeypot action", canary_hit: "Canary key reused", banned: "Banned",
  session_ended: "Session ended", rule_learned: "Rule learned", rule_rejected: "Rule rejected",
  marked_safe: "Marked safe", learned_rule_caught: "Learned rule caught it",
};
const CHANNEL = { web: "web", prompt: "chat", shell: "shell", system: "system" };
function evClass(ev) {
  switch (ev.action) {
    case "request": case "marked_safe": return "ok";
    case "routed_to_honeypot": case "honeypot_interaction": return "trap";
    case "canary_hit": case "banned": case "blocked": return "bad";
    case "rule_learned": case "learned_rule_caught": return "learn";
    default: return "sys";
  }
}

/* ================================================================ request flow canvas */
const Flow = (() => {
  const stage = $("flow-stage");
  const cv = $("flow-canvas");
  const ctx = cv.getContext("2d");
  const css = getComputedStyle(document.documentElement);
  const C = {};
  for (const k of ["ok", "trap", "bad", "learn", "ink", "ink-2", "ink-3", "line", "line-2", "surface", "sunk"]) C[k] = css.getPropertyValue("--" + k).trim();
  const SANS = '"IBM Plex Sans", system-ui, sans-serif';
  const MONO = '"IBM Plex Mono", ui-monospace, monospace';

  // positions follow the hand-drawn reference (fractions of the stage)
  const N = {
    user: { fx: 0.09, fy: 0.40, shape: "circle", label: "User" },
    gw: { fx: 0.38, fy: 0.40, shape: "diamond", label: "Gateway", sub: "rules + ban list" },
    app: { fx: 0.83, fy: 0.15, shape: "rect", label: "Service database", sub: "real app" },
    hp: { fx: 0.83, fy: 0.60, shape: "rect", label: "Honeypot database", sub: "fake data + canaries" },
    llm: { fx: 0.53, fy: 0.88, shape: "rect", label: "Honeypot LLM sandbox", sub: "fake replies" },
    dec: { fx: 0.11, fy: 0.80, shape: "diamond", label: "Decision", sub: "trap or ban" },
  };
  // edges: from, to, label, dashed, and optional control points (functions of node centres)
  const E = {
    ug: { a: "user", b: "gw", label: "request" },
    ga: { a: "gw", b: "app", label: "valid user" },
    au: { a: "app", b: "user", label: "response", c: (n) => [{ x: n.app.x - n.app.w * 0.9, y: n.app.y - 4 }, { x: n.user.x + 4, y: n.app.y - 4 }] },
    gh: { a: "gw", b: "hp", label: "hacker" },
    hl: { a: "hp", b: "llm", c: (n) => [{ x: n.hp.x, y: n.llm.y }, { x: n.hp.x - 10, y: n.llm.y }] },
    ld: { a: "llm", b: "dec", c: (n) => [{ x: n.dec.x + 40, y: n.llm.y + 2 }, { x: n.dec.x, y: n.llm.y + 2 }] },
    dh: { a: "dec", b: "hp", label: "keep trapping", dashed: true },
    du: { a: "dec", b: "user", label: "ban", dashed: true },
  };

  let W = 0, H = 0, S = 1, dpr = 1;
  const fsLabel = () => Math.round(13 * S);
  const fsSmall = () => Math.round(10.5 * S);
  const packets = [];
  const pulses = [];
  const tags = [];
  const stamps = [];
  const heat = {};
  const counts = { app: "", hp: "", dec: "" };
  let nextStart = 0;

  function layout() {
    const r = stage.getBoundingClientRect();
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = Math.max(280, r.width); H = Math.max(220, r.height);
    cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr);
    S = Math.max(0.85, Math.min(1.15, Math.min(W / 860, H / 400)));
    const pad = 16;
    const fs = fsLabel(), fsSub = fsSmall();
    for (const n of Object.values(N)) {
      ctx.font = `600 ${fs}px ${SANS}`;
      const lw = ctx.measureText(n.label).width;
      ctx.font = `400 ${fsSub}px ${MONO}`;
      const sw = n.sub ? ctx.measureText(n.sub).width : 0;
      if (n.shape === "circle") { n.w = n.h = Math.max(lw + 26, 48); }
      else if (n.shape === "diamond") { n.w = lw * 1.9 + 34; n.h = fs * 3.6; } // caption sits under the diamond
      else { n.w = Math.max(lw, sw) + 30; n.h = fs + fsSub + 22; }
      n.x = Math.min(W - n.w / 2 - pad, Math.max(n.w / 2 + pad, n.fx * W));
      const under = n.shape === "diamond" ? 34 : 18; // room for the caption and counter below
      n.y = Math.min(H - n.h / 2 - pad - under, Math.max(n.h / 2 + pad + 6, n.fy * H));
    }
    for (const e of Object.values(E)) buildEdge(e);
  }

  // where a ray from the node centre towards (tx,ty) leaves the node outline
  function anchor(n, tx, ty) {
    const dx = tx - n.x, dy = ty - n.y;
    const len = Math.hypot(dx, dy) || 1;
    const ux = dx / len, uy = dy / len;
    let t;
    if (n.shape === "circle") t = n.w / 2;
    else if (n.shape === "diamond") t = 1 / (Math.abs(ux) / (n.w / 2) + Math.abs(uy) / (n.h / 2));
    else t = Math.min((n.w / 2) / Math.abs(ux || 1e-6), (n.h / 2) / Math.abs(uy || 1e-6));
    return { x: n.x + ux * (t + 3), y: n.y + uy * (t + 3) };
  }
  function buildEdge(e) {
    const a = N[e.a], b = N[e.b];
    let c1, c2;
    if (e.c) [c1, c2] = e.c(N);
    const p0 = anchor(a, c1 ? c1.x : b.x, c1 ? c1.y : b.y);
    const p3 = anchor(b, c2 ? c2.x : a.x, c2 ? c2.y : a.y);
    if (!c1) { c1 = lerp(p0, p3, 1 / 3); c2 = lerp(p0, p3, 2 / 3); }
    e.p = [p0, c1, c2, p3];
    e.len = 0;
    let prev = p0;
    for (let i = 1; i <= 24; i++) { const q = at(e, i / 24); e.len += Math.hypot(q.x - prev.x, q.y - prev.y); prev = q; }
  }
  const lerp = (a, b, t) => ({ x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t });
  function at(e, t) {
    const [p0, p1, p2, p3] = e.p, u = 1 - t;
    return {
      x: u * u * u * p0.x + 3 * u * u * t * p1.x + 3 * u * t * t * p2.x + t * t * t * p3.x,
      y: u * u * u * p0.y + 3 * u * u * t * p1.y + 3 * u * t * t * p2.y + t * t * t * p3.y,
    };
  }
  function tangent(e, t) { const a = at(e, Math.max(0, t - 0.01)), b = at(e, Math.min(1, t + 0.01)); return Math.atan2(b.y - a.y, b.x - a.x); }

  /* ---------- public: animate one event ---------- */
  function send(hops, color, done, { onHop } = {}) {
    if (reduceMotion.matches) {
      hops.forEach((h, i) => { heat[h.e || h] = { v: 1, color }; onHop && onHop(i); });
      done && done();
      return;
    }
    const now = performance.now();
    const start = Math.max(now, nextStart);
    nextStart = start + 140;
    packets.push({ hops: hops.map((h) => (typeof h === "string" ? { e: h } : h)), i: 0, t: 0, start, last: start, color, trail: [], done, onHop });
  }
  const pulse = (node, color) => pulses.push({ node, color, t0: performance.now() });
  const tag = (node, text, color) => {
    for (let i = tags.length - 1; i >= 0; i--) if (tags[i].node === node) tags.splice(i, 1);
    tags.push({ node, text, color: color || C["ink-2"], t0: performance.now() });
  };
  const stamp = (node, text, color) => stamps.push({ node, text, color, t0: performance.now() });

  function event(ev) {
    const cat = (ev.extra && ev.extra.category) ? String(ev.extra.category).replace(/_/g, " ") : "";
    switch (ev.action) {
      case "request":
        send(["ug", "ga", "au"], C.ok, null, { onHop: (i) => { if (i === 0) pulse("gw", C.ok); if (i === 1) { pulse("app", C.ok); tag("app", "allowed"); } } });
        break;
      case "routed_to_honeypot":
        send(["ug", "gh"], C.trap, () => { pulse("hp", C.trap); tag("hp", cat ? `trapped · ${cat}` : "trapped", C.trap); },
          { onHop: (i) => { if (i === 0) { pulse("gw", C.trap); tag("gw", "flagged by rules", C.trap); } } });
        break;
      case "honeypot_interaction":
        send(["ug", "gh", "hl", "ld", "dh"], C.trap, () => tag("dec", "keep trapping", C.trap),
          { onHop: (i) => { if (i === 1) pulse("hp", C.trap); if (i === 2) { pulse("llm", C.trap); tag("llm", "fake reply"); } if (i === 3) pulse("dec", C.trap); } });
        break;
      case "canary_hit":
        send(["ug", "gh"], C.bad, () => { pulse("hp", C.bad); tag("hp", "canary key reused", C.bad); pulse("dec", C.bad); },
          { onHop: (i) => { if (i === 0) pulse("gw", C.bad); } });
        break;
      case "banned":
        send(["du"], C.bad, () => { pulse("user", C.bad); stamp("user", "BANNED", C.bad); }, { onHop: () => pulse("dec", C.bad) });
        break;
      case "blocked":
        send(["ug"], C.bad, () => { pulse("gw", C.bad); stamp("gw", "403", C.bad); send([{ e: "ug", rev: true }], C.bad); });
        break;
      case "session_ended":
        pulse("dec", C.ink); tag("dec", "session over", C.ink);
        break;
      case "learned_rule_caught":
        pulse("gw", C.learn); tag("gw", "learned rule caught it", C.learn);
        break;
      case "rule_learned":
        pulse("gw", C.learn); tag("gw", "new rule active", C.learn);
        break;
      case "rule_rejected":
        tag("gw", "proposed rule rejected", C["ink-3"]);
        break;
      case "marked_safe":
        pulse("gw", C.ok); tag("gw", "false positive fixed", C.ok);
        break;
    }
  }

  /* ---------- drawing ---------- */
  function roundRect(x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath();
  }
  function shapePath(n, grow = 0) {
    const w = n.w + grow * 2, h = n.h + grow * 2;
    if (n.shape === "circle") { ctx.beginPath(); ctx.arc(n.x, n.y, w / 2, 0, Math.PI * 2); }
    else if (n.shape === "diamond") {
      ctx.beginPath(); ctx.moveTo(n.x, n.y - h / 2); ctx.lineTo(n.x + w / 2, n.y); ctx.lineTo(n.x, n.y + h / 2); ctx.lineTo(n.x - w / 2, n.y); ctx.closePath();
    } else roundRect(n.x - w / 2, n.y - h / 2, w, h, 10 * S);
  }
  function drawEdge(id, e, now) {
    const h = heat[id];
    const hv = h ? h.v : 0;
    ctx.save();
    ctx.lineWidth = 1.5 + hv * 1.5;
    ctx.strokeStyle = hv > 0.02 ? mix(C["line-2"], h.color, hv) : C["line-2"];
    if (e.dashed) { ctx.setLineDash([6, 6]); ctx.lineDashOffset = reduceMotion.matches ? 0 : -now / 60; }
    const [p0, p1, p2, p3] = e.p;
    ctx.beginPath(); ctx.moveTo(p0.x, p0.y); ctx.bezierCurveTo(p1.x, p1.y, p2.x, p2.y, p3.x, p3.y); ctx.stroke();
    ctx.setLineDash([]);
    // arrow head
    const ang = tangent(e, 0.995), s = 8;
    ctx.fillStyle = ctx.strokeStyle;
    ctx.beginPath(); ctx.moveTo(p3.x, p3.y);
    ctx.lineTo(p3.x - s * Math.cos(ang - 0.42), p3.y - s * Math.sin(ang - 0.42));
    ctx.lineTo(p3.x - s * Math.cos(ang + 0.42), p3.y - s * Math.sin(ang + 0.42));
    ctx.closePath(); ctx.fill();
    if (e.label) {
      const m = at(e, 0.5);
      let a = tangent(e, 0.5);
      if (a > Math.PI / 2) a -= Math.PI; if (a < -Math.PI / 2) a += Math.PI;
      if (Math.abs(a) > 1.2) a = 0;
      ctx.translate(m.x, m.y); ctx.rotate(a);
      ctx.font = `500 ${fsSmall()}px ${MONO}`;
      ctx.textAlign = "center"; ctx.textBaseline = "bottom";
      ctx.fillStyle = hv > 0.1 ? h.color : C["ink-3"];
      ctx.fillText(e.label, 0, -5);
    }
    ctx.restore();
  }
  function drawNode(id, n, now) {
    ctx.save();
    shapePath(n);
    ctx.fillStyle = C.surface; ctx.fill();
    ctx.lineWidth = 1.6; ctx.strokeStyle = C.ink; ctx.stroke();
    ctx.fillStyle = C.ink; ctx.textAlign = "center";
    const fs = fsLabel(), fsSub = fsSmall();
    ctx.font = `600 ${fs}px ${SANS}`;
    let below = n.y + n.h / 2 + 5; // next free line under the shape
    if (n.shape === "rect") {
      ctx.textBaseline = "middle";
      ctx.fillText(n.label, n.x, n.y - fsSub * 0.55);
      ctx.font = `400 ${fsSub}px ${MONO}`; ctx.fillStyle = C["ink-3"];
      ctx.fillText(n.sub, n.x, n.y + fs * 0.6);
    } else {
      ctx.textBaseline = "middle";
      ctx.fillText(n.label, n.x, n.y + 1);
      if (n.sub) {
        ctx.font = `400 ${fsSub}px ${MONO}`; ctx.fillStyle = C["ink-3"]; ctx.textBaseline = "top";
        ctx.fillText(n.sub, n.x, below); below += fsSub + 4;
      }
    }
    if (counts[id]) {
      ctx.font = `500 ${fsSub}px ${MONO}`; ctx.fillStyle = C["ink-2"];
      ctx.textBaseline = "top";
      ctx.fillText(counts[id], n.x, below);
    }
    ctx.restore();
  }
  function mix(a, b, t) {
    const pa = hex(a), pb = hex(b);
    return `rgb(${pa.map((v, i) => Math.round(v + (pb[i] - v) * t)).join(",")})`;
  }
  function hex(c) { const m = c.replace("#", ""); return [0, 2, 4].map((i) => parseInt(m.slice(i, i + 2), 16)); }
  const rgba = (c, a) => { const [r, g, b] = hex(c); return `rgba(${r},${g},${b},${a})`; };

  function frame(now) {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    for (const k in heat) { heat[k].v *= 0.965; if (heat[k].v < 0.02) delete heat[k]; }
    for (const [id, e] of Object.entries(E)) drawEdge(id, e, now);

    // pulses (rings growing out of a node)
    for (let i = pulses.length - 1; i >= 0; i--) {
      const p = pulses[i], age = (now - p.t0) / 700;
      if (age >= 1) { pulses.splice(i, 1); continue; }
      const n = N[p.node];
      ctx.save(); shapePath(n, 2 + age * 14 * S); ctx.strokeStyle = rgba(p.color, 0.55 * (1 - age)); ctx.lineWidth = 2.5; ctx.stroke(); ctx.restore();
    }
    for (const [id, n] of Object.entries(N)) drawNode(id, n, now);
    // highlight a node outline while it pulses
    for (const p of pulses) { const n = N[p.node]; ctx.save(); shapePath(n); ctx.strokeStyle = p.color; ctx.lineWidth = 2.2; ctx.stroke(); ctx.restore(); }

    // packets
    for (let i = packets.length - 1; i >= 0; i--) {
      const pk = packets[i];
      if (now < pk.start) continue;
      const hop = pk.hops[pk.i], e = E[hop.e];
      const dur = Math.max(320, e.len * 2.1);
      pk.t += (now - pk.last) / dur; pk.last = now;
      heat[hop.e] = { v: 1, color: pk.color };
      const tt = Math.min(1, pk.t);
      const ease = tt < 0.5 ? 2 * tt * tt : 1 - Math.pow(-2 * tt + 2, 2) / 2;
      const pos = at(e, hop.rev ? 1 - ease : ease);
      pk.trail.push(pos); if (pk.trail.length > 16) pk.trail.shift();
      if (pk.t >= 1) {
        pk.onHop && pk.onHop(pk.i);
        pk.i++; pk.t = 0;
        if (pk.i >= pk.hops.length) { packets.splice(i, 1); pk.done && pk.done(); continue; }
      }
      for (let j = 1; j < pk.trail.length; j++) {
        ctx.strokeStyle = rgba(pk.color, (j / pk.trail.length) * 0.5); ctx.lineWidth = 3;
        ctx.beginPath(); ctx.moveTo(pk.trail[j - 1].x, pk.trail[j - 1].y); ctx.lineTo(pk.trail[j].x, pk.trail[j].y); ctx.stroke();
      }
      ctx.beginPath(); ctx.arc(pos.x, pos.y, 5.5, 0, Math.PI * 2);
      ctx.fillStyle = pk.color; ctx.fill(); ctx.lineWidth = 2; ctx.strokeStyle = C.surface; ctx.stroke();
    }

    // floating tags above nodes
    for (let i = tags.length - 1; i >= 0; i--) {
      const t = tags[i], age = (now - t.t0) / 2400;
      if (age >= 1) { tags.splice(i, 1); continue; }
      const n = N[t.node];
      const alpha = age < 0.08 ? age / 0.08 : age > 0.75 ? (1 - age) / 0.25 : 1;
      ctx.save(); ctx.globalAlpha = alpha;
      ctx.font = `500 ${Math.round(11.5 * Math.max(S, 0.85))}px ${MONO}`;
      const tw = ctx.measureText(t.text).width + 14, th = 22;
      const x = Math.max(4, Math.min(W - tw - 4, n.x - tw / 2));
      let y = n.y - n.h / 2 - th - 8 - (reduceMotion.matches ? 0 : age * 6);
      if (y < 4) y = n.y + n.h / 2 + 6; // no room above (top row): show it underneath
      roundRect(x, y, tw, th, 6); ctx.fillStyle = C.surface; ctx.fill();
      ctx.strokeStyle = t.color; ctx.lineWidth = 1.2; ctx.stroke();
      ctx.fillStyle = t.color; ctx.textAlign = "center"; ctx.textBaseline = "middle";
      ctx.fillText(t.text, x + tw / 2, y + th / 2 + 0.5);
      ctx.restore();
    }
    // stamps (BANNED / 403)
    for (let i = stamps.length - 1; i >= 0; i--) {
      const s = stamps[i], age = (now - s.t0) / 2600;
      if (age >= 1) { stamps.splice(i, 1); continue; }
      const n = N[s.node];
      const sc = reduceMotion.matches ? 1 : age < 0.1 ? 1.4 - age * 4 : 1;
      ctx.save(); ctx.globalAlpha = age > 0.8 ? (1 - age) / 0.2 : 1;
      ctx.translate(n.x + n.w * 0.35, n.y + n.h * 0.42); ctx.rotate(-0.14); ctx.scale(sc, sc);
      ctx.font = `600 ${Math.round(13 * Math.max(S, 0.85))}px ${MONO}`;
      const tw = ctx.measureText(s.text).width + 14;
      roundRect(-tw / 2, -12, tw, 24, 4); ctx.fillStyle = s.color; ctx.fill();
      ctx.fillStyle = "#fff"; ctx.textAlign = "center"; ctx.textBaseline = "middle"; ctx.fillText(s.text, 0, 1);
      ctx.restore();
    }
    requestAnimationFrame(frame);
  }

  function setCounts(stats) {
    const by = stats.by_action || {};
    counts.app = by.request ? `${by.request} served` : "";
    const hpN = (by.routed_to_honeypot || 0) + (by.honeypot_interaction || 0);
    counts.hp = hpN ? `${hpN} attacker actions` : "";
    counts.dec = stats.attackers_banned ? `${stats.attackers_banned} banned` : "";
  }
  function clear() { packets.length = 0; pulses.length = 0; tags.length = 0; stamps.length = 0; for (const k in heat) delete heat[k]; }

  new ResizeObserver(layout).observe(stage);
  layout();
  (document.fonts ? document.fonts.ready : Promise.resolve()).then(layout);
  requestAnimationFrame(frame);
  return { event, setCounts, clear };
})();

/* big moments: short banner over the flow */
function banner(kind, title, text) {
  const b = $("flow-banner");
  b.className = "flow-banner " + kind;
  b.innerHTML = `<b>${esc(title)}</b>${esc(text)}`;
  clearTimeout(banner._t);
  banner._t = setTimeout(() => b.classList.add("hidden"), 5000);
}

/* ================================================================ live feed */
const feed = $("feed");
let lastLearnedCatch = null;
function addFeed(ev, live) {
  const li = document.createElement("li");
  li.className = "ev " + evClass(ev) + (live ? " new" : "");
  const who = ev.attacker_ip ? `${esc(ev.attacker_ip)} · ` : "";
  li.innerHTML = `<div><div class="ev-top"><span>${esc(LABEL[ev.action] || ev.action)}</span><time>${time(ev.ts)}</time></div>
    ${ev.payload ? `<div class="pl">${esc(readable(ev.payload))}</div>` : ""}
    <div class="meta">${who}${CHANNEL[ev.channel] || ev.channel} · risk ${ev.risk ?? 0}${ev.rule_id ? " · " + esc(ev.rule_id) : ""}${ev.detail ? " · " + esc(ev.detail) : ""}</div></div>`;
  feed.prepend(li);
  while (feed.children.length > 150) feed.lastChild.remove();
  $("feed-empty").classList.add("hidden");
  updateSplit(ev);
  if (ev.action === "learned_rule_caught") { lastLearnedCatch = ev.rule_id; setBeforeAfter(); }
  if (live) {
    Flow.event(ev);
    if (ev.action === "canary_hit") banner("bad", "Canary key reused", `${ev.attacker_ip || "Attacker"} used a planted fake key. Banned instantly.`);
    else if (ev.action === "learned_rule_caught") banner("", "Learned rule caught a new attack", `Built-in rules missed this one. ${ev.rule_id || "A learned rule"} stopped it.`);
    else if (ev.action === "marked_safe") banner("ok", "False positive fixed", "The visitor is cleared and their request is allowed from now on.");
    else if (ev.action === "rule_learned") banner("", "New rule learned", ev.detail || ev.rule_id || "");
  }
}
/* show URL-encoded payloads the way the attacker typed them */
function readable(p) { try { return decodeURIComponent(String(p).replace(/\+/g, " ")); } catch (e) { return p; } }
function updateSplit(ev) {
  if (ev.action === "request") $("split-legit").textContent = readable(ev.payload) || "—";
  else if (["routed_to_honeypot", "honeypot_interaction", "canary_hit", "blocked"].includes(ev.action))
    $("split-attacker").textContent = readable(ev.payload) || LABEL[ev.action];
}
document.querySelectorAll(".seg button").forEach((b) => (b.onclick = () => {
  document.querySelectorAll(".seg button").forEach((x) => x.classList.toggle("on", x === b));
  feed.className = "feed-list" + (b.dataset.filter === "all" ? "" : " f-" + b.dataset.filter);
}));

/* ================================================================ counters */
async function refreshStats() {
  try {
    const s = await api("/api/stats");
    const set = (id, v) => { const el = $(id); if (el.textContent !== String(v)) { el.textContent = v; el.classList.remove("bump"); void el.offsetWidth; el.classList.add("bump"); } };
    set("c-requests", s.requests); set("c-attacks", s.attacks_detected); set("c-trapped", s.attackers_trapped);
    set("c-banned", s.attackers_banned); set("c-rules", s.rules_learned); set("c-fixed", s.false_positives_fixed);
    Flow.setCounts(s);
    window.__learnedCatches = s.learned_catches;
    setBeforeAfter();
  } catch (e) { /* monitor restarting */ }
}
function setBeforeAfter() {
  const show = (window.__learnedCatches || 0) > 0;
  $("beforeafter").classList.toggle("hidden", !show);
  if (show) $("ba-after").textContent = `${lastLearnedCatch || "A learned rule"} caught it and sent the attacker to the honeypot.`;
}

/* ================================================================ honeypot sessions */
let sessionsCache = [];
const prevStatus = {};
const TL_KIND = { routed_to_honeypot: ["trap", "trap"], honeypot_interaction: ["act", "trap"], canary_hit: ["canary", "bad"], banned: ["ban", "bad"], session_ended: ["end", ""], blocked: ["403", "bad"] };
async function refreshSessions() {
  try {
    const sessions = await api("/api/sessions");
    sessionsCache = sessions;
    const box = $("sessions");
    $("sessions-empty").classList.toggle("hidden", sessions.length > 0);
    const trapped = sessions.filter((s) => s.status === "trapped").length;
    $("hp-count").textContent = `${trapped} trapped · ${sessions.length} total`;
    box.innerHTML = sessions.map(sessionCard).join("");
    sessions.forEach((s) => {
      if (prevStatus[s.session_id] && prevStatus[s.session_id] !== s.status && s.status === "banned") {
        const el = box.querySelector(`[data-sid="${CSS.escape(s.session_id)}"]`); if (el) el.classList.add("flash");
      }
      prevStatus[s.session_id] = s.status;
    });
  } catch (e) { /* ignore */ }
}
function sessionCard(s) {
  const badge = { trapped: "Trapped", banned: "Banned", ended: "Ended", safe: "Marked safe" }[s.status] || s.status;
  const pct = Math.min(100, Math.round((s.actions / (s.max_actions || 8)) * 100));
  const tl = s.timeline.slice(-5).reverse().map((t) => {
    const [k, cls] = TL_KIND[t.action] || [t.action, ""];
    return `<li><span class="k ${cls}">${esc(k)}</span><code>${esc(readable(t.payload) || t.detail || LABEL[t.action] || t.action)}</code></li>`;
  }).join("");
  const canMark = s.status !== "safe";
  return `<article class="scard ${esc(s.status)}" data-sid="${esc(s.session_id)}">
    <div class="scard-head"><span class="scard-id">${esc(s.attacker_ip)} <span>· ${esc(s.fingerprint)}</span></span>
      ${s.canary ? '<span class="tag bad">canary</span>' : ""}<span class="badge ${esc(s.status)}">${badge}</span></div>
    <div class="meter"><span>${s.actions}/${s.max_actions} actions before ejection</span><span class="bar"><i style="width:${pct}%"></i></span><span>risk ${s.risk}</span></div>
    <ul class="timeline">${tl}</ul>
    ${canMark ? `<div class="scard-actions"><button class="link-btn mark-session" type="button" data-sid="${esc(s.session_id)}">Mark as safe</button></div>` : ""}
  </article>`;
}

/* ================================================================ analyst */
const stream = $("analyst-stream");
function typeLine(el, text, done) {
  if (reduceMotion.matches) { el.textContent = text; done && done(); return; }
  let i = 0;
  el.classList.add("cursor");
  (function tick() {
    el.textContent = text.slice(0, i++);
    if (i <= text.length) setTimeout(tick, 12);
    else { el.classList.remove("cursor"); done && done(); }
  })();
}
function addCommentary(a, instant) {
  setAnalystSource(a.source);
  const li = document.createElement("li");
  const line = document.createElement("div");
  line.className = "line";
  const tags = document.createElement("div");
  tags.className = "tags" + (instant ? "" : " hidden");
  tags.innerHTML = `${a.intent ? `<span class="pill intent">${esc(a.intent)}</span>` : ""}
    ${a.technique ? `<span class="pill">${esc(a.technique)}</span>` : ""}
    ${a.mitre ? `<span class="pill mitre">${esc(a.mitre)}</span>` : ""}
    <span class="rmeter" title="risk ${esc(a.risk ?? 0)}/10"><i style="width:${(a.risk || 0) * 10}%"></i></span>`;
  li.append(line, tags);
  stream.prepend(li);
  if (instant) line.textContent = a.commentary || "(no commentary)";
  else typeLine(line, a.commentary || "(no commentary)", () => tags.classList.remove("hidden"));
  while (stream.children.length > 30) stream.lastChild.remove();
}
function setAnalystSource(src) {
  const el = $("analyst-src");
  if (src === "llm") { el.textContent = (window.__llmLabel || "AI model") + " · live"; el.className = "src-tag live"; }
  else { el.textContent = "offline analyst"; el.className = "src-tag"; }
}
function showReport(r) {
  const card = $("report-card");
  card.classList.remove("hidden");
  card.innerHTML = `<h4>Session report · ${esc(r.attacker_ip || "")} · ${esc(r.attacker_goal || "attack")}</h4>
    <div>${esc(r.summary || "")}</div>
    ${list("Techniques", r.techniques)}${list("Indicators", r.iocs)}${list("Recommended", r.recommended_actions)}
    <div class="muted">risk ${esc(r.risk ?? "?")} · ${r.source === "llm" ? "written by the AI model" : "offline analyst"}</div>`;
}
function list(label, arr) {
  if (!arr || !arr.length) return "";
  return `<div><b>${label}</b><ul>${arr.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>`;
}

/* ================================================================ real vs fake */
const KIND = { customers: "customers", api_keys: "API keys", secrets: "secrets", schema: "schema", prompt: "chat leak", empty: "write query" };
let cxItems = [];
let cxPinned = null;
async function refreshContrast() {
  try { cxItems = await api("/api/data-contrast?limit=8"); } catch (e) { return; }
  renderContrast();
}
function renderContrast() {
  const empty = cxItems.length === 0;
  $("cx-empty").classList.toggle("hidden", !empty);
  if (empty) { $("cx-picker").innerHTML = ""; $("cx-body").innerHTML = ""; $("cx-foot").textContent = ""; return; }
  const sel = cxItems.find((i) => i.id === cxPinned) || cxItems[0];
  $("cx-picker").innerHTML = cxItems.map((i) => `<button type="button" role="tab" aria-selected="${i.id === sel.id}" data-cx="${esc(i.id)}">${time(i.ts)} · ${esc(KIND[i.kind] || i.kind)}</button>`).join("");
  const row = (r, real) => `<div class="cx-row${r.canary ? " canary" : ""}">${r.canary ? '<span class="ctag">CANARY</span>' : ""}
      <div class="l">${esc(r.label)}</div><div class="v">${esc(r.value)}</div>${r.meta ? `<div class="m">${esc(r.meta)}</div>` : ""}</div>`;
  $("cx-body").innerHTML = `<div class="cx-req">${esc(sel.attacker_ip)} asked: ${esc(readable(sel.payload))}</div>
    <div class="cx-cols">
      <div class="cx-col real"><h4>In your database (masked)</h4>${sel.real.map((r) => row(r, true)).join("") || '<p class="empty">Real table not available.</p>'}</div>
      <div class="cx-col fake"><h4>Sent to the hacker</h4>${sel.fake.map((r) => row(r)).join("") || '<p class="empty">An empty “success”.</p>'}</div>
    </div>`;
  const totalCanaries = cxItems.reduce((n, i) => n + i.canaries, 0);
  $("cx-foot").innerHTML = `<b>${totalCanaries}</b> canary tokens planted in the last ${cxItems.length} responses · <b>0</b> real values sent to attackers`;
}
$("cx-picker").addEventListener("click", (e) => {
  const b = e.target.closest("[data-cx]");
  if (!b) return;
  cxPinned = b.dataset.cx === (cxItems[0] && cxItems[0].id) ? null : b.dataset.cx; // picking the newest = follow live again
  renderContrast();
});

/* ================================================================ memory & learning */
let knownLearned = null;
async function refreshMemory() {
  try {
    const [bans, rules] = await Promise.all([api("/api/bans"), api("/api/rules")]);
    $("bans-body").innerHTML = bans.map((b) => `<li><span class="who">${esc(b.ip || "")} · ${esc(b.fingerprint || "")}</span>
        <button class="link-btn mark-safe" type="button" data-fp="${esc(b.fingerprint || "")}" data-ip="${esc(b.ip || "")}">Mark safe</button>
        <span class="why">${esc(b.reason || "")}</span></li>`).join("")
      || '<li class="muted">No bans yet.</li>';
    const learned = rules.filter((r) => r.source === "learned");
    const builtin = rules.filter((r) => r.source !== "learned");
    const fresh = knownLearned ? learned.filter((r) => !knownLearned.has(r.id)).map((r) => r.id) : [];
    knownLearned = new Set(learned.map((r) => r.id));
    const ruleLi = (r) => `<li class="${r.source === "learned" ? "learned" : ""}${r.enabled ? "" : " off"}${fresh.includes(r.id) ? " new" : ""}">
        <span class="rid">${esc(r.id)} <span>· ${esc(r.category)} · ${r.hits || 0} hits</span></span>
        <button class="switch" type="button" role="switch" aria-checked="${!!r.enabled}" aria-label="Turn rule ${esc(r.id)} ${r.enabled ? "off" : "on"}" data-rule="${esc(r.id)}"></button>
        <code class="pat">${esc(r.regex)}</code></li>`;
    $("rules-body").innerHTML = learned.map(ruleLi).join("") || '<li class="muted">Nothing learned yet. Rules appear after an attacker\'s session ends.</li>';
    $("rules-count").textContent = learned.length ? `(${learned.length})` : "";
    $("builtin-body").innerHTML = builtin.map(ruleLi).join("");
    $("builtin-count").textContent = `(${builtin.length})`;
  } catch (e) { /* ignore */ }
}

/* ================================================================ dialogs */
function confirmBox({ title, body, yes, alt, danger }) {
  return new Promise((resolve) => {
    const d = $("confirm-modal");
    $("confirm-title").textContent = title;
    $("confirm-body").innerHTML = body;
    $("confirm-yes").textContent = yes;
    $("confirm-yes").className = "btn " + (danger ? "danger" : "primary");
    $("confirm-alt").hidden = !alt;
    $("confirm-alt").textContent = alt || "";
    const finish = (v) => { d.close(); resolve(v); };
    $("confirm-yes").onclick = () => finish("yes");
    $("confirm-no").onclick = () => finish(null);
    $("confirm-alt").onclick = () => finish("alt");
    d.oncancel = () => resolve(null);
    d.showModal();
    $("confirm-no").focus();
  });
}

/* mark safe: from a ban row (unban) or from a honeypot session (false positive) */
document.addEventListener("click", async (e) => {
  const ms = e.target.closest(".mark-safe");
  if (ms) {
    const ok = await confirmBox({ title: "Unban this visitor?", body: `<p><code>${esc(ms.dataset.ip)} · ${esc(ms.dataset.fp)}</code> will be able to reach the app again.</p>`, yes: "Unban" });
    if (ok) await markSafe({ fingerprint: ms.dataset.fp, ip: ms.dataset.ip }, "Visitor unbanned");
  }
  const mss = e.target.closest(".mark-session");
  if (mss) {
    const s = sessionsCache.find((x) => x.session_id === mss.dataset.sid);
    if (!s) return;
    const first = s.timeline.find((t) => t.action === "routed_to_honeypot") || s.timeline[0] || {};
    const rule = (s.rule_ids || [])[0];
    const ok = await confirmBox({
      title: "Mark this visitor as safe?",
      body: `<p>Use this when a normal user was trapped by mistake.</p>
        <ul><li>Clears <code>${esc(s.attacker_ip)}</code> and lifts any ban</li>
        <li>Allows this exact request from now on: <code>${esc(first.payload || "")}</code></li>
        </ul>
        ${rule ? `<label class="row"><input type="checkbox" id="ms-rule" /> Also turn off rule <code>${esc(rule)}</code>, which flagged it (only if the rule itself is too eager)</label>` : ""}`,
      yes: "Mark as safe",
    });
    if (!ok) return;
    const ruleOff = rule && $("ms-rule") && $("ms-rule").checked;
    await markSafe({ fingerprint: s.fingerprint, ip: s.attacker_ip, rule_id: ruleOff ? rule : undefined, payload: first.payload },
      ruleOff ? "Marked safe: visitor cleared, rule turned off" : "Marked safe: visitor cleared");
  }
  const tg = e.target.closest(".switch");
  if (tg) {
    await api(`/api/rules/${encodeURIComponent(tg.dataset.rule)}/toggle`, { method: "POST", headers: adminHeaders() })
      .then(refreshMemory).catch(() => toast("Couldn't change the rule. Check the admin token in settings."));
  }
});
async function markSafe(body, msg) {
  await api("/api/mark-safe", { method: "POST", headers: adminHeaders(), body: JSON.stringify(body) })
    .then(() => { toast(msg); refreshAll(); })
    .catch(() => toast("Mark safe failed. Check the admin token in settings."));
}

/* ================================================================ AI analyst status + settings */
async function refreshLLM() {
  try {
    const s = await api("/api/llm/status");
    window.__llmLabel = s.label;
    const chip = $("llm-chip"), txt = $("llm-chip-text");
    chip.className = "chip " + ((s.state === "online" || (s.state === "idle" && s.enabled)) ? "online" : (s.state === "unreachable" || s.state === "circuit_open") ? "error" : s.state === "unconfigured" ? "warn" : "");
    if (s.state === "online") txt.textContent = `${s.label} · ${s.last_latency_ms ?? "?"} ms`;
    else if (s.state === "disabled") txt.textContent = "Offline analyst";
    else if (s.state === "unconfigured") txt.textContent = "AI model not set up";
    else if (s.state === "circuit_open") txt.textContent = `AI paused ${s.circuit_open_for_s}s`;
    else if (s.state === "unreachable") txt.textContent = "AI model unreachable";
    else txt.textContent = `${s.label} · idle`;
  } catch (e) { /* ignore */ }
}
function openGear() {
  $("f-token").value = localStorage.getItem("st_admin_token") || "";
  api("/api/llm/config").then((c) => {
    $("f-url").value = c.base_url || "";
    $("f-key").value = "";
    $("f-key").placeholder = c.api_key ? `keep current (${c.api_key})` : "API key";
    $("f-model").value = c.model || "";
    $("f-model").placeholder = c.model || "model name";
    $("f-enabled").checked = !!c.enabled;
  }).catch(() => {});
  $("f-result").textContent = "";
  $("gear-modal").showModal();
}
function collectCfg() {
  localStorage.setItem("st_admin_token", $("f-token").value || "dev-admin-token");
  return { base_url: $("f-url").value, api_key: $("f-key").value, model: $("f-model").value, enabled: $("f-enabled").checked };
}
$("gear-btn").onclick = openGear;
$("llm-chip").onclick = openGear;
$("f-cancel").onclick = () => $("gear-modal").close();
$("f-save").onclick = async () => {
  try {
    await api("/api/llm/config", { method: "POST", headers: adminHeaders(), body: JSON.stringify(collectCfg()) });
    toast("Settings saved"); refreshLLM(); $("gear-modal").close();
  } catch (e) { $("f-result").textContent = "Save failed: the admin token was rejected."; }
};
$("f-test").onclick = async () => {
  $("f-result").textContent = "Saving and testing…";
  try {
    await api("/api/llm/config", { method: "POST", headers: adminHeaders(), body: JSON.stringify(collectCfg()) });
    const r = await api("/api/llm/test", { method: "POST", headers: adminHeaders() });
    $("f-result").textContent = JSON.stringify(r, null, 2);
    if (r.ok && !$("f-enabled").checked) $("f-result").textContent = "Connection works. Tick “Use the AI model” and Save to switch it on.\n\n" + $("f-result").textContent;
    refreshLLM();
  } catch (e) { $("f-result").textContent = "Test failed: check the admin token and URL."; }
};

/* ================================================================ reset */
$("reset-btn").onclick = async () => {
  const ok = await confirmBox({ title: "Reset the demo?", body: "<p>Clears all events, bans, learned rules and attackers. The AI settings are kept.</p>", yes: "Reset", danger: true });
  if (!ok) return;
  try {
    await api("/api/reset", { method: "POST", headers: adminHeaders() });
    clearUI(); toast("Demo reset");
  } catch (e) { toast("Reset failed. Check the admin token in settings."); }
};
function clearUI() {
  feed.innerHTML = ""; stream.innerHTML = ""; $("report-card").classList.add("hidden");
  $("feed-empty").classList.remove("hidden");
  $("split-legit").textContent = "—"; $("split-attacker").textContent = "—";
  lastLearnedCatch = null; knownLearned = null; cxPinned = null;
  Flow.clear(); refreshAll(); refreshContrast();
}

/* ================================================================ ban all + final report */
let lastReport = null;
const op = { active: false, expect: 0, banned: 0, reports: 0 };
const STEPS = ["Eject & ban", "Write attacker reports", "Learn rules", "Build final report"];
function setSteps(state) { // state: index of the running step; -1 = all done
  $("fr-steps").innerHTML = STEPS.map((s, i) => `<li class="${state === -1 || i < state ? "done" : i === state ? "run" : ""}">${s}</li>`).join("");
}
function opProgress() {
  if (!op.active) return;
  let step = 0;
  if (op.banned >= op.expect) step = 1;
  if (step === 1 && op.reports >= op.expect) step = 2;
  setSteps(step);
}

$("banall-btn").onclick = async () => {
  await refreshSessions();
  const trapped = sessionsCache.filter((s) => s.status === "trapped");
  const n = trapped.length;
  const choice = await confirmBox({
    title: n ? `Ban ${n} attacker${n > 1 ? "s" : ""} and build the final report?` : "No one is in the honeypot",
    body: n
      ? `<p>Everyone still in the honeypot is ejected and banned: ${trapped.map((s) => `<code>${esc(s.attacker_ip)}</code>`).join(", ")}.</p>
         <p>The analyst writes a report for each one and learns rules from what they did, so the same attack is stopped next time. Takes up to a minute with the AI model on.</p>
         <p class="muted">Someone trapped by mistake can be cleared afterwards with “Mark as safe”.</p>`
      : "<p>There's nobody to ban right now. You can still build the report from everything recorded so far.</p>",
    yes: n ? `Ban ${n} & build report` : "Build report",
    alt: n ? "Report only" : null,
    danger: n > 0,
  });
  if (!choice) return;
  const doBan = choice === "yes" && n > 0;
  Object.assign(op, { active: doBan, expect: n, banned: 0, reports: 0 });
  $("fr-body").innerHTML = "";
  $("fr-sub").textContent = doBan ? "Working…" : "Building…";
  $("fr-download").disabled = $("fr-print").disabled = true;
  setSteps(doBan ? 0 : 3);
  $("report-modal").showModal();
  try {
    const r = doBan
      ? await api("/api/ban-all", { method: "POST", headers: adminHeaders() })
      : await api("/api/final-report");
    op.active = false;
    setSteps(-1);
    lastReport = r;
    renderFinal(r);
    refreshAll();
  } catch (e) {
    op.active = false;
    $("fr-steps").innerHTML = "";
    $("fr-sub").textContent = e && e.status === 401 ? "The admin token was rejected. Set it in AI analyst settings and try again." : "Couldn't reach the gateway. Is it running?";
  }
};
$("fr-close").onclick = () => $("report-modal").close();
$("fr-print").onclick = () => window.print();
$("fr-download").onclick = () => {
  if (!lastReport) return;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" }));
  a.download = `sentinel-trap-report-${lastReport.generated_at.replace(/[:.]/g, "-")}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
};

function renderFinal(r) {
  const t = r.totals;
  const hostile = r.attackers.filter((a) => a.status !== "safe");
  const cleared = r.attackers.filter((a) => a.status === "safe");
  const ended = (r.ended_now || []).length;
  $("fr-sub").textContent = `Generated ${new Date(r.generated_at).toLocaleString()}${ended ? ` · ${ended} attacker${ended > 1 ? "s" : ""} ejected and banned just now` : ""}`;
  $("fr-download").disabled = $("fr-print").disabled = false;
  const kpi = (v, l) => `<div><b>${v}</b><span>${l}</span></div>`;
  const actK = { request: "allowed", routed_to_honeypot: "trapped", honeypot_interaction: "action", canary_hit: "canary", banned: "banned", session_ended: "ended", blocked: "403" };
  const att = (a) => {
    const rc = a.return_check;
    const allCaught = rc.payloads_checked > 0 && rc.caught === rc.payloads_checked;
    const verdict = a.banned
      ? `<div class="fr-verdict ok"><b>If they come back: stopped.</b>Their fingerprint and IP are banned, so any request gets a 403.
          ${rc.payloads_checked ? `${rc.caught} of ${rc.payloads_checked} of their attack requests are also caught by the rules${rc.learned_rule_ids.length ? `, including learned rules ${rc.learned_rule_ids.map((x) => `<code>${esc(x)}</code>`).join(", ")}` : ""}, so a new identity sending the same attack goes straight back to the honeypot.` : ""}</div>`
      : `<div class="fr-verdict warn"><b>Not banned.</b>${rc.payloads_checked ? `${rc.caught} of ${rc.payloads_checked} of their requests would be caught by the rules.` : ""}</div>`;
    const an = a.analysis;
    return `<article class="fr-att">
      <div class="fr-att-head"><span class="who">${esc(a.attacker_ip)}</span><span class="muted mono">${esc(a.fingerprint)}</span>
        <span class="badge ${esc(a.status)}">${esc(a.status)}</span>${a.canary ? '<span class="tag bad">reused a canary key</span>' : ""}
        <span class="muted">${a.actions} honeypot actions · risk ${a.risk}</span></div>
      <div class="fr-att-grid">
        <div><h4>What they did</h4><ol class="fr-act">${a.activity.map((x) => `<li><span class="k">${esc(actK[x.action] || x.action)}</span><code>${esc(readable(x.payload) || x.detail || "")}</code></li>`).join("")}</ol></div>
        <div><h4>Analyst conclusion ${an ? `<span class="muted">· ${an.source === "llm" ? "AI model" : "offline analyst"}</span>` : ""}</h4>
          ${an ? `<p>${esc(an.summary || "")}</p>${an.attacker_goal ? `<p><b>Goal:</b> ${esc(an.attacker_goal)}</p>` : ""}
            ${list("Techniques", an.techniques)}${list("Indicators", an.iocs)}` : '<p class="muted">No report yet: this session hasn’t ended.</p>'}
          ${verdict}</div>
      </div></article>`;
  };
  $("fr-body").innerHTML = `
    <div class="fr-kpis">${kpi(t.requests, "requests")}${kpi(t.attacks_detected, "attack requests")}${kpi(t.attackers_trapped, "attackers trapped")}
      ${kpi(t.attackers_banned, "banned")}${kpi(t.rules_learned, "rules learned")}${kpi(t.learned_catches, "new attacks caught by learned rules")}${kpi(t.blocked, "return visits blocked")}</div>
    ${(r.unfinished || []).length ? `<p class="fr-verdict warn">The analyst is still finishing ${r.unfinished.length} session(s). Build the report again in a moment to include them.</p>` : ""}
    <section class="fr-section"><h3>Attackers (${hostile.length})</h3>${hostile.map(att).join("") || '<p class="muted">No attackers recorded.</p>'}</section>
    ${cleared.length ? `<section class="fr-section"><h3>Cleared as false positives (${cleared.length})</h3><ul>${cleared.map((a) => `<li><code>${esc(a.attacker_ip)} · ${esc(a.fingerprint)}</code></li>`).join("")}</ul></section>` : ""}
    <section class="fr-section"><h3>What the system learned (${r.learned_rules.length} rules)</h3>
      ${r.learned_rules.length ? `<div style="overflow-x:auto"><table class="fr-table"><thead><tr><th>Rule</th><th>Category</th><th>Pattern</th><th>Hits</th><th>Status</th></tr></thead><tbody>
        ${r.learned_rules.map((x) => `<tr><td><code>${esc(x.id)}</code></td><td>${esc(x.category)}</td><td><code>${esc(x.regex)}</code></td><td>${x.hits || 0}</td><td>${x.enabled ? "on" : "off"}</td></tr>`).join("")}
      </tbody></table></div>` : '<p class="muted">No rules learned yet.</p>'}</section>`;
}

/* presentation mode: press P for bigger type */
document.addEventListener("keydown", (e) => {
  if ((e.key === "p" || e.key === "P") && !/input|textarea/i.test(document.activeElement?.tagName || "") && !document.querySelector("dialog[open]")) {
    document.body.classList.toggle("present");
  }
});

/* ================================================================ live updates */
function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen = () => { $("ws-state").textContent = "Live"; $("ws-dot").classList.add("on"); };
  ws.onclose = () => { $("ws-state").textContent = "Reconnecting…"; $("ws-dot").classList.remove("on"); setTimeout(connectWS, 1500); };
  ws.onmessage = (msg) => {
    const m = JSON.parse(msg.data);
    if (m.type === "event") {
      addFeed(m.event, true);
      if (op.active && m.event.action === "banned") { op.banned++; opProgress(); }
      scheduleRefresh(m.event.action === "honeypot_interaction");
    } else if (m.type === "analysis") addCommentary(m);
    else if (m.type === "report") { showReport(m); if (op.active) { op.reports++; opProgress(); } }
    else if (m.type === "llm") refreshLLM();
    else if (m.type === "reset") clearUI();
    else if (m.type === "final_report" && !$("report-modal").open) toast("A final report was generated");
  };
}
let _refreshTimer = null, _wantContrast = false;
function scheduleRefresh(contrast) {
  _wantContrast = _wantContrast || contrast;
  if (_refreshTimer) return; // throttle: refresh at most every 400ms, even during a burst of events
  _refreshTimer = setTimeout(() => {
    _refreshTimer = null;
    refreshStats(); refreshSessions(); refreshMemory();
    if (_wantContrast) { refreshContrast(); _wantContrast = false; }
  }, 400);
}
function refreshAll() { refreshStats(); refreshSessions(); refreshMemory(); refreshLLM(); }

/* ================================================================ boot */
async function loadAnalyses() {
  const items = await api("/api/analyses?limit=40").catch(() => []);
  items.reverse().forEach((a) => { // oldest first so the newest ends up on top
    if (a.kind === "commentary") addCommentary(a, true);
    else if (a.kind === "report") showReport(a);
  });
}
(async function boot() {
  const evs = await api("/api/events?limit=100").catch(() => []);
  evs.reverse().forEach((ev) => addFeed(ev, false));
  await loadAnalyses();
  refreshAll();
  refreshContrast();
  connectWS();
  setInterval(refreshLLM, 5000);
})();
