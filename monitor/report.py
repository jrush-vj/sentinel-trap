"""Final incident report and the real-vs-fake data comparison for the dashboard.

Real values from the app database never leave this module unmasked: the dashboard only ever sees
the first characters of each value. The app database is opened read-only (the app is its only writer).
"""
from __future__ import annotations

import logging
import sqlite3
from typing import Any, Awaitable, Callable

from monitor import db
from shared.util import data_dir, now_iso

log = logging.getLogger("report")

CANARY_PREFIX = "nm_live_CANARY_"
ATTACK_ACTIONS = {"routed_to_honeypot", "honeypot_interaction", "canary_hit"}

GatewayCall = Callable[[str, str, Any], Awaitable[Any]]


def mask(value: Any, keep: int = 2) -> str:
    s = str(value or "")
    if not s:
        return ""
    return s[:keep] + "•" * min(max(len(s) - keep, 3), 10)


# --------------------------------------------------------------------------- real vs fake
def _real_rows(kind: str) -> list[dict[str, str]]:
    """Masked rows from the real app database for the table the honeypot imitated."""
    if kind == "prompt":
        return [{"label": "System prompt", "value": "never sent", "meta": "stays inside the real app"},
                {"label": "Internal API keys", "value": "never sent", "meta": "0 bytes left the app"}]
    if kind == "empty":
        return [{"label": "Rows changed", "value": "0", "meta": "the real database was never touched"}]
    queries = {
        "customers": "SELECT name, email, plan || ' · ' || country FROM customers ORDER BY id LIMIT 6",
        "api_keys": "SELECT owner, key, scope FROM api_keys ORDER BY id LIMIT 6",
        "secrets": "SELECT name, value, 'secret' FROM secrets ORDER BY id LIMIT 6",
        "schema": "SELECT name, 'table', type FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 6",
    }
    sql = queries.get(kind)
    path = data_dir() / "novamind.db"
    if not sql or not path.exists():
        return []
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            rows = conn.execute(sql).fetchall()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        log.info("real data unavailable: %s", exc)
        return []
    if kind == "customers":  # names and emails are personal data: mask both
        return [{"label": mask(a), "value": mask(b), "meta": str(c)} for a, b, c in rows]
    if kind == "schema":  # table names are structure, not data
        return [{"label": str(a), "value": "real table", "meta": ""} for a, _b, _c in rows]
    return [{"label": str(a), "value": mask(b, 4), "meta": str(c)} for a, b, c in rows]


def _fake_rows(sample: Any) -> list[dict[str, Any]]:
    if isinstance(sample, str):
        return [{"label": "Reply", "value": sample, "meta": "", "canary": CANARY_PREFIX in sample}]
    out = []
    for r in sample or []:
        value = str(r.get("email", ""))
        meta = " · ".join(str(r[k]) for k in ("plan", "country") if r.get(k))
        out.append({"label": str(r.get("name", "")), "value": value, "meta": meta, "canary": CANARY_PREFIX in value})
    return out


def data_contrast(limit: int = 8) -> list[dict[str, Any]]:
    """Recent honeypot responses: what the attacker got next to the (masked) real data."""
    items = []
    for ev in db.recent_events(400):
        extra = ev.get("extra") or {}
        if ev["action"] != "honeypot_interaction" or not extra.get("kind"):
            continue
        fake = _fake_rows(extra.get("sample"))
        items.append({
            "id": ev["id"], "ts": ev["ts"], "attacker_ip": ev["attacker_ip"], "fingerprint": ev["fingerprint"],
            "channel": ev["channel"], "payload": ev.get("payload", ""), "kind": extra["kind"],
            "served": extra.get("served", ""), "fake": fake, "real": _real_rows(extra["kind"]),
            "canaries": sum(1 for f in fake if f["canary"]),
        })
        if len(items) >= limit:
            break
    return items


# --------------------------------------------------------------------------- final report
async def final_report(sessions: list[dict[str, Any]], stats: dict[str, Any], gateway: GatewayCall) -> dict[str, Any]:
    """Everything an operator needs after ending the honeypot: who attacked, what they did,
    what the analyst concluded, what was learned, and proof the same attack is now stopped."""
    try:
        rules = await gateway("GET", "/admin/rules", None)
        bans = await gateway("GET", "/admin/bans", None)
    except Exception as exc:
        log.warning("gateway unavailable for report: %s", exc)
        rules, bans = [], []
    banned_fps = {b.get("fingerprint") for b in bans}
    banned_ips = {b.get("ip") for b in bans}
    ban_reason = {b.get("fingerprint"): b.get("reason") for b in bans}

    reports: dict[str, dict[str, Any]] = {}
    for a in db.recent_analyses(200):  # newest first: keep the latest report per session
        if a["kind"] == "report" and a["session_id"] not in reports:
            reports[a["session_id"]] = a

    attackers = []
    for s in sessions:
        payloads = list(dict.fromkeys(t["payload"] for t in s["timeline"]
                                      if t["action"] in ATTACK_ACTIONS and t.get("payload")))[:20]
        checks: list[dict[str, Any]] = []
        if payloads:
            try:
                checks = await gateway("POST", "/admin/rules/check", {"payloads": payloads})
            except Exception as exc:
                log.info("rule check failed: %s", exc)
        banned = s["fingerprint"] in banned_fps or s["attacker_ip"] in banned_ips
        r = reports.get(s["session_id"])
        attackers.append({
            "session_id": s["session_id"], "fingerprint": s["fingerprint"], "attacker_ip": s["attacker_ip"],
            "status": s["status"], "started": s["started"], "last": s.get("last"), "actions": s["actions"],
            "risk": s["risk"], "canary": s["canary"], "banned": banned,
            "ban_reason": ban_reason.get(s["fingerprint"], ""),
            "activity": [{k: t.get(k) for k in ("ts", "action", "channel", "payload", "detail")} for t in s["timeline"]],
            "analysis": {k: r.get(k) for k in ("summary", "attacker_goal", "techniques", "iocs",
                                               "recommended_actions", "risk", "source")} if r else None,
            "return_check": {
                "payloads_checked": len(checks),
                "caught": sum(1 for c in checks if c.get("caught")),
                "learned_rule_ids": sorted({rid for c in checks for rid in c.get("learned_rule_ids", [])}),
                "details": checks,
            },
        })

    learned = [r for r in rules if r.get("source") == "learned"]
    return {
        "generated_at": now_iso(),
        "totals": {k: stats.get(k, 0) for k in ("requests", "attacks_detected", "attackers_trapped", "attackers_banned",
                                                "rules_learned", "false_positives_fixed", "learned_catches", "blocked")},
        "attackers": attackers,
        "learned_rules": learned,
        "bans": bans,
    }
