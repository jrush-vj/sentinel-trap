"""Reputation store (DATA_DIR/reputation.db): bans, attacker sessions, and the mark-safe whitelist.

This is the gateway's MEMORY. Bans match on fingerprint OR ip, so clearing cookies does not evade a
ban (the ip still matches). The gateway is the only writer.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from typing import Any

from shared.util import data_dir, now_iso

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS attackers (
    session_id TEXT PRIMARY KEY,
    fingerprint TEXT, ip TEXT,
    risk INTEGER DEFAULT 0,
    honeypot_actions INTEGER DEFAULT 0,
    ban_eligible INTEGER DEFAULT 0,
    canary INTEGER DEFAULT 0,
    first_seen TEXT, last_seen TEXT,
    payloads TEXT DEFAULT '[]',
    rule_ids TEXT DEFAULT '[]',
    ended INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT, ip TEXT, reason TEXT,
    first_seen TEXT, banned_at TEXT, prior_attacks INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_bans_fp ON bans(fingerprint);
CREATE INDEX IF NOT EXISTS idx_bans_ip ON bans(ip);
CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payload_norm TEXT UNIQUE, note TEXT, created_at TEXT
);
"""


def conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(data_dir() / "reputation.db", check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=DELETE")
        _conn.executescript(SCHEMA)
    return _conn


# ---------------- attackers ----------------
def get_attacker(session_id: str) -> sqlite3.Row | None:
    with _lock:
        return conn().execute("SELECT * FROM attackers WHERE session_id=?", (session_id,)).fetchone()


def upsert_attacker(session_id: str, fingerprint: str, ip: str, *, risk_add: int = 0,
                    honeypot_inc: int = 0, payload: str | None = None, rule_ids: list[str] | None = None,
                    canary: bool = False) -> sqlite3.Row:
    import json
    with _lock:
        row = get_attacker(session_id)
        ts = now_iso()
        if row is None:
            conn().execute(
                "INSERT INTO attackers (session_id,fingerprint,ip,risk,honeypot_actions,canary,first_seen,last_seen,payloads,rule_ids) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (session_id, fingerprint, ip, risk_add, honeypot_inc, int(canary), ts, ts,
                 json.dumps([payload] if payload else []), json.dumps(rule_ids or [])))
        else:
            payloads = json.loads(row["payloads"])
            if payload:
                payloads = (payloads + [payload])[-20:]
            rids = json.loads(row["rule_ids"])
            for rid in rule_ids or []:
                if rid not in rids:
                    rids.append(rid)
            conn().execute(
                "UPDATE attackers SET risk=?,honeypot_actions=?,canary=?,last_seen=?,payloads=?,rule_ids=? WHERE session_id=?",
                (min(10, row["risk"] + risk_add), row["honeypot_actions"] + honeypot_inc,
                 int(bool(row["canary"]) or canary), ts, json.dumps(payloads), json.dumps(rids), session_id))
        conn().commit()
        return get_attacker(session_id)


def set_ban_eligible(session_id: str) -> None:
    with _lock:
        conn().execute("UPDATE attackers SET ban_eligible=1 WHERE session_id=?", (session_id,))
        conn().commit()


def mark_ended(session_id: str) -> None:
    with _lock:
        conn().execute("UPDATE attackers SET ended=1 WHERE session_id=?", (session_id,))
        conn().commit()


def idle_eligible_sessions(idle_seconds: int) -> list[sqlite3.Row]:
    """Ban-eligible, not-yet-ended sessions whose last activity is older than idle_seconds."""
    cutoff = time.time() - idle_seconds
    with _lock:
        rows = conn().execute("SELECT * FROM attackers WHERE ban_eligible=1 AND ended=0").fetchall()
    out = []
    for r in rows:
        try:
            last = time.mktime(time.strptime(r["last_seen"][:19], "%Y-%m-%dT%H:%M:%S"))
        except Exception:
            continue
        if last < cutoff:
            out.append(r)
    return out


# ---------------- bans ----------------
def is_banned(fingerprint: str, ip: str) -> sqlite3.Row | None:
    with _lock:
        return conn().execute(
            "SELECT * FROM bans WHERE fingerprint=? OR ip=? ORDER BY banned_at LIMIT 1",
            (fingerprint, ip)).fetchone()


def add_ban(fingerprint: str, ip: str, reason: str, first_seen: str | None = None, prior_attacks: int = 0) -> sqlite3.Row:
    with _lock:
        if is_banned(fingerprint, ip):
            return is_banned(fingerprint, ip)
        conn().execute(
            "INSERT INTO bans (fingerprint,ip,reason,first_seen,banned_at,prior_attacks) VALUES (?,?,?,?,?,?)",
            (fingerprint, ip, reason, first_seen or now_iso(), now_iso(), prior_attacks))
        conn().commit()
        return is_banned(fingerprint, ip)


def remove_ban(fingerprint: str | None = None, ip: str | None = None) -> int:
    with _lock:
        cur = conn().execute("DELETE FROM bans WHERE (?1 IS NOT NULL AND fingerprint=?1) OR (?2 IS NOT NULL AND ip=?2)",
                             (fingerprint, ip))
        conn().commit()
        return cur.rowcount


def list_bans() -> list[dict[str, Any]]:
    with _lock:
        rows = conn().execute("SELECT * FROM bans ORDER BY banned_at DESC").fetchall()
    return [dict(r) for r in rows]


# ---------------- whitelist ----------------
def add_whitelist(payload_norm: str, note: str = "") -> None:
    with _lock:
        conn().execute("INSERT OR IGNORE INTO whitelist (payload_norm,note,created_at) VALUES (?,?,?)",
                       (payload_norm, note, now_iso()))
        conn().commit()


def whitelisted(variants: list[str]) -> bool:
    with _lock:
        rows = conn().execute("SELECT payload_norm FROM whitelist").fetchall()
    wl = {r["payload_norm"] for r in rows}
    return any(v in wl for v in variants)


def open_sessions() -> list[sqlite3.Row]:
    """Trapped attackers whose honeypot session has not ended yet."""
    with _lock:
        return conn().execute("SELECT * FROM attackers WHERE ended=0").fetchall()


def reset() -> None:
    with _lock:
        for t in ("attackers", "bans", "whitelist"):
            conn().execute(f"DELETE FROM {t}")
        conn().commit()
