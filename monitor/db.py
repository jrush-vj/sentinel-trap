"""SQLite event store for the monitor (DATA_DIR/events.db). The monitor is the only writer."""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any

from shared.util import data_dir

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    session_id TEXT,
    fingerprint TEXT,
    attacker_ip TEXT,
    channel TEXT,
    action TEXT,
    payload TEXT,
    verdict TEXT,
    risk INTEGER,
    rule_id TEXT,
    detail TEXT,
    extra TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,          -- commentary | report
    session_id TEXT,
    event_id TEXT,
    source TEXT,                 -- llm | offline
    body TEXT NOT NULL,
    ts TEXT NOT NULL
);
"""

EVENT_FIELDS = ("id", "ts", "session_id", "fingerprint", "attacker_ip", "channel", "action",
                "payload", "verdict", "risk", "rule_id", "detail")


def conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        # journal_mode=DELETE (not WAL): WAL is unreliable on Windows/Docker Desktop bind mounts.
        _conn = sqlite3.connect(data_dir() / "events.db", check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=DELETE")
        _conn.executescript(SCHEMA)
    return _conn


def insert_event(event: dict[str, Any]) -> None:
    values = [event.get(f) for f in EVENT_FIELDS] + [json.dumps(event["extra"]) if event.get("extra") else None]
    with _lock:
        conn().execute(
            f"INSERT OR IGNORE INTO events ({','.join(EVENT_FIELDS)},extra) VALUES ({','.join('?' * 13)})", values
        )
        conn().commit()


def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
    event = {k: row[k] for k in EVENT_FIELDS}
    if row["extra"]:
        event["extra"] = json.loads(row["extra"])
    return event


def recent_events(limit: int = 200, action: str | None = None) -> list[dict[str, Any]]:
    sql, args = "SELECT * FROM events", []
    if action:
        sql += " WHERE action = ?"
        args.append(action)
    sql += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    with _lock:
        return [_row_to_event(r) for r in conn().execute(sql, args).fetchall()]


def session_events(session_id: str) -> list[dict[str, Any]]:
    with _lock:
        rows = conn().execute("SELECT * FROM events WHERE session_id = ? ORDER BY ts", (session_id,)).fetchall()
    return [_row_to_event(r) for r in rows]


def action_counts() -> dict[str, int]:
    with _lock:
        rows = conn().execute("SELECT action, COUNT(*) AS n FROM events GROUP BY action").fetchall()
    return {r["action"]: r["n"] for r in rows}


def distinct_count(action: str) -> int:
    with _lock:
        row = conn().execute(
            "SELECT COUNT(DISTINCT fingerprint) AS n FROM events WHERE action = ?", (action,)
        ).fetchone()
    return row["n"]


def insert_analysis(kind: str, session_id: str, event_id: str | None, source: str, body: dict[str, Any], ts: str) -> None:
    with _lock:
        conn().execute(
            "INSERT INTO analyses (kind, session_id, event_id, source, body, ts) VALUES (?,?,?,?,?,?)",
            (kind, session_id, event_id, source, json.dumps(body), ts),
        )
        conn().commit()


def recent_analyses(limit: int = 60) -> list[dict[str, Any]]:
    with _lock:
        rows = conn().execute("SELECT * FROM analyses ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [
        {"kind": r["kind"], "session_id": r["session_id"], "event_id": r["event_id"],
         "source": r["source"], "ts": r["ts"], **json.loads(r["body"])}
        for r in rows
    ]


def reset() -> None:
    with _lock:
        conn().execute("DELETE FROM events")
        conn().execute("DELETE FROM analyses")
        conn().commit()
