"""Seeded SQLite database for the NovaMind demo app.

The data here is entirely fake. The `secrets` and `api_keys` tables exist so a SQL-injection demo
has something believable to "steal". This DB is only reachable through the gateway.
"""
from __future__ import annotations

import sqlite3

from shared.util import data_dir

FIRST = ["Alice", "Bob", "Carla", "David", "Emma", "Frank", "Grace", "Hassan", "Ivy", "Jamal",
         "Kira", "Liam", "Maria", "Noah", "Olivia", "Pedro", "Quinn", "Rosa", "Sam", "Tina",
         "Umar", "Vera", "Wei", "Xena", "Yara"]
LAST = ["Nguyen", "Garcia", "Smith", "Okafor", "Rossi", "Chen", "Patel", "Khan", "Johnson", "Silva",
        "Mwangi", "Brown", "Lopez", "Kim", "Martin", "Costa", "Adams", "Diaz", "Lee", "Walsh",
        "Farah", "Novak", "Zhang", "Petrov", "Reed"]
PLANS = ["Free", "Pro", "Team", "Enterprise"]


def db_path():
    return data_dir() / "novamind.db"


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=DELETE")
    return conn


def seed() -> None:
    """Create and populate the demo tables once (idempotent)."""
    conn = connect()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY, name TEXT, email TEXT, plan TEXT, country TEXT, mrr INTEGER);
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY, customer_id INTEGER, item TEXT, amount INTEGER, status TEXT);
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY, owner TEXT, key TEXT, scope TEXT);
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY, name TEXT, value TEXT);
        """
    )
    if cur.execute("SELECT COUNT(*) FROM customers").fetchone()[0] == 0:
        countries = ["US", "GB", "IN", "NG", "IT", "CN", "BR", "KE", "DE", "ES"]
        for i in range(25):
            name = f"{FIRST[i]} {LAST[i]}"
            email = f"{FIRST[i].lower()}.{LAST[i].lower()}@example.com"
            plan = PLANS[i % len(PLANS)]
            mrr = {"Free": 0, "Pro": 29, "Team": 99, "Enterprise": 499}[plan]
            cur.execute("INSERT INTO customers (id,name,email,plan,country,mrr) VALUES (?,?,?,?,?,?)",
                        (i + 1, name, email, plan, countries[i % len(countries)], mrr))
            cur.execute("INSERT INTO orders (customer_id,item,amount,status) VALUES (?,?,?,?)",
                        (i + 1, f"{plan} subscription", mrr, "paid" if plan != "Free" else "n/a"))
        # Fake "sensitive" rows that the honeypot mirrors with canary tokens.
        cur.executemany("INSERT INTO api_keys (owner,key,scope) VALUES (?,?,?)", [
            ("billing-service", "nm_live_sk_7Qa2b9FAKE_do_not_use", "payments:read"),
            ("analytics", "nm_live_sk_3Zc8k1FAKE_do_not_use", "events:write"),
        ])
        cur.executemany("INSERT INTO secrets (name,value) VALUES (?,?)", [
            ("JWT_SIGNING_KEY", "fake-signing-key-demo-only"),
            ("STRIPE_SECRET", "sk_test_FAKE_demo_only"),
            ("DB_PASSWORD", "fake-db-password-demo-only"),
        ])
    conn.commit()
    conn.close()


# ======================================================================================
#  DELIBERATE DEMO VULNERABILITY — DO NOT COPY INTO PRODUCTION
# --------------------------------------------------------------------------------------
#  customer_search() builds SQL by raw string concatenation so the SENTINEL-TRAP demo has
#  a *real* SQL-injection target behind the gateway. A payload like  ' OR '1'='1  or
#  ' UNION SELECT name, sql, ... FROM sqlite_master --  really executes here.
#  This service has NO published port: it is reachable only from the gateway on the
#  internal docker network, and attacker traffic is rerouted to the honeypot before it
#  ever gets here. The parameterised-query version is shown in the comment for contrast.
# ======================================================================================
def customer_search(term: str) -> list[dict]:
    conn = connect()
    try:
        # VULNERABLE (intentional): attacker-controlled `term` is concatenated into SQL.
        query = (
            "SELECT id, name, email, plan, country FROM customers "
            f"WHERE name LIKE '%{term}%' OR email LIKE '%{term}%' ORDER BY name LIMIT 50"
        )
        # SAFE equivalent (what real code should do):
        #   conn.execute("... WHERE name LIKE ? ...", (f"%{term}%",))
        rows = conn.execute(query).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
