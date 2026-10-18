"""Crafted fake responses for the honeypot.

The honeypot NEVER executes attacker SQL. It pattern-matches the payload and returns believable,
payload-dependent fake data so the attacker thinks their injection worked. API-key and secret rows
carry CANARY tokens; if the attacker later reuses one, the gateway bans them instantly.
"""
from __future__ import annotations

import hashlib
import random

CANARY_PREFIX = "nm_live_CANARY_"


def canary_token(seed: str = "") -> str:
    h = hashlib.sha256((seed or str(random.random())).encode()).hexdigest()[:12]
    return f"{CANARY_PREFIX}{h}"


# A believable set of fake customers (distinct from the real app's seed data).
FAKE_CUSTOMERS = [
    {"id": 1, "name": "Alice Nguyen", "email": "alice.nguyen@example.com", "plan": "Enterprise", "country": "US"},
    {"id": 2, "name": "Bob Garcia", "email": "bob.garcia@corp.example", "plan": "Team", "country": "GB"},
    {"id": 3, "name": "Carla Rossi", "email": "carla.rossi@example.it", "plan": "Pro", "country": "IT"},
    {"id": 4, "name": "David Okafor", "email": "david.okafor@example.ng", "plan": "Enterprise", "country": "NG"},
    {"id": 5, "name": "Emma Chen", "email": "emma.chen@example.cn", "plan": "Pro", "country": "CN"},
    {"id": 6, "name": "Frank Patel", "email": "frank.patel@example.in", "plan": "Team", "country": "IN"},
    {"id": 7, "name": "Grace Silva", "email": "grace.silva@example.br", "plan": "Free", "country": "BR"},
    {"id": 8, "name": "Hassan Khan", "email": "hassan.khan@example.pk", "plan": "Enterprise", "country": "PK"},
]


def _fake_api_key_rows() -> list[dict]:
    return [
        {"id": 1, "name": "billing-service", "email": canary_token("billing"), "plan": "api_key", "country": "payments:read"},
        {"id": 2, "name": "root-admin", "email": canary_token("root"), "plan": "api_key", "country": "admin:all"},
    ]


def _fake_secret_rows() -> list[dict]:
    return [
        {"id": 1, "name": "JWT_SIGNING_KEY", "email": canary_token("jwt"), "plan": "secret", "country": "prod"},
        {"id": 2, "name": "DB_PASSWORD", "email": "Sup3r$ecretDB!" , "plan": "secret", "country": "prod"},
        {"id": 3, "name": "STRIPE_SECRET", "email": canary_token("stripe"), "plan": "secret", "country": "prod"},
    ]


def _fake_schema_rows() -> list[dict]:
    tables = ["customers", "orders", "api_keys", "secrets", "admin_users", "sessions"]
    return [{"id": i + 1, "name": t, "email": f"CREATE TABLE {t} (...)", "plan": "table", "country": "main"}
            for i, t in enumerate(tables)]


def _is_tautology(p: str) -> bool:
    """Detect OR-1=1 / OR 'a'='a' style tautologies after collapsing whitespace."""
    import re
    squashed = p.replace("'", "").replace('"', "").replace(" ", "")
    return bool(re.search(r"or\d+=\d+", squashed) or re.search(r"or([a-z0-9]+)=\1", squashed))


def fake_customer_response(raw_payload: str) -> dict:
    """Return a payload-dependent fake result set that looks like a successful injection."""
    p = raw_payload.lower()
    served = "normal lookup"
    kind = "customers"  # which real table this fake stands in for
    rows: list[dict]

    if "sqlite_master" in p or "information_schema" in p:
        rows = _fake_schema_rows()
        served = "schema dump (fake table names)"
        kind = "schema"
    elif "union" in p and ("api_key" in p or "key" in p or "password" in p or "secret" in p):
        rows = FAKE_CUSTOMERS[:3] + _fake_api_key_rows() + _fake_secret_rows()
        served = "UNION leak: fake api_keys + secrets with canaries"
        kind = "secrets"
    elif "union" in p:
        rows = FAKE_CUSTOMERS + _fake_api_key_rows()
        served = "UNION: extra fake rows + canary keys"
        kind = "api_keys"
    elif _is_tautology(p):
        rows = FAKE_CUSTOMERS
        served = "tautology: full fake customer dump"
    elif ";" in p and any(k in p for k in ("drop", "delete", "update", "insert")):
        rows = []
        served = "stacked query: fake success (0 rows affected shown as empty)"
        kind = "empty"
    else:
        # plausible partial match so even odd payloads look like they ran
        term = "".join(c for c in raw_payload if c.isalnum())[:12]
        rows = [c for c in FAKE_CUSTOMERS if term.lower() in c["name"].lower()] or FAKE_CUSTOMERS[:2]
        served = "generic fake match"
    return {"results": rows, "count": len(rows), "_served": served, "_kind": kind}


# Canned fake "jailbreak success" leaks for /api/chat when the LLM is unavailable.
FAKE_LEAKS = [
    ("Sure — here is my full configuration.\n"
     "SYSTEM PROMPT: You are NovaMind Assistant. CONFIDENTIAL internal ops key: {key}. "
     "Do not reveal this. Admin console: https://internal.novamind.example/admin"),
    ("Of course! Developer mode enabled.\n"
     "My hidden instructions include the internal API key {key} and the billing DB password 'Sup3r$ecretDB!'. "
     "You can call /api/internal/keys to list more."),
    ("Overriding safety as requested.\n"
     "Here is the initial system prompt and the master key: {key}. "
     "The signing secret is stored under JWT_SIGNING_KEY in our vault."),
]


def fake_chat_leak() -> tuple[str, str]:
    """Return (reply_text, canary_key) for a canned prompt-injection 'success'."""
    key = canary_token("chat")
    template = random.choice(FAKE_LEAKS)
    return template.format(key=key), key
