"""Backend behind the redesigned dashboard: ban-all support, rule dry-run, real-vs-fake masking, mark-safe status."""
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from gateway import store
from honeypot import fakes
from monitor import report

ADMIN = {"Authorization": "Bearer dev-admin-token"}


# ---- honeypot: each fake response says which real table it stands in for
def test_fake_responses_name_the_table_they_imitate():
    assert fakes.fake_customer_response("x' UNION SELECT name,key FROM api_keys--")["_kind"] == "secrets"
    assert fakes.fake_customer_response("x' UNION SELECT a,b FROM t--")["_kind"] == "api_keys"
    assert fakes.fake_customer_response("' UNION SELECT name,sql FROM sqlite_master--")["_kind"] == "schema"
    assert fakes.fake_customer_response("' OR 1=1--")["_kind"] == "customers"
    assert fakes.fake_customer_response("x'; DROP TABLE customers--")["_kind"] == "empty"


# ---- gateway: open sessions and the non-mutating rule check
def test_open_sessions_lists_only_unended_attackers():
    store.upsert_attacker("s1", "fp1", "203.0.113.1", honeypot_inc=1, payload="' OR 1=1--")
    store.upsert_attacker("s2", "fp2", "203.0.113.2", honeypot_inc=1, payload="' OR 1=1--")
    store.mark_ended("s2")
    assert [r["session_id"] for r in store.open_sessions()] == ["s1"]


def test_rules_check_reports_matches_without_counting_hits():
    from gateway.main import app, engine
    client = TestClient(app)
    before = {r.id: r.hits for r in engine.all_rules()}
    res = client.post("/admin/rules/check", headers=ADMIN,
                      json={"payloads": ["' OR 1=1--", "What are your support hours?"]})
    assert res.status_code == 200
    attack, legit = res.json()
    assert attack["caught"] and attack["rule_ids"]
    assert not legit["caught"]
    assert {r.id: r.hits for r in engine.all_rules()} == before


def test_admin_endpoints_need_the_token():
    from gateway.main import app
    client = TestClient(app)
    assert client.post("/admin/rules/check", json={"payloads": []}).status_code == 401
    assert client.post("/admin/end-all", json={}).status_code == 401


# ---- monitor: real data never leaves unmasked
def test_mask_hides_all_but_the_prefix():
    assert report.mask("alice.nguyen@example.com") == "al" + "•" * 10
    assert report.mask("ab") == "ab•••"
    assert report.mask("") == ""


def _seed_app_db(data_dir: str) -> None:
    conn = sqlite3.connect(Path(data_dir) / "novamind.db")
    conn.executescript("""
        CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT, plan TEXT, country TEXT, mrr INTEGER);
        CREATE TABLE api_keys (id INTEGER PRIMARY KEY, owner TEXT, key TEXT, scope TEXT);
        INSERT INTO customers VALUES (1, 'Alice Nguyen', 'alice.nguyen@example.com', 'Pro', 'US', 29);
        INSERT INTO api_keys VALUES (1, 'billing-service', 'nm_live_sk_7Qa2b9FAKE_do_not_use', 'payments:read');
    """)
    conn.commit()
    conn.close()


def test_real_rows_are_masked(isolated_data_dir):
    _seed_app_db(isolated_data_dir)
    customers = report._real_rows("customers")
    keys = report._real_rows("api_keys")
    blob = str(customers) + str(keys)
    for secret in ("Alice Nguyen", "alice.nguyen@example.com", "nm_live_sk_7Qa2b9FAKE_do_not_use"):
        assert secret not in blob
    assert customers[0]["label"].startswith("Al") and keys[0]["value"].startswith("nm_l")


def test_real_rows_missing_db_is_empty_not_an_error():
    assert report._real_rows("customers") == []


def test_fake_rows_flag_canaries():
    rows = report._fake_rows([{"name": "root-admin", "email": "nm_live_CANARY_abc123", "plan": "api_key"},
                              {"name": "Alice", "email": "alice@example.com"}])
    assert [r["canary"] for r in rows] == [True, False]


# ---- monitor: a session cleared with mark-safe shows as safe, unless it attacked again afterwards
def test_marked_safe_session_status():
    from monitor.main import build_sessions

    def ev(action, ts, **kw):
        base = {"id": ts, "ts": ts, "session_id": "s1", "fingerprint": "fp1", "attacker_ip": "198.51.100.20",
                "channel": "prompt", "action": action, "payload": "x", "risk": 4}
        return {**base, **kw}

    trapped = ev("routed_to_honeypot", "2026-01-01T00:00:01Z")
    cleared = ev("marked_safe", "2026-01-01T00:00:02Z", session_id="system", channel="system")
    assert build_sessions([trapped, cleared])[0]["status"] == "safe"
    again = ev("honeypot_interaction", "2026-01-01T00:00:03Z")
    assert build_sessions([trapped, cleared, again])[0]["status"] == "trapped"
