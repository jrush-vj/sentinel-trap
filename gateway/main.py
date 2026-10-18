"""SENTINEL-TRAP gateway — the only public entry point (:8080).

Decision order for every request (ALL deterministic, no LLM in this path):
  1. fingerprint = sha256(ip | user-agent | st_session cookie)[:16]; a valid signed nm_user login
     cookie makes the identity the account ("acct:<name>") instead of the browser session
  2. canary signature anywhere -> immediate ban + route to honeypot
  3. banned (account, else fingerprint OR ip) -> plain 403 "Access denied"
  4. already an active attacker session -> keep them in the honeypot
  5. rule engine scores the request -> clean proxies to the app, suspicious/malicious -> honeypot.
     A logged-in account whose attack is of a category the system has already LEARNED is stopped
     with a 403 instead (attack_stopped): not trapped, not banned, the account stays usable.
  6. every decision emits a fire-and-forget event to the monitor

Admin API (Bearer ADMIN_TOKEN, internal network) powers banning, rule proposal/validation,
mark-safe self-correction, and demo reset.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from gateway import store
from gateway.normalize import normalize_variants
from gateway.proxy import aclose, forward
from gateway.rules import CANARY_PATTERNS, MALICIOUS_MIN, Rule, RuleEngine
from gateway.validator import validate
from shared import auth
from shared.events import EventSender, make_event
from shared.util import env_bool, env_int, env_str, fingerprint as make_fp, now_iso

logging.basicConfig(level=logging.INFO, format="%(asctime)s gateway %(levelname)s %(message)s")
log = logging.getLogger("gateway")

APP_URL = env_str("APP_URL", "http://app:8000")
HONEYPOT_URL = env_str("HONEYPOT_URL", "http://honeypot:8001")
ADMIN_TOKEN = env_str("ADMIN_TOKEN", "dev-admin-token")
TRUST_XFF = env_bool("TRUST_XFF", True)
BAN_THRESHOLD = env_int("BAN_THRESHOLD", 6)
MAX_HONEYPOT_ACTIONS = env_int("MAX_HONEYPOT_ACTIONS", 8)
BAN_IDLE_SECONDS = env_int("BAN_IDLE_SECONDS", 90)

engine = RuleEngine()
sender = EventSender()

DENIED_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Access denied</title>
<style>body{background:#0b0e14;color:#8893a7;font-family:system-ui;display:grid;place-items:center;height:100vh;margin:0}
.b{text-align:center}h1{font-size:22px;color:#c7d0e0}</style></head>
<body><div class="b"><h1>Access denied</h1><p>You don't have permission to access this resource.</p></div></body></html>"""


@asynccontextmanager
async def lifespan(_: FastAPI):
    sender.start()
    sweeper = asyncio.create_task(idle_sweeper())
    emit(make_event("request", channel="system", detail="gateway online", session_id="system"))
    yield
    sweeper.cancel()
    await sender.stop()
    await aclose()


app = FastAPI(title="SENTINEL-TRAP gateway", docs_url=None, redoc_url=None, lifespan=lifespan)


def emit(event: dict[str, Any]) -> None:
    sender.emit(event)


# --------------------------------------------------------------------------- identity
def client_ip(request: Request) -> str:
    if TRUST_XFF:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


def bannable_ip(request: Request, ip: str) -> str | None:
    """The ip to remember in the ban store, or None to ban by fingerprint only. Behind Docker Desktop every
    browser on the LAN arrives from the same NAT ip, so banning a non-public socket ip would lock out everyone."""
    if TRUST_XFF and request.headers.get("x-forwarded-for"):
        return ip
    try:
        return ip if ipaddress.ip_address(ip).is_global else None
    except ValueError:
        return None


def identity(request: Request) -> tuple[str, str, str, str | None]:
    """Return (ip, user_agent, session_id, set_cookie_or_None)."""
    ip = client_ip(request)
    ua = request.headers.get("user-agent", "")
    session = request.cookies.get("st_session")
    set_cookie = None
    if not session:
        import uuid
        session = uuid.uuid4().hex[:20]
        set_cookie = session
    return ip, ua, session, set_cookie


def inspect_fields(request: Request, body: bytes) -> dict[str, str]:
    """Collect the strings the rule engine inspects: query, JSON values, form fields, key headers."""
    fields: dict[str, str] = {"path": request.url.path, "query": request.url.query}
    text = body.decode("utf-8", "replace") if body else ""
    if text:
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, (str, int, float)):
                        fields[f"body.{k}"] = str(v)
            else:
                fields["body"] = text
        except json.JSONDecodeError:
            fields["body"] = text  # form-encoded or raw
    for h in ("user-agent", "referer", "x-api-key", "authorization"):
        if h in request.headers:
            fields[f"hdr.{h}"] = request.headers[h]
    return fields


def login_target(request: Request, fields: dict[str, str]) -> str | None:
    """The account a login/signup request is for (unverified: used only to refuse banned accounts)."""
    if request.url.path not in ("/api/login", "/api/signup"):
        return None
    name = fields.get("body.username", "").strip().lower()
    return name if auth.USERNAME_RE.match(name) else None


def channel_of(path: str) -> str:
    if path.endswith("/api/chat"):
        return "prompt"
    if path.endswith("/api/feedback"):
        return "log"
    return "web"


def has_canary(fields: dict[str, str]) -> bool:
    blob = " ".join(fields.values())
    return any(p.search(blob) for p in CANARY_PATTERNS)


# --------------------------------------------------------------------------- proxy helper
def st_headers(fp: str, session: str, ip: str, actions: int, risk: int, rule_ids: list[str]) -> dict[str, str]:
    return {"X-ST-Fingerprint": fp, "X-ST-Session": session, "X-ST-IP": ip,
            "X-ST-Actions": str(actions), "X-ST-Risk": str(risk), "X-ST-Rules": ",".join(rule_ids)}


def with_cookie(resp: Response, set_cookie: str | None) -> Response:
    if set_cookie:
        resp.set_cookie("st_session", set_cookie, httponly=True, samesite="lax", max_age=86400)
    return resp


async def route_to_honeypot(request: Request, body: bytes, *, fp: str, session: str, ip: str,
                            actions: int, risk: int, rule_ids: list[str]) -> Response:
    return await forward(request, HONEYPOT_URL, body,
                         st_headers(fp, session, ip, actions, risk, rule_ids))


# --------------------------------------------------------------------------- main entry
@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "gateway"}


async def gateway(request: Request, full_path: str) -> Response:
    body = await request.body()
    ip, ua, session, set_cookie = identity(request)
    fp = make_fp(ip, ua, session)
    bip = bannable_ip(request, ip)
    fields = inspect_fields(request, body)
    account = auth.verify(request.cookies.get(auth.COOKIE))
    sid = f"acct:{account}" if account else session  # who attacks/bans/learning are tracked against
    login_name = login_target(request, fields)
    channel = channel_of(request.url.path)
    payload = summarize_payload(request, fields)

    # (2) canary signature -> immediate ban + honeypot
    if has_canary(fields):
        existing = store.get_attacker(sid)
        store.upsert_attacker(sid, fp, bip, honeypot_inc=1, payload=payload, canary=True)
        commit_ban(fp, bip, "canary hit (token reused / decoy endpoint touched)", sid)
        emit(make_event("canary_hit", session_id=sid, fingerprint=fp, attacker_ip=ip, channel=channel,
                        payload=payload, verdict="malicious", risk=10, detail="canary signature in request"))
        emit(make_event("session_ended", session_id=sid, fingerprint=fp, attacker_ip=ip, channel="system",
                        verdict="malicious", risk=10, detail="canary hit"))
        resp = await route_to_honeypot(request, body, fp=fp, session=sid, ip=ip,
                                       actions=(existing["honeypot_actions"] if existing else 0) + 1, risk=10, rule_ids=[])
        return with_cookie(resp, set_cookie)

    # (3) banned -> plain 403
    names = [n for n in (account, login_name) if n]
    ban = None
    for name in names:
        ban = ban or store.is_banned(fp, bip, name)
    if not names:
        ban = store.is_banned(fp, bip)
    if ban:
        mins = minutes_since(ban["first_seen"])
        who = f"account {ban['account']}" if ban["account"] else "attacker"
        emit(make_event("blocked", session_id=f"acct:{ban['account']}" if ban["account"] else sid, fingerprint=fp,
                        attacker_ip=ip, channel=channel, payload=payload, verdict="malicious", risk=10, rule_id=None,
                        detail=f"Known {who}, banned (first seen {mins} min ago, {ban['prior_attacks']} prior attacks)"))
        resp = with_cookie(HTMLResponse(DENIED_HTML, status_code=403), set_cookie)
        if names:
            resp.delete_cookie(auth.COOKIE)  # signs the banned account out so another account can be used
        return resp

    # (4) already an active (not-ended) attacker -> keep them trapped
    attacker = store.get_attacker(sid)
    if attacker and not attacker["ended"]:
        return with_cookie(await handle_honeypot_action(request, body, fp, sid, ip, payload, channel, attacker, fields),
                           set_cookie)

    # (5) rule evaluation
    if store.whitelisted(normalize_variants(payload)):
        verdict = {"verdict": "clean", "score": 0, "matched": [], "rule_ids": [], "learned_only_hit": False,
                   "builtin_score": 0, "top_category": None}
    else:
        verdict = engine.evaluate(fields)

    if verdict["verdict"] == "clean":
        emit(make_event("request", session_id=sid, fingerprint=fp, attacker_ip=ip, channel=channel,
                        payload=payload, verdict="clean", risk=verdict["score"], detail="proxied to app"))
        resp = await forward(request, APP_URL, body)
        return with_cookie(resp, set_cookie)

    if request.url.path in ("/api/login", "/api/signup"):
        # never trap a sign-in: the browser's next (real) login would land in the honeypot and stay anonymous
        return with_cookie(stop_attack(sid, fp, ip, channel, payload, verdict, verdict["matched"],
                                       "attack on the sign-in form stopped; not trapped"), set_cookie)
    if account:
        learned = {r.category for r in engine.all_rules() if r.source == "learned" and r.enabled}
        known = [r for r in verdict["matched"] if r.category in learned]
        if known:
            cat = known[0].category.replace("_", " ")
            return with_cookie(stop_attack(sid, fp, ip, channel, payload, verdict, known,
                                           f"known {cat} attack stopped; account {account} not banned"), set_cookie)

    # suspicious or malicious -> first detection, silently route to honeypot
    row = store.upsert_attacker(sid, fp, bip, risk_add=verdict["score"], honeypot_inc=1,
                                payload=payload, rule_ids=verdict["rule_ids"])
    maybe_mark_eligible(row)
    if verdict.get("learned_only_hit"):
        emit(make_event("learned_rule_caught", session_id=sid, fingerprint=fp, attacker_ip=ip, channel=channel,
                        payload=payload, verdict="malicious", risk=verdict["score"],
                        rule_id=next((r.id for r in verdict["matched"] if r.source == "learned"), None),
                        detail="learned rule caught a variant the built-ins would have missed",
                        extra={"builtin_score": verdict["builtin_score"], "builtin_verdict": verdict["builtin_verdict"]}))
    emit(make_event("routed_to_honeypot", session_id=sid, fingerprint=fp, attacker_ip=ip, channel=channel,
                    payload=payload, verdict=verdict["verdict"], risk=verdict["score"],
                    rule_id=verdict["rule_ids"][0] if verdict["rule_ids"] else None,
                    detail=f"matched {', '.join(verdict['rule_ids']) or 'rules'} -> rerouted silently",
                    extra={"actions": row["honeypot_actions"], "max_actions": MAX_HONEYPOT_ACTIONS,
                           "category": verdict.get("top_category")}))
    resp = await route_to_honeypot(request, body, fp=fp, session=sid, ip=ip,
                                   actions=row["honeypot_actions"], risk=row["risk"], rule_ids=verdict["rule_ids"])
    return with_cookie(resp, set_cookie)


def stop_attack(sid: str, fp: str, ip: str, channel: str, payload: str,
                verdict: dict[str, Any], rules: list[Rule], detail: str) -> Response:
    """Refuse this request only. No trap, no ban."""
    rule = next((r for r in rules if r.source == "learned"), rules[0])
    emit(make_event("attack_stopped", session_id=sid, fingerprint=fp, attacker_ip=ip, channel=channel,
                    payload=payload, verdict=verdict["verdict"], risk=verdict["score"], rule_id=rule.id,
                    detail=detail, extra={"category": rule.category, "rule_ids": verdict["rule_ids"]}))
    return JSONResponse({"error": "blocked", "detail": "This request was blocked by NovaMind's security policy."},
                        status_code=403)


async def handle_honeypot_action(request: Request, body: bytes, fp: str, session: str, ip: str,
                                 payload: str, channel: str, attacker, fields: dict[str, str]) -> Response:
    """Subsequent requests from a trapped attacker: stay in the honeypot, count the action."""
    row = store.upsert_attacker(session, fp, bannable_ip(request, ip), honeypot_inc=1, payload=payload)
    maybe_mark_eligible(row)
    category = engine.evaluate(fields)["top_category"]  # tells the analyst which attack type to learn
    emit(make_event("honeypot_interaction", session_id=session, fingerprint=fp, attacker_ip=ip, channel=channel,
                    payload=payload, verdict="malicious", risk=row["risk"],
                    detail="trapped attacker interaction",
                    extra={"actions": row["honeypot_actions"], "max_actions": MAX_HONEYPOT_ACTIONS,
                           "category": category}))
    # account sessions are ended by the operator's Ban button, not by an action limit
    if row["honeypot_actions"] >= MAX_HONEYPOT_ACTIONS and not session.startswith("acct:"):
        emit(make_event("session_ended", session_id=session, fingerprint=fp, attacker_ip=ip, channel="system",
                        verdict="malicious", risk=row["risk"],
                        detail=f"reached {MAX_HONEYPOT_ACTIONS} honeypot actions"))
    return await route_to_honeypot(request, body, fp=fp, session=session, ip=ip,
                                   actions=row["honeypot_actions"], risk=row["risk"], rule_ids=[])


def maybe_mark_eligible(row) -> None:
    """Trap-then-ban: cross the threshold -> ban-eligible, but keep trapping (ban on session end)."""
    if row["risk"] >= BAN_THRESHOLD and row["honeypot_actions"] >= 2 and not row["ban_eligible"]:
        store.set_ban_eligible(row["session_id"])


def commit_ban(fp: str, ip: str, reason: str, session: str) -> None:
    """Account sessions ban only the account; anonymous ones ban fingerprint + ip."""
    account = session[5:] if session.startswith("acct:") else None
    row = store.get_attacker(session)
    first_seen = row["first_seen"] if row else now_iso()
    prior = row["honeypot_actions"] if row else 0
    if store.is_banned(None, None, account) if account else store.is_banned(fp, ip):
        return
    if account:
        store.add_ban(None, None, reason, first_seen=first_seen, prior_attacks=prior, account=account)
    else:
        store.add_ban(fp, ip, reason, first_seen=first_seen, prior_attacks=prior)
    store.mark_ended(session)
    emit(make_event("banned", session_id=session, fingerprint=fp, attacker_ip=ip, channel="system",
                    verdict="malicious", risk=10, detail=f"ban{' account ' + account if account else ''}: {reason}"))


def end_session(row, reason: str) -> None:
    """Ban a trapped attacker and announce the session end, so the monitor writes the report and learns."""
    commit_ban(row["fingerprint"], row["ip"], reason, row["session_id"])
    store.mark_ended(row["session_id"])  # commit_ban skips this when the attacker was already banned
    emit(make_event("session_ended", session_id=row["session_id"], fingerprint=row["fingerprint"],
                    attacker_ip=row["ip"], channel="system", verdict="malicious", risk=row["risk"], detail=reason))


async def idle_sweeper() -> None:
    """Ban-eligible sessions that go quiet (attacker left) are ended + banned after BAN_IDLE_SECONDS."""
    while True:
        await asyncio.sleep(10)
        try:
            for row in store.idle_eligible_sessions(BAN_IDLE_SECONDS):
                end_session(row, "ban-eligible session idle")
        except Exception as exc:
            log.warning("idle sweeper error: %s", exc)


# --------------------------------------------------------------------------- helpers
def summarize_payload(request: Request, fields: dict[str, str]) -> str:
    if request.url.path.endswith("/api/chat") and "body.message" in fields:
        return fields["body.message"]
    if request.url.query:
        return f"{request.url.path}?{request.url.query}"
    body_vals = [v for k, v in fields.items() if k.startswith("body")]
    return body_vals[0] if body_vals else request.url.path


def minutes_since(iso_ts: str) -> int:
    import time
    try:
        t = time.mktime(time.strptime(iso_ts[:19], "%Y-%m-%dT%H:%M:%S"))
        return max(0, int((time.time() - t) / 60))
    except Exception:
        return 0


# =========================================================================== admin API
def require_admin(authorization: str = Header(default=""), x_admin_token: str = Header(default="")) -> None:
    token = x_admin_token or authorization.removeprefix("Bearer ").strip()
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="admin token required")


@app.post("/admin/ban", dependencies=[Depends(require_admin)])
async def admin_ban(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    fp = payload.get("fingerprint", "")
    ip = payload.get("ip", "")
    reason = payload.get("reason", "manual ban")
    session = payload.get("session_id", fp or ip)
    commit_ban(fp, ip, reason, session)
    return {"banned": True, "fingerprint": fp, "ip": ip}


@app.post("/admin/ban-account", dependencies=[Depends(require_admin)])
async def admin_ban_account(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """Operator action: ban one demo account and end its honeypot session (the monitor then writes the report)."""
    account = str(payload.get("account", "")).strip().lower()
    if not auth.USERNAME_RE.match(account):
        raise HTTPException(status_code=400, detail="invalid account")
    sid = f"acct:{account}"
    reason = str(payload.get("reason") or "operator ban after the analyst learned the account's attacks")
    row = store.get_attacker(sid)
    if row:
        end_session(row, reason)
    else:
        commit_ban("", "", reason, sid)
    return {"banned": True, "account": account, "ended": [sid] if row else []}


@app.post("/admin/end-all", dependencies=[Depends(require_admin)])
async def admin_end_all(payload: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    """Operator action: eject every attacker still in the honeypot and ban them."""
    reason = str(payload.get("reason") or "operator ended all honeypot sessions")
    ended = []
    for row in store.open_sessions():
        end_session(row, reason)
        ended.append(row["session_id"])
    return {"ended": ended}


@app.post("/admin/rules/check", dependencies=[Depends(require_admin)])
async def admin_rules_check(payload: dict[str, Any] = Body(...)) -> list[dict[str, Any]]:
    """Dry run: which enabled rules would catch each payload now. Does not change hit counters."""
    rules = [r for r in engine.all_rules() if r.enabled]
    out = []
    for text in [str(p) for p in payload.get("payloads", [])][:50]:
        variants = normalize_variants(text)
        matched = [r for r in rules if r.matches(variants)]
        # any match sends the request to the honeypot (suspicious and malicious both route there)
        out.append({"payload": text, "rule_ids": [r.id for r in matched],
                    "learned_rule_ids": [r.id for r in matched if r.source == "learned"],
                    "caught": bool(matched)})
    return out


@app.post("/admin/rules/propose", dependencies=[Depends(require_admin)])
async def admin_propose(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """Validate an (untrusted) proposed rule. On success, activate it and emit rule_learned."""
    category = str(payload.get("category", "other"))
    regex = str(payload.get("regex", ""))
    example = str(payload.get("example_payload", ""))
    reasoning = str(payload.get("reasoning", ""))[:300]
    result = validate(category, regex, example)
    if not result.accepted:
        emit(make_event("rule_rejected", channel="system", verdict="suspicious", risk=0,
                        payload=regex, detail=f"rejected: {result.reason}"))
        return {"accepted": False, "reason": result.reason}
    rule_id = f"LR-{category[:4].upper()}-{abs(hash(regex)) % 10000:04d}"
    rule = Rule(id=rule_id, category=category, regex=regex, severity=6, source="learned",
                description=reasoning or "learned from attacker session")
    engine.add_learned(rule)
    emit(make_event("rule_learned", channel="system", verdict="malicious", risk=6, rule_id=rule_id,
                    payload=regex, detail=f"activated learned {category} rule",
                    extra={"rule": rule.to_dict(), "reasoning": reasoning}))
    return {"accepted": True, "rule": rule.to_dict()}


@app.post("/admin/rules/{rule_id}/toggle", dependencies=[Depends(require_admin)])
async def admin_toggle(rule_id: str) -> dict[str, Any]:
    enabled = engine.toggle(rule_id)
    if enabled is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return {"rule_id": rule_id, "enabled": enabled}


@app.post("/admin/mark-safe", dependencies=[Depends(require_admin)])
async def admin_mark_safe(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """Self-correction: unban a fingerprint/ip and/or disable a mis-firing rule + whitelist its payload."""
    fp = payload.get("fingerprint")
    ip = payload.get("ip")
    account = payload.get("account")
    rule_id = payload.get("rule_id")
    example = payload.get("payload") or payload.get("example_payload")
    removed = 0
    if account:
        removed += store.remove_ban(account=account)
        with store._lock:
            store.conn().execute("DELETE FROM attackers WHERE session_id=?", (f"acct:{account}",))
            store.conn().commit()
    if fp or ip:
        removed += store.remove_ban(fp, ip)
        if fp:
            # clear the attacker flag so the (now-cleared) session is treated as clean again
            row = None
            with store._lock:
                rows = store.conn().execute("SELECT session_id FROM attackers WHERE fingerprint=?", (fp,)).fetchall()
                for r in rows:
                    store.conn().execute("DELETE FROM attackers WHERE session_id=?", (r["session_id"],))
                store.conn().commit()
    disabled_rule = None
    if rule_id:
        if engine.disable(rule_id):
            disabled_rule = rule_id
    if example:
        store.add_whitelist(normalize_variants(example)[0], note=f"marked safe{' for ' + rule_id if rule_id else ''}")
        # also store the squashed variant so obfuscation-normalized matches are whitelisted
        for v in normalize_variants(example):
            store.add_whitelist(v, note="marked safe")
    emit(make_event("marked_safe", session_id=f"acct:{account}" if account else "system", fingerprint=fp or "", attacker_ip=ip or "", channel="system", verdict="clean", risk=0, rule_id=rule_id,
                    payload=str(example or account or fp or ip or ""),
                    detail=f"false positive corrected (unbanned={removed}, disabled_rule={disabled_rule})"))
    return {"ok": True, "unbanned": removed, "disabled_rule": disabled_rule}


@app.get("/admin/rules", dependencies=[Depends(require_admin)])
async def admin_rules() -> list[dict[str, Any]]:
    return [r.to_dict() for r in engine.all_rules()]


@app.get("/admin/bans", dependencies=[Depends(require_admin)])
async def admin_bans() -> list[dict[str, Any]]:
    return store.list_bans()


@app.post("/admin/reset", dependencies=[Depends(require_admin)])
async def admin_reset() -> dict[str, Any]:
    store.reset()
    engine.learned = []
    engine.save_learned()
    engine.builtins = __import__("gateway.rules", fromlist=["builtin_rules"]).builtin_rules()
    return {"ok": True}


# Catch-all proxy is registered LAST so /healthz and every /admin/* route win over it.
app.add_api_route("/{full_path:path}", gateway,
                  methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"])
