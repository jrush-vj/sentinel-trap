"""Monitor: event ingest, WebSocket broadcast, read APIs, LLM settings and the dashboard (:9000)."""
from __future__ import annotations

import logging
import mimetypes
from pathlib import Path
from typing import Any

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from monitor import db, report
from monitor.analyst import Analyst
from monitor.hub import hub
from monitor.mock import MockRunner
from shared import llm
from shared.util import env_int, env_str

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("monitor")

STATIC = Path(__file__).parent / "static"
mimetypes.add_type("font/woff2", ".woff2")  # slim images lack it; browsers expect a font type
GATEWAY_URL = env_str("GATEWAY_URL", "http://gateway:8080").rstrip("/")
ADMIN_TOKEN = env_str("ADMIN_TOKEN", "dev-admin-token")
MAX_ACTIONS = env_int("MAX_HONEYPOT_ACTIONS", 8)

TRAP_ACTIONS = {"routed_to_honeypot", "honeypot_interaction", "canary_hit", "session_ended", "banned", "blocked"}

app = FastAPI(title="SENTINEL-TRAP monitor", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


analyst = Analyst(hub.broadcast, GATEWAY_URL, ADMIN_TOKEN)


async def ingest(event: dict[str, Any]) -> None:
    """Store, broadcast, and hand to the analyst. Shared by POST /events and the mock runner."""
    db.insert_event(event)
    await hub.broadcast({"type": "event", "event": event})
    analyst.handle(event)  # async commentary/report/learning (never blocks the request path)


mock = MockRunner(ingest)


def require_admin(authorization: str = Header(default=""), x_admin_token: str = Header(default="")) -> None:
    token = x_admin_token or authorization.removeprefix("Bearer ").strip()
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="admin token required")


async def gateway_admin(method: str, path: str, json: Any = None) -> Any:
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.request(method, f"{GATEWAY_URL}{path}", json=json,
                                    headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    resp.raise_for_status()
    return resp.json()


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.post("/events")
async def post_events(request: Request) -> dict[str, int]:
    body = await request.json()
    events = body if isinstance(body, list) else [body]
    accepted = 0
    for event in events:
        if isinstance(event, dict) and event.get("id") and event.get("action"):
            await ingest(event)
            accepted += 1
    return {"accepted": accepted}


@app.websocket("/ws")
async def ws(websocket: WebSocket) -> None:
    await hub.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # dashboards don't send; this just detects disconnects
    except WebSocketDisconnect:
        hub.disconnect(websocket)


@app.get("/api/events")
async def api_events(limit: int = 200, action: str | None = None) -> list[dict[str, Any]]:
    return db.recent_events(min(limit, 1000), action)


@app.get("/api/analyses")
async def api_analyses(limit: int = 60) -> list[dict[str, Any]]:
    """Recent analyst output (commentary + reports) so a late-loading dashboard isn't blank."""
    return db.recent_analyses(min(limit, 200))


def build_sessions(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group trap-related events into per-attacker honeypot sessions (oldest event first)."""
    sessions: dict[str, dict[str, Any]] = {}
    marked_safe = {e["fingerprint"]: e["ts"] for e in sorted(events, key=lambda e: e["ts"])
                   if e["action"] == "marked_safe" and e.get("fingerprint")}
    for event in sorted(events, key=lambda e: e["ts"]):
        if event["action"] not in TRAP_ACTIONS:
            continue
        sid = event["session_id"]
        if event["action"] == "blocked" and sid not in sessions:
            continue  # blocks of already-banned visitors are not new sessions
        s = sessions.setdefault(sid, {
            "session_id": sid, "fingerprint": event["fingerprint"], "attacker_ip": event["attacker_ip"],
            "started": event["ts"], "status": "trapped", "actions": 0, "max_actions": MAX_ACTIONS,
            "risk": 0, "canary": False, "rule_ids": [], "timeline": [],
        })
        s["last"] = event["ts"]
        s["risk"] = max(s["risk"], event.get("risk") or 0)
        if event.get("rule_id") and event["rule_id"] not in s["rule_ids"]:
            s["rule_ids"].append(event["rule_id"])
        if event["action"] in {"routed_to_honeypot", "honeypot_interaction"}:
            s["actions"] = (event.get("extra") or {}).get("actions", s["actions"] + 1)
        if event["action"] == "canary_hit":
            s["canary"] = True
        if event["action"] in {"session_ended", "banned"}:
            s["status"] = "banned" if event["action"] == "banned" else "ended"
        s["timeline"].append({k: event.get(k) for k in ("id", "ts", "action", "channel", "payload", "risk", "detail", "rule_id")})
    for s in sessions.values():
        if marked_safe.get(s["fingerprint"], "") >= s["last"]:  # cleared after its last trap event
            s["status"] = "safe"  # an operator corrected this false positive
    return sorted(sessions.values(), key=lambda s: s["last"], reverse=True)


@app.get("/api/sessions")
async def api_sessions() -> list[dict[str, Any]]:
    return build_sessions(db.recent_events(2000))


@app.get("/api/stats")
async def api_stats() -> dict[str, Any]:
    counts = db.action_counts()
    gateway_requests = sum(counts.get(a, 0) for a in
                           ("request", "routed_to_honeypot", "honeypot_interaction", "blocked", "canary_hit"))
    return {
        "requests": gateway_requests,
        "attacks_detected": sum(counts.get(a, 0) for a in ("routed_to_honeypot", "honeypot_interaction", "canary_hit")),
        "attackers_trapped": db.distinct_count("routed_to_honeypot"),
        "attackers_banned": db.distinct_count("banned"),
        "rules_learned": counts.get("rule_learned", 0),
        "false_positives_fixed": counts.get("marked_safe", 0),
        "blocked": counts.get("blocked", 0),
        "learned_catches": counts.get("learned_rule_caught", 0),
        "by_action": counts,
    }


@app.get("/api/rules")
async def api_rules() -> list[dict[str, Any]]:
    try:
        return await gateway_admin("GET", "/admin/rules")
    except Exception as exc:
        log.info("gateway rules unavailable: %s", exc)
        return []


@app.get("/api/bans")
async def api_bans() -> list[dict[str, Any]]:
    try:
        return await gateway_admin("GET", "/admin/bans")
    except Exception as exc:
        log.info("gateway bans unavailable: %s", exc)
        return []


@app.post("/api/rules/{rule_id}/toggle", dependencies=[Depends(require_admin)])
async def api_rule_toggle(rule_id: str) -> Any:
    return await gateway_admin("POST", f"/admin/rules/{rule_id}/toggle")


@app.post("/api/mark-safe", dependencies=[Depends(require_admin)])
async def api_mark_safe(body: dict[str, Any]) -> Any:
    return await gateway_admin("POST", "/admin/mark-safe", body)


@app.get("/api/data-contrast")
async def api_data_contrast(limit: int = 8) -> list[dict[str, Any]]:
    """What trapped attackers received from the honeypot, next to the masked real data."""
    return report.data_contrast(min(limit, 30))


@app.get("/api/final-report")
async def api_final_report() -> dict[str, Any]:
    return await report.final_report(build_sessions(db.recent_events(2000)), await api_stats(), gateway_admin)


@app.post("/api/ban-all", dependencies=[Depends(require_admin)])
async def api_ban_all() -> dict[str, Any]:
    """Eject every attacker still in the honeypot, ban them, wait for their reports and learned
    rules, then return the final report."""
    try:
        result = await gateway_admin("POST", "/admin/end-all", {"reason": "operator: ban all and final report"})
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"gateway unreachable: {exc}") from exc
    ended = result.get("ended", [])
    unfinished = await analyst.wait_for(ended, timeout=45.0)
    final = await api_final_report()
    final.update(ended_now=ended, unfinished=unfinished)
    await hub.broadcast({"type": "final_report", "generated_at": final["generated_at"], "ended_now": ended})
    return final


@app.post("/api/reset", dependencies=[Depends(require_admin)])
async def api_reset() -> dict[str, Any]:
    mock.stop()
    gateway_result: Any = "unreachable"
    try:
        gateway_result = await gateway_admin("POST", "/admin/reset")
    except Exception as exc:
        log.warning("gateway reset failed: %s", exc)
    db.reset()
    analyst.reset()
    await hub.broadcast({"type": "reset"})
    return {"ok": True, "gateway": gateway_result}


@app.get("/api/llm/status")
async def api_llm_status() -> dict[str, Any]:
    return llm.status()


@app.get("/api/llm/config")
async def api_llm_config() -> dict[str, Any]:
    return llm.public_config()


@app.post("/api/llm/config", dependencies=[Depends(require_admin)])
async def api_llm_config_save(body: dict[str, Any]) -> dict[str, Any]:
    cfg = llm.save_config(body)
    await hub.broadcast({"type": "llm", "status": llm.status()})
    return llm.public_config(cfg)


@app.post("/api/llm/test", dependencies=[Depends(require_admin)])
async def api_llm_test() -> dict[str, Any]:
    result = await llm.test_connection()
    await hub.broadcast({"type": "llm", "status": llm.status()})
    return result


@app.post("/mock/start")
async def mock_start() -> dict[str, bool]:
    mock.start()
    return {"running": True}


@app.post("/mock/stop")
async def mock_stop() -> dict[str, bool]:
    mock.stop()
    return {"running": False}
