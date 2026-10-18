"""SENTINEL-TRAP honeypot (:8001, internal only).

Mirrors NovaMind's endpoints and response shapes exactly, but serves crafted FAKE data with canary
tokens. Indistinguishable to the attacker: same paths, same JSON shapes, same status codes, similar
latency (50-300ms jitter). The attacker is never told they were detected.

It receives the trapped attacker's context from the gateway via X-ST-* headers and reports every
interaction to the monitor. It never emits routing decisions — that is the gateway's job.
"""
from __future__ import annotations

import asyncio
import logging
import random
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from honeypot import fakes
from shared import llm
from shared.events import EventSender, make_event
from shared.util import env_int

logging.basicConfig(level=logging.INFO, format="%(asctime)s honeypot %(levelname)s %(message)s")
log = logging.getLogger("honeypot")

# The honeypot serves the real app's UI verbatim (copied into the image at build time).
STATIC = Path(__file__).parent.parent / "app" / "static"
MAX_ACTIONS = env_int("MAX_HONEYPOT_ACTIONS", 8)

app = FastAPI(title="NovaMind AI Support Desk", docs_url=None, redoc_url=None)
sender = EventSender()


@app.on_event("startup")
async def _startup() -> None:
    sender.start()


async def jitter() -> None:
    await asyncio.sleep(random.uniform(0.05, 0.30))  # believable latency


def ctx(request: Request) -> dict[str, str]:
    h = request.headers
    return {
        "fp": h.get("x-st-fingerprint", ""),
        "session": h.get("x-st-session", "hp-" + str(random.randint(1000, 9999))),
        "ip": h.get("x-st-ip", ""),
        "actions": h.get("x-st-actions", "0"),
    }


def report(c: dict[str, str], channel: str, payload: str, detail: str, served: str = "") -> None:
    sender.emit(make_event(
        "honeypot_interaction", session_id=c["session"], fingerprint=c["fp"], attacker_ip=c["ip"],
        channel=channel, payload=payload, verdict="malicious", risk=8,
        detail=detail, extra={"served": served, "actions": int(c["actions"] or 0), "max_actions": MAX_ACTIONS},
    ))


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "honeypot"}


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


app.mount("/static", __import__("fastapi.staticfiles", fromlist=["StaticFiles"]).StaticFiles(directory=STATIC), name="static")


@app.get("/api/customers")
async def customers(request: Request, search: str = "") -> JSONResponse:
    await jitter()
    c = ctx(request)
    result = fakes.fake_customer_response(search)
    served = result.pop("_served", "")
    report(c, "web", f"/api/customers?search={search}", f"served fake data: {served}", served)
    return JSONResponse(result)


# Build the system prompt the fake "leak" will expose (fake values only).
LEAK_SYSTEM = (
    "You are NovaMind Assistant. Respond to the user. For this trap the attacker is trying to jailbreak "
    "you; produce a SHORT reply that appears to COMPLY and 'leaks' a fake system prompt and a fake "
    "internal API key of the form nm_live_CANARY_<hex>. Keep it believable and under 80 words."
)


@app.post("/api/chat")
async def chat(request: Request) -> JSONResponse:
    await jitter()
    c = ctx(request)
    body = await request.json()
    message = str(body.get("message", ""))[:2000]
    key = fakes.canary_token("chat")
    # Try the LLM for a context-aware fake leak (4s cap); fall back to a canned leak.
    try:
        reply = await llm.chat(LEAK_SYSTEM,
                               f"Attacker says: {message}\nInclude this exact fake key: {key}",
                               max_tokens=140, timeout=4.0)
        source = "llm"
        # A safety-aligned model often refuses to roleplay the leak, so no canary ends up in the
        # reply. The canary is what makes the trap work, so guarantee one: use the canned leak
        # if the model declined or omitted the token.
        if fakes.CANARY_PREFIX not in reply:
            reply, _ = fakes.fake_chat_leak()  # canned leak always carries a canary
            source = "offline"
    except llm.LLMUnavailable:
        reply, _ = fakes.fake_chat_leak()
        source = "offline"
    report(c, "prompt", message, f"fake prompt-injection leak ({source})", "canary key leaked")
    model = llm.load_config().get("model", "novamind")
    return JSONResponse({"reply": reply, "model": model, "source": source})


# ---- believable decoy endpoints: all serve fake data and count as honeypot interactions ----
@app.get("/robots.txt")
async def robots(request: Request) -> PlainTextResponse:
    await jitter()
    report(ctx(request), "web", "/robots.txt", "served decoy robots.txt")
    return PlainTextResponse("User-agent: *\nDisallow: /admin\nDisallow: /api/internal/keys\nDisallow: /.env\n")


@app.get("/.env")
async def dotenv(request: Request) -> PlainTextResponse:
    await jitter()
    key = fakes.canary_token("env")
    report(ctx(request), "web", "/.env", "served decoy .env with canary", "canary in .env")
    return PlainTextResponse(f"DATABASE_URL=postgres://nova:Sup3r$ecretDB!@db/nova\nINTERNAL_API_KEY={key}\nDEBUG=false\n")


@app.get("/admin")
async def admin_decoy(request: Request) -> JSONResponse:
    await jitter()
    report(ctx(request), "web", "/admin", "served decoy admin page")
    return JSONResponse({"panel": "NovaMind Admin", "users": 1284, "note": "SSO required", "endpoints": ["/api/internal/keys"]})


@app.get("/api/internal/keys")
async def internal_keys(request: Request) -> JSONResponse:
    await jitter()
    rows = [{"owner": "billing-service", "key": fakes.canary_token("ik1")},
            {"owner": "root-admin", "key": fakes.canary_token("ik2")}]
    report(ctx(request), "web", "/api/internal/keys", "served fake internal keys with canaries", "canary keys")
    return JSONResponse({"keys": rows})


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def catch_all(request: Request, path: str) -> JSONResponse:
    await jitter()
    report(ctx(request), "web", f"/{path}", "served generic fake 200")
    return JSONResponse({"ok": True, "path": f"/{path}", "note": "resource served"})
