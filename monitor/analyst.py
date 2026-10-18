"""Async analyst + learning orchestrator.

One in-order queue/worker per attacker session, so commentary for a session streams in order.
The LLM is used only as an ASYNC analyst (commentary, report, rule proposal) — never in the
attacker's request path. Every LLM call has a timeout + canned fallback tagged "offline analyst".

On session_ended the orchestrator: bans the attacker (via the gateway), writes a report, then
proposes a generalized rule per category and submits it to the gateway for validation+activation.
If the LLM is down, deterministic fallbacks keep the whole loop working.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable

import httpx

from monitor import db, fallbacks, prompts
from shared import llm
from shared.util import now_iso

log = logging.getLogger("analyst")

Broadcast = Callable[[dict[str, Any]], Awaitable[None]]

COMMENTARY_ACTIONS = {"routed_to_honeypot", "honeypot_interaction", "canary_hit", "blocked", "learned_rule_caught"}


class Analyst:
    def __init__(self, broadcast: Broadcast, gateway_url: str, admin_token: str) -> None:
        self.broadcast = broadcast
        self.gateway_url = gateway_url.rstrip("/")
        self.admin_token = admin_token
        self.queues: dict[str, asyncio.Queue] = {}
        self.workers: dict[str, asyncio.Task] = {}
        self.payloads: dict[str, list[str]] = {}
        self.categories: dict[str, str] = {}
        self.ended: set[str] = set()

    # ---- ingest hook: called by the monitor for every event ----
    def handle(self, event: dict[str, Any]) -> None:
        action = event.get("action")
        sid = event.get("session_id") or "system"
        if action in COMMENTARY_ACTIONS or action == "session_ended":
            if event.get("payload"):
                self.payloads.setdefault(sid, []).append(event["payload"])
            cat = (event.get("extra") or {}).get("category")
            if cat:
                self.categories[sid] = cat
            self._enqueue(sid, event)

    def _enqueue(self, sid: str, event: dict[str, Any]) -> None:
        if sid not in self.queues:
            self.queues[sid] = asyncio.Queue()
            self.workers[sid] = asyncio.create_task(self._worker(sid))
        self.queues[sid].put_nowait(event)

    async def _worker(self, sid: str) -> None:
        queue = self.queues[sid]
        while True:
            event = await queue.get()
            try:
                if event["action"] == "session_ended":
                    await self._on_session_ended(sid, event)
                elif event["action"] in COMMENTARY_ACTIONS:
                    await self._commentary(sid, event)
            except Exception as exc:
                log.warning("analyst worker error (%s): %s", sid, exc)
            finally:
                queue.task_done()

    # ---- commentary ----
    async def _commentary(self, sid: str, event: dict[str, Any]) -> None:
        payload = event.get("payload", "")
        data = await llm.chat_json(
            prompts.COMMENTARY_SYSTEM,
            prompts.commentary_user(event["action"], event.get("channel", "web"), payload),
            max_tokens=120, timeout=8.0,
        )
        if data and isinstance(data.get("commentary"), str):
            data["source"] = "llm"
            data.setdefault("risk", event.get("risk", 6))
        else:
            data = fallbacks.commentary(event["action"], payload, event.get("risk", 6))
        msg = {"type": "analysis", "session_id": sid, "event_id": event.get("id"), "ts": now_iso(), **data}
        db.insert_analysis("commentary", sid, event.get("id"), data["source"], data, msg["ts"])
        await self.broadcast(msg)

    # ---- session end: ban -> report -> learn ----
    async def _on_session_ended(self, sid: str, event: dict[str, Any]) -> None:
        if sid in self.ended:
            return
        self.ended.add(sid)
        fp = event.get("fingerprint", "")
        ip = event.get("attacker_ip", "")
        payloads = self.payloads.get(sid, [])
        risk = event.get("risk", 8)

        # 1) ensure banned (gateway is the source of truth; canary path may have banned already)
        await self._gateway("POST", "/admin/ban",
                            {"fingerprint": fp, "ip": ip, "session_id": sid,
                             "reason": event.get("detail", "honeypot session ended")})

        # 2) report
        report = await llm.chat_json(prompts.REPORT_SYSTEM, prompts.report_user(ip, fp, payloads),
                                     max_tokens=350, timeout=10.0)
        if report and isinstance(report.get("summary"), str):
            report["source"] = "llm"
        else:
            report = fallbacks.report(ip, fp, payloads, risk)
        report.update({"type": "report", "session_id": sid, "fingerprint": fp, "attacker_ip": ip, "ts": now_iso()})
        db.insert_analysis("report", sid, None, report["source"], report, report["ts"])
        await self.broadcast(report)

        # 3) learn: propose a generalized rule per category seen, submit for validation
        cats = self._categories_for(sid, payloads)
        for cat in cats:
            await self._propose_rule(sid, cat, payloads)

    def _categories_for(self, sid: str, payloads: list[str]) -> list[str]:
        cats: list[str] = []
        if sid in self.categories:
            cats.append(self.categories[sid])
        blob = " ".join(payloads).lower()
        if "sqli" not in cats and any(k in blob for k in ("union", "select", "or 1=1", "sqlite_master", "drop")):
            cats.append("sqli")
        if "prompt_injection" not in cats and any(k in blob for k in ("ignore", "disregard", "system prompt", "instructions")):
            cats.append("prompt_injection")
        return cats or ["other"]

    async def _propose_rule(self, sid: str, category: str, payloads: list[str]) -> None:
        """Ask the LLM for a generalized rule; on LLM miss or gateway rejection, use the fallback."""
        proposal = await llm.chat_json(prompts.PROPOSE_SYSTEM, prompts.propose_user(category, payloads),
                                       max_tokens=200, timeout=10.0)
        source = "llm"
        if not (proposal and proposal.get("regex") and proposal.get("example_payload")):
            proposal, source = fallbacks.propose(category, payloads), "offline"
        proposal.setdefault("category", category)

        result = await self._submit_rule(proposal)
        # If the LLM's rule was rejected, fall back to the precomputed proposal so learning still lands.
        if result is not None and not result.get("accepted") and source == "llm":
            fb = fallbacks.propose(category, payloads)
            log.info("LLM rule rejected (%s); trying offline fallback", result.get("reason"))
            await self._submit_rule(fb)

    async def _submit_rule(self, proposal: dict[str, Any]) -> dict[str, Any] | None:
        return await self._gateway("POST", "/admin/rules/propose", {
            "category": proposal.get("category", "other"),
            "regex": proposal.get("regex", ""),
            "example_payload": proposal.get("example_payload", ""),
            "reasoning": proposal.get("reasoning", ""),
        })

    async def _gateway(self, method: str, path: str, json: Any = None) -> dict[str, Any] | None:
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.request(method, f"{self.gateway_url}{path}", json=json,
                                            headers={"Authorization": f"Bearer {self.admin_token}"})
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:
            log.warning("gateway call %s %s failed: %s", method, path, exc)
            return None

    def reset(self) -> None:
        for task in self.workers.values():
            task.cancel()
        self.queues.clear()
        self.workers.clear()
        self.payloads.clear()
        self.categories.clear()
        self.ended.clear()
