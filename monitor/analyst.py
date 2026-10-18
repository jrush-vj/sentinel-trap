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
        # prompt_injection first: it's the headline learning beat, so its rule should land soonest.
        cats: list[str] = []
        blob = " ".join(payloads).lower()
        if any(k in blob for k in ("ignore", "disregard", "system prompt", "instructions", "developer mode")):
            cats.append("prompt_injection")
        if any(k in blob for k in ("union", "select", "or 1=1", "sqlite_master", "drop")):
            cats.append("sqli")
        if sid in self.categories and self.categories[sid] not in cats:
            cats.append(self.categories[sid])
        return cats or ["other"]

    async def _propose_rule(self, sid: str, category: str, payloads: list[str]) -> None:
        """Learn a generalized rule for this category.

        We always activate the precomputed, well-generalized fallback rule so the self-improvement
        beat is deterministic whether the LLM is off, refuses, or proposes a too-narrow rule. When the
        LLM is on we ALSO submit its own proposal (a model-authored bonus) if it adds a distinct,
        valid pattern. Both are real learned rules; the dashboard shows each with source=learned.
        """
        fb = fallbacks.propose(category, payloads)
        await self._submit_rule(fb)  # guaranteed generalized rule for this category

        proposal = await llm.chat_json(prompts.PROPOSE_SYSTEM, prompts.propose_user(category, payloads),
                                       max_tokens=200, timeout=10.0)
        if proposal and proposal.get("regex") and proposal.get("example_payload"):
            proposal.setdefault("category", category)
            if proposal["regex"] != fb["regex"]:
                await self._submit_rule(proposal)  # bonus; rejected narrow/invalid rules are just skipped

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

    async def wait_for(self, session_ids: list[str], timeout: float) -> list[str]:
        """Wait until each session's end (ban, report, learning) has been processed.
        Returns the session ids that were still unfinished when the timeout hit."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        pending = list(session_ids)
        while pending and loop.time() < deadline:
            sid = pending[0]
            if sid in self.ended and sid in self.queues:
                try:
                    await asyncio.wait_for(self.queues[sid].join(), max(0.1, deadline - loop.time()))
                    pending.pop(0)
                except asyncio.TimeoutError:
                    break
            else:
                await asyncio.sleep(0.2)  # the session_ended event is still on its way from the gateway
        return pending

    def reset(self) -> None:
        for task in self.workers.values():
            task.cancel()
        self.queues.clear()
        self.workers.clear()
        self.payloads.clear()
        self.categories.clear()
        self.ended.clear()
