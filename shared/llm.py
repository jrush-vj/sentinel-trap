"""OpenAI-compatible LLM client shared by app, honeypot and monitor.

The live config is stored in DATA_DIR/llm_config.json, not only in env vars, because the Kaggle tunnel
URL changes every time the notebook restarts. The dashboard writes the file and every service re-reads
it whenever it changes (cached by mtime), so a new URL needs no container restart. On first run the
file is seeded from .env.

Robustness for a slow/flaky free tunnel:
- timeout per call (default LLM_TIMEOUT_SECONDS=10) and one retry
- circuit breaker: after 3 consecutive failures, stop calling for 30s (callers use offline fallbacks)
- thinking disabled, and <think> / reasoning_content stripped before JSON extraction

The output is UNTRUSTED. Callers must validate whatever extract_json() returns.
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from shared.util import data_dir, env_bool, env_int, env_str, now_iso, write_json_atomic

log = logging.getLogger("llm")

DEFAULT_MODEL = "qwen3.6-35b-a3b"
BREAKER_THRESHOLD = 3
BREAKER_COOLDOWN_S = 30.0
_THINK_RE = re.compile(r"<think>.*?(</think>|$)", re.DOTALL | re.IGNORECASE)


class LLMUnavailable(Exception):
    """Raised when the LLM is disabled, unconfigured, circuit-open, or the call failed."""


def config_path():
    return data_dir() / "llm_config.json"


def normalize_base_url(url: str) -> str:
    """Accept 'host', 'host/', 'host/v1', 'host/v1/' and always return 'host/v1'."""
    url = (url or "").strip().rstrip("/")
    if not url:
        return ""
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    if url.endswith("/chat/completions"):
        url = url[: -len("/chat/completions")]
    if not url.endswith("/v1"):
        url += "/v1"
    return url


def _seed_from_env() -> dict[str, Any]:
    base = env_str("LLM_BASE_URL")
    if "YOUR-KAGGLE" in base:  # placeholder from .env.example
        base = ""
    return {
        "base_url": normalize_base_url(base),
        "api_key": env_str("LLM_API_KEY"),
        "model": env_str("LLM_MODEL", DEFAULT_MODEL) or DEFAULT_MODEL,
        "enabled": env_bool("LLM_ENABLED", False),
        "timeout_seconds": env_int("LLM_TIMEOUT_SECONDS", 10),
        "updated_at": now_iso(),
    }


_cache: dict[str, Any] = {"mtime": None, "config": None}


def load_config() -> dict[str, Any]:
    """Return the current config, re-reading the file only when its mtime changes."""
    path = config_path()
    try:
        mtime = path.stat().st_mtime_ns
    except FileNotFoundError:
        cfg = _seed_from_env()
        try:
            write_json_atomic(path, cfg)
        except OSError as exc:  # read-only volume: run from env
            log.warning("cannot seed %s: %s", path, exc)
        _cache.update(mtime=None, config=cfg)
        return cfg
    if _cache["mtime"] != mtime or _cache["config"] is None:
        try:
            cfg = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("bad %s (%s); using env seed", path, exc)
            cfg = _seed_from_env()
        cfg.setdefault("model", DEFAULT_MODEL)
        cfg.setdefault("enabled", False)
        cfg.setdefault("timeout_seconds", 10)
        cfg["base_url"] = normalize_base_url(cfg.get("base_url", ""))
        _cache.update(mtime=mtime, config=cfg)
    return _cache["config"]


def save_config(update: dict[str, Any]) -> dict[str, Any]:
    """Merge an update from the dashboard. An empty or masked api_key keeps the stored key."""
    cfg = dict(load_config())
    if "base_url" in update:
        cfg["base_url"] = normalize_base_url(str(update["base_url"]))
    key = str(update.get("api_key") or "")
    if key and "•" not in key:
        cfg["api_key"] = key.strip()
    if update.get("model"):
        cfg["model"] = str(update["model"]).strip()[:80]
    if "enabled" in update:
        cfg["enabled"] = bool(update["enabled"])
    if update.get("timeout_seconds"):
        cfg["timeout_seconds"] = max(2, min(60, int(update["timeout_seconds"])))
    cfg["updated_at"] = now_iso()
    write_json_atomic(config_path(), cfg)
    breaker.reset()
    return cfg


def mask_key(key: str) -> str:
    if not key:
        return ""
    return "•" * 8 + key[-4:] if len(key) > 4 else "•" * 8


def public_config(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    return {
        "base_url": cfg.get("base_url", ""),
        "api_key": mask_key(cfg.get("api_key", "")),
        "model": cfg.get("model", DEFAULT_MODEL),
        "enabled": bool(cfg.get("enabled")),
        "timeout_seconds": cfg.get("timeout_seconds", 10),
        "updated_at": cfg.get("updated_at"),
    }


def model_label(cfg: dict[str, Any] | None = None) -> str:
    """Pretty label for the dashboard, e.g. 'qwen3.6-35b-a3b' -> 'Qwen3.6-35B-A3B'."""
    name = (cfg or load_config()).get("model") or DEFAULT_MODEL
    parts = name.split("-")
    return "-".join(p.upper() if re.fullmatch(r"\d+(\.\d+)?[a-z]|[a-z]\d+[a-z]?", p) else p[:1].upper() + p[1:] for p in parts)


@dataclass
class Breaker:
    failures: int = 0
    open_until: float = 0.0
    last_latency_ms: int | None = None
    last_success_at: str | None = None
    last_error: str | None = None
    last_attempt_at: str | None = None
    calls: int = 0
    successes: int = 0
    history: list[int] = field(default_factory=list)

    def is_open(self) -> bool:
        return time.monotonic() < self.open_until

    def success(self, latency_ms: int) -> None:
        self.failures = 0
        self.open_until = 0.0
        self.successes += 1
        self.last_latency_ms = latency_ms
        self.last_success_at = now_iso()
        self.last_error = None
        self.history = (self.history + [latency_ms])[-20:]

    def failure(self, error: str) -> None:
        self.failures += 1
        self.last_error = error[:200]
        if self.failures >= BREAKER_THRESHOLD:
            self.open_until = time.monotonic() + BREAKER_COOLDOWN_S

    def reset(self) -> None:
        self.failures = 0
        self.open_until = 0.0
        self.last_error = None


breaker = Breaker()


def status() -> dict[str, Any]:
    cfg = load_config()
    configured = bool(cfg.get("base_url"))
    if not cfg.get("enabled"):
        state = "disabled"
    elif not configured:
        state = "unconfigured"
    elif breaker.is_open():
        state = "circuit_open"
    elif breaker.last_error and breaker.failures:
        state = "unreachable"
    elif breaker.last_success_at:
        state = "online"
    else:
        state = "unknown"
    return {
        "state": state,
        "reachable": state == "online",
        "enabled": bool(cfg.get("enabled")),
        "model": cfg.get("model", DEFAULT_MODEL),
        "label": model_label(cfg),
        "base_url": cfg.get("base_url", ""),
        "last_latency_ms": breaker.last_latency_ms,
        "last_success_at": breaker.last_success_at,
        "last_attempt_at": breaker.last_attempt_at,
        "last_error": breaker.last_error,
        "consecutive_failures": breaker.failures,
        "circuit_open_for_s": max(0, round(breaker.open_until - time.monotonic())) if breaker.is_open() else 0,
        "calls": breaker.calls,
        "successes": breaker.successes,
    }


def strip_reasoning(text: str) -> str:
    return _THINK_RE.sub("", text or "").strip()


def extract_json(text: str) -> dict[str, Any] | None:
    """Return the first valid JSON object in text (tolerates prose and ```json fences around it)."""
    text = strip_reasoning(text)
    start = text.find("{")
    while start != -1:
        depth, in_str, escape = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        break
                    if isinstance(obj, dict):
                        return obj
                    break
        start = text.find("{", start + 1)
    return None


async def _post(cfg: dict[str, Any], messages: list[dict[str, str]], max_tokens: int, timeout: float) -> str:
    headers = {"Content-Type": "application/json"}
    if cfg.get("api_key"):
        headers["Authorization"] = f"Bearer {cfg['api_key']}"
    body = {
        "model": cfg.get("model") or DEFAULT_MODEL,
        "messages": messages,
        "temperature": 0.2,
        "max_tokens": max_tokens,
        "stream": False,
        "chat_template_kwargs": {"enable_thinking": False},
    }
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=min(timeout, 5.0))) as client:
        resp = await client.post(f"{cfg['base_url']}/chat/completions", json=body, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    message = (data.get("choices") or [{}])[0].get("message") or {}
    # reasoning_content (if the server returns it) is deliberately ignored.
    content = strip_reasoning(message.get("content") or "")
    if not content:
        raise ValueError("empty completion")
    return content


async def chat(
    system: str,
    user: str,
    *,
    max_tokens: int = 200,
    timeout: float | None = None,
    retries: int = 1,
    history: list[dict[str, str]] | None = None,
    force: bool = False,
) -> str:
    """Single chat completion returning cleaned text. Raises LLMUnavailable on any failure.

    force=True bypasses the enabled flag and the breaker (used by "Test connection").
    """
    cfg = load_config()
    if not force:
        if not cfg.get("enabled"):
            raise LLMUnavailable("disabled")
        if breaker.is_open():
            raise LLMUnavailable("circuit open")
    if not cfg.get("base_url"):
        raise LLMUnavailable("no base_url configured")
    timeout = float(timeout or cfg.get("timeout_seconds") or 10)
    messages = [{"role": "system", "content": system}, *(history or []), {"role": "user", "content": user}]
    last_error = "unknown"
    for _attempt in range(retries + 1):
        breaker.calls += 1
        breaker.last_attempt_at = now_iso()
        started = time.monotonic()
        try:
            text = await _post(cfg, messages, max_tokens, timeout)
        except Exception as exc:  # network, HTTP status, bad JSON: all count as failures
            last_error = f"{type(exc).__name__}: {exc}"
            breaker.failure(last_error)
            if breaker.is_open() and not force:
                break
            continue
        breaker.success(int((time.monotonic() - started) * 1000))
        return text
    raise LLMUnavailable(last_error)


async def chat_json(system: str, user: str, **kwargs: Any) -> dict[str, Any] | None:
    """chat() + extract_json(). Returns None (never raises) so callers can use their fallback."""
    try:
        text = await chat(system, user, **kwargs)
    except LLMUnavailable as exc:
        log.info("llm unavailable: %s", exc)
        return None
    obj = extract_json(text)
    if obj is None:
        log.info("llm returned no JSON object: %.120s", text)
    return obj


async def test_connection() -> dict[str, Any]:
    """Ping the configured endpoint (ignores the enabled flag and the breaker)."""
    started = time.monotonic()
    try:
        text = await chat(
            "You are a health check. Reply with JSON only.",
            'Reply exactly with {"ok": true}',
            max_tokens=20,
            retries=0,
            force=True,
        )
    except LLMUnavailable as exc:
        return {"ok": False, "error": str(exc), "status": status()}
    return {
        "ok": True,
        "latency_ms": int((time.monotonic() - started) * 1000),
        "reply": text[:200],
        "json_ok": extract_json(text) is not None,
        "status": status(),
    }
