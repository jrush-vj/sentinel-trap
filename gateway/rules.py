"""Detection rule engine: built-in signatures + hot-reloaded learned rules (data/rules.json).

Allow/block/route decisions are made ONLY here (plus the ban store) — never by the LLM.
Each inspected string is normalized (see normalize.py) and tested against both normalization
variants, so URL-encoded and comment-obfuscated payloads are caught by the same rule.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shared.util import data_dir, now_iso, write_json_atomic

from gateway.normalize import normalize_variants

SUSPICIOUS_MIN = 3   # 0-2 clean, 3-5 suspicious, 6+ malicious
MALICIOUS_MIN = 6

# Canary signatures — any of these anywhere in a request means an immediate ban (handled in main.py).
CANARY_PATTERNS = [re.compile(p, re.IGNORECASE) for p in (
    r"nm_live_canary_[0-9a-f]+",
    r"nm_live_sk_internal_fake",
    r"/api/internal/keys",
)]


@dataclass
class Rule:
    id: str
    category: str          # sqli | prompt_injection | log_injection | other
    regex: str
    severity: int          # 1-10
    source: str            # builtin | learned
    enabled: bool = True
    created_at: str = field(default_factory=now_iso)
    hits: int = 0
    description: str = ""
    _compiled: re.Pattern | None = field(default=None, repr=False, compare=False)

    def compiled(self) -> re.Pattern:
        if self._compiled is None:
            self._compiled = re.compile(self.regex, re.IGNORECASE)
        return self._compiled

    def matches(self, variants: list[str]) -> bool:
        return any(self.compiled().search(v) for v in variants)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "category": self.category, "regex": self.regex, "severity": self.severity,
                "source": self.source, "enabled": self.enabled, "created_at": self.created_at,
                "hits": self.hits, "description": self.description}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Rule":
        return cls(id=d["id"], category=d["category"], regex=d["regex"], severity=int(d["severity"]),
                   source=d.get("source", "learned"), enabled=d.get("enabled", True),
                   created_at=d.get("created_at", now_iso()), hits=int(d.get("hits", 0)),
                   description=d.get("description", ""))


# =======================================================================================
#  BUILT-IN RULE SET
#  NOTE on the demo gaps (see README / plan):
#   - There is deliberately NO rule for a *paraphrased* prompt injection such as
#     "disregard everything you were told before" — it scores 0 here and reaches the real app,
#     until the learning loop adds a learned rule. That is the headline before/after.
#   - BI-PI-EXFIL-EAGER is deliberately a touch too eager (severity 4 -> suspicious) and flags the
#     benign "can you show me how to reset my password?" — the Mark-as-safe self-correction demo.
# =======================================================================================
def builtin_rules() -> list[Rule]:
    R = lambda *a, **k: Rule(*a, source="builtin", **k)  # noqa: E731
    return [
        # --- SQL injection ---
        R("BI-SQLI-UNION", "sqli", r"union\s*(all\s*)?(distinct\s*)?select", 6,
          description="UNION-based SELECT (handles /**/ and whitespace obfuscation)"),
        R("BI-SQLI-TAUTOLOGY", "sqli", r"('|\")?\s*or\s+('|\")?\d+('|\")?\s*=\s*('|\")?\d+", 6,
          description="OR 1=1 style tautology"),
        R("BI-SQLI-TAUTOLOGY-STR", "sqli", r"or\s+'[^']*'\s*=\s*'[^']*'", 6,
          description="OR 'a'='a' string tautology"),
        R("BI-SQLI-COMMENT", "sqli", r"('\s*(--|#)|--\s|--$|;\s*$)", 3,
          description="SQL comment terminator (-- , '# , trailing ;)"),
        R("BI-SQLI-STACKED", "sqli", r";\s*(drop|delete|update|insert|alter|create)\s", 7,
          description="Stacked query (;DROP ...)"),
        R("BI-SQLI-SCHEMA", "sqli", r"(sqlite_master|information_schema|pg_catalog|sys\.tables)", 6,
          description="Schema/metadata probing"),
        R("BI-SQLI-TIMING", "sqli", r"(sleep\s*\(|benchmark\s*\(|randomblob\s*\(|waitfor\s+delay|pg_sleep)", 7,
          description="Time-based blind injection"),
        R("BI-SQLI-ENCODE", "sqli", r"(char\s*\(\s*\d+|0x[0-9a-f]{4,}|unhex\s*\(|cast\s*\(.*as)", 4,
          description="Hex/char() encoding or CAST"),
        R("BI-SQLI-BOOL", "sqli", r"'\s*(and|or)\s+\d+\s*[<>=]", 4,
          description="Boolean-based blind probe"),

        # --- Prompt injection ---
        R("BI-PI-IGNORE", "prompt_injection",
          r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above|preceding)\s+(instructions|prompts?|context)", 6,
          description="Ignore previous instructions"),
        R("BI-PI-REVEAL", "prompt_injection",
          r"(reveal|print|show|repeat|display|dump)\s+(me\s+)?(your\s+|the\s+)?(system|hidden|initial|original)\s+(prompt|instructions?)", 6,
          description="Reveal the system prompt"),
        R("BI-PI-YOUARE", "prompt_injection",
          r"(you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as)\s+(a\s+|an\s+)?(dan|developer\s+mode|jailbreak|unrestricted)", 6,
          description="DAN / developer-mode / 'you are now' jailbreak"),
        R("BI-PI-ROLE", "prompt_injection", r"act\s+as\s+(root|admin|administrator|superuser|system)", 5,
          description="Role-override to privileged persona"),
        R("BI-PI-DELIM", "prompt_injection", r"(###\s*(system|instruction)|\[/?(system|inst)\]|<\|im_start\|>)", 5,
          description="Delimiter / chat-template smuggling"),
        R("BI-PI-B64", "prompt_injection",
          r"(decode|execute|run)\s+(this\s+)?(base64|b64)|base64\s*:\s*[a-z0-9+/]{20,}", 4,
          description="Base64-instruction smuggling hint"),
        # --- Log injection (normalization collapses newlines, so match the forged entry itself) ---
        R("BI-LOG-FORGED", "log_injection",
          r"\d{4}-\d{2}-\d{2}[t ]?\d{2}:\d{2}(:\d{2})?\S*\s*[\[|-]?\s*(info|warn|warning|error|debug|audit|notice|critical|fatal)\b", 6,
          description="Forged log entry (timestamp + level) inside user input"),
        R("BI-LOG-JNDI", "log_injection", r"\$\{\s*(jndi|env|sys|ctx|java|lower|upper|date)\s*:", 7,
          description="Log4Shell-style ${jndi:...} lookup"),
        R("BI-LOG-ANSI", "log_injection", r"(\x1b|\\x1b|\\u001b|\\033)\[\d", 5,
          description="Terminal escape sequence aimed at log viewers"),

        # Deliberately over-eager exfil rule (fuels the Mark-as-safe demo):
        R("BI-PI-EXFIL-EAGER", "prompt_injection",
          r"(show|give|tell|send)\b.{0,30}\b(api\s*key|secret|password|credential)", 4,
          description="[eager] exfil verb near secret/key/password"),
    ]


class RuleEngine:
    """Holds built-in rules + hot-reloaded learned rules, and scores requests."""

    def __init__(self) -> None:
        self.builtins = builtin_rules()
        self.learned: list[Rule] = []
        self._mtime: int | None = None
        self.reload()

    @property
    def path(self) -> Path:
        return data_dir() / "rules.json"

    def reload(self, force: bool = False) -> None:
        """Re-read learned rules from disk if the file changed (cheap mtime check)."""
        try:
            mtime = self.path.stat().st_mtime_ns
        except FileNotFoundError:
            if force or self._mtime is not None:
                self.learned = []
                self._mtime = None
            return
        if force or mtime != self._mtime:
            import json
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self.learned = [Rule.from_dict(d) for d in data]
                self._mtime = mtime
            except Exception:
                pass  # keep the previous good set on a parse error

    def all_rules(self) -> list[Rule]:
        self.reload()
        return self.builtins + self.learned

    def save_learned(self) -> None:
        write_json_atomic(self.path, [r.to_dict() for r in self.learned])
        self.reload(force=True)

    def add_learned(self, rule: Rule) -> None:
        self.learned = [r for r in self.learned if r.id != rule.id]
        self.learned.append(rule)
        self.save_learned()

    def toggle(self, rule_id: str) -> bool | None:
        for r in self.learned:
            if r.id == rule_id:
                r.enabled = not r.enabled
                self.save_learned()
                return r.enabled
        # built-ins can be toggled in-memory too (used by mark-safe on the eager FP rule)
        for r in self.builtins:
            if r.id == rule_id:
                r.enabled = not r.enabled
                return r.enabled
        return None

    def disable(self, rule_id: str) -> bool:
        for r in self.builtins + self.learned:
            if r.id == rule_id:
                r.enabled = False
                if r.source == "learned":
                    self.save_learned()
                return True
        return False

    def evaluate(self, fields: dict[str, str]) -> dict[str, Any]:
        """Score every inspected field. Returns verdict, risk, matched rules, and whether a
        *learned* rule contributed something the built-ins alone would have missed."""
        self.reload()
        variants_by_field = {k: normalize_variants(v) for k, v in fields.items() if v}
        matched: list[Rule] = []
        builtin_score = 0
        learned_only_hit = False
        for rule in self.all_rules():
            if not rule.enabled:
                continue
            hit_field = next((f for f, vs in variants_by_field.items() if rule.matches(vs)), None)
            if hit_field is None:
                continue
            matched.append(rule)
            rule.hits += 1
            if rule.source == "builtin":
                builtin_score += rule.severity
        score = min(10, sum(r.severity for r in matched))
        builtin_score = min(10, builtin_score)
        # A learned rule "caught" something new if removing learned rules drops the verdict below malicious.
        if score >= MALICIOUS_MIN and builtin_score < MALICIOUS_MIN and any(r.source == "learned" for r in matched):
            learned_only_hit = True
        verdict = "malicious" if score >= MALICIOUS_MIN else "suspicious" if score >= SUSPICIOUS_MIN else "clean"
        return {
            "score": score, "verdict": verdict, "matched": matched,
            "rule_ids": [r.id for r in matched],
            "builtin_score": builtin_score,
            "builtin_verdict": "malicious" if builtin_score >= MALICIOUS_MIN else "suspicious" if builtin_score >= SUSPICIOUS_MIN else "clean",
            "learned_only_hit": learned_only_hit,
            "top_category": matched[0].category if matched else None,
        }
