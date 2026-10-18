"""Validation for LLM/offline-proposed rules. LLM output is untrusted and NEVER executed.

A proposal is accepted only if ALL checks pass:
  a) regex compiles, length < 300, no catastrophic-backtracking shape (nested quantifiers),
     and does not match the empty string; every test runs in a worker process under a 50ms budget
     so a pathological pattern can never hang the gateway.
  b) it MUST match the example_payload that produced it (normalized).
  c) it MUST NOT match any entry in the benign clean corpus.
  d) it must not be overly broad: no matching >2% of the corpus, and no matching a benign 3-word probe.
"""
from __future__ import annotations

import re
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass

from gateway.clean_corpus import BENIGN_WORD_PROBES, CLEAN_CORPUS
from gateway.normalize import normalize_variants

MAX_LEN = 300
MATCH_BUDGET_S = 0.05
CORPUS_MAX_FRACTION = 0.02
# Nested quantifiers like (a+)+ , (a*)* , (a+)* , grouping followed by a quantifier that wraps a quantifier.
NESTED_QUANTIFIER = re.compile(r"\([^()]*[+*][^()]*\)\s*[+*{]")
VALID_CATEGORIES = {"sqli", "prompt_injection", "other"}


@dataclass
class ValidationResult:
    accepted: bool
    reason: str


def _match_worker(pattern: str, text: str) -> bool:
    return bool(re.compile(pattern, re.IGNORECASE).search(text))


# A single pre-warmed worker process. Reusing it means we measure only the regex match time,
# not interpreter startup (~100ms), so the 50ms budget actually bounds backtracking.
_pool: ProcessPoolExecutor | None = None


def _get_pool() -> ProcessPoolExecutor:
    global _pool
    if _pool is None:
        _pool = ProcessPoolExecutor(max_workers=1)
        _pool.submit(bool, True).result(timeout=10)  # warm the worker up front
    return _pool


def _reset_pool() -> None:
    """A timed-out match leaves the worker busy, so tear the pool down and let it rebuild."""
    global _pool
    if _pool is not None:
        _pool.shutdown(wait=False, cancel_futures=True)
        _pool = None


def safe_search(pattern: str, text: str, budget: float = MATCH_BUDGET_S) -> bool:
    """Run one regex search in a reused worker process under a time budget.

    A timeout means the pattern backtracks catastrophically on this input -> reject it.
    """
    try:
        future = _get_pool().submit(_match_worker, pattern, text)
        return bool(future.result(timeout=budget))
    except FutureTimeout:
        _reset_pool()
        raise TimeoutError("regex exceeded time budget")


def _matches_any(pattern: str, variants: list[str]) -> bool:
    return any(safe_search(pattern, v) for v in variants)


def validate(category: str, regex: str, example_payload: str) -> ValidationResult:
    regex = (regex or "").strip()
    if category not in VALID_CATEGORIES:
        return ValidationResult(False, f"unknown category '{category}'")
    if not regex:
        return ValidationResult(False, "empty regex")
    if len(regex) >= MAX_LEN:
        return ValidationResult(False, f"regex too long ({len(regex)} >= {MAX_LEN})")
    if NESTED_QUANTIFIER.search(regex):
        return ValidationResult(False, "nested quantifier (catastrophic backtracking risk)")
    try:
        re.compile(regex)
    except re.error as exc:
        return ValidationResult(False, f"does not compile: {exc}")

    # (a) must not match empty string; run everything under the time budget
    try:
        if safe_search(regex, ""):
            return ValidationResult(False, "matches the empty string (too broad)")

        # (b) must match the example payload
        if not example_payload or not _matches_any(regex, normalize_variants(example_payload)):
            return ValidationResult(False, "does not match its own example_payload")

        # (c) must not match any benign clean-corpus entry
        hits = 0
        for benign in CLEAN_CORPUS:
            if _matches_any(regex, normalize_variants(benign)):
                hits += 1
                if hits == 1:
                    first = benign
        if hits:
            return ValidationResult(False, f"matches {hits} benign input(s), e.g. '{first}'")

        # (d) overly broad: fraction cap (already 0 above, kept explicit) + benign 3-word probes
        if hits / max(1, len(CLEAN_CORPUS)) > CORPUS_MAX_FRACTION:
            return ValidationResult(False, "matches too much of the clean corpus")
        for probe in BENIGN_WORD_PROBES:
            if _matches_any(regex, normalize_variants(probe)):
                return ValidationResult(False, f"matches benign probe '{probe}' (too broad)")
    except TimeoutError as exc:
        return ValidationResult(False, f"regex too slow: {exc}")
    except ValueError as exc:
        return ValidationResult(False, f"regex error: {exc}")

    return ValidationResult(True, "all checks passed")
