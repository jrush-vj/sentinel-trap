"""Payload normalization applied BEFORE rule matching.

Attackers obfuscate payloads to slip past naive signatures. We canonicalize first so one rule
catches many encodings: URL-decode (twice), Unicode NFKC, strip zero-width characters, collapse
SQL inline comments `/**/`, lowercase, and collapse whitespace.
"""
from __future__ import annotations

import re
import unicodedata
from urllib.parse import unquote_plus

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍‎‏﻿­"), None)
_INLINE_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_WS = re.compile(r"\s+")


def normalize(text: str) -> str:
    if not text:
        return ""
    # URL-decode up to twice to unwrap double-encoding like %2527 -> %27 -> '
    for _ in range(2):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_ZERO_WIDTH)
    text = _INLINE_COMMENT.sub(" ", text)   # UN/**/ION -> UN ION ... see below
    text = text.replace("/**/", " ")
    text = text.lower()
    text = _WS.sub(" ", text).strip()
    return text


def normalize_variants(text: str) -> list[str]:
    """Return both the spaced and the de-spaced normalization.

    Removing `/**/` can leave `un ion select`; collapsing the injected whitespace to nothing
    recovers `unionselect`, so a comment-obfuscated `UN/**/ION SEL/**/ECT` still matches a
    `union\\s*select` rule. We test rules against every variant.
    """
    base = normalize(text)
    squashed = base.replace(" ", "")
    return [base, squashed] if squashed != base else [base]
