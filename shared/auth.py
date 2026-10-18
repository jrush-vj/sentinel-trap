"""Signed login cookie (nm_user) shared by the app (issues it) and the gateway (verifies it).

The HMAC key comes from env SESSION_SECRET; without it, a random key is generated in
DATA_DIR/.session_secret (gitignored). Whichever service starts first creates it (O_EXCL, so
two services racing at boot still end up with one key). The honeypot never signs cookies: a login inside
the honeypot must not mint a cookie that the real app or the gateway would accept.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import time

from shared.util import data_dir

COOKIE = "nm_user"
USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")

_secret: bytes | None = None


def _load_secret() -> bytes:
    global _secret
    if _secret is None and os.environ.get("SESSION_SECRET"):
        _secret = os.environ["SESSION_SECRET"].encode()
    if _secret is None:
        path = data_dir() / ".session_secret"
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(secrets.token_hex(32))
        except FileExistsError:
            pass
        for _ in range(20):  # the other service may still be writing it
            text = path.read_text().strip()
            if text:
                _secret = text.encode()
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("session secret file is empty")
    return _secret


def _sig(username: str) -> str:
    return hmac.new(_load_secret(), username.encode(), hashlib.sha256).hexdigest()[:32]


def sign(username: str) -> str:
    return f"{username}.{_sig(username)}"


def verify(cookie: str | None) -> str | None:
    """Username from a valid cookie, else None."""
    name, _, sig = (cookie or "").partition(".")
    if USERNAME_RE.match(name) and sig and hmac.compare_digest(sig, _sig(name)):
        return name
    return None


def claimed_username(cookie: str | None) -> str | None:
    """Username part WITHOUT checking the signature (display only, e.g. inside the honeypot)."""
    name = (cookie or "").partition(".")[0]
    return name if USERNAME_RE.match(name) else None
