"""Ban-store tests: fingerprint OR ip matching (cookie-clear doesn't evade), eligibility, idle sweep."""
import time

from gateway import store


def test_ban_matches_by_fingerprint():
    store.add_ban("fp-aaa", "203.0.113.1", "test")
    assert store.is_banned("fp-aaa", "9.9.9.9") is not None


def test_ban_matches_by_ip_after_cookie_cleared():
    # Attacker banned with one fingerprint; clears cookies -> new fingerprint, SAME ip -> still banned.
    store.add_ban("fp-old", "203.0.113.2", "test")
    assert store.is_banned("fp-new-after-clearing-cookies", "203.0.113.2") is not None


def test_not_banned_when_neither_matches():
    store.add_ban("fp-x", "203.0.113.3", "test")
    assert store.is_banned("fp-y", "203.0.113.99") is None


def test_add_ban_is_idempotent():
    store.add_ban("fp-dup", "203.0.113.4", "first")
    store.add_ban("fp-dup", "203.0.113.4", "second")
    assert len([b for b in store.list_bans() if b["fingerprint"] == "fp-dup"]) == 1


def test_remove_ban():
    store.add_ban("fp-rm", "203.0.113.5", "test")
    assert store.remove_ban(fingerprint="fp-rm") >= 1
    assert store.is_banned("fp-rm", "203.0.113.5") is None


def test_attacker_risk_accumulates_and_marks_eligible():
    store.upsert_attacker("s1", "fp1", "203.0.113.6", risk_add=3, honeypot_inc=1, payload="a")
    row = store.upsert_attacker("s1", "fp1", "203.0.113.6", risk_add=4, honeypot_inc=1, payload="b")
    assert row["risk"] == 7 and row["honeypot_actions"] == 2
    store.set_ban_eligible("s1")
    assert store.get_attacker("s1")["ban_eligible"] == 1


def test_idle_eligible_sweep():
    store.upsert_attacker("s2", "fp2", "203.0.113.7", risk_add=7, honeypot_inc=2)
    store.set_ban_eligible("s2")
    # last_seen is 'now', so with idle_seconds negative it should be considered idle immediately
    idle = store.idle_eligible_sessions(idle_seconds=-1)
    assert any(r["session_id"] == "s2" for r in idle)


def test_ended_session_not_swept():
    store.upsert_attacker("s3", "fp3", "203.0.113.8", risk_add=7, honeypot_inc=2)
    store.set_ban_eligible("s3")
    store.mark_ended("s3")
    assert all(r["session_id"] != "s3" for r in store.idle_eligible_sessions(idle_seconds=-1))
