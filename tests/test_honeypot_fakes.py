"""Honeypot fake-data contract: a canary must always be present, and SQLi payloads get the right shape."""
from honeypot import fakes


def test_fake_chat_leak_always_has_canary():
    # The whole trap->ban chain depends on a canary in the leak, so lock that contract.
    reply, key = fakes.fake_chat_leak()
    assert fakes.CANARY_PREFIX in reply
    assert key.startswith(fakes.CANARY_PREFIX)


def test_union_response_includes_canary_rows():
    r = fakes.fake_customer_response("x' UNION SELECT name,key FROM api_keys--")
    blob = str(r["results"])
    assert fakes.CANARY_PREFIX in blob


def test_tautology_dumps_all_fake_customers():
    r = fakes.fake_customer_response("' OR 1=1--")
    assert r["count"] == len(fakes.FAKE_CUSTOMERS)


def test_schema_probe_returns_table_names():
    r = fakes.fake_customer_response("' UNION SELECT name,sql FROM sqlite_master--")
    names = [row["name"] for row in r["results"]]
    assert "customers" in names and "secrets" in names
