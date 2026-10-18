"""Mark-safe / self-correction tests: whitelist bypasses matching; disabled rule stops firing."""
from gateway import store
from gateway.clean_corpus import FALSE_POSITIVE_EXAMPLE
from gateway.normalize import normalize_variants
from gateway.rules import RuleEngine


def test_whitelisted_payload_is_recognized():
    variants = normalize_variants(FALSE_POSITIVE_EXAMPLE)
    assert store.whitelisted(variants) is False
    for v in variants:
        store.add_whitelist(v, note="marked safe")
    assert store.whitelisted(variants) is True


def test_disabling_eager_rule_clears_false_positive():
    engine = RuleEngine()
    before = engine.evaluate({"q": FALSE_POSITIVE_EXAMPLE})
    assert before["verdict"] == "suspicious" and "BI-PI-EXFIL-EAGER" in before["rule_ids"]

    assert engine.disable("BI-PI-EXFIL-EAGER") is True
    after = engine.evaluate({"q": FALSE_POSITIVE_EXAMPLE})
    assert after["verdict"] == "clean"


def test_disabled_rule_does_not_affect_real_attacks():
    engine = RuleEngine()
    engine.disable("BI-PI-EXFIL-EAGER")
    # a genuine injection is still caught by other rules
    assert engine.evaluate({"q": "' OR 1=1--"})["verdict"] == "malicious"


def test_toggle_learned_rule():
    from gateway.rules import Rule
    engine = RuleEngine()
    engine.add_learned(Rule(id="LR-TOG", category="other", regex=r"needle_marker", severity=6, source="learned"))
    assert engine.evaluate({"q": "needle_marker here"})["verdict"] == "malicious"
    assert engine.toggle("LR-TOG") is False  # now disabled
    assert engine.evaluate({"q": "needle_marker here"})["verdict"] == "clean"
    assert engine.toggle("LR-TOG") is True   # re-enabled
    assert engine.evaluate({"q": "needle_marker here"})["verdict"] == "malicious"
