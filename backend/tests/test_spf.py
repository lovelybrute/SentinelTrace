import ipaddress
from spf_evaluator import SPFEvaluator


def test_spf_evaluator_ip4_match():
    evaluator = SPFEvaluator()
    record = "v=spf1 ip4:192.0.2.0/24 -all"
    target_ip = ipaddress.ip_address("192.0.2.45")
    res, mech, reason = evaluator._evaluate_record(record, "example.com", target_ip, [0])
    assert res == "PASS"
    assert "ip4:192.0.2.0/24" in mech


def test_spf_evaluator_hard_fail():
    evaluator = SPFEvaluator()
    record = "v=spf1 ip4:192.0.2.0/24 -all"
    target_ip = ipaddress.ip_address("198.51.100.1")
    res, mech, reason = evaluator._evaluate_record(record, "example.com", target_ip, [0])
    assert res == "FAIL"
    assert mech == "-all"


def test_spf_evaluator_softfail():
    evaluator = SPFEvaluator()
    record = "v=spf1 ip4:192.0.2.0/24 ~all"
    target_ip = ipaddress.ip_address("198.51.100.1")
    res, mech, reason = evaluator._evaluate_record(record, "example.com", target_ip, [0])
    assert res == "SOFTFAIL"
    assert mech == "~all"


def test_spf_evaluator_private_ip(monkeypatch):
    evaluator = SPFEvaluator()
    monkeypatch.setattr(
        evaluator,
        "query_spf_record",
        lambda _domain: (_ for _ in ()).throw(AssertionError("private IP must not trigger DNS")),
    )
    result = evaluator.evaluate("example.com", "192.168.1.100")
    assert result["result"] == "NEUTRAL"
    assert "private/internal" in result["reasoning"]
