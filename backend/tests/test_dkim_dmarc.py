from dkim_verifier import DKIMVerifier
from dmarc_analyzer import DMARCAnalyzer


def test_dkim_header_parsing():
    verifier = DKIMVerifier()
    header = "v=1; a=rsa-sha256; d=example.com; s=default; c=relaxed/relaxed; bh=abc123; b=xyz789;"
    tags = verifier.parse_dkim_header(header)
    assert tags.get("v") == "1"
    assert tags.get("a") == "rsa-sha256"
    assert tags.get("d") == "example.com"
    assert tags.get("s") == "default"


def test_dkim_alignment_strict():
    verifier = DKIMVerifier()
    header = "v=1; a=rsa-sha256; d=example.com; s=default; bh=abc123; b=xyz789;"
    # Offline test without live DNS resolution
    res = verifier.verify(header, "example.com")
    assert res["domain_alignment"] == "STRICT_ALIGNED"


def test_dkim_alignment_mismatch():
    verifier = DKIMVerifier()
    header = "v=1; a=rsa-sha256; d=attacker.net; s=default; bh=abc123; b=xyz789;"
    res = verifier.verify(header, "target-bank.com")
    assert res["domain_alignment"] == "MISMATCHED"


def test_dkim_key_presence_alone_never_asserts_pass(monkeypatch):
    verifier = DKIMVerifier()
    monkeypatch.setattr(
        verifier,
        "query_public_key",
        lambda _selector, _domain: ("v=DKIM1; k=rsa; p=ZmFrZS1rZXk=", None),
    )
    header = "v=1; a=rsa-sha256; d=example.com; s=default; bh=abc123; b=xyz789;"

    result = verifier.verify(header, "example.com", raw_message_bytes=None)

    assert result["status"] == "NEUTRAL"
    assert result["cryptographic_verification"] == "UNVERIFIED_KEY_PRESENT"


def test_dmarc_tags_parsing():
    analyzer = DMARCAnalyzer()
    record = "v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:dmarc-reports@example.com"
    tags = analyzer.parse_dmarc_tags(record)
    assert tags.get("v") == "DMARC1"
    assert tags.get("p") == "reject"
    assert tags.get("sp") == "quarantine"
    assert tags.get("pct") == "100"
