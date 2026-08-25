from received_parser import ReceivedHeaderParser


def test_received_chain_chronology():
    parser = ReceivedHeaderParser()
    headers = [
        {"raw": "from mail-edge.target.com [198.51.100.2] by mx.destination.com with ESMTP; Tue, 25 Aug 2026 10:02:00 +0000"},
        {"raw": "from client.origin.org [198.51.100.1] by mail-edge.target.com with ESMTP; Tue, 25 Aug 2026 10:00:00 +0000"}
    ]
    chain = parser.analyze_chain(headers)
    assert chain["chain_length"] == 2
    # In chronological order, earliest sending hop is hop 1
    assert chain["chronological_hops"][0]["from_ip"] == "198.51.100.1"
    assert chain["chronological_hops"][1]["from_ip"] == "198.51.100.2"


def test_earliest_external_source_identification():
    parser = ReceivedHeaderParser()
    headers = [
        {"raw": "from internal-srv [10.0.0.5] by dest-mx [10.0.0.1]; Tue, 25 Aug 2026 10:02:00 +0000"},
        {"raw": "from external-mta.cloud.com [198.51.100.44] by internal-srv with ESMTP; Tue, 25 Aug 2026 10:01:00 +0000"},
        {"raw": "from sender-pc [192.168.1.50] by external-mta.cloud.com with ESMTP; Tue, 25 Aug 2026 10:00:00 +0000"}
    ]
    chain = parser.analyze_chain(headers)
    assert chain["earliest_external_source"] is not None
    assert chain["earliest_external_source"]["ip"] == "198.51.100.44"
    assert "public IP" in chain["earliest_external_source"]["evidence"][0]
