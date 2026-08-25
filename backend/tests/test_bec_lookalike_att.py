from bec_detector import BECDetector
from lookalike_detector import LookalikeDetector
from attachment_analyzer import AttachmentAnalyzer
from url_analyzer import URLAnalyzer


def test_bec_executive_impersonation():
    detector = BECDetector()
    res = detector.analyze(
        from_header='"John Smith (CEO)" <ceo.john.smith99@gmail.com>',
        subject="Urgent Wire Transfer Authorization",
        body_text="Please wire $50,000 immediately to the attached account coordinates. Keep this strictly confidential."
    )
    assert res["bec_detected"] is True
    assert res["display_name_spoofing"] is True
    assert res["confidence_score"] >= 60


def test_lookalike_detector():
    detector = LookalikeDetector()
    res = detector.check_domain("paypa1-security.com")
    assert res["is_lookalike"] is True
    assert res["impersonated_brand"] == "paypal"
    assert res["similarity_score"] >= 0.75


def test_subdomain_deception():
    detector = LookalikeDetector()
    res = detector.check_domain("paypal.com.attacker-controlled.net")
    assert res["subdomain_deception"] is True
    assert res["is_lookalike"] is True


def test_dangerous_attachment():
    analyzer = AttachmentAnalyzer()
    res = analyzer.analyze_attachment("invoice_2026.pdf.exe", b"MZ\x90\x00Dummy binary payload")
    assert res["is_dangerous"] is True
    assert res["risk_level"] == "CRITICAL"
    assert res["has_double_extension"] is True


def test_url_analyzer_ssrf_safety():
    analyzer = URLAnalyzer()
    res_private = analyzer.analyze_url("http://192.168.1.1/admin")
    assert res_private["is_ip_host"] is True

    res_short = analyzer.analyze_url("https://bit.ly/verify-now")
    assert res_short["is_shortened"] is True
