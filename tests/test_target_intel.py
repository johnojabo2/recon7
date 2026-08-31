import pytest
from unittest.mock import patch, MagicMock
from recon.email_sec import analyze_email_security
from recon.tls_intel import extract_tls_certificate_intel, _parse_ssl_date
from recon.dns_risk import assess_dns_risks


def test_dmarc_analysis_reject():
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_txt = MagicMock()
        mock_txt.strings = [b"v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com"]
        mock_resolve.return_value = [mock_txt]

        res = analyze_email_security("example.com")
        assert res["dmarc_policy"] == "reject"
        assert res["dmarc_pct"] == 100
        assert res["spoofable"] is False
        assert res["spoofability_score"] == "BLOCKED"


def test_dmarc_analysis_none_spoofable():
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_txt = MagicMock()
        mock_txt.strings = [b"v=DMARC1; p=none; rua=mailto:reports@example.com"]
        mock_resolve.return_value = [mock_txt]

        res = analyze_email_security("example.com")
        assert res["dmarc_policy"] == "none"
        assert res["spoofable"] is True
        assert res["spoofability_score"] == "HIGH_FEASIBILITY"


def test_parse_ssl_date():
    dt = _parse_ssl_date("Nov  2 16:27:53 2026 GMT")
    assert dt is not None
    assert dt.year == 2026
    assert dt.month == 11
    assert dt.day == 2


def test_assess_dns_risks_protected():
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_ip = MagicMock()
        mock_ip.__str__.return_value = "1.2.3.4"
        mock_resolve.return_value = [mock_ip]

        with patch("dns.query.xfr") as mock_xfr:
            mock_xfr.side_effect = Exception("REFUSED")
            res = assess_dns_risks("example.com", ["ns1.example.com"])
            assert res["axfr_vulnerable"] is False
            assert "Passed" in res["axfr_verdict"]
