import pytest
from vuln.epss_engine import get_epss_score, get_likelihood_label


def test_epss_high_profile_cve():
    # Apache Path Traversal (CVE-2021-41773) has high EPSS exploitation likelihood
    res = get_epss_score("CVE-2021-41773")
    assert res is not None
    assert res["cve_id"] == "CVE-2021-41773"
    assert res["epss_score"] > 0.90
    assert res["epss_percentile"] > 0.99
    assert "CRITICAL" in res["likelihood_label"]


def test_epss_rapid_reset_dos():
    # HTTP/2 Rapid Reset (CVE-2023-44487)
    res = get_epss_score("CVE-2023-44487")
    assert res is not None
    assert res["cve_id"] == "CVE-2023-44487"
    assert res["epss_score"] > 0.05
    assert "epss_percent" in res


def test_epss_unknown_cve_fallback():
    res = get_epss_score("CVE-1999-99999")
    assert res is not None
    assert res["cve_id"] == "CVE-1999-99999"
    assert res["epss_score"] <= 0.05
    assert "BASELINE" in res["likelihood_label"]


def test_likelihood_label_classification():
    assert "CRITICAL" in get_likelihood_label(0.95)
    assert "HIGH" in get_likelihood_label(0.45)
    assert "ELEVATED" in get_likelihood_label(0.12)
    assert "BASELINE" in get_likelihood_label(0.01)
