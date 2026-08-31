import pytest
from vuln.vulnerability_engine import evaluate_vulnerabilities


def test_threat_dimensions_apache_path_traversal():
    findings = evaluate_vulnerabilities(
        product="Apache",
        version="2.4.49",
        service="http",
        evidence_banner="Server: Apache/2.4.49 (Debian)",
    )
    assert len(findings) >= 1
    f = findings[0]
    
    # Verify Identity
    assert f["cpe_23"] == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert f["identity"]["vendor"] == "apache"
    assert f["identity"]["product"] == "http_server"

    # Verify Threat Dimensions
    assert "threat_dimensions" in f
    assert f["threat_dimensions"]["severity"]["cvss"] == 9.8
    assert f["cisa_kev"] is True
    assert f["epss_score"] > 0.90
    assert "%" in f["epss_percent"]


def test_threat_dimensions_openssh_patched_backport():
    findings = evaluate_vulnerabilities(
        product="OpenSSH",
        version="9.6p1",
        service="ssh",
        evidence_banner="SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18",
    )
    assert len(findings) >= 1
    f = findings[0]

    assert f["finding_status"] == "NOT_VULNERABLE"
    assert f["severity"] == "info"
    assert "cpe_23" in f
    assert "cpe:2.3:a:openbsd:openssh:9.6p1" in f["cpe_23"]
    assert "3ubuntu13.18" in f["evidence_proof"]
