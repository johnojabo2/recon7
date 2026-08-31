import pytest
from vuln.distro_matcher import (
    parse_banner_components,
    compare_dpkg_versions,
    evaluate_distro_security_status,
)
from vuln.vulnerability_engine import evaluate_vulnerabilities


def test_parse_banner_components():
    # 1. OpenSSH with Ubuntu package revision
    b1 = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18"
    p1 = parse_banner_components(b1)
    assert p1["product"] == "OpenSSH"
    assert p1["upstream_version"] == "9.6p1"
    assert p1["distro"] == "ubuntu"
    assert p1["package_revision"] == "3ubuntu13.18"

    # 2. Apache with Debian
    b2 = "Apache/2.4.58 (Debian)"
    p2 = parse_banner_components(b2)
    assert p2["product"] == "Apache"
    assert p2["upstream_version"] == "2.4.58"
    assert p2["distro"] == "debian"

    # 3. Nginx with Ubuntu
    b3 = "nginx/1.24.0 (Ubuntu)"
    p3 = parse_banner_components(b3)
    assert p3["product"] == "Nginx"
    assert p3["upstream_version"] == "1.24.0"
    assert p3["distro"] == "ubuntu"


def test_compare_dpkg_versions():
    # Higher revision vs lower revision
    assert compare_dpkg_versions("3ubuntu13.18", "3ubuntu13.3") == 1
    assert compare_dpkg_versions("3ubuntu13.2", "3ubuntu13.3") == -1
    assert compare_dpkg_versions("3ubuntu13.3", "3ubuntu13.3") == 0

    # Debian revisions
    assert compare_dpkg_versions("1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u2") == 1
    assert compare_dpkg_versions("1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u3") == 0

    # Tildes (pre-release) vs full release
    assert compare_dpkg_versions("1.0~rc1", "1.0") == -1


def test_evaluate_distro_security_status_openssh_patched():
    # Patched Ubuntu 24.04 (Noble) OpenSSH 9.6p1 with revision 3ubuntu13.18
    banner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18"
    res = evaluate_distro_security_status(
        cve_id="CVE-2024-6387",
        product="OpenSSH",
        upstream_version="9.6p1",
        banner=banner,
    )
    assert res["finding_status"] == "NOT_VULNERABLE"
    assert res["is_vulnerable"] is False
    assert res["confidence"] >= 0.95
    assert "backported" in res["reason"].lower() or "patched" in res["reason"].lower()
    assert "3ubuntu13.18 >= 3ubuntu13.3" in res["mathematical_proof"]


def test_evaluate_distro_security_status_openssh_unpatched():
    # Unpatched Ubuntu OpenSSH 9.6p1 with revision 3ubuntu13.2 (below fixed 3ubuntu13.3)
    banner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.2"
    res = evaluate_distro_security_status(
        cve_id="CVE-2024-6387",
        product="OpenSSH",
        upstream_version="9.6p1",
        banner=banner,
    )
    assert res["finding_status"] == "LIKELY_VULNERABLE"
    assert res["is_vulnerable"] is True
    assert res["confidence"] >= 0.90


def test_evaluate_distro_security_status_nginx_rapid_reset():
    # Nginx 1.24.0 HTTP/2 Rapid Reset
    banner = "nginx/1.24.0 (Ubuntu)"
    res = evaluate_distro_security_status(
        cve_id="CVE-2023-44487",
        product="Nginx",
        upstream_version="1.24.0",
        banner=banner,
    )
    assert res["finding_status"] == "POTENTIALLY_AFFECTED"
    assert "default configuration" in res["reason"].lower()


def test_evaluate_vulnerabilities_end_to_end():
    # Test end-to-end vulnerability engine on patched OpenSSH 9.6p1 Ubuntu server
    findings = evaluate_vulnerabilities(
        product="OpenSSH",
        version="9.6p1",
        service="ssh",
        evidence_banner="SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18",
    )
    assert len(findings) > 0
    regresshion = next((f for f in findings if f["cve_id"] == "CVE-2024-6387"), None)
    assert regresshion is not None
    assert regresshion["finding_status"] == "NOT_VULNERABLE"
    assert regresshion["status"] == "patched"
    assert regresshion["severity"] == "info"
    assert regresshion["evidence_tier"] == "DISTRO_BACKPORT_VERIFIED"
