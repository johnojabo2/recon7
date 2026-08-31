import pytest
from vuln.vulnerability_engine import evaluate_vulnerabilities, audit_host_misconfigurations


def test_apache_strict_version_matching():
    # 2.4.49 is vulnerable to Path Traversal RCE
    vulns_49 = evaluate_vulnerabilities(
        product="Apache HTTP Server",
        version="2.4.49",
        service="http",
        evidence_banner="Server: Apache/2.4.49 (Unix)",
    )
    cve_ids_49 = [v["cve_id"] for v in vulns_49]
    assert "CVE-2021-41773" in cve_ids_49
    assert vulns_49[0]["cisa_kev"] is True
    assert vulns_49[0]["exploit_available"] is True
    assert "Server: Apache/2.4.49 (Unix)" in vulns_49[0]["evidence_proof"]

    # 2.4.58 is patched and must NOT match any Apache CVEs (fixed in 2.4.56+)
    vulns_58 = evaluate_vulnerabilities(
        product="Apache HTTP Server",
        version="2.4.58",
        service="http",
        evidence_banner="Server: Apache/2.4.58 (Unix)",
    )
    assert len(vulns_58) == 0


def test_openssh_version_boundary():
    # 8.2p1 is vulnerable to SCP injection (CVE-2020-15778) and Terrapin (CVE-2023-48795)
    # but NOT regreSSHion (CVE-2024-6387, which is 8.5p1 to 9.7p1)
    vulns_82 = evaluate_vulnerabilities(
        product="OpenSSH",
        version="8.2p1",
        service="ssh",
        evidence_banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
    )
    cve_ids_82 = [v["cve_id"] for v in vulns_82]
    assert "CVE-2020-15778" in cve_ids_82
    assert "CVE-2023-48795" in cve_ids_82
    assert "CVE-2024-6387" not in cve_ids_82

    # 9.2p1 matches regreSSHion (CVE-2024-6387) on Debian with patched backport 2+deb12u3
    vulns_92 = evaluate_vulnerabilities(
        product="OpenSSH",
        version="9.2p1",
        service="ssh",
        evidence_banner="SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
    )
    cve_ids_92 = [v["cve_id"] for v in vulns_92]
    assert "CVE-2024-6387" in cve_ids_92
    regresshion = next(v for v in vulns_92 if v["cve_id"] == "CVE-2024-6387")
    # Verify CISA KEV is False for regreSSHion to prevent false claims
    assert regresshion["cisa_kev"] is False
    assert regresshion["finding_status"] == "NOT_VULNERABLE"
    assert regresshion["evidence_tier"] == "DISTRO_BACKPORT_VERIFIED"
    assert regresshion["distro_backport_possible"] is True


def test_cisa_kev_verification():
    from vuln.cve_lookup import is_verified_cisa_kev
    # Confirmed KEV: HTTP/2 Rapid Reset
    assert is_verified_cisa_kev("CVE-2023-44487") is True
    assert is_verified_cisa_kev("CVE-2021-44228") is True
    # Non-KEV: regreSSHion (lab/PoC only, not in CISA catalog)
    assert is_verified_cisa_kev("CVE-2024-6387") is False
    assert is_verified_cisa_kev("CVE-9999-99999") is False


def test_deterministic_triage_fallback():
    from ai.triage import deterministic_triage_findings
    sample_scan_data = {
        "target_domain": "corp-target.com",
        "subdomains": [{"subdomain": "dev-api.corp-target.com"}, {"subdomain": "www.corp-target.com"}],
        "ip_resolutions": [{"subdomain": "dev-api.corp-target.com", "ips": ["1.2.3.4"], "is_cdn": False}],
        "ports": [{"port": 8080, "service": "http", "product": "Nginx", "version": "1.24.0"}],
        "vulns": [
            {
                "cve_id": "CVE-2023-44487",
                "title": "Nginx HTTP/2 Rapid Reset",
                "severity": "high",
                "evidence_tier": "VERSION_ADVISORY",
                "description": "HTTP/2 stream reset advisory.",
                "remediation": "Check keepalive_requests.",
            }
        ],
        "people": {
            "confirmed_count": 4,
            "email_pattern": "{first}.{last}@corp-target.com",
            "people": [{"name": "Jane Doe", "email": "jane.doe@corp-target.com"}],
        }
    }
    triage = deterministic_triage_findings(sample_scan_data)
    assert "executive_summary" in triage
    assert len(triage["prioritized_findings"]) >= 1
    assert len(triage["attack_vectors"]) >= 1
    # Verify vector synthesis
    vector_names = [v["vector_name"] for v in triage["attack_vectors"]]
    assert any("Non-Production" in name for name in vector_names)
    assert any("Spearphishing" in name for name in vector_names)


def test_audit_host_misconfigurations():
    test_ports = [
        {"port": 22, "state": "open", "service": "ssh", "version": "8.2p1", "service_verified": True},
        {"port": 80, "state": "open", "service": "http", "dangerous_methods": ["PUT", "DELETE"], "service_verified": True},
        {"port": 3306, "state": "open", "service": "mysql", "version": "5.7.33", "service_verified": True},
        {"port": 21, "state": "open", "service": "ftp", "anonymous_access": True, "service_verified": True},
        {"port": 23, "state": "open", "service": "telnet", "service_verified": True, "banner": "Telnet IAC Protocol Negotiated"},
        {"port": 5432, "state": "open", "service": "postgresql", "service_verified": False, "banner": ""},
    ]
    misconfigs = audit_host_misconfigurations("154.68.225.18", test_ports)
    cve_ids = [m["cve_id"] for m in misconfigs]

    assert "MISCONFIG-WAN-DB-3306" in cve_ids
    assert "MISCONFIG-WAN-DB-5432" in cve_ids
    assert "MISCONFIG-HTTP-DANGEROUS-METHODS" in cve_ids
    assert "MISCONFIG-ANONYMOUS-LOGIN" in cve_ids
    assert "MISCONFIG-CLEARTEXT-TELNET" in cve_ids

    # Verify verified MySQL port is CRITICAL
    db_verified = next(m for m in misconfigs if m["cve_id"] == "MISCONFIG-WAN-DB-3306")
    assert db_verified["severity"] == "critical"
    assert db_verified["finding_status"] == "CONFIRMED"
    assert "154.68.225.18" in db_verified["evidence_proof"]

    # Verify unverified PostgreSQL port is POTENTIALLY_AFFECTED / MEDIUM (preventing false-positive CONFIRMED)
    db_unverified = next(m for m in misconfigs if m["cve_id"] == "MISCONFIG-WAN-DB-5432")
    assert db_unverified["severity"] == "medium"
    assert db_unverified["finding_status"] == "POTENTIALLY_AFFECTED"
    assert "not verified" in db_unverified["evidence_proof"]
