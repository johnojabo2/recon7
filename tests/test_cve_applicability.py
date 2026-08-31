import pytest
from vuln.vulnerability_engine import evaluate_vulnerabilities, audit_host_misconfigurations, _infer_host_os


def test_php_cgi_windows_cve_rejected_on_linux():
    # Target: PHP 7.1.26 on Debian Linux (from testphp.vulnweb.com)
    # CVE-2024-4577 is a Windows-specific PHP-CGI flaw. It MUST evaluate to NOT_APPLICABLE on Linux.
    findings = evaluate_vulnerabilities(
        product="PHP",
        version="8.1.5",
        service="http",
        evidence_banner="Apache/2.4.25 (Debian) X-Powered-By: PHP/8.1.5",
        host_context={"os": "linux", "ip": "192.168.1.100", "port": 80},
    )
    
    php_cve = next((f for f in findings if f["cve_id"] == "CVE-2024-4577"), None)
    assert php_cve is not None
    assert php_cve["finding_status"] == "NOT_APPLICABLE"
    assert php_cve["status"] == "not_applicable"
    assert php_cve["severity"] == "info"
    assert php_cve["evidence_tier"] == "PLATFORM_MISMATCH"
    assert "Platform mismatch" in php_cve["evidence_proof"]
    assert "Linux" in php_cve["evidence_proof"]


def test_php_cgi_windows_cve_accepted_on_windows():
    # Target: PHP 8.1.5 on Microsoft Windows
    # CVE-2024-4577 SHOULD evaluate to POTENTIALLY_AFFECTED or CONFIRMED on Windows.
    findings = evaluate_vulnerabilities(
        product="PHP",
        version="8.1.5",
        service="http",
        evidence_banner="X-Powered-By: PHP/8.1.5",
        host_context={"os": "windows", "ip": "192.168.1.200", "port": 80},
    )
    
    php_cve = next((f for f in findings if f["cve_id"] == "CVE-2024-4577"), None)
    assert php_cve is not None
    assert php_cve["finding_status"] != "NOT_APPLICABLE"
    assert php_cve["status"] in ["potential", "likely", "confirmed"]


def test_iis_ms15_034_rejected_on_linux():
    # Target: Debian Linux server
    # Microsoft IIS HTTP.sys CVE-2015-1635 MUST evaluate to NOT_APPLICABLE on Linux.
    findings = evaluate_vulnerabilities(
        product="Microsoft IIS",
        version="8.5",
        service="http",
        evidence_banner="Apache/2.4.25 (Debian)",
        host_context={"os": "linux", "ip": "10.0.0.5", "port": 80},
    )
    
    iis_cve = next((f for f in findings if f["cve_id"] == "CVE-2015-1635"), None)
    assert iis_cve is not None
    assert iis_cve["finding_status"] == "NOT_APPLICABLE"
    assert iis_cve["evidence_tier"] == "PLATFORM_MISMATCH"


def test_apache_request_smuggling_module_prerequisite():
    # Apache 2.4.25 without confirmed mod_proxy configuration
    findings = evaluate_vulnerabilities(
        product="Apache",
        version="2.4.25",
        service="http",
        evidence_banner="Server: Apache/2.4.25 (Debian)",
        host_context={"os": "linux"},
    )
    
    smuggle_cve = next((f for f in findings if f["cve_id"] == "CVE-2022-22720"), None)
    assert smuggle_cve is not None
    assert smuggle_cve["finding_status"] == "POTENTIALLY_AFFECTED"
    assert "mod_proxy" in smuggle_cve["evidence_proof"]


def test_trace_method_misconfiguration_text():
    # Only TRACE method enabled
    ports = [{
        "port": 80,
        "protocol": "tcp",
        "state": "open",
        "dangerous_methods": ["TRACE"],
    }]
    misconfigs = audit_host_misconfigurations("10.0.0.1", ports)
    trace_finding = next((m for m in misconfigs if m["cve_id"] == "MISCONFIG-HTTP-DANGEROUS-METHODS"), None)
    assert trace_finding is not None
    assert "Cross-Site Tracing" in trace_finding["title"]
    assert "Cross-Site Tracing (XST)" in trace_finding["exploit_type"]
    assert "TraceEnable off" in trace_finding["remediation"]
    assert "file upload" not in trace_finding["title"].lower()


def test_infer_host_os_helper():
    assert _infer_host_os("Server: Apache/2.4.25 (Debian)") == "linux"
    assert _infer_host_os("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18") == "linux"
    assert _infer_host_os("Server: Microsoft-IIS/10.0") == "windows"
    assert _infer_host_os("", product="Microsoft IIS") == "windows"
    assert _infer_host_os("", host_context={"os": "windows"}) == "windows"
