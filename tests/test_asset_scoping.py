import pytest
from recon.ports import COMMON_PROBE_PORTS_STANDARD, COMMON_PROBE_PORTS_FAST
from vuln.vulnerability_engine import evaluate_vulnerabilities


def test_dev_ports_in_standard_list():
    # Port 3000 (Juice Shop / Node / React) must be in standard and fast probe lists
    assert 3000 in COMMON_PROBE_PORTS_STANDARD
    assert 3000 in COMMON_PROBE_PORTS_FAST
    assert 5000 in COMMON_PROBE_PORTS_STANDARD
    assert 8000 in COMMON_PROBE_PORTS_STANDARD
    assert 8080 in COMMON_PROBE_PORTS_STANDARD


def test_host_bound_scoping_no_cross_pollution():
    # Host A: Linux Apache Server on 10.0.0.1
    host_a_vulns = evaluate_vulnerabilities(
        product="Apache",
        version="2.4.25",
        evidence_banner="Apache/2.4.25 (Debian)",
        host_context={"os": "linux", "ip": "10.0.0.1", "port": 80},
    )

    # Host B: Windows IIS Server on 10.0.0.2
    host_b_vulns = evaluate_vulnerabilities(
        product="IIS",
        version="8.5",
        evidence_banner="Microsoft-IIS/8.5",
        host_context={"os": "windows", "ip": "10.0.0.2", "port": 80},
    )

    # Host A should NOT have Windows IIS CVEs
    iis_on_a = [v for v in host_a_vulns if v["cve_id"] == "CVE-2015-1635"]
    assert len(iis_on_a) == 0

    # Host B should have MS15-034
    iis_on_b = [v for v in host_b_vulns if v["cve_id"] == "CVE-2015-1635"]
    assert len(iis_on_b) > 0
    assert iis_on_b[0]["finding_status"] != "NOT_APPLICABLE"
