import pytest
from recon.ip_resolve import resolve_subdomain_ips, is_cdn_ip
from recon.subdomains import enumerate_subdomains
from recon.company_resolve import resolve_company_info
from worker import _should_run_step, SCAN_MODES


def test_ip_resolve_direct_private_ip():
    # Scanning a local private VM (e.g. 10.251.132.28 or 192.168.1.50) must bypass DNS resolution
    hosts = resolve_subdomain_ips(["10.251.132.28", "192.168.1.50"])
    assert len(hosts) == 2
    
    vm_host = hosts[0]
    assert vm_host["subdomain"] == "10.251.132.28"
    assert vm_host["ips"] == ["10.251.132.28"]
    assert vm_host["is_cdn"] is False
    assert vm_host["cdn_provider"] is None

    local_host = hosts[1]
    assert local_host["subdomain"] == "192.168.1.50"
    assert local_host["ips"] == ["192.168.1.50"]
    assert local_host["is_cdn"] is False


def test_subdomains_direct_ip_fast_path():
    # Direct IP targets should return immediately without Certificate Transparency queries
    subs = enumerate_subdomains("10.251.132.28")
    assert len(subs) == 1
    assert subs[0]["subdomain"] == "10.251.132.28"
    assert "seed_ip" in subs[0]["sources"]


def test_company_resolve_direct_ip():
    # Company info resolver must gracefully return host info without failing WHOIS
    info = resolve_company_info("10.251.132.28")
    assert "Host (10.251.132.28)" in info["org_name"]
    assert info["primary_ips"] == ["10.251.132.28"]
    assert info["origin_candidates"][0]["ip"] == "10.251.132.28"
    assert "Private" in info["asn_infrastructure_type"]


def test_should_run_step_vm_audit_mode():
    # In vm_audit mode, external OSINT & People stages are skipped in 0ms
    assert _should_run_step("init", "1.company_resolve", scan_mode="vm_audit") is False
    assert _should_run_step("init", "2.subdomains", scan_mode="vm_audit") is False
    assert _should_run_step("init", "8.people_osint", scan_mode="vm_audit") is False

    # Infrastructure & vulnerability stages must execute
    assert _should_run_step("init", "3.ip_resolve", scan_mode="vm_audit") is True
    assert _should_run_step("init", "4.ports", scan_mode="vm_audit") is True
    assert _should_run_step("init", "5.fingerprint", scan_mode="vm_audit") is True
    assert _should_run_step("init", "6.nuclei_match", scan_mode="vm_audit") is True
    assert _should_run_step("init", "7.cve_lookup", scan_mode="vm_audit") is True
    assert _should_run_step("init", "9.ai_triage", scan_mode="vm_audit") is True
    assert _should_run_step("init", "10.report_writer", scan_mode="vm_audit") is True


def test_should_run_step_people_only_mode():
    # In people_only mode, port sweeping and network scanning are skipped
    assert _should_run_step("init", "1.company_resolve", scan_mode="people_only") is True
    assert _should_run_step("init", "8.people_osint", scan_mode="people_only") is True
    assert _should_run_step("init", "9.ai_triage", scan_mode="people_only") is True
    assert _should_run_step("init", "10.report_writer", scan_mode="people_only") is True

    assert _should_run_step("init", "4.ports", scan_mode="people_only") is False
    assert _should_run_step("init", "6.nuclei_match", scan_mode="people_only") is False
    assert _should_run_step("init", "7.cve_lookup", scan_mode="people_only") is False


def test_should_run_step_custom_enabled_stages():
    # Custom enabled stages
    custom_stages = ["4.ports", "7.cve_lookup"]
    assert _should_run_step("init", "4.ports", enabled_stages=custom_stages) is True
    assert _should_run_step("init", "7.cve_lookup", enabled_stages=custom_stages) is True
    assert _should_run_step("init", "10.report_writer", enabled_stages=custom_stages) is True
    assert _should_run_step("init", "1.company_resolve", enabled_stages=custom_stages) is False
    assert _should_run_step("init", "8.people_osint", enabled_stages=custom_stages) is False
