import os
import re
import time
import logging
import asyncio
import threading
import traceback
import concurrent.futures
import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set

# Core & Scope Engine
from core.config import settings
from core.scope import normalize_domain, extract_root_domain, classify_target
from storage.db import (
    get_db_session,
    init_db,
    update_scan_job,
    add_finding,
    add_findings_batch,
    get_findings_for_job,
    create_ai_report,
    add_observation,
    add_evidence,
    upsert_entity,
    upsert_relationship,
    ScanJob,
)

# Pipeline Step Modules & Engines
from recon.company_resolve import resolve_company_info
from recon.subdomains import enumerate_subdomains
from recon.ip_resolve import resolve_subdomain_ips, is_cdn_ip
from recon.ports import scan_ports_and_services, prioritize_target_ips, scan_multiple_hosts_concurrently
from recon.fingerprint import fingerprint_target_urls
from vuln.nuclei_match import run_nuclei_scans
from vuln.cve_lookup import correlate_findings_with_cve_and_owasp, correlate_port_findings_to_vulns
from vuln.vulnerability_engine import evaluate_vulnerabilities, audit_host_misconfigurations, _infer_host_os
from vuln.app_vuln import run_app_vuln_scans_sync
from people.aggregate import aggregate_people_osint
from core.identity.resolution import resolve_identities
from people.doc_metadata import extract_public_doc_metadata
from recon.exposure_engine import (
    check_cloud_storage_exposure,
    check_breach_exposure_signal,
)
from people.breach_correlator import correlate_email_breach_signals
from ai.triage import triage_findings
from ai.report_writer import generate_engagement_report

log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)-7s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("r7.worker")
logger.setLevel(log_level)

PIPELINE_STEPS = [
    "1.company_resolve",
    "2.subdomains",
    "3.ip_resolve",
    "4.ports",
    "5.fingerprint",
    "6.nuclei_match",
    "7.cve_lookup",
    "8.people_osint",
    "9.ai_triage",
    "10.report_writer",
]

# Declarative Step Mappings for Modular Scanning Profiles
SCAN_MODES: Dict[str, Set[str]] = {
    # Full 360° Reconnaissance (Default)
    "full": {
        "1.company_resolve", "2.subdomains", "3.ip_resolve", "4.ports",
        "5.fingerprint", "6.nuclei_match", "7.cve_lookup", "8.people_osint",
        "9.ai_triage", "10.report_writer",
    },
    # Internal VM & Host Audit (Direct IP / VM Target: skips external OSINT/DNS/People)
    "vm_audit": {
        "3.ip_resolve", "4.ports", "5.fingerprint", "6.nuclei_match",
        "7.cve_lookup", "9.ai_triage", "10.report_writer",
    },
    # Infrastructure, Tech Stack & Vulnerabilities Only (Skips People/Docs OSINT)
    "infra_vuln": {
        "2.subdomains", "3.ip_resolve", "4.ports", "5.fingerprint",
        "6.nuclei_match", "7.cve_lookup", "9.ai_triage", "10.report_writer",
    },
    # People & Identity OSINT Only (Skips Port scans & Network Probing)
    "people_only": {
        "1.company_resolve", "8.people_osint", "9.ai_triage", "10.report_writer",
    },
    # Fast Recon & Port Sweep (No Nuclei or People OSINT)
    "fast_recon": {
        "2.subdomains", "3.ip_resolve", "4.ports", "5.fingerprint",
        "7.cve_lookup", "9.ai_triage", "10.report_writer",
    },
}


class ScanAbortedException(Exception):
    """Raised when an active scan job is cancelled by the operator."""
    pass


def _check_if_aborted(tenant_id: str, job_id: str):
    """Checks database to determine if the scan was cancelled by operator."""
    with get_db_session() as db:
        job = (
            db.query(ScanJob)
            .filter(ScanJob.tenant_id == tenant_id, ScanJob.id == job_id)
            .first()
        )
        if job and job.status in ("cancelled", "aborted"):
            raise ScanAbortedException(f"Scan job '{job_id}' was cancelled by operator.")


def _checkpoint_step(tenant_id: str, job_id: str, step_name: str):
    """Updates current_step in database for state checkpointing and verifies cancellation."""
    _check_if_aborted(tenant_id, job_id)
    try:
        with get_db_session() as db:
            update_scan_job(db, tenant_id, job_id, current_step=step_name)
    except ScanAbortedException:
        raise
    except Exception as e:
        logger.debug(f"Checkpoint update failed for step '{step_name}': {e}")


def _should_run_step(
    current_step: str,
    target_step: str,
    scan_mode: str = "full",
    enabled_stages: Optional[List[str]] = None,
) -> bool:
    """
    Evaluates if target_step should be executed based on:
    1. Active scan mode / custom stage selection.
    2. Current step position (for resuming checkpointed jobs).
    """
    # 1. Modular Stage Filtering
    if enabled_stages and len(enabled_stages) > 0:
        # Always allow report writer if any findings were evaluated
        allowed = set(enabled_stages) | {"10.report_writer"}
        if target_step not in allowed:
            return False
    else:
        allowed = SCAN_MODES.get(scan_mode, SCAN_MODES["full"])
        if target_step not in allowed:
            return False

    # 2. Checkpoint Order Check
    if current_step in ("init", "pending", "", None):
        return True
    try:
        curr_idx = PIPELINE_STEPS.index(current_step)
        target_idx = PIPELINE_STEPS.index(target_step)
        return target_idx >= curr_idx
    except ValueError:
        return True


def _record_sensor(context: Dict[str, Any], sensor_name: str, lock: threading.Lock):
    with lock:
        if sensor_name not in context["sensors_executed"]:
            context["sensors_executed"].append(sensor_name)


# =====================================================================
# MODULAR STEP RUNNERS (THREAD-SAFE WORKERS)
# =====================================================================

def step_1_company_resolve(tenant_id: str, job_id: str, context: Dict[str, Any], lock: threading.Lock):
    """Step 1: Company OSINT, DNS zone pointers, MX, SPF, and WHOIS."""
    current_step = context.get("initial_step", "init")
    scan_mode = context.get("scan_mode", "full")
    enabled_stages = context.get("enabled_stages")
    if not _should_run_step(current_step, "1.company_resolve", scan_mode, enabled_stages):
        logger.info(f"[1.company_resolve] Skipping step (not active in '{scan_mode}' mode)")
        return

    _checkpoint_step(tenant_id, job_id, "1.company_resolve")
    root_domain = context["root_domain"]
    scan_params = context.get("scan_params", {})

    logger.info(f"[*] [1.company_resolve] Resolving company & ASN profile for '{root_domain}'")
    company_data = resolve_company_info(root_domain)
    
    with lock:
        context["company_info"] = company_data
    _record_sensor(context, "whois_sensor", lock)

    seed_org = scan_params.get("org_name")
    org_name = seed_org or company_data.get("org_name") or company_data.get("company_name") or root_domain.split(".")[0].capitalize()
    org_slug = re.sub(r"[^a-zA-Z0-9]", "_", org_name.lower())

    with get_db_session() as db:
        add_finding(db, tenant_id, job_id, "company_info", company_data, "info", "recon.company_resolve")
        add_observation(db, tenant_id, job_id, "whois_sensor", company_data)
        whois_ev = add_evidence(
            db,
            tenant_id=tenant_id,
            scan_job_id=job_id,
            source="whois",
            source_type="public_document",
            collector="recon.company_resolve",
            extracted_claim=f"Target domain '{root_domain}' is registered to organization '{org_name}'.",
            raw_reference=company_data,
            reliability=0.95,
        )
        org_entity = upsert_entity(
            db,
            tenant_id=tenant_id,
            scan_job_id=job_id,
            canonical_id=f"organization:{org_slug}",
            entity_type="organization",
            label=org_name,
            properties=company_data,
        )
        domain_entity = upsert_entity(
            db,
            tenant_id=tenant_id,
            scan_job_id=job_id,
            canonical_id=f"domain:{root_domain}",
            entity_type="domain",
            label=root_domain,
            properties={"registrar": company_data.get("registrar", ""), "country": company_data.get("country", "")},
        )
        upsert_relationship(
            db,
            tenant_id=tenant_id,
            scan_job_id=job_id,
            source_entity_id=org_entity.id,
            target_entity_id=domain_entity.id,
            relationship_type="OWNS",
            confidence=0.95,
            status="confirmed",
            supporting_evidence_ids=[whois_ev.id],
        )
    logger.info(f"[+] [1.company_resolve] Finished company profile for '{root_domain}'")


def step_2_subdomains(tenant_id: str, job_id: str, context: Dict[str, Any], lock: threading.Lock):
    """Step 2: Passive and Certificate Transparency Subdomain Enumeration."""
    current_step = context.get("initial_step", "init")
    scan_mode = context.get("scan_mode", "full")
    enabled_stages = context.get("enabled_stages")
    if not _should_run_step(current_step, "2.subdomains", scan_mode, enabled_stages):
        logger.info(f"[2.subdomains] Skipping step (not active in '{scan_mode}' mode)")
        return

    _checkpoint_step(tenant_id, job_id, "2.subdomains")
    root_domain = context["root_domain"]
    target_domain = context["target_domain"]

    logger.info(f"[*] [2.subdomains] Enumerating subdomains for '{root_domain}'")
    subs = enumerate_subdomains(root_domain)
    target_clean = normalize_domain(target_domain)
    if target_clean and not any(s.get("subdomain") == target_clean for s in subs):
        subs.insert(0, {"subdomain": target_clean, "sources": ["seed_target"]})

    with lock:
        context["subdomains"] = subs
    _record_sensor(context, "dns_subdomain_sensor", lock)

    with get_db_session() as db:
        findings_batch = [
            {"type": "subdomain", "data": s, "severity": "info", "source_tool": "recon.subdomains"}
            for s in subs
        ]
        add_findings_batch(db, tenant_id, job_id, findings_batch)
        add_observation(db, tenant_id, job_id, "subdomains", {"count": len(subs), "subdomains": subs})

        dns_ev = add_evidence(
            db,
            tenant_id=tenant_id,
            scan_job_id=job_id,
            source="dns",
            source_type="network_probe",
            collector="recon.subdomains",
            extracted_claim=f"Discovered {len(subs)} subdomains for {root_domain} via certificate transparency and passive DNS.",
            reliability=1.0,
        )
        domain_entity = upsert_entity(
            db,
            tenant_id=tenant_id,
            scan_job_id=job_id,
            canonical_id=f"domain:{root_domain}",
            entity_type="domain",
            label=root_domain,
        )

        for s in subs:
            sub_name = s.get("subdomain")
            if not sub_name:
                continue
            sub_entity = upsert_entity(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                canonical_id=f"domain:{sub_name}",
                entity_type="domain",
                label=sub_name,
                properties=s,
            )
            upsert_relationship(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                source_entity_id=domain_entity.id,
                target_entity_id=sub_entity.id,
                relationship_type="HAS_SUBDOMAIN",
                confidence=1.0,
                status="confirmed",
                supporting_evidence_ids=[dns_ev.id],
            )
    logger.info(f"[+] [2.subdomains] Discovered {len(subs)} subdomains for '{root_domain}'")


def step_3_ip_resolve(tenant_id: str, job_id: str, context: Dict[str, Any], lock: threading.Lock):
    """Step 3: DNS A/AAAA and CDN/WAF Segregation."""
    current_step = context.get("initial_step", "init")
    scan_mode = context.get("scan_mode", "full")
    enabled_stages = context.get("enabled_stages")
    if not _should_run_step(current_step, "3.ip_resolve", scan_mode, enabled_stages):
        logger.info(f"[3.ip_resolve] Skipping step (not active in '{scan_mode}' mode)")
        return

    _checkpoint_step(tenant_id, job_id, "3.ip_resolve")
    root_domain = context["root_domain"]
    with lock:
        subs = context.get("subdomains", [])
        subdomain_names = [s.get("subdomain") for s in subs if s.get("subdomain")]
        if not subdomain_names:
            subdomain_names = [root_domain]

    logger.info(f"[*] [3.ip_resolve] Resolving IPs and CDN fingerprints for {len(subdomain_names)} subdomains")
    resolved_hosts = resolve_subdomain_ips(subdomain_names)

    with lock:
        context["ip_resolutions"] = resolved_hosts
    _record_sensor(context, "dns_ip_sensor", lock)

    with get_db_session() as db:
        findings_batch = [
            {"type": "ip_resolution", "data": h, "severity": "info", "source_tool": "recon.ip_resolve"}
            for h in resolved_hosts
        ]
        add_findings_batch(db, tenant_id, job_id, findings_batch)
        add_observation(db, tenant_id, job_id, "ip_resolutions", {"count": len(resolved_hosts), "hosts": resolved_hosts})

        ip_ev = add_evidence(
            db,
            tenant_id=tenant_id,
            scan_job_id=job_id,
            source="dns_resolver",
            source_type="network_probe",
            collector="recon.ip_resolve",
            extracted_claim=f"Resolved {len(resolved_hosts)} live domain records to IP addresses and cloud edge services.",
            reliability=1.0,
        )

        for h in resolved_hosts:
            sub_name = h.get("subdomain")
            if not sub_name:
                continue
            sub_entity = upsert_entity(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                canonical_id=f"domain:{sub_name}",
                entity_type="domain",
                label=sub_name,
                properties=h,
            )

            # Ingest resolved IP nodes and relationships
            for ip in h.get("ips", []):
                ip_entity = upsert_entity(
                    db,
                    tenant_id=tenant_id,
                    scan_job_id=job_id,
                    canonical_id=f"ip:{ip}",
                    entity_type="ip",
                    label=ip,
                )
                upsert_relationship(
                    db,
                    tenant_id=tenant_id,
                    scan_job_id=job_id,
                    source_entity_id=sub_entity.id,
                    target_entity_id=ip_entity.id,
                    relationship_type="RESOLVES_TO",
                    confidence=1.0,
                    status="confirmed",
                    supporting_evidence_ids=[ip_ev.id],
                )

            # Ingest Cloud / CDN Provider Entity
            if h.get("is_cdn") or h.get("cloud_provider"):
                provider_name = h.get("cdn_provider") or h.get("cloud_provider")
                cloud_slug = re.sub(r"[^a-zA-Z0-9]", "_", provider_name.lower())
                cloud_entity = upsert_entity(
                    db,
                    tenant_id=tenant_id,
                    scan_job_id=job_id,
                    canonical_id=f"cloud_provider:{cloud_slug}",
                    entity_type="cloud_provider",
                    label=provider_name.capitalize(),
                )
                upsert_relationship(
                    db,
                    tenant_id=tenant_id,
                    scan_job_id=job_id,
                    source_entity_id=sub_entity.id,
                    target_entity_id=cloud_entity.id,
                    relationship_type="USES_PROVIDER",
                    confidence=0.95,
                    status="confirmed",
                    supporting_evidence_ids=[ip_ev.id],
                )
    logger.info(f"[+] [3.ip_resolve] Resolved {len(resolved_hosts)} live hosts")


def step_4_ports(tenant_id: str, job_id: str, context: Dict[str, Any], lock: threading.Lock):
    """Step 4: Port & Service Enumeration (Nmap / Masscan). CDN-safeguarded."""
    current_step = context.get("initial_step", "init")
    scan_mode = context.get("scan_mode", "full")
    enabled_stages = context.get("enabled_stages")
    if not _should_run_step(current_step, "4.ports", scan_mode, enabled_stages):
        logger.info(f"[4.ports] Skipping step (not active in '{scan_mode}' mode)")
        return

    _checkpoint_step(tenant_id, job_id, "4.ports")
    root_domain = context["root_domain"]
    
    with lock:
        ip_resolutions = list(context.get("ip_resolutions", []))
        origin_candidates = list(context.get("company_info", {}).get("origin_candidates", []))
        primary_ips = list(context.get("company_info", {}).get("primary_ips", []))
        profile = context.get("scan_profile", "standard")

    non_cdn_ips: Set[str] = set()
    cdn_ips: Set[str] = set()

    # 0. Failsafe Direct IP target inclusion
    try:
        ip_obj = ipaddress.ip_address(root_domain)
        is_priv = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        is_cdn, _ = (False, None) if is_priv else is_cdn_ip(root_domain)
        if not is_cdn:
            non_cdn_ips.add(root_domain)
    except ValueError:
        pass

    # 1. Filter out CDN edge proxy Anycast IPs
    for host in ip_resolutions:
        is_host_cdn = host.get("is_cdn", False)
        for ip in host.get("ips", []):
            is_ip_cdn, _ = is_cdn_ip(ip)
            if is_host_cdn or is_ip_cdn:
                cdn_ips.add(ip)
            else:
                non_cdn_ips.add(ip)

    # 2. Prioritize unmasked origin candidates from Step 1
    for cand in origin_candidates:
        cand_ip = cand.get("ip", "").split("/")[0].strip()
        if cand_ip:
            is_ip_cdn, _ = is_cdn_ip(cand_ip)
            if not is_ip_cdn:
                non_cdn_ips.add(cand_ip)

    # 3. Fallback: check company primary IPs if no CDN-free IPs found
    if not non_cdn_ips and primary_ips:
        for ip in primary_ips:
            is_ip_cdn, _ = is_cdn_ip(ip)
            if not is_ip_cdn:
                non_cdn_ips.add(ip)

    target_ips = non_cdn_ips
    if not target_ips and cdn_ips:
        logger.warning(
            f"[4.ports] All resolved hosts for '{root_domain}' sit behind CDN/WAF ({len(cdn_ips)} Anycast IPs). "
            "Skipping active Nmap/Masscan on CDN edge proxy nodes to prevent SYN-proxy false positives."
        )

    # 4. Asset-Weighted IP Prioritization
    prioritized_ips = prioritize_target_ips(
        target_ips=target_ips,
        ip_resolutions=ip_resolutions,
        origin_candidates=origin_candidates,
    )

    max_ips = 100 if profile == "deep" else 25 if profile == "standard" else 10
    ips_to_scan = prioritized_ips[:max_ips]
    logger.info(f"[*] [4.ports] Starting concurrent port & service scan for {len(ips_to_scan)} prioritized non-CDN target IPs (Profile: {profile.upper()})")

    # 5. Concurrent Multi-Host Execution Pool
    all_ports = scan_multiple_hosts_concurrently(
        ips=ips_to_scan,
        profile=profile,
        max_workers=10 if profile == "deep" else 6 if profile == "standard" else 4,
        timeout=300,
    )

    with lock:
        context["ports"] = all_ports
    _record_sensor(context, "port_service_sensor", lock)

    with get_db_session() as db:
        findings_batch = [
            {"type": "port", "data": p, "severity": "info", "source_tool": "recon.ports"}
            for p in all_ports
        ]
        add_findings_batch(db, tenant_id, job_id, findings_batch)
        add_observation(db, tenant_id, job_id, "ports", {"count": len(all_ports), "ports": all_ports})

        port_ev = add_evidence(
            db,
            tenant_id=tenant_id,
            scan_job_id=job_id,
            source="nmap",
            source_type="network_probe",
            collector="recon.ports",
            extracted_claim=f"Identified {len(all_ports)} active network ports and service banners.",
            reliability=0.95,
        )

        for p in all_ports:
            ip_addr = p.get("ip")
            port_num = p.get("port")
            proto = p.get("protocol", "tcp")
            service_name = p.get("service") or "unknown"
            product = p.get("product") or service_name
            version = p.get("version") or ""
            banner = p.get("banner") or ""

            port_canonical = f"port:{ip_addr}:{port_num}:{proto}"
            service_canonical = f"service:{ip_addr}:{port_num}:{service_name}"

            ip_entity = upsert_entity(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                canonical_id=f"ip:{ip_addr}",
                entity_type="ip",
                label=ip_addr,
            )
            port_entity = upsert_entity(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                canonical_id=port_canonical,
                entity_type="port",
                label=f"{port_num}/{proto}",
                properties={"port": port_num, "protocol": proto, "ip": ip_addr},
            )
            service_entity = upsert_entity(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                canonical_id=service_canonical,
                entity_type="service",
                label=f"{product} {version}".strip(),
                properties={"service": service_name, "product": product, "version": version, "banner": banner},
            )

            upsert_relationship(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                source_entity_id=ip_entity.id,
                target_entity_id=port_entity.id,
                relationship_type="EXPOSES_PORT",
                confidence=0.98,
                status="confirmed",
                supporting_evidence_ids=[port_ev.id],
            )
            upsert_relationship(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                source_entity_id=port_entity.id,
                target_entity_id=service_entity.id,
                relationship_type="RUNS_SERVICE",
                confidence=0.95,
                status="confirmed",
                supporting_evidence_ids=[port_ev.id],
            )
    logger.info(f"[+] [4.ports] Discovered {len(all_ports)} open ports and services")


def step_5_fingerprint(tenant_id: str, job_id: str, context: Dict[str, Any], lock: threading.Lock):
    """Step 5: Web Application Technology Stack Fingerprinting (HTTPX / Wappalyzer)."""
    current_step = context.get("initial_step", "init")
    scan_mode = context.get("scan_mode", "full")
    enabled_stages = context.get("enabled_stages")
    if not _should_run_step(current_step, "5.fingerprint", scan_mode, enabled_stages):
        logger.info(f"[5.fingerprint] Skipping step (not active in '{scan_mode}' mode)")
        return

    _checkpoint_step(tenant_id, job_id, "5.fingerprint")
    root_domain = context["root_domain"]
    
    with lock:
        ip_res = list(context.get("ip_resolutions", []))
    
    targets_to_fp = [host.get("subdomain") for host in ip_res[:15] if host.get("subdomain")]
    if not targets_to_fp:
        targets_to_fp = [root_domain]

    logger.info(f"[*] [5.fingerprint] Fingerprinting technology stack on {len(targets_to_fp)} web endpoints")
    fp_results = fingerprint_target_urls(targets_to_fp)

    all_technologies = []
    for fp in fp_results:
        tech_list = fp.get("technologies", [])
        for t in tech_list:
            if isinstance(t, dict):
                all_technologies.append(t)
            elif isinstance(t, str):
                all_technologies.append({"name": t, "category": "Web Technology", "confidence": 0.85})

    with lock:
        context["fingerprints"] = fp_results
        context["technologies"] = all_technologies
    _record_sensor(context, "technology_sensor", lock)

    with get_db_session() as db:
        findings_batch = [
            {"type": "fingerprint", "data": fp, "severity": "info", "source_tool": "recon.fingerprint"}
            for fp in fp_results
        ]
        add_findings_batch(db, tenant_id, job_id, findings_batch)
        add_observation(db, tenant_id, job_id, "technology", {"count": len(all_technologies), "tech": all_technologies})

        tech_ev = add_evidence(
            db,
            tenant_id=tenant_id,
            scan_job_id=job_id,
            source="technology_engine",
            source_type="network_probe",
            collector="recon.fingerprint",
            extracted_claim=f"Multi-signal web inspection identified {len(all_technologies)} active software technologies.",
            reliability=0.92,
        )

        domain_entity = upsert_entity(
            db,
            tenant_id=tenant_id,
            scan_job_id=job_id,
            canonical_id=f"domain:{root_domain}",
            entity_type="domain",
            label=root_domain,
        )

        for t in all_technologies:
            t_name = t.get("name", "")
            if not t_name:
                continue
            t_canonical = f"technology:{re.sub(r'[^a-zA-Z0-9]', '_', t_name.lower())}"
            tech_entity = upsert_entity(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                canonical_id=t_canonical,
                entity_type="technology",
                label=f"{t_name} {t.get('version') or ''}".strip(),
                properties=t,
            )
            upsert_relationship(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                source_entity_id=domain_entity.id,
                target_entity_id=tech_entity.id,
                relationship_type="USES_TECHNOLOGY",
                confidence=t.get("confidence", 0.85),
                status="confirmed" if t.get("confidence", 0.85) >= 0.80 else "likely",
                supporting_evidence_ids=[tech_ev.id],
            )
    logger.info(f"[+] [5.fingerprint] Identified {len(all_technologies)} technologies across {len(fp_results)} web assets")


def step_6_nuclei(tenant_id: str, job_id: str, context: Dict[str, Any], lock: threading.Lock):
    """Step 6: Nuclei Template & Modular Application Vulnerability Probing."""
    current_step = context.get("initial_step", "init")
    scan_mode = context.get("scan_mode", "full")
    enabled_stages = context.get("enabled_stages")
    if not _should_run_step(current_step, "6.nuclei_match", scan_mode, enabled_stages):
        logger.info(f"[6.nuclei_match] Skipping step (not active in '{scan_mode}' mode)")
        return

    _checkpoint_step(tenant_id, job_id, "6.nuclei_match")
    root_domain = context["root_domain"]
    
    with lock:
        fingerprints = list(context.get("fingerprints", []))
        ip_resolutions = list(context.get("ip_resolutions", []))
        subdomains = list(context.get("subdomains", []))

    # 1. Collect targets for Nuclei scan
    urls_to_scan = [fp.get("url") for fp in fingerprints if fp.get("url")]
    if not urls_to_scan:
        urls_to_scan = [f"https://{root_domain}"]

    logger.info(f"[*] [6.nuclei_match] Launching Nuclei scans on {len(urls_to_scan[:10])} target endpoints")
    vuln_findings = run_nuclei_scans(urls_to_scan[:10])

    # 2. Run Advanced Application Vulnerability Engine (CORS, GraphQL, SSTI, JS Harvester, Open Redirect)
    all_subdomain_names = [s.get("subdomain") for s in subdomains if s.get("subdomain")]
    if not all_subdomain_names:
        all_subdomain_names = [root_domain]

    logger.info(f"[*] [6.nuclei_match] Running Application Vulnerability Engine across {len(all_subdomain_names)} subdomains (Clustered & Deduplicated)")
    app_vuln_findings = run_app_vuln_scans_sync(
        targets=all_subdomain_names,
        ip_resolutions=ip_resolutions,
        timeout=6.0,
    )

    combined_step6_findings = vuln_findings + app_vuln_findings

    with lock:
        context["nuclei_findings"] = vuln_findings
        context["app_vuln_findings"] = app_vuln_findings
        context.setdefault("vulns", []).extend(combined_step6_findings)
    logger.info(f"[+] [6.nuclei_match] Completed with {len(vuln_findings)} nuclei and {len(app_vuln_findings)} advanced app vuln findings")


def step_7_cve(tenant_id: str, job_id: str, context: Dict[str, Any], lock: threading.Lock):
    """Step 7: CVE Correlation and Red Team Misconfiguration Engine."""
    current_step = context.get("initial_step", "init")
    scan_mode = context.get("scan_mode", "full")
    enabled_stages = context.get("enabled_stages")
    if not _should_run_step(current_step, "7.cve_lookup", scan_mode, enabled_stages):
        logger.info(f"[7.cve_lookup] Skipping step (not active in '{scan_mode}' mode)")
        return

    _checkpoint_step(tenant_id, job_id, "7.cve_lookup")
    
    with lock:
        ports = list(context.get("ports", []))
        technologies = list(context.get("technologies", []))
        ip_resolutions = list(context.get("ip_resolutions", []))
        company_info = dict(context.get("company_info", {}))
        existing_vulns = list(context.get("vulns", []))

    logger.info(f"[*] [7.cve_lookup] Correlating CVEs and auditing service misconfigurations")
    port_vulns = correlate_port_findings_to_vulns(ports)
    evaluated_vulns = []

    # Map subdomains to resolved IP addresses for strict asset attribution
    subdomain_to_ip: Dict[str, str] = {}
    for res in ip_resolutions:
        sub = res.get("subdomain")
        ips = res.get("ips", [])
        if sub and ips:
            subdomain_to_ip[sub] = ips[0]

    # Pre-infer host operating systems across discovered ports
    host_os_map: Dict[str, str] = {}
    for p in ports:
        ip_addr = p.get("ip")
        banner_text = p.get("banner") or ""
        prod_text = p.get("product") or ""
        if ip_addr and ip_addr not in host_os_map:
            inferred = _infer_host_os(banner=banner_text, product=prod_text)
            if inferred != "unknown":
                host_os_map[ip_addr] = inferred

    # 1. Evaluate open ports and banners with host context
    for p in ports:
        ip_addr = p.get("ip")
        product = p.get("product") or p.get("service") or ""
        version = p.get("version") or ""
        h_context = {
            "ip": ip_addr,
            "port": p.get("port"),
            "os": host_os_map.get(ip_addr, "unknown"),
        }
        findings = evaluate_vulnerabilities(
            product=product,
            version=version,
            service=p.get("service", ""),
            evidence_banner=p.get("banner") or f"{product} {version}".strip(),
            host_context=h_context,
        )
        for f in findings:
            f["ip"] = ip_addr
            f["port"] = p.get("port")
            f["service"] = p.get("service")
            evaluated_vulns.append(f)

    # 2. Evaluate web technologies strictly bound to their originating endpoint & host
    fallback_ip = "127.0.0.1"
    non_cdn_ips = [ip_res.get("ips", []) for ip_res in ip_resolutions if not ip_res.get("is_cdn")]
    if non_cdn_ips and non_cdn_ips[0]:
        fallback_ip = non_cdn_ips[0][0]
    elif company_info.get("primary_ips"):
        fallback_ip = company_info["primary_ips"][0]
    elif ip_resolutions and ip_resolutions[0].get("ips"):
        fallback_ip = ip_resolutions[0]["ips"][0]

    with lock:
        fingerprints = list(context.get("fingerprints", []))

    for fp in fingerprints:
        fp_url = fp.get("url", "")
        # Extract host and port from URL
        clean_url_host = re.sub(r"^https?://", "", fp_url).split("/")[0]
        if ":" in clean_url_host:
            host_part, port_str = clean_url_host.split(":", 1)
            try:
                target_port = int(port_str)
            except ValueError:
                target_port = 443 if fp_url.startswith("https") else 80
        else:
            host_part = clean_url_host
            target_port = 443 if fp_url.startswith("https") else 80

        # Strict IP resolution attribution
        bound_ip = subdomain_to_ip.get(host_part)
        if not bound_ip:
            try:
                ipaddress.ip_address(host_part)
                bound_ip = host_part
            except ValueError:
                bound_ip = fallback_ip

        host_os = host_os_map.get(bound_ip, "unknown")
        h_context = {"ip": bound_ip, "port": target_port, "os": host_os}

        # Cross-Stage Reconciliation: If this port responded with live web tech, ensure it exists in ports list
        port_exists = any(
            p.get("ip") == bound_ip and int(p.get("port", 0)) == int(target_port)
            for p in ports
        )
        if not port_exists and bound_ip:
            reconciled_service = "https" if fp_url.startswith("https") or target_port in (443, 8443, 9443) else "http"
            top_tech = fp.get("technologies", [])
            prod_name = "HTTP Web Server"
            prod_ver = ""
            if top_tech:
                first = top_tech[0]
                if isinstance(first, dict):
                    prod_name = first.get("name") or "HTTP Web Server"
                    prod_ver = first.get("version") or ""
                else:
                    prod_name = str(first)

            reconciled_port = {
                "ip": bound_ip,
                "port": int(target_port),
                "protocol": "tcp",
                "service": reconciled_service,
                "product": prod_name,
                "version": prod_ver,
                "banner": f"Live endpoint verified on {fp_url}: {prod_name} {prod_ver}".strip(),
                "state": "open",
                "service_verified": True,
                "detection_method": "l7_live_http_reconciliation",
                "cpe": [],
                "dangerous_methods": [],
                "anonymous_access": False,
                "weak_ciphers": [],
            }
            ports.append(reconciled_port)
            with lock:
                if "ports" in context:
                    context["ports"].append(reconciled_port)

            try:
                with get_db_session() as db:
                    add_finding(
                        db,
                        tenant_id,
                        job_id,
                        "port",
                        reconciled_port,
                        "info",
                        "recon.ports.reconciliation"
                    )
            except Exception as e:
                logger.debug(f"Failed to persist reconciled port finding: {e}")

        for tech in fp.get("technologies", []):
            if isinstance(tech, dict):
                t_name = tech.get("name", "")
                t_ver = tech.get("version", "")
            elif isinstance(tech, str):
                t_name = tech
                t_ver = ""
            else:
                continue

            if t_name:
                tech_findings = evaluate_vulnerabilities(
                    product=t_name,
                    version=t_ver,
                    service="http" if target_port in [80, 8000, 8080, 3000, 5000] else "https",
                    evidence_banner=f"Web inspection on {fp_url}: {t_name} {t_ver}".strip(),
                    host_context=h_context,
                )
                for tf in tech_findings:
                    tf["ip"] = bound_ip
                    tf["port"] = target_port
                    tf["service"] = "https" if target_port == 443 else "http"
                    tf["url"] = fp_url
                    evaluated_vulns.append(tf)

    # 3. Misconfiguration Audits
    ports_by_ip: Dict[str, List[Dict[str, Any]]] = {}
    for p in ports:
        ip_addr = p.get("ip")
        if ip_addr:
            ports_by_ip.setdefault(ip_addr, []).append(p)

    for ip_addr, host_ports in ports_by_ip.items():
        misconfigs = audit_host_misconfigurations(ip_addr, host_ports)
        for m in misconfigs:
            m["ip"] = ip_addr
            evaluated_vulns.append(m)

    all_vulns_to_correlate = existing_vulns + port_vulns + evaluated_vulns
    enriched_vulns = correlate_findings_with_cve_and_owasp(all_vulns_to_correlate)

    with lock:
        context["vulns"] = enriched_vulns
    _record_sensor(context, "vulnerability_sensor", lock)

    with get_db_session() as db:
        findings_batch = [
            {
                "type": "vuln",
                "data": v,
                "severity": v.get("severity", "info"),
                "source_tool": v.get("source_tool", "vuln.cve_lookup"),
            }
            for v in enriched_vulns
        ]
        add_findings_batch(db, tenant_id, job_id, findings_batch)
        add_observation(db, tenant_id, job_id, "vulnerabilities", {"count": len(enriched_vulns), "vulns": enriched_vulns})

        vuln_ev = add_evidence(
            db,
            tenant_id=tenant_id,
            scan_job_id=job_id,
            source="vulnerability_engine",
            source_type="api",
            collector="vuln.cve_lookup",
            extracted_claim=f"Validated {len(enriched_vulns)} candidate vulnerability exposure(s).",
            reliability=0.88,
        )

        for v in enriched_vulns:
            cve_id = v.get("cve_id") or v.get("template_id") or v.get("title", "vuln")
            vuln_canonical = f"vulnerability:{re.sub(r'[^a-zA-Z0-9]', '_', cve_id.lower())}"
            vuln_entity = upsert_entity(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                canonical_id=vuln_canonical,
                entity_type="vulnerability",
                label=cve_id,
                properties=v,
            )
            ip_addr = v.get("ip")
            port_num = v.get("port")
            if ip_addr and port_num:
                service_canonical = f"service:{ip_addr}:{port_num}:{v.get('service', 'unknown')}"
                service_entity = upsert_entity(
                    db,
                    tenant_id=tenant_id,
                    scan_job_id=job_id,
                    canonical_id=service_canonical,
                    entity_type="service",
                    label=f"Service on {ip_addr}:{port_num}",
                )
                upsert_relationship(
                    db,
                    tenant_id=tenant_id,
                    scan_job_id=job_id,
                    source_entity_id=service_entity.id,
                    target_entity_id=vuln_entity.id,
                    relationship_type="POTENTIALLY_AFFECTED_BY",
                    confidence=v.get("confidence", 0.65),
                    status=v.get("status", "potential"),
                    supporting_evidence_ids=[vuln_ev.id],
                )

            # Link all member subdomains in cluster to the vulnerability entity
            for cluster_sub in v.get("cluster_domains", []):
                if cluster_sub:
                    sub_entity = upsert_entity(
                        db,
                        tenant_id=tenant_id,
                        scan_job_id=job_id,
                        canonical_id=f"domain:{cluster_sub}",
                        entity_type="domain",
                        label=cluster_sub,
                    )
                    upsert_relationship(
                        db,
                        tenant_id=tenant_id,
                        scan_job_id=job_id,
                        source_entity_id=sub_entity.id,
                        target_entity_id=vuln_entity.id,
                        relationship_type="HAS_VULNERABILITY",
                        confidence=v.get("confidence", 0.95),
                        status=v.get("status", "confirmed"),
                        supporting_evidence_ids=[vuln_ev.id],
                    )
    logger.info(f"[+] [7.cve_lookup] Enriched {len(enriched_vulns)} vulnerability findings")


def step_8_people(tenant_id: str, job_id: str, context: Dict[str, Any], lock: threading.Lock):
    """Step 8: People Intelligence, Document OSINT & Exposure Signals."""
    current_step = context.get("initial_step", "init")
    scan_mode = context.get("scan_mode", "full")
    enabled_stages = context.get("enabled_stages")
    if not _should_run_step(current_step, "8.people_osint", scan_mode, enabled_stages):
        logger.info(f"[8.people_osint] Skipping step (not active in '{scan_mode}' mode)")
        return

    _checkpoint_step(tenant_id, job_id, "8.people_osint")
    root_domain = context["root_domain"]
    scan_params = context.get("scan_params", {})
    
    with lock:
        company_info = dict(context.get("company_info", {}))
        subs = list(context.get("subdomains", []))

    seed_org = scan_params.get("org_name")
    seed_ceo = scan_params.get("ceo_name")
    resolved_org = seed_org or company_info.get("org_name") or root_domain.split(".")[0].capitalize()
    org_slug = re.sub(r"[^a-zA-Z0-9]", "_", resolved_org.lower())

    subdomain_names = [s.get("subdomain", s) if isinstance(s, dict) else s for s in subs]

    people_data = aggregate_people_osint(
        root_domain,
        org_name=resolved_org,
        seed_ceo=seed_ceo,
        subdomains=subdomain_names,
    )
    employee_candidates = people_data.get("people") or people_data.get("employees", [])
    resolved_persons = resolve_identities(employee_candidates, target_org=resolved_org)

    with lock:
        context["people"] = people_data
    _record_sensor(context, "people_osint_sensor", lock)

    # Eagerly persist People OSINT findings so the frontend streams them in real-time
    with get_db_session() as db:
        add_finding(db, tenant_id, job_id, "people", people_data, "info", "people.aggregate")
        add_observation(db, tenant_id, job_id, "people_osint", people_data)

    docs_data = extract_public_doc_metadata(root_domain, org_name=resolved_org, seed_ceo=seed_ceo, timeout=15)
    cloud_exposures = check_cloud_storage_exposure(root_domain)
    breach_signals = check_breach_exposure_signal(root_domain)

    # Correlate discovered employee emails with public breach signals
    all_discovered_emails = []
    for rp in resolved_persons:
        all_discovered_emails.extend(rp.emails)
    if all_discovered_emails:
        try:
            employee_breaches = correlate_email_breach_signals(all_discovered_emails[:15], timeout=5)
            breach_signals.extend(employee_breaches)
        except Exception as e:
            logger.debug(f"[worker] Employee breach correlation failed: {e}")

    with lock:
        context["documents"] = docs_data
        context["cloud_exposures"] = cloud_exposures
        context["breach_signals"] = breach_signals
    _record_sensor(context, "document_sensor", lock)
    _record_sensor(context, "exposure_sensor", lock)

    with get_db_session() as db:
        people_ev = add_evidence(
            db,
            tenant_id=tenant_id,
            scan_job_id=job_id,
            source="people_osint",
            source_type="direct_profile",
            collector="people.aggregate",
            extracted_claim=f"Identified and resolved {len(resolved_persons)} human personnel associated with '{resolved_org}'.",
            reliability=0.90,
        )

        org_entity = upsert_entity(
            db,
            tenant_id=tenant_id,
            scan_job_id=job_id,
            canonical_id=f"organization:{org_slug}",
            entity_type="organization",
            label=resolved_org,
        )
        domain_entity = upsert_entity(
            db,
            tenant_id=tenant_id,
            scan_job_id=job_id,
            canonical_id=f"domain:{root_domain}",
            entity_type="domain",
            label=root_domain,
        )

        for rp in resolved_persons:
            p_dict = rp.to_dict()
            person_entity = upsert_entity(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                canonical_id=rp.canonical_id,
                entity_type="person",
                label=rp.primary_name,
                properties=p_dict,
            )
            upsert_relationship(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                source_entity_id=org_entity.id,
                target_entity_id=person_entity.id,
                relationship_type="EMPLOYS",
                confidence=rp.confidence,
                status=rp.status,
                supporting_evidence_ids=[people_ev.id],
            )
            for em in rp.emails:
                email_entity = upsert_entity(
                    db,
                    tenant_id=tenant_id,
                    scan_job_id=job_id,
                    canonical_id=f"email:{em}",
                    entity_type="email",
                    label=em,
                    properties={"email": em, "domain": em.split("@")[-1] if "@" in em else ""},
                )
                upsert_relationship(
                    db,
                    tenant_id=tenant_id,
                    scan_job_id=job_id,
                    source_entity_id=person_entity.id,
                    target_entity_id=email_entity.id,
                    relationship_type="USES_EMAIL",
                    confidence=0.92,
                    status="confirmed",
                    supporting_evidence_ids=[people_ev.id],
                )
            for un in rp.usernames:
                user_entity = upsert_entity(
                    db,
                    tenant_id=tenant_id,
                    scan_job_id=job_id,
                    canonical_id=f"username:{un}",
                    entity_type="username",
                    label=un,
                    properties={"username": un},
                )
                upsert_relationship(
                    db,
                    tenant_id=tenant_id,
                    scan_job_id=job_id,
                    source_entity_id=person_entity.id,
                    target_entity_id=user_entity.id,
                    relationship_type="HAS_USERNAME",
                    confidence=0.85,
                    status="likely",
                    supporting_evidence_ids=[people_ev.id],
                )

        # Ingest Document Entities & Forensics
        doc_list = docs_data.get("document_exposures", []) if isinstance(docs_data, dict) else (docs_data if isinstance(docs_data, list) else [])
        for doc in doc_list:
            doc_src = doc.get("url") or doc.get("filename") or "/report.pdf"
            doc_slug = re.sub(r"[^a-zA-Z0-9]", "_", doc_src.lower())
            doc_entity = upsert_entity(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                canonical_id=f"document:{doc_slug[:120]}",
                entity_type="document",
                label=doc.get("filename") or doc_src.split("/")[-1],
                properties=doc,
            )
            upsert_relationship(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                source_entity_id=org_entity.id,
                target_entity_id=doc_entity.id,
                relationship_type="PUBLISHED",
                confidence=0.95,
                status="confirmed",
            )
            for doc_email in doc.get("emails_discovered", []):
                email_ent = upsert_entity(
                    db,
                    tenant_id=tenant_id,
                    scan_job_id=job_id,
                    canonical_id=f"email:{doc_email}",
                    entity_type="email",
                    label=doc_email,
                    properties={"email": doc_email},
                )
                upsert_relationship(
                    db,
                    tenant_id=tenant_id,
                    scan_job_id=job_id,
                    source_entity_id=doc_entity.id,
                    target_entity_id=email_ent.id,
                    relationship_type="CONTAINS_EMAIL",
                    confidence=0.95,
                    status="confirmed",
                )
            doc_author = doc.get("name")
            if doc_author:
                author_slug = re.sub(r"[^a-zA-Z0-9]", "_", doc_author.lower())
                author_ent = upsert_entity(
                    db,
                    tenant_id=tenant_id,
                    scan_job_id=job_id,
                    canonical_id=f"person:{author_slug}",
                    entity_type="person",
                    label=doc_author,
                    properties={"name": doc_author, "source": doc_src},
                )
                upsert_relationship(
                    db,
                    tenant_id=tenant_id,
                    scan_job_id=job_id,
                    source_entity_id=author_ent.id,
                    target_entity_id=doc_entity.id,
                    relationship_type="AUTHORED",
                    confidence=0.88,
                    status="confirmed",
                )

        # Ingest Discovered Corporate Subsidiaries
        subsidiary_list = people_data.get("subsidiaries", [])
        for sub in subsidiary_list:
            sub_dom = sub.get("candidate_domain")
            if sub_dom:
                sub_slug = re.sub(r"[^a-zA-Z0-9]", "_", sub_dom.lower())
                sub_entity = upsert_entity(
                    db,
                    tenant_id=tenant_id,
                    scan_job_id=job_id,
                    canonical_id=f"subsidiary:{sub_slug}",
                    entity_type="organization",
                    label=sub_dom,
                    properties=sub,
                )
                upsert_relationship(
                    db,
                    tenant_id=tenant_id,
                    scan_job_id=job_id,
                    source_entity_id=org_entity.id,
                    target_entity_id=sub_entity.id,
                    relationship_type="OWNS_SUBSIDIARY",
                    confidence=sub.get("confidence_score", 70) / 100.0,
                    status="confirmed" if sub.get("confidence_score", 0) >= 60 else "likely",
                )

        # Ingest Cloud Storage Exposures
        for cs in cloud_exposures:
            cs_slug = re.sub(r"[^a-zA-Z0-9]", "_", cs["resource_url"].lower())
            cloud_entity = upsert_entity(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                canonical_id=f"cloud_resource:{cs_slug}",
                entity_type="cloud_resource",
                label=f"{cs['provider']}: {cs['status']}",
                properties=cs,
            )
            upsert_relationship(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                source_entity_id=org_entity.id,
                target_entity_id=cloud_entity.id,
                relationship_type="ASSOCIATED_WITH",
                confidence=cs["confidence"],
                status="confirmed" if cs["status"] == "ACCESSIBLE" else "likely",
            )
            add_finding(db, tenant_id, job_id, "cloud", cs, cs.get("severity", "medium"), "recon.exposure")

        # Ingest Breach Exposure Signals
        for br in breach_signals:
            b_slug = re.sub(r"[^a-zA-Z0-9]", "_", br.get("breach_name", "breach").lower())
            breach_entity = upsert_entity(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                canonical_id=f"breach:{b_slug}",
                entity_type="breach",
                label=br.get("breach_name", "Data Breach"),
                properties=br,
            )
            raw_conf = br.get("confidence", 0.75)
            conf_val = raw_conf / 100.0 if (isinstance(raw_conf, (int, float)) and raw_conf > 1.0) else float(raw_conf)
            upsert_relationship(
                db,
                tenant_id=tenant_id,
                scan_job_id=job_id,
                source_entity_id=domain_entity.id,
                target_entity_id=breach_entity.id,
                relationship_type="APPEARS_IN",
                confidence=min(1.0, max(0.1, conf_val)),
                status="likely",
            )
            add_finding(db, tenant_id, job_id, "breach", br, br.get("severity", "medium"), "recon.exposure")
    logger.info(f"[+] [8.people_osint] Resolved {len(resolved_persons)} personnel and OSINT signals")


def step_9_ai_triage(tenant_id: str, job_id: str, context: Dict[str, Any], lock: threading.Lock):
    """Step 9: AI Attack Surface Triage Layer (Claude Sonnet)."""
    current_step = context.get("initial_step", "init")
    scan_mode = context.get("scan_mode", "full")
    enabled_stages = context.get("enabled_stages")
    if not _should_run_step(current_step, "9.ai_triage", scan_mode, enabled_stages):
        logger.info(f"[9.ai_triage] Skipping step (not active in '{scan_mode}' mode)")
        return

    _checkpoint_step(tenant_id, job_id, "9.ai_triage")
    logger.info("[*] [9.ai_triage] Synthesizing findings through AI Triage Layer")
    triage_data = triage_findings(context)
    with lock:
        context["triage"] = triage_data
    logger.info("[+] [9.ai_triage] AI Triage complete")


def step_10_report(tenant_id: str, job_id: str, context: Dict[str, Any], lock: threading.Lock):
    """Step 10: Engagement & Executive Report Generation."""
    current_step = context.get("initial_step", "init")
    scan_mode = context.get("scan_mode", "full")
    enabled_stages = context.get("enabled_stages")
    if not _should_run_step(current_step, "10.report_writer", scan_mode, enabled_stages):
        logger.info(f"[10.report_writer] Skipping step (not active in '{scan_mode}' mode)")
        return

    _checkpoint_step(tenant_id, job_id, "10.report_writer")
    logger.info("[*] [10.report_writer] Generating final Markdown engagement report")
    report_markdown = generate_engagement_report(context, context["triage"])
    
    with lock:
        context["report_text"] = report_markdown

    with get_db_session() as db:
        create_ai_report(
            db=db,
            tenant_id=tenant_id,
            scan_job_id=job_id,
            prioritized_findings=context["triage"].get("prioritized_findings", []),
            recommendations=context["triage"].get("executive_summary", ""),
            report_text=report_markdown,
        )
    logger.info("[+] [10.report_writer] Report compiled and persisted to database")


# =====================================================================
# ASYNC DAG PIPELINE ORCHESTRATOR
# =====================================================================

def _sync_tenant_integrations_for_job(tenant_id: str):
    """Loads configured API keys from the tenant_integrations database table into runtime environment."""
    from storage.db import get_tenant_integrations
    try:
        with get_db_session() as db:
            integrations = get_tenant_integrations(db, tenant_id=tenant_id)
            for item in integrations:
                if not item.is_enabled or not item.config:
                    continue
                cfg = item.config
                if item.provider == "censys":
                    if cfg.get("api_id"):
                        os.environ["CENSYS_API_ID"] = str(cfg["api_id"]).strip()
                        settings.CENSYS_API_ID = str(cfg["api_id"]).strip()
                    if cfg.get("api_secret"):
                        os.environ["CENSYS_API_SECRET"] = str(cfg["api_secret"]).strip()
                        settings.CENSYS_API_SECRET = str(cfg["api_secret"]).strip()
                elif item.provider == "github":
                    if cfg.get("token"):
                        os.environ["GITHUB_TOKEN"] = str(cfg["token"]).strip()
                        settings.GITHUB_TOKEN = str(cfg["token"]).strip()
                elif item.provider == "google_search":
                    if cfg.get("api_key"):
                        os.environ["GOOGLE_SEARCH_API_KEY"] = str(cfg["api_key"]).strip()
                        settings.GOOGLE_SEARCH_API_KEY = str(cfg["api_key"]).strip()
                    if cfg.get("engine_id"):
                        os.environ["GOOGLE_SEARCH_ENGINE_ID"] = str(cfg["engine_id"]).strip()
                        settings.GOOGLE_SEARCH_ENGINE_ID = str(cfg["engine_id"]).strip()
                elif item.provider == "serpapi":
                    if cfg.get("api_key"):
                        os.environ["SERPAPI_API_KEY"] = str(cfg["api_key"]).strip()
                        settings.SERPAPI_API_KEY = str(cfg["api_key"]).strip()
                elif item.provider == "ai_gateway":
                    if cfg.get("anthropic_api_key"):
                        os.environ["ANTHROPIC_API_KEY"] = str(cfg["anthropic_api_key"]).strip()
                        settings.ANTHROPIC_API_KEY = str(cfg["anthropic_api_key"]).strip()
                    if cfg.get("openai_api_key"):
                        os.environ["OPENAI_API_KEY"] = str(cfg["openai_api_key"]).strip()
                        settings.OPENAI_API_KEY = str(cfg["openai_api_key"]).strip()
                    if cfg.get("gemini_api_key"):
                        os.environ["GEMINI_API_KEY"] = str(cfg["gemini_api_key"]).strip()
                    if cfg.get("deepseek_api_key"):
                        os.environ["DEEPSEEK_API_KEY"] = str(cfg["deepseek_api_key"]).strip()
                    if cfg.get("model"):
                        os.environ["LITELLM_MODEL"] = str(cfg["model"]).strip()
                        settings.LITELLM_MODEL = str(cfg["model"]).strip()
                elif item.provider == "shodan":
                    if cfg.get("api_key"):
                        os.environ["SHODAN_API_KEY"] = str(cfg["api_key"]).strip()
    except Exception as e:
        logger.debug(f"Failed to sync tenant integrations for job: {e}")


async def execute_pipeline_dag_async(job_id: str, tenant_id: str, target_domain: str) -> bool:
    """
    Executes the multi-stage reconnaissance pipeline as a concurrent DAG.
    Independent branches execute in parallel, bounded by an in-process ThreadPool.
    """
    logger.info(f"[*] [DAG Engine] Starting async scan job '{job_id}' for '{target_domain}' (Tenant: {tenant_id})")
    _sync_tenant_integrations_for_job(tenant_id)
    target_type = classify_target(target_domain)
    root_domain = extract_root_domain(target_domain) if target_type == "domain" else target_domain

    with get_db_session() as db:
        job = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.tenant_id == tenant_id).first()
        if not job:
            logger.error(f"Job {job_id} not found in database")
            return False

        update_scan_job(db, tenant_id, job_id, status="running")
        job.target_type = target_type
        job.normalized_target = root_domain
        initial_step = job.current_step or "init"
        scan_profile = getattr(job, "scan_profile", "standard") or "standard"
        scan_params = getattr(job, "scan_params", {}) or {}
        scan_mode = scan_params.get("scan_mode", "full")
        enabled_stages = scan_params.get("enabled_stages")

        # Smart Auto-Detection for Direct IP Targets:
        # If user provided an IP literal (e.g. 10.251.132.28) and scan_mode is "full",
        # auto-route to "vm_audit" mode for maximum efficiency and precision.
        is_direct_ip = False
        try:
            ipaddress.ip_address(root_domain)
            is_direct_ip = True
        except ValueError:
            pass

        if is_direct_ip and scan_mode == "full" and not enabled_stages:
            scan_mode = "vm_audit"
            logger.info(f"[*] [DAG Engine] Target '{root_domain}' is a direct IP address. Auto-selected [VM_AUDIT] pipeline mode.")

    context: Dict[str, Any] = {
        "job_id": job_id,
        "tenant_id": tenant_id,
        "target_domain": target_domain,
        "target_type": target_type,
        "root_domain": root_domain,
        "scan_profile": scan_profile,
        "scan_mode": scan_mode,
        "enabled_stages": enabled_stages,
        "scan_params": scan_params,
        "initial_step": initial_step,
        "company_info": {},
        "subdomains": [],
        "ip_resolutions": [],
        "ports": [],
        "fingerprints": [],
        "technologies": [],
        "vulns": [],
        "people": {},
        "documents": [],
        "cloud_exposures": [],
        "breach_signals": [],
        "triage": {},
        "report_text": "",
        "sensors_executed": [],
    }

    # Restore existing findings if resuming
    with get_db_session() as db:
        existing_findings = get_findings_for_job(db, tenant_id=tenant_id, scan_job_id=job_id)
        for f in existing_findings:
            if f.type == "company_info":
                context["company_info"] = f.data
            elif f.type == "subdomain":
                context["subdomains"].append(f.data)
            elif f.type == "ip_resolution":
                context["ip_resolutions"].append(f.data)
            elif f.type == "port":
                context["ports"].append(f.data)
            elif f.type == "fingerprint":
                context["fingerprints"].append(f.data)
            elif f.type == "vuln":
                context["vulns"].append(f.data)
            elif f.type == "people":
                context["people"] = f.data

    lock = threading.Lock()
    loop = asyncio.get_running_loop()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="r7-dag")

    try:
        # -------------------------------------------------------------
        # Phase 1: Initial Parallel Reconnaissance
        # Launch Track A (Company Resolve), Track B (Subdomains), and Track C (People OSINT & Exposure) simultaneously
        # -------------------------------------------------------------
        _check_if_aborted(tenant_id, job_id)
        task_company = loop.run_in_executor(executor, step_1_company_resolve, tenant_id, job_id, context, lock)
        task_subdomains = loop.run_in_executor(executor, step_2_subdomains, tenant_id, job_id, context, lock)
        task_people = loop.run_in_executor(executor, step_8_people, tenant_id, job_id, context, lock)

        # -------------------------------------------------------------
        # Phase 2: Subdomain Handoff -> IP Resolve
        # Once subdomains are known, start IP resolution
        # -------------------------------------------------------------
        await task_subdomains
        _check_if_aborted(tenant_id, job_id)
        task_ip_resolve = loop.run_in_executor(executor, step_3_ip_resolve, tenant_id, job_id, context, lock)

        # -------------------------------------------------------------
        # Phase 3: Network Probing (Ports) & Web Fingerprinting (HTTPX)
        # As soon as IPs are resolved, launch Ports and Web Fingerprint in parallel
        # -------------------------------------------------------------
        await task_ip_resolve
        _check_if_aborted(tenant_id, job_id)
        task_ports = loop.run_in_executor(executor, step_4_ports, tenant_id, job_id, context, lock)
        task_fingerprint = loop.run_in_executor(executor, step_5_fingerprint, tenant_id, job_id, context, lock)

        # -------------------------------------------------------------
        # Phase 4: Web Nuclei Scans vs. Service CVE Correlation
        # As soon as Web Fingerprinting finishes, kick off Nuclei!
        # When Ports finish, run CVE correlation!
        # -------------------------------------------------------------
        async def run_nuclei_branch():
            await task_fingerprint
            _check_if_aborted(tenant_id, job_id)
            return await loop.run_in_executor(executor, step_6_nuclei, tenant_id, job_id, context, lock)

        async def run_cve_branch():
            await asyncio.gather(task_ports, task_fingerprint)
            _check_if_aborted(tenant_id, job_id)
            return await loop.run_in_executor(executor, step_7_cve, tenant_id, job_id, context, lock)

        task_nuclei = asyncio.create_task(run_nuclei_branch())
        task_cve = asyncio.create_task(run_cve_branch())

        # -------------------------------------------------------------
        # Phase 5: Global Synchronization Barrier
        # Wait for all parallel upstream branches to complete
        # -------------------------------------------------------------
        await asyncio.gather(task_company, task_people, task_nuclei, task_cve)
        _check_if_aborted(tenant_id, job_id)

        # -------------------------------------------------------------
        # Phase 6: Final Convergence (AI Triage & Executive Report)
        # -------------------------------------------------------------
        await loop.run_in_executor(executor, step_9_ai_triage, tenant_id, job_id, context, lock)
        _check_if_aborted(tenant_id, job_id)
        await loop.run_in_executor(executor, step_10_report, tenant_id, job_id, context, lock)

        # Mark Job Complete
        with get_db_session() as db:
            job = update_scan_job(db, tenant_id, job_id, status="complete", current_step="completed", completed=True)
            if job:
                job.sensors_used = context.get("sensors_executed", [])
                db.commit()

        logger.info(f"[+] [DAG Engine] Successfully completed scan job '{job_id}' for '{target_domain}'")
        return True

    except ScanAbortedException as e:
        logger.info(f"[-] [DAG Engine] Scan job '{job_id}' was aborted by operator.")
        with get_db_session() as db:
            update_scan_job(db, tenant_id, job_id, status="cancelled", current_step="aborted", completed=True, error_message="Scan execution was gracefully aborted by operator.")
        return False
    except Exception as e:
        err_msg = f"Pipeline execution failed: {str(e)}\n{traceback.format_exc()}"
        logger.error(err_msg)
        with get_db_session() as db:
            update_scan_job(db, tenant_id, job_id, status="failed", error_message=str(e))
        return False
    finally:
        executor.shutdown(wait=False)


def execute_pipeline_for_job(job_id: str, tenant_id: str, target_domain: str) -> bool:
    """Synchronous entry point that runs the async DAG pipeline."""
    try:
        return asyncio.run(execute_pipeline_dag_async(job_id, tenant_id, target_domain))
    except RuntimeError:
        # If an event loop is already running in current thread
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(execute_pipeline_dag_async(job_id, tenant_id, target_domain))


def poll_and_process_jobs(max_iterations: Optional[int] = None):
    """
    Main worker polling loop. Scans DB for pending jobs and processes them.
    """
    init_db()
    try:
        extract_root_domain("example.com")  # Pre-warm TLD suffix cache
    except Exception:
        pass
    logger.info("[*] R7 Async Worker started. Polling for pending scan jobs...")


    iteration = 0
    while True:
        try:
            with get_db_session() as db:
                pending_job = (
                    db.query(ScanJob)
                    .filter(ScanJob.status == "pending")
                    .order_by(ScanJob.created_at.asc())
                    .first()
                )
                if pending_job:
                    job_id = pending_job.id
                    tenant_id = pending_job.tenant_id
                    target_domain = pending_job.target_domain
                else:
                    job_id = None

            if job_id:
                execute_pipeline_for_job(job_id, tenant_id, target_domain)
            else:
                time.sleep(settings.WORKER_POLL_INTERVAL_SECONDS)

        except KeyboardInterrupt:
            logger.info("Worker stopped by operator.")
            break
        except Exception as e:
            logger.error(f"Worker poll loop error: {e}")
            time.sleep(settings.WORKER_POLL_INTERVAL_SECONDS)

        iteration += 1
        if max_iterations and iteration >= max_iterations:
            break


if __name__ == "__main__":
    poll_and_process_jobs()
