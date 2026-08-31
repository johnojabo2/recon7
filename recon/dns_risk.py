import logging
import socket
from typing import Dict, Any, List, Optional
import dns.resolver
import dns.query
import dns.zone
import dns.exception

logger = logging.getLogger(__name__)


def assess_dns_risks(domain: str, nameservers: List[str], timeout: int = 4) -> Dict[str, Any]:
    """
    Submodule: Probes authoritative nameservers for DNS Zone Transfer (AXFR) vulnerability
    and tests for dangling / orphaned nameservers (NS takeover risk).
    """
    logger.info(f"[recon.dns_risk] Testing AXFR zone transfers and NS hygiene for '{domain}' on {len(nameservers)} nameservers")

    result: Dict[str, Any] = {
        "domain": domain,
        "axfr_vulnerable": False,
        "axfr_verdict": "Passed / Protected (Zone Transfer Refused on all Authoritative Nameservers)",
        "axfr_tested_servers": [],
        "orphaned_nameservers": [],
        "has_orphaned_ns": False,
        "dnssec_status": "Unsigned / Standard (No DNSSEC Records)",
    }

    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

    # 1. Check DNSSEC
    try:
        ds_answers = resolver.resolve(domain, "DS")
        if len(ds_answers) > 0:
            result["dnssec_status"] = "Signed / Protected (DS Record Validated)"
    except Exception:
        result["dnssec_status"] = "Unsigned / Standard (No DNSSEC Records)"

    # 2. Test AXFR and Orphaned status on each Authoritative Nameserver
    for ns in nameservers:
        ns_clean = ns.rstrip(".")
        ns_ips = []
        
        # Resolve NS IP
        try:
            a_answers = resolver.resolve(ns_clean, "A")
            ns_ips = [str(r) for r in a_answers]
        except Exception:
            result["orphaned_nameservers"].append({
                "nameserver": ns_clean,
                "risk": "CRITICAL: Nameserver hostname does not resolve to an IP address (Orphaned NS / Hijack Vector)"
            })
            result["has_orphaned_ns"] = True
            continue

        for ns_ip in ns_ips:
            axfr_status = "Refused / Secure (RCODE: REFUSED or Dropped)"
            records_dumped = 0

            try:
                xfr = dns.query.xfr(ns_ip, domain, timeout=timeout, lifetime=timeout)
                zone = dns.zone.from_xfr(xfr)
                if zone:
                    records_dumped = len(zone.nodes)
                    if records_dumped > 0:
                        axfr_status = f"VULNERABLE (Full Zone Dumped: {records_dumped} nodes)"
                        result["axfr_vulnerable"] = True
                        result["axfr_verdict"] = f"CRITICAL: Unauthenticated DNS Zone Transfer Allowed on {ns_clean} ({ns_ip})"
            except Exception:
                axfr_status = "Refused / Secure (RCODE: REFUSED or Dropped)"

            result["axfr_tested_servers"].append({
                "nameserver": ns_clean,
                "ip": ns_ip,
                "axfr_status": axfr_status,
                "records_dumped": records_dumped,
            })

    logger.info(f"[recon.dns_risk] AXFR Assessment for '{domain}': Vulnerable={result['axfr_vulnerable']}, Orphaned={result['has_orphaned_ns']}")
    return result
