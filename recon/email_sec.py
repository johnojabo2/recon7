import logging
import re
from typing import Dict, Any, List, Optional
import dns.resolver

logger = logging.getLogger(__name__)

# Common DKIM Selectors to probe across corporate domains
COMMON_DKIM_SELECTORS = [
    "google", "k1", "s1", "s2", "zoho", "zmail", "default",
    "mail", "smtp", "dkim", "sendgrid", "mandrill", "mailgun",
    "m1", "cm", "email", "pm", "selector1", "selector2", "hubspot"
]


def analyze_email_security(domain: str, timeout: int = 4) -> Dict[str, Any]:
    """
    Submodule: Evaluates DMARC policy, spoofability risk, and probes common DKIM selectors.
    Provides actionable phishing feasibility telemetry for red team assessments.
    """
    logger.info(f"[recon.email_sec] Analyzing DMARC policy & DKIM selectors for '{domain}'")
    
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    result: Dict[str, Any] = {
        "domain": domain,
        "dmarc_record": None,
        "dmarc_policy": "none",
        "dmarc_subdomain_policy": None,
        "dmarc_pct": 100,
        "dmarc_rua": None,
        "dmarc_ruf": None,
        "dmarc_aspf": "r",  # relaxed by default
        "dmarc_adkim": "r",
        "spoofable": True,
        "spoofability_verdict": "Vulnerable / High Risk (No Enforced DMARC Policy)",
        "spoofability_score": "HIGH_FEASIBILITY",
        "discovered_dkim_selectors": [],
    }

    # 1. Query and parse _dmarc TXT record
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_answers:
            txt_str = "".join([
                part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                for part in rdata.strings
            ]).strip()
            
            if "v=dmarc1" in txt_str.lower():
                result["dmarc_record"] = txt_str
                
                # Parse tags
                tags = [t.strip() for t in txt_str.split(";") if t.strip()]
                for tag in tags:
                    if "=" in tag:
                        k, v = tag.split("=", 1)
                        k = k.strip().lower()
                        v = v.strip()
                        if k == "p":
                            result["dmarc_policy"] = v.lower()
                        elif k == "sp":
                            result["dmarc_subdomain_policy"] = v.lower()
                        elif k == "pct":
                            try:
                                result["dmarc_pct"] = int(v)
                            except ValueError:
                                pass
                        elif k == "rua":
                            result["dmarc_rua"] = v
                        elif k == "ruf":
                            result["dmarc_ruf"] = v
                        elif k == "aspf":
                            result["dmarc_aspf"] = v.lower()
                        elif k == "adkim":
                            result["dmarc_adkim"] = v.lower()
                break
    except Exception as e:
        logger.debug(f"DMARC query failed for _dmarc.{domain}: {e}")

    # 2. Evaluate Phishing & Spoofability Feasibility
    policy = result["dmarc_policy"]
    pct = result["dmarc_pct"]
    
    if not result["dmarc_record"]:
        result["spoofable"] = True
        result["spoofability_verdict"] = "Vulnerable (No DMARC Record Published - Direct Inbound Spoofing Possible)"
        result["spoofability_score"] = "HIGH_FEASIBILITY"
    elif policy == "none":
        result["spoofable"] = True
        result["spoofability_verdict"] = "Spoofable (DMARC p=none Monitoring Mode Only - Mail Not Rejected by Gateways)"
        result["spoofability_score"] = "HIGH_FEASIBILITY"
    elif policy == "quarantine":
        if pct < 100:
            result["spoofable"] = True
            result["spoofability_verdict"] = f"Partial Risk (DMARC p=quarantine at {pct}% Enforcement)"
            result["spoofability_score"] = "MODERATE_FEASIBILITY"
        else:
            result["spoofable"] = False
            result["spoofability_verdict"] = "Quarantined (DMARC p=quarantine 100% - Spoofed Mails Routed to Spam)"
            result["spoofability_score"] = "LOW_FEASIBILITY"
    elif policy == "reject":
        if pct < 100:
            result["spoofable"] = True
            result["spoofability_verdict"] = f"Partial Risk (DMARC p=reject at {pct}% Enforcement)"
            result["spoofability_score"] = "MODERATE_FEASIBILITY"
        else:
            result["spoofable"] = False
            result["spoofability_verdict"] = "Enforced / Protected (DMARC p=reject 100% - Gateways Drop Unauthorized Senders)"
            result["spoofability_score"] = "BLOCKED"

    # 3. Probe common DKIM selectors concurrently
    discovered_dkim = []
    for sel in COMMON_DKIM_SELECTORS:
        dkim_target = f"{sel}._domainkey.{domain}"
        try:
            dkim_answers = resolver.resolve(dkim_target, "TXT")
            for rdata in dkim_answers:
                txt_str = "".join([
                    part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                    for part in rdata.strings
                ]).strip()
                if "v=dkim1" in txt_str.lower() or "k=rsa" in txt_str.lower() or "p=" in txt_str.lower():
                    # Extract key type
                    k_type = "rsa"
                    k_match = re.search(r"k=([a-zA-Z0-9]+)", txt_str, re.IGNORECASE)
                    if k_match:
                        k_type = k_match.group(1).lower()
                    
                    discovered_dkim.append({
                        "selector": sel,
                        "record": dkim_target,
                        "key_type": k_type.upper(),
                        "raw": txt_str[:60] + "..." if len(txt_str) > 60 else txt_str
                    })
                    break
        except Exception:
            continue

    result["discovered_dkim_selectors"] = discovered_dkim
    logger.info(f"[recon.email_sec] DMARC Policy for '{domain}': p={result['dmarc_policy']}, Spoofable: {result['spoofable']}, DKIM Selectors: {len(discovered_dkim)}")
    return result
