import ipaddress
import logging
import socket
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import httpx
import dns.resolver
from recon.origin_extractor import extract_origin_intelligence, map_cname_infrastructure
from recon.email_sec import analyze_email_security
from recon.tls_intel import extract_tls_certificate_intel
from recon.dns_risk import assess_dns_risks

logger = logging.getLogger(__name__)

# Known Privacy Proxy Services
PRIVACY_PROXIES = [
    "markmonitor", "domains by proxy", "privacyguardian", "withheld for privacy",
    "whoisguard", "cloudflare privacy", "amazon privacy", "super privacy",
    "contact privacy", "privacy service", "redacted for privacy", "data protected"
]

# Known Shared Multi-Tenant CDN ASNs
SHARED_CDN_ASNS = {
    "AS13335": "Cloudflare Global Anycast Edge (Shared Multi-Tenant)",
    "AS20940": "Akamai International CDN Edge (Shared Multi-Tenant)",
    "AS33905": "Akamai Technologies CDN Edge (Shared Multi-Tenant)",
    "AS54113": "Fastly Anycast Edge CDN (Shared Multi-Tenant)",
    "AS16509": "Amazon Web Services Anycast Edge (Shared Multi-Tenant)",
    "AS15169": "Google LLC Global Infrastructure",
    "AS8075": "Microsoft Corporation Anycast Network",
}


def resolve_company_info(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Step 1: Resolve owning organization, structured WHOIS telemetry, ASN, BGP CIDR ranges,
    DNSSEC status, Registrar Abuse contact, DMARC/DKIM email posture, TLS certificate intel,
    AXFR zone transfer risks, privacy proxy detection, and correlated lifecycle hijack scoring.
    """
    # 0. Fast-Path: If target is a direct IP address / Private VM, return clean host profile
    try:
        ip_obj = ipaddress.ip_address(domain.strip())
        is_priv = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        net_type = "Private RFC 1918 Network / Local VM" if is_priv else "Public IP Host"
        logger.info(f"[recon.company_resolve] Target '{domain}' is a direct IP address ({net_type}).")
        return {
            "domain": domain,
            "org_name": f"Host ({domain})",
            "asn": "Private Network" if is_priv else None,
            "asn_description": "Local Private Subnet / Virtual Machine" if is_priv else "Direct IP Target",
            "asn_infrastructure_type": net_type,
            "cidr_ranges": [f"{domain}/32"],
            "registrar": "Internal Network (RFC 1918)" if is_priv else "Direct IP Allocation",
            "registrar_iana_id": None,
            "registration_date": None,
            "expiration_date": None,
            "days_until_expiration": None,
            "nameservers": [],
            "dnssec": False,
            "registrant_organization": "Internal Host Machine",
            "abuse_email": None,
            "is_privacy_protected": False,
            "privacy_provider": None,
            "primary_ips": [domain],
            "origin_candidates": [{"ip": domain, "source": "direct_ip_target", "confidence": 1.0}],
            "email_security": {},
            "tls_intel": {},
            "dns_risks": {},
        }
    except ValueError:
        pass

    logger.info(f"[recon.company_resolve] Resolving rich enterprise target intel & WHOIS for '{domain}'")
    
    result: Dict[str, Any] = {
        "domain": domain,
        "org_name": "Unknown",
        "asn": None,
        "asn_description": None,
        "asn_infrastructure_type": "Dedicated Corporate Network",
        "cidr_ranges": [],
        "registrar": None,
        "registrar_iana_id": None,
        "registration_date": None,
        "expiration_date": None,
        "domain_age_years": None,
        "days_until_expiry": None,
        "is_expiring_soon": False,
        "status_codes": [],
        "abuse_contact_email": None,
        "abuse_contact_phone": None,
        "dnssec": "Unsigned / Standard",
        "nameservers": [],
        "country": None,
        "registrant_country": None,
        "is_privacy_proxied": False,
        "privacy_proxy_service": None,
        "domain_lifecycle_risk": {},
        "primary_ips": [],
        "origin_candidates": [],
        "mail_servers": [],
        "spf_record": None,
        "root_cname_mapping": None,
        "email_security": {},
        "tls_intel": {},
        "dns_risks": {},
    }

    # 1. Resolve Primary IPs, Nameservers, and DNSSEC via DNS
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = min(timeout, 3)
        resolver.lifetime = min(timeout, 3)
        resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
        
        # A records
        try:
            a_answers = resolver.resolve(domain, "A")
            result["primary_ips"] = [str(rdata) for rdata in a_answers]
        except Exception:
            pass

        # NS records
        try:
            ns_answers = resolver.resolve(domain, "NS")
            result["nameservers"] = [str(rdata).rstrip(".") for rdata in ns_answers]
        except Exception:
            pass

        # DNSSEC DS query
        try:
            ds_answers = resolver.resolve(domain, "DS")
            if len(ds_answers) > 0:
                result["dnssec"] = "Signed / Protected"
        except Exception:
            result["dnssec"] = "Unsigned / Standard"

    except Exception as e:
        logger.warning(f"DNS resolution failed for {domain}: {e}")

    # 2. Structured Domain RDAP & WHOIS Query (Free ICANN/Registry RDAP)
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            rdap_url = f"https://rdap.org/domain/{domain}"
            resp = client.get(rdap_url, headers={"User-Agent": "R7-ReconEngine/1.0"})
            if resp.status_code == 200:
                data = resp.json()
                
                # Status codes (e.g. clientTransferProhibited)
                status_list = data.get("status", [])
                if isinstance(status_list, list):
                    result["status_codes"] = [s.strip() for s in status_list if isinstance(s, str)]

                # Registrar & Contact Entities
                entities = data.get("entities", [])
                for entity in entities:
                    roles = entity.get("roles", [])
                    vcard = entity.get("vcardArray", [])
                    name = _extract_vcard_name(vcard)
                    email = _extract_vcard_email(vcard)
                    phone = _extract_vcard_phone(vcard)
                    country = _extract_vcard_country(vcard)
                    
                    if "registrar" in roles:
                        if name:
                            result["registrar"] = name
                        public_ids = entity.get("publicIds", [])
                        for pid in public_ids:
                            if pid.get("type") == "IANA Registrar ID":
                                result["registrar_iana_id"] = pid.get("identifier")
                                
                    elif "abuse" in roles:
                        if email:
                            result["abuse_contact_email"] = email
                        if phone:
                            result["abuse_contact_phone"] = phone

                    elif ("registrant" in roles or "administrative" in roles) and name:
                        result["org_name"] = name
                        if country:
                            result["registrant_country"] = country
                        
                # Registration & Expiration Events
                events = data.get("events", [])
                for ev in events:
                    action = ev.get("eventAction")
                    date_str = ev.get("eventDate")
                    if action == "registration" and date_str:
                        result["registration_date"] = date_str
                    elif action == "expiration" and date_str:
                        result["expiration_date"] = date_str

    except Exception as e:
        logger.warning(f"RDAP domain lookup failed for {domain}: {e}")

    # Detect Privacy Proxy Services
    combined_strings = f"{result['org_name']} {result['registrar']}".lower()
    for proxy in PRIVACY_PROXIES:
        if proxy in combined_strings:
            result["is_privacy_proxied"] = True
            result["privacy_proxy_service"] = proxy.title()
            break

    # Calculate Domain Age and Expiry Metrics
    now = datetime.now(timezone.utc)
    if result["registration_date"]:
        try:
            reg_dt = _parse_iso_date(result["registration_date"])
            if reg_dt:
                age_days = (now - reg_dt).days
                result["domain_age_years"] = round(age_days / 365.25, 1)
        except Exception:
            pass

    if result["expiration_date"]:
        try:
            exp_dt = _parse_iso_date(result["expiration_date"])
            if exp_dt:
                days_left = (exp_dt - now).days
                result["days_until_expiry"] = days_left
                result["is_expiring_soon"] = 0 < days_left <= 60
        except Exception:
            pass

    # Correlated Domain Lifecycle & Hijack Risk Score
    has_transfer_lock = any("transferprohibited" in s.lower().replace(" ", "") for s in result["status_codes"])
    days_left = result["days_until_expiry"] or 999
    
    if not has_transfer_lock and days_left <= 30:
        result["domain_lifecycle_risk"] = {
            "level": "HIGH",
            "score": "CRITICAL / HIGH HIJACK RISK",
            "reason": f"Domain is UNLOCKED (Transfer Allowed) and expiring in {days_left} days. High risk for unauthorized transfer or expiration sniping.",
        }
    elif not has_transfer_lock or days_left <= 60:
        result["domain_lifecycle_risk"] = {
            "level": "MEDIUM",
            "score": "MODERATE RISK",
            "reason": f"{'Domain lacks clientTransferProhibited lock' if not has_transfer_lock else f'Expiring soon ({days_left} days remaining)'}.",
        }
    else:
        result["domain_lifecycle_risk"] = {
            "level": "LOW",
            "score": "LOW RISK (LOCKED & PROTECTED)",
            "reason": f"Transfer locks active ({', '.join(result['status_codes'])}) with {days_left} days remaining until expiration.",
        }

    # 3. ASN & Network CIDR lookup using Cymru DNS or RDAP on first IP
    if result["primary_ips"]:
        first_ip = result["primary_ips"][0]
        ip_info = _lookup_ip_asn(first_ip, timeout=timeout)
        asn_str = ip_info.get("asn")
        result["asn"] = asn_str
        result["asn_description"] = ip_info.get("asn_description") or ip_info.get("org")
        if ip_info.get("cidr"):
            result["cidr_ranges"].append(ip_info["cidr"])
        if ip_info.get("country"):
            result["country"] = ip_info["country"]
            
        if result["org_name"] == "Unknown" and ip_info.get("org"):
            result["org_name"] = ip_info["org"]

        # Classify Shared CDN vs Dedicated Origin
        if asn_str and asn_str in SHARED_CDN_ASNS:
            result["asn_infrastructure_type"] = SHARED_CDN_ASNS[asn_str]
        else:
            result["asn_infrastructure_type"] = f"Dedicated / Independent Network ({result['asn_description'] or 'Custom Autonomous System'})"

    # 4. MX & SPF Origin IP Extractor
    try:
        origin_data = extract_origin_intelligence(domain, timeout=min(timeout, 5))
        result["origin_candidates"] = origin_data.get("origin_candidates", [])
        result["mail_servers"] = origin_data.get("mail_servers", [])
        result["spf_record"] = origin_data.get("spf_record")
    except Exception as e:
        logger.debug(f"Origin intelligence extraction failed: {e}")

    # 5. Email Security & Phishing Feasibility (DMARC & DKIM)
    try:
        result["email_security"] = analyze_email_security(domain, timeout=min(timeout, 4))
    except Exception as e:
        logger.debug(f"Email security analysis failed: {e}")

    # 6. Live TLS Certificate Intelligence
    try:
        result["tls_intel"] = extract_tls_certificate_intel(domain, port=443, timeout=min(timeout, 4))
    except Exception as e:
        logger.debug(f"TLS certificate extraction failed: {e}")

    # 7. DNS Risks & AXFR Zone Transfer Checks
    try:
        result["dns_risks"] = assess_dns_risks(domain, result["nameservers"], timeout=min(timeout, 4))
    except Exception as e:
        logger.debug(f"DNS risk assessment failed: {e}")

    # 8. Root CNAME Cloud Mapping
    try:
        result["root_cname_mapping"] = map_cname_infrastructure(domain, timeout=3)
    except Exception:
        pass

    logger.info(f"[recon.company_resolve] Result for '{domain}': Org={result['org_name']}, DMARC={result.get('email_security', {}).get('dmarc_policy')}, TLS_Issuer={result.get('tls_intel', {}).get('issuer_cn')}")
    return result


def _parse_iso_date(dt_str: str) -> Optional[datetime]:
    """Parses ISO date string into datetime object."""
    clean = dt_str.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(clean)
    except Exception:
        try:
            return datetime.strptime(clean[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except Exception:
            return None


def _extract_vcard_name(vcard_array: List[Any]) -> Optional[str]:
    """Helper to extract formatted name from jCard/vCard JSON array."""
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return None
    for item in vcard_array[1]:
        if isinstance(item, list) and len(item) >= 4:
            if item[0] in ("fn", "org"):
                return str(item[3])
    return None


def _extract_vcard_email(vcard_array: List[Any]) -> Optional[str]:
    """Helper to extract email address from jCard/vCard JSON array."""
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return None
    for item in vcard_array[1]:
        if isinstance(item, list) and len(item) >= 4:
            if item[0] == "email":
                return str(item[3])
    return None


def _extract_vcard_phone(vcard_array: List[Any]) -> Optional[str]:
    """Helper to extract telephone from jCard/vCard JSON array."""
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return None
    for item in vcard_array[1]:
        if isinstance(item, list) and len(item) >= 4:
            if item[0] == "tel":
                return str(item[3])
    return None


def _extract_vcard_country(vcard_array: List[Any]) -> Optional[str]:
    """Helper to extract country code / address from jCard/vCard JSON array."""
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return None
    for item in vcard_array[1]:
        if isinstance(item, list) and len(item) >= 4:
            if item[0] == "adr" and isinstance(item[3], list) and len(item[3]) >= 7:
                return str(item[3][6])  # Country is 7th element in jCard adr array
    return None


def _lookup_ip_asn(ip_str: str, timeout: int = 5) -> Dict[str, Any]:
    """Queries IP RDAP / Cymru DNS for ASN, Organization, and CIDR."""
    info: Dict[str, Any] = {}
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(f"https://rdap.org/ip/{ip_str}", headers={"User-Agent": "R7-ReconEngine/1.0"})
            if resp.status_code == 200:
                data = resp.json()
                info["cidr"] = data.get("handle")
                info["country"] = data.get("country")
                info["org"] = data.get("name")
                
                entities = data.get("entities", [])
                for entity in entities:
                    vcard = entity.get("vcardArray", [])
                    name = _extract_vcard_name(vcard)
                    if name and not info.get("org"):
                        info["org"] = name
    except Exception as e:
        logger.debug(f"IP RDAP failed for {ip_str}: {e}")

    try:
        octets = ip_str.split(".")
        if len(octets) == 4:
            reversed_ip = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.origin.asn.cymru.com"
            answers = dns.resolver.resolve(reversed_ip, "TXT", lifetime=timeout)
            for rdata in answers:
                txt = str(rdata).strip('"')
                parts = [p.strip() for p in txt.split("|")]
                if len(parts) >= 3:
                    info["asn"] = f"AS{parts[0]}"
                    info["cidr"] = parts[1]
                    info["country"] = parts[2]
    except Exception:
        pass

    return info
