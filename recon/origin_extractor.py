import logging
import re
from typing import List, Dict, Any, Optional, Set, Tuple
import dns.resolver
import httpx

logger = logging.getLogger(__name__)

# Known Cloud and SaaS CNAME Fingerprints
CNAME_FINGERPRINTS = [
    (r".*s3.*\.amazonaws\.com|.*\.s3-website.*\.amazonaws\.com", "AWS S3 Bucket", "Amazon Web Services"),
    (r".*\.cloudfront\.net", "AWS CloudFront CDN", "Amazon Web Services"),
    (r".*\.azurewebsites\.net|.*\.trafficmanager\.net|.*\.blob\.core\.windows\.net", "Azure Cloud Services", "Microsoft Azure"),
    (r".*\.herokuapp\.com|.*\.herokussl\.com", "Heroku Dyno", "Salesforce Heroku"),
    (r".*\.github\.io", "GitHub Pages", "GitHub"),
    (r".*\.myshopify\.com|.*\.shopify\.com", "Shopify Store", "Shopify"),
    (r".*\.ghost\.io", "Ghost Blog Hosting", "Ghost Foundation"),
    (r".*\.vercel\.app|.*\.vercel-dns\.com", "Vercel Edge Platform", "Vercel"),
    (r".*\.netlify\.app|.*\.netlifyglobalcdn\.com", "Netlify Edge", "Netlify"),
    (r".*\.wpengine\.com", "WP Engine Managed WordPress", "WP Engine"),
    (r".*\.hubspot\.net", "HubSpot CMS", "HubSpot"),
    (r".*\.zendesk\.com", "Zendesk Help Center", "Zendesk"),
    (r".*\.fastly\.net", "Fastly Edge CDN", "Fastly"),
    (r".*\.cloudflare\.net", "Cloudflare Edge Proxy", "Cloudflare"),
]

# Major SaaS Mail Exchange Providers
KNOWN_MAIL_GATEWAYS = {
    "zoho.com": "Zoho Mail",
    "google.com": "Google Workspace / Gmail",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365 / Exchange",
    "pphosted.com": "Proofpoint Enterprise Gateway",
    "mimecast.com": "Mimecast Email Security",
    "sendgrid.net": "Twilio SendGrid",
    "mailgun.org": "Mailgun Transactional Email",
    "mandrillapp.com": "Mailchimp Mandrill",
}

# Known CDN IPv4 Prefixes / Ranges
CDN_ASN_KEYWORDS = ["cloudflare", "akamai", "fastly", "amazon", "cloudfront", "incapsula", "imperva"]


def extract_origin_intelligence(domain: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Uncovers true origin server IP candidates and cloud infrastructure
    by inspecting MX records, SPF policies, and DNS zone pointers.
    """
    logger.info(f"[recon.origin_extractor] Extracting origin intelligence & SPF/MX pointers for '{domain}'")
    
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    origin_candidates: List[Dict[str, Any]] = []
    seen_ips: Set[str] = set()
    mail_servers: List[Dict[str, Any]] = []
    spf_record: Optional[str] = None
    spf_ip_cidrs: List[str] = []

    # 1. Inspect MX Records
    try:
        mx_answers = resolver.resolve(domain, "MX")
        for rdata in mx_answers:
            mx_host = str(rdata.exchange).rstrip(".")
            pref = rdata.preference
            
            # Detect SaaS Gateway
            gateway_name = None
            for pattern, name in KNOWN_MAIL_GATEWAYS.items():
                if pattern in mx_host.lower():
                    gateway_name = name
                    break
                    
            # Resolve MX Host IP
            resolved_mx_ips = []
            try:
                a_answers = resolver.resolve(mx_host, "A")
                for a_data in a_answers:
                    ip_str = str(a_data)
                    resolved_mx_ips.append(ip_str)
                    if not gateway_name and ip_str not in seen_ips:
                        seen_ips.add(ip_str)
                        origin_candidates.append({
                            "ip": ip_str,
                            "type": "MX Origin Candidate",
                            "source": f"mx:{mx_host}",
                            "confidence": 85,
                            "note": "Non-SaaS direct mail server; potential unmasked origin",
                        })
            except Exception:
                pass

            mail_servers.append({
                "host": mx_host,
                "preference": pref,
                "provider": gateway_name or "Custom / Self-Hosted Mail Server",
                "ips": resolved_mx_ips,
            })
    except Exception as e:
        logger.debug(f"MX lookup failed for {domain}: {e}")

    # 2. Inspect SPF (TXT) Policies for Origin IP CIDRs
    try:
        txt_answers = resolver.resolve(domain, "TXT")
        for rdata in txt_answers:
            txt_str = "".join([part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part) for part in rdata.strings])
            if "v=spf1" in txt_str:
                spf_record = txt_str
                
                # Extract explicit ip4 / ip6 mechanisms
                ip4_matches = re.findall(r"ip4:([0-9./]+)", txt_str)
                ip6_matches = re.findall(r"ip6:([0-9a-fA-F:/]+)", txt_str)
                
                for cidr in ip4_matches + ip6_matches:
                    spf_ip_cidrs.append(cidr)
                    # If single IP (/32 or no slash), test as origin candidate
                    base_ip = cidr.split("/")[0]
                    if base_ip not in seen_ips:
                        seen_ips.add(base_ip)
                        origin_candidates.append({
                            "ip": cidr,
                            "type": "SPF Authorized Origin CIDR",
                            "source": "spf:txt_record",
                            "confidence": 90,
                            "note": "Explicitly authorized outbound sending server; potential internal network",
                        })
    except Exception as e:
        logger.debug(f"TXT/SPF lookup failed for {domain}: {e}")

    # 3. Query Censys Hosts for Bare-Metal Origin Servers presenting Domain SSL Certs
    try:
        from recon.censys_client import query_censys_hosts
        censys_hosts = query_censys_hosts(domain, timeout=min(timeout, 15))
        for ch in censys_hosts:
            host_ip = ch.get("ip")
            if host_ip and host_ip not in seen_ips:
                seen_ips.add(host_ip)
                asn_name = ch.get("asn_name") or ""
                origin_candidates.append({
                    "ip": host_ip,
                    "type": "Censys Verified TLS Certificate Host",
                    "source": "censys_hosts",
                    "asn": ch.get("asn"),
                    "asn_name": asn_name,
                    "country": ch.get("country"),
                    "ports": ch.get("ports", []),
                    "confidence": 95,
                    "note": f"Host presents valid {domain} TLS certificate; ASN: {asn_name}",
                })
    except Exception as e:
        logger.debug(f"Censys host origin search failed: {e}")

    return {
        "domain": domain,
        "spf_record": spf_record,
        "spf_cidrs": spf_ip_cidrs,
        "mail_servers": mail_servers,
        "origin_candidates": origin_candidates,
    }


def map_cname_infrastructure(subdomain: str, timeout: int = 3) -> Dict[str, Any]:
    """
    Resolves CNAME pointers for a subdomain and matches against cloud fingerprints.
    """
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

    cname_target = None
    cloud_service = None
    cloud_provider = None

    try:
        answers = resolver.resolve(subdomain, "CNAME")
        for rdata in answers:
            cname_target = str(rdata.target).rstrip(".")
            break
            
        if cname_target:
            for pattern, service, provider in CNAME_FINGERPRINTS:
                if re.search(pattern, cname_target, re.IGNORECASE):
                    cloud_service = service
                    cloud_provider = provider
                    break
    except Exception:
        pass

    return {
        "subdomain": subdomain,
        "cname": cname_target,
        "cloud_service": cloud_service,
        "cloud_provider": cloud_provider,
        "is_cloud_hosted": bool(cloud_service),
    }
