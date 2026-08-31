import logging
import ipaddress
from typing import List, Dict, Any, Set, Tuple, Optional
import dns.resolver
from recon.origin_extractor import map_cname_infrastructure

logger = logging.getLogger(__name__)

# Known CDN CNAME signature patterns
CDN_CNAME_PATTERNS = {
    "cloudflare": ["cloudflare.com", "cloudflare.net"],
    "cloudfront": ["cloudfront.net"],
    "akamai": ["akamai.net", "akamaiedge.net", "edgekey.net", "edgesuite.net"],
    "fastly": ["fastly.net", "fastlylb.net"],
    "imperva": ["incapdns.net", "imperva.com"],
    "azure_cdn": ["azureedge.net", "trafficmanager.net"],
    "sucuri": ["sucuri.net"],
    "aws_elb": ["elb.amazonaws.com", "awsglobalaccelerator.com"],
}

# Known CDN / Cloud Provider IPv4/IPv6 Prefixes
CDN_IP_PREFIXES = {
    "cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    ],
    "fastly": [
        "151.101.0.0/16", "199.232.0.0/16", "146.75.0.0/16",
    ],
    "incapsula": [
        "199.83.128.0/21", "198.143.32.0/19", "149.126.72.0/21", "103.28.248.0/22",
        "185.11.124.0/22", "192.230.64.0/18", "107.154.0.0/16", "45.64.64.0/22",
    ],
    "akamai": [
        "23.32.0.0/11", "23.64.0.0/14", "104.64.0.0/10", "184.24.0.0/13", "184.84.0.0/14",
    ],
}

# Pre-parse CIDR networks for fast in-memory matching
PARSED_CDN_NETWORKS: Dict[str, List[Any]] = {
    provider: [ipaddress.ip_network(cidr) for cidr in cidrs]
    for provider, cidrs in CDN_IP_PREFIXES.items()
}


def is_cdn_ip(ip_str: str) -> Tuple[bool, Optional[str]]:
    """
    Checks if an IP address belongs to a known CDN/WAF Anycast network range.
    Returns: (is_cdn: bool, provider: Optional[str])
    """
    if not ip_str or not isinstance(ip_str, str):
        return False, None
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        for provider, networks in PARSED_CDN_NETWORKS.items():
            for net in networks:
                if ip_obj in net:
                    return True, provider
    except ValueError:
        pass
    return False, None


_check_ip_cdn = is_cdn_ip


def resolve_subdomain_ips(subdomains: List[str], timeout: int = 5) -> List[Dict[str, Any]]:
    """
    Step 3: Resolves subdomains to real IPs, maps cloud CNAME services, and flags CDN/WAF presence.
    Returns: [{subdomain, ips, cnames, is_cdn, cdn_provider, cloud_service, cloud_provider}]
    """
    logger.info(f"[recon.ip_resolve] Resolving IPs and Cloud CNAMEs for {len(subdomains)} subdomains")
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = min(timeout, 3)
    resolver.lifetime = min(timeout, 3)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    
    results: List[Dict[str, Any]] = []

    for sub in subdomains:
        if not sub or not isinstance(sub, str):
            continue
        sub_str = sub.strip()

        # 0. Fast-Path: If target is already a valid IPv4/IPv6 literal, bypass DNS completely
        try:
            ip_obj = ipaddress.ip_address(sub_str)
            is_priv = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
            is_cdn, provider = (False, None) if is_priv else is_cdn_ip(sub_str)
            results.append({
                "subdomain": sub_str,
                "ips": [sub_str],
                "cnames": [],
                "is_cdn": is_cdn,
                "cdn_provider": provider,
                "cloud_service": None,
                "cloud_provider": None,
            })
            continue
        except ValueError:
            pass

        sub_entry: Dict[str, Any] = {
            "subdomain": sub_str,
            "ips": [],
            "cnames": [],
            "is_cdn": False,
            "cdn_provider": None,
            "cloud_service": None,
            "cloud_provider": None,
        }

        # 1. Resolve CNAME records and map cloud fingerprints
        try:
            cloud_info = map_cname_infrastructure(sub, timeout=min(timeout, 3))
            if cloud_info.get("cname"):
                sub_entry["cnames"].append(cloud_info["cname"].lower())
            if cloud_info.get("cloud_service"):
                sub_entry["cloud_service"] = cloud_info["cloud_service"]
                sub_entry["cloud_provider"] = cloud_info["cloud_provider"]

            cname_answers = resolver.resolve(sub, "CNAME")
            for rdata in cname_answers:
                cname_target = str(rdata.target).rstrip(".").lower()
                if cname_target not in sub_entry["cnames"]:
                    sub_entry["cnames"].append(cname_target)
                
                # Check CDN signatures in CNAME
                for provider, patterns in CDN_CNAME_PATTERNS.items():
                    if any(pat in cname_target for pat in patterns):
                        sub_entry["is_cdn"] = True
                        sub_entry["cdn_provider"] = provider
                        break
        except Exception:
            pass

        # 2. Resolve A records (IPv4)
        try:
            a_answers = resolver.resolve(sub, "A")
            for rdata in a_answers:
                ip_str = str(rdata)
                sub_entry["ips"].append(ip_str)
                
                # Check IP CIDR if not already identified as CDN
                if not sub_entry["is_cdn"]:
                    is_cdn_found, provider = is_cdn_ip(ip_str)
                    if is_cdn_found:
                        sub_entry["is_cdn"] = True
                        sub_entry["cdn_provider"] = provider
        except Exception:
            pass

        if sub_entry["ips"] or sub_entry["cnames"]:
            results.append(sub_entry)

    logger.info(f"[recon.ip_resolve] Successfully resolved {len(results)} active hosts")
    return results

