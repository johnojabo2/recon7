import logging
import re
import socket
import ssl
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urlparse
import dns.resolver

logger = logging.getLogger(__name__)

# Known third-party SaaS, CDNs, and vendor domains to exclude immediately from subsidiary consideration
VENDOR_BLACKLIST = {
    "google.com", "google.co.uk", "googleapis.com", "gstatic.com", "gmail.com",
    "microsoft.com", "office.com", "azure.com", "windows.net", "live.com", "outlook.com",
    "amazon.com", "amazonaws.com", "aws.amazon.com", "cloudfront.net",
    "cloudflare.com", "cloudflare.net", "cloudflareinsights.com",
    "apple.com", "icloud.com",
    "linkedin.com", "twitter.com", "x.com", "facebook.com", "instagram.com", "youtube.com",
    "github.com", "gitlab.com", "bitbucket.org",
    "adobe.com", "salesforce.com", "hubspot.com", "zendesk.com", "atlassian.net",
    "wordpress.org", "wordpress.com", "w3.org", "schema.org", "gravatar.com",
    "unpkg.com", "jsdelivr.net", "cdnjs.cloudflare.com", "fontawesome.com",
    "doubleclick.net", "google-analytics.com", "googletagmanager.com",
    "vimeo.com", "spotify.com", "medium.com", "zoom.us", "slack.com",
}


def _extract_root_domain(domain_or_url: str) -> str:
    """Extracts root domain from a domain string or URL."""
    if not domain_or_url:
        return ""
    if "://" in domain_or_url:
        parsed = urlparse(domain_or_url)
        domain_or_url = parsed.netloc or parsed.path
    clean = domain_or_url.split(":")[0].strip().lower()
    parts = clean.split(".")
    if len(parts) >= 3 and parts[-2] in ["co", "com", "org", "gov", "net", "edu", "ac"]:
        return ".".join(parts[-3:])
    elif len(parts) >= 2:
        return ".".join(parts[-2:])
    return clean


def extract_tls_sans_and_org(domain: str, timeout: float = 3.0) -> Tuple[Set[str], str]:
    """
    Connects to target domain on port 443 and inspects TLS certificate for Subject Organization
    and Subject Alternative Names (SANs).
    """
    sans: Set[str] = set()
    subject_org = ""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # In CERT_NONE mode, binary_form might be required for raw DER
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        # Fallback parsing
                        return sans, subject_org
                
                # Subject Organization
                for sub_tuple in cert.get("subject", ()):
                    for key, val in sub_tuple:
                        if key == "organizationName":
                            subject_org = val

                # Subject Alternative Names
                for ext_type, ext_val in cert.get("subjectAltName", ()):
                    if ext_type.lower() == "dns":
                        sans.add(ext_val.lower().lstrip("*."))
    except Exception as e:
        logger.debug(f"[subsidiaries.tls] TLS inspection failed for '{domain}': {e}")

    return sans, subject_org


def get_authoritative_nameservers(domain: str, timeout: float = 3.0) -> Set[str]:
    """Resolves authoritative nameservers for a domain."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.timeout = timeout
    resolver.lifetime = timeout
    ns_set: Set[str] = set()
    try:
        answers = resolver.resolve(domain, "NS")
        for r in answers:
            ns_set.add(str(r.target).rstrip(".").lower())
    except Exception as e:
        logger.debug(f"[subsidiaries.dns] NS query failed for '{domain}': {e}")
    return ns_set


def evaluate_subsidiary_relationship(
    parent_domain: str,
    candidate_domain: str,
    parent_org_name: str = "",
    evidence_hints: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Evaluates whether a candidate domain is a genuine corporate subsidiary of parent_domain
    using 5 High-Fidelity Infrastructure Anchors:
    1. TLS SAN Cross-Link / Subject Organization
    2. Shared Authoritative Nameservers
    3. Registrant Email or Org Match
    4. Document / Annual Report Organogram Mentions
    5. Brand Name Token Containment
    """
    parent_root = _extract_root_domain(parent_domain)
    cand_root = _extract_root_domain(candidate_domain)

    if not cand_root or cand_root == parent_root or cand_root in VENDOR_BLACKLIST:
        return {
            "candidate_domain": cand_root or candidate_domain,
            "parent_domain": parent_root,
            "is_subsidiary": False,
            "confidence_score": 0,
            "anchors": [],
            "status": "rejected_vendor" if cand_root in VENDOR_BLACKLIST else "rejected_non_subsidiary",
        }

    score = 0
    anchors: List[Dict[str, Any]] = []

    # Clean org tokens
    clean_parent_org = re.sub(r"[^a-zA-Z0-9\s]", "", parent_org_name).lower() if parent_org_name else parent_root.split(".")[0].lower()

    # Anchor 1: Document Organogram & Explicit Text Hints
    if evidence_hints:
        for hint in evidence_hints:
            hint_lower = str(hint).lower()
            if cand_root in hint_lower or (len(clean_parent_org) >= 4 and clean_parent_org in hint_lower and cand_root.split(".")[0] in hint_lower):
                score += 35
                anchors.append({
                    "anchor": "STATUTORY_DOCUMENT_ORGANOGRAM",
                    "description": f"Candidate domain '{cand_root}' cited in parent corporate disclosures/organogram",
                    "weight": 35,
                })
                break

    # Anchor 2: Brand / Acronym Containment
    # e.g., parent="nnpcgroup.com" (core="nnpc"), cand="nnpcretail.com" or "nnpc-energy.com"
    parent_brand_prefix = parent_root.split(".")[0].lower()
    core_parent_brand = re.sub(r"(group|corp|ltd|limited|holdings|energy|petroleum|global|inc)$", "", parent_brand_prefix).strip("-_")
    cand_prefix = cand_root.split(".")[0].lower()
    
    brand_matches = False
    if len(core_parent_brand) >= 3 and (cand_prefix.startswith(core_parent_brand) or core_parent_brand in cand_prefix):
        brand_matches = True
    elif len(parent_brand_prefix) >= 3 and (cand_prefix.startswith(parent_brand_prefix) or parent_brand_prefix in cand_prefix):
        brand_matches = True

    if brand_matches:
        score += 30
        anchors.append({
            "anchor": "BRAND_TOKEN_CONTAINMENT",
            "description": f"Candidate domain prefix '{cand_prefix}' contains parent brand token '{core_parent_brand or parent_brand_prefix}'",
            "weight": 30,
        })

    # Anchor 3: Shared Authoritative Nameservers (DNS Infrastructure)
    try:
        parent_ns = get_authoritative_nameservers(parent_root)
        cand_ns = get_authoritative_nameservers(cand_root)
        shared_ns = parent_ns.intersection(cand_ns)
        # Check if candidate uses parent domain NS
        uses_parent_ns = any(parent_root in ns for ns in cand_ns)

        if shared_ns or uses_parent_ns:
            score += 30
            anchors.append({
                "anchor": "SHARED_DNS_INFRASTRUCTURE",
                "description": f"Shared authoritative nameservers with parent ({list(shared_ns or cand_ns)[:2]})",
                "weight": 30,
            })
    except Exception:
        pass

    # Anchor 4: TLS Certificate SAN / Subject Organization
    try:
        sans, cand_tls_org = extract_tls_sans_and_org(cand_root)
        # Check if parent domain is in candidate's TLS SANs
        if any(parent_root in san for san in sans):
            score += 40
            anchors.append({
                "anchor": "TLS_CROSS_DOMAIN_SAN",
                "description": f"Parent domain '{parent_root}' present in candidate TLS Subject Alternative Names",
                "weight": 40,
            })
        if cand_tls_org and clean_parent_org and (clean_parent_org in cand_tls_org.lower() or cand_tls_org.lower() in clean_parent_org):
            score += 40
            anchors.append({
                "anchor": "TLS_SUBJECT_ORGANIZATION",
                "description": f"Candidate TLS Subject Organization '{cand_tls_org}' matches parent",
                "weight": 40,
            })
    except Exception:
        pass

    # Anchor 5: Shared Web Analytics & Tag Manager (GTM / GA4 / UA / AdSense)
    try:
        from people.analytics_miner import fetch_and_extract_analytics_ids, correlate_shared_analytics
        parent_tokens = fetch_and_extract_analytics_ids(parent_root)
        cand_tokens = fetch_and_extract_analytics_ids(cand_root)
        has_shared_tag, tag_boost, tag_anchors = correlate_shared_analytics(parent_tokens, cand_tokens)
        if has_shared_tag:
            score += tag_boost
            anchors.extend(tag_anchors)
    except Exception:
        pass

    is_subsidiary = score >= 35

    return {
        "candidate_domain": cand_root,
        "parent_domain": parent_root,
        "is_subsidiary": is_subsidiary,
        "confidence_score": min(100, score),
        "anchors": anchors,
        "status": "confirmed_subsidiary" if score >= 50 else ("probable_affiliate" if is_subsidiary else "rejected_vendor"),
    }


def discover_corporate_subsidiaries(
    parent_domain: str,
    org_name: str = "",
    candidate_urls_and_domains: Optional[List[str]] = None,
    document_snippets: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Discovers and corroborates genuine corporate subsidiaries from discovered URLs,
    document mentions, and web assets. Rejects vendor/third-party noise.
    """
    parent_root = _extract_root_domain(parent_domain)
    candidates_to_test: Set[str] = set()

    # Ingest candidate URLs and extract external domains
    if candidate_urls_and_domains:
        for item in candidate_urls_and_domains:
            root = _extract_root_domain(item)
            if root and root != parent_root and root not in VENDOR_BLACKLIST:
                candidates_to_test.add(root)

    # Ingest document text snippets for domain mentions
    if document_snippets:
        domain_regex = re.compile(r"\b([a-zA-Z0-9-]+\.(?:com|org|gov|net|co|io|ng|uk|ca|de|com\.ng|gov\.ng|org\.ng))\b", re.IGNORECASE)
        for snippet in document_snippets:
            matches = domain_regex.findall(str(snippet))
            for m in matches:
                root = _extract_root_domain(m)
                if root and root != parent_root and root not in VENDOR_BLACKLIST:
                    candidates_to_test.add(root)

    verified_subsidiaries: List[Dict[str, Any]] = []

    for cand in candidates_to_test:
        eval_result = evaluate_subsidiary_relationship(
            parent_domain=parent_root,
            candidate_domain=cand,
            parent_org_name=org_name,
            evidence_hints=document_snippets,
        )
        if eval_result.get("is_subsidiary"):
            verified_subsidiaries.append(eval_result)

    # Sort by confidence score
    verified_subsidiaries.sort(key=lambda s: -s.get("confidence_score", 0))
    logger.info(f"[subsidiaries] Evaluated {len(candidates_to_test)} candidate domains; confirmed {len(verified_subsidiaries)} true subsidiaries for '{parent_root}'")
    return verified_subsidiaries
