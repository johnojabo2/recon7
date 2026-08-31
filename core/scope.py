import re
from typing import Optional, Tuple
from urllib.parse import urlparse
from core.config import settings


DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"  # First character of domain
    r"(?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+"  # Subdomains
    r"[a-zA-Z]{2,63}$"  # Top-level domain
)

IP_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


class ScopeAuthorizationError(Exception):
    """Raised when a target domain is not authorized for scanning."""
    pass


class InvalidTargetError(Exception):
    """Raised when a target domain format is invalid."""
    pass


def normalize_domain(raw_target: str) -> str:
    """
    Sanitize and extract clean FQDN or IP from raw input.
    Strips schemes (http/https), port numbers, path, query parameters.
    """
    if not raw_target:
        raise InvalidTargetError("Target cannot be empty")
    
    target = raw_target.strip().lower()
    
    # Strip URL schemes if present
    if "://" in target:
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path
    
    # Strip port if present
    if ":" in target and not target.count(":") > 1: # exclude IPv6
        target = target.split(":")[0]
        
    # Strip trailing slashes or paths
    target = target.split("/")[0].strip()

    # Validate against Domain or IP regex
    if not (DOMAIN_REGEX.match(target) or IP_REGEX.match(target)):
        raise InvalidTargetError(f"Target '{raw_target}' is not a valid domain name or IPv4 address")
    
    return target


try:
    import tldextract
    _tld_extractor = tldextract.TLDExtract(cache_dir=None)
except Exception:
    _tld_extractor = None

# Known second-level category prefixes across ccTLDs (.edu.ng, .gov.ng, .co.uk, .com.au, etc.)
TWO_PART_PREFIXES = {
    "edu", "gov", "com", "co", "org", "net", "sch", "ac", "mil",
    "gob", "ne", "or", "go", "gen", "ltd", "me", "web", "asso"
}


def extract_root_domain(target: str) -> str:
    """
    Extracts the root domain (apex / eTLD+1) from a domain or subdomain.
    Accurately handles all international domains and multi-part public suffixes
    (e.g., .edu.ng, .gov.ng, .co.uk, .com.ng, .edu.au).
    Examples:
      - www.bsum.edu.ng -> bsum.edu.ng
      - fula.edu.ng -> fula.edu.ng
      - zoo.fula.edu.ng -> fula.edu.ng
      - dev.abc.com -> abc.com
      - api.staging.corp.co.uk -> corp.co.uk
      - 192.168.1.1 -> 192.168.1.1
    """
    clean = normalize_domain(target)
    if IP_REGEX.match(clean):
        return clean

    if _tld_extractor is not None:
        try:
            ext = _tld_extractor(clean)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}".lower()
        except Exception:
            pass

    parts = clean.split(".")
    if len(parts) <= 2:
        return clean

    # Check multi-part TLD (e.g. fula.edu.ng -> edu.ng suffix -> fula.edu.ng root)
    if len(parts) >= 3:
        if parts[-2].lower() in TWO_PART_PREFIXES:
            return ".".join(parts[-3:])

    # Standard single TLD (e.g. dev.abc.com -> abc.com)
    return ".".join(parts[-2:])


def classify_target(target: str) -> str:
    """Classifies a target string as 'ip' or 'domain'."""
    clean = normalize_domain(target)
    if IP_REGEX.match(clean):
        return "ip"
    return "domain"



def check_scope_authorization(tenant_id: str, target_domain: str, db_session = None) -> Tuple[bool, str]:
    """
    Core authorization gate function. Every scan request MUST pass through this gate.
    
    Returns:
        (is_authorized: bool, reason_or_message: str)
    """
    normalized = normalize_domain(target_domain)
    
    # In development mode, check allowlist or bypass flag
    if settings.ALLOW_ALL_SCOPES_DEV:
        return True, f"Authorized under ALLOW_ALL_SCOPES_DEV mode for target '{normalized}'"

    # If DB session is provided, verify against authorized_scopes table
    if db_session is not None:
        try:
            from storage.models import AuthorizedScope
            scope_record = (
                db_session.query(AuthorizedScope)
                .filter(
                    AuthorizedScope.tenant_id == tenant_id,
                    AuthorizedScope.domain == normalized
                )
                .first()
            )
            if scope_record:
                return True, f"Target '{normalized}' matched authorized scope id {scope_record.id} ({scope_record.authorization_type})"
        except Exception as e:
            return False, f"Scope check query failed: {str(e)}"

    return False, f"Target '{normalized}' is not in authorized scopes for tenant '{tenant_id}'"


def enforce_scope(tenant_id: str, target_domain: str, db_session = None) -> str:
    """
    Enforces scope authorization; raises ScopeAuthorizationError if not permitted.
    Returns normalized domain string if authorized.
    """
    normalized = normalize_domain(target_domain)
    authorized, reason = check_scope_authorization(tenant_id, normalized, db_session)
    if not authorized:
        raise ScopeAuthorizationError(reason)
    return normalized
