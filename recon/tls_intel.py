import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


def extract_tls_certificate_intel(domain: str, port: int = 443, timeout: int = 5) -> Dict[str, Any]:
    """
    Submodule: Connects to target over TLS on port 443 with SNI.
    Extracts complete cryptographic certificate metadata, SAN list, and wildcard risk.
    """
    logger.info(f"[recon.tls_intel] Extracting live TLS certificate intelligence for '{domain}:{port}'")

    result: Dict[str, Any] = {
        "domain": domain,
        "tls_connected": False,
        "tls_version": None,
        "cipher": None,
        "subject_cn": None,
        "issuer_cn": None,
        "issuer_org": None,
        "valid_from": None,
        "valid_to": None,
        "days_remaining": None,
        "is_expired": False,
        "key_algorithm": "Unknown",
        "sans": [],
        "is_wildcard": False,
        "wildcard_risk": None,
    }

    # First try with system CA verification (provides full parsed dictionary)
    cert = None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                result["tls_connected"] = True
                result["tls_version"] = ssock.version()
                cipher_info = ssock.cipher()
                if cipher_info:
                    result["cipher"] = cipher_info[0]
                    if len(cipher_info) > 2:
                        result["key_algorithm"] = f"{cipher_info[1]} ({cipher_info[2]}-bit)"
                cert = ssock.getpeercert()
    except ssl.SSLError:
        # Fallback for self-signed or expired certs
        try:
            ctx_insecure = ssl.create_default_context()
            ctx_insecure.check_hostname = False
            ctx_insecure.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with ctx_insecure.wrap_socket(sock, server_hostname=domain) as ssock:
                    result["tls_connected"] = True
                    result["tls_version"] = ssock.version()
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        result["cipher"] = cipher_info[0]
        except Exception:
            pass
    except Exception as e:
        logger.debug(f"TLS connection failed for {domain}:{port} - {e}")

    if cert:
        # Subject CN
        subject = cert.get("subject", ())
        for rdn in subject:
            for item in rdn:
                if len(item) == 2:
                    k, v = item
                    if k == "commonName":
                        result["subject_cn"] = v

        # Issuer CN & Org
        issuer = cert.get("issuer", ())
        for rdn in issuer:
            for item in rdn:
                if len(item) == 2:
                    k, v = item
                    if k == "commonName":
                        result["issuer_cn"] = v
                    elif k == "organizationName":
                        result["issuer_org"] = v

        # Dates & Validity
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")
        
        if not_before:
            dt_before = _parse_ssl_date(not_before)
            if dt_before:
                result["valid_from"] = dt_before.isoformat()

        if not_after:
            dt_after = _parse_ssl_date(not_after)
            if dt_after:
                result["valid_to"] = dt_after.isoformat()
                now = datetime.now(timezone.utc)
                days_left = (dt_after - now).days
                result["days_remaining"] = days_left
                result["is_expired"] = days_left <= 0

        # SANs & Wildcard Assessment
        san_tuples = cert.get("subjectAltName", ())
        san_list = [val for key, val in san_tuples if key == "DNS"]
        result["sans"] = san_list

        wildcards = [s for s in san_list if s.startswith("*.")]
        if wildcards:
            result["is_wildcard"] = True
            result["wildcard_risk"] = f"Wildcard Certificate Active ({', '.join(wildcards)}) — Single Point of Compromise Across Subdomains"

    logger.info(f"[recon.tls_intel] TLS Intel for '{domain}': Issuer={result['issuer_cn'] or result['issuer_org']}, Wildcard={result['is_wildcard']}")
    return result


def _parse_ssl_date(date_str: str) -> Optional[datetime]:
    """Parses SSL certificate timestamp string format (e.g. 'Aug  4 15:28:10 2026 GMT')."""
    formats = [
        "%b %d %H:%M:%S %Y %Z",
        "%b  %d %H:%M:%S %Y %Z",
        "%Y%m%d%H%M%SZ",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None
