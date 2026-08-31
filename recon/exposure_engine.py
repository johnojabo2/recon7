import re
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import httpx

logger = logging.getLogger(__name__)

# Multi-Cloud storage probe templates based on target organization/domain slug
CLOUD_PATTERNS = [
    # AWS S3 Permutations
    {"provider": "AWS S3", "template": "https://{slug}.s3.amazonaws.com", "service": "s3"},
    {"provider": "AWS S3", "template": "https://{slug}-public.s3.amazonaws.com", "service": "s3"},
    {"provider": "AWS S3", "template": "https://{slug}-assets.s3.amazonaws.com", "service": "s3"},
    {"provider": "AWS S3", "template": "https://{slug}-media.s3.amazonaws.com", "service": "s3"},
    {"provider": "AWS S3", "template": "https://{slug}-backup.s3.amazonaws.com", "service": "s3"},
    {"provider": "AWS S3", "template": "https://{slug}-data.s3.amazonaws.com", "service": "s3"},
    {"provider": "AWS S3", "template": "https://{slug}-db.s3.amazonaws.com", "service": "s3"},
    {"provider": "AWS S3", "template": "https://{slug}-logs.s3.amazonaws.com", "service": "s3"},
    {"provider": "AWS S3", "template": "https://{slug}-prod.s3.amazonaws.com", "service": "s3"},
    {"provider": "AWS S3", "template": "https://{slug}-dev.s3.amazonaws.com", "service": "s3"},
    {"provider": "AWS S3", "template": "https://{slug}-staging.s3.amazonaws.com", "service": "s3"},
    {"provider": "AWS S3", "template": "https://{slug}-static.s3.amazonaws.com", "service": "s3"},
    {"provider": "AWS S3", "template": "https://{slug}-docs.s3.amazonaws.com", "service": "s3"},
    {"provider": "AWS S3", "template": "https://{slug}-files.s3.amazonaws.com", "service": "s3"},

    # Azure Blob Storage
    {"provider": "Azure Blob", "template": "https://{slug}.blob.core.windows.net/public?restype=container&comp=list", "service": "azure_blob"},
    {"provider": "Azure Blob", "template": "https://{slug}.blob.core.windows.net/assets?restype=container&comp=list", "service": "azure_blob"},
    {"provider": "Azure Blob", "template": "https://{slug}.blob.core.windows.net/data?restype=container&comp=list", "service": "azure_blob"},
    {"provider": "Azure Blob", "template": "https://{slug}.blob.core.windows.net/backup?restype=container&comp=list", "service": "azure_blob"},

    # Google Cloud Storage (GCS)
    {"provider": "Google Cloud Storage", "template": "https://storage.googleapis.com/{slug}", "service": "gcs"},
    {"provider": "Google Cloud Storage", "template": "https://storage.googleapis.com/{slug}-public", "service": "gcs"},
    {"provider": "Google Cloud Storage", "template": "https://storage.googleapis.com/{slug}-assets", "service": "gcs"},
    {"provider": "Google Cloud Storage", "template": "https://storage.googleapis.com/{slug}-backup", "service": "gcs"},
    {"provider": "Google Cloud Storage", "template": "https://storage.googleapis.com/{slug}-data", "service": "gcs"},

    # DigitalOcean Spaces (Multi-region)
    {"provider": "DigitalOcean Spaces", "template": "https://{slug}.nyc3.digitaloceanspaces.com", "service": "digitalocean"},
    {"provider": "DigitalOcean Spaces", "template": "https://{slug}.ams3.digitaloceanspaces.com", "service": "digitalocean"},
    {"provider": "DigitalOcean Spaces", "template": "https://{slug}.sgp1.digitaloceanspaces.com", "service": "digitalocean"},
]


def check_cloud_storage_exposure(target: str, timeout: int = 5) -> List[Dict[str, Any]]:
    """
    Dedicated Multi-Cloud Public Storage Exposure Sensor inspired by SpiderFoot sfp_s3bucket / sfp_azureblob / sfp_gcs.
    Tests target-derived public storage buckets across AWS, Azure, GCP, and DigitalOcean.
    Classifies exposure status:
      - 'ACCESSIBLE': public list or get permitted (HTTP 200 with XML contents)
      - 'DISCOVERED': bucket exists on provider but access restricted (HTTP 403)
      - 'UNKNOWN': unreachable or 404
    """
    # Extract clean slug
    clean_target = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    slug = clean_target.split(".")[0].lower()
    if len(slug) < 3:
        return []

    exposures: List[Dict[str, Any]] = []

    with httpx.Client(timeout=timeout, verify=False, follow_redirects=False) as client:
        for pat in CLOUD_PATTERNS:
            url = pat["template"].format(slug=slug)
            provider = pat["provider"]
            service = pat["service"]

            try:
                resp = client.get(url, headers={"User-Agent": "Mozilla/5.0 Recon7-CloudBucketHunter/1.0"})
                status_code = resp.status_code

                if status_code == 200:
                    # Publicly accessible
                    body = resp.text
                    is_listable = "<ListBucketResult" in body or "<EnumerationResults" in body
                    keys_found = re.findall(r"<Key>(.*?)</Key>", body) or re.findall(r"<Name>(.*?)</Name>", body)

                    has_sensitive_files = any(
                        ext in body.lower() for ext in [".sql", ".bak", ".env", ".pem", ".key", ".config", ".csv", ".pdf"]
                    )

                    severity = "critical" if (is_listable and has_sensitive_files) else "high"
                    title = f"Publicly Accessible {provider} Bucket ({'Listable Contents' if is_listable else 'Open Read'})"
                    evidence_desc = f"HTTP 200 OK. Public listing enabled. {len(keys_found)} object keys enumerated." if is_listable else f"HTTP 200 response from {url}"

                    exposures.append({
                        "resource_url": url,
                        "provider": provider,
                        "service": service,
                        "status": "ACCESSIBLE",
                        "severity": severity,
                        "title": title,
                        "status_code": status_code,
                        "confidence": 0.98,
                        "evidence": evidence_desc,
                        "sample_keys": keys_found[:5],
                        "remediation": f"Block public ACL/read access immediately for {url} and audit bucket IAM policies.",
                        "observed_at": datetime.now(timezone.utc).isoformat(),
                    })

                elif status_code == 403:
                    # Exists, bucket name confirmed, but access denied
                    exposures.append({
                        "resource_url": url,
                        "provider": provider,
                        "service": service,
                        "status": "DISCOVERED",
                        "severity": "low",
                        "title": f"Discovered {provider} Bucket (Access Restricted)",
                        "status_code": status_code,
                        "confidence": 0.85,
                        "evidence": f"HTTP 403 Forbidden confirmed valid bucket name at {url}",
                        "remediation": "Ensure Public Access Blocks (PAB) remain permanently enforced on this storage resource.",
                        "observed_at": datetime.now(timezone.utc).isoformat(),
                    })
            except Exception:
                continue

    logger.info(f"[recon.exposure] Multi-cloud storage hunter evaluated {len(CLOUD_PATTERNS)} bucket permutations for '{slug}'; found {len(exposures)} active resources")
    return exposures


def mask_identifier(identifier: str) -> str:
    """Masks email or username for privacy per Spec Section 20."""
    if "@" in identifier:
        user_part, domain_part = identifier.split("@", 1)
        if len(user_part) <= 2:
            masked_user = user_part[0] + "*"
        else:
            masked_user = user_part[:2] + "*" * (len(user_part) - 3) + user_part[-1]
        return f"{masked_user}@{domain_part}"
    elif len(identifier) > 3:
        return identifier[:2] + "*" * (len(identifier) - 3) + identifier[-1]
    return "***"


def check_breach_exposure_signal(email_or_domain: str) -> List[Dict[str, Any]]:
    """
    Legitimate Breach Exposure Intelligence Sensor per Spec Section 20.
    Stores minimal indicator signals (masked identifier, breach name, date, source).
    Strictly zero raw credentials or passwords stored or displayed.
    """
    # Deterministic simulation / baseline lookup for demonstration and testing
    target_clean = email_or_domain.lower().strip()
    signals: List[Dict[str, Any]] = []

    # If domain or email matches known mock test targets, provide representative exposure signal
    if any(k in target_clean for k in ["example.com", "test.com", "target.com"]):
        signals.append({
            "target": target_clean,
            "masked_identifier": mask_identifier(target_clean),
            "exposure_detected": True,
            "breach_name": "Historical Public Data Compilation (2023)",
            "breach_date": "2023-04-15",
            "source": "Defensive Breach Intelligence Aggregator",
            "confidence": 0.88,
            "severity": "medium",
            "title": f"Breach Exposure Signal Detected for {mask_identifier(target_clean)}",
            "evidence": f"Identifier appears in historical threat-intelligence index for compilation 2023.",
            "remediation": "Audit enterprise accounts for reused passwords, enforce MFA, and review active session tokens.",
            "observed_at": datetime.now(timezone.utc).isoformat(),
        })

    return signals
