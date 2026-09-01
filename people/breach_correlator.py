import logging
import os
import re
from typing import List, Dict, Any, Optional, Set
import httpx

from core.config import settings

logger = logging.getLogger(__name__)


def mask_email(email: str) -> str:
    """Masks email for privacy (e.g. jo***bo@target.com)."""
    if "@" not in email:
        return "***"
    user_part, domain_part = email.split("@", 1)
    if len(user_part) <= 2:
        masked_user = user_part[0] + "*"
    else:
        masked_user = user_part[:2] + "*" * (len(user_part) - 3) + user_part[-1]
    return f"{masked_user}@{domain_part}"


def correlate_email_breach_signals(
    emails: List[str],
    timeout: int = 8,
) -> List[Dict[str, Any]]:
    """
    Correlates employee emails with verified data breach indices.
    Requires an official HIBP API Key (HIBP_API_KEY).
    If no key is configured, zero speculative alarms are generated.
    """
    if not emails:
        return []

    hibp_key = getattr(settings, "HIBP_API_KEY", None) or os.getenv("HIBP_API_KEY")
    if not hibp_key:
        logger.info("[people.breach] No HIBP_API_KEY configured. Skipping active breach lookup. (Verify manually at haveibeenpwned.com/DomainSearch)")
        return []

    logger.info(f"[people.breach] Checking verified HaveIBeenPwned breach feeds for {len(emails)} corporate emails...")

    breach_findings: List[Dict[str, Any]] = []
    seen = set()

    headers = {
        "hibp-api-key": hibp_key.strip(),
        "user-agent": "Recon7-SecurityPlatform/1.0",
    }

    with httpx.Client(timeout=timeout, headers=headers) as client:
        for raw_email in emails[:25]:  # Throttle to avoid rate limits
            clean_email = raw_email.strip().lower()
            if not clean_email or "@" not in clean_email or clean_email in seen:
                continue
            seen.add(clean_email)

            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{clean_email}?truncateResponse=false"
            try:
                resp = client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data:
                        breach_name = item.get("Name") or item.get("Title") or "Historical Data Breach"
                        breach_date = item.get("BreachDate") or "Unknown"
                        data_classes = item.get("DataClasses") or ["Email Address"]
                        pwn_count = item.get("PwnCount", 0)

                        breach_findings.append({
                            "email": clean_email,
                            "masked_identifier": mask_email(clean_email),
                            "breach_name": breach_name,
                            "breach_date": breach_date,
                            "risk_score": 80,
                            "confidence": 0.95,
                            "data_classes": data_classes,
                            "pwn_count": pwn_count,
                            "source": "HaveIBeenPwned Verified Breach Registry",
                            "evidence": f"Email {mask_email(clean_email)} surfaced in verified {breach_name} breach ({breach_date}) containing: {', '.join(data_classes[:4])}",
                            "remediation": "Audit account for credential reuse, enforce mandatory MFA, and rotate associated API tokens.",
                            "is_verified": True,
                        })
                elif resp.status_code == 404:
                    # Not found in any breach
                    continue
                elif resp.status_code == 429:
                    logger.warning("[people.breach] HIBP API rate limit reached (429).")
                    break
            except Exception as e:
                logger.debug(f"[people.breach] Failed HIBP lookup for {mask_email(clean_email)}: {e}")
                continue

    logger.info(f"[people.breach] Correlated {len(breach_findings)} verified breach records")
    return breach_findings
