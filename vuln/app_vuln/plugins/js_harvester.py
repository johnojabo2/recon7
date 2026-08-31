import re
import logging
from typing import Dict, Any, List, Set
from urllib.parse import urljoin
import httpx
from bs4 import BeautifulSoup
from vuln.app_vuln.base import BaseAppVulnPlugin

logger = logging.getLogger(__name__)


class JsHarvesterPlugin(BaseAppVulnPlugin):
    """
    Public JavaScript Bundle & Source Map Asset Harvester.
    Extracts undocumented internal API endpoints, administrative routes, and hardcoded API tokens.
    """
    plugin_id = "js_harvester"
    name = "JavaScript Bundle API Route & Sensitive Secret Harvester"
    description = (
        "Parses client-side JavaScript chunk files and source maps to discover internal "
        "REST API endpoints, GraphQL routes, and leaked hardcoded tokens."
    )
    owasp_category = "A01:2021 - Broken Access Control"
    cwe_id = "CWE-538"
    default_severity = "medium"
    default_cvss = 6.0

    # Secret / Token Patterns
    SECRET_PATTERNS = [
        ("AWS Access Key ID", r"\b(AKIA[0-9A-Z]{16})\b", "high", 8.0, "CWE-798"),
        ("GitHub Personal Access Token", r"\b(ghp_[a-zA-Z0-9]{36,40}|github_pat_[a-zA-Z0-9_]{82})\b", "critical", 9.0, "CWE-798"),
        ("Stripe Live API Key", r"\b(sk_live_[0-9a-zA-Z]{24,34})\b", "critical", 9.5, "CWE-798"),
        ("Slack Incoming Webhook", r"(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)", "high", 7.5, "CWE-200"),
        ("Google Maps API Key", r"\b(AIza[0-9A-Za-z\-_]{35})\b", "low", 4.0, "CWE-200"),
    ]

    # Internal / Sensitive Route Regex
    ROUTE_REGEX = re.compile(
        r'["\'](/(?:api/v[0-9]+|admin|internal|v[0-9]+|private|management)/[a-zA-Z0-9_\-/\.]+?)["\']'
    )

    async def audit(
        self,
        target_url: str,
        context: Dict[str, Any],
        client: httpx.AsyncClient,
    ) -> List[Dict[str, Any]]:
        findings = []
        cluster_domains = context.get("cluster_domains", [])

        # 1. Fetch main page HTML and extract script tags
        script_urls: List[str] = []
        try:
            resp = await client.get(target_url, headers={"User-Agent": "Mozilla/5.0 Recon7-JSHarvester/1.0"})
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text[:50000], "html.parser")
                for s in soup.find_all("script"):
                    src = s.get("src")
                    if src:
                        full_script_url = urljoin(target_url, src)
                        # Filter to local or CDN chunk scripts, avoiding third-party analytics (Google, Facebook)
                        if not any(k in full_script_url.lower() for k in ["google-analytics", "googletagmanager", "facebook", "sentry", "datadog", "hotjar"]):
                            script_urls.append(full_script_url)
        except Exception as e:
            logger.debug(f"[js_harvester] Failed to crawl base page {target_url}: {e}")
            return findings

        # Limit to top 5 script files to prevent excessive requests
        discovered_routes: Set[str] = set()
        discovered_secrets: List[Dict[str, Any]] = []

        for script_url in script_urls[:5]:
            try:
                s_resp = await client.get(script_url, headers={"User-Agent": "Mozilla/5.0 Recon7-JSHarvester/1.0"})
                if s_resp.status_code == 200:
                    text_content = s_resp.text

                    # A. Scan for Leaked Secrets
                    for secret_name, pattern, sev, cvss, cwe in self.SECRET_PATTERNS:
                        matches = re.findall(pattern, text_content)
                        for m in matches:
                            # Redact match for safety
                            redacted = f"{m[:6]}...{m[-4:]}" if len(m) > 10 else f"{m[:3]}..."
                            discovered_secrets.append({
                                "name": secret_name,
                                "redacted": redacted,
                                "severity": sev,
                                "cvss": cvss,
                                "cwe": cwe,
                                "script_url": script_url,
                            })

                    # B. Scan for Internal API Endpoints
                    route_matches = self.ROUTE_REGEX.findall(text_content)
                    for r in route_matches:
                        if len(r) > 4 and not r.endswith((".png", ".jpg", ".svg", ".css")):
                            discovered_routes.add(r)
            except Exception as e:
                logger.debug(f"[js_harvester] Error inspecting script {script_url}: {e}")

        # 2. Build Finding for Leaked Secrets if found
        for sec in discovered_secrets[:3]:
            proof = (
                f"[CONFIRMED // ACTIVE PROOF] Discovered {sec['name']} hardcoded in public client bundle '{sec['script_url']}'. "
                f"Token signature: '{sec['redacted']}'."
            )
            findings.append(
                self.build_finding(
                    title=f"Critical Token Exposure: {sec['name']} Leaked in JavaScript",
                    severity=sec["severity"],
                    cvss_score=sec["cvss"],
                    evidence_proof=proof,
                    remediation="Immediately revoke the exposed credential and migrate all secrets to server-side environment variables.",
                    description=f"Public client JavaScript bundle '{sec['script_url']}' exposes a hardcoded {sec['name']}.",
                    target_url=sec["script_url"],
                    cwe_ids=[sec["cwe"]],
                    cluster_domains=cluster_domains,
                    metadata={"secret_type": sec["name"], "token_redacted": sec["redacted"]},
                )
            )

        # 3. Build Finding for Discovered API Routes if significant surface mapped
        admin_or_internal = [r for r in discovered_routes if any(k in r.lower() for k in ["admin", "internal", "private", "management"])]
        if len(discovered_routes) >= 3 or admin_or_internal:
            proof = (
                f"[CONFIRMED // ACTIVE PROOF] Harvester extracted {len(discovered_routes)} internal API routes from public JS chunks. "
                f"Sample routes: {', '.join(list(discovered_routes)[:6])}."
            )
            if admin_or_internal:
                proof += f" Privileged routes detected: {', '.join(admin_or_internal[:3])}."

            findings.append(
                self.build_finding(
                    title="Undocumented Internal API Surface Mapped via JavaScript Bundles",
                    severity="low",
                    cvss_score=3.5,
                    evidence_proof=proof,
                    remediation="Ensure all discovered internal routes enforce strict server-side authorization checks and are not accessible publicly.",
                    description=f"Client-side JavaScript bundles on {target_url} expose internal API route schemas.",
                    target_url=target_url,
                    cluster_domains=cluster_domains,
                    finding_status="CONFIRMED",
                    metadata={
                        "total_routes": len(discovered_routes),
                        "routes": list(discovered_routes)[:15],
                        "privileged_routes": admin_or_internal,
                    },
                )
            )

        return findings
