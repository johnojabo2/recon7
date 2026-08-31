import logging
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx
from vuln.app_vuln.base import BaseAppVulnPlugin

logger = logging.getLogger(__name__)


class RedirectProbePlugin(BaseAppVulnPlugin):
    """
    Non-destructive Unvalidated Open Redirect Vulnerability Evaluator.
    Identifies parameters that permit arbitrary redirection to untrusted third-party domains.
    """
    plugin_id = "redirect_probe"
    name = "Unvalidated Open URL Redirect Vulnerability"
    description = (
        "Audits URL parameters used for navigational redirection (next=, return_to=, redirect_uri=) "
        "to determine if the application safely validates target destinations."
    )
    owasp_category = "A01:2021 - Broken Access Control"
    cwe_id = "CWE-601"
    default_severity = "medium"
    default_cvss = 6.1

    CANARY_HOST = "recon7-redirect-test.com"
    CANARY_URL = f"https://{CANARY_HOST}/auth-callback"

    REDIRECT_PARAMS = [
        "next", "return_to", "redirect", "redirect_uri", "url",
        "target", "destination", "dest", "continue", "forward", "r",
    ]

    async def audit(
        self,
        target_url: str,
        context: Dict[str, Any],
        client: httpx.AsyncClient,
    ) -> List[Dict[str, Any]]:
        findings = []
        cluster_domains = context.get("cluster_domains", [])
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)

        # Identify candidate parameters in URL or inject top redirect parameter names
        params_to_test = [p for p in params.keys() if p.lower() in self.REDIRECT_PARAMS]
        if not params_to_test:
            params_to_test = self.REDIRECT_PARAMS[:4]

        # Use non-redirect-following client for inspecting 3xx Location header
        for param_name in params_to_test:
            for test_payload in [self.CANARY_URL, f"//{self.CANARY_HOST}"]:
                test_params = dict(params)
                test_params[param_name] = [test_payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, new_query, parsed.fragment))

                try:
                    # Explicitly disable redirect following to inspect 3xx status and Location header
                    resp = await client.get(
                        test_url,
                        follow_redirects=False,
                        headers={"User-Agent": "Mozilla/5.0 Recon7-RedirectProbe/1.0"},
                    )

                    if resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get("location", "")
                        if self.CANARY_HOST in location:
                            proof = (
                                f"[CONFIRMED // ACTIVE PROOF] Server issued HTTP {resp.status_code} redirect "
                                f"to external canary destination '{location}' via parameter '{param_name}'."
                            )
                            findings.append(
                                self.build_finding(
                                    title=f"Open Redirect Vulnerability via Parameter '{param_name}'",
                                    severity="medium",
                                    cvss_score=6.1,
                                    evidence_proof=proof,
                                    remediation=(
                                        "Implement strict server-side allowlisting for all redirect destination URLs. "
                                        "Disallow protocol-relative URLs (//) and reject any redirect targets outside authorized domains."
                                    ),
                                    description=(
                                        f"The endpoint on {test_url} accepts arbitrary redirection URLs in parameter '{param_name}'. "
                                        "Attackers can weaponize this in spearphishing campaigns and OAuth token theft."
                                    ),
                                    target_url=test_url,
                                    cluster_domains=cluster_domains,
                                    metadata={
                                        "parameter": param_name,
                                        "injected_payload": test_payload,
                                        "status_code": resp.status_code,
                                        "location_header": location,
                                    },
                                )
                            )
                            return findings
                except Exception as e:
                    logger.debug(f"[redirect_probe] Probe error on {test_url}: {e}")

        return findings
