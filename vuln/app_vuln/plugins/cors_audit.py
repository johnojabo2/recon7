import logging
from typing import Dict, Any, List
import httpx
from vuln.app_vuln.base import BaseAppVulnPlugin

logger = logging.getLogger(__name__)


class CorsAuditPlugin(BaseAppVulnPlugin):
    """
    Non-destructive Cross-Origin Resource Sharing (CORS) Security Evaluator.
    Audits dynamic Origin reflection, credential trust flags, and null-origin misconfigurations.
    """
    plugin_id = "cors_audit"
    name = "Cross-Origin Resource Sharing (CORS) Misconfiguration Audit"
    description = (
        "Evaluates whether the web application insecurely reflects arbitrary untrusted origins "
        "or permits credentialed requests from unverified third-party domains."
    )
    owasp_category = "A01:2021 - Broken Access Control"
    cwe_id = "CWE-942"
    default_severity = "high"
    default_cvss = 7.5

    TEST_ORIGIN = "https://recon7-security-audit.com"

    async def audit(
        self,
        target_url: str,
        context: Dict[str, Any],
        client: httpx.AsyncClient,
    ) -> List[Dict[str, Any]]:
        findings = []
        cluster_domains = context.get("cluster_domains", [])

        # 1. Arbitrary Origin Reflection Test
        try:
            resp = await client.get(
                target_url,
                headers={
                    "Origin": self.TEST_ORIGIN,
                    "User-Agent": "Mozilla/5.0 Recon7-CORSAuditor/1.0",
                },
            )
            acao = resp.headers.get("access-control-allow-origin", "").strip()
            acac = resp.headers.get("access-control-allow-credentials", "").strip().lower()

            if acao == self.TEST_ORIGIN:
                if acac == "true":
                    proof = (
                        f"[CONFIRMED // ACTIVE PROOF] Target reflected arbitrary Origin '{self.TEST_ORIGIN}' "
                        f"in Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true. "
                        f"Attacking origins can extract private session responses and sensitive data."
                    )
                    findings.append(
                        self.build_finding(
                            title="Critical CORS Misconfiguration: Arbitrary Origin Reflection with Credentials",
                            severity="high",
                            cvss_score=8.5,
                            evidence_proof=proof,
                            remediation=(
                                "Configure an explicit allowlist of trusted origins instead of reflecting "
                                "the incoming Origin request header. Never pair wildcard/reflected origins with Access-Control-Allow-Credentials: true."
                            ),
                            description=(
                                f"The server on {target_url} dynamically trusts arbitrary third-party origins and allows credentialed access. "
                                "An attacker can host malicious JavaScript on any domain to read authenticated API responses."
                            ),
                            target_url=target_url,
                            cluster_domains=cluster_domains,
                            metadata={"acao": acao, "acac": acac, "tested_origin": self.TEST_ORIGIN},
                        )
                    )
                else:
                    proof = (
                        f"[CONFIRMED // ACTIVE PROOF] Target reflected arbitrary Origin '{self.TEST_ORIGIN}' "
                        f"in Access-Control-Allow-Origin (Credentials disabled)."
                    )
                    findings.append(
                        self.build_finding(
                            title="Overly Permissive CORS Origin Reflection",
                            severity="low",
                            cvss_score=4.3,
                            evidence_proof=proof,
                            remediation="Restrict Access-Control-Allow-Origin to authorized corporate domains.",
                            description=f"The server on {target_url} reflects untrusted request origins without validating against an allowlist.",
                            target_url=target_url,
                            cluster_domains=cluster_domains,
                            metadata={"acao": acao, "acac": acac},
                        )
                    )
        except Exception as e:
            logger.debug(f"[cors_audit] Origin reflection probe failed on {target_url}: {e}")

        # 2. Null Origin Trust Test
        try:
            resp_null = await client.get(
                target_url,
                headers={
                    "Origin": "null",
                    "User-Agent": "Mozilla/5.0 Recon7-CORSAuditor/1.0",
                },
            )
            acao_null = resp_null.headers.get("access-control-allow-origin", "").strip()
            acac_null = resp_null.headers.get("access-control-allow-credentials", "").strip().lower()

            if acao_null == "null" and acac_null == "true":
                proof = (
                    f"[CONFIRMED // ACTIVE PROOF] Target trusts 'Origin: null' with Access-Control-Allow-Credentials: true. "
                    "Sandboxed iframes and local file protocols can initiate cross-origin requests and read sensitive responses."
                )
                findings.append(
                    self.build_finding(
                        title="Vulnerable CORS Policy: Null Origin Trusted with Credentials",
                        severity="medium",
                        cvss_score=6.5,
                        evidence_proof=proof,
                        remediation="Do not trust 'null' origins in CORS configuration. Remove 'null' from the allowed origins list.",
                        description=(
                            f"The server on {target_url} allows 'Origin: null' requests with credentials enabled, "
                            "allowing attacks via sandboxed iframes."
                        ),
                        target_url=target_url,
                        cluster_domains=cluster_domains,
                        metadata={"acao": acao_null, "acac": acac_null},
                    )
                )
        except Exception as e:
            logger.debug(f"[cors_audit] Null origin probe failed on {target_url}: {e}")

        return findings
