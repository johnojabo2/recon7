import re
import logging
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx
from vuln.app_vuln.base import BaseAppVulnPlugin

logger = logging.getLogger(__name__)


class SstiProbePlugin(BaseAppVulnPlugin):
    """
    Non-destructive Server-Side Template Injection (SSTI) Arithmetic Prober.
    Validates template engine code execution via deterministic mathematical evaluation (4919 * 7 = 34433)
    without triggering intrusive system shell commands or modifying backend state.
    """
    plugin_id = "ssti_probe"
    name = "Server-Side Template Injection (SSTI) Arithmetic Evaluation"
    description = (
        "Injects benign mathematical expressions into URL parameters to verify if the server-side "
        "template engine executes expressions in the runtime context."
    )
    owasp_category = "A03:2021 - Injection"
    cwe_id = "CWE-1336"
    default_severity = "critical"
    default_cvss = 9.8

    # Math expression probes with distinct expected product '34433'
    # 4919 * 7 = 34433
    EXPECTED_PRODUCT = "34433"
    PROBE_TEMPLATES = [
        ("{{4919*7}}", "Jinja2 / Twig / Nunjucks Template Injection"),
        ("${4919*7}", "Java FreeMarker / Thymeleaf / Smarty / Spring Expression Language"),
        ("#{4919*7}", "Ruby / Spring EL Expression Injection"),
        ("<%= 4919*7 %>", "ERB / EJS Template Injection"),
    ]

    CANDIDATE_PARAMS = ["q", "query", "search", "name", "template", "id", "msg", "page", "preview", "view", "item"]

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

        # Collect target parameters: either existing in URL or candidate probe parameters
        params_to_test = list(params.keys()) if params else self.CANDIDATE_PARAMS[:3]

        for param_name in params_to_test:
            for probe_payload, engine_hint in self.PROBE_TEMPLATES:
                # Construct query with injected payload
                test_params = dict(params)
                test_params[param_name] = [probe_payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, new_query, parsed.fragment))

                try:
                    resp = await client.get(
                        test_url,
                        headers={"User-Agent": "Mozilla/5.0 Recon7-SSTIProbe/1.0"},
                    )

                    body_text = resp.text

                    # Verification Rule:
                    # 1. Evaluated product '34433' must appear in body
                    # 2. Raw math expression '4919*7' must NOT appear right beside it (to rule out raw reflection)
                    if self.EXPECTED_PRODUCT in body_text:
                        # Check if it was true evaluation rather than literal string reflection
                        if probe_payload not in body_text and "4919*7" not in body_text:
                            proof = (
                                f"[CONFIRMED // ACTIVE PROOF] Server evaluated mathematical expression '{probe_payload}' "
                                f"in parameter '{param_name}' and rendered result '{self.EXPECTED_PRODUCT}'. "
                                f"Engine family: {engine_hint}."
                            )
                            findings.append(
                                self.build_finding(
                                    title=f"Critical Remote Code Execution: Server-Side Template Injection ({engine_hint})",
                                    severity="critical",
                                    cvss_score=9.8,
                                    evidence_proof=proof,
                                    remediation=(
                                        "Ensure user inputs are never passed directly to template engine compilation functions. "
                                        "Use parameterized templates and enforce strict sandboxing (e.g. Jinja2 SandboxedEnvironment)."
                                    ),
                                    description=(
                                        f"The application on {test_url} executes untrusted user input inside a server-side template engine. "
                                        "An attacker can escalate this to full unauthenticated Remote Code Execution (RCE)."
                                    ),
                                    target_url=test_url,
                                    cluster_domains=cluster_domains,
                                    metadata={
                                        "parameter": param_name,
                                        "probe": probe_payload,
                                        "engine_hint": engine_hint,
                                        "evaluated_product": self.EXPECTED_PRODUCT,
                                    },
                                )
                            )
                            # Once proven on this param, avoid redundant triggers
                            return findings
                except Exception as e:
                    logger.debug(f"[ssti_probe] Probe error on {test_url}: {e}")

        return findings
