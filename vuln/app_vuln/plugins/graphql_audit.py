import logging
import json
from typing import Dict, Any, List
import httpx
from vuln.app_vuln.base import BaseAppVulnPlugin

logger = logging.getLogger(__name__)


class GraphQLAuditPlugin(BaseAppVulnPlugin):
    """
    Non-destructive GraphQL Endpoint Discovery & Schema Introspection Auditor.
    Identifies publicly reachable GraphQL interfaces and maps unauthenticated API surface.
    """
    plugin_id = "graphql_audit"
    name = "GraphQL Schema Introspection & Attack Surface Exposure"
    description = (
        "Probes web endpoints for enabled GraphQL introspection, exposing entire internal "
        "data models, database schemas, mutations, and hidden API queries to unauthenticated attackers."
    )
    owasp_category = "A01:2021 - Broken Access Control"
    cwe_id = "CWE-200"
    default_severity = "medium"
    default_cvss = 6.5

    COMMON_GRAPHQL_PATHS = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/api/v1/graphql",
        "/query",
        "/api/query",
    ]

    INTROSPECTION_QUERY = {
        "query": "{ __schema { queryType { name fields { name } } types { name kind } } }"
    }

    async def audit(
        self,
        target_url: str,
        context: Dict[str, Any],
        client: httpx.AsyncClient,
    ) -> List[Dict[str, Any]]:
        findings = []
        cluster_domains = context.get("cluster_domains", [])
        base_clean = target_url.rstrip("/")

        for path in self.COMMON_GRAPHQL_PATHS:
            endpoint_url = f"{base_clean}{path}"
            try:
                # 1. POST JSON Introspection Query
                resp = await client.post(
                    endpoint_url,
                    json=self.INTROSPECTION_QUERY,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "Mozilla/5.0 Recon7-GraphQLAuditor/1.0",
                    },
                )
                
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        schema = data.get("data", {}).get("__schema")
                        if schema and isinstance(schema, dict):
                            types = schema.get("types", [])
                            query_fields = schema.get("queryType", {}).get("fields", [])
                            type_names = [t.get("name") for t in types if t.get("name") and not t.get("name", "").startswith("__")]
                            field_names = [f.get("name") for f in query_fields if f.get("name")]

                            sensitive_indicators = [
                                fn for fn in field_names
                                if any(k in fn.lower() for k in ["admin", "user", "auth", "token", "password", "secret", "billing", "payment", "internal", "config"])
                            ]

                            proof = (
                                f"[CONFIRMED // ACTIVE PROOF] GraphQL Introspection enabled on '{endpoint_url}'. "
                                f"Extracted {len(type_names)} custom object types and {len(field_names)} public query methods. "
                                f"Sample queries exposed: {', '.join(field_names[:8]) or 'Standard Schema'}."
                            )
                            if sensitive_indicators:
                                proof += f" Potentially privileged methods detected: {', '.join(sensitive_indicators[:5])}."

                            findings.append(
                                self.build_finding(
                                    title="Publicly Exposed GraphQL Schema Introspection & API Surface",
                                    severity="medium",
                                    cvss_score=6.5,
                                    evidence_proof=proof,
                                    remediation=(
                                        "Disable GraphQL introspection in production environments. "
                                        "In Apollo Server, set 'introspection: false'; in GraphQL-Yoga / Express-GraphQL, disable introspection middleware in production."
                                    ),
                                    description=(
                                        f"The GraphQL endpoint on {endpoint_url} permits arbitrary introspection queries. "
                                        "Attackers can reconstruct the complete schema, internal relationships, and undocumented queries."
                                    ),
                                    target_url=endpoint_url,
                                    cluster_domains=cluster_domains,
                                    metadata={
                                        "endpoint": endpoint_url,
                                        "total_types": len(type_names),
                                        "total_queries": len(field_names),
                                        "sample_queries": field_names[:10],
                                        "sensitive_queries": sensitive_indicators,
                                    },
                                )
                            )
                            # Once confirmed on a path, avoid duplicate reports on subsequent paths for this host
                            break
                    except json.JSONDecodeError:
                        pass
            except Exception as e:
                logger.debug(f"[graphql_audit] Probe failed on {endpoint_url}: {e}")

        return findings
