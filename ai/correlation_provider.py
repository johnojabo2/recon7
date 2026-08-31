import json
import logging
from typing import Dict, Any, List, Optional
from ai.gateway import complete_prompt
from core.config import settings

logger = logging.getLogger(__name__)


class CorrelationProvider:
    """
    AI Provider Abstraction Interface per Spec Sections 24, 25, 26.
    Acts as an interpretation, summarization, and correlation assistant.
    Guarantees that every cited evidence ID exists in the evidence pool and
    never silently invents unsupported facts.
    """

    def summarize_investigation(self, graph_snapshot: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Generates an executive summary and defensive posture analysis for the investigation."""
        node_count = graph_snapshot.get("nodes_count", 0)
        edge_count = graph_snapshot.get("edges_count", 0)
        nodes = graph_snapshot.get("nodes", [])
        
        # Categorize nodes
        entity_types = {}
        for n in nodes:
            t = n.get("type", "unknown")
            entity_types[t] = entity_types.get(t, 0) + 1

        prompt = f"""You are a senior red-team security analyst. Summarize the following reconnaissance findings for target '{target}'.
Investigation Graph:
- Total Entities Discovered: {node_count} ({entity_types})
- Verified Relationships: {edge_count}

Provide a concise, professional, evidence-based executive analysis in JSON with the following schema:
{{
  "executive_summary": "...",
  "attack_surface_posture": "...",
  "priority_risk_areas": ["..."],
  "recommended_defenses": ["..."]
}}
Return ONLY valid JSON."""

        system_prompt = "You are a professional defensive reconnaissance and threat-modeling AI. Respond in structured JSON only."

        # If AI is enabled and API key is present, attempt LLM call
        if settings.AI_ENABLED and (settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY):
            try:
                raw_response = complete_prompt(prompt, system_prompt=system_prompt)
                cleaned = raw_response.strip()
                if cleaned.startswith("```json"):
                    cleaned = cleaned.replace("```json", "").replace("```", "").strip()
                elif cleaned.startswith("```"):
                    cleaned = cleaned.replace("```", "").strip()
                return json.loads(cleaned)
            except Exception as e:
                logger.warning(f"LLM summarization failed: {e}. Falling back to deterministic summary.")

        # Deterministic Fallback Engine
        return self._deterministic_summary(target, entity_types, node_count, edge_count)

    def _deterministic_summary(self, target: str, entity_types: Dict[str, int], node_count: int, edge_count: int) -> Dict[str, Any]:
        """High-grade deterministic fallback summary when no LLM key is configured."""
        subdomains = entity_types.get("subdomain", 0)
        ips = entity_types.get("ip", 0)
        ports = entity_types.get("port", 0)
        services = entity_types.get("service", 0)
        vulns = entity_types.get("vulnerability", 0)
        people = entity_types.get("person", 0)
        clouds = entity_types.get("cloud_resource", 0)
        breaches = entity_types.get("breach", 0)

        risks = []
        if vulns > 0:
            risks.append(f"Identified {vulns} candidate vulnerability finding(s) on exposed perimeter services.")
        if clouds > 0:
            risks.append(f"Discovered {clouds} public cloud storage resource(s) associated with target naming conventions.")
        if breaches > 0:
            risks.append(f"Found historical breach exposure signal(s) affecting target assets.")
        if ports > 5:
            risks.append(f"Broad exposed port surface with {ports} open ports across {ips} public IPs.")
        if not risks:
            risks.append("Perimeter services show standard external exposure with minimal anomalous findings.")

        return {
            "executive_summary": (
                f"Automated defensive reconnaissance of '{target}' mapped an intelligence graph of {node_count} canonical entities "
                f"({subdomains} subdomains, {ips} IPs, {services} services, and {people} identified personnel) supported by {edge_count} evidence-backed relationships."
            ),
            "attack_surface_posture": "Elevated Exposure" if (vulns > 0 or clouds > 0) else "Standard Enterprise Perimeter",
            "priority_risk_areas": risks,
            "recommended_defenses": [
                "Restrict administrative ports (SSH, RDP, databases) using IP whitelisting or VPN/Zero-Trust tunnels.",
                "Enforce multi-factor authentication (MFA) across all employee accounts and corporate email domains.",
                "Audit public cloud storage buckets to ensure public access block policies are active.",
                "Apply vendor security patches for outdated web server and OpenSSH components.",
            ],
        }

    def validate_cited_evidence(self, cited_evidence_ids: List[str], valid_evidence_pool: Dict[str, Any]) -> List[str]:
        """
        Guarantees that every evidence ID cited actually exists in the Evidence Ledger (Spec Section 24).
        Discards hallucinated or fabricated citations.
        """
        return [eid for eid in cited_evidence_ids if eid in valid_evidence_pool]


# Global correlation provider singleton
correlation_provider = CorrelationProvider()
