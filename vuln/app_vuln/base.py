import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import httpx

logger = logging.getLogger(__name__)


class BaseAppVulnPlugin(ABC):
    """
    Abstract Base Class for all Application Vulnerability Detection Plugins.
    Enforces non-destructive execution, strict timeout controls, and 4-tier evidence formatting.
    """
    plugin_id: str = "base_plugin"
    name: str = "Base Application Vulnerability Plugin"
    description: str = ""
    owasp_category: str = "A05:2021 - Security Misconfiguration"
    cwe_id: str = "CWE-16"
    default_severity: str = "medium"
    default_cvss: float = 5.3

    @abstractmethod
    async def audit(
        self,
        target_url: str,
        context: Dict[str, Any],
        client: httpx.AsyncClient,
    ) -> List[Dict[str, Any]]:
        """
        Executes non-destructive vulnerability probing against target URL.
        Returns a list of standardized finding dictionaries.
        """
        pass

    def build_finding(
        self,
        title: str,
        severity: str,
        cvss_score: float,
        evidence_proof: str,
        remediation: str,
        description: str,
        target_url: str,
        cve_id: Optional[str] = None,
        cwe_ids: Optional[List[str]] = None,
        owasp_category: Optional[str] = None,
        cluster_domains: Optional[List[str]] = None,
        finding_status: str = "CONFIRMED",
        evidence_tier: str = "ACTIVE_EXPLOIT_PROOF",
        confidence: float = 0.99,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Constructs a standardized finding record conforming to Recon7's 4-Tier Evidence Taxonomy.
        """
        cwe_list = cwe_ids or [self.cwe_id]
        owasp_cat = owasp_category or self.owasp_category
        resolved_cve_id = cve_id or f"APP-VULN-{self.plugin_id.upper()}"

        return {
            "cve_id": resolved_cve_id,
            "template_id": self.plugin_id,
            "title": title,
            "name": title,
            "severity": severity or self.default_severity,
            "cvss_score": cvss_score or self.default_cvss,
            "status": "confirmed" if finding_status == "CONFIRMED" else "potential",
            "finding_status": finding_status,
            "evidence_tier": evidence_tier,
            "confidence": confidence,
            "host": target_url,
            "url": target_url,
            "matched_at": target_url,
            "evidence_proof": evidence_proof,
            "evidence": f"Active application probe ({self.name}): {evidence_proof}",
            "description": description or self.description,
            "remediation": remediation,
            "detection_method": "active_app_probe",
            "source_tool": f"vuln.app_vuln.{self.plugin_id}",
            "cve_ids": [resolved_cve_id] if resolved_cve_id.startswith("CVE-") else [],
            "cwe_ids": cwe_list,
            "owasp_category": owasp_cat,
            "cisa_kev": False,
            "exploit_available": finding_status == "CONFIRMED",
            "exploit_type": "Direct HTTP Application Exploit",
            "cluster_domains": cluster_domains or [],
            "metadata": metadata or {},
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }
