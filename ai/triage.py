import re
import json
import logging
from typing import Dict, Any, List
from ai.gateway import complete_prompt

logger = logging.getLogger(__name__)

TRIAGE_SYSTEM_PROMPT = """You are a Principal Red Team Architect and Senior Attack Surface Intelligence Analyst.
Your role is to analyze automated reconnaissance data, triage vulnerabilities and misconfigurations, 
prioritize findings based on true adversarial exploitability, and synthesize actionable multi-step attack chains.

Strict Triage Guidelines:
1. Zero False-Positive Discipline:
   - Differentiate between ACTIVE PROOF (payload confirmed, leaked file, open database) and VERSION ADVISORY (passive banner match).
   - Do NOT claim a vulnerability is actively exploited unless verified in CISA KEV.
   - Note when Linux OS vendors (Ubuntu, Debian, Red Hat) frequently backport security fixes without changing upstream version strings.
   - Acknowledge default framework mitigations (e.g., default Nginx stream limits mitigating HTTP/2 Rapid Reset DoS).
2. Attack Path Synthesis:
   - Correlate disparate reconnaissance nodes: connect staging/dev subdomains, open non-standard ports, discovered tech stacks, and exposed employee emails/GitHub commit authors into coherent 2-3 step red team attack vectors.

Output must be STRICTLY VALID JSON with this exact structure:
{
  "executive_summary": "High-level summary of the target organization's security posture and attack surface.",
  "prioritized_findings": [
    {
      "id": "FIND-001",
      "title": "Finding Title",
      "severity": "critical|high|medium|low|info",
      "affected_asset": "hostname or IP",
      "evidence_tier": "ACTIVE_EXPLOIT_PROOF|VERSION_ADVISORY",
      "rationale": "Concise explanation of adversarial impact with distro/config nuances (2-3 sentences)",
      "recommendation": "Concise remediation and investigative steps (2-3 sentences)",
      "risk_score": 8.5
    }
  ],
  "attack_vectors": [
    {
      "vector_name": "Attack Vector Name",
      "steps": ["Step 1", "Step 2", "Step 3"],
      "likelihood": "High|Medium|Low",
      "impact": "High|Medium|Low"
    }
  ]
}

Important Instructions:
- Focus on the top 8 to 12 most impactful findings to ensure the output is concise, prioritized, and complete.
- Provide up to 3 high-impact attack vectors.
- Do NOT output any markdown text, conversation, or reasoning before or after the JSON.
"""


def parse_and_repair_json(raw_text: str) -> Dict[str, Any]:
    """
    Robust JSON parser for LLM responses.
    Handles markdown code fences, unescaped newlines, trailing commas,
    and truncated outputs (e.g. from hitting token limits).
    """
    if not raw_text or not raw_text.strip():
        raise ValueError("Empty LLM response")

    clean = raw_text.strip()
    
    # 1. Strip markdown fences if present
    if "```json" in clean:
        clean = clean.split("```json", 1)[1]
        if "```" in clean:
            clean = clean.split("```", 1)[0]
    elif "```" in clean:
        clean = clean.split("```", 1)[1]
        if "```" in clean:
            clean = clean.split("```", 1)[0]
    clean = clean.strip()

    # Find opening brace
    start_idx = clean.find("{")
    if start_idx != -1:
        clean = clean[start_idx:]

    # 2. Try standard json.loads
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        pass

    # 3. Progressive truncation repair
    repaired = clean
    repaired = re.sub(r'[,:\s]+$', '', repaired)

    in_string = False
    escape = False
    bracket_stack = []
    
    for ch in repaired:
        if ch == '\\' and not escape:
            escape = True
            continue
        if ch == '"' and not escape:
            in_string = not in_string
        elif not in_string:
            if ch in '{[':
                bracket_stack.append(ch)
            elif ch == '}' and bracket_stack and bracket_stack[-1] == '{':
                bracket_stack.pop()
            elif ch == ']' and bracket_stack and bracket_stack[-1] == '[':
                bracket_stack.pop()
        escape = False

    if in_string:
        repaired += '"'

    repaired = re.sub(r',?\s*"[^"]*"\s*:\s*"\s*$', '', repaired)
    repaired = re.sub(r',?\s*"[^"]*"\s*:\s*$', '', repaired)
    repaired = re.sub(r'[,:\s]+$', '', repaired)

    bracket_stack = []
    in_string = False
    escape = False
    for ch in repaired:
        if ch == '\\' and not escape:
            escape = True
            continue
        if ch == '"' and not escape:
            in_string = not in_string
        elif not in_string:
            if ch in '{[':
                bracket_stack.append(ch)
            elif ch == '}' and bracket_stack and bracket_stack[-1] == '{':
                bracket_stack.pop()
            elif ch == ']' and bracket_stack and bracket_stack[-1] == '[':
                bracket_stack.pop()
        escape = False

    if in_string:
        repaired += '"'

    for b in reversed(bracket_stack):
        if b == '{':
            repaired += '}'
        elif b == '[':
            repaired += ']'

    try:
        return json.loads(repaired)
    except Exception:
        pass

    last_brace = clean.rfind("}")
    if last_brace != -1:
        truncated = clean[:last_brace + 1]
        open_braces = truncated.count("{") - truncated.count("}")
        open_brackets = truncated.count("[") - truncated.count("]")
        truncated += ("]" * max(0, open_brackets)) + ("}" * max(0, open_braces))
        try:
            return json.loads(truncated)
        except Exception:
            pass

    raise ValueError(f"Could not parse or repair JSON from LLM response (length {len(raw_text)})")


def deterministic_triage_findings(scan_job_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    High-Precision Deterministic Triage Engine.
    Executes 100% locally with zero external API key requirements.
    Prioritizes findings by evidence tier, synthesizes realistic attack vectors,
    and formats defensible executive summaries.
    """
    domain = scan_job_data.get("target_domain", "target.com")
    subdomains = scan_job_data.get("subdomains", [])
    ip_resolutions = scan_job_data.get("ip_resolutions", [])
    ports = scan_job_data.get("ports", [])
    vulns = scan_job_data.get("vulns", [])
    people = scan_job_data.get("people", {})

    prioritized_findings = []
    find_counter = 1

    # 1. Prioritize findings based on 4-Tier Taxonomy and severity
    tier_priority = {
        "CONFIRMED": 1,
        "ACTIVE_EXPLOIT_PROOF": 1,
        "LIKELY_VULNERABLE": 2,
        "DISTRO_UNPATCHED_REVISION": 2,
        "POTENTIALLY_AFFECTED": 3,
        "VERSION_ADVISORY": 3,
        "NOT_VULNERABLE": 4,
        "DISTRO_BACKPORT_VERIFIED": 4,
    }
    severity_order = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}

    def finding_sort_key(v):
        f_status = v.get("finding_status") or v.get("evidence_tier") or "POTENTIALLY_AFFECTED"
        f_sev = v.get("severity", "info").lower()
        return (tier_priority.get(f_status, 3), severity_order.get(f_sev, 99))

    sorted_vulns = sorted(vulns, key=finding_sort_key)

    for v in sorted_vulns[:12]:
        sev = v.get("severity", "medium").lower()
        title = v.get("title") or v.get("name") or v.get("cve_id") or "Security Finding"
        host = v.get("host") or domain
        finding_status = v.get("finding_status") or ("CONFIRMED" if v.get("status") == "confirmed" else "POTENTIALLY_AFFECTED")
        tier = v.get("evidence_tier") or finding_status
        
        # Calculate defensible risk score based on 4-Tier evidence
        if finding_status == "CONFIRMED":
            base_score = 9.8 if sev == "critical" else 8.5
        elif finding_status == "LIKELY_VULNERABLE":
            base_score = 8.5 if sev == "critical" else 7.0
        elif finding_status == "NOT_VULNERABLE":
            base_score = 1.0  # Patched / Defended
        else:
            base_score = 5.0 if sev in ("critical", "high") else 3.5

        rationale = v.get("evidence_proof") or v.get("description") or f"Evaluated {title} on {host}."

        prioritized_findings.append({
            "id": f"FIND-{find_counter:03d}",
            "title": title,
            "severity": sev,
            "affected_asset": host,
            "evidence_tier": tier,
            "finding_status": finding_status,
            "status_label": v.get("status_label") or finding_status,
            "rationale": rationale,
            "recommendation": v.get("remediation") or "Review service exposure and apply latest vendor patches.",
            "risk_score": round(base_score, 1),
        })
        find_counter += 1

    # 2. Synthesize Deterministic Attack Vectors
    attack_vectors = []

    # Vector A: Staging / Dev Perimeter Vector
    dev_subs = [s.get("subdomain") for s in subdomains if any(k in s.get("subdomain", "").lower() for k in ["dev", "staging", "test", "uat", "admin", "internal"])]
    if dev_subs:
        sample_dev = dev_subs[0]
        attack_vectors.append({
            "vector_name": "Non-Production & Staging Perimeter Exposure",
            "steps": [
                f"Identify public DNS resolution for non-production asset '{sample_dev}'.",
                "Probe exposed HTTP routes for debug headers, Swagger UI, or unauthenticated API endpoints.",
                "Leverage staging environment information leakage to target production infrastructure."
            ],
            "likelihood": "High",
            "impact": "High"
        })

    # Vector B: People OSINT & Social Engineering Vector
    confirmed_people = people.get("confirmed_count", 0)
    email_pattern = people.get("email_pattern")
    if confirmed_people > 0 or email_pattern:
        attack_vectors.append({
            "vector_name": "Targeted Corporate Spearphishing & Identity Reconnaissance",
            "steps": [
                f"Harvest corporate employee identities ({confirmed_people} confirmed profiles cataloged).",
                f"Generate targeted address lists using verified syntax: '{email_pattern or '{first}.{last}@' + domain}'.",
                "Execute credential harvesting or OAuth consent phishing campaigns against discovered department personnel."
            ],
            "likelihood": "High",
            "impact": "High" if confirmed_people > 5 else "Medium"
        })

    # Vector C: Direct Origin IP / WAF Bypass Vector
    direct_origins = [h.get("ips", []) for h in ip_resolutions if not h.get("is_cdn") and h.get("ips")]
    if direct_origins:
        sample_ip = direct_origins[0][0]
        attack_vectors.append({
            "vector_name": "Cloud WAF Bypass via Direct Origin IP",
            "steps": [
                f"Discover unmasked bare-metal origin IP '{sample_ip}' via MX/SPF records or SSL host certificates.",
                "Send direct HTTP/TCP payloads bypassing Cloudflare/Akamai rate limits and WAF filtering rules.",
                "Exploit unshielded web application endpoints directly on the origin server."
            ],
            "likelihood": "Medium",
            "impact": "High"
        })

    if not attack_vectors:
        attack_vectors.append({
            "vector_name": "Perimeter Service Reconnaissance & Version Auditing",
            "steps": [
                "Map all active perimeter IP addresses and open TCP service ports.",
                "Evaluate software versions against vulnerability advisories and vendor backport notices.",
                "Verify authentication barriers on exposed HTTP endpoints."
            ],
            "likelihood": "Medium",
            "impact": "Medium"
        })

    # 3. Executive Summary
    summary = (
        f"Automated attack surface assessment for '{domain}' completed. Discovered {len(subdomains)} subdomains, "
        f"{len(ip_resolutions)} active hosts, and {len(ports)} open service ports. "
        f"Identified {len(prioritized_findings)} prioritized security items across external perimeter assets. "
        f"People OSINT harvested {confirmed_people} employee profiles with '{email_pattern or 'standard'}' corporate syntax."
    )

    return {
        "executive_summary": summary,
        "prioritized_findings": prioritized_findings,
        "attack_vectors": attack_vectors,
    }


def triage_findings(scan_job_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Step 9: AI Triage Layer.
    Consumes structured findings, prioritizes attack surface, and suggests offensive attack vectors.
    Falls back gracefully to the High-Precision Deterministic Engine when no LLM API key is present.
    """
    domain = scan_job_data.get("target_domain", "target.com")
    logger.info(f"[ai.triage] Running attack surface triage for '{domain}'")

    # Build concise digest of findings to optimize token usage
    digest = {
        "target_domain": domain,
        "org_metadata": scan_job_data.get("company_info", {}),
        "total_subdomains": len(scan_job_data.get("subdomains", [])),
        "sample_subdomains": [s.get("subdomain") for s in scan_job_data.get("subdomains", [])[:20]],
        "hosts_and_ips": scan_job_data.get("ip_resolutions", [])[:15],
        "open_ports_and_services": scan_job_data.get("ports", [])[:20],
        "tech_stack": scan_job_data.get("fingerprints", [])[:15],
        "vulnerabilities": scan_job_data.get("vulns", [])[:25],
        "people_osint": {
            "email_pattern": scan_job_data.get("people", {}).get("email_pattern"),
            "confirmed_count": scan_job_data.get("people", {}).get("confirmed_count", 0),
            "sample_emails": [p.get("email") for p in scan_job_data.get("people", {}).get("people", [])[:10] if p.get("email")],
        }
    }

    prompt = f"Analyze the following structured reconnaissance findings for target domain '{domain}':\n\n```json\n{json.dumps(digest, indent=2)}\n```"

    try:
        raw_response = complete_prompt(
            prompt=prompt,
            system_prompt=TRIAGE_SYSTEM_PROMPT,
            temperature=0.2,
            max_tokens=8192,
        )

        if raw_response and raw_response.strip():
            data = parse_and_repair_json(raw_response)
            if data and "prioritized_findings" in data:
                logger.info(f"[ai.triage] Successfully parsed AI triage output ({len(data.get('prioritized_findings', []))} findings)")
                return data
    except Exception as e:
        logger.warning(f"[ai.triage] AI Gateway triage unavailable or failed ({e}). Activating deterministic triage engine.")

    logger.info(f"[ai.triage] Executing deterministic triage engine for '{domain}' (zero API keys required)")
    return deterministic_triage_findings(scan_job_data)

