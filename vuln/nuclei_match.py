import json
import logging
import re
import shutil
import subprocess
from typing import List, Dict, Any, Optional
import httpx
from core.config import settings

logger = logging.getLogger(__name__)

# Common web security checks for internal fallback scanner
FALLBACK_SECURITY_PROBES = [
    {
        "id": "exposed-git-config",
        "name": "Exposed .git Configuration",
        "path": "/.git/config",
        "match_pattern": r"\[core\]",
        "severity": "high",
        "description": "Git repository configuration file publicly accessible, allowing source code extraction.",
        "cwe_id": "CWE-538",
    },
    {
        "id": "exposed-env-file",
        "name": "Exposed Environment File (.env)",
        "path": "/.env",
        "match_pattern": r"(DB_PASSWORD|SECRET_KEY|API_KEY|APP_ENV)=",
        "severity": "critical",
        "description": "Environment configuration file exposed containing sensitive application secrets and keys.",
        "cwe_id": "CWE-552",
    },
    {
        "id": "springboot-actuator-env",
        "name": "Spring Boot Actuator Exposed",
        "path": "/actuator/env",
        "match_pattern": r'"activeProfiles":',
        "severity": "high",
        "description": "Spring Boot actuator environment endpoint publicly exposed.",
        "cwe_id": "CWE-200",
    },
    {
        "id": "swagger-api-docs",
        "name": "Exposed Swagger / OpenAPI Documentation",
        "path": "/swagger-ui.html",
        "match_pattern": r"swagger-ui",
        "severity": "low",
        "description": "Interactive API documentation publicly accessible, expanding attack surface.",
        "cwe_id": "CWE-200",
    },
]


def run_nuclei_scans(targets: List[str], timeout: int = 180) -> List[Dict[str, Any]]:
    """
    Step 6: Runs nuclei template scans against discovered web targets.
    Falls back to internal HTTP security baseline probes if nuclei CLI is absent.
    """
    logger.info(f"[vuln.nuclei_match] Running vulnerability matching for {len(targets)} targets")
    
    nuclei_bin = shutil.which(settings.NUCLEI_BIN) or shutil.which("nuclei")
    results: List[Dict[str, Any]] = []

    if nuclei_bin:
        try:
            cli_results = _run_nuclei_cli(nuclei_bin, targets, timeout=settings.NUCLEI_TIMEOUT_SECONDS)
            if cli_results:
                results.extend(cli_results)
        except Exception as e:
            logger.warning(f"nuclei CLI execution failed: {e}")

    # Fallback to internal security header & path prober if no results or CLI missing
    if not results:
        results = _run_internal_security_checks(targets, timeout=10)

    logger.info(f"[vuln.nuclei_match] Discovered {len(results)} potential vulnerability findings")
    return results


def _run_nuclei_cli(binary_path: str, targets: List[str], timeout: int = 180) -> List[Dict[str, Any]]:
    """Executes nuclei CLI with JSONL output."""
    results = []
    input_str = "\n".join(targets)
    
    cmd = [
        binary_path,
        "-silent",
        "-jsonl",
        "-duc", # disable update check
    ]
    proc = subprocess.run(
        cmd,
        input=input_str,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
    )
    if proc.stdout:
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                info = item.get("info", {})
                classification = info.get("classification", {})
                
                results.append({
                    "template_id": item.get("template-id", "unknown"),
                    "name": info.get("name", "Vulnerability Finding"),
                    "severity": info.get("severity", "info").lower(),
                    "host": item.get("host", ""),
                    "matched_at": item.get("matched-at", ""),
                    "description": info.get("description", ""),
                    "cve_ids": classification.get("cve-id") or [],
                    "cwe_ids": classification.get("cwe-id") or [],
                    "cvss_score": classification.get("cvss-score"),
                    "curl_command": item.get("curl-command", ""),
                    "source_tool": "nuclei",
                })
            except json.JSONDecodeError:
                pass
    return results


def _run_internal_security_checks(targets: List[str], timeout: int = 8) -> List[Dict[str, Any]]:
    """Internal HTTP baseline security inspector."""
    results = []
    
    with httpx.Client(
        timeout=timeout,
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 R7-VulnScanner/1.0"},
    ) as client:
        for target in targets:
            base_url = target if target.startswith("http") else f"https://{target}"
            
            # 1. Check Missing Security Headers on Base URL
            try:
                resp = client.get(base_url)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                
                # Check HSTS
                if base_url.startswith("https") and "strict-transport-security" not in headers:
                    results.append({
                        "template_id": "http-missing-hsts",
                        "name": "Missing Strict-Transport-Security (HSTS) Header",
                        "severity": "low",
                        "host": target,
                        "matched_at": base_url,
                        "description": "The web server does not enforce HTTPS connections via HSTS header.",
                        "cve_ids": [],
                        "cwe_ids": ["CWE-319"],
                        "cvss_score": 3.1,
                        "source_tool": "r7_security_baseline",
                    })

                # Check CSP
                if "content-security-policy" not in headers:
                    results.append({
                        "template_id": "http-missing-csp",
                        "name": "Missing Content-Security-Policy (CSP) Header",
                        "severity": "low",
                        "host": target,
                        "matched_at": base_url,
                        "description": "No Content-Security-Policy header defined, increasing risk of Cross-Site Scripting (XSS).",
                        "cve_ids": [],
                        "cwe_ids": ["CWE-1021"],
                        "cvss_score": 3.5,
                        "source_tool": "r7_security_baseline",
                    })
                    
                # Check Clickjacking X-Frame-Options
                if "x-frame-options" not in headers and "content-security-policy" not in headers:
                    results.append({
                        "template_id": "http-missing-x-frame-options",
                        "name": "Missing Anti-Clickjacking Header (X-Frame-Options)",
                        "severity": "low",
                        "host": target,
                        "matched_at": base_url,
                        "description": "Target page can be embedded in an iframe, potentially enabling clickjacking attacks.",
                        "cve_ids": [],
                        "cwe_ids": ["CWE-1021"],
                        "cvss_score": 3.0,
                        "source_tool": "r7_security_baseline",
                    })
            except Exception:
                pass

            # 2. Check Sensitive Exposed Paths
            for probe in FALLBACK_SECURITY_PROBES:
                try:
                    probe_url = f"{base_url.rstrip('/')}{probe['path']}"
                    p_resp = client.get(probe_url)
                    if p_resp.status_code == 200 and re.search(probe["match_pattern"], p_resp.text):
                        results.append({
                            "template_id": probe["id"],
                            "name": probe["name"],
                            "severity": probe["severity"],
                            "host": target,
                            "matched_at": probe_url,
                            "description": probe["description"],
                            "cve_ids": [],
                            "cwe_ids": [probe["cwe_id"]],
                            "cvss_score": 7.5 if probe["severity"] == "high" else (9.0 if probe["severity"] == "critical" else 4.0),
                            "source_tool": "r7_path_prober",
                        })
                except Exception:
                    pass

    return results
