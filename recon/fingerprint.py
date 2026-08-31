import json
import logging
import re
import shutil
import subprocess
from typing import List, Dict, Any, Optional
import httpx
from bs4 import BeautifulSoup
from core.config import settings

logger = logging.getLogger(__name__)

# Built-in Wappalyzer-style Technology Signatures
BUILTIN_SIGNATURES = [
    {
        "name": "WordPress",
        "category": "CMS",
        "headers": {"x-powered-by": r"WordPress"},
        "body": [r"wp-content/themes", r"wp-includes/", r'<meta name="generator" content="WordPress\s*([0-9.]+)?'],
    },
    {
        "name": "Nginx",
        "category": "Web Server",
        "headers": {"server": r"nginx(?:/([0-9.]+))?"},
    },
    {
        "name": "Apache Tomcat",
        "category": "Application Server",
        "headers": {"server": r"Apache-Coyote(?:/([0-9.]+))?"},
    },
    {
        "name": "Apache HTTP Server",
        "category": "Web Server",
        "headers": {"server": r"Apache(?:-Server)?/([0-9.]+)"},
    },
    {
        "name": "Microsoft IIS",
        "category": "Web Server",
        "headers": {"server": r"Microsoft-IIS(?:/([0-9.]+))?"},
    },
    {
        "name": "Cloudflare",
        "category": "CDN/WAF",
        "headers": {"server": r"cloudflare", "cf-ray": r".+"},
    },
    {
        "name": "React",
        "category": "JavaScript Framework",
        "body": [r'data-reactroot', r'_reactRootContainer', r'react\.production\.min\.js'],
    },
    {
        "name": "Next.js",
        "category": "Web Framework",
        "headers": {"x-powered-by": r"Next\.js"},
        "body": [r'__NEXT_DATA__', r'/_next/static/'],
    },
    {
        "name": "Vue.js",
        "category": "JavaScript Framework",
        "body": [r'data-v-[a-f0-9]+', r'vue\.min\.js'],
    },
    {
        "name": "Django",
        "category": "Web Framework",
        "headers": {"set-cookie": r"csrftoken="},
    },
    {
        "name": "Laravel",
        "category": "Web Framework",
        "headers": {"set-cookie": r"laravel_session="},
    },
    {
        "name": "ASP.NET",
        "category": "Web Framework",
        "headers": {"x-powered-by": r"ASP\.NET", "set-cookie": r"ASP\.NET_SessionId="},
    },
    {
        "name": "PHP",
        "category": "Programming Language",
        "headers": {"x-powered-by": r"PHP(?:/([0-9.]+))?", "set-cookie": r"PHPSESSID="},
    },
    {
        "name": "Express",
        "category": "Web Framework",
        "headers": {"x-powered-by": r"Express"},
    },
    {
        "name": "Spring Boot",
        "category": "Web Framework",
        "headers": {"x-application-context": r".+"},
        "body": [r'Whitelabel Error Page'],
    },
    {
        "name": "Bootstrap",
        "category": "UI Framework",
        "body": [r'bootstrap(?:\.min)?\.css', r'bootstrap(?:\.min)?\.js'],
    },
    {
        "name": "jQuery",
        "category": "JavaScript Library",
        "body": [r'jquery(?:-([0-9.]+))?(?:\.min)?\.js'],
    },
    {
        "name": "Grafana",
        "category": "Monitoring",
        "body": [r'<title>Grafana</title>', r'window\.grafanaBootData'],
    },
    {
        "name": "Jenkins",
        "category": "CI/CD",
        "headers": {"x-jenkins": r".+"},
    },
]


def fingerprint_target_urls(urls_or_hosts: List[str], timeout: int = 10) -> List[Dict[str, Any]]:
    """
    Step 5: Inspects HTTP services and fingerprints tech stack using httpx and local Wappalyzer signatures.
    """
    logger.info(f"[recon.fingerprint] Fingerprinting {len(urls_or_hosts)} hosts/URLs")
    
    httpx_bin = shutil.which(settings.HTTPX_BIN) or shutil.which("httpx")
    
    # Format URLs
    formatted_urls = []
    for item in urls_or_hosts:
        if item.startswith("http://") or item.startswith("https://"):
            formatted_urls.append(item)
        else:
            formatted_urls.append(f"https://{item}")
            formatted_urls.append(f"http://{item}")

    results: List[Dict[str, Any]] = []

    # If httpx CLI is available, run it
    if httpx_bin:
        try:
            cli_results = _run_httpx_cli(httpx_bin, formatted_urls, timeout=settings.HTTPX_TIMEOUT_SECONDS)
            if cli_results:
                results.extend(cli_results)
        except Exception as e:
            logger.warning(f"httpx CLI fingerprint failed: {e}")

    # If no results or httpx CLI was not available, run internal async/sync HTTP fingerprint engine
    if not results:
        results = _run_internal_fingerprint(formatted_urls, timeout=timeout)

    logger.info(f"[recon.fingerprint] Fingerprinted {len(results)} active web services")
    return results


def _run_internal_fingerprint(urls: List[str], timeout: int = 8) -> List[Dict[str, Any]]:
    """Internal HTTP prober + signature evaluator."""
    results = []
    
    with httpx.Client(
        timeout=timeout,
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) R7-Fingerprint/1.0"},
    ) as client:
        for url in urls:
            try:
                resp = client.get(url)
                body_text = resp.text
                headers_lower = {k.lower(): str(v) for k, v in resp.headers.items()}
                
                # Extract title
                title = ""
                try:
                    soup = BeautifulSoup(body_text[:50000], "html.parser")
                    if soup.title and soup.title.string:
                        title = soup.title.string.strip()
                except Exception:
                    pass

                techs = match_signatures(headers_lower, body_text)

                results.append({
                    "url": str(resp.url),
                    "status_code": resp.status_code,
                    "title": title,
                    "web_server": headers_lower.get("server", "unknown"),
                    "technologies": techs,
                    "content_length": len(resp.content),
                    "content_type": headers_lower.get("content-type", ""),
                })
            except Exception as e:
                logger.debug(f"Failed to probe {url}: {e}")

    return results


def match_signatures(headers: Dict[str, str], body_text: str) -> List[Dict[str, Any]]:
    """Matches headers and HTML body against technology signatures."""
    detected = []
    
    for sig in BUILTIN_SIGNATURES:
        name = sig["name"]
        category = sig.get("category", "General")
        version = ""
        matched = False

        # Header checks
        if "headers" in sig:
            for hdr_name, pattern in sig["headers"].items():
                if hdr_name in headers:
                    m = re.search(pattern, headers[hdr_name], re.IGNORECASE)
                    if m:
                        matched = True
                        if m.groups() and m.group(1):
                            version = m.group(1)
                        break

        # Body checks
        if not matched and "body" in sig and body_text:
            for pattern in sig["body"]:
                m = re.search(pattern, body_text, re.IGNORECASE)
                if m:
                    matched = True
                    if m.groups() and m.group(1):
                        version = m.group(1)
                    break

        if matched:
            detected.append({
                "name": name,
                "category": category,
                "version": version,
                "confidence": 95 if version else 85,
            })

    return detected


def _run_httpx_cli(binary_path: str, urls: List[str], timeout: int = 60) -> List[Dict[str, Any]]:
    """Executes httpx CLI tool with JSON output."""
    results = []
    # Write targets to stdin or pass as args
    input_urls = "\n".join(urls)
    cmd = [
        binary_path,
        "-silent",
        "-title",
        "-tech-detect",
        "-status-code",
        "-json",
    ]
    proc = subprocess.run(
        cmd,
        input=input_urls,
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
                url = item.get("url")
                status_code = item.get("status_code", 0)
                title = item.get("title", "")
                tech_list = item.get("tech", [])
                
                techs = [
                    {"name": t, "category": "General", "version": "", "confidence": 90}
                    for t in tech_list
                ]
                results.append({
                    "url": url,
                    "status_code": status_code,
                    "title": title,
                    "web_server": item.get("webserver", "unknown"),
                    "technologies": techs,
                })
            except json.JSONDecodeError:
                pass
    return results
