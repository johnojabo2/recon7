import re
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Multi-Signal Technology Rules Dictionary
# Each technology specifies multiple independent signal patterns across headers, html, scripts, cookies, meta
TECH_RULES: List[Dict[str, Any]] = [
    {
        "name": "WordPress",
        "category": "CMS",
        "signals": {
            "meta_generator": r"WordPress(?:\s+([0-9.]+))?",
            "headers": {"x-powered-by": r"WordPress"},
            "html_patterns": [r"wp-content/(?:themes|plugins)", r"wp-includes/"],
            "script_paths": [r"/wp-content/", r"/wp-includes/js/"],
            "cookies": [r"wordpress_logged_in_", r"wp-settings-"],
        },
    },
    {
        "name": "Next.js",
        "category": "Web Framework",
        "signals": {
            "headers": {"x-powered-by": r"Next\.js"},
            "html_patterns": [r'<script\s+id="__NEXT_DATA__"', r'/_next/static/'],
            "script_paths": [r"/_next/static/chunks/"],
        },
    },
    {
        "name": "React",
        "category": "JavaScript Framework",
        "signals": {
            "html_patterns": [r'data-reactroot', r'_reactRootContainer', r'<div id="root">'],
            "script_paths": [r'react(?:\.production\.min)?\.js', r'react-dom'],
        },
    },
    {
        "name": "Vue.js",
        "category": "JavaScript Framework",
        "signals": {
            "html_patterns": [r'data-v-[a-f0-9]{6,10}', r'v-cloak', r'<div id="app">'],
            "script_paths": [r'vue(?:\.runtime)?(?:\.min)?\.js'],
        },
    },
    {
        "name": "Angular",
        "category": "JavaScript Framework",
        "signals": {
            "html_patterns": [r'ng-version="([0-9.]+)"', r'ng-app', r'<app-root>'],
            "script_paths": [r'runtime\.([a-f0-9]+)\.js', r'polyfills\.([a-f0-9]+)\.js', r'main\.([a-f0-9]+)\.js'],
        },
    },
    {
        "name": "Django",
        "category": "Web Framework",
        "signals": {
            "cookies": [r"csrftoken="],
            "headers": {"x-frame-options": r"DENY"},
            "html_patterns": [r'csrfmiddlewaretoken'],
        },
    },
    {
        "name": "Laravel",
        "category": "Web Framework",
        "signals": {
            "cookies": [r"laravel_session=", r"XSRF-TOKEN="],
            "headers": {"set-cookie": r"laravel_session="},
        },
    },
    {
        "name": "Spring Boot",
        "category": "Web Framework",
        "signals": {
            "headers": {"x-application-context": r".+"},
            "html_patterns": [r'Whitelabel Error Page', r'This application has no explicit mapping for /error'],
        },
    },
    {
        "name": "Nginx",
        "category": "Web Server",
        "signals": {
            "headers": {"server": r"nginx(?:/([0-9.]+))?"},
        },
    },
    {
        "name": "Apache Tomcat",
        "category": "Application Server",
        "signals": {
            "headers": {"server": r"Apache-Coyote(?:/([0-9.]+))?"},
        },
    },
    {
        "name": "Apache HTTP Server",
        "category": "Web Server",
        "signals": {
            "headers": {"server": r"Apache(?:-Server)?/([0-9.]+)"},
        },
    },
    {
        "name": "Microsoft IIS",
        "category": "Web Server",
        "signals": {
            "headers": {"server": r"Microsoft-IIS(?:/([0-9.]+))?", "x-powered-by": r"ASP\.NET"},
            "cookies": [r"ASP\.NET_SessionId="],
        },
    },
    {
        "name": "Cloudflare",
        "category": "CDN / Reverse Proxy",
        "signals": {
            "headers": {"server": r"cloudflare", "cf-ray": r".+", "cf-cache-status": r".+"},
        },
    },
]


def analyze_tech_signals(
    url: str,
    status_code: int,
    headers: Dict[str, str],
    body_text: str = "",
    tls_info: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Multi-Signal Technology Detection Engine per Spec Section 10.
    Evaluates HTTP response headers, HTML DOM structures, script paths, cookies,
    and meta tags. Accumulates independent signals to calculate confidence.
    """
    detected: List[Dict[str, Any]] = []
    headers_lower = {k.lower(): str(v) for k, v in headers.items()}
    cookie_str = headers_lower.get("set-cookie", "")

    for rule in TECH_RULES:
        tech_name = rule["name"]
        category = rule["category"]
        signals_matched: List[str] = []
        extracted_version: Optional[str] = None
        rule_signals = rule.get("signals", {})

        # 1. Header checks
        rule_headers = rule_signals.get("headers", {})
        for h_name, h_pattern in rule_headers.items():
            val = headers_lower.get(h_name, "")
            if val:
                match = re.search(h_pattern, val, re.IGNORECASE)
                if match:
                    signals_matched.append(f"header:{h_name}={val}")
                    if match.groups() and match.group(1):
                        extracted_version = match.group(1)

        # 2. Meta Generator
        meta_gen_pat = rule_signals.get("meta_generator")
        if meta_gen_pat and body_text:
            gen_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', body_text, re.IGNORECASE)
            if gen_match:
                gen_content = gen_match.group(1)
                m = re.search(meta_gen_pat, gen_content, re.IGNORECASE)
                if m:
                    signals_matched.append(f"meta:generator={gen_content}")
                    if m.groups() and m.group(1):
                        extracted_version = m.group(1)

        # 3. HTML Patterns
        html_pats = rule_signals.get("html_patterns", [])
        for pat in html_pats:
            if body_text and re.search(pat, body_text, re.IGNORECASE):
                signals_matched.append(f"html_pattern:{pat}")

        # 4. Script Paths
        script_pats = rule_signals.get("script_paths", [])
        for sp in script_pats:
            if body_text and re.search(sp, body_text, re.IGNORECASE):
                signals_matched.append(f"script_path:{sp}")

        # 5. Cookie Patterns
        cookie_pats = rule_signals.get("cookies", [])
        for cp in cookie_pats:
            if cookie_str and re.search(cp, cookie_str, re.IGNORECASE):
                signals_matched.append(f"cookie:{cp}")

        # 6. Confidence Scoring based on multi-signal matching
        # 1 weak signal -> 0.50; 2 signals -> 0.85; 3+ signals -> 0.95+
        match_count = len(signals_matched)
        if match_count > 0:
            if match_count == 1:
                # Strong header with version or meta generator is higher confidence
                if any(s.startswith("header:server") or s.startswith("meta:generator") for s in signals_matched):
                    confidence = 0.80
                else:
                    confidence = 0.55
            elif match_count == 2:
                confidence = 0.88
            else:
                confidence = min(0.99, 0.90 + (match_count - 2) * 0.03)

            evidence_summary = f"Detected {tech_name} via {match_count} independent signal(s): " + ", ".join(signals_matched[:3])
            detected.append({
                "name": tech_name,
                "category": category,
                "version": extracted_version,
                "confidence": round(confidence, 2),
                "signals": signals_matched,
                "evidence": evidence_summary,
                "url": url,
            })

    return detected
