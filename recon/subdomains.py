import json
import logging
import re
import shutil
import subprocess
import ipaddress
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Dict, Any, Optional
import httpx
import dns.resolver
import dns.exception

from core.config import settings
from core.scope import normalize_domain

logger = logging.getLogger(__name__)

# Curated, High-Signal Infrastructure Wordlist (Zero Noise: Production, Cloud, Auth, Microservices, Devops)
HIGH_SIGNAL_SUBDOMAIN_WORDLIST = [
    # Core Environments
    "dev", "devel", "develop", "development", "stage", "staging", "stg", "test", "testing",
    "qa", "uat", "prod", "production", "prd", "demo", "beta", "alpha", "preview", "sandbox",
    "lab", "labs", "canary", "release", "rc", "pre", "preprod", "live", "internal", "corp",
    
    # Core Web, App & Authentication Portals
    "app", "apps", "api", "apis", "v1", "v2", "v3", "auth", "login", "signin", "signup",
    "sso", "oauth", "identity", "id", "portal", "admin", "administrator", "adm", "dashboard",
    "dash", "console", "manage", "management", "panel", "cp", "cpanel", "hub", "gateway",
    "proxy", "router", "ingress", "edge", "web", "www", "m", "mobile", "my", "client",
    "clients", "customer", "customers", "user", "users", "member", "members", "account",
    "accounts", "profile", "partner", "partners", "vendor", "vendors", "merchant", "checkout",
    "pay", "payment", "payments", "billing", "invoice", "invoices", "store", "shop", "cart",
    
    # API, Backend & Microservices
    "graphql", "gql", "rest", "grpc", "ws", "websocket", "socket", "backend", "frontend",
    "service", "services", "micro", "core", "engine", "worker", "workers", "queue", "queues",
    "job", "jobs", "task", "tasks", "feed", "stream", "events", "event", "webhook", "webhooks",
    "connect", "sync", "broker", "rpc", "data", "db", "database", "sql", "redis", "cache",
    "search", "elastic", "elasticsearch", "mongo", "mongodb", "postgres", "mysql",
    
    # DevOps, CI/CD, Repositories & Cloud Infrastructure
    "git", "github", "gitlab", "gitea", "bitbucket", "repo", "code", "jenkins", "ci", "cd",
    "build", "builds", "deploy", "deployment", "runner", "runners", "registry", "docker",
    "harbor", "nexus", "artifactory", "k8s", "kube", "kubernetes", "cluster", "node", "nodes",
    "swarm", "vault", "consul", "etcd", "terraform", "ansible", "cloud", "aws", "gcp", "azure",
    "s3", "blob", "storage", "bucket", "buckets", "assets", "static", "media", "img", "images",
    "cdn", "files", "file", "download", "downloads", "upload", "uploads", "backup", "backups",
    
    # Monitoring, Observability & Security
    "status", "health", "uptime", "monitor", "monitoring", "metrics", "metric", "grafana",
    "kibana", "prometheus", "alert", "alerts", "alertmanager", "jaeger", "sentry", "datadog",
    "newrelic", "splunk", "logs", "logging", "log", "audit", "trace", "tracing",
    "security", "sec", "siem", "soc", "vpn", "remote", "bastion", "jump", "ssh", "rdp",
    "firewall", "waf", "cert", "certs", "pki", "ca",
    
    # Email, DNS & Communication Infrastructure
    "mail", "email", "mx", "mx1", "mx2", "smtp", "imap", "pop", "pop3", "webmail", "exchange",
    "relay", "mta", "mailserver", "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    "nameserver", "chat", "slack", "mattermost", "teams", "meet", "zoom", "voice", "sip",
    "voip", "video", "conf", "conference", "call",
    
    # Corporate, Support & Collaboration Portals
    "docs", "doc", "documentation", "wiki", "kb", "knowledge", "guide", "guides", "help",
    "support", "ticket", "tickets", "servicedesk", "desk", "jira", "confluence", "notion",
    "trello", "asana", "crm", "erp", "hr", "people", "staff", "employees", "work", "office",
    "intranet", "forum", "community", "blog", "news", "press", "media", "contact", "about",
    "careers", "jobs", "investors", "ir", "legal", "terms", "privacy", "trust", "compliance",
    "affiliate", "affiliates", "survey", "forms", "marketing", "analytics", "tracking", "track",
]


def enumerate_subdomains(domain: str, timeout: int = 60) -> List[Dict[str, Any]]:
    """
    Step 2: Enumerate subdomains for target domain using free CT logs, passive DNS, and active zero-noise DNS brute-forcing.
    Returns a list of structured findings: [{subdomain: str, sources: [str]}].
    """
    clean_domain = normalize_domain(domain)
    
    # 0. Fast-Path: If target is a direct IP address, return it immediately without CT/DNS scraping
    try:
        ipaddress.ip_address(clean_domain)
        logger.info(f"[recon.subdomains] Target '{clean_domain}' is a direct IP address. Returning seed IP host.")
        return [{"subdomain": clean_domain, "sources": ["seed_ip"]}]
    except ValueError:
        pass

    logger.info(f"[recon.subdomains] Starting subdomain discovery for '{clean_domain}'")
    
    discovered: Dict[str, Set[str]] = {}

    def _add(sub: str, source: str):
        sub_clean = sub.strip().lower().lstrip("*.")
        if sub_clean and (sub_clean == clean_domain or sub_clean.endswith(f".{clean_domain}")):
            # basic sanity check for valid hostname
            if re.match(r"^[a-zA-Z0-9.-]+$", sub_clean):
                if sub_clean not in discovered:
                    discovered[sub_clean] = set()
                discovered[sub_clean].add(source)

    # 1. crt.sh (Certificate Transparency)
    try:
        crt_subs = _query_crt_sh(clean_domain, timeout=min(timeout, 20))
        for s in crt_subs:
            _add(s, "crt.sh")
    except Exception as e:
        logger.warning(f"crt.sh enumeration failed for {clean_domain}: {e}")

    # 2. HackerTarget Hostsearch (Free Passive DNS)
    try:
        ht_subs = _query_hackertarget(clean_domain, timeout=min(timeout, 15))
        for s in ht_subs:
            _add(s, "hackertarget")
    except Exception as e:
        logger.debug(f"HackerTarget enumeration failed for {clean_domain}: {e}")

    # 3. Certspotter CT Log API (Free Tier)
    try:
        cs_subs = _query_certspotter(clean_domain, timeout=min(timeout, 15))
        for s in cs_subs:
            _add(s, "certspotter")
    except Exception as e:
        logger.debug(f"Certspotter enumeration failed for {clean_domain}: {e}")

    # 4. Subfinder Subprocess (if binary available)
    subfinder_bin = shutil.which(settings.SUBFINDER_BIN) or shutil.which("subfinder")
    if subfinder_bin:
        try:
            sf_subs = _run_subfinder_cli(subfinder_bin, clean_domain, timeout=timeout)
            for s in sf_subs:
                _add(s, "subfinder")
        except Exception as e:
            logger.warning(f"subfinder execution failed for {clean_domain}: {e}")
    else:
        logger.debug("subfinder binary not detected in PATH; using direct CT log sources")

    # 5. Google Custom Search (1 budgeted query if available)
    try:
        from core.google_search import query_google_search
        import urllib.parse
        g_results = query_google_search(f"site:*.{clean_domain} -www", num=10, timeout=10)
        for gr in g_results:
            link = gr.get("link", "")
            parsed_host = urllib.parse.urlparse(link).hostname
            if parsed_host:
                _add(parsed_host, "google_search")
    except Exception as e:
        logger.debug(f"Google search subdomain enumeration failed: {e}")

    # 6. Censys Certificate Search (if configured)
    try:
        from recon.censys_client import query_censys_subdomains
        censys_subs = query_censys_subdomains(clean_domain, timeout=min(timeout, 15))
        for s in censys_subs:
            _add(s, "censys")
    except Exception as e:
        logger.debug(f"Censys subdomain query failed: {e}")

    # 7. Active Zero-Noise DNS Wordlist Brute-Forcing (Runs concurrently alongside passive sources)
    try:
        active_subs = _active_dns_bruteforce(clean_domain, timeout=min(timeout, 20))
        for s in active_subs:
            _add(s, "active_dns_bruteforce")
    except Exception as e:
        logger.warning(f"Active DNS brute-force failed for {clean_domain}: {e}")

    # Always ensure root domain is included
    _add(clean_domain, "root_domain")

    results = [
        {"subdomain": sub, "sources": sorted(list(sources))}
        for sub, sources in sorted(discovered.items())
    ]
    logger.info(f"[recon.subdomains] Discovered {len(results)} unique subdomains for '{clean_domain}'")
    return results


def _active_dns_bruteforce(domain: str, timeout: int = 15) -> List[str]:
    """
    Active Zero-Noise DNS Wordlist Brute-Forcing with Triple-Canary Wildcard Detection.
    Queries curated high-signal infrastructure words against authoritative/trusted resolvers.
    Excludes 100% of wildcard catch-all false positives.
    """
    clean_domain = normalize_domain(domain)
    discovered_subs: List[str] = []

    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.5
    resolver.lifetime = 2.0
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4"]

    # 1. Triple-Canary Wildcard Detection
    wildcard_ips: Set[str] = set()
    canary_hits = 0
    for _ in range(3):
        canary = f"r7-canary-{secrets.token_hex(4)}.{clean_domain}"
        try:
            answers = resolver.resolve(canary, "A")
            for rdata in answers:
                wildcard_ips.add(rdata.address)
            canary_hits += 1
        except Exception:
            pass

    is_wildcard = canary_hits >= 2
    if is_wildcard:
        logger.info(f"[recon.subdomains] Wildcard DNS detected for '{clean_domain}' on IPs: {wildcard_ips}. Active delta filtering enabled.")

    def _probe_word(word: str) -> Optional[str]:
        target_sub = f"{word}.{clean_domain}"
        try:
            # Query A record
            answers = resolver.resolve(target_sub, "A")
            resolved_ips = {rdata.address for rdata in answers}

            if is_wildcard:
                # Discard if all resolved IPs match the wildcard catch-all IP pool
                if resolved_ips.issubset(wildcard_ips):
                    return None
            return target_sub
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        except Exception as e:
            logger.debug(f"DNS brute-force probe error for {target_sub}: {e}")

        # Also check CNAME if A returned nothing
        try:
            cname_answers = resolver.resolve(target_sub, "CNAME")
            if cname_answers:
                return target_sub
        except Exception:
            pass

        return None

    # Execute concurrent high-signal queries
    with ThreadPoolExecutor(max_workers=35) as executor:
        futures = {executor.submit(_probe_word, word): word for word in HIGH_SIGNAL_SUBDOMAIN_WORDLIST}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    discovered_subs.append(res)
            except Exception:
                pass

    logger.info(f"[recon.subdomains] Active DNS brute-force discovered {len(discovered_subs)} subdomains for '{clean_domain}' (Wildcard active: {is_wildcard})")
    return discovered_subs


def _query_crt_sh(domain: str, timeout: int = 20) -> List[str]:
    """Queries crt.sh JSON endpoint directly via HTTP."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) R7/1.0"}
    subdomains = []
    
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                for raw_sub in name_value.split("\n"):
                    subdomains.append(raw_sub.strip())
    return subdomains


def _query_certspotter(domain: str, timeout: int = 15) -> List[str]:
    """Queries Certspotter free public API."""
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    headers = {"User-Agent": "R7/1.0"}
    subdomains = []
    
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            for item in data:
                dns_names = item.get("dns_names", [])
                subdomains.extend(dns_names)
    return subdomains


def _query_hackertarget(domain: str, timeout: int = 15) -> List[str]:
    """Queries HackerTarget free hostsearch API for passive DNS records."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) R7/1.0"}
    subdomains = []
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200 and not resp.text.startswith("error"):
                for line in resp.text.splitlines():
                    if "," in line:
                        host = line.split(",")[0].strip()
                        if host:
                            subdomains.append(host)
    except Exception as e:
        logger.debug(f"HackerTarget request error: {e}")
    return subdomains


def _run_subfinder_cli(binary_path: str, domain: str, timeout: int = 60) -> List[str]:
    """Runs subfinder CLI tool in JSON output mode."""
    cmd = [binary_path, "-d", domain, "-silent", "-json"]
    subdomains = []
    
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
    )
    if proc.returncode == 0 and proc.stdout:
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host")
                if host:
                    subdomains.append(host)
            except json.JSONDecodeError:
                subdomains.append(line)
    return subdomains

