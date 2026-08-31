import re
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Tuple


@dataclass
class TechnologyIdentity:
    """
    Canonical technology identity normalized to NIST CPE 2.3 specification.
    """
    vendor: str
    product: str
    version: str
    cpe_23: str
    category: str = "application"  # application (a) | operating_system (o) | hardware (h)
    display_name: str = ""
    raw_input: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "cpe_23": self.cpe_23,
            "category": self.category,
            "display_name": self.display_name or f"{self.vendor.title()} {self.product.title()}",
            "raw_input": self.raw_input,
            "metadata": self.metadata,
        }


# Canonical Vendor & Product Aliases Dictionary
# Maps common names, banner strings, and header patterns to (vendor, product, category, display_name)
CANONICAL_TECH_MAP: Dict[str, Tuple[str, str, str, str]] = {
    # Web Servers & Proxies
    "apache": ("apache", "http_server", "a", "Apache HTTP Server"),
    "apache2": ("apache", "http_server", "a", "Apache HTTP Server"),
    "apache http server": ("apache", "http_server", "a", "Apache HTTP Server"),
    "httpd": ("apache", "http_server", "a", "Apache HTTP Server"),
    "nginx": ("nginx", "nginx", "a", "Nginx Web Server"),
    "nginx web server": ("nginx", "nginx", "a", "Nginx Web Server"),
    "openresty": ("openresty", "openresty", "a", "OpenResty Nginx"),
    "iis": ("microsoft", "iis", "a", "Microsoft IIS"),
    "microsoft-iis": ("microsoft", "iis", "a", "Microsoft IIS"),
    "caddy": ("caddyserver", "caddy", "a", "Caddy Web Server"),
    "lighttpd": ("lighttpd", "lighttpd", "a", "Lighttpd"),
    "traefik": ("traefik", "traefik", "a", "Traefik Reverse Proxy"),
    "envoy": ("envoyproxy", "envoy", "a", "Envoy Proxy"),
    "haproxy": ("haproxy", "haproxy", "a", "HAProxy"),

    # Application Servers & Frameworks
    "apache-coyote": ("apache", "tomcat", "a", "Apache Tomcat"),
    "apache coyote": ("apache", "tomcat", "a", "Apache Tomcat"),
    "coyote": ("apache", "tomcat", "a", "Apache Tomcat"),
    "tomcat": ("apache", "tomcat", "a", "Apache Tomcat"),
    "apache tomcat": ("apache", "tomcat", "a", "Apache Tomcat"),
    "jboss": ("redhat", "jboss_enterprise_application_platform", "a", "Red Hat JBoss"),
    "wildfly": ("redhat", "wildfly", "a", "WildFly Application Server"),
    "weblogic": ("oracle", "weblogic_server", "a", "Oracle WebLogic"),
    "websphere": ("ibm", "websphere_application_server", "a", "IBM WebSphere"),
    "node.js": ("nodejs", "node.js", "a", "Node.js Runtime"),
    "nodejs": ("nodejs", "node.js", "a", "Node.js Runtime"),
    "express": ("expressjs", "express", "a", "Express.js"),
    "django": ("djangoproject", "django", "a", "Django Framework"),
    "flask": ("palletsprojects", "flask", "a", "Flask Framework"),
    "fastapi": ("tiangolo", "fastapi", "a", "FastAPI Framework"),
    "spring": ("pivotal_software", "spring_framework", "a", "Spring Framework"),
    "spring boot": ("pivotal_software", "spring_boot", "a", "Spring Boot"),
    "laravel": ("laravel", "laravel", "a", "Laravel Framework"),
    "ruby on rails": ("rubyonrails", "rails", "a", "Ruby on Rails"),
    "rails": ("rubyonrails", "rails", "a", "Ruby on Rails"),
    "php": ("php", "php", "a", "PHP Hypertext Preprocessor"),

    # Databases & Caches
    "mysql": ("oracle", "mysql", "a", "MySQL Database"),
    "mysql database": ("oracle", "mysql", "a", "MySQL Database"),
    "mariadb": ("mariadb", "mariadb", "a", "MariaDB Database"),
    "mariadb database": ("mariadb", "mariadb", "a", "MariaDB Database"),
    "postgresql": ("postgresql", "postgresql", "a", "PostgreSQL Database"),
    "postgres": ("postgresql", "postgresql", "a", "PostgreSQL Database"),
    "redis": ("redis", "redis", "a", "Redis In-Memory Store"),
    "mongodb": ("mongodb", "mongodb", "a", "MongoDB Document Database"),
    "elasticsearch": ("elastic", "elasticsearch", "a", "Elasticsearch"),
    "kibana": ("elastic", "kibana", "a", "Kibana"),
    "memcached": ("memcached", "memcached", "a", "Memcached"),
    "rabbitmq": ("pivotal_software", "rabbitmq", "a", "RabbitMQ Message Broker"),
    "kafka": ("apache", "kafka", "a", "Apache Kafka"),

    # Remote Management & Services
    "openssh": ("openbsd", "openssh", "a", "OpenSSH Daemon"),
    "ssh": ("openbsd", "openssh", "a", "OpenSSH Daemon"),
    "dropbear": ("dropbear_ssh_project", "dropbear_ssh", "a", "Dropbear SSH"),
    "vsftpd": ("vsftpd_project", "vsftpd", "a", "vsftpd"),
    "proftpd": ("proftpd_project", "proftpd", "a", "ProFTPD"),
    "postfix": ("postfix", "postfix", "a", "Postfix Mail Transfer Agent"),
    "exim": ("exim", "exim", "a", "Exim Mail Server"),
    "sendmail": ("sendmail", "sendmail", "a", "Sendmail"),
    "dovecot": ("dovecot", "dovecot", "a", "Dovecot IMAP/POP3"),
    "telnet": ("telnet_project", "telnet", "a", "Telnet Daemon"),
    "ms-wbt-server": ("microsoft", "remote_desktop_services", "a", "Microsoft RDP"),
    "rdp": ("microsoft", "remote_desktop_services", "a", "Microsoft RDP"),

    # CMS & Web Applications
    "wordpress": ("wordpress", "wordpress", "a", "WordPress CMS"),
    "drupal": ("drupal", "drupal", "a", "Drupal CMS"),
    "joomla": ("joomla", "joomla\\!", "a", "Joomla! CMS"),
    "magento": ("magento", "magento", "a", "Magento E-Commerce"),
    "grafana": ("grafana", "grafana", "a", "Grafana Dashboard"),
    "jenkins": ("jenkins", "jenkins", "a", "Jenkins Automation Server"),
    "gitlab": ("gitlab", "gitlab", "a", "GitLab"),
    "confluence": ("atlassian", "confluence", "a", "Atlassian Confluence"),
    "jira": ("atlassian", "jira", "a", "Atlassian Jira"),

    # Operating Systems
    "ubuntu": ("canonical", "ubuntu_linux", "o", "Ubuntu Linux"),
    "debian": ("debian", "debian_linux", "o", "Debian GNU/Linux"),
    "redhat": ("redhat", "enterprise_linux", "o", "Red Hat Enterprise Linux"),
    "rhel": ("redhat", "enterprise_linux", "o", "Red Hat Enterprise Linux"),
    "centos": ("centos", "centos", "o", "CentOS Linux"),
    "rocky": ("rocky", "rocky_linux", "o", "Rocky Linux"),
    "almalinux": ("almalinux", "almalinux", "o", "AlmaLinux"),
    "windows": ("microsoft", "windows", "o", "Microsoft Windows"),
    "windows_server": ("microsoft", "windows_server", "o", "Microsoft Windows Server"),
}


def sanitize_version(version_str: str) -> str:
    """
    Extracts and sanitizes clean semver / dot-separated version strings from raw banners.
    Strips trailing OS packaging, suffixes, and noise.
    """
    if not version_str:
        return ""

    clean = str(version_str).strip()
    
    # Strip common leading prefix chars
    clean = re.sub(r'^[vV/_\-\s]+', '', clean)

    # Match semver or major.minor[.patch[.build]]
    # e.g., '2.4.49 (Ubuntu)', '9.6p1-1ubuntu1', '1.24.0-release'
    m = re.search(r'([0-9]+(?:\.[0-9]+)+(?:[a-zA-Z0-9_\-\.]*)?)', clean)
    if m:
        ver = m.group(1).rstrip('.,;:-')
        # Clean off common release suffixes (-release, -RELEASE, -GA, -final, etc.)
        ver = re.sub(r'-(?:release|RELEASE|GA|final|FINAL|stable|STABLE).*$', '', ver)
        # Clean off common trailing distro junk while preserving 'p1' for OpenSSH
        ver = re.sub(r'-(?:[0-9]+)?[a-zA-Z]*(?:ubuntu|debian|deb|el|amzn|dfsg|arch|fc).*$', '', ver, flags=re.I)
        return ver

    # Fallback to single digit or short token
    m_single = re.search(r'\b([0-9]+(?:\.[0-9]+)*)\b', clean)
    if m_single:
        return m_single.group(1)

    return clean.split()[0] if clean else ""


def build_cpe_23(category: str, vendor: str, product: str, version: str) -> str:
    """
    Constructs an official NIST CPE 2.3 formatted identifier string:
    cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>
    """
    part = "a"
    if category in ("o", "operating_system", "os"):
        part = "o"
    elif category in ("h", "hardware", "hw"):
        part = "h"

    v_clean = re.sub(r'[^a-zA-Z0-9_\-]', '_', vendor.lower().strip()) or "*"
    p_clean = re.sub(r'[^a-zA-Z0-9_\-]', '_', product.lower().strip()) or "*"
    ver_clean = re.sub(r'[^a-zA-Z0-9_\.\-]', '_', version.strip()) if version else "*"

    return f"cpe:2.3:{part}:{v_clean}:{p_clean}:{ver_clean}:*:*:*:*:*:*:*"


def normalize_technology(
    raw_name: str,
    raw_version: Optional[str] = None,
    banner: str = "",
    service_hint: str = "",
) -> TechnologyIdentity:
    """
    Normalizes arbitrary scanner / port / HTTP observations into a canonical TechnologyIdentity
    complete with standardized NIST CPE 2.3 identifier.
    """
    input_str = (raw_name or service_hint or banner or "").strip()
    norm_key = re.sub(r'[^a-zA-Z0-9_\-\.\s]', ' ', input_str.lower()).strip()
    
    # 1. Direct key match or alias resolution
    resolved = None
    if norm_key in CANONICAL_TECH_MAP:
        resolved = CANONICAL_TECH_MAP[norm_key]
    else:
        # Check token boundaries
        for key, val in CANONICAL_TECH_MAP.items():
            if re.search(rf'\b{re.escape(key)}\b', norm_key):
                resolved = val
                break

    # 2. If not found, inspect banner
    if not resolved and banner:
        b_clean = banner.lower()
        for key, val in CANONICAL_TECH_MAP.items():
            if re.search(rf'\b{re.escape(key)}\b', b_clean):
                resolved = val
                break

    # 3. If still not found, check service_hint
    if not resolved and service_hint:
        s_clean = service_hint.lower()
        if s_clean in CANONICAL_TECH_MAP:
            resolved = CANONICAL_TECH_MAP[s_clean]

    # 4. Resolve Vendor, Product, Category, Display Name
    if resolved:
        vendor, product, category, display_name = resolved
    else:
        # Fallback to sanitized raw tokens
        clean_tokens = [t for t in re.split(r'[\s/_\-]+', input_str) if t]
        if clean_tokens:
            vendor = clean_tokens[0].lower()
            product = clean_tokens[1].lower() if len(clean_tokens) > 1 else clean_tokens[0].lower()
            display_name = input_str.title()
        else:
            vendor = "generic"
            product = "service"
            display_name = "Generic Network Service"
        category = "a"

    # 5. Extract and normalize version
    extracted_version = ""
    if raw_version:
        extracted_version = sanitize_version(raw_version)
    elif banner:
        extracted_version = sanitize_version(banner)
    elif raw_name:
        extracted_version = sanitize_version(raw_name)

    cpe_str = build_cpe_23(category, vendor, product, extracted_version)

    return TechnologyIdentity(
        vendor=vendor,
        product=product,
        version=extracted_version,
        cpe_23=cpe_str,
        category=category,
        display_name=display_name,
        raw_input=f"{raw_name} {raw_version or ''}".strip(),
        metadata={
            "sanitized": bool(extracted_version),
            "service_hint": service_hint,
        },
    )
