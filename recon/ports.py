import os
import re
import ssl
import json
import logging
import shutil
import socket
import subprocess
import concurrent.futures
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional, Union, Set, Tuple

import httpx

from core.config import settings
from recon.ip_resolve import is_cdn_ip

logger = logging.getLogger(__name__)

# Common fallback ports for TCP probe when masscan/nmap are absent in local dev
COMMON_PROBE_PORTS_FAST = [80, 443, 22, 21, 25, 53, 3000, 3306, 3389, 8000, 8080, 8443]
COMMON_PROBE_PORTS_STANDARD = [
    80, 443, 22, 21, 23, 25, 53, 110, 111, 135, 139, 143, 445, 993, 995,
    1433, 1521, 3000, 3001, 3306, 3389, 4000, 5000, 5173, 5432, 5900, 6379,
    8000, 8080, 8081, 8443, 8888, 9000, 9200, 27017
]
COMMON_PROBE_PORTS_DEEP = COMMON_PROBE_PORTS_STANDARD + [
    69, 88, 123, 161, 162, 389, 465, 500, 514, 587, 873, 1080, 1099, 1434, 2049,
    2181, 2375, 2376, 2379, 3128, 4500, 5060, 5672, 5984, 5985, 5986, 6443,
    7001, 7077, 8008, 8088, 8090, 8161, 8848, 9092, 9443, 10000, 11211, 27018, 50000
]

WINDOWS_NMAP_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    r"C:\ProgramData\chocolatey\bin\nmap.exe",
]


def _find_nmap_binary() -> Optional[Union[str, List[str]]]:
    """Finds Nmap executable across PATH, default Windows install locations, or WSL."""
    bin_path = shutil.which(settings.NMAP_BIN) or shutil.which("nmap")
    if bin_path:
        return bin_path

    for win_path in WINDOWS_NMAP_PATHS:
        if os.path.exists(win_path):
            logger.info(f"Detected Nmap in Windows installation directory: {win_path}")
            return win_path

    try:
        proc = subprocess.run(["wsl", "which", "nmap"], capture_output=True, text=True, timeout=2)
        if proc.returncode == 0 and proc.stdout.strip():
            logger.info("Detected Nmap inside WSL environment.")
            return ["wsl", "nmap"]
    except Exception:
        pass

    return None


def _probe_postgres(ip: str, port: int, timeout: float = 2.0) -> Optional[Dict[str, Any]]:
    """Probes PostgreSQL daemon using SSLRequest and StartupMessage Layer 7 protocol packets."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            
            # 1. Send PostgreSQL SSLRequest packet (8 bytes: length=8, code=80877103)
            s.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
            resp = s.recv(16)
            if resp in (b"S", b"N"):
                ssl_status = "SSL Supported" if resp == b"S" else "SSL Unsupported"
                return {
                    "ip": ip,
                    "port": port,
                    "protocol": "tcp",
                    "service": "postgresql",
                    "product": "PostgreSQL Database",
                    "version": f"PostgreSQL Server ({ssl_status})",
                    "banner": f"PostgreSQL Protocol Handshake (SSLRequest acknowledged: {resp.decode('ascii', errors='ignore')})",
                    "state": "open",
                    "service_verified": True,
                    "detection_method": "l7_protocol_handshake",
                    "cpe": ["cpe:/a:postgresql:postgresql"],
                    "dangerous_methods": [],
                    "anonymous_access": False,
                    "weak_ciphers": [],
                }
            
            # 2. If SSLRequest didn't get S/N, send standard StartupMessage (protocol 3.0)
            startup = b"\x00\x00\x00\x27\x00\x03\x00\x00user\x00recon7\x00database\x00postgres\x00\x00"
            s.sendall(startup)
            resp2 = s.recv(1024)
            if resp2 and (resp2.startswith(b"E") or b"SFATAL" in resp2 or b"PostgreSQL" in resp2 or b"FATAL" in resp2):
                msg_text = resp2.decode("latin1", errors="ignore")
                return {
                    "ip": ip,
                    "port": port,
                    "protocol": "tcp",
                    "service": "postgresql",
                    "product": "PostgreSQL Database",
                    "version": "PostgreSQL Server",
                    "banner": f"PostgreSQL ErrorResponse Protocol Handshake ({msg_text[:60].strip()})",
                    "state": "open",
                    "service_verified": True,
                    "detection_method": "l7_protocol_handshake",
                    "cpe": ["cpe:/a:postgresql:postgresql"],
                    "dangerous_methods": [],
                    "anonymous_access": False,
                    "weak_ciphers": [],
                }
    except Exception:
        pass
    return None


def _probe_telnet(ip: str, port: int, timeout: float = 2.0) -> Optional[Dict[str, Any]]:
    """Probes Telnet daemon using Telnet IAC negotiation sequences."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            
            # Send Telnet IAC DO SUPPRESS_GO_AHEAD, IAC WILL TERMINAL_TYPE
            s.sendall(b"\xff\xfd\x03\xff\xfb\x18\r\n")
            raw_bytes = s.recv(1024)
            if raw_bytes:
                text = raw_bytes.decode("utf-8", errors="ignore").strip()
                has_iac = b"\xff" in raw_bytes[:10]
                has_prompt = any(k in text.lower() for k in ("login:", "password:", "telnet", "welcome", "user:", "username:"))
                if has_iac or has_prompt or "telnet" in text.lower():
                    clean_banner = re.sub(r"[\x00-\x1f\x7f-\xff]", " ", text).strip()
                    return {
                        "ip": ip,
                        "port": port,
                        "protocol": "tcp",
                        "service": "telnet",
                        "product": "Telnet Daemon",
                        "version": "Cleartext Telnet Service",
                        "banner": clean_banner or "Telnet Protocol IAC Handshake Negotiated",
                        "state": "open",
                        "service_verified": True,
                        "detection_method": "l7_protocol_handshake",
                        "cpe": [],
                        "dangerous_methods": [],
                        "anonymous_access": False,
                        "weak_ciphers": [],
                    }
    except Exception:
        pass
    return None


def _probe_redis(ip: str, port: int, timeout: float = 2.0) -> Optional[Dict[str, Any]]:
    """Probes Redis datastore using RESP protocol PING and INFO commands."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            
            s.sendall(b"PING\r\nINFO\r\n")
            raw = s.recv(2048)
            if raw:
                text = raw.decode("utf-8", errors="ignore")
                if text.startswith("+PONG") or "-NOAUTH" in text or "-ERR" in text or "redis_version" in text:
                    ver_m = re.search(r"redis_version:([0-9\.]+)", text)
                    ver = ver_m.group(1) if ver_m else ""
                    anon = text.startswith("+PONG") or ("redis_version" in text and "-NOAUTH" not in text)
                    return {
                        "ip": ip,
                        "port": port,
                        "protocol": "tcp",
                        "service": "redis",
                        "product": "Redis In-Memory Store",
                        "version": ver or "Redis Server",
                        "banner": f"Redis Protocol Handshake (Version: {ver or 'Protected Mode'})",
                        "state": "open",
                        "service_verified": True,
                        "detection_method": "l7_protocol_handshake",
                        "cpe": [f"cpe:/a:redis:redis:{ver}"] if ver else ["cpe:/a:redis:redis"],
                        "dangerous_methods": [],
                        "anonymous_access": anon,
                        "weak_ciphers": [],
                    }
    except Exception:
        pass
    return None


def _probe_mysql(ip: str, port: int, timeout: float = 2.0) -> Optional[Dict[str, Any]]:
    """Probes MySQL/MariaDB database by parsing Initial Handshake Packet."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            raw = s.recv(1024)
            if len(raw) > 5 and raw[4] == 10:  # Protocol 10 Initial Handshake
                ver_bytes = raw[5:].split(b"\x00")[0]
                version_str = ver_bytes.decode("latin1", errors="ignore").strip()
                product = "MariaDB Database" if "mariadb" in version_str.lower() else "MySQL Database"
                return {
                    "ip": ip,
                    "port": port,
                    "protocol": "tcp",
                    "service": "mysql",
                    "product": product,
                    "version": version_str,
                    "banner": f"MySQL Protocol Initial Handshake (Version {version_str})",
                    "state": "open",
                    "service_verified": True,
                    "detection_method": "l7_protocol_handshake",
                    "cpe": [f"cpe:/a:oracle:mysql:{version_str}"],
                    "dangerous_methods": [],
                    "anonymous_access": False,
                    "weak_ciphers": [],
                }
    except Exception:
        pass
    return None


def _probe_rdp(ip: str, port: int, timeout: float = 2.0) -> Optional[Dict[str, Any]]:
    """Probes Microsoft RDP using T.125 / X.224 Connection Request."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            # X.224 Connection Request (TPDU CR)
            x224_cr = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
            s.sendall(x224_cr)
            resp = s.recv(128)
            if len(resp) >= 4 and resp[0] == 3 and resp[1] == 0:  # TPKT header
                return {
                    "ip": ip,
                    "port": port,
                    "protocol": "tcp",
                    "service": "ms-wbt-server",
                    "product": "Microsoft Remote Desktop (RDP)",
                    "version": "RDP Server (X.224 Acknowledged)",
                    "banner": "Microsoft RDP X.224 Protocol Handshake Negotiated",
                    "state": "open",
                    "service_verified": True,
                    "detection_method": "l7_protocol_handshake",
                    "cpe": ["cpe:/a:microsoft:remote_desktop_services"],
                    "dangerous_methods": [],
                    "anonymous_access": False,
                    "weak_ciphers": [],
                }
    except Exception:
        pass
    return None


def probe_port_service_native(ip: str, port: int, timeout: float = 2.5) -> Optional[Dict[str, Any]]:
    """
    Performs high-speed Layer 7 active service probing, protocol handshake verification, and banner extraction.
    Distinguishes verified application-layer daemons from raw TCP port forwarders / honeypots.
    """
    # 1. HTTP / Web Ports
    if port in (80, 8080, 8000, 8888, 9000, 5000, 3000):
        try:
            with httpx.Client(timeout=timeout, verify=False, follow_redirects=False) as client:
                resp = client.get(f"http://{ip}:{port}/")
                server_hdr = resp.headers.get("server", "").strip()
                powered_by = resp.headers.get("x-powered-by", "").strip()
                
                dangerous_methods = []
                try:
                    opt = client.options(f"http://{ip}:{port}/", timeout=1.5)
                    allow = opt.headers.get("allow", "").upper()
                    for verb in ("PUT", "DELETE", "TRACE"):
                        if verb in allow:
                            dangerous_methods.append(verb)
                except Exception:
                    pass

                product = "HTTP Web Server"
                version = ""
                if server_hdr:
                    m = re.search(r"([a-zA-Z0-9\-_]+)(?:/([0-9\.]+))?", server_hdr)
                    if m:
                        product = m.group(1)
                        version = m.group(2) or ""
                    else:
                        product = server_hdr
                
                banner_lines = [f"HTTP/{resp.http_version} {resp.status_code}"]
                if server_hdr:
                    banner_lines.append(f"Server: {server_hdr}")
                if powered_by:
                    banner_lines.append(f"X-Powered-By: {powered_by}")
                if "location" in resp.headers:
                    banner_lines.append(f"Location: {resp.headers['location']}")
                
                return {
                    "ip": ip,
                    "port": port,
                    "protocol": "tcp",
                    "service": "http",
                    "product": product,
                    "version": version or (server_hdr if server_hdr else ""),
                    "banner": "\r\n".join(banner_lines),
                    "state": "open",
                    "service_verified": True,
                    "detection_method": "l7_protocol_handshake",
                    "cpe": [f"cpe:/a:{product.lower()}:{product.lower()}:{version}"] if version else [],
                    "dangerous_methods": dangerous_methods,
                    "anonymous_access": False,
                    "weak_ciphers": [],
                }
        except Exception:
            pass

    # 2. HTTPS / SSL Ports
    if port in (443, 8443, 9443):
        try:
            with httpx.Client(timeout=timeout, verify=False, follow_redirects=False) as client:
                resp = client.get(f"https://{ip}:{port}/")
                server_hdr = resp.headers.get("server", "").strip()
                powered_by = resp.headers.get("x-powered-by", "").strip()

                dangerous_methods = []
                try:
                    opt = client.options(f"https://{ip}:{port}/", timeout=1.5)
                    allow = opt.headers.get("allow", "").upper()
                    for verb in ("PUT", "DELETE", "TRACE"):
                        if verb in allow:
                            dangerous_methods.append(verb)
                except Exception:
                    pass

                product = "HTTPS Web Server"
                version = ""
                if server_hdr:
                    m = re.search(r"([a-zA-Z0-9\-_]+)(?:/([0-9\.]+))?", server_hdr)
                    if m:
                        product = m.group(1)
                        version = m.group(2) or ""
                    else:
                        product = server_hdr

                banner_lines = [f"HTTP/{resp.http_version} {resp.status_code}"]
                if server_hdr:
                    banner_lines.append(f"Server: {server_hdr}")
                if powered_by:
                    banner_lines.append(f"X-Powered-By: {powered_by}")
                if "location" in resp.headers:
                    banner_lines.append(f"Location: {resp.headers['location']}")

                return {
                    "ip": ip,
                    "port": port,
                    "protocol": "tcp",
                    "service": "https",
                    "product": product,
                    "version": version or (server_hdr if server_hdr else ""),
                    "banner": "\r\n".join(banner_lines),
                    "state": "open",
                    "service_verified": True,
                    "detection_method": "l7_protocol_handshake",
                    "cpe": [f"cpe:/a:{product.lower()}:{product.lower()}:{version}"] if version else [],
                    "dangerous_methods": dangerous_methods,
                    "anonymous_access": False,
                    "weak_ciphers": [],
                }
        except Exception:
            pass

    # 3. Dedicated Database & Remote Management Protocol Probes
    if port == 5432:
        pg = _probe_postgres(ip, port, timeout)
        if pg:
            return pg
    elif port == 23:
        tel = _probe_telnet(ip, port, timeout)
        if tel:
            return tel
    elif port == 6379:
        red = _probe_redis(ip, port, timeout)
        if red:
            return red
    elif port == 3306:
        my = _probe_mysql(ip, port, timeout)
        if my:
            return my
    elif port == 3389:
        rdp = _probe_rdp(ip, port, timeout)
        if rdp:
            return rdp

    # 4. Socket-based Banner Grab & Generic Protocol Verification (SSH, FTP, SMTP, POP3, etc.)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            
            if port not in (21, 22, 25, 110, 143, 3306, 5432):
                s.sendall(b"\r\n")

            raw_bytes = s.recv(1024)
            if not raw_bytes or len(raw_bytes.strip()) == 0:
                # Connected at TCP layer, but no Layer 7 application response
                guessed = _guess_service(port)
                return {
                    "ip": ip,
                    "port": port,
                    "protocol": "tcp",
                    "service": guessed,
                    "product": f"Port {port}/TCP (Unverified)",
                    "version": "",
                    "banner": "Direct TCP socket connect (No L7 protocol response)",
                    "state": "open",
                    "service_verified": False,
                    "detection_method": "tcp_syn_ack",
                    "cpe": [],
                    "dangerous_methods": [],
                    "anonymous_access": False,
                    "weak_ciphers": [],
                }

            banner = raw_bytes.decode("utf-8", errors="ignore").strip()
            
            # Match SSH
            if "SSH-" in banner or port == 22:
                m = re.search(r"OpenSSH[_-]?([\d\.]+(?:p\d+)?)", banner, re.I)
                version = m.group(1) if m else ""
                return {
                    "ip": ip,
                    "port": port,
                    "protocol": "tcp",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": version or banner,
                    "banner": banner,
                    "state": "open",
                    "service_verified": True,
                    "detection_method": "l7_protocol_handshake",
                    "cpe": [f"cpe:/a:openbsd:openssh:{version}"] if version else [],
                    "dangerous_methods": [],
                    "anonymous_access": False,
                    "weak_ciphers": [],
                }

            # Match FTP
            if port == 21 or banner.startswith("220"):
                product = "FTP Daemon"
                version = ""
                if "vsftpd" in banner.lower():
                    product = "vsftpd"
                    m = re.search(r"vsftpd\s*([\d\.]+)", banner, re.I)
                    version = m.group(1) if m else ""
                elif "proftpd" in banner.lower():
                    product = "ProFTPD"
                    m = re.search(r"proftpd\s*([\d\.]+)", banner, re.I)
                    version = m.group(1) if m else ""
                
                anon_access = False
                try:
                    s.sendall(b"USER anonymous\r\n")
                    r1 = s.recv(256).decode("utf-8", errors="ignore")
                    s.sendall(b"PASS anonymous@\r\n")
                    r2 = s.recv(256).decode("utf-8", errors="ignore")
                    if "230" in r1 or "230" in r2:
                        anon_access = True
                except Exception:
                    pass

                return {
                    "ip": ip,
                    "port": port,
                    "protocol": "tcp",
                    "service": "ftp",
                    "product": product,
                    "version": version or banner,
                    "banner": banner,
                    "state": "open",
                    "service_verified": True,
                    "detection_method": "l7_protocol_handshake",
                    "cpe": [f"cpe:/a:{product.lower()}:{product.lower()}:{version}"] if version else [],
                    "dangerous_methods": [],
                    "anonymous_access": anon_access,
                    "weak_ciphers": [],
                }

            # Match SMTP
            if port in (25, 465, 587) or "ESMTP" in banner or "220" in banner:
                product = "SMTP Postfix" if "postfix" in banner.lower() else "SMTP Exim" if "exim" in banner.lower() else "SMTP Daemon"
                return {
                    "ip": ip,
                    "port": port,
                    "protocol": "tcp",
                    "service": "smtp",
                    "product": product,
                    "version": banner,
                    "banner": banner,
                    "state": "open",
                    "service_verified": True,
                    "detection_method": "l7_protocol_handshake",
                    "cpe": [],
                    "dangerous_methods": [],
                    "anonymous_access": False,
                    "weak_ciphers": [],
                }

            # Match MySQL
            if port == 3306 or b"\x00" in raw_bytes[:10]:
                version_match = re.search(r"([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9]+)?)", banner)
                ver = version_match.group(1) if version_match else "5.7"
                return {
                    "ip": ip,
                    "port": port,
                    "protocol": "tcp",
                    "service": "mysql",
                    "product": "MySQL Database",
                    "version": ver,
                    "banner": f"MySQL Protocol Handshake (Version {ver})",
                    "state": "open",
                    "service_verified": True,
                    "detection_method": "l7_protocol_handshake",
                    "cpe": [f"cpe:/a:oracle:mysql:{ver}"],
                    "dangerous_methods": [],
                    "anonymous_access": False,
                    "weak_ciphers": [],
                }

            # Match POP3
            if port in (110, 995) or banner.startswith("+OK"):
                return {
                    "ip": ip,
                    "port": port,
                    "protocol": "tcp",
                    "service": "pop3",
                    "product": "POP3 Mail Server",
                    "version": banner[:40],
                    "banner": banner,
                    "state": "open",
                    "service_verified": True,
                    "detection_method": "l7_protocol_handshake",
                    "cpe": [],
                    "dangerous_methods": [],
                    "anonymous_access": False,
                    "weak_ciphers": [],
                }

            # Generic responsive banner
            return {
                "ip": ip,
                "port": port,
                "protocol": "tcp",
                "service": _guess_service(port),
                "product": banner[:40] if len(banner) > 3 else f"Service on port {port}",
                "version": banner[:20] if len(banner) > 3 else "",
                "banner": banner,
                "state": "open",
                "service_verified": True if len(banner.strip()) > 3 else False,
                "detection_method": "banner_grab",
                "cpe": [],
                "dangerous_methods": [],
                "anonymous_access": False,
                "weak_ciphers": [],
            }
    except Exception:
        return None


def scan_ports_and_services(
    ip: str,
    profile: str = "standard",
    allow_cdn: bool = False,
    timeout: int = 300,
) -> List[Dict[str, Any]]:
    """
    Step 4: Multi-stage port sweep, Layer 7 verified active service probing, and Nmap enumeration.
    Automatically identifies and filters out SYN-proxy firewall phantom ports.
    Safeguarded against scanning CDN Anycast edge proxy nodes (Cloudflare, Fastly, Akamai).
    """
    profile = (profile or "standard").lower()

    # 0. CDN Anycast Guard
    if not allow_cdn:
        is_cdn, provider = is_cdn_ip(ip)
        if is_cdn:
            logger.info(
                f"[recon.ports] Target IP '{ip}' belongs to {provider.upper() if provider else 'CDN'} Anycast edge proxy. "
                "Skipping active port & service sweep on edge node to avoid SYN-proxy false positives."
            )
            return []

    logger.info(f"[recon.ports] Starting [{profile.upper()}] port & service scan for target IP '{ip}'")
    
    masscan_bin = shutil.which(settings.MASSCAN_BIN) or shutil.which("masscan")
    nmap_bin = _find_nmap_binary()

    # Stage 1: Fast Port Sweep
    open_ports: List[int] = []
    if masscan_bin and profile in ("standard", "deep"):
        try:
            masscan_results = run_masscan(ip, masscan_bin=masscan_bin, profile=profile, timeout=settings.MASSCAN_TIMEOUT_SECONDS)
            open_ports = [entry["port"] for entry in masscan_results if entry.get("state") == "open"]
        except Exception as e:
            logger.warning(f"Masscan execution failed for {ip}: {e}")
    
    if not open_ports:
        if profile == "fast":
            probe_list = COMMON_PROBE_PORTS_FAST
        elif profile == "deep":
            probe_list = COMMON_PROBE_PORTS_DEEP
        else:
            probe_list = COMMON_PROBE_PORTS_STANDARD
            
        open_ports = run_fallback_tcp_sweep(ip, ports=probe_list, timeout=1.0)

    if not open_ports:
        logger.info(f"[recon.ports] No open ports discovered on {ip}")
        return []

    logger.info(f"[recon.ports] Candidate open ports on {ip}: {open_ports}")

    # Stage 2: Layer 7 Verified Active Service Probing
    # Probe all candidate ports concurrently to extract real banners and filter SYN proxies
    l7_findings = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, len(open_ports))) as executor:
        futures = {executor.submit(probe_port_service_native, ip, p): p for p in open_ports}
        for fut in concurrent.futures.as_completed(futures):
            try:
                res = fut.result()
                if res:
                    l7_findings.append(res)
            except Exception:
                pass

    l7_findings.sort(key=lambda x: x["port"])

    # SYN-Proxy Defense: if many ports responded to TCP connect but few answered L7,
    # keep only the verified listening services
    verified_l7_findings = [x for x in l7_findings if x.get("service_verified") is True]
    if len(open_ports) > 8 and len(verified_l7_findings) < len(open_ports) / 2:
        logger.info(
            f"[recon.ports] Detected SYN-proxy / phantom socket firewall on {ip}. "
            f"Filtered out {len(open_ports) - len(verified_l7_findings)} ghost ports and kept {len(verified_l7_findings)} verified active services."
        )
        active_ports = [x["port"] for x in verified_l7_findings]
        l7_findings = verified_l7_findings
    else:
        active_ports = open_ports

    # Stage 3: Deep Nmap Probe on verified ports (using unprivileged -sT mode to avoid Windows dnet crashes)
    if nmap_bin and active_ports:
        try:
            nmap_results = run_nmap_deep_scan(
                ip,
                ports=active_ports[:25],
                profile=profile,
                nmap_bin=nmap_bin,
                timeout=min(timeout or settings.NMAP_TIMEOUT_SECONDS, 60),
            )
            if nmap_results:
                merged = {nr["port"]: nr for nr in nmap_results}
                for l7 in l7_findings:
                    p_num = l7["port"]
                    if p_num not in merged:
                        merged[p_num] = l7
                    else:
                        if l7.get("version") and not merged[p_num].get("version"):
                            merged[p_num]["version"] = l7["version"]
                            merged[p_num]["product"] = l7["product"]
                        if l7.get("banner") and not merged[p_num].get("banner"):
                            merged[p_num]["banner"] = l7["banner"]
                
                final_results = sorted(list(merged.values()), key=lambda x: x["port"])
                for r in final_results:
                    r["ip"] = ip
                return final_results
        except Exception as e:
            logger.warning(f"nmap deep scan failed for {ip}: {e}")

    # If Nmap was absent or failed, return rich L7 findings with verified versions!
    if l7_findings:
        for r in l7_findings:
            r["ip"] = ip
        return l7_findings

    # Failsafe fallback
    results = []
    for port in active_ports:
        service_guess = _guess_service(port)
        results.append({
            "ip": ip,
            "port": port,
            "protocol": "tcp",
            "service": service_guess,
            "product": f"{service_guess.upper()} Service",
            "version": "",
            "state": "open",
            "cpe": [],
            "os_match": None,
            "scripts": {},
            "dangerous_methods": [],
            "anonymous_access": False,
            "weak_ciphers": [],
        })
    return results


def run_masscan(ip_or_range: str, masscan_bin: str = "masscan", profile: str = "standard", timeout: int = 120) -> List[Dict[str, Any]]:
    """Runs masscan subprocess sweep and parses JSON output."""
    port_arg = "-p1-65535" if profile == "deep" else "--top-ports=1000" if profile == "standard" else "--top-ports=100"
    rate_arg = "--rate=2000" if profile == "deep" else "--rate=1000"
    
    cmd = [
        masscan_bin,
        ip_or_range,
        port_arg,
        rate_arg,
        "-oJ",
        "-",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
    results = []
    if proc.stdout:
        try:
            clean_out = proc.stdout.strip().rstrip(",")
            if not clean_out.startswith("["):
                clean_out = f"[{clean_out}]"
            data = json.loads(clean_out)
            for item in data:
                ip = item.get("ip")
                for port_obj in item.get("ports", []):
                    results.append({
                        "ip": ip,
                        "port": port_obj.get("port"),
                        "protocol": port_obj.get("proto", "tcp"),
                        "state": port_obj.get("status", "open"),
                    })
        except Exception as e:
            logger.warning(f"Failed to parse masscan JSON: {e}")
    return results


def run_nmap_deep_scan(
    ip: str,
    ports: List[int],
    profile: str = "standard",
    nmap_bin: Union[str, List[str]] = "nmap",
    timeout: int = 300,
) -> List[Dict[str, Any]]:
    """
    Runs Nmap deep service version scan with profile-specific flags.
    - Fast: -sV --version-light
    - Standard: -sV --version-intensity 5 -sC -O --osscan-guess
    - Deep: -A -sV --version-all --version-intensity 9 -O --osscan-guess --script="default,http-title,http-headers,http-methods,ssl-enum-ciphers,ftp-anon,smb-os-discovery,mysql-info,ms-sql-info,ssh-auth-methods"
    """
    port_str = ",".join(str(p) for p in ports)
    base_cmd = [nmap_bin] if isinstance(nmap_bin, str) else list(nmap_bin)

    if profile == "deep":
        # Full Red Team Assault Scan (using -sT unprivileged TCP connect for Windows & firewall resilience)
        cmd = base_cmd + [
            "-sT",
            "-sV",
            "--version-intensity", "7",
            "-Pn",
            "-T4",
            "-p", port_str,
            "-oX", "-",
            ip,
        ]
    elif profile == "fast":
        # Fast Stealth Scan
        cmd = base_cmd + [
            "-sT",
            "-sV",
            "--version-light",
            "-Pn",
            "-T4",
            "-p", port_str,
            "-oX", "-",
            ip,
        ]
    else:
        # Standard Balanced Scan
        cmd = base_cmd + [
            "-sT",
            "-sV",
            "--version-intensity", "5",
            "-Pn",
            "-T4",
            "-p", port_str,
            "-oX", "-",
            ip,
        ]

    logger.debug(f"Executing Nmap command: {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
    if proc.returncode != 0 and not proc.stdout:
        logger.warning(f"nmap returned error code {proc.returncode}: {proc.stderr}")
        return []

    return parse_nmap_xml(proc.stdout)


def parse_nmap_xml(xml_content: str) -> List[Dict[str, Any]]:
    """
    Parses Nmap XML string into standard rich structured findings:
    - Service name, exact product and version string
    - CPEs (Common Platform Enumeration)
    - OS Guess & Confidence percentage
    - NSE Script Outputs (Dangerous HTTP methods TRACE/PUT, Anonymous FTP, Weak Ciphers)
    """
    results = []
    if not xml_content or not xml_content.strip():
        return results

    try:
        root = ET.fromstring(xml_content)
        for host in root.findall("host"):
            # 1. Parse OS Match Telemetry
            os_match_info = None
            os_elem = host.find("os")
            if os_elem is not None:
                osmatch = os_elem.find("osmatch")
                if osmatch is not None:
                    os_match_info = {
                        "name": osmatch.get("name", "Unknown OS"),
                        "accuracy": int(osmatch.get("accuracy", 0)),
                        "osfamily": "Unknown",
                    }
                    osclass = osmatch.find("osclass")
                    if osclass is not None:
                        os_match_info["osfamily"] = osclass.get("osfamily", "Unknown")
                        os_match_info["osgen"] = osclass.get("osgen", "")

            # 2. Parse Open Ports and Services
            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port in ports_elem.findall("port"):
                port_id = int(port.get("portid", 0))
                protocol = port.get("protocol", "tcp")
                
                state_elem = port.find("state")
                state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
                
                service_elem = port.find("service")
                service_name = "unknown"
                product = ""
                version = ""
                cpe_list = []
                
                if service_elem is not None:
                    service_name = service_elem.get("name", "unknown")
                    product = service_elem.get("product", "")
                    version = service_elem.get("version", "")
                    extrainfo = service_elem.get("extrainfo", "")
                    if extrainfo:
                        version = f"{version} ({extrainfo})".strip() if version else extrainfo

                    for cpe in service_elem.findall("cpe"):
                        if cpe.text:
                            cpe_list.append(cpe.text.strip())

                # 3. Parse NSE Script Results
                scripts_dict: Dict[str, Any] = {}
                dangerous_methods: List[str] = []
                anonymous_access = False
                weak_ciphers: List[str] = []

                for script in port.findall("script"):
                    s_id = script.get("id", "")
                    s_output = script.get("output", "").strip()
                    scripts_dict[s_id] = s_output

                    # Dangerous HTTP Methods Check
                    if s_id == "http-methods":
                        if "TRACE" in s_output:
                            dangerous_methods.append("TRACE")
                        if "PUT" in s_output:
                            dangerous_methods.append("PUT")
                        if "DELETE" in s_output:
                            dangerous_methods.append("DELETE")

                    # Anonymous FTP Check
                    if s_id == "ftp-anon":
                        if "Anonymous FTP login allowed" in s_output or "230" in s_output:
                            anonymous_access = True

                    # Weak Cipher Check
                    if s_id == "ssl-enum-ciphers":
                        if "TLSv1.0" in s_output or "SSLv3" in s_output or "RC4" in s_output or "3DES" in s_output:
                            weak_ciphers.append("Legacy/Weak TLS or Cipher Detected (SSLv3/TLS1.0/RC4/3DES)")

                if state in ("open", "open|filtered"):
                    results.append({
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        "product": product or _guess_service(port_id).upper(),
                        "version": version,
                        "state": state,
                        "cpe": cpe_list,
                        "os_match": os_match_info,
                        "scripts": scripts_dict,
                        "dangerous_methods": dangerous_methods,
                        "anonymous_access": anonymous_access,
                        "weak_ciphers": weak_ciphers,
                    })
    except Exception as e:
        logger.warning(f"Error parsing nmap XML output: {e}")

    return results


def run_fallback_tcp_sweep(ip: str, ports: List[int], timeout: float = 1.0) -> List[int]:
    """Fast concurrent non-privileged TCP connect probe for local testing."""
    open_ports = []

    def _probe(port: int) -> Optional[int]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return port
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, len(ports))) as executor:
        results = executor.map(_probe, ports)
        for r in results:
            if r is not None:
                open_ports.append(r)

    open_ports.sort()
    return open_ports


def _guess_service(port: int) -> str:
    """Fallback common port -> service mapping."""
    service_map = {
        80: "http",
        443: "https",
        22: "ssh",
        21: "ftp",
        23: "telnet",
        25: "smtp",
        53: "domain",
        110: "pop3",
        143: "imap",
        445: "microsoft-ds",
        3306: "mysql",
        3389: "ms-wbt-server",
        5432: "postgresql",
        6379: "redis",
        8080: "http-proxy",
        8443: "https-alt",
        8000: "http-alt",
        9000: "http-alt",
        9200: "elasticsearch",
        27017: "mongodb",
    }
    return service_map.get(port, f"port-{port}")


HIGH_RISK_SUBDOMAIN_KEYWORDS = {
    "vpn", "auth", "sso", "login", "admin", "api", "gateway", "portal",
    "mail", "remote", "ssh", "cpanel", "whm", "corp", "internal", "db",
    "database", "gitlab", "jenkins", "jira", "bastion", "access", "owa",
}

PRODUCTION_WEB_KEYWORDS = {
    "www", "app", "shop", "store", "pay", "secure", "web", "cloud",
}

DEV_STAGING_KEYWORDS = {
    "dev", "stage", "staging", "test", "qa", "beta", "sandbox",
}


def prioritize_target_ips(
    target_ips: Union[Set[str], List[str]],
    ip_resolutions: List[Dict[str, Any]],
    origin_candidates: Optional[List[Dict[str, Any]]] = None,
) -> List[str]:
    """
    Asset-Weighted IP Prioritizer.
    Ranks non-CDN IPs so high-value attack surface (VPNs, Auth gateways, APIs,
    Admin panels, unmasked SPF/MX origins) is scanned before generic/dev nodes.
    """
    origin_ips: Set[str] = set()
    if origin_candidates:
        for cand in origin_candidates:
            cip = cand.get("ip", "").split("/")[0].strip()
            if cip:
                origin_ips.add(cip)

    # Map each IP to its subdomains
    ip_to_hostnames: Dict[str, List[str]] = {ip: [] for ip in target_ips}
    for res in ip_resolutions:
        sub = (res.get("subdomain") or "").lower()
        for ip in res.get("ips", []):
            if ip in ip_to_hostnames and sub:
                ip_to_hostnames[ip].append(sub)

    scored_ips: List[Tuple[str, int]] = []
    for ip in target_ips:
        score = 10  # base score
        if ip in origin_ips:
            score += 100  # unmasked origin server

        hostnames = ip_to_hostnames.get(ip, [])
        for h in hostnames:
            sub_labels = h.split(".")
            first_label = sub_labels[0] if sub_labels else ""
            
            # Check high risk keywords
            if any(k in first_label for k in HIGH_RISK_SUBDOMAIN_KEYWORDS):
                score += 90
            elif any(k in first_label for k in PRODUCTION_WEB_KEYWORDS):
                score += 50
            elif any(k in first_label for k in DEV_STAGING_KEYWORDS):
                score += 30
            else:
                score += 15

        scored_ips.append((ip, score))

    # Sort descending by score
    scored_ips.sort(key=lambda x: x[1], reverse=True)
    return [ip for ip, _ in scored_ips]


def scan_multiple_hosts_concurrently(
    ips: List[str],
    profile: str = "standard",
    max_workers: int = 6,
    timeout: int = 300,
) -> List[Dict[str, Any]]:
    """
    Enterprise-Grade Concurrent Multi-Host Port Scanner.
    Probes up to `max_workers` hosts in parallel across threads.
    """
    if not ips:
        return []

    logger.info(f"[recon.ports] Launching concurrent port scan across {len(ips)} hosts with {max_workers} parallel workers")
    all_findings: List[Dict[str, Any]] = []

    def _scan_worker(target_ip: str) -> List[Dict[str, Any]]:
        try:
            findings = scan_ports_and_services(target_ip, profile=profile, timeout=timeout)
            for f in findings:
                f["ip"] = target_ip
            return findings
        except Exception as e:
            logger.warning(f"[recon.ports] Port scan failed on host {target_ip}: {e}")
            return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(ips))) as executor:
        future_to_ip = {executor.submit(_scan_worker, ip): ip for ip in ips}
        for fut in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[fut]
            try:
                host_findings = fut.result()
                if host_findings:
                    logger.info(f"[recon.ports] Host {ip} finished: {len(host_findings)} open ports identified")
                    all_findings.extend(host_findings)
                else:
                    logger.info(f"[recon.ports] Host {ip} finished: 0 open ports")
            except Exception as e:
                logger.warning(f"[recon.ports] Error gathering results for host {ip}: {e}")

    # Sort all findings by IP and Port
    all_findings.sort(key=lambda x: (x.get("ip", ""), x.get("port", 0)))
    return all_findings

