import pytest
from unittest.mock import patch, MagicMock
from recon.ports import parse_nmap_xml, scan_ports_and_services
from vuln.cve_lookup import correlate_port_findings_to_vulns

SAMPLE_DEEP_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <os>
      <osmatch name="Linux 5.4 - 5.15" accuracy="96">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="96"/>
      </osmatch>
    </os>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open"/>
        <service name="ftp" product="vsftpd" version="3.0.3" method="probed" conf="10">
          <cpe>cpe:/a:vsftpd:vsftpd:3.0.3</cpe>
        </service>
        <script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.41" extrainfo="Ubuntu" method="probed" conf="10">
          <cpe>cpe:/a:apache:http_server:2.4.41</cpe>
        </service>
        <script id="http-methods" output="Supported Methods: GET HEAD POST OPTIONS TRACE"/>
        <script id="http-title" output="ACME Portal - Internal Login"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0" method="probed" conf="10">
          <cpe>cpe:/a:igor_sysoev:nginx:1.18.0</cpe>
        </service>
        <script id="ssl-enum-ciphers" output="TLSv1.0: ciphers: TLS_RSA_WITH_3DES_EDE_CBC_SHA"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

def test_parse_nmap_xml_deep_telemetry():
    results = parse_nmap_xml(SAMPLE_DEEP_NMAP_XML)
    assert len(results) == 3

    # Port 21 FTP
    ftp = next(r for r in results if r["port"] == 21)
    assert ftp["service"] == "ftp"
    assert ftp["product"] == "vsftpd"
    assert ftp["version"] == "3.0.3"
    assert ftp["anonymous_access"] is True
    assert "cpe:/a:vsftpd:vsftpd:3.0.3" in ftp["cpe"]
    assert ftp["os_match"]["name"] == "Linux 5.4 - 5.15"
    assert ftp["os_match"]["accuracy"] == 96

    # Port 80 Apache
    http = next(r for r in results if r["port"] == 80)
    assert http["service"] == "http"
    assert http["product"] == "Apache httpd"
    assert "2.4.41" in http["version"]
    assert "TRACE" in http["dangerous_methods"]

    # Port 443 Nginx Weak Ciphers
    https = next(r for r in results if r["port"] == 443)
    assert len(https["weak_ciphers"]) > 0


def test_correlate_port_findings_to_vulns():
    ports = parse_nmap_xml(SAMPLE_DEEP_NMAP_XML)
    for p in ports:
        p["ip"] = "192.168.1.50"

    vulns = correlate_port_findings_to_vulns(ports)
    assert len(vulns) >= 3

    anon_ftp = next((v for v in vulns if v["template_id"] == "ftp-anonymous-access"), None)
    assert anon_ftp is not None
    assert anon_ftp["severity"] == "high"

    trace_method = next((v for v in vulns if v["template_id"] == "http-dangerous-methods-detected"), None)
    assert trace_method is not None
    assert trace_method["severity"] == "medium"
    assert "TRACE" in trace_method["name"]


def test_cdn_ip_detection_and_scan_ports_guard():
    from recon.ip_resolve import is_cdn_ip

    # 1. Cloudflare Anycast IP detection
    is_cf, provider = is_cdn_ip("104.21.55.10")
    assert is_cf is True
    assert provider == "cloudflare"

    is_cf2, provider2 = is_cdn_ip("172.67.182.11")
    assert is_cf2 is True
    assert provider2 == "cloudflare"

    # Fastly IP
    is_fastly, provider_f = is_cdn_ip("151.101.1.69")
    assert is_fastly is True
    assert provider_f == "fastly"

    # Non-CDN IP
    is_non_cdn, _ = is_cdn_ip("192.168.1.100")
    assert is_non_cdn is False

    # 2. scan_ports_and_services guard against Cloudflare Anycast nodes
    with patch("recon.ports.run_nmap_deep_scan") as mock_nmap, \
         patch("recon.ports.run_masscan") as mock_masscan, \
         patch("recon.ports.run_fallback_tcp_sweep") as mock_tcp:
        
        # When called on Cloudflare IP with allow_cdn=False (default), it must return [] immediately
        findings = scan_ports_and_services("104.21.55.10")
        assert findings == []
        mock_nmap.assert_not_called()
        mock_masscan.assert_not_called()
        mock_tcp.assert_not_called()


def test_asset_weighted_ip_prioritizer():
    from recon.ports import prioritize_target_ips

    target_ips = {"192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.40"}
    ip_resolutions = [
        {"subdomain": "vpn.target.com", "ips": ["192.168.1.20"]},
        {"subdomain": "api.target.com", "ips": ["192.168.1.20"]},
        {"subdomain": "dev.target.com", "ips": ["192.168.1.30"]},
        {"subdomain": "assets.target.com", "ips": ["192.168.1.40"]},
    ]
    # 192.168.1.10 is an unmasked origin server from SPF/MX
    origin_candidates = [{"ip": "192.168.1.10", "source": "spf"}]

    ranked = prioritize_target_ips(target_ips, ip_resolutions, origin_candidates)

    # 192.168.1.20 has vpn + api (score 10 + 90 + 90 = 190)
    # 192.168.1.10 is origin (score 10 + 100 = 110)
    # 192.168.1.30 has dev (score 10 + 30 = 40)
    # 192.168.1.40 has assets (score 10 + 15 = 25)
    assert ranked[0] == "192.168.1.20"
    assert ranked[1] == "192.168.1.10"
    assert ranked[2] == "192.168.1.30"
    assert ranked[3] == "192.168.1.40"


def test_scan_multiple_hosts_concurrently():
    import time
    from recon.ports import scan_multiple_hosts_concurrently

    def mock_scan(ip, profile="standard", timeout=300):
        time.sleep(0.1)
        return [{"port": 80, "service": "http"}]

    ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    
    t0 = time.time()
    with patch("recon.ports.scan_ports_and_services", side_effect=mock_scan):
        results = scan_multiple_hosts_concurrently(ips, profile="standard", max_workers=4)
    duration = time.time() - t0

    assert len(results) == 4
    # Sequential would be 0.1 * 4 = 0.4s. Concurrently with 4 workers it should take < 0.25s
    assert duration < 0.3, f"Concurrent scan took {duration:.2f}s, expected < 0.3s"
    assert {r["ip"] for r in results} == set(ips)


