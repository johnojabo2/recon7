import pytest
from recon.ports import parse_nmap_xml
from recon.fingerprint import match_signatures
from people.aggregate import infer_email_pattern, generate_email_from_name


SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -p 80,443 -oX - 192.168.1.50">
  <host>
    <status state="up"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.24.0" extrainfo="Ubuntu" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="OpenSSL" version="3.0.2" tunnel="ssl" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml():
    results = parse_nmap_xml(SAMPLE_NMAP_XML)
    assert len(results) == 2
    
    p80 = next(p for p in results if p["port"] == 80)
    assert p80["protocol"] == "tcp"
    assert p80["service"] == "http"
    assert p80["product"] == "nginx"
    assert "1.24.0" in p80["version"]
    assert p80["state"] == "open"


def test_wappalyzer_signature_matcher():
    headers = {
        "server": "nginx/1.24.0",
        "x-powered-by": "PHP/8.2.10",
        "set-cookie": "PHPSESSID=abc123xyz",
    }
    body = """
    <html>
      <head><title>Test App</title></head>
      <body>
        <div data-reactroot=""></div>
        <script src="/static/js/react.production.min.js"></script>
      </body>
    </html>
    """
    techs = match_signatures(headers, body)
    names = [t["name"] for t in techs]
    assert "Nginx" in names
    assert "PHP" in names
    assert "React" in names


def test_email_pattern_inference():
    confirmed = [
        "john.doe@targetcorp.com",
        "alice.smith@targetcorp.com",
        "bob.johnson@targetcorp.com",
        "info@targetcorp.com",
    ]
    pattern = infer_email_pattern(confirmed, "targetcorp.com")
    assert pattern == "{first}.{last}@targetcorp.com"

    # Test generation from name
    generated = generate_email_from_name("Marcus Holloway", pattern, "targetcorp.com")
    assert generated == "marcus.holloway@targetcorp.com"

    # Test alternative pattern {f}{last}
    f_last_pattern = "{f}{last}@targetcorp.com"
    gen_f_last = generate_email_from_name("Marcus Holloway", f_last_pattern, "targetcorp.com")
    assert gen_f_last == "mholloway@targetcorp.com"

    # Test title and honorific stripping (e.g. Prof, Dr, Engr, Barr, Chief, Ph.D., SAN)
    assert generate_email_from_name("Prof Aleruchi Chuku", pattern, "fulafia.edu.ng") == "aleruchi.chuku@fulafia.edu.ng"
    assert generate_email_from_name("Prof. Dr. Aleruchi Chuku, Ph.D.", pattern, "fulafia.edu.ng") == "aleruchi.chuku@fulafia.edu.ng"
    assert generate_email_from_name("Engr. Emmanuel Okon (FNSE)", pattern, "company.com") == "emmanuel.okon@company.com"
    assert generate_email_from_name("Barrister Ngozi Eze, SAN", pattern, "lawfirm.ng") == "ngozi.eze@lawfirm.ng"
    assert generate_email_from_name("Chief Babatunde Adeyemi Jr.", pattern, "holding.com") == "babatunde.adeyemi@holding.com"


def test_ui_noise_and_corporate_name_filtering():
    from people.linkedin_enum import is_valid_human_name

    # 1. UI buttons and navigation links MUST be rejected
    assert is_valid_human_name("Visit Us", "notjustevent") is False
    assert is_valid_human_name("Contact Us", "notjustevent") is False
    assert is_valid_human_name("Read More", "notjustevent") is False
    assert is_valid_human_name("Learn More", "notjustevent") is False

    # 2. Corporate legal entities MUST be rejected
    assert is_valid_human_name("NotJustEvent, Inc.", "notjustevent") is False
    assert is_valid_human_name("Acme Technologies LLC", "acme") is False
    assert is_valid_human_name("Global Holdings Ltd", "global") is False

    # 3. Truncated single-letter names MUST be rejected
    assert is_valid_human_name("FULafia V", "fulafia") is False

    # 4. Real human names MUST be accepted
    assert is_valid_human_name("Grace Aboyi", "notjustevent") is True
    assert is_valid_human_name("Jesutofunmi Adeboye", "notjustevent") is True
    assert is_valid_human_name("John Ojabo", "notjustevent") is True

    # 5. Generic single-word mailboxes must NOT trigger {f}{last}
    from people.aggregate import infer_email_pattern
    pattern = infer_email_pattern(["events@notjustevent.com", "hello@notjustevent.com", "team@notjustevent.com"], "notjustevent.com")
    assert pattern == "{first}.{last}@notjustevent.com"


