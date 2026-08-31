import pytest
from bs4 import BeautifulSoup
from people.site_crawler import (
    decode_cloudflare_email,
    extract_json_ld_entities,
    crawl_site_for_people,
)


def _make_cf_hex(email: str, key: int = 0x25) -> str:
    """Helper to generate Cloudflare XOR hex for testing."""
    return f"{key:02x}" + "".join(f"{ord(c) ^ key:02x}" for c in email)


def test_decode_cloudflare_email():
    original = "security-contact@recon7.target.com"
    cf_hex = _make_cf_hex(original, key=0x4a)
    decoded = decode_cloudflare_email(cf_hex)
    assert decoded == original.lower()

    # Invalid / empty hex checks
    assert decode_cloudflare_email("") == ""
    assert decode_cloudflare_email("abc") == ""
    assert decode_cloudflare_email("invalid_non_hex") == ""


def test_extract_json_ld_entities_person_and_org():
    html = """
    <html>
      <head>
        <script type="application/ld+json">
        {
          "@context": "https://schema.org",
          "@type": "Person",
          "name": "Sarah Connor",
          "jobTitle": "Chief Information Security Officer",
          "email": "sarah.connor@cyberdyne.corp",
          "telephone": "+1-555-0199",
          "url": "https://cyberdyne.corp/team/sarah"
        }
        </script>
        <script type="application/ld+json">
        {
          "@context": "https://schema.org",
          "@graph": [
            {
              "@type": "Organization",
              "name": "Cyberdyne Systems",
              "email": "inquiries@cyberdyne.corp",
              "telephone": "+1-800-555-0100"
            }
          ]
        }
        </script>
      </head>
      <body><h1>Team</h1></body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    results = extract_json_ld_entities(soup, "https://cyberdyne.corp/team")

    assert len(results) >= 2

    person = next((r for r in results if r["name"] == "Sarah Connor"), None)
    assert person is not None
    assert person["email"] == "sarah.connor@cyberdyne.corp"
    assert person["phone"] == "+1-555-0199"
    assert person["title"] == "Chief Information Security Officer"
    assert person["is_human"] is True
    assert person["confidence"] == 96

    org_email = next((r for r in results if r["email"] == "inquiries@cyberdyne.corp"), None)
    assert org_email is not None
    assert org_email["is_human"] is False


def test_deep_crawler_with_mocked_http(monkeypatch):
    """Tests the in-scope crawl loop with mock responses."""
    cf_email = "cf-hidden@target.com"
    cf_hex = _make_cf_hex(cf_email, key=0x37)

    mock_html = f"""
    <html>
      <body>
        <a href="/cdn-cgi/l/email-protection#{cf_hex}">Protected Contact</a>
        <a href="mailto:direct.team@target.com">Direct Mail</a>
        <a href="tel:+1-555-4321">Call Us</a>
        <a href="https://careers.target.com/about">Careers Subdomain (In-Scope)</a>
        <a href="https://external-social.com/target">External Out-of-Scope Link</a>
        <div class="team-member">
          <h3>John Doe</h3>
          <span class="role">Lead Architect</span>
        </div>
      </body>
    </html>
    """

    class MockResponse:
        def __init__(self, text, status_code=200):
            self.text = text
            self.status_code = status_code
            self.headers = {"content-type": "text/html; charset=utf-8"}
            self.url = "https://target.com"

        def read(self):
            return self.text.encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    class MockClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

        def get(self, url, timeout=None):
            return MockResponse(mock_html)

        def stream(self, method, url):
            return MockResponse(mock_html)

    import httpx
    monkeypatch.setattr(httpx, "Client", MockClient)

    results = crawl_site_for_people(
        domain="target.com",
        subdomains=["careers.target.com", "api.target.com", "evil.out-of-scope.com"],
        max_pages=5,
        max_depth=1,
        timeout=5,
    )

    emails = {r.get("email") for r in results if r.get("email")}
    phones = {r.get("phone") for r in results if r.get("phone")}
    names = {r.get("name") for r in results if r.get("name")}

    # 1. Cloudflare de-obfuscated email was recovered
    assert cf_email in emails

    # 2. Direct mailto email was recovered
    assert "direct.team@target.com" in emails

    # 3. Tel link was recovered
    assert "+1-555-4321" in phones

    # 4. Human name was extracted from team card
    assert "John Doe" in names
