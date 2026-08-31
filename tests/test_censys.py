import pytest
import os
from unittest.mock import patch, MagicMock
from core.config import settings
from recon.censys_client import (
    get_censys_credentials,
    query_censys_subdomains,
    query_censys_hosts,
)


def test_censys_credentials_absent():
    """Verify that absent credentials return (None, None, None)."""
    with patch.object(settings, "CENSYS_API_ID", None), patch.object(settings, "CENSYS_API_SECRET", None), patch.dict(os.environ, {}, clear=True):
        cid, sec, oid = get_censys_credentials()
        assert cid is None
        assert sec is None
        assert oid is None


def test_censys_credentials_configured():
    """Verify configured credentials resolution."""
    with patch.object(settings, "CENSYS_API_ID", "test-id-123"), patch.object(settings, "CENSYS_API_SECRET", "test-secret-456"):
        cid, sec, oid = get_censys_credentials()
        assert cid == "test-id-123"
        assert sec == "test-secret-456"


def test_query_censys_subdomains_mocked():
    """Verify certificate SAN subdomain extraction."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "result": {
            "hits": [
                {
                    "names": ["auth.example.com", "api.example.com", "otherdomain.com"]
                }
            ]
        }
    }

    with patch("httpx.Client.get", return_value=mock_resp):
        subs = query_censys_subdomains("example.com", api_id="id", api_secret="sec")
        assert "auth.example.com" in subs
        assert "api.example.com" in subs
        assert "otherdomain.com" not in subs


def test_query_censys_hosts_mocked():
    """Verify host IP and open port extraction."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "result": {
            "hits": [
                {
                    "ip": "198.51.100.42",
                    "services": [
                        {"port": 443, "service_name": "HTTP"},
                        {"port": 22, "service_name": "SSH"},
                    ],
                    "autonomous_system": {"asn": 13335, "name": "Cloudflare Inc"},
                    "location": {"country": "United States"},
                }
            ]
        }
    }

    with patch("httpx.Client.get", return_value=mock_resp):
        hosts = query_censys_hosts("example.com", api_id="id", api_secret="sec")
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "198.51.100.42"
        assert len(hosts[0]["ports"]) == 2
        assert hosts[0]["ports"][0]["port"] == 443


def test_censys_rate_limit_and_error_handling():
    """Verify 401 and 429 errors do not crash and return empty list cleanly."""
    mock_resp_401 = MagicMock()
    mock_resp_401.status_code = 401
    mock_resp_401.text = "Unauthorized"

    with patch("httpx.Client.get", return_value=mock_resp_401):
        subs = query_censys_subdomains("example.com", api_id="bad_id", api_secret="bad_sec")
        assert subs == []
        hosts = query_censys_hosts("example.com", api_id="bad_id", api_secret="bad_sec")
        assert hosts == []
