import pytest
from unittest.mock import patch, MagicMock
from recon.subdomains import (
    enumerate_subdomains,
    _active_dns_bruteforce,
    HIGH_SIGNAL_SUBDOMAIN_WORDLIST,
)
import dns.resolver


def test_high_signal_wordlist_integrity():
    assert len(HIGH_SIGNAL_SUBDOMAIN_WORDLIST) >= 150
    assert "api" in HIGH_SIGNAL_SUBDOMAIN_WORDLIST
    assert "dev" in HIGH_SIGNAL_SUBDOMAIN_WORDLIST
    assert "staging" in HIGH_SIGNAL_SUBDOMAIN_WORDLIST
    assert "admin" in HIGH_SIGNAL_SUBDOMAIN_WORDLIST
    assert "auth" in HIGH_SIGNAL_SUBDOMAIN_WORDLIST
    assert "vpn" in HIGH_SIGNAL_SUBDOMAIN_WORDLIST


def test_active_dns_bruteforce_non_wildcard():
    # Mock dns.resolver.Resolver to simulate normal domain without wildcard
    with patch("dns.resolver.Resolver") as mock_resolver_cls:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        def side_effect(qname, rtype):
            qname_str = str(qname)
            # Canary lookups fail (NXDOMAIN) -> Non-wildcard domain
            if "r7-canary" in qname_str:
                raise dns.resolver.NXDOMAIN()
            # api and dev succeed
            if "api.example.com" in qname_str or "dev.example.com" in qname_str:
                ans = MagicMock()
                ans.address = "93.184.216.34"
                return [ans]
            raise dns.resolver.NXDOMAIN()

        mock_resolver.resolve.side_effect = side_effect

        subs = _active_dns_bruteforce("example.com")
        assert "api.example.com" in subs
        assert "dev.example.com" in subs


def test_active_dns_bruteforce_wildcard_noise_filtered():
    # Mock dns.resolver.Resolver to simulate wildcard domain (e.g. *.example.com -> 1.2.3.4)
    with patch("dns.resolver.Resolver") as mock_resolver_cls:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        def side_effect(qname, rtype):
            qname_str = str(qname)
            # Canaries resolve to wildcard IP 1.2.3.4
            if "r7-canary" in qname_str:
                ans = MagicMock()
                ans.address = "1.2.3.4"
                return [ans]
            # Standard words resolve to wildcard IP 1.2.3.4 (should be filtered out)
            if "staging.example.com" in qname_str:
                ans = MagicMock()
                ans.address = "1.2.3.4"
                return [ans]
            # Genuine distinct service resolves to different IP 5.6.7.8 (should be kept!)
            if "api.example.com" in qname_str:
                ans = MagicMock()
                ans.address = "5.6.7.8"
                return [ans]
            raise dns.resolver.NXDOMAIN()

        mock_resolver.resolve.side_effect = side_effect

        subs = _active_dns_bruteforce("example.com")
        # api.example.com had a distinct IP -> kept
        assert "api.example.com" in subs
        # staging.example.com had the wildcard IP -> filtered out as noise!
        assert "staging.example.com" not in subs


def test_enumerate_subdomains_aggregates_passive_and_active():
    with patch("recon.subdomains._query_crt_sh", return_value=["mail.example.com"]), \
         patch("recon.subdomains._query_hackertarget", return_value=["blog.example.com"]), \
         patch("recon.subdomains._query_certspotter", return_value=[]), \
         patch("recon.subdomains._active_dns_bruteforce", return_value=["api.example.com", "mail.example.com"]):

        results = enumerate_subdomains("example.com")
        sub_map = {r["subdomain"]: r["sources"] for r in results}

        assert "example.com" in sub_map
        assert "root_domain" in sub_map["example.com"]

        # Discovered by passive CT log
        assert "blog.example.com" in sub_map
        assert "hackertarget" in sub_map["blog.example.com"]

        # Discovered by active DNS brute-force
        assert "api.example.com" in sub_map
        assert "active_dns_bruteforce" in sub_map["api.example.com"]

        # Discovered by both passive and active
        assert "mail.example.com" in sub_map
        assert "crt.sh" in sub_map["mail.example.com"]
        assert "active_dns_bruteforce" in sub_map["mail.example.com"]
