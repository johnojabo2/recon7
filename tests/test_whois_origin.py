import pytest
from unittest.mock import patch, MagicMock
from recon.company_resolve import resolve_company_info, _parse_iso_date
from recon.origin_extractor import extract_origin_intelligence, map_cname_infrastructure


def test_parse_iso_date():
    dt = _parse_iso_date("2023-04-12T10:18:47Z")
    assert dt is not None
    assert dt.year == 2023
    assert dt.month == 4
    assert dt.day == 12


def test_map_cname_infrastructure_s3():
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_rdata = MagicMock()
        mock_rdata.target = "mybucket.s3.amazonaws.com."
        mock_resolve.return_value = [mock_rdata]
        
        info = map_cname_infrastructure("assets.example.com")
        assert info["cloud_service"] == "AWS S3 Bucket"
        assert info["cloud_provider"] == "Amazon Web Services"
        assert info["is_cloud_hosted"] is True


def test_map_cname_infrastructure_vercel():
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_rdata = MagicMock()
        mock_rdata.target = "cname.vercel-dns.com."
        mock_resolve.return_value = [mock_rdata]
        
        info = map_cname_infrastructure("app.example.com")
        assert info["cloud_service"] == "Vercel Edge Platform"
        assert info["cloud_provider"] == "Vercel"
        assert info["is_cloud_hosted"] is True


def test_extract_origin_intelligence_spf():
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        # Mock TXT for SPF
        mock_txt = MagicMock()
        mock_txt.strings = [b"v=spf1 ip4:198.51.100.25 include:_spf.google.com ~all"]
        mock_resolve.return_value = [mock_txt]
        
        origin_data = extract_origin_intelligence("example.com")
        assert "v=spf1" in (origin_data["spf_record"] or "")
        assert "198.51.100.25" in origin_data["spf_cidrs"]
