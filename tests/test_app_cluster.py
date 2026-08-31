import pytest
import asyncio
from unittest.mock import patch, MagicMock
from vuln.app_vuln.cluster import (
    compute_cluster_signature,
    probe_and_cluster_targets,
    TargetCluster,
)


def test_compute_cluster_signature_determinism():
    sig1 = compute_cluster_signature(
        origin_ip="192.168.1.1",
        status_code=200,
        title="Production Dashboard",
        server="nginx/1.24.0",
        body_snippet="<html><body>Welcome to Dashboard</body></html>",
    )
    sig2 = compute_cluster_signature(
        origin_ip="192.168.1.1",
        status_code=200,
        title="production dashboard",
        server="nginx/1.24.0",
        body_snippet="<html><body>Welcome to Dashboard</body></html>",
    )
    assert len(sig1) == 16
    assert sig1 == sig2  # Case-insensitive title normalization

    sig_diff = compute_cluster_signature(
        origin_ip="192.168.1.2",
        status_code=404,
        title="Not Found",
        server="Apache/2.4.58",
    )
    assert sig1 != sig_diff


@pytest.mark.asyncio
async def test_probe_and_cluster_targets_grouping():
    # 5 subdomains where 3 are aliases to the same app, and 2 are distinct
    subdomains = [
        "app.target.com",
        "app-alias.target.com",
        "app-cname.target.com",
        "api.target.com",
        "admin.target.com",
    ]
    ip_resolutions = [
        {"subdomain": "app.target.com", "ips": ["1.1.1.1"]},
        {"subdomain": "app-alias.target.com", "ips": ["1.1.1.1"]},
        {"subdomain": "app-cname.target.com", "ips": ["1.1.1.1"]},
        {"subdomain": "api.target.com", "ips": ["2.2.2.2"]},
        {"subdomain": "admin.target.com", "ips": ["3.3.3.3"]},
    ]

    async def mock_get(url, *args, **kwargs):
        resp = MagicMock()
        url_str = str(url)
        if "app" in url_str:
            resp.status_code = 200
            resp.url = url_str
            resp.headers = {"server": "Nginx/1.24.0"}
            resp.text = "<html><head><title>Corporate Portal</title></head><body>Welcome</body></html>"
        elif "api" in url_str:
            resp.status_code = 200
            resp.url = url_str
            resp.headers = {"server": "Express"}
            resp.text = '{"status": "ok", "version": "v1"}'
        elif "admin" in url_str:
            resp.status_code = 403
            resp.url = url_str
            resp.headers = {"server": "Nginx/1.24.0"}
            resp.text = "<html><head><title>403 Forbidden</title></head></html>"
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        clusters = await probe_and_cluster_targets(
            subdomain_names=subdomains,
            ip_resolutions=ip_resolutions,
        )

        assert len(clusters) == 3
        # Find the app cluster with 3 members
        app_cluster = next((c for c in clusters if "Corporate Portal" in c.title or "app.target.com" in c.member_subdomains), None)
        assert app_cluster is not None
        assert len(app_cluster.member_subdomains) == 3
        assert "app.target.com" in app_cluster.member_subdomains
        assert "app-alias.target.com" in app_cluster.member_subdomains
        assert "app-cname.target.com" in app_cluster.member_subdomains
