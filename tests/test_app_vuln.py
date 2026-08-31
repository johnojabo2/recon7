import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from vuln.app_vuln.plugins.cors_audit import CorsAuditPlugin
from vuln.app_vuln.plugins.graphql_audit import GraphQLAuditPlugin
from vuln.app_vuln.plugins.ssti_probe import SstiProbePlugin
from vuln.app_vuln.plugins.js_harvester import JsHarvesterPlugin
from vuln.app_vuln.plugins.redirect_probe import RedirectProbePlugin
from vuln.app_vuln.runner import run_app_vuln_scans_sync


@pytest.mark.asyncio
async def test_cors_audit_vulnerable_origin_with_credentials():
    plugin = CorsAuditPlugin()
    mock_client = AsyncMock()

    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {
        "access-control-allow-origin": "https://recon7-security-audit.com",
        "access-control-allow-credentials": "true",
    }
    mock_client.get.return_value = resp

    findings = await plugin.audit(
        target_url="https://api.target.com",
        context={"cluster_domains": ["api.target.com", "dev-api.target.com"]},
        client=mock_client,
    )

    assert len(findings) >= 1
    f = findings[0]
    assert f["severity"] == "high"
    assert f["finding_status"] == "CONFIRMED"
    assert f["evidence_tier"] == "ACTIVE_EXPLOIT_PROOF"
    assert "Arbitrary Origin Reflection with Credentials" in f["title"]
    assert "dev-api.target.com" in f["cluster_domains"]


@pytest.mark.asyncio
async def test_cors_audit_secure_no_reflection():
    plugin = CorsAuditPlugin()
    mock_client = AsyncMock()

    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {
        "access-control-allow-origin": "https://target.com",
        "access-control-allow-credentials": "true",
    }
    mock_client.get.return_value = resp

    findings = await plugin.audit(
        target_url="https://api.target.com",
        context={"cluster_domains": ["api.target.com"]},
        client=mock_client,
    )
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_graphql_audit_introspection_exposed():
    plugin = GraphQLAuditPlugin()
    mock_client = AsyncMock()

    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "data": {
            "__schema": {
                "queryType": {
                    "name": "Query",
                    "fields": [{"name": "getAdminUsers"}, {"name": "getUserToken"}, {"name": "listProducts"}],
                },
                "types": [
                    {"name": "User", "kind": "OBJECT"},
                    {"name": "AdminRole", "kind": "OBJECT"},
                ],
            }
        }
    }
    mock_client.post.return_value = resp

    findings = await plugin.audit(
        target_url="https://target.com",
        context={"cluster_domains": ["target.com", "www.target.com"]},
        client=mock_client,
    )

    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "medium"
    assert f["finding_status"] == "CONFIRMED"
    assert "GraphQL Schema Introspection" in f["title"]
    assert "getAdminUsers" in f["evidence_proof"]
    assert f["metadata"]["total_queries"] == 3


@pytest.mark.asyncio
async def test_ssti_probe_arithmetic_evaluation():
    plugin = SstiProbePlugin()
    mock_client = AsyncMock()

    # Target evaluates {{4919*7}} to 34433 without raw payload reflection
    resp = MagicMock()
    resp.status_code = 200
    resp.text = "<html><body><h1>Hello 34433!</h1><p>Welcome back</p></body></html>"
    mock_client.get.return_value = resp

    findings = await plugin.audit(
        target_url="https://target.com/profile?name=test",
        context={"cluster_domains": ["target.com"]},
        client=mock_client,
    )

    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "critical"
    assert f["cvss_score"] == 9.8
    assert "Server-Side Template Injection" in f["title"]
    assert "34433" in f["evidence_proof"]


@pytest.mark.asyncio
async def test_js_harvester_secret_and_routes():
    plugin = JsHarvesterPlugin()
    mock_client = AsyncMock()

    # Base page response referencing bundle.js
    base_resp = MagicMock()
    base_resp.status_code = 200
    base_resp.text = '<html><head><script src="/static/js/main.chunk.js"></script></head></html>'

    # JS file response containing leaked GitHub token and internal admin route
    js_resp = MagicMock()
    js_resp.status_code = 200
    js_resp.text = (
        'const config = { api: "/api/v1/admin/user-secrets", token: "ghp_1234567890abcdefghijklmnopqrstuvwxyz12" };'
    )

    mock_client.get.side_effect = [base_resp, js_resp]

    findings = await plugin.audit(
        target_url="https://app.target.com",
        context={"cluster_domains": ["app.target.com"]},
        client=mock_client,
    )

    assert len(findings) >= 1
    secret_finding = next((f for f in findings if "GitHub Personal Access Token" in f["title"]), None)
    assert secret_finding is not None
    assert secret_finding["severity"] == "critical"
    assert "ghp_12" in secret_finding["evidence_proof"]


@pytest.mark.asyncio
async def test_redirect_probe_unvalidated():
    plugin = RedirectProbePlugin()
    mock_client = AsyncMock()

    resp = MagicMock()
    resp.status_code = 302
    resp.headers = {"location": "https://recon7-redirect-test.com/auth-callback"}
    mock_client.get.return_value = resp

    findings = await plugin.audit(
        target_url="https://target.com/login?next=/dashboard",
        context={"cluster_domains": ["target.com"]},
        client=mock_client,
    )

    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "medium"
    assert "Open Redirect" in f["title"]
    assert "recon7-redirect-test.com" in f["evidence_proof"]


def test_app_vuln_runner_sync_fanout():
    # Test synchronous runner bridge and cluster domain fan-out
    with patch("vuln.app_vuln.cluster.probe_and_cluster_targets") as mock_cluster, \
         patch("httpx.AsyncClient.get") as mock_get:

        from vuln.app_vuln.cluster import TargetCluster
        mock_cluster.return_value = [
            TargetCluster(
                cluster_id="test_cluster",
                representative_url="https://app.target.com",
                origin_ip="1.2.3.4",
                status_code=200,
                title="App Portal",
                server_header="Nginx",
                member_subdomains=["app.target.com", "app2.target.com", "app3.target.com"],
            )
        ]

        cors_resp = MagicMock()
        cors_resp.status_code = 200
        cors_resp.headers = {
            "access-control-allow-origin": "https://recon7-security-audit.com",
            "access-control-allow-credentials": "true",
        }
        mock_get.return_value = cors_resp

        findings = run_app_vuln_scans_sync(
            targets=["app.target.com", "app2.target.com", "app3.target.com"],
            plugins=[CorsAuditPlugin()],
        )

        assert len(findings) >= 1
        assert findings[0]["affected_subdomains_count"] == 3
        assert "app3.target.com" in findings[0]["cluster_domains"]
