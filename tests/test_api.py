import pytest
import uuid
from fastapi.testclient import TestClient
from main import app
from storage.db import init_db

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


def get_admin_token() -> str:
    login_res = client.post(
        "/api/auth/login",
        json={"email": "admin@recon7.io", "password": "Admin@12345"},
    )
    if login_res.status_code != 200:
        # If admin@recon7.io doesn't exist, create one
        from storage.db import SessionLocal, create_user, create_tenant
        from core.auth import hash_password
        db = SessionLocal()
        try:
            tenant = create_tenant(db, name="Default Organization")
            create_user(
                db=db,
                email="admin@recon7.io",
                password_hash=hash_password("Admin@12345"),
                tenant_id=tenant.id,
                role="system_admin",
                allowed_tenants=["*"],
            )
        finally:
            db.close()
        login_res = client.post(
            "/api/auth/login",
            json={"email": "admin@recon7.io", "password": "Admin@12345"},
        )
    assert login_res.status_code == 200
    return login_res.json()["access_token"]


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app"] == "R7 - Reconnaissance Platform"


def test_unauthenticated_requests_strictly_rejected():
    """Verify that all operational endpoints strictly deny unauthenticated/guest access."""
    # 1. Dashboard
    dash_res = client.get("/api/dashboard")
    assert dash_res.status_code == 401

    # 2. Trigger Scan
    scan_res = client.post("/api/scan", json={"domain": "example.com"})
    assert scan_res.status_code == 401

    # 3. List Scans
    scans_res = client.get("/api/scans")
    assert scans_res.status_code == 401

    # 4. Scopes
    scopes_res = client.get("/api/scopes")
    assert scopes_res.status_code == 401

    # 5. Integrations
    integrations_res = client.get("/api/integrations")
    assert integrations_res.status_code == 401


def test_tenant_and_scope_workflow():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Register Scope
    scope_res = client.post(
        "/api/scopes",
        headers=headers,
        json={"domain": "example.com", "authorization_type": "engagement_letter", "authorized_by": "sec-lead@target.com"},
    )
    assert scope_res.status_code == 201
    assert scope_res.json()["domain"] == "example.com"

    # 2. Trigger Scan
    scan_res = client.post(
        "/api/scan",
        headers=headers,
        json={"domain": "example.com"},
    )
    assert scan_res.status_code == 202
    job_data = scan_res.json()
    job_id = job_data["id"]
    assert job_data["status"] == "pending"
    assert job_data["target_domain"] == "example.com"

    # 3. Check Scan Status
    status_res = client.get(f"/api/scan/{job_id}", headers=headers)
    assert status_res.status_code == 200
    assert status_res.json()["id"] == job_id

    # 4. Check Dashboard
    dash_res = client.get("/api/dashboard", headers=headers)
    assert dash_res.status_code == 200
    dash_data = dash_res.json()
    assert dash_data["scans"]["total"] >= 1


def test_integrations_endpoints():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. GET integrations
    get_res = client.get("/api/integrations", headers=headers)
    assert get_res.status_code == 200
    items = get_res.json()
    assert isinstance(items, list)
    assert len(items) >= 5
    provider_names = [i["provider"] for i in items]
    assert "google_search" in provider_names
    assert "github" in provider_names
    assert "shodan" in provider_names

    # 2. POST save integration (e.g. Shodan)
    save_res = client.post(
        "/api/integrations",
        headers=headers,
        json={
            "provider": "shodan",
            "config": {"api_key": "shodan_secret_key_12345"},
            "is_enabled": True,
        },
    )
    assert save_res.status_code == 200
    assert save_res.json()["status"] == "success"

    # 3. Verify updated
    get_res2 = client.get("/api/integrations", headers=headers)
    items2 = get_res2.json()
    shodan_item = next(i for i in items2 if i["provider"] == "shodan")
    assert shodan_item["is_configured"] is True
    assert "••••••••" in shodan_item["config"]["api_key"]


def test_auth_login_default_admin():
    token = get_admin_token()
    # Test /api/auth/me with Bearer token
    me_res = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["user"]["email"] == "admin@recon7.io"


def test_auth_provision_new_operator_via_iam():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}
    random_email = f"operator_{uuid.uuid4().hex[:6]}@redteam.local"

    # 1. IAM Admin Provisions Operator
    iam_res = client.post(
        "/api/iam/users",
        headers=headers,
        json={
            "full_name": "Marcus Kane",
            "email": random_email,
            "password": "SecurePassword123!",
            "role": "operator",
            "tenant_id": "default-tenant",
        },
    )
    assert iam_res.status_code == 201
    data = iam_res.json()
    assert data["email"] == random_email
    assert data["full_name"] == "Marcus Kane"

    # 2. Login with newly created user
    login_res = client.post(
        "/api/auth/login",
        json={"email": random_email, "password": "SecurePassword123!"},
    )
    assert login_res.status_code == 200


def test_auth_invalid_credentials():
    bad_login = client.post(
        "/api/auth/login",
        json={"email": "admin@recon7.io", "password": "WrongPassword123"},
    )
    assert bad_login.status_code == 401

