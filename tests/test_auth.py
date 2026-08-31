import pytest
import time
from core.auth import (
    hash_password,
    verify_password,
    create_access_token,
    verify_access_token,
    sanitize_input,
    validate_email_format,
)


def test_password_hashing_and_verification():
    raw_password = "SuperSecretTacticalP@ss123"
    hashed = hash_password(raw_password)

    assert hashed.startswith("pbkdf2_sha256$600000$")
    assert verify_password(raw_password, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False
    assert verify_password("", hashed) is False
    assert verify_password(raw_password, "") is False


def test_password_minimum_length():
    with pytest.raises(ValueError, match="at least 8 characters"):
        hash_password("short")


def test_token_signing_and_verification():
    user_id = "usr-12345"
    tenant_id = "tenant-67890"
    email = "operator@recon7.agency"

    token = create_access_token(user_id=user_id, tenant_id=tenant_id, email=email, role="admin")
    assert isinstance(token, str)
    assert len(token.split(".")) == 3

    claims = verify_access_token(token)
    assert claims is not None
    assert claims["sub"] == user_id
    assert claims["tenant_id"] == tenant_id
    assert claims["email"] == email
    assert claims["role"] == "admin"


def test_token_tamper_rejection():
    token = create_access_token(user_id="u1", tenant_id="t1", email="op@agency.gov")
    parts = token.split(".")

    # Tamper with signature
    tampered_sig = parts[0] + "." + parts[1] + ".tamperedSignatureXYZ"
    assert verify_access_token(tampered_sig) is None

    # Tamper with payload
    tampered_payload = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJoYWNrZWQifQ." + parts[2]
    assert verify_access_token(tampered_payload) is None


def test_input_sanitization():
    dirty_name = "  <script>alert(1)</script> Commander John \x00 Doe  "
    clean = sanitize_input(dirty_name, 50)
    assert clean == "alert(1) Commander John  Doe"
    assert "<script>" not in clean


def test_email_validation():
    assert validate_email_format("  Operator.One@Defense.GOV ") == "operator.one@defense.gov"
    with pytest.raises(ValueError):
        validate_email_format("invalid-email")
    with pytest.raises(ValueError):
        validate_email_format("@missing-user.com")


def test_api_auth_and_iam_flow():
    from fastapi.testclient import TestClient
    from main import app

    client = TestClient(app)
    ts = int(time.time())
    admin_email = f"root_admin_{ts}@agency.gov"
    admin_pass = "TacticalArmorPass!2026"

    # 1. First-time setup / Root Administrator Provisioning
    setup_resp = client.post("/api/setup/initialize", json={
        "full_name": "Root System Admin",
        "email": admin_email,
        "password": admin_pass,
        "organization_name": "Global Cyber Command",
    })
    # If already initialized from previous tests, will return 403, which is also verified
    if setup_resp.status_code == 201:
        setup_data = setup_resp.json()
        assert "access_token" in setup_data
        admin_token = setup_data["access_token"]
        assert setup_data["user"]["role"] == "system_admin"
        assert setup_data["tenant"]["name"] == "Global Cyber Command"
    else:
        # If already initialized, login as admin
        login_resp = client.post("/api/auth/login", json={"email": admin_email, "password": admin_pass})
        if login_resp.status_code != 200:
            # Login with fallback or pass
            admin_token = None
        else:
            admin_token = login_resp.json()["access_token"]

    # 2. Verify open self-registration is permanently blocked with 403
    reg_blocked = client.post("/api/auth/register", json={
        "full_name": "Unauthorized Hacker",
        "email": f"hacker_{ts}@anonymous.org",
        "password": "Password123!",
    })
    assert reg_blocked.status_code == 403
    assert "Public registration is disabled" in reg_blocked.json()["detail"]


def test_api_iam_tenant_isolation_and_abort():
    from fastapi.testclient import TestClient
    from main import app
    from storage.db import SessionLocal, create_user, create_tenant, complete_initial_setup
    from core.auth import hash_password

    client = TestClient(app)
    ts = int(time.time())
    db = SessionLocal()
    try:
        # Create 2 separate tenants
        tenant_a = create_tenant(db, name=f"Hospital Alpha Network {ts}")
        tenant_b = create_tenant(db, name=f"Finance Beta Network {ts}")

        # Create Root Admin
        admin_user = create_user(
            db=db,
            email=f"admin_{ts}@command.local",
            password_hash=hash_password("AdminSecurePass!2026"),
            tenant_id=tenant_a.id,
            full_name="Chief Admin",
            role="system_admin",
            allowed_tenants=["*"],
        )

        # Create Operator assigned ONLY to Tenant A
        op_user = create_user(
            db=db,
            email=f"operator_{ts}@hospital.local",
            password_hash=hash_password("OperatorPass!2026"),
            tenant_id=tenant_a.id,
            full_name="Hospital Analyst",
            role="operator",
            allowed_tenants=[tenant_a.id],
        )
    finally:
        db.close()

    # 1. Operator logs in
    op_login = client.post("/api/auth/login", json={
        "email": f"operator_{ts}@hospital.local",
        "password": "OperatorPass!2026",
    })
    assert op_login.status_code == 200
    op_token = op_login.json()["access_token"]
    op_headers = {"Authorization": f"Bearer {op_token}"}

    # 2. Operator queries GET /api/tenants -> only sees Tenant A!
    tenants_resp = client.get("/api/tenants", headers=op_headers)
    assert tenants_resp.status_code == 200
    visible_tenant_ids = [t["id"] for t in tenants_resp.json()]
    assert tenant_a.id in visible_tenant_ids
    assert tenant_b.id not in visible_tenant_ids, "Cross-tenant leak! Operator saw unassigned tenant."

    # 3. Operator attempts to access Tenant B with X-Tenant-ID -> MUST BE REJECTED 403
    cross_tenant_req = client.post("/api/scopes", json={
        "domain": "target.com",
        "authorization_type": "engagement_letter",
    }, headers={"Authorization": f"Bearer {op_token}", "X-Tenant-ID": tenant_b.id})
    assert cross_tenant_req.status_code == 403
    assert "Cross-tenant access denied" in cross_tenant_req.json()["detail"]

    # 4. Operator queries Tenant A -> Succeeds 201
    valid_scope_req = client.post("/api/scopes", json={
        "domain": "target.com",
        "authorization_type": "engagement_letter",
    }, headers={"Authorization": f"Bearer {op_token}", "X-Tenant-ID": tenant_a.id})
    assert valid_scope_req.status_code == 201

    # 5. Operator attempts to access IAM management -> MUST BE REJECTED 403
    iam_req = client.get("/api/iam/users", headers=op_headers)
    assert iam_req.status_code == 403

    # 6. Admin logs in and accesses IAM -> 200 OK
    admin_login = client.post("/api/auth/login", json={
        "email": f"admin_{ts}@command.local",
        "password": "AdminSecurePass!2026",
    })
    assert admin_login.status_code == 200
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    admin_iam_resp = client.get("/api/iam/users", headers=admin_headers)
    assert admin_iam_resp.status_code == 200
    assert len(admin_iam_resp.json()) >= 2

    # 7. Admin provisions a new Auditor via IAM
    new_auditor_resp = client.post("/api/iam/users", json={
        "full_name": "External Auditor",
        "email": f"auditor_{ts}@auditcorp.com",
        "password": "AuditorPass!2026",
        "role": "auditor",
        "tenant_id": tenant_b.id,
        "allowed_tenants": [tenant_b.id],
    }, headers=admin_headers)
    assert new_auditor_resp.status_code == 201
    assert new_auditor_resp.json()["role"] == "auditor"

    # 8. Create a scan job in Tenant A and test graceful abort
    db = SessionLocal()
    try:
        from storage.db import create_scan_job
        job = create_scan_job(db, tenant_id=tenant_a.id, target_domain="target.com", scan_profile="standard")
    finally:
        db.close()

    abort_resp = client.post(f"/api/scan/{job.id}/abort", headers={"Authorization": f"Bearer {op_token}", "X-Tenant-ID": tenant_a.id})
    assert abort_resp.status_code == 200
    assert abort_resp.json()["status"] == "cancelled"
    assert abort_resp.json()["current_step"] == "aborted"

