import pytest
import time
import base64
import json
from fastapi.testclient import TestClient
from main import app
from core.auth import (
    hash_password,
    verify_password,
    create_access_token,
    verify_access_token,
    DUMMY_TIMING_HASH,
    validate_password_complexity,
)
from core.security_limiter import check_rate_limit, record_failed_login, clear_failed_logins
from storage.db import SessionLocal, create_user, create_tenant


def test_password_complexity_and_weak_dictionary_defense():
    """Verify weak and common passwords are strictly rejected."""
    with pytest.raises(ValueError, match="too common"):
        validate_password_complexity("password123")

    with pytest.raises(ValueError, match="too common"):
        validate_password_complexity("12345678")

    with pytest.raises(ValueError, match="at least 8 characters"):
        validate_password_complexity("short")

    with pytest.raises(ValueError, match="cannot exceed 128"):
        validate_password_complexity("a" * 150)

    # Strong password passes
    validate_password_complexity("TacticalArmorP@ss2026!")


def test_jwt_algorithm_confusion_and_none_attack():
    """Verify tokens with manipulated headers (e.g. alg: none or invalid typ) are rejected."""
    token = create_access_token("usr-1", "ten-1", "admin@org.local", "system_admin")
    parts = token.split(".")
    assert len(parts) == 3

    # Craft 'alg': 'none' attack header
    none_header = {"alg": "none", "typ": "JWT"}
    none_header_b64 = base64.urlsafe_b64encode(json.dumps(none_header).encode()).decode().rstrip("=")
    fake_token = f"{none_header_b64}.{parts[1]}."

    claims = verify_access_token(fake_token)
    assert claims is None, "Vulnerability: Token accepted with alg=none!"


def test_jwt_payload_tampering():
    """Verify modifying claims in JWT invalidates the token."""
    token = create_access_token("usr-1", "ten-1", "user@org.local", "operator")
    parts = token.split(".")

    # Decode and tamper payload
    payload_padding = "=" * (4 - len(parts[1]) % 4 if len(parts[1]) % 4 != 0 else 0)
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + payload_padding).decode())
    payload["role"] = "system_admin"  # Privilege escalation attempt

    tampered_payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    tampered_token = f"{parts[0]}.{tampered_payload_b64}.{parts[2]}"

    assert verify_access_token(tampered_token) is None


def test_brute_force_rate_limiting_defense():
    """Verify repeated failed attempts trigger HTTP 429 Too Many Requests."""
    client = TestClient(app)
    victim_email = f"target_{int(time.time())}@enterprise.local"

    clear_failed_logins(victim_email)

    # 5 failed attempts
    for _ in range(5):
        resp = client.post("/api/auth/login", json={"email": victim_email, "password": "WrongPassword!2026"})
        assert resp.status_code == 401

    # 6th attempt should be rate limited with 429
    limited_resp = client.post("/api/auth/login", json={"email": victim_email, "password": "WrongPassword!2026"})
    assert limited_resp.status_code == 429
    assert "Too many failed login attempts" in limited_resp.json()["detail"]
    assert "Retry-After" in limited_resp.headers

    # Cleanup
    clear_failed_logins(victim_email)


def test_anti_lockout_self_demotion_defense():
    """Verify an admin cannot demote their own account."""
    client = TestClient(app)
    ts = int(time.time())
    db = SessionLocal()
    try:
        tenant = create_tenant(db, name=f"Admin Sec Org {ts}")
        admin = create_user(
            db=db,
            email=f"root_{ts}@adminsec.local",
            password_hash=hash_password("RootAdminSecure!2026"),
            tenant_id=tenant.id,
            role="system_admin",
            allowed_tenants=["*"],
        )
    finally:
        db.close()

    # Login as admin
    login_resp = client.post("/api/auth/login", json={"email": f"root_{ts}@adminsec.local", "password": "RootAdminSecure!2026"})
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Attempt to demote self to auditor
    demote_resp = client.put(f"/api/iam/users/{admin.id}", json={"role": "auditor"}, headers=headers)
    assert demote_resp.status_code == 400
    assert "Self-demotion blocked" in demote_resp.json()["detail"]


def test_password_reset_revokes_active_sessions():
    """Verify resetting user password immediately revokes all prior active tokens across devices."""
    from storage.db import update_iam_user
    client = TestClient(app)
    ts = int(time.time())
    db = SessionLocal()
    try:
        tenant = create_tenant(db, name=f"Session Revoke Org {ts}")
        user = create_user(
            db=db,
            email=f"operator_{ts}@revoke.local",
            password_hash=hash_password("InitialSecurePass!2026"),
            tenant_id=tenant.id,
            role="operator",
        )
        user_id = user.id
        user_email = user.email
    finally:
        db.close()

    # 1. Login with initial password and obtain valid token
    login_resp = client.post("/api/auth/login", json={"email": user_email, "password": "InitialSecurePass!2026"})
    assert login_resp.status_code == 200
    old_token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {old_token}"}

    # Verify token works for /api/auth/me
    me_resp = client.get("/api/auth/me", headers=headers)
    assert me_resp.status_code == 200

    # 2. Simulate password reset (e.g. from CLI or IAM admin reset)
    db = SessionLocal()
    try:
        new_hashed = hash_password("NewChangedPassword!2026")
        update_iam_user(db=db, user_id=user_id, password_hash=new_hashed)
    finally:
        db.close()

    # 3. Old active token must now be rejected immediately with 401 Unauthorized
    revoked_resp = client.get("/api/auth/me", headers=headers)
    assert revoked_resp.status_code == 401
    assert "Session has been revoked" in revoked_resp.json()["detail"]

