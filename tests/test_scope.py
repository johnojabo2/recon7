import pytest
from core.scope import normalize_domain, check_scope_authorization, enforce_scope, InvalidTargetError, ScopeAuthorizationError
from core.config import settings
from storage.db import init_db, get_db_session, create_tenant, add_authorized_scope


def test_normalize_domain():
    assert normalize_domain("https://example.com/test?id=1") == "example.com"
    assert normalize_domain("http://sub.target.org:8080/") == "sub.target.org"
    assert normalize_domain("  192.168.1.1:443  ") == "192.168.1.1"
    assert normalize_domain("CORP.INTERNAL.CO.UK") == "corp.internal.co.uk"


def test_extract_root_domain():
    from core.scope import extract_root_domain
    assert extract_root_domain("dev.abc.com") == "abc.com"
    assert extract_root_domain("scanme.nmap.org") == "nmap.org"
    assert extract_root_domain("api.staging.corp.co.uk") == "corp.co.uk"
    assert extract_root_domain("example.com") == "example.com"
    assert extract_root_domain("192.168.1.50") == "192.168.1.50"
    # Multi-part ccTLDs and educational domains
    assert extract_root_domain("www.bsum.edu.ng") == "bsum.edu.ng"
    assert extract_root_domain("fula.edu.ng") == "fula.edu.ng"
    assert extract_root_domain("zoo.fula.edu.ng") == "fula.edu.ng"
    assert extract_root_domain("portal.unilag.edu.ng") == "unilag.edu.ng"
    assert extract_root_domain("admin.notjustevent.com") == "notjustevent.com"


def test_invalid_target_rejection():
    with pytest.raises(InvalidTargetError):
        normalize_domain("invalid domain name with spaces")

    with pytest.raises(InvalidTargetError):
        normalize_domain("; rm -rf / ;")

    with pytest.raises(InvalidTargetError):
        normalize_domain("")


def test_scope_authorization_gate(monkeypatch):
    init_db()
    with get_db_session() as db:
        tenant = create_tenant(db, "Scope Test Tenant")
        add_authorized_scope(db, tenant.id, "allowed-target.com")

        # In non-dev mode (strict enforcement)
        monkeypatch.setattr(settings, "ALLOW_ALL_SCOPES_DEV", False)

        # Allowed domain should pass
        auth, msg = check_scope_authorization(tenant.id, "allowed-target.com", db)
        assert auth is True

        # Unregistered domain should be rejected
        auth, msg = check_scope_authorization(tenant.id, "unauthorized-target.com", db)
        assert auth is False

        with pytest.raises(ScopeAuthorizationError):
            enforce_scope(tenant.id, "unauthorized-target.com", db)
