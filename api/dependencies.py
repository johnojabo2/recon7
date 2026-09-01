from typing import Optional
from fastapi import Header, HTTPException, Depends, status
from sqlalchemy.orm import Session

from core.config import settings
from core.scope import enforce_scope, normalize_domain, ScopeAuthorizationError, InvalidTargetError
from core.auth import verify_access_token
from storage.db import get_db, get_tenant, create_tenant, get_user_by_id
from storage.models import User


def get_current_user(
    authorization: Optional[str] = Header(None, alias="Authorization", description="Bearer access token"),
    db: Session = Depends(get_db),
) -> User:
    """
    Resolves the authenticated operator from Bearer token.
    Raises 401 Unauthorized if token is missing, invalid, or expired.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    claims = verify_access_token(authorization)
    if not claims or "sub" not in claims:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = get_user_by_id(db, claims["sub"])
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Operator account associated with token was not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Token Version Check (Immediate session invalidation on password reset)
    token_ver = claims.get("token_version")
    user_ver = getattr(user, "token_version", 1) or 1
    if token_ver is not None and token_ver != user_ver:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked due to a password reset. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operator account is disabled.",
        )

    return user


def require_system_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """Requires that the authenticated operator has global system_admin privileges."""
    if current_user.role != "system_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access restricted: System Administrator privileges required.",
        )
    return current_user


def get_current_tenant_id(
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> str:
    """
    Resolves the active tenant ID from X-Tenant-ID header or the user's primary tenant.
    Strictly enforces that non-system_admin users can ONLY access tenants in their allowed_tenants list.
    """
    target_tenant = x_tenant_id or current_user.tenant_id or "dev-default-tenant"

    # Global system administrators can access any organization workspace
    if current_user.role == "system_admin":
        t = get_tenant(db, target_tenant)
        return t.id if t else target_tenant

    # Normal operators & auditors: strictly check allowed_tenants whitelist
    allowed = current_user.allowed_tenants if isinstance(current_user.allowed_tenants, list) else [current_user.tenant_id]
    if "*" not in allowed and target_tenant not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cross-tenant access denied: You do not have permissions for organization tenant '{target_tenant}'.",
        )

    t = get_tenant(db, target_tenant)
    if not t:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization tenant '{target_tenant}' not found.",
        )
    return t.id


def validate_and_authorize_target(
    target: str,
    tenant_id: str,
    db: Session,
) -> str:
    """Validates domain format and strictly enforces scope authorization gate."""
    try:
        return enforce_scope(tenant_id=tenant_id, target_domain=target, db_session=db)
    except InvalidTargetError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ScopeAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
