import os
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from core.scope import check_scope_authorization, normalize_domain
from core.auth import (
    hash_password,
    verify_password,
    create_access_token,
    sanitize_input,
    validate_email_format,
    DUMMY_TIMING_HASH,
)
from core.security_limiter import (
    check_rate_limit,
    record_failed_login,
    clear_failed_logins,
)
from storage.db import (
    get_db,
    create_tenant,
    get_tenant,
    list_tenants,
    add_authorized_scope,
    list_authorized_scopes,
    create_scan_job,
    get_scan_job,
    update_scan_job,
    list_scan_jobs,
    get_findings_for_job,
    get_ai_report_for_job,
    get_tenant_dashboard,
    get_investigation_graph,
    expand_graph_node,
    find_entity_path,
    get_evidence_by_id,
    get_evidence_records_batch,
    create_user,
    get_user_by_email,
    get_user_by_id,
    get_tenant_integrations,
    get_tenant_integration,
    upsert_tenant_integration,
    is_system_initialized,
    complete_initial_setup,
    list_iam_users,
    update_iam_user,
)
from storage.models import Entity, Evidence, EntityRelationship, User, TenantIntegration
from api.dependencies import (
    get_current_tenant_id,
    validate_and_authorize_target,
    get_current_user,
    require_system_admin,
)

router = APIRouter()


# ---------------------------------------------------------
# Request / Response Schemas
# ---------------------------------------------------------

class TenantCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=255, json_schema_extra={"example": "Red Team Ops Corp"})


class TenantResponse(BaseModel):
    id: str
    name: str
    created_at: datetime


class SetupStatusResponse(BaseModel):
    initialized: bool


class SetupInitializeRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100, json_schema_extra={"example": "Security Administrator"})
    email: str = Field(..., min_length=5, max_length=255, json_schema_extra={"example": "admin@enterprise.local"})
    password: str = Field(..., min_length=8, max_length=128, json_schema_extra={"example": "MasterAdminPass!2026"})
    organization_name: Optional[str] = Field(None, max_length=100, json_schema_extra={"example": "Primary Security Command"})


class IamUserResponse(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    role: str
    tenant_id: str
    allowed_tenants: List[str] = []
    is_active: bool
    created_at: datetime
    created_by: Optional[str] = None


class IamUserCreateRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100)
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(default="operator", description="system_admin | operator | auditor")
    tenant_id: str = Field(..., description="Primary tenant organization ID")
    allowed_tenants: Optional[List[str]] = Field(None, description="List of permitted tenant IDs or ['*'] for global admin")


class IamUserUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    allowed_tenants: Optional[List[str]] = None
    is_active: Optional[bool] = None
    tenant_id: Optional[str] = None


class IamUserResetPasswordRequest(BaseModel):
    new_password: str = Field(..., min_length=8, max_length=128)


class RegisterRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100, json_schema_extra={"example": "Marcus Vance"})
    email: str = Field(..., min_length=5, max_length=255, json_schema_extra={"example": "operator@enterprise.com"})
    password: str = Field(..., min_length=8, max_length=128, json_schema_extra={"example": "SecureP@ssw0rd!"})
    organization_name: Optional[str] = Field(None, max_length=100, json_schema_extra={"example": "Cyber Defense Group"})


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=255, json_schema_extra={"example": "operator@enterprise.com"})
    password: str = Field(..., min_length=1, max_length=128)


class UserProfileResponse(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    role: str
    tenant_id: str
    allowed_tenants: List[str] = []


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    user: UserProfileResponse
    tenant: TenantResponse


class ScopeCreateRequest(BaseModel):
    domain: str = Field(..., json_schema_extra={"example": "example.com"})
    authorization_type: str = Field(default="self_attested", json_schema_extra={"example": "engagement_letter"})
    authorized_by: Optional[str] = Field(None, json_schema_extra={"example": "john.doe@target.com"})
    expires_at: Optional[datetime] = None


class ScopeResponse(BaseModel):
    id: str
    tenant_id: str
    domain: str
    authorization_type: str
    authorized_by: Optional[str]
    created_at: datetime


class ScanTriggerRequest(BaseModel):
    domain: str = Field(..., json_schema_extra={"example": "example.com"})
    scan_profile: str = Field(default="standard", description="Scan Depth Profile: fast | standard | deep", json_schema_extra={"example": "deep"})
    scan_mode: str = Field(default="full", description="Modular Scan Mode: full | vm_audit | infra_vuln | people_only | fast_recon", json_schema_extra={"example": "vm_audit"})
    enabled_stages: Optional[List[str]] = Field(None, description="Optional custom list of stages to execute (e.g. ['4.ports', '7.cve_lookup'])")
    org_name: Optional[str] = Field(None, description="Optional target organization name (e.g. 'Example Corp')")
    ceo_name: Optional[str] = Field(None, description="Optional CEO / executive / key worker name to focus OSINT on")
    additional_keywords: Optional[str] = Field(None, description="Optional additional keywords or seed terms")



class ScanJobResponse(BaseModel):
    id: str
    tenant_id: str
    target_domain: str
    scan_profile: str = "standard"
    status: str
    current_step: str
    error_message: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None


class FindingResponse(BaseModel):
    id: str
    scan_job_id: str
    tenant_id: str
    type: str
    data: Dict[str, Any]
    severity: str
    source_tool: str
    created_at: datetime


class AIReportResponse(BaseModel):
    id: str
    scan_job_id: str
    tenant_id: str
    prioritized_findings: List[Dict[str, Any]]
    recommendations: Optional[str]
    report_text: str
    created_at: datetime


class NodeSchema(BaseModel):
    id: str
    canonical_id: str
    type: str
    label: str
    properties: Dict[str, Any] = {}
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class EdgeSchema(BaseModel):
    id: str
    source: str
    target: str
    type: str
    confidence: float
    status: str
    supporting_evidence_ids: List[str] = []
    contradicting_evidence_ids: List[str] = []
    metadata: Dict[str, Any] = {}


class GraphResponse(BaseModel):
    scan_job_id: str
    nodes_count: int
    edges_count: int
    nodes: List[NodeSchema]
    edges: List[EdgeSchema]


class EvidenceResponse(BaseModel):
    id: str
    scan_job_id: str
    tenant_id: str
    source: str
    source_url: Optional[str] = None
    source_type: str
    collector: str
    collector_version: str
    observed_at: datetime
    collected_at: datetime
    raw_reference: Dict[str, Any]
    extracted_claim: str
    reliability: float
    hash: Optional[str] = None


# ---------------------------------------------------------
# Initial Installation & Setup Endpoints
# ---------------------------------------------------------

@router.get("/setup/status", response_model=SetupStatusResponse, tags=["Initial Setup"])
def endpoint_setup_status(db: Session = Depends(get_db)):
    """Checks whether initial administrator setup has been completed."""
    return SetupStatusResponse(initialized=is_system_initialized(db))


@router.post("/setup/initialize", response_model=AuthResponse, status_code=status.HTTP_201_CREATED, tags=["Initial Setup"])
def endpoint_setup_initialize(payload: SetupInitializeRequest, db: Session = Depends(get_db)):
    """Initializes the Root Security Administrator account on first web launch."""
    if is_system_initialized(db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Initial setup has already been completed. Further public root creation is locked.",
        )

    clean_name = sanitize_input(payload.full_name, 100)
    if len(clean_name) < 2:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Full name must be at least 2 characters.")

    try:
        clean_email = validate_email_format(payload.email)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    if len(payload.password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Master password must be at least 8 characters.")

    hashed_pw = hash_password(payload.password)
    admin_user, tenant = complete_initial_setup(
        db=db,
        email=clean_email,
        password_hash=hashed_pw,
        full_name=clean_name,
        org_name=payload.organization_name or f"{clean_name}'s Org",
    )

    token = create_access_token(
        user_id=admin_user.id,
        tenant_id=tenant.id,
        email=admin_user.email,
        role=admin_user.role,
    )

    return AuthResponse(
        access_token=token,
        token_type="Bearer",
        user=UserProfileResponse(
            id=admin_user.id,
            email=admin_user.email,
            full_name=admin_user.full_name,
            role=admin_user.role,
            tenant_id=tenant.id,
            allowed_tenants=admin_user.allowed_tenants if isinstance(admin_user.allowed_tenants, list) else ["*"],
        ),
        tenant=TenantResponse(
            id=tenant.id,
            name=tenant.name,
            created_at=tenant.created_at,
        ),
    )


# ---------------------------------------------------------
# Authentication & IAM Endpoints
# ---------------------------------------------------------

@router.post("/auth/register", tags=["Authentication"])
def endpoint_register(payload: RegisterRequest, db: Session = Depends(get_db)):
    """Public registration is disabled. Accounts must be provisioned by a System Administrator."""
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Public registration is disabled on this enterprise instance. Please contact your system administrator to provision an account.",
    )


@router.post("/auth/login", response_model=AuthResponse, tags=["Authentication"])
def endpoint_login(payload: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate with work email and password with brute-force defense and timing attack protection."""
    try:
        clean_email = validate_email_format(payload.email)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 1. Anti-Brute Force / Rate Limit Check
    is_limited, retry_after = check_rate_limit(clean_email)
    if is_limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Access temporarily restricted. Retry in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )

    user = get_user_by_email(db, clean_email)
    # 2. Timing Attack Mitigation: Equalize latency for non-existent users
    if not user or not user.password_hash:
        record_failed_login(clean_email)
        verify_password(payload.password, DUMMY_TIMING_HASH)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Constant-Time Password Verification
    if not verify_password(payload.password, user.password_hash):
        record_failed_login(clean_email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. Account Status Gate
    if not user.is_active:
        record_failed_login(clean_email)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operator account has been deactivated. Please contact your security administrator.",
        )

    # Clear failed attempts on successful login
    clear_failed_logins(clean_email)

    tenant = get_tenant(db, user.tenant_id)
    if not tenant:
        tenant = create_tenant(db, name=f"{user.full_name or 'Operator'}'s Org")
        user.tenant_id = tenant.id
        db.commit()

    token = create_access_token(user_id=user.id, tenant_id=tenant.id, email=user.email, role=user.role)

    allowed = user.allowed_tenants if isinstance(user.allowed_tenants, list) else (["*"] if user.role == "system_admin" else [user.tenant_id])

    return AuthResponse(
        access_token=token,
        token_type="Bearer",
        user=UserProfileResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            tenant_id=tenant.id,
            allowed_tenants=allowed,
        ),
        tenant=TenantResponse(
            id=tenant.id,
            name=tenant.name,
            created_at=tenant.created_at,
        ),
    )


@router.get("/auth/me", tags=["Authentication"])
def endpoint_me(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve profile and tenant details of the currently authenticated operator."""
    tenant = get_tenant(db, current_user.tenant_id)
    allowed = current_user.allowed_tenants if isinstance(current_user.allowed_tenants, list) else (["*"] if current_user.role == "system_admin" else [current_user.tenant_id])
    return {
        "user": {
            "id": current_user.id,
            "email": current_user.email,
            "full_name": current_user.full_name,
            "role": current_user.role,
            "tenant_id": current_user.tenant_id,
            "allowed_tenants": allowed,
        },
        "tenant": {
            "id": tenant.id if tenant else current_user.tenant_id,
            "name": tenant.name if tenant else "Default Organization",
        },
    }


@router.post("/auth/switch-tenant/{tenant_id}", tags=["Authentication"])
def endpoint_switch_tenant(
    tenant_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Switch the operator's active organization workspace and persist to user profile."""
    # Verify permission
    allowed = current_user.allowed_tenants if isinstance(current_user.allowed_tenants, list) else [current_user.tenant_id]
    if current_user.role != "system_admin" and "*" not in allowed and tenant_id not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied: You do not have permissions for this organization workspace.",
        )

    tenant = get_tenant(db, tenant_id)
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant organization not found.")

    current_user.tenant_id = tenant.id
    db.commit()

    token = create_access_token(user_id=current_user.id, tenant_id=tenant.id, email=current_user.email, role=current_user.role)

    return {
        "status": "success",
        "access_token": token,
        "tenant": {
            "id": tenant.id,
            "name": tenant.name,
        },
    }


# ---------------------------------------------------------
# Enterprise IAM & Operator Access Control Endpoints
# ---------------------------------------------------------

@router.get("/iam/users", response_model=List[IamUserResponse], tags=["IAM & Access Control"])
def endpoint_iam_list_users(
    admin: User = Depends(require_system_admin),
    db: Session = Depends(get_db),
):
    """List all system users, roles, and tenant assignments (System Admins only)."""
    users = list_iam_users(db)
    return [
        IamUserResponse(
            id=u.id,
            email=u.email,
            full_name=u.full_name,
            role=u.role,
            tenant_id=u.tenant_id,
            allowed_tenants=u.allowed_tenants if isinstance(u.allowed_tenants, list) else [u.tenant_id],
            is_active=u.is_active,
            created_at=u.created_at,
            created_by=u.created_by,
        )
        for u in users
    ]


@router.post("/iam/users", response_model=IamUserResponse, status_code=status.HTTP_201_CREATED, tags=["IAM & Access Control"])
def endpoint_iam_create_user(
    payload: IamUserCreateRequest,
    admin: User = Depends(require_system_admin),
    db: Session = Depends(get_db),
):
    """Provision a new operator or auditor with role and tenant access (System Admins only)."""
    clean_name = sanitize_input(payload.full_name, 100)
    try:
        clean_email = validate_email_format(payload.email)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    if len(payload.password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be at least 8 characters.")

    existing = get_user_by_email(db, clean_email)
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="A user with this email already exists.")

    tenant = get_tenant(db, payload.tenant_id)
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Primary organization tenant '{payload.tenant_id}' not found.")

    hashed_pw = hash_password(payload.password)
    user = create_user(
        db=db,
        email=clean_email,
        password_hash=hashed_pw,
        tenant_id=tenant.id,
        full_name=clean_name,
        role=payload.role,
        allowed_tenants=payload.allowed_tenants or [tenant.id],
        created_by=admin.email,
    )

    return IamUserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        tenant_id=user.tenant_id,
        allowed_tenants=user.allowed_tenants if isinstance(user.allowed_tenants, list) else [user.tenant_id],
        is_active=user.is_active,
        created_at=user.created_at,
        created_by=user.created_by,
    )


@router.put("/iam/users/{user_id}", response_model=IamUserResponse, tags=["IAM & Access Control"])
def endpoint_iam_update_user(
    user_id: str,
    payload: IamUserUpdateRequest,
    admin: User = Depends(require_system_admin),
    db: Session = Depends(get_db),
):
    """Update user role, active status, or tenant access (System Admins only)."""
    target = get_user_by_id(db, user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    # Anti-Lockout Rule 1: Self-demotion guard
    if user_id == admin.id:
        if payload.role is not None and payload.role != "system_admin":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Self-demotion blocked: You cannot revoke your own System Administrator privileges.",
            )
        if payload.is_active is False:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot deactivate your own active System Administrator account.",
            )

    # Anti-Lockout Rule 2: Sole System Administrator protection
    if target.role == "system_admin":
        is_changing_role = payload.role is not None and payload.role != "system_admin"
        is_deactivating = payload.is_active is False
        if is_changing_role or is_deactivating:
            active_admin_count = db.query(User).filter(User.role == "system_admin", User.is_active == True).count()
            if active_admin_count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Anti-lockout protection: Cannot demote or deactivate the only active System Administrator account. Promote another user first.",
                )

    user = update_iam_user(
        db=db,
        user_id=user_id,
        full_name=payload.full_name,
        role=payload.role,
        allowed_tenants=payload.allowed_tenants,
        is_active=payload.is_active,
        tenant_id=payload.tenant_id,
    )
    return IamUserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        tenant_id=user.tenant_id,
        allowed_tenants=user.allowed_tenants if isinstance(user.allowed_tenants, list) else [user.tenant_id],
        is_active=user.is_active,
        created_at=user.created_at,
        created_by=user.created_by,
    )


@router.delete("/iam/users/{user_id}", tags=["IAM & Access Control"])
def endpoint_iam_deactivate_user(
    user_id: str,
    admin: User = Depends(require_system_admin),
    db: Session = Depends(get_db),
):
    """Suspend/Deactivate a user account (System Admins only)."""
    if user_id == admin.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot deactivate the currently active administrator account.")
    user = update_iam_user(db=db, user_id=user_id, is_active=False)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return {"status": "success", "message": f"User '{user.email}' has been deactivated."}


@router.post("/iam/users/{user_id}/reset-password", tags=["IAM & Access Control"])
def endpoint_iam_reset_password(
    user_id: str,
    payload: IamUserResetPasswordRequest,
    admin: User = Depends(require_system_admin),
    db: Session = Depends(get_db),
):
    """Reset an operator's password (System Admins only)."""
    if len(payload.new_password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be at least 8 characters.")
    hashed_pw = hash_password(payload.new_password)
    user = update_iam_user(db=db, user_id=user_id, password_hash=hashed_pw)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return {"status": "success", "message": f"Password reset for '{user.email}'."}


# ---------------------------------------------------------
# Tenant Endpoints
# ---------------------------------------------------------

@router.post("/tenants", response_model=TenantResponse, status_code=status.HTTP_201_CREATED, tags=["Tenants"])
def endpoint_create_tenant(
    payload: TenantCreateRequest,
    current_user: User = Depends(require_system_admin),
    db: Session = Depends(get_db),
):
    """Create a new tenant organization (System Administrators only)."""
    tenant = create_tenant(db, name=payload.name)
    return tenant


@router.get("/tenants", response_model=List[TenantResponse], tags=["Tenants"])
def endpoint_list_tenants(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List authorized organization tenants for the authenticated operator."""
    all_tenants = list_tenants(db)
    if current_user.role == "system_admin":
        return all_tenants

    allowed = current_user.allowed_tenants if isinstance(current_user.allowed_tenants, list) else [current_user.tenant_id]
    if "*" in allowed:
        return all_tenants

    return [t for t in all_tenants if t.id in allowed]


@router.post("/scopes", response_model=ScopeResponse, status_code=status.HTTP_201_CREATED, tags=["Scopes"])
def endpoint_register_scope(
    payload: ScopeCreateRequest,
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """Register an authorized target domain in scope for the tenant."""
    normalized = normalize_domain(payload.domain)
    scope = add_authorized_scope(
        db=db,
        tenant_id=tenant_id,
        domain=normalized,
        authorization_type=payload.authorization_type,
        authorized_by=payload.authorized_by,
        expires_at=payload.expires_at,
    )
    return scope


@router.get("/scopes", response_model=List[ScopeResponse], tags=["Scopes"])
def endpoint_list_scopes(
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """List all authorized scopes for the current tenant."""
    return list_authorized_scopes(db, tenant_id=tenant_id)


@router.post("/scan", response_model=ScanJobResponse, status_code=status.HTTP_202_ACCEPTED, tags=["Scans"])
def endpoint_trigger_scan(
    payload: ScanTriggerRequest,
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """
    Trigger a reconnaissance & attack-surface scan for an authorized target domain.
    Authorization gate (core.scope) verifies target before job creation.
    """
    normalized_domain = validate_and_authorize_target(payload.domain, tenant_id, db)
    scan_params = {
        "org_name": payload.org_name.strip() if payload.org_name else None,
        "ceo_name": payload.ceo_name.strip() if payload.ceo_name else None,
        "additional_keywords": payload.additional_keywords.strip() if payload.additional_keywords else None,
        "scan_mode": payload.scan_mode or "full",
        "enabled_stages": payload.enabled_stages,
    }
    job = create_scan_job(
        db=db,
        tenant_id=tenant_id,
        target_domain=normalized_domain,
        scan_profile=payload.scan_profile,
        scan_params=scan_params,
    )
    return job


@router.get("/scans", response_model=List[ScanJobResponse], tags=["Scans"])
def endpoint_list_scans(
    limit: int = Query(100, ge=1, le=500),
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """List all reconnaissance scan jobs performed by the current tenant."""
    return list_scan_jobs(db=db, tenant_id=tenant_id, limit=limit)


@router.get("/scan/{job_id}", response_model=ScanJobResponse, tags=["Scans"])
def endpoint_get_scan_status(
    job_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """Get the current progress status and step of a scan job."""
    job = get_scan_job(db=db, tenant_id=tenant_id, job_id=job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")
    return job


@router.post("/scan/{job_id}/abort", response_model=ScanJobResponse, tags=["Scans"])
def endpoint_abort_scan(
    job_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """Gracefully abort a pending or running reconnaissance scan job."""
    job = get_scan_job(db=db, tenant_id=tenant_id, job_id=job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")

    if job.status in ("complete", "failed", "cancelled"):
        return job

    updated_job = update_scan_job(
        db=db,
        tenant_id=tenant_id,
        job_id=job_id,
        status="cancelled",
        current_step="aborted",
        completed=True,
        error_message="Scan execution was gracefully aborted by operator.",
    )
    return updated_job


@router.get("/scan/{job_id}/findings", response_model=List[FindingResponse], tags=["Findings"])
def endpoint_get_scan_findings(
    job_id: str,
    finding_type: Optional[str] = Query(None, description="Filter by type (subdomain, ip, port, vuln, person)"),
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """Retrieve raw or categorized findings for a specific scan job."""
    job = get_scan_job(db=db, tenant_id=tenant_id, job_id=job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")
    
    findings = get_findings_for_job(db=db, tenant_id=tenant_id, scan_job_id=job_id, finding_type=finding_type)
    return findings


@router.get("/scan/{job_id}/graph", response_model=GraphResponse, tags=["Intelligence Graph"])
def endpoint_get_scan_graph(
    job_id: str,
    entity_types: Optional[List[str]] = Query(None, description="Filter nodes by entity type"),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0, description="Minimum confidence threshold"),
    limit: int = Query(300, ge=1, le=1000, description="Max entities to return"),
    lens: str = Query("all", description="Graph lens: all, executive, attack_surface, or composite"),
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """
    Retrieve the normalized Entity Intelligence Graph (nodes & edges) for an investigation.
    Filters by entity types and lens mode ('executive', 'attack_surface', or 'composite').
    """
    job = get_scan_job(db=db, tenant_id=tenant_id, job_id=job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")

    graph_data = get_investigation_graph(
        db=db,
        tenant_id=tenant_id,
        scan_job_id=job_id,
        entity_types=entity_types,
        min_confidence=min_confidence,
        limit=limit,
        lens=lens,
    )
    return graph_data


@router.get("/scan/{job_id}/graph/expand", tags=["Intelligence Graph"])
def endpoint_expand_graph_node(
    job_id: str,
    entity_id: str = Query(..., description="Target node ID to expand"),
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """Dynamically expand a specific entity node to retrieve its 1st-degree connected graph neighborhood."""
    job = get_scan_job(db=db, tenant_id=tenant_id, job_id=job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")

    return expand_graph_node(db=db, tenant_id=tenant_id, scan_job_id=job_id, entity_id=entity_id)


@router.get("/scan/{job_id}/graph/path", tags=["Intelligence Graph"])
def endpoint_find_graph_path(
    job_id: str,
    source_id: str = Query(..., description="Source entity node ID"),
    target_id: str = Query(..., description="Target entity node ID"),
    max_depth: int = Query(default=5, ge=1, le=10, description="Maximum traversal depth"),
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """
    Finds the shortest evidence-backed traversal path connecting two entities in the investigation graph.
    Returns the sequential chain of nodes and edges with confidence scores and evidence linkages.
    """
    job = get_scan_job(db=db, tenant_id=tenant_id, job_id=job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")

    return find_entity_path(
        db=db,
        tenant_id=tenant_id,
        scan_job_id=job_id,
        source_entity_id=source_id,
        target_entity_id=target_id,
        max_depth=max_depth,
    )



@router.get("/scan/{job_id}/evidence/{evidence_id}", response_model=EvidenceResponse, tags=["Evidence Ledger"])
def endpoint_get_evidence(
    job_id: str,
    evidence_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """Retrieve immutable evidence details and verification claims from the Evidence Ledger."""
    job = get_scan_job(db=db, tenant_id=tenant_id, job_id=job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")

    evidence = get_evidence_by_id(db=db, tenant_id=tenant_id, scan_job_id=job_id, evidence_id=evidence_id)
    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence record not found")
    return evidence


@router.get("/scan/{job_id}/exposures", tags=["Exposures"])
def endpoint_get_scan_exposures(
    job_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """Retrieve cloud storage resources and breach exposure signals."""
    job = get_scan_job(db=db, tenant_id=tenant_id, job_id=job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")

    entities = (
        db.query(Entity)
        .filter(
            Entity.tenant_id == tenant_id,
            Entity.scan_job_id == job_id,
            Entity.type.in_(["cloud_resource", "breach"]),
        )
        .all()
    )
    return [
        {
            "id": e.id,
            "type": e.type,
            "label": e.label,
            "properties": e.properties,
            "first_seen": e.first_seen.isoformat() if e.first_seen else None,
        }
        for e in entities
    ]


@router.get("/scan/{job_id}/documents", tags=["Documents"])
def endpoint_get_scan_documents(
    job_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """Retrieve discovered document entities and extracted mentions."""
    job = get_scan_job(db=db, tenant_id=tenant_id, job_id=job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")

    docs = (
        db.query(Entity)
        .filter(
            Entity.tenant_id == tenant_id,
            Entity.scan_job_id == job_id,
            Entity.type == "document",
        )
        .all()
    )
    return [
        {
            "id": d.id,
            "canonical_id": d.canonical_id,
            "label": d.label,
            "properties": d.properties,
            "first_seen": d.first_seen.isoformat() if d.first_seen else None,
        }
        for d in docs
    ]


@router.get("/scan/{job_id}/report", response_model=AIReportResponse, tags=["AI Reports"])
def endpoint_get_scan_report(
    job_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """Retrieve the AI-generated triage and executive report for a scan job."""
    job = get_scan_job(db=db, tenant_id=tenant_id, job_id=job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")

    report = get_ai_report_for_job(db=db, tenant_id=tenant_id, scan_job_id=job_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AI report is not yet generated or job is still processing",
        )
    return report


@router.get("/dashboard", tags=["Dashboard"])
def endpoint_get_dashboard(
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """Get the tenant-scoped dashboard metrics, severity breakdown, and recent activity."""
    return get_tenant_dashboard(db=db, tenant_id=tenant_id)


@router.get("/system/settings", tags=["System Settings"])
def endpoint_get_system_settings():
    """Returns platform configuration, AI provider status, search engine status, and tools telemetry."""
    import shutil
    from core.config import settings

    def mask_key(k: Optional[str]) -> Optional[str]:
        if not k:
            return None
        if len(k) <= 8:
            return "****"
        return f"{k[:4]}...{k[-4:]}"

    tools = {
        "nmap": bool(shutil.which(settings.NMAP_BIN)),
        "masscan": bool(shutil.which(settings.MASSCAN_BIN)),
        "subfinder": bool(shutil.which(settings.SUBFINDER_BIN)),
        "httpx": bool(shutil.which(settings.HTTPX_BIN)),
        "nuclei": bool(shutil.which(settings.NUCLEI_BIN)),
    }

    return {
        "app_name": settings.APP_NAME,
        "app_version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "debug": settings.DEBUG,
        "allow_all_scopes_dev": settings.ALLOW_ALL_SCOPES_DEV,
        "database_url": "sqlite:///./recon7.db" if "sqlite" in settings.DATABASE_URL else "PostgreSQL",
        "ai": {
            "enabled": settings.AI_ENABLED,
            "model": settings.LITELLM_MODEL,
            "anthropic_configured": bool(settings.ANTHROPIC_API_KEY),
            "anthropic_key_masked": mask_key(settings.ANTHROPIC_API_KEY),
            "openai_configured": bool(settings.OPENAI_API_KEY),
        },
        "search": {
            "serpapi_configured": bool(getattr(settings, "SERPAPI_API_KEY", None)),
            "serpapi_key_masked": mask_key(getattr(settings, "SERPAPI_API_KEY", None)),
            "google_cse_configured": bool(settings.GOOGLE_SEARCH_API_KEY and settings.GOOGLE_SEARCH_ENGINE_ID),
            "google_cse_key_masked": mask_key(settings.GOOGLE_SEARCH_API_KEY),
            "search_cache_ttl_days": getattr(settings, "SEARCH_CACHE_TTL_DAYS", 7),
            "query_budget_per_scan": 6,
        },
        "tools": tools,
    }


# ---------------------------------------------------------
# External API Integrations Endpoints
# ---------------------------------------------------------

class IntegrationSaveRequest(BaseModel):
    provider: str
    config: Dict[str, Any]
    is_enabled: bool = True


@router.get("/integrations", tags=["Integrations"])
def endpoint_get_integrations(
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """Retrieve configured integration statuses and masked credentials for the tenant."""
    from core.config import settings

    tenant_records = {i.provider: i for i in get_tenant_integrations(db, tenant_id=tenant_id)}

    def mask_val(val: Optional[str]) -> Optional[str]:
        if not val:
            return None
        s = str(val).strip()
        if len(s) <= 8:
            return "••••••••"
        return f"{s[:4]}••••••••{s[-4:]}"

    active_env_model = settings.LITELLM_MODEL or "claude-sonnet-4-5-20250929"
    model_options = [
        {"value": "claude-sonnet-4-5-20250929", "label": "Anthropic Claude Sonnet 4.5"},
        {"value": "anthropic/claude-3-7-sonnet-20250219", "label": "Anthropic Claude 3.7 Sonnet"},
        {"value": "anthropic/claude-3-5-sonnet-20241022", "label": "Anthropic Claude 3.5 Sonnet"},
        {"value": "openai/gpt-4o", "label": "OpenAI GPT-4o"},
        {"value": "gemini/gemini-2.0-flash", "label": "Google Gemini 2.0 Flash"},
        {"value": "gemini/gemini-1.5-pro", "label": "Google Gemini 1.5 Pro"},
        {"value": "deepseek/deepseek-chat", "label": "DeepSeek-V3 Chat"},
    ]
    if active_env_model and not any(o["value"] == active_env_model for o in model_options):
        model_options.insert(0, {"value": active_env_model, "label": f"Active (.env): {active_env_model}"})
    model_options.append({"value": "custom", "label": "Custom Model Identifier..."})

    integrations_meta = [
        # --- Active / Production-Ready Integrations ---
        {
            "provider": "github",
            "name": "GitHub Personal Access Token",
            "category": "Threat Intelligence & OSINT",
            "description": "Target organization public repository enumeration, author email extraction, and secret exposure audit. Elevates rate limit to 5,000 req/hr.",
            "fields": [
                {"key": "token", "label": "Personal Access Token (classic / fine-grained)", "type": "password", "required": True, "placeholder": "ghp_..."},
            ],
            "default_configured": bool(os.getenv("GITHUB_TOKEN")),
            "default_config": {
                "token": mask_val(os.getenv("GITHUB_TOKEN")),
            },
        },
        {
            "provider": "google_search",
            "name": "Google Custom Search Engine (CSE)",
            "category": "Search Engines",
            "description": "Used by Recon7 for high-yield company document harvesting, executive name identification, and passive footprinting.",
            "fields": [
                {"key": "api_key", "label": "Google Cloud API Key", "type": "password", "required": True, "placeholder": "AIzaSy..."},
                {"key": "engine_id", "label": "Search Engine ID (CX / Browser ID)", "type": "text", "required": True, "placeholder": "d59224a2fe..."},
            ],
            "default_configured": bool(settings.GOOGLE_SEARCH_API_KEY and settings.GOOGLE_SEARCH_ENGINE_ID),
            "default_config": {
                "api_key": mask_val(settings.GOOGLE_SEARCH_API_KEY),
                "engine_id": settings.GOOGLE_SEARCH_ENGINE_ID or "",
            },
        },
        {
            "provider": "serpapi",
            "name": "SerpAPI Search Engine",
            "category": "Search Engines",
            "description": "High-yield fallback search engine for scraping Google, Bing, and DuckDuckGo without IP rate limits.",
            "fields": [
                {"key": "api_key", "label": "SerpAPI Secret Key", "type": "password", "required": True, "placeholder": "d6d7ec30f..."},
            ],
            "default_configured": bool(getattr(settings, "SERPAPI_API_KEY", None)),
            "default_config": {
                "api_key": mask_val(getattr(settings, "SERPAPI_API_KEY", None)),
            },
        },

        # --- In-Development Integrations ---
        {
            "provider": "shodan",
            "name": "Shodan Threat Intelligence",
            "category": "Threat Intelligence & OSINT",
            "description": "Passive port inspection, internet-wide exposed host banners, and CVE correlation for discovered IP addresses.",
            "fields": [
                {"key": "api_key", "label": "Shodan API Key", "type": "password", "required": True, "placeholder": "shodan_api_key_..."},
            ],
            "default_configured": bool(os.getenv("SHODAN_API_KEY")),
            "default_config": {
                "api_key": mask_val(os.getenv("SHODAN_API_KEY")),
            },
        },
        {
            "provider": "securitytrails",
            "name": "SecurityTrails DNS",
            "category": "Threat Intelligence & OSINT",
            "description": "Historical DNS records, past A/AAAA/MX records, and rapid passive subdomain discovery.",
            "fields": [
                {"key": "api_key", "label": "SecurityTrails API Key", "type": "password", "required": True, "placeholder": "st_key_..."},
            ],
            "default_configured": bool(os.getenv("SECURITYTRAILS_API_KEY")),
            "default_config": {
                "api_key": mask_val(os.getenv("SECURITYTRAILS_API_KEY")),
            },
        },
        {
            "provider": "virustotal",
            "name": "VirusTotal Intelligence",
            "category": "Threat Intelligence & OSINT",
            "description": "Domain threat score, detected malicious communications, and passive DNS telemetry.",
            "fields": [
                {"key": "api_key", "label": "VirusTotal API Key", "type": "password", "required": True, "placeholder": "vt_api_key_..."},
            ],
            "default_configured": bool(os.getenv("VIRUSTOTAL_API_KEY")),
            "default_config": {
                "api_key": mask_val(os.getenv("VIRUSTOTAL_API_KEY")),
            },
        },
        {
            "provider": "hunter",
            "name": "Hunter.io Contact Engine",
            "category": "Threat Intelligence & OSINT",
            "description": "Target domain email syntax discovery (first.last, etc.) and verification of corporate personnel.",
            "fields": [
                {"key": "api_key", "label": "Hunter.io API Key", "type": "password", "required": True, "placeholder": "hunter_key_..."},
            ],
            "default_configured": bool(os.getenv("HUNTER_API_KEY")),
            "default_config": {
                "api_key": mask_val(os.getenv("HUNTER_API_KEY")),
            },
        },
    ]

    result = []
    for meta in integrations_meta:
        prov = meta["provider"]
        record = tenant_records.get(prov)
        is_configured = meta["default_configured"]
        is_enabled = True
        config_display = dict(meta["default_config"])

        if record:
            is_configured = bool(record.config)
            is_enabled = record.is_enabled
            for k, v in (record.config or {}).items():
                if any(sec in k.lower() for sec in ["key", "secret", "token", "password"]):
                    config_display[k] = mask_val(v)
                else:
                    config_display[k] = v

        result.append({
            "provider": prov,
            "name": meta["name"],
            "category": meta["category"],
            "description": meta["description"],
            "fields": meta["fields"],
            "is_configured": is_configured,
            "is_enabled": is_enabled,
            "config": config_display,
            "updated_at": record.updated_at if record else None,
        })

    return result


@router.post("/integrations", tags=["Integrations"])
def endpoint_save_integration(
    payload: IntegrationSaveRequest,
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """Save or update an external API integration for the tenant and refresh active runtime credentials."""
    from core.config import settings

    clean_config = {}
    for k, v in payload.config.items():
        if v and not str(v).startswith("••••") and not "••••••••" in str(v):
            clean_config[k] = str(v).strip()

    record = upsert_tenant_integration(
        db=db,
        tenant_id=tenant_id,
        provider=payload.provider,
        config=clean_config,
        is_enabled=payload.is_enabled,
    )

    if payload.provider == "google_search":
        if "api_key" in clean_config:
            os.environ["GOOGLE_SEARCH_API_KEY"] = clean_config["api_key"]
            settings.GOOGLE_SEARCH_API_KEY = clean_config["api_key"]
        if "engine_id" in clean_config:
            os.environ["GOOGLE_SEARCH_ENGINE_ID"] = clean_config["engine_id"]
            settings.GOOGLE_SEARCH_ENGINE_ID = clean_config["engine_id"]
    elif payload.provider == "serpapi":
        if "api_key" in clean_config:
            os.environ["SERPAPI_API_KEY"] = clean_config["api_key"]
            settings.SERPAPI_API_KEY = clean_config["api_key"]
    elif payload.provider == "ai_gateway":
        if "anthropic_api_key" in clean_config:
            os.environ["ANTHROPIC_API_KEY"] = clean_config["anthropic_api_key"]
            settings.ANTHROPIC_API_KEY = clean_config["anthropic_api_key"]
        if "openai_api_key" in clean_config:
            os.environ["OPENAI_API_KEY"] = clean_config["openai_api_key"]
            settings.OPENAI_API_KEY = clean_config["openai_api_key"]
        if "gemini_api_key" in clean_config:
            os.environ["GEMINI_API_KEY"] = clean_config["gemini_api_key"]
        if "deepseek_api_key" in clean_config:
            os.environ["DEEPSEEK_API_KEY"] = clean_config["deepseek_api_key"]
        if "model" in clean_config:
            os.environ["LITELLM_MODEL"] = clean_config["model"]
            settings.LITELLM_MODEL = clean_config["model"]
    elif payload.provider == "shodan":
        if "api_key" in clean_config:
            os.environ["SHODAN_API_KEY"] = clean_config["api_key"]
    elif payload.provider == "censys":
        if "api_id" in clean_config:
            os.environ["CENSYS_API_ID"] = clean_config["api_id"]
            settings.CENSYS_API_ID = clean_config["api_id"]
        if "api_secret" in clean_config:
            os.environ["CENSYS_API_SECRET"] = clean_config["api_secret"]
            settings.CENSYS_API_SECRET = clean_config["api_secret"]
    elif payload.provider == "securitytrails":
        if "api_key" in clean_config:
            os.environ["SECURITYTRAILS_API_KEY"] = clean_config["api_key"]
    elif payload.provider == "virustotal":
        if "api_key" in clean_config:
            os.environ["VIRUSTOTAL_API_KEY"] = clean_config["api_key"]
    elif payload.provider == "hunter":
        if "api_key" in clean_config:
            os.environ["HUNTER_API_KEY"] = clean_config["api_key"]
    elif payload.provider == "github":
        if "token" in clean_config:
            os.environ["GITHUB_TOKEN"] = clean_config["token"]
            settings.GITHUB_TOKEN = clean_config["token"]

    return {
        "status": "success",
        "provider": payload.provider,
        "message": f"Successfully configured {payload.provider} integration.",
    }


class IntegrationTestRequest(BaseModel):
    provider: str
    config: Dict[str, Any] = {}


@router.post("/integrations/test", tags=["Integrations"])
def endpoint_test_integration(
    payload: IntegrationTestRequest,
    tenant_id: str = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """Test connection credentials against live provider APIs."""
    import httpx
    from core.config import settings

    # Resolve unmasked values from DB if user passed masked string
    cfg = dict(payload.config)
    db_record = get_tenant_integration(db, tenant_id=tenant_id, provider=payload.provider)
    if db_record and db_record.config:
        for k, v in db_record.config.items():
            if k not in cfg or not cfg[k] or "••••" in str(cfg[k]):
                cfg[k] = v

    prov = payload.provider

    try:
        if prov == "censys":
            api_id = (cfg.get("api_id") or getattr(settings, "CENSYS_API_ID", None) or os.getenv("CENSYS_API_ID") or "").strip()
            api_sec = (cfg.get("api_secret") or getattr(settings, "CENSYS_API_SECRET", None) or os.getenv("CENSYS_API_SECRET") or "").strip()
            org_id = (cfg.get("org_id") or getattr(settings, "CENSYS_ORG_ID", None) or os.getenv("CENSYS_ORG_ID") or "").strip()

            if not api_id and not api_sec:
                return {"success": False, "message": "Censys API ID or Personal Access Token (PAT) is required."}

            headers = {"User-Agent": "R7-ReconEngine/1.0"}
            auth = None
            if org_id:
                headers["X-Organization-ID"] = org_id

            # Determine authentication strategy: Check for PAT token
            if api_id.startswith("censys_"):
                headers["Authorization"] = f"Bearer {api_id}"
            elif api_sec.startswith("censys_"):
                headers["Authorization"] = f"Bearer {api_sec}"
            elif api_id and api_sec:
                auth = (api_id, api_sec)
            else:
                token = api_id or api_sec
                headers["Authorization"] = f"Bearer {token}"

            with httpx.Client(timeout=12, auth=auth, headers=headers) as client:
                # 1. Try Certificates Search endpoint
                res = client.get(
                    "https://search.censys.io/api/v2/certificates/search",
                    params={"q": "names: google.com", "per_page": 1},
                )
                if res.status_code == 200:
                    data = res.json()
                    total = data.get("result", {}).get("total", "Active")
                    return {
                        "success": True,
                        "message": "Connected to Censys Search & Platform API successfully.",
                    }

                # 2. Try Platform v3 Hosts endpoint if v2 returned 401 or 404
                if "Authorization" in headers:
                    res_v3 = client.get("https://api.platform.censys.io/v3/global/asset/host/8.8.8.8")
                    if res_v3.status_code == 200:
                        return {
                            "success": True,
                            "message": "Connected to Censys Platform API (v3) successfully.",
                        }

                if res.status_code == 401:
                    return {
                        "success": False,
                        "message": "Censys authentication failed (401 Unauthorized). Please check your Token / API Secret.",
                    }
                elif res.status_code == 429:
                    return {
                        "success": False,
                        "message": "Censys API rate limit reached / quota exhausted (429).",
                    }
                else:
                    return {"success": False, "message": f"Censys API returned HTTP {res.status_code}: {res.text[:120]}"}

        elif prov == "github":
            pat = (cfg.get("token") or getattr(settings, "GITHUB_TOKEN", None) or os.getenv("GITHUB_TOKEN") or "").strip()
            if not pat:
                return {"success": False, "message": "GitHub Personal Access Token is required."}

            headers = {
                "User-Agent": "R7-ReconEngine/1.0",
                "Accept": "application/vnd.github.v3+json",
                "Authorization": f"Bearer {pat}" if (pat.startswith("ghp_") or pat.startswith("github_pat_")) else f"token {pat}",
            }
            with httpx.Client(timeout=10, headers=headers) as client:
                res = client.get("https://api.github.com/user")
                if res.status_code == 200:
                    user_data = res.json()
                    login = user_data.get("login", "Unknown")
                    rem = res.headers.get("x-ratelimit-remaining", "5000")
                    return {
                        "success": True,
                        "message": f"Authenticated as GitHub user '{login}'. Rate limit: {rem}/5000 remaining.",
                    }
                elif res.status_code == 401:
                    return {"success": False, "message": "Invalid GitHub Personal Access Token (401 Unauthorized)."}
                else:
                    return {"success": False, "message": f"GitHub returned HTTP {res.status_code}"}

        elif prov == "serpapi":
            key = (cfg.get("api_key") or getattr(settings, "SERPAPI_API_KEY", None) or "").strip()
            if not key:
                return {"success": False, "message": "SerpAPI Key is required."}
            with httpx.Client(timeout=10) as client:
                res = client.get(f"https://serpapi.com/account?api_key={key}")
                if res.status_code == 200:
                    data = res.json()
                    plan = data.get("plan_name", "Standard")
                    searches_left = data.get("total_searches_left", "Active")
                    return {"success": True, "message": f"SerpAPI active on {plan} plan ({searches_left} searches left)."}
                else:
                    return {"success": False, "message": f"SerpAPI rejected key (HTTP {res.status_code})."}

        elif prov == "google_search":
            key = (cfg.get("api_key") or settings.GOOGLE_SEARCH_API_KEY or "").strip()
            cx = (cfg.get("engine_id") or settings.GOOGLE_SEARCH_ENGINE_ID or "").strip()
            if not key or not cx:
                return {"success": False, "message": "Both Google API Key and Search Engine ID (CX) are required."}
            with httpx.Client(timeout=10) as client:
                res = client.get(f"https://www.googleapis.com/customsearch/v1?key={key}&cx={cx}&q=test&num=1")
                if res.status_code == 200:
                    return {"success": True, "message": "Google Custom Search API connected and responding successfully."}
                elif res.status_code == 403:
                    return {"success": False, "message": "Google Custom Search API quota exhausted or API disabled for key (403)."}
                else:
                    return {"success": False, "message": f"Google CSE returned HTTP {res.status_code}."}

        elif prov == "ai_gateway":
            anthropic_key = (cfg.get("anthropic_api_key") or settings.ANTHROPIC_API_KEY or "").strip()
            openai_key = (cfg.get("openai_api_key") or settings.OPENAI_API_KEY or "").strip()
            model = cfg.get("model") or "claude-sonnet-4-5-20250929"

            if model.startswith("ollama/"):
                return {"success": True, "message": f"Local Ollama model '{model}' configured without external API keys."}

            if "claude" in model or "anthropic" in model:
                if not anthropic_key:
                    return {"success": False, "message": "Anthropic API Key is required for Claude models."}
                headers = {
                    "x-api-key": anthropic_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                }
                with httpx.Client(timeout=10, headers=headers) as client:
                    res = client.post("https://api.anthropic.com/v1/messages", json={
                        "model": "claude-3-5-haiku-20241022",
                        "max_tokens": 1,
                        "messages": [{"role": "user", "content": "ping"}],
                    })
                    if res.status_code == 200:
                        return {"success": True, "message": "Anthropic Claude API connected and verified successfully."}
                    elif res.status_code == 401:
                        return {"success": False, "message": "Anthropic API Key is invalid (401 Unauthorized)."}
                    else:
                        return {"success": False, "message": f"Anthropic returned HTTP {res.status_code}"}

            elif "gpt" in model or "openai" in model:
                if not openai_key:
                    return {"success": False, "message": "OpenAI API Key is required for GPT models."}
                headers = {"Authorization": f"Bearer {openai_key}"}
                with httpx.Client(timeout=10, headers=headers) as client:
                    res = client.get("https://api.openai.com/v1/models")
                    if res.status_code == 200:
                        return {"success": True, "message": "OpenAI API connected and verified successfully."}
                    else:
                        return {"success": False, "message": f"OpenAI returned HTTP {res.status_code}"}

            return {"success": True, "message": f"Model '{model}' configured successfully."}

        else:
            return {"success": True, "message": f"{prov.capitalize()} integration parameters saved."}

    except Exception as e:
        return {"success": False, "message": f"Connection test failed: {str(e)}"}


