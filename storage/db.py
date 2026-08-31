import logging
from collections import deque
from contextlib import contextmanager
from typing import Generator, List, Optional, Dict, Any, Tuple, Set
from datetime import datetime, timezone

from sqlalchemy import create_engine, func, desc, text, event
from sqlalchemy.orm import sessionmaker, Session

from core.config import settings
from storage.models import (
    Base,
    Tenant,
    User,
    AuthorizedScope,
    ScanJob,
    Finding,
    AIReport,
    Entity,
    Evidence,
    EntityRelationship,
    ObservationRecord,
    SearchCache,
    TenantIntegration,
    SystemConfig,
    utc_now,
)

logger = logging.getLogger(__name__)

# Engine configuration
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    connect_args["timeout"] = 30.0

engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DB_ECHO,
    connect_args=connect_args,
    pool_pre_ping=True,
)

if settings.DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()
        except Exception:
            pass

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, expire_on_commit=False)


def init_db():
    """Initializes schema, applies lightweight column migrations, and seeds default tenant/users."""
    Base.metadata.create_all(bind=engine)
    # Lightweight SQLite column migration for new fields
    migrations = [
        "ALTER TABLE scan_jobs ADD COLUMN scan_profile VARCHAR(50) DEFAULT 'standard'",
        "ALTER TABLE scan_jobs ADD COLUMN target_type VARCHAR(50) DEFAULT 'domain'",
        "ALTER TABLE scan_jobs ADD COLUMN normalized_target VARCHAR(255)",
        "ALTER TABLE scan_jobs ADD COLUMN requester VARCHAR(255)",
        "ALTER TABLE scan_jobs ADD COLUMN sensors_used JSON",
        "ALTER TABLE scan_jobs ADD COLUMN scan_params JSON",
        "ALTER TABLE findings ADD COLUMN confidence FLOAT DEFAULT 1.0",
        "ALTER TABLE findings ADD COLUMN evidence_ids JSON",
        "ALTER TABLE users ADD COLUMN full_name VARCHAR(255)",
        "ALTER TABLE users ADD COLUMN password_hash VARCHAR(255)",
        "ALTER TABLE users ADD COLUMN allowed_tenants JSON DEFAULT '[]'",
        "ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT 1",
        "ALTER TABLE users ADD COLUMN created_by VARCHAR(255)",
    ]
    with engine.connect() as conn:
        for stmt in migrations:
            try:
                conn.execute(text(stmt))
                conn.commit()
            except Exception:
                pass

    # Ensure Default System Tenants exist
    try:
        with SessionLocal() as db:
            default_tenant = db.query(Tenant).filter(Tenant.id == "default-tenant").first()
            if not default_tenant:
                default_tenant = Tenant(
                    id="default-tenant",
                    name="Default Enterprise Organization",
                )
                db.add(default_tenant)
                db.commit()

            dev_tenant = db.query(Tenant).filter(Tenant.id == "dev-default-tenant").first()
            if not dev_tenant:
                dev_tenant = Tenant(
                    id="dev-default-tenant",
                    name="Development Organization",
                )
                db.add(dev_tenant)
                db.commit()

            # Backfill any legacy users with missing allowed_tenants
            for u in db.query(User).all():
                if u.role == "admin":
                    u.role = "system_admin"
                if not u.allowed_tenants or u.allowed_tenants == []:
                    u.allowed_tenants = ["*"] if u.role == "system_admin" else [u.tenant_id]
            db.commit()
    except Exception as e:
        logger.warning(f"Tenant initialization notice: {e}")

    logger.info("Database tables and schema initialized successfully.")


# Run DB schema init on module load
try:
    init_db()
except Exception as e:
    logger.warning(f"init_db invocation notice: {e}")


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Context manager for scoped database sessions."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db():
    """FastAPI dependency for database session."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


# ---------------------------------------------------------
# Tenant & User Enforced Data Access Layer (DAL)
# ---------------------------------------------------------

def create_tenant(db: Session, name: str) -> Tenant:
    tenant = Tenant(name=name)
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


def is_system_initialized(db: Session) -> bool:
    """Checks if the system has completed initial administrator setup."""
    cfg = db.query(SystemConfig).filter(SystemConfig.key == "setup_completed").first()
    if cfg and isinstance(cfg.value, dict) and cfg.value.get("completed"):
        return True
    admin_exists = db.query(User).filter(User.role == "system_admin", User.is_active == True).first()
    return admin_exists is not None


def complete_initial_setup(
    db: Session,
    email: str,
    password_hash: str,
    full_name: str,
    org_name: str,
) -> Tuple[User, Tenant]:
    """Provisions the initial root system administrator and primary tenant."""
    clean_email = email.strip().lower()
    clean_name = full_name.strip()
    clean_org = org_name.strip() if org_name else f"{clean_name}'s Org"

    # 1. Create primary organization
    tenant = create_tenant(db, name=clean_org)

    # 2. Create Root System Admin with global permissions
    admin_user = User(
        email=clean_email,
        password_hash=password_hash,
        tenant_id=tenant.id,
        full_name=clean_name,
        role="system_admin",
        allowed_tenants=["*"],
        is_active=True,
        created_by="initial_setup",
    )
    db.add(admin_user)

    # 3. Mark system as initialized in SystemConfig
    cfg = db.query(SystemConfig).filter(SystemConfig.key == "setup_completed").first()
    if not cfg:
        cfg = SystemConfig(
            key="setup_completed",
            value={"completed": True, "initialized_at": utc_now().isoformat(), "admin_email": clean_email},
        )
        db.add(cfg)
    else:
        cfg.value = {"completed": True, "initialized_at": utc_now().isoformat(), "admin_email": clean_email}

    db.commit()
    db.refresh(admin_user)
    db.refresh(tenant)
    return admin_user, tenant


def create_user(
    db: Session,
    email: str,
    password_hash: str,
    tenant_id: str,
    full_name: Optional[str] = None,
    role: str = "operator",
    allowed_tenants: Optional[List[str]] = None,
    created_by: Optional[str] = None,
) -> User:
    clean_email = email.strip().lower()
    if allowed_tenants is None:
        allowed_tenants = ["*"] if role == "system_admin" else [tenant_id]
    elif role == "system_admin" and "*" not in allowed_tenants:
        allowed_tenants = ["*"]

    user = User(
        email=clean_email,
        password_hash=password_hash,
        tenant_id=tenant_id,
        full_name=full_name.strip() if full_name else None,
        role=role,
        allowed_tenants=allowed_tenants,
        is_active=True,
        created_by=created_by,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def list_iam_users(db: Session) -> List[User]:
    return db.query(User).order_by(desc(User.created_at)).all()


def update_iam_user(
    db: Session,
    user_id: str,
    full_name: Optional[str] = None,
    role: Optional[str] = None,
    allowed_tenants: Optional[List[str]] = None,
    is_active: Optional[bool] = None,
    password_hash: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Optional[User]:
    user = get_user_by_id(db, user_id)
    if not user:
        return None
    if full_name is not None:
        user.full_name = full_name.strip()
    if role is not None:
        user.role = role
        if role == "system_admin" and (allowed_tenants is None or "*" not in allowed_tenants):
            user.allowed_tenants = ["*"]
    if allowed_tenants is not None:
        user.allowed_tenants = allowed_tenants
    if is_active is not None:
        user.is_active = is_active
    if password_hash is not None:
        user.password_hash = password_hash
    if tenant_id is not None:
        user.tenant_id = tenant_id
    db.commit()
    db.refresh(user)
    return user


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    if not email:
        return None
    return db.query(User).filter(User.email == email.strip().lower()).first()


def get_user_by_id(db: Session, user_id: str) -> Optional[User]:
    if not user_id:
        return None
    return db.query(User).filter(User.id == user_id).first()


def get_tenant(db: Session, tenant_id: str) -> Optional[Tenant]:
    return db.query(Tenant).filter(Tenant.id == tenant_id).first()


def list_tenants(db: Session, limit: int = 100) -> List[Tenant]:
    return db.query(Tenant).order_by(desc(Tenant.created_at)).limit(limit).all()


def get_tenant_integrations(db: Session, tenant_id: str) -> List[TenantIntegration]:
    return db.query(TenantIntegration).filter(TenantIntegration.tenant_id == tenant_id).all()


def get_tenant_integration(db: Session, tenant_id: str, provider: str) -> Optional[TenantIntegration]:
    return (
        db.query(TenantIntegration)
        .filter(TenantIntegration.tenant_id == tenant_id, TenantIntegration.provider == provider)
        .first()
    )


def upsert_tenant_integration(
    db: Session,
    tenant_id: str,
    provider: str,
    config: Dict[str, Any],
    is_enabled: bool = True,
) -> TenantIntegration:
    integration = get_tenant_integration(db, tenant_id, provider)
    if not integration:
        integration = TenantIntegration(
            tenant_id=tenant_id,
            provider=provider,
            config=config,
            is_enabled=is_enabled,
        )
        db.add(integration)
    else:
        new_config = dict(integration.config or {})
        new_config.update(config)
        integration.config = new_config
        integration.is_enabled = is_enabled
    db.commit()
    db.refresh(integration)
    return integration


def add_authorized_scope(
    db: Session,
    tenant_id: str,
    domain: str,
    authorization_type: str = "self_attested",
    authorized_by: Optional[str] = None,
    expires_at: Optional[datetime] = None,
) -> AuthorizedScope:
    scope = AuthorizedScope(
        tenant_id=tenant_id,
        domain=domain.lower().strip(),
        authorization_type=authorization_type,
        authorized_by=authorized_by,
        expires_at=expires_at,
    )
    db.add(scope)
    db.commit()
    db.refresh(scope)
    return scope


def list_authorized_scopes(db: Session, tenant_id: str) -> List[AuthorizedScope]:
    return (
        db.query(AuthorizedScope)
        .filter(AuthorizedScope.tenant_id == tenant_id)
        .order_by(desc(AuthorizedScope.created_at))
        .all()
    )


def create_scan_job(
    db: Session,
    tenant_id: str,
    target_domain: str,
    scan_profile: str = "standard",
    scan_params: Optional[Dict[str, Any]] = None,
) -> ScanJob:
    job = ScanJob(
        tenant_id=tenant_id,
        target_domain=target_domain,
        scan_profile=scan_profile or "standard",
        status="pending",
        current_step="init",
        scan_params=scan_params or {},
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def get_scan_job(db: Session, tenant_id: str, job_id: str) -> Optional[ScanJob]:
    return (
        db.query(ScanJob)
        .filter(ScanJob.tenant_id == tenant_id, ScanJob.id == job_id)
        .first()
    )


def list_scan_jobs(db: Session, tenant_id: str, limit: int = 50) -> List[ScanJob]:
    return (
        db.query(ScanJob)
        .filter(ScanJob.tenant_id == tenant_id)
        .order_by(desc(ScanJob.created_at))
        .limit(limit)
        .all()
    )


def update_scan_job(
    db: Session,
    tenant_id: str,
    job_id: str,
    status: Optional[str] = None,
    current_step: Optional[str] = None,
    error_message: Optional[str] = None,
    completed: bool = False,
) -> Optional[ScanJob]:
    job = get_scan_job(db, tenant_id=tenant_id, job_id=job_id)
    if not job:
        return None
    if status is not None:
        job.status = status
    if current_step is not None:
        job.current_step = current_step
    if error_message is not None:
        job.error_message = error_message
    if completed:
        job.completed_at = utc_now()
    db.commit()
    db.refresh(job)
    return job


def add_finding(
    db: Session,
    tenant_id: str,
    scan_job_id: str,
    finding_type: str,
    data: Dict[str, Any],
    severity: str = "info",
    source_tool: str = "r7",
) -> Finding:
    finding = Finding(
        tenant_id=tenant_id,
        scan_job_id=scan_job_id,
        type=finding_type,
        data=data,
        severity=severity.lower(),
        source_tool=source_tool,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def add_findings_batch(
    db: Session,
    tenant_id: str,
    scan_job_id: str,
    findings_data: List[Dict[str, Any]],
) -> List[Finding]:
    findings = [
        Finding(
            tenant_id=tenant_id,
            scan_job_id=scan_job_id,
            type=item["type"],
            data=item["data"],
            severity=item.get("severity", "info").lower(),
            source_tool=item.get("source_tool", "r7"),
        )
        for item in findings_data
    ]
    db.add_all(findings)
    db.commit()
    return findings


def get_findings_for_job(
    db: Session,
    tenant_id: str,
    scan_job_id: str,
    finding_type: Optional[str] = None,
) -> List[Finding]:
    query = db.query(Finding).filter(
        Finding.tenant_id == tenant_id,
        Finding.scan_job_id == scan_job_id,
    )
    if finding_type:
        query = query.filter(Finding.type == finding_type)
    return query.order_by(Finding.created_at).all()


def create_ai_report(
    db: Session,
    tenant_id: str,
    scan_job_id: str,
    prioritized_findings: List[Dict[str, Any]],
    recommendations: str,
    report_text: str,
) -> AIReport:
    report = AIReport(
        tenant_id=tenant_id,
        scan_job_id=scan_job_id,
        prioritized_findings=prioritized_findings,
        recommendations=recommendations,
        report_text=report_text,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def get_ai_report_for_job(
    db: Session,
    tenant_id: str,
    scan_job_id: str,
) -> Optional[AIReport]:
    return (
        db.query(AIReport)
        .filter(
            AIReport.tenant_id == tenant_id,
            AIReport.scan_job_id == scan_job_id,
        )
        .first()
    )


def get_tenant_dashboard(db: Session, tenant_id: str) -> Dict[str, Any]:
    total_jobs = db.query(ScanJob).filter(ScanJob.tenant_id == tenant_id).count()
    completed_jobs = (
        db.query(ScanJob)
        .filter(ScanJob.tenant_id == tenant_id, ScanJob.status == "complete")
        .count()
    )
    running_jobs = (
        db.query(ScanJob)
        .filter(ScanJob.tenant_id == tenant_id, ScanJob.status == "running")
        .count()
    )
    
    total_findings = db.query(Finding).filter(Finding.tenant_id == tenant_id).count()
    
    # Severity breakdown
    severity_counts = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.tenant_id == tenant_id)
        .group_by(Finding.severity)
        .all()
    )
    severity_map = {sev: count for sev, count in severity_counts}

    # Finding types breakdown
    type_counts = (
        db.query(Finding.type, func.count(Finding.id))
        .filter(Finding.tenant_id == tenant_id)
        .group_by(Finding.type)
        .all()
    )
    type_map = {ftype: count for ftype, count in type_counts}

    # Recent scans
    recent_jobs = (
        db.query(ScanJob)
        .filter(ScanJob.tenant_id == tenant_id)
        .order_by(desc(ScanJob.created_at))
        .limit(5)
        .all()
    )

    return {
        "tenant_id": tenant_id,
        "scans": {
            "total": total_jobs,
            "completed": completed_jobs,
            "running": running_jobs,
        },
        "findings_count": total_findings,
        "severity_distribution": {
            "critical": severity_map.get("critical", 0),
            "high": severity_map.get("high", 0),
            "medium": severity_map.get("medium", 0),
            "low": severity_map.get("low", 0),
            "info": severity_map.get("info", 0),
        },
        "type_distribution": type_map,
        "recent_scans": [
            {
                "id": job.id,
                "target_domain": job.target_domain,
                "status": job.status,
                "current_step": job.current_step,
                "created_at": job.created_at.isoformat() if job.created_at else None,
                "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            }
            for job in recent_jobs
        ],
    }


# =========================================================================
# Intelligence Graph, Entity Resolution & Evidence Ledger Operations
# =========================================================================

def upsert_entity(
    db: Session,
    tenant_id: str,
    scan_job_id: str,
    canonical_id: str,
    entity_type: str,
    label: str,
    properties: Optional[Dict[str, Any]] = None,
) -> Entity:
    """
    Inserts or updates a canonical entity in the intelligence graph.
    Deduplicates based on canonical_id (e.g. domain:example.com, person:john_doe).
    """
    properties = properties or {}
    entity = (
        db.query(Entity)
        .filter(
            Entity.tenant_id == tenant_id,
            Entity.scan_job_id == scan_job_id,
            Entity.canonical_id == canonical_id,
        )
        .first()
    )
    if entity:
        entity.label = label or entity.label
        entity.type = entity_type or entity.type
        # Merge properties
        merged = dict(entity.properties or {})
        merged.update(properties)
        entity.properties = merged
        entity.last_seen = utc_now()
    else:
        entity = Entity(
            tenant_id=tenant_id,
            scan_job_id=scan_job_id,
            canonical_id=canonical_id,
            type=entity_type,
            label=label,
            properties=properties,
            first_seen=utc_now(),
            last_seen=utc_now(),
        )
        db.add(entity)
    db.commit()
    db.refresh(entity)
    return entity


def add_evidence(
    db: Session,
    tenant_id: str,
    scan_job_id: str,
    source: str,
    source_type: str,
    collector: str,
    extracted_claim: str,
    raw_reference: Optional[Dict[str, Any]] = None,
    source_url: Optional[str] = None,
    collector_version: str = "1.0.0",
    reliability: float = 1.0,
    hash_val: Optional[str] = None,
    expires_at: Optional[datetime] = None,
) -> Evidence:
    """Records an immutable evidence observation supporting or refuting graph facts."""
    evidence = Evidence(
        tenant_id=tenant_id,
        scan_job_id=scan_job_id,
        source=source,
        source_url=source_url,
        source_type=source_type,
        collector=collector,
        collector_version=collector_version,
        raw_reference=raw_reference or {},
        extracted_claim=extracted_claim,
        reliability=reliability,
        hash=hash_val,
        expires_at=expires_at,
        observed_at=utc_now(),
        collected_at=utc_now(),
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence


def upsert_relationship(
    db: Session,
    tenant_id: str,
    scan_job_id: str,
    source_entity_id: str,
    target_entity_id: str,
    relationship_type: str,
    confidence: float = 1.0,
    status: str = "confirmed",
    supporting_evidence_ids: Optional[List[str]] = None,
    contradicting_evidence_ids: Optional[List[str]] = None,
    metadata_properties: Optional[Dict[str, Any]] = None,
) -> EntityRelationship:
    """
    Creates or updates an evidence-backed relationship edge between two entities.
    Accumulates supporting and contradicting evidence IDs and updates confidence.
    """
    supporting_evidence_ids = supporting_evidence_ids or []
    contradicting_evidence_ids = contradicting_evidence_ids or []
    metadata_properties = metadata_properties or {}

    rel = (
        db.query(EntityRelationship)
        .filter(
            EntityRelationship.tenant_id == tenant_id,
            EntityRelationship.scan_job_id == scan_job_id,
            EntityRelationship.source_entity_id == source_entity_id,
            EntityRelationship.target_entity_id == target_entity_id,
            EntityRelationship.relationship_type == relationship_type,
        )
        .first()
    )
    if rel:
        # Merge evidence IDs avoiding duplicates
        cur_supp = set(rel.supporting_evidence_ids or [])
        cur_supp.update(supporting_evidence_ids)
        rel.supporting_evidence_ids = list(cur_supp)

        cur_contra = set(rel.contradicting_evidence_ids or [])
        cur_contra.update(contradicting_evidence_ids)
        rel.contradicting_evidence_ids = list(cur_contra)

        # Update confidence & status
        rel.confidence = confidence
        rel.status = status
        merged_meta = dict(rel.metadata_properties or {})
        merged_meta.update(metadata_properties)
        rel.metadata_properties = merged_meta
        rel.last_seen = utc_now()
    else:
        rel = EntityRelationship(
            tenant_id=tenant_id,
            scan_job_id=scan_job_id,
            source_entity_id=source_entity_id,
            target_entity_id=target_entity_id,
            relationship_type=relationship_type,
            confidence=confidence,
            status=status,
            supporting_evidence_ids=supporting_evidence_ids,
            contradicting_evidence_ids=contradicting_evidence_ids,
            metadata_properties=metadata_properties,
            first_seen=utc_now(),
            last_seen=utc_now(),
        )
        db.add(rel)
    db.commit()
    db.refresh(rel)
    return rel


def add_observation(
    db: Session,
    tenant_id: str,
    scan_job_id: str,
    sensor_name: str,
    raw_data: Dict[str, Any],
) -> ObservationRecord:
    """Stores raw sensor output before normalization."""
    obs = ObservationRecord(
        tenant_id=tenant_id,
        scan_job_id=scan_job_id,
        sensor_name=sensor_name,
        raw_data=raw_data,
        created_at=utc_now(),
    )
    db.add(obs)
    db.commit()
    db.refresh(obs)
    return obs


def get_investigation_graph(
    db: Session,
    tenant_id: str,
    scan_job_id: str,
    entity_types: Optional[List[str]] = None,
    min_confidence: float = 0.0,
    limit: int = 400,
    lens: str = "all",
) -> Dict[str, Any]:
    """
    Returns an intelligence entity graph synthesized for clarity and signal.
    Supports 4 specialized lenses:
    - 'all' / 'raw': Full raw entity graph containing all ingested database nodes and relationships.
    - 'executive': Org -> Executive Leadership -> Department Leads -> Authored Documents & Staff Cluster.
    - 'attack_surface': Root Domain -> High-Value Subdomains -> Origin Servers -> Critical/High CVEs.
    - 'composite': Balanced executive-grade view with staff clustering & CDN collapsing.
    """
    lens = (lens or "all").lower().strip()

    # Base query for all entities in this scan job
    all_entities = (
        db.query(Entity)
        .filter(Entity.tenant_id == tenant_id, Entity.scan_job_id == scan_job_id)
        .limit(limit)
        .all()
    )

    # If no entities were found in Entity table, synthesize them dynamically from Findings!
    if not all_entities:
        findings = (
            db.query(Finding)
            .filter(Finding.tenant_id == tenant_id, Finding.scan_job_id == scan_job_id)
            .all()
        )
        if findings:
            job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
            root_dom = job.target_domain if job else "target"
            
            # 1. Root Domain Entity
            dom_ent = upsert_entity(
                db, tenant_id, scan_job_id,
                f"domain:{root_dom}", "domain", root_dom, {"is_root": True}
            )

            # 2. Subdomain & IP Entities
            for f in findings:
                f_type = (f.type or "").lower()
                f_data = f.data or {}
                if f_type == "subdomain":
                    sub = f_data.get("subdomain") or f_data.get("host")
                    if sub:
                        s_ent = upsert_entity(db, tenant_id, scan_job_id, f"domain:{sub}", "subdomain", sub, f_data)
                        upsert_relationship(db, tenant_id, scan_job_id, dom_ent.id, s_ent.id, "HAS_SUBDOMAIN", 0.95)
                elif f_type == "ip_resolution":
                    sub = f_data.get("subdomain")
                    ips = f_data.get("ips", [])
                    for ip in ips:
                        ip_ent = upsert_entity(db, tenant_id, scan_job_id, f"ip:{ip}", "ip", ip, f_data)
                        upsert_relationship(db, tenant_id, scan_job_id, dom_ent.id, ip_ent.id, "RESOLVES_TO", 0.90)
                elif f_type == "port":
                    p_num = f_data.get("port")
                    p_ip = f_data.get("ip") or root_dom
                    p_srv = f_data.get("service") or "tcp"
                    if p_num:
                        p_ent = upsert_entity(db, tenant_id, scan_job_id, f"port:{p_ip}:{p_num}", "port", f"{p_num}/{p_srv}", f_data)
                        ip_parent = upsert_entity(db, tenant_id, scan_job_id, f"ip:{p_ip}", "ip", p_ip, {})
                        upsert_relationship(db, tenant_id, scan_job_id, ip_parent.id, p_ent.id, "LISTENS_ON", 0.98)
                elif f_type == "vuln":
                    v_title = f_data.get("title") or f_data.get("cve_id") or "Vulnerability"
                    v_sev = f_data.get("severity") or f.severity or "medium"
                    v_host = f_data.get("host") or root_dom
                    v_ent = upsert_entity(db, tenant_id, scan_job_id, f"vuln:{v_title[:60]}", "vulnerability", v_title, f_data)
                    h_ent = upsert_entity(db, tenant_id, scan_job_id, f"domain:{v_host}", "domain", v_host, {})
                    upsert_relationship(db, tenant_id, scan_job_id, h_ent.id, v_ent.id, "AFFECTED_BY", 0.92)
                elif f_type == "people":
                    raw_p = f_data.get("people") or f_data.get("employees") or []
                    for idx, p in enumerate(raw_p[:20]):
                        p_name = p.get("name")
                        if p_name:
                            p_ent = upsert_entity(db, tenant_id, scan_job_id, f"person:{p_name.lower().replace(' ', '_')}", "person", p_name, p)
                            upsert_relationship(db, tenant_id, scan_job_id, dom_ent.id, p_ent.id, "EMPLOYS", 0.90)

            # Re-fetch synthesized entities
            all_entities = (
                db.query(Entity)
                .filter(Entity.tenant_id == tenant_id, Entity.scan_job_id == scan_job_id)
                .limit(limit)
                .all()
            )

    if not all_entities:
        return {"scan_job_id": scan_job_id, "nodes_count": 0, "edges_count": 0, "nodes": [], "edges": [], "lens": lens}

    # Group entities by type
    by_type: Dict[str, List[Entity]] = {}
    for e in all_entities:
        by_type.setdefault(e.type, []).append(e)

    # Base query for stored relationships
    raw_edges = (
        db.query(EntityRelationship)
        .filter(
            EntityRelationship.tenant_id == tenant_id,
            EntityRelationship.scan_job_id == scan_job_id,
            EntityRelationship.confidence >= min_confidence,
        )
        .all()
    )

    org_nodes = by_type.get("organization", [])
    domain_nodes = by_type.get("domain", [])
    subdomain_nodes = by_type.get("subdomain", [])
    ip_nodes = by_type.get("ip", [])
    port_nodes = by_type.get("port", [])
    service_nodes = by_type.get("service", [])
    vuln_nodes = by_type.get("vulnerability", [])
    person_nodes = by_type.get("person", [])
    doc_nodes = by_type.get("document", [])
    cloud_nodes = by_type.get("cloud_resource", [])

    # If person_nodes is empty in Entity table, synthesize directly from Finding(type="people")
    if not person_nodes:
        import urllib.parse
        people_findings = (
            db.query(Finding)
            .filter(Finding.tenant_id == tenant_id, Finding.scan_job_id == scan_job_id)
            .all()
        )
        for f in people_findings:
            if "people" in (f.type or "").lower() and isinstance(f.data, dict):
                raw_people = f.data.get("people") or f.data.get("employees") or []
                synthesized = []
                for idx, p in enumerate(raw_people):
                    p_name = p.get("name") or p.get("cleaned_name")
                    if not p_name or not p.get("is_human", True):
                        continue
                    p_props = dict(p)
                    p_props["image_url"] = f"https://ui-avatars.com/api/?name={urllib.parse.quote_plus(p_name)}&background=042f2e&color=2dd4bf&bold=true&size=128"
                    synthesized.append(
                        type("SynthesizedPerson", (), {
                            "id": f"syn_person_{scan_job_id}_{idx}",
                            "canonical_id": f"person:{p_name.lower().replace(' ', '_')}",
                            "type": "person",
                            "label": p_name,
                            "properties": p_props,
                        })()
                    )
                person_nodes = synthesized
                break

    # Map ports & services into their parent IP properties so we can collapse raw port dots
    ip_ports_map: Dict[str, List[Dict[str, Any]]] = {}
    for p in port_nodes:
        ip_addr = (p.properties or {}).get("ip")
        if ip_addr:
            ip_ports_map.setdefault(ip_addr, []).append(p.properties or {})

    # Helper: Check if IP is CDN
    def is_cdn_node(ip_node: Entity) -> bool:
        props = ip_node.properties or {}
        return bool(props.get("is_cdn")) or "cloudflare" in (props.get("cdn_provider") or "").lower() or ip_node.label.startswith("104.18.") or ip_node.label.startswith("104.21.")

    selected_nodes: List[Dict[str, Any]] = []
    selected_edges: List[Dict[str, Any]] = []
    included_node_ids: Set[str] = set()

    def add_node(n: Dict[str, Any]):
        if n["id"] not in included_node_ids:
            selected_nodes.append(n)
            included_node_ids.add(n["id"])

    def add_edge(src_id: str, tgt_id: str, rel_type: str, confidence: float = 0.90, status: str = "confirmed"):
        if src_id in included_node_ids and tgt_id in included_node_ids:
            selected_edges.append({
                "id": f"syn_{src_id}_{tgt_id}_{rel_type}",
                "source": src_id,
                "target": tgt_id,
                "type": rel_type,
                "confidence": confidence,
                "status": status,
                "supporting_evidence_ids": [],
                "contradicting_evidence_ids": [],
                "metadata": {},
            })

    # =========================================================================
    # LENS 0: FULL / RAW UNFILTERED GRAPH (ALL INGESTED DATABASE ENTITIES & EDGES)
    # =========================================================================
    if lens in ("all", "raw", "full", "none"):
        for e in all_entities:
            add_node({
                "id": e.id,
                "canonical_id": e.canonical_id,
                "type": e.type,
                "label": e.label,
                "properties": e.properties or {},
            })
        for r in raw_edges:
            if r.source_entity_id in included_node_ids and r.target_entity_id in included_node_ids:
                selected_edges.append({
                    "id": r.id,
                    "source": r.source_entity_id,
                    "target": r.target_entity_id,
                    "type": r.relationship_type,
                    "confidence": r.confidence,
                    "status": r.status,
                    "supporting_evidence_ids": r.supporting_evidence_ids or [],
                    "contradicting_evidence_ids": r.contradicting_evidence_ids or [],
                    "metadata": r.metadata_properties or {},
                })

    # =========================================================================
    # LENS 1: EXECUTIVE OSINT & HUMAN HIERARCHY
    # =========================================================================
    elif lens == "executive":
        primary_domains = sorted(domain_nodes, key=lambda d: len(d.label))[:1]
        root_dom_label = primary_domains[0].label if primary_domains else (domain_nodes[0].label if domain_nodes else "")
        logo_url = f"https://www.google.com/s2/favicons?domain={root_dom_label}&sz=128" if root_dom_label else None

        # Always include Organization and Root Domain
        for o in org_nodes:
            add_node({
                "id": o.id,
                "canonical_id": o.canonical_id,
                "type": "organization",
                "label": o.label,
                "properties": {**(o.properties or {}), "image_url": logo_url}
            })
        
        for d in primary_domains:
            add_node({
                "id": d.id,
                "canonical_id": d.canonical_id,
                "type": "domain",
                "label": d.label,
                "properties": {**(d.properties or {}), "image_url": logo_url}
            })
            if org_nodes:
                add_edge(org_nodes[0].id, d.id, "OWNS_DOMAIN", 0.95)

        # Categorize People into: 1) Executive Leadership, 2) Department Leads, 3) Routine Staff
        exec_keywords = ["ceo", "founder", "chancellor", "vice-chancellor", "vice chancellor", "president", "managing director", "chairman", "co-founder", "director", "rector", "provost"]
        lead_keywords = ["head of", "dean", "vp", "chief", "lead", "principal", "manager", "associate professor", "professor", "hod", "lecturer"]

        executives: List[Entity] = []
        leads: List[Entity] = []
        routine_staff: List[Entity] = []

        for p in person_nodes:
            title = ((p.properties or {}).get("title") or "").lower()
            if any(k in title for k in exec_keywords):
                executives.append(p)
            elif any(k in title for k in lead_keywords):
                leads.append(p)
            else:
                routine_staff.append(p)

        # If no explicit executive found, promote top leads
        if not executives and leads:
            executives.append(leads.pop(0))
        elif not executives and routine_staff:
            executives.append(routine_staff.pop(0))

        # Add Executives (Direct link to Org)
        for ex in executives:
            add_node({"id": ex.id, "canonical_id": ex.canonical_id, "type": "person", "label": ex.label, "properties": {**(ex.properties or {}), "hierarchy_tier": "Executive Leadership"}})
            if org_nodes:
                add_edge(org_nodes[0].id, ex.id, "LEADS_ORGANIZATION", 0.98)

        # Add Department Leads (Link to Executive if exists, else Org)
        lead_parent_id = executives[0].id if executives else (org_nodes[0].id if org_nodes else None)
        for ld in leads[:6]: # Limit to top 6 prominent leads to keep graph elegant
            add_node({"id": ld.id, "canonical_id": ld.canonical_id, "type": "person", "label": ld.label, "properties": {**(ld.properties or {}), "hierarchy_tier": "Department Leadership"}})
            if lead_parent_id:
                add_edge(lead_parent_id, ld.id, "SUPERVISES", 0.88)

        # Cluster remaining staff into a single expandable staff cluster node
        total_remaining = len(routine_staff) + max(0, len(leads) - 6)
        all_remaining_staff = routine_staff + leads[6:]
        if total_remaining > 0 and lead_parent_id:
            cluster_id = f"cluster_staff_{scan_job_id}"
            add_node({
                "id": cluster_id,
                "canonical_id": f"cluster:staff:{scan_job_id}",
                "type": "staff_cluster",
                "label": f"+{total_remaining} Personnel Roster",
                "properties": {
                    "count": total_remaining,
                    "staff_list": [
                        {
                            "name": s.label,
                            "title": (s.properties or {}).get("title", "Staff"),
                            "email": (s.properties or {}).get("email", ""),
                            "platform": (s.properties or {}).get("platform", "OSINT"),
                            "profile_url": (s.properties or {}).get("profile_url", ""),
                        }
                        for s in all_remaining_staff
                    ],
                },
            })
            # Connect cluster to primary executive or leads
            cluster_anchor = leads[0].id if leads else lead_parent_id
            add_edge(cluster_anchor, cluster_id, "COLLABORATES_WITH", 0.80)

        # Document Attribution: Connect authored documents directly to employees
        for doc in doc_nodes:
            add_node({"id": doc.id, "canonical_id": doc.canonical_id, "type": "document", "label": doc.label, "properties": doc.properties})
            doc_author = ((doc.properties or {}).get("author") or "").lower().strip()
            matched_person = None
            if doc_author and len(doc_author) > 2:
                for p in person_nodes:
                    if doc_author in p.label.lower() or p.label.lower() in doc_author:
                        matched_person = p
                        break
            if matched_person and matched_person.id in included_node_ids:
                add_edge(matched_person.id, doc.id, "AUTHORED", 0.92)
            elif domain_nodes:
                add_edge(domain_nodes[0].id, doc.id, "HOSTS_DOCUMENT", 0.85)

    # =========================================================================
    # LENS 2: TACTICAL ATTACK SURFACE & THREAT VECTORS
    # =========================================================================
    elif lens == "attack_surface":
        # Root Domain
        primary_domains = sorted(domain_nodes, key=lambda d: len(d.label))[:1]
        for d in primary_domains:
            add_node({"id": d.id, "canonical_id": d.canonical_id, "type": "domain", "label": d.label, "properties": d.properties})

        # High-Value Subdomains (prioritize admin, vpn, api, auth, portal)
        candidate_subs = subdomain_nodes or [d for d in domain_nodes if d not in primary_domains]
        high_value_keywords = ["admin", "vpn", "api", "auth", "portal", "mail", "dev", "staging", "remote"]
        sorted_subs = sorted(
            candidate_subs,
            key=lambda s: any(k in s.label.lower() for k in high_value_keywords),
            reverse=True
        )

        for s in sorted_subs[:8]: # Top 8 critical subdomains
            add_node({"id": s.id, "canonical_id": s.canonical_id, "type": "subdomain", "label": s.label, "properties": s.properties})
            if primary_domains:
                add_edge(primary_domains[0].id, s.id, "SUBDOMAIN_OF", 0.95)

        # Origin vs CDN Edge IP Handling
        origin_ips = [ip for ip in ip_nodes if not is_cdn_node(ip)]
        cdn_ips = [ip for ip in ip_nodes if is_cdn_node(ip)]

        # Dedicated nodes for unmasked origin IPs
        for oip in origin_ips[:4]:
            ip_addr = oip.label
            ports = ip_ports_map.get(ip_addr, [])
            add_node({
                "id": oip.id,
                "canonical_id": oip.canonical_id,
                "type": "ip",
                "label": f"{ip_addr} (Origin)",
                "properties": {**(oip.properties or {}), "is_origin": True, "open_ports": ports},
            })
            if primary_domains:
                add_edge(primary_domains[0].id, oip.id, "RESOLVES_ORIGIN", 0.95)

        # Single collapsed Cloudflare CDN Gateway node
        if cdn_ips and primary_domains:
            cdn_gateway_id = f"cdn_edge_gateway_{scan_job_id}"
            add_node({
                "id": cdn_gateway_id,
                "canonical_id": f"cloud:cdn:{scan_job_id}",
                "type": "cloud_resource",
                "label": "Cloudflare Anycast Edge",
                "properties": {"provider": "Cloudflare", "collapsed_ip_count": len(cdn_ips)},
            })
            add_edge(primary_domains[0].id, cdn_gateway_id, "PROXIED_BY", 0.99)

        # Critical & High Vulnerabilities (branch out to vulnerable hosts)
        vuln_anchor = origin_ips[0].id if origin_ips else (primary_domains[0].id if primary_domains else None)
        for v in vuln_nodes:
            sev = ((v.properties or {}).get("severity") or "info").lower()
            if sev in ["critical", "high", "medium"]:
                add_node({"id": v.id, "canonical_id": v.canonical_id, "type": "vulnerability", "label": v.label, "properties": v.properties})
                if vuln_anchor:
                    add_edge(vuln_anchor, v.id, "VULNERABLE_TO", 0.90)

    # =========================================================================
    # LENS 3: COMPOSITE MASTER GRAPH (BALANCED)
    # =========================================================================
    else:
        # Organization & Root Domain
        for o in org_nodes:
            add_node({"id": o.id, "canonical_id": o.canonical_id, "type": "organization", "label": o.label, "properties": o.properties})
        
        primary_domains = sorted(domain_nodes, key=lambda d: len(d.label))[:1]
        root_dom_label = primary_domains[0].label if primary_domains else (domain_nodes[0].label if domain_nodes else "")
        logo_url = f"https://www.google.com/s2/favicons?domain={root_dom_label}&sz=128" if root_dom_label else None

        for o in org_nodes:
            add_node({"id": o.id, "canonical_id": o.canonical_id, "type": "organization", "label": o.label, "properties": {**(o.properties or {}), "image_url": logo_url}})
        
        for d in primary_domains:
            add_node({"id": d.id, "canonical_id": d.canonical_id, "type": "domain", "label": d.label, "properties": {**(d.properties or {}), "image_url": logo_url}})
            if org_nodes:
                add_edge(org_nodes[0].id, d.id, "OWNS_DOMAIN", 0.95)

        # 1. Executive Leadership & Prominent Personnel
        exec_keywords = ["ceo", "founder", "chancellor", "vice-chancellor", "vice chancellor", "president", "managing director", "chairman", "co-founder", "director", "rector", "provost"]
        lead_keywords = ["head of", "dean", "vp", "chief", "lead", "principal", "manager", "associate professor", "professor", "hod", "lecturer"]

        executives = [p for p in person_nodes if any(k in ((p.properties or {}).get("title") or "").lower() for k in exec_keywords)]
        leads = [p for p in person_nodes if any(k in ((p.properties or {}).get("title") or "").lower() for k in lead_keywords) and p not in executives]
        if not executives and person_nodes:
            executives = [person_nodes[0]]
            if len(person_nodes) > 1:
                leads = person_nodes[1:4]

        for ex in executives[:2]:
            add_node({"id": ex.id, "canonical_id": ex.canonical_id, "type": "person", "label": ex.label, "properties": {**(ex.properties or {}), "hierarchy_tier": "Executive"}})
            if org_nodes:
                add_edge(org_nodes[0].id, ex.id, "LEADS_ORGANIZATION", 0.98)

        lead_parent_id = executives[0].id if executives else (org_nodes[0].id if org_nodes else None)
        for ld in leads[:3]:
            add_node({"id": ld.id, "canonical_id": ld.canonical_id, "type": "person", "label": ld.label, "properties": {**(ld.properties or {}), "hierarchy_tier": "Department Leadership"}})
            if lead_parent_id:
                add_edge(lead_parent_id, ld.id, "SUPERVISES", 0.88)

        # 2. Staff Cluster (collapsing remaining employees into roster)
        surfaced_person_ids = {ex.id for ex in executives[:2]} | {ld.id for ld in leads[:3]}
        other_staff = [p for p in person_nodes if p.id not in surfaced_person_ids]
        if other_staff and lead_parent_id:
            cluster_id = f"cluster_staff_{scan_job_id}"
            add_node({
                "id": cluster_id,
                "canonical_id": f"cluster:staff:{scan_job_id}",
                "type": "staff_cluster",
                "label": f"+{len(other_staff)} Personnel Roster",
                "properties": {
                    "count": len(other_staff),
                    "staff_list": [
                        {
                            "name": s.label,
                            "title": (s.properties or {}).get("title", "Staff"),
                            "email": (s.properties or {}).get("email", ""),
                            "platform": (s.properties or {}).get("platform", "OSINT"),
                            "profile_url": (s.properties or {}).get("profile_url", ""),
                        }
                        for s in other_staff
                    ],
                },
            })
            add_edge(lead_parent_id, cluster_id, "SUPERVISES", 0.85)

        # 3. Documents
        for doc in doc_nodes[:4]:
            add_node({"id": doc.id, "canonical_id": doc.canonical_id, "type": "document", "label": doc.label, "properties": doc.properties})
            if executives:
                add_edge(executives[0].id, doc.id, "AUTHORED", 0.88)
            elif domain_nodes:
                add_edge(domain_nodes[0].id, doc.id, "HOSTS_DOCUMENT", 0.85)

        # 4. Sensitive Subdomains
        high_value_keywords = ["admin", "vpn", "api", "auth", "portal", "mail"]
        sensitive_subs = [s for s in subdomain_nodes if any(k in s.label.lower() for k in high_value_keywords)]
        for s in (sensitive_subs or subdomain_nodes)[:6]:
            add_node({"id": s.id, "canonical_id": s.canonical_id, "type": "subdomain", "label": s.label, "properties": s.properties})
            if domain_nodes:
                add_edge(domain_nodes[0].id, s.id, "SUBDOMAIN_OF", 0.95)

        # 5. Origin Host
        origin_ips = [ip for ip in ip_nodes if not is_cdn_node(ip)]
        if origin_ips and domain_nodes:
            oip = origin_ips[0]
            add_node({
                "id": oip.id,
                "canonical_id": oip.canonical_id,
                "type": "ip",
                "label": f"{oip.label} (Origin)",
                "properties": {**(oip.properties or {}), "is_origin": True, "open_ports": ip_ports_map.get(oip.label, [])},
            })
            add_edge(domain_nodes[0].id, oip.id, "RESOLVES_ORIGIN", 0.95)

        # 6. Critical Vulns
        vuln_target = origin_ips[0].id if origin_ips else (domain_nodes[0].id if domain_nodes else None)
        for v in vuln_nodes:
            sev = ((v.properties or {}).get("severity") or "info").lower()
            if sev in ["critical", "high"]:
                add_node({"id": v.id, "canonical_id": v.canonical_id, "type": "vulnerability", "label": v.label, "properties": v.properties})
                if vuln_target:
                    add_edge(vuln_target, v.id, "VULNERABLE_TO", 0.92)

    # Safety Fallback: If lens filtering produced 0 nodes, fallback to all ingested nodes!
    if not selected_nodes and all_entities:
        for e in all_entities:
            add_node({
                "id": e.id,
                "canonical_id": e.canonical_id,
                "type": e.type,
                "label": e.label,
                "properties": e.properties or {},
            })
        for r in raw_edges:
            if r.source_entity_id in included_node_ids and r.target_entity_id in included_node_ids:
                selected_edges.append({
                    "id": r.id,
                    "source": r.source_entity_id,
                    "target": r.target_entity_id,
                    "type": r.relationship_type,
                    "confidence": r.confidence,
                    "status": r.status,
                    "supporting_evidence_ids": r.supporting_evidence_ids or [],
                    "contradicting_evidence_ids": r.contradicting_evidence_ids or [],
                    "metadata": r.metadata_properties or {},
                })

    return {
        "scan_job_id": scan_job_id,
        "lens": lens,
        "nodes_count": len(selected_nodes),
        "edges_count": len(selected_edges),
        "nodes": selected_nodes,
        "edges": selected_edges,
    }


def expand_graph_node(
    db: Session,
    tenant_id: str,
    scan_job_id: str,
    entity_id: str,
) -> Dict[str, Any]:
    """
    Expands a single node by dynamically fetching its 1st-degree connected entities.
    Supports unfolding emails & social identities from people, open ports from hosts,
    subdomains from domains, and roster members from staff clusters.
    """
    import urllib.parse

    expanded_nodes: List[Dict[str, Any]] = []
    expanded_edges: List[Dict[str, Any]] = []
    seen_node_ids = set()

    def add_n(n: Dict[str, Any]):
        if n["id"] not in seen_node_ids:
            expanded_nodes.append(n)
            seen_node_ids.add(n["id"])

    def add_e(src: str, tgt: str, rel_type: str, conf: float = 0.95):
        expanded_edges.append({
            "id": f"exp_{src}_{tgt}_{rel_type}",
            "source": src,
            "target": tgt,
            "type": rel_type,
            "confidence": conf,
            "status": "confirmed",
            "supporting_evidence_ids": [],
            "contradicting_evidence_ids": [],
            "metadata": {},
        })

    # 1. Attempt to locate node in Entity table
    center_entity = (
        db.query(Entity)
        .filter(Entity.tenant_id == tenant_id, Entity.scan_job_id == scan_job_id, Entity.id == entity_id)
        .first()
    )

    center_node_dict = None
    if center_entity:
        center_node_dict = {
            "id": center_entity.id,
            "canonical_id": center_entity.canonical_id,
            "type": center_entity.type,
            "label": center_entity.label,
            "properties": center_entity.properties or {},
        }
    elif entity_id.startswith("syn_person_"):
        # Synthesized person from Finding(type="people")
        people_findings = (
            db.query(Finding)
            .filter(Finding.tenant_id == tenant_id, Finding.scan_job_id == scan_job_id)
            .all()
        )
        for f in people_findings:
            if "people" in (f.type or "").lower() and isinstance(f.data, dict):
                raw_people = f.data.get("people") or f.data.get("employees") or []
                try:
                    p_idx = int(entity_id.split("_")[-1])
                    if p_idx < len(raw_people):
                        p = raw_people[p_idx]
                        p_name = p.get("name") or p.get("cleaned_name") or "Person"
                        center_node_dict = {
                            "id": entity_id,
                            "canonical_id": f"person:{p_name.lower().replace(' ', '_')}",
                            "type": "person",
                            "label": p_name,
                            "properties": p,
                        }
                        break
                except (ValueError, IndexError):
                    pass

    if not center_node_dict:
        return {"nodes": [], "edges": []}

    add_n(center_node_dict)
    n_type = center_node_dict.get("type")
    n_props = center_node_dict.get("properties") or {}

    # === BRANCH A: PERSON NODE EXPANSION ===
    if n_type == "person":
        # 1. Expand corporate email if exists
        email = n_props.get("email")
        if email and "@" in email:
            email_node_id = f"email_{entity_id}"
            add_n({
                "id": email_node_id,
                "canonical_id": f"email:{email}",
                "type": "email",
                "label": email,
                "properties": {"email": email, "deliverability": n_props.get("deliverability", "inferred")},
            })
            add_e(entity_id, email_node_id, "HAS_EMAIL", 0.95)

        # 2. Expand social / LinkedIn profile if exists
        profile_url = n_props.get("profile_url")
        if profile_url and "http" in profile_url:
            platform = n_props.get("platform", "Social")
            handle = profile_url.split("/")[-1] or profile_url.split("/")[-2] or platform
            prof_node_id = f"prof_{entity_id}"
            add_n({
                "id": prof_node_id,
                "canonical_id": f"profile:{platform.lower()}:{handle}",
                "type": "username",
                "label": f"{platform}: {handle}",
                "properties": {"profile_url": profile_url, "platform": platform, "image_url": "https://cdn-icons-png.flaticon.com/512/174/174857.png"},
            })
            add_e(entity_id, prof_node_id, "HAS_PROFILE", 0.98)

        # 3. Expand authored documents matching this person
        doc_entities = (
            db.query(Entity)
            .filter(Entity.tenant_id == tenant_id, Entity.scan_job_id == scan_job_id, Entity.type == "document")
            .all()
        )
        person_name = center_node_dict.get("label", "").lower()
        for doc in doc_entities:
            author = ((doc.properties or {}).get("author") or "").lower()
            if author and (author in person_name or person_name in author):
                add_n({
                    "id": doc.id,
                    "canonical_id": doc.canonical_id,
                    "type": "document",
                    "label": doc.label,
                    "properties": doc.properties,
                })
                add_e(entity_id, doc.id, "AUTHORED", 0.90)

    # === BRANCH B: IP / HOST NODE EXPANSION ===
    elif n_type == "ip":
        ip_addr = center_node_dict.get("label", "").split(" ")[0]
        # Query open ports for this host
        port_findings = (
            db.query(Finding)
            .filter(Finding.tenant_id == tenant_id, Finding.scan_job_id == scan_job_id)
            .all()
        )
        for f in port_findings:
            if "port" in (f.type or "").lower() and isinstance(f.data, dict):
                p_ip = f.data.get("ip")
                if p_ip == ip_addr:
                    port_num = f.data.get("port")
                    service = f.data.get("service") or f.data.get("product") or "Service"
                    port_node_id = f"port_{entity_id}_{port_num}"
                    add_n({
                        "id": port_node_id,
                        "canonical_id": f"port:{ip_addr}:{port_num}",
                        "type": "port",
                        "label": f"{port_num}/tcp {service}",
                        "properties": f.data,
                    })
                    add_e(entity_id, port_node_id, "EXPOSES_PORT", 0.95)

    # === BRANCH C: DOMAIN NODE EXPANSION ===
    # Note: Explicit relationships in database are processed below in Branch D

    # === BRANCH D: ALSO INCLUDE EXPLICIT STORED RELATIONSHIPS ===
    incident_rels = (
        db.query(EntityRelationship)
        .filter(
            EntityRelationship.tenant_id == tenant_id,
            EntityRelationship.scan_job_id == scan_job_id,
            (EntityRelationship.source_entity_id == entity_id) | (EntityRelationship.target_entity_id == entity_id),
        )
        .all()
    )
    for rel in incident_rels:
        other_id = rel.target_entity_id if rel.source_entity_id == entity_id else rel.source_entity_id
        other_ent = db.query(Entity).filter(Entity.tenant_id == tenant_id, Entity.id == other_id).first()
        if other_ent:
            add_n({
                "id": other_ent.id,
                "canonical_id": other_ent.canonical_id,
                "type": other_ent.type,
                "label": other_ent.label,
                "properties": other_ent.properties,
            })
            add_e(rel.source_entity_id, rel.target_entity_id, rel.relationship_type, rel.confidence)

    return {
        "nodes": expanded_nodes,
        "edges": expanded_edges,
    }


def get_evidence_by_id(
    db: Session,
    tenant_id: str,
    scan_job_id: str,
    evidence_id: str,
) -> Optional[Evidence]:
    """Retrieves an evidence record by its primary key ID."""
    return (
        db.query(Evidence)
        .filter(
            Evidence.tenant_id == tenant_id,
            Evidence.scan_job_id == scan_job_id,
            Evidence.id == evidence_id,
        )
        .first()
    )


def get_evidence_records_batch(
    db: Session,
    tenant_id: str,
    scan_job_id: str,
    evidence_ids: List[str],
) -> List[Evidence]:
    """Retrieves multiple evidence records by their IDs."""
    if not evidence_ids:
        return []
    return (
        db.query(Evidence)
        .filter(
            Evidence.tenant_id == tenant_id,
            Evidence.scan_job_id == scan_job_id,
            Evidence.id.in_(evidence_ids),
        )
        .all()
    )


def find_entity_path(
    db: Session,
    tenant_id: str,
    scan_job_id: str,
    source_entity_id: str,
    target_entity_id: str,
    max_depth: int = 5,
) -> Dict[str, Any]:
    """
    Finds the shortest evidence-backed traversal path connecting source_entity_id
    and target_entity_id within an investigation graph using BFS.
    """
    if source_entity_id == target_entity_id:
        node = (
            db.query(Entity)
            .filter(
                Entity.tenant_id == tenant_id,
                Entity.scan_job_id == scan_job_id,
                Entity.id == source_entity_id,
            )
            .first()
        )
        if not node:
            return {"found": False, "path_length": -1, "nodes": [], "edges": []}
        return {
            "found": True,
            "path_length": 0,
            "nodes": [
                {
                    "id": node.id,
                    "canonical_id": node.canonical_id,
                    "type": node.type,
                    "label": node.label,
                    "properties": node.properties,
                }
            ],
            "edges": [],
        }

    # Verify both entities exist in this scan job
    entities_query = (
        db.query(Entity)
        .filter(
            Entity.tenant_id == tenant_id,
            Entity.scan_job_id == scan_job_id,
            Entity.id.in_([source_entity_id, target_entity_id]),
        )
        .all()
    )
    if len(entities_query) < 2:
        return {"found": False, "path_length": -1, "nodes": [], "edges": []}

    # Load all relationships for this scan job
    all_relationships = (
        db.query(EntityRelationship)
        .filter(
            EntityRelationship.tenant_id == tenant_id,
            EntityRelationship.scan_job_id == scan_job_id,
        )
        .all()
    )

    # Build undirected adjacency map: node_id -> list of (neighbor_id, relationship_obj)
    adj: Dict[str, List[Tuple[str, EntityRelationship]]] = {}
    for r in all_relationships:
        adj.setdefault(r.source_entity_id, []).append((r.target_entity_id, r))
        adj.setdefault(r.target_entity_id, []).append((r.source_entity_id, r))

    # BFS queue: (current_node_id, [node_ids_in_path], [edge_objs_in_path])
    queue: deque = deque([(source_entity_id, [source_entity_id], [])])
    visited = {source_entity_id}

    found_nodes_path: Optional[List[str]] = None
    found_edges_path: Optional[List[EntityRelationship]] = None

    while queue:
        curr_id, node_path, edge_path = queue.popleft()

        if len(edge_path) >= max_depth:
            continue

        for neighbor_id, edge in adj.get(curr_id, []):
            if neighbor_id == target_entity_id:
                found_nodes_path = node_path + [neighbor_id]
                found_edges_path = edge_path + [edge]
                break

            if neighbor_id not in visited:
                visited.add(neighbor_id)
                queue.append((neighbor_id, node_path + [neighbor_id], edge_path + [edge]))

        if found_nodes_path:
            break

    if not found_nodes_path or not found_edges_path:
        return {"found": False, "path_length": -1, "nodes": [], "edges": []}

    # Fetch entity objects for the path
    entity_map = {
        e.id: e
        for e in db.query(Entity)
        .filter(
            Entity.tenant_id == tenant_id,
            Entity.scan_job_id == scan_job_id,
            Entity.id.in_(found_nodes_path),
        )
        .all()
    }

    nodes_data = [
        {
            "id": entity_map[nid].id,
            "canonical_id": entity_map[nid].canonical_id,
            "type": entity_map[nid].type,
            "label": entity_map[nid].label,
            "properties": entity_map[nid].properties,
        }
        for nid in found_nodes_path
        if nid in entity_map
    ]

    edges_data = [
        {
            "id": r.id,
            "source": r.source_entity_id,
            "target": r.target_entity_id,
            "type": r.relationship_type,
            "confidence": round(r.confidence, 2),
            "status": r.status,
            "supporting_evidence_ids": r.supporting_evidence_ids,
            "contradicting_evidence_ids": r.contradicting_evidence_ids,
            "metadata": r.metadata_properties,
        }
        for r in found_edges_path
    ]

    return {
        "found": True,
        "path_length": len(edges_data),
        "nodes": nodes_data,
        "edges": edges_data,
    }


