import uuid
from datetime import datetime, timezone
from typing import Optional, Any, Dict, List
from sqlalchemy import (
    Column,
    String,
    DateTime,
    ForeignKey,
    Text,
    Enum,
    Index,
    Float,
    JSON,
    Boolean,
    Integer,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    scopes = relationship("AuthorizedScope", back_populates="tenant", cascade="all, delete-orphan")
    scan_jobs = relationship("ScanJob", back_populates="tenant", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="tenant", cascade="all, delete-orphan")
    ai_reports = relationship("AIReport", back_populates="tenant", cascade="all, delete-orphan")
    entities = relationship("Entity", back_populates="tenant", cascade="all, delete-orphan")
    evidence_records = relationship("Evidence", back_populates="tenant", cascade="all, delete-orphan")
    relationships = relationship("EntityRelationship", back_populates="tenant", cascade="all, delete-orphan")
    observations = relationship("ObservationRecord", back_populates="tenant", cascade="all, delete-orphan")
    integrations = relationship("TenantIntegration", back_populates="tenant", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    full_name = Column(String(255), nullable=True)
    password_hash = Column(String(255), nullable=True)
    role = Column(String(50), default="operator", nullable=False)
    allowed_tenants = Column(JSON, default=list, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    token_version = Column(Integer, default=1, nullable=False)
    created_by = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    tenant = relationship("Tenant", back_populates="users")

    __table_args__ = (
        Index("ix_users_tenant_email", "tenant_id", "email"),
    )


class SystemConfig(Base):
    __tablename__ = "system_config"

    key = Column(String(100), primary_key=True)
    value = Column(JSON, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)


class TenantIntegration(Base):
    __tablename__ = "tenant_integrations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(50), nullable=False)
    config = Column(JSON, nullable=False, default=dict)
    is_enabled = Column(Boolean, default=True, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    tenant = relationship("Tenant", back_populates="integrations")

    __table_args__ = (
        Index("ix_tenant_integrations_tenant_provider", "tenant_id", "provider", unique=True),
    )


class AuthorizedScope(Base):
    __tablename__ = "authorized_scopes"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    authorization_type = Column(String(50), default="self_attested", nullable=False)  # self_attested | engagement_letter
    authorized_by = Column(String(255), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    tenant = relationship("Tenant", back_populates="scopes")

    __table_args__ = (
        Index("ix_tenant_domain", "tenant_id", "domain"),
    )


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    target_domain = Column(String(255), nullable=False, index=True)
    target_type = Column(String(50), default="domain", nullable=False)  # domain | organization | ip | person | email | username
    normalized_target = Column(String(255), nullable=True)
    requester = Column(String(255), nullable=True)
    scan_profile = Column(String(50), default="standard", nullable=False)  # fast | standard | deep
    status = Column(String(50), default="pending", nullable=False, index=True)  # pending | running | complete | failed
    current_step = Column(String(100), default="init", nullable=False)
    sensors_used = Column(JSON, default=list, nullable=True)
    scan_params = Column(JSON, default=dict, nullable=True)  # Stores seed org_name, ceo_name, keywords
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    tenant = relationship("Tenant", back_populates="scan_jobs")
    findings = relationship("Finding", back_populates="scan_job", cascade="all, delete-orphan")
    ai_reports = relationship("AIReport", back_populates="scan_job", cascade="all, delete-orphan")
    entities = relationship("Entity", back_populates="scan_job", cascade="all, delete-orphan")
    evidence_records = relationship("Evidence", back_populates="scan_job", cascade="all, delete-orphan")
    relationships = relationship("EntityRelationship", back_populates="scan_job", cascade="all, delete-orphan")
    observations = relationship("ObservationRecord", back_populates="scan_job", cascade="all, delete-orphan")


class Entity(Base):
    """
    Canonical entity in the intelligence graph.
    Represents an Organization, Person, Domain, Subdomain, IP, Port, Service, Technology,
    Vulnerability, Email, Username, Document, CloudResource, Breach, or URL.
    """
    __tablename__ = "entities"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id = Column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    canonical_id = Column(String(255), nullable=False, index=True)
    type = Column(String(50), nullable=False, index=True)
    label = Column(String(255), nullable=False)
    properties = Column(JSON, default=dict, nullable=False)
    first_seen = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    scan_job = relationship("ScanJob", back_populates="entities")
    tenant = relationship("Tenant", back_populates="entities")
    outgoing_relationships = relationship(
        "EntityRelationship",
        foreign_keys="EntityRelationship.source_entity_id",
        back_populates="source_entity",
        cascade="all, delete-orphan",
    )
    incoming_relationships = relationship(
        "EntityRelationship",
        foreign_keys="EntityRelationship.target_entity_id",
        back_populates="target_entity",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_entity_tenant_job_canonical", "tenant_id", "scan_job_id", "canonical_id"),
        Index("ix_entity_tenant_type", "tenant_id", "type"),
    )


class Evidence(Base):
    """
    Immutable evidence record supporting or refuting facts in the intelligence graph.
    Every relationship or non-trivial finding cites one or more evidence records.
    """
    __tablename__ = "evidence_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id = Column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    source = Column(String(100), nullable=False, index=True)  # e.g., whois, dns, nmap, tech_engine, crawler
    source_url = Column(Text, nullable=True)
    source_type = Column(String(50), nullable=False)  # network_probe | public_document | official_website | passive_dns | api
    collector = Column(String(100), nullable=False)
    collector_version = Column(String(50), default="1.0.0", nullable=False)
    observed_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    collected_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    raw_reference = Column(JSON, default=dict, nullable=False)
    extracted_claim = Column(Text, nullable=False)
    reliability = Column(Float, default=1.0, nullable=False)
    hash = Column(String(64), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)

    scan_job = relationship("ScanJob", back_populates="evidence_records")
    tenant = relationship("Tenant", back_populates="evidence_records")

    __table_args__ = (
        Index("ix_evidence_tenant_job", "tenant_id", "scan_job_id"),
        Index("ix_evidence_source", "tenant_id", "source"),
    )


class EntityRelationship(Base):
    """
    Typed, evidence-backed edge connecting two entities in the intelligence graph.
    Stores confidence, status (confirmed/likely/possible_match/contradicted),
    and sets of supporting and contradicting evidence IDs.
    """
    __tablename__ = "entity_relationships"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id = Column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    source_entity_id = Column(String(36), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False, index=True)
    target_entity_id = Column(String(36), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type = Column(String(50), nullable=False, index=True)
    confidence = Column(Float, default=1.0, nullable=False)
    status = Column(String(50), default="confirmed", nullable=False)  # confirmed | likely | possible_match | contradicted
    supporting_evidence_ids = Column(JSON, default=list, nullable=False)
    contradicting_evidence_ids = Column(JSON, default=list, nullable=False)
    metadata_properties = Column(JSON, default=dict, nullable=False)
    first_seen = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    scan_job = relationship("ScanJob", back_populates="relationships")
    tenant = relationship("Tenant", back_populates="relationships")
    source_entity = relationship("Entity", foreign_keys=[source_entity_id], back_populates="outgoing_relationships")
    target_entity = relationship("Entity", foreign_keys=[target_entity_id], back_populates="incoming_relationships")

    __table_args__ = (
        Index("ix_rel_tenant_job_type", "tenant_id", "scan_job_id", "relationship_type"),
        Index("ix_rel_source_target", "source_entity_id", "target_entity_id"),
    )


class ObservationRecord(Base):
    """Raw observation output collected by an individual sensor prior to entity normalization."""
    __tablename__ = "observation_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id = Column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    sensor_name = Column(String(100), nullable=False, index=True)
    raw_data = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    scan_job = relationship("ScanJob", back_populates="observations")
    tenant = relationship("Tenant", back_populates="observations")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id = Column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    type = Column(String(50), nullable=False, index=True)  # org | subdomain | ip | port | fingerprint | vuln | person | cloud | doc
    data = Column(JSON, nullable=False)
    severity = Column(String(50), default="info", nullable=False)  # info | low | medium | high | critical
    confidence = Column(Float, default=1.0, nullable=False)
    source_tool = Column(String(100), nullable=False)
    evidence_ids = Column(JSON, default=list, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    scan_job = relationship("ScanJob", back_populates="findings")
    tenant = relationship("Tenant", back_populates="findings")

    __table_args__ = (
        Index("ix_finding_tenant_job", "tenant_id", "scan_job_id"),
        Index("ix_finding_tenant_type", "tenant_id", "type"),
    )


class AIReport(Base):
    __tablename__ = "ai_reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id = Column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    prioritized_findings = Column(JSON, nullable=False)
    recommendations = Column(Text, nullable=True)
    report_text = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    scan_job = relationship("ScanJob", back_populates="ai_reports")
    tenant = relationship("Tenant", back_populates="ai_reports")


class SearchCache(Base):
    __tablename__ = "search_cache"

    query_hash = Column(String(64), primary_key=True)
    query = Column(Text, nullable=False)
    provider = Column(String(50), default="serpapi", nullable=False)
    results = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)


