from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class CandidateEntity:
    """A proposed entity observed by a sensor before deduplication and normalization."""
    canonical_id: str
    type: str  # organization | person | domain | subdomain | ip | port | service | technology | vulnerability | email | username | document | cloud_resource | breach
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CandidateRelationship:
    """A proposed relationship observed between two candidate entities."""
    source_canonical_id: str
    target_canonical_id: str
    relationship_type: str  # OWNS | HAS_SUBDOMAIN | RESOLVES_TO | EXPOSES_PORT | RUNS_SERVICE | USES_TECHNOLOGY | POTENTIALLY_AFFECTED_BY | EMPLOYED_BY | USES_EMAIL | HAS_USERNAME | AUTHORED | PUBLISHED | MENTIONS | REFERENCES | ASSOCIATED_WITH | APPEARS_IN
    confidence: float = 1.0
    status: str = "confirmed"  # confirmed | likely | possible_match | contradicted
    metadata: Dict[str, Any] = field(default_factory=dict)
    contradiction: bool = False


@dataclass
class Observation:
    """
    Standardized observation packet emitted by a Sensor during reconnaissance.
    Carries raw telemetry, extracted facts, proposed entities/relationships, and source metadata.
    """
    sensor_name: str
    sensor_version: str
    source_type: str  # network_probe | public_document | official_website | passive_dns | api
    observed_at: datetime = field(default_factory=utc_now)
    source_url: Optional[str] = None
    reliability: float = 1.0
    extracted_claim: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    entities: List[CandidateEntity] = field(default_factory=list)
    relationships: List[CandidateRelationship] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
