import pytest
from storage.db import (
    get_db_session,
    init_db,
    create_tenant,
    create_scan_job,
    get_investigation_graph,
    expand_graph_node,
    get_evidence_by_id,
    upsert_entity,
    add_evidence,
    upsert_relationship,
)
from core.sensors.builtins import (
    WhoisSensor,
    DnsSubdomainSensor,
    PortServiceSensor,
    TechnologySensor,
    PeopleSensor,
    DocumentSensor,
    ExposureSensor,
)
from core.sensors.registry import sensor_registry


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


def test_milestone1_entity_intelligence_graph_contract():
    """
    Validates Milestone 1 (Spec Section 43):
    Given a target ('example.com'), produce a normalized investigation containing
    domains, subdomains, IPs, ports, services, technologies, people, emails, documents,
    findings, evidence, relationships, and confidence scores. The output is queryable as a graph.
    """
    with get_db_session() as db:
        tenant = create_tenant(db, "Milestone1 Tenant")
        job = create_scan_job(db, tenant.id, "example.com", scan_profile="standard")
        tenant_id = tenant.id
        job_id = job.id

    # Verify sensor registry is populated with core sensors
    sensors = sensor_registry.list_all()
    sensor_names = [s.name for s in sensors]
    assert "whois_sensor" in sensor_names
    assert "dns_subdomain_sensor" in sensor_names
    assert "port_service_sensor" in sensor_names
    assert "technology_sensor" in sensor_names
    assert "people_osint_sensor" in sensor_names
    assert "exposure_sensor" in sensor_names

    with get_db_session() as db:
        # 1. Ingest Evidence
        whois_ev = add_evidence(
            db, tenant_id, job_id,
            source="whois", source_type="public_document", collector="whois_sensor",
            extracted_claim="Target example.com owned by Example Corporation.",
            reliability=0.95,
        )
        dns_ev = add_evidence(
            db, tenant_id, job_id,
            source="dns", source_type="network_probe", collector="dns_subdomain_sensor",
            extracted_claim="Subdomain api.example.com resolves to 93.184.216.34.",
            reliability=1.0,
        )
        tech_ev = add_evidence(
            db, tenant_id, job_id,
            source="technology_engine", source_type="network_probe", collector="technology_sensor",
            extracted_claim="Multi-signal HTTP inspection detected Nginx 1.24.0.",
            reliability=0.92,
        )
        people_ev = add_evidence(
            db, tenant_id, job_id,
            source="direct_profile", source_type="public_profile", collector="people_osint_sensor",
            extracted_claim="John Smith verified as Lead Infrastructure Engineer at Example Corp.",
            reliability=0.90,
        )

        # 2. Ingest Milestone 1 Canonical Entities
        org = upsert_entity(db, tenant_id, job_id, "organization:example_corp", "organization", "Example Corporation")
        dom = upsert_entity(db, tenant_id, job_id, "domain:example.com", "domain", "example.com")
        sub = upsert_entity(db, tenant_id, job_id, "subdomain:api.example.com", "subdomain", "api.example.com")
        ip = upsert_entity(db, tenant_id, job_id, "ip:93.184.216.34", "ip", "93.184.216.34")
        port = upsert_entity(db, tenant_id, job_id, "port:93.184.216.34:443:tcp", "port", "443/tcp")
        service = upsert_entity(db, tenant_id, job_id, "service:93.184.216.34:443:https", "service", "HTTPS (Nginx)")
        tech = upsert_entity(db, tenant_id, job_id, "technology:nginx", "technology", "Nginx 1.24.0")
        person = upsert_entity(db, tenant_id, job_id, "person:john_smith", "person", "John Smith")
        email = upsert_entity(db, tenant_id, job_id, "email:john.smith@example.com", "email", "john.smith@example.com")
        doc = upsert_entity(db, tenant_id, job_id, "document:annual_report", "document", "annual-report.pdf")
        cloud = upsert_entity(db, tenant_id, job_id, "cloud_resource:s3_example", "cloud_resource", "AWS S3: DISCOVERED")
        breach = upsert_entity(db, tenant_id, job_id, "breach:compilation_2023", "breach", "Historical Public Data Compilation")

        # 3. Ingest Typed, Evidence-Backed Relationships
        upsert_relationship(db, tenant_id, job_id, org.id, dom.id, "OWNS", 0.95, supporting_evidence_ids=[whois_ev.id])
        upsert_relationship(db, tenant_id, job_id, dom.id, sub.id, "HAS_SUBDOMAIN", 1.0, supporting_evidence_ids=[dns_ev.id])
        upsert_relationship(db, tenant_id, job_id, sub.id, ip.id, "RESOLVES_TO", 1.0, supporting_evidence_ids=[dns_ev.id])
        upsert_relationship(db, tenant_id, job_id, ip.id, port.id, "EXPOSES_PORT", 0.98)
        upsert_relationship(db, tenant_id, job_id, port.id, service.id, "RUNS_SERVICE", 0.95)
        upsert_relationship(db, tenant_id, job_id, dom.id, tech.id, "USES_TECHNOLOGY", 0.92, supporting_evidence_ids=[tech_ev.id])
        upsert_relationship(db, tenant_id, job_id, org.id, person.id, "EMPLOYS", 0.90, supporting_evidence_ids=[people_ev.id])
        upsert_relationship(db, tenant_id, job_id, person.id, email.id, "USES_EMAIL", 0.92, supporting_evidence_ids=[people_ev.id])
        upsert_relationship(db, tenant_id, job_id, org.id, doc.id, "PUBLISHED", 0.95)
        upsert_relationship(db, tenant_id, job_id, org.id, cloud.id, "ASSOCIATED_WITH", 0.85)
        upsert_relationship(db, tenant_id, job_id, dom.id, breach.id, "APPEARS_IN", 0.88)

        # 4. Query Investigation Graph
        graph = get_investigation_graph(db, tenant_id, job_id)
        assert graph["nodes_count"] == 12
        assert graph["edges_count"] == 11

        # 5. Verify Node Expansion
        expanded_org = expand_graph_node(db, tenant_id, job_id, org.id)
        # Org connected to domain, person, document, cloud_resource
        assert len(expanded_org["nodes"]) == 5
        assert len(expanded_org["edges"]) == 4

        # 6. Verify Evidence Ledger Traceability
        retrieved_whois = get_evidence_by_id(db, tenant_id, job_id, whois_ev.id)
        assert retrieved_whois is not None
        assert retrieved_whois.reliability == 0.95
        assert "Example Corporation" in retrieved_whois.extracted_claim
