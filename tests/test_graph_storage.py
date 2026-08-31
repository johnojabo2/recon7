import pytest
from storage.db import (
    get_db_session,
    init_db,
    create_tenant,
    create_scan_job,
    upsert_entity,
    add_evidence,
    upsert_relationship,
    get_investigation_graph,
    expand_graph_node,
    get_evidence_by_id,
)


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


def test_graph_and_evidence_ledger_lifecycle():
    with get_db_session() as db:
        # Create tenant and scan job
        tenant = create_tenant(db, name="Test Graph Tenant")
        job = create_scan_job(db, tenant_id=tenant.id, target_domain="example.com", scan_profile="deep")

        # 1. Upsert entities
        org = upsert_entity(
            db,
            tenant_id=tenant.id,
            scan_job_id=job.id,
            canonical_id="organization:example_corp",
            entity_type="organization",
            label="Example Corp",
            properties={"country": "US", "industry": "Technology"},
        )

        domain = upsert_entity(
            db,
            tenant_id=tenant.id,
            scan_job_id=job.id,
            canonical_id="domain:example.com",
            entity_type="domain",
            label="example.com",
            properties={"root": "example.com"},
        )

        subdomain = upsert_entity(
            db,
            tenant_id=tenant.id,
            scan_job_id=job.id,
            canonical_id="subdomain:api.example.com",
            entity_type="subdomain",
            label="api.example.com",
            properties={"parent": "example.com"},
        )

        ip = upsert_entity(
            db,
            tenant_id=tenant.id,
            scan_job_id=job.id,
            canonical_id="ip:203.0.113.10",
            entity_type="ip",
            label="203.0.113.10",
            properties={"asn": "AS15169", "cloud": "GCP"},
        )

        assert org.id is not None
        assert domain.id is not None
        assert subdomain.id is not None
        assert ip.id is not None

        # 2. Test Canonical Deduplication: upserting same canonical_id updates rather than duplicates
        domain_again = upsert_entity(
            db,
            tenant_id=tenant.id,
            scan_job_id=job.id,
            canonical_id="domain:example.com",
            entity_type="domain",
            label="example.com",
            properties={"registrar": "MarkMonitor"},
        )
        assert domain.id == domain_again.id
        assert domain_again.properties.get("registrar") == "MarkMonitor"
        assert domain_again.properties.get("root") == "example.com"

        # 3. Create Evidence
        whois_ev = add_evidence(
            db,
            tenant_id=tenant.id,
            scan_job_id=job.id,
            source="whois",
            source_type="public_document",
            collector="whois_sensor",
            extracted_claim="Domain example.com is registered to Example Corp",
            reliability=0.95,
        )

        dns_ev = add_evidence(
            db,
            tenant_id=tenant.id,
            scan_job_id=job.id,
            source="dns",
            source_type="network_probe",
            collector="dns_sensor",
            extracted_claim="api.example.com resolves to 203.0.113.10",
            reliability=1.0,
        )

        assert whois_ev.id is not None
        assert dns_ev.id is not None

        # 4. Connect Entities with Evidence-backed Relationships
        rel1 = upsert_relationship(
            db,
            tenant_id=tenant.id,
            scan_job_id=job.id,
            source_entity_id=org.id,
            target_entity_id=domain.id,
            relationship_type="OWNS",
            confidence=0.95,
            status="confirmed",
            supporting_evidence_ids=[whois_ev.id],
        )

        rel2 = upsert_relationship(
            db,
            tenant_id=tenant.id,
            scan_job_id=job.id,
            source_entity_id=domain.id,
            target_entity_id=subdomain.id,
            relationship_type="HAS_SUBDOMAIN",
            confidence=1.0,
            status="confirmed",
            supporting_evidence_ids=[dns_ev.id],
        )

        rel3 = upsert_relationship(
            db,
            tenant_id=tenant.id,
            scan_job_id=job.id,
            source_entity_id=subdomain.id,
            target_entity_id=ip.id,
            relationship_type="RESOLVES_TO",
            confidence=1.0,
            status="confirmed",
            supporting_evidence_ids=[dns_ev.id],
        )

        # 5. Query Graph
        graph = get_investigation_graph(db, tenant_id=tenant.id, scan_job_id=job.id)
        assert graph["nodes_count"] == 4
        assert graph["edges_count"] == 3

        # 6. Test Node Expansion
        expanded = expand_graph_node(db, tenant_id=tenant.id, scan_job_id=job.id, entity_id=domain.id)
        # Connected to org (OWNS) and subdomain (HAS_SUBDOMAIN)
        assert len(expanded["nodes"]) == 3
        assert len(expanded["edges"]) == 2

        # 7. Test Evidence Retrieval
        retrieved_ev = get_evidence_by_id(db, tenant_id=tenant.id, scan_job_id=job.id, evidence_id=whois_ev.id)
        assert retrieved_ev is not None
        assert retrieved_ev.source == "whois"
        assert retrieved_ev.reliability == 0.95
