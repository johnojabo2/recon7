import pytest
from fastapi.testclient import TestClient
from main import app
from storage.db import (
    get_db_session,
    init_db,
    create_tenant,
    create_scan_job,
    upsert_entity,
    add_evidence,
    upsert_relationship,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


def test_graph_and_evidence_api_endpoints():
    with get_db_session() as db:
        tenant_id = "default-tenant"
        job = create_scan_job(db, tenant_id, "graph-test.com")

        # Ingest test graph entities
        org = upsert_entity(db, tenant_id, job.id, "organization:graph_inc", "organization", "Graph Inc")
        dom = upsert_entity(db, tenant_id, job.id, "domain:graph-test.com", "domain", "graph-test.com")
        sub = upsert_entity(db, tenant_id, job.id, "subdomain:api.graph-test.com", "subdomain", "api.graph-test.com")
        ip = upsert_entity(db, tenant_id, job.id, "ip:198.51.100.1", "ip", "198.51.100.1")
        cloud = upsert_entity(db, tenant_id, job.id, "cloud_resource:s3_bucket", "cloud_resource", "AWS S3: DISCOVERED")
        doc = upsert_entity(db, tenant_id, job.id, "document:whitepaper", "document", "whitepaper.pdf")

        # Ingest evidence
        ev = add_evidence(
            db,
            tenant_id=tenant_id,
            scan_job_id=job.id,
            source="dns",
            source_type="network_probe",
            collector="dns_sensor",
            extracted_claim="api.graph-test.com resolves to 198.51.100.1",
            reliability=1.0,
        )

        # Ingest relationships
        upsert_relationship(db, tenant_id, job.id, org.id, dom.id, "OWNS", 0.95, supporting_evidence_ids=[ev.id])
        upsert_relationship(db, tenant_id, job.id, dom.id, sub.id, "HAS_SUBDOMAIN", 1.0, supporting_evidence_ids=[ev.id])
        upsert_relationship(db, tenant_id, job.id, sub.id, ip.id, "RESOLVES_TO", 1.0, supporting_evidence_ids=[ev.id])

        job_id = job.id
        ev_id = ev.id
        dom_id = dom.id
        org_id = org.id
        ip_id = ip.id
        doc_id = doc.id

    login_res = client.post(
        "/auth/login",
        json={"email": "admin@recon7.io", "password": "Admin@12345"},
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": tenant_id}

    # 1. Test /scan/{job_id}/graph
    resp = client.get(f"/scan/{job_id}/graph", headers=headers)
    assert resp.status_code == 200
    graph = resp.json()
    assert graph["scan_job_id"] == job_id
    assert graph["nodes_count"] >= 6
    assert graph["edges_count"] >= 3
    assert any(n["canonical_id"] == "domain:graph-test.com" for n in graph["nodes"])

    # 2. Test /scan/{job_id}/graph/expand
    resp_expand = client.get(f"/scan/{job_id}/graph/expand?entity_id={dom_id}", headers=headers)
    assert resp_expand.status_code == 200
    expand_data = resp_expand.json()
    assert len(expand_data["nodes"]) >= 2
    assert len(expand_data["edges"]) >= 2

    # 3. Test /scan/{job_id}/graph/path (Connected entities: org -> dom -> sub -> ip)
    resp_path = client.get(
        f"/scan/{job_id}/graph/path?source_id={org_id}&target_id={ip_id}",
        headers=headers,
    )
    assert resp_path.status_code == 200
    path_data = resp_path.json()
    assert path_data["found"] is True
    assert path_data["path_length"] == 3
    assert len(path_data["nodes"]) == 4
    assert len(path_data["edges"]) == 3
    assert path_data["nodes"][0]["id"] == org_id
    assert path_data["nodes"][-1]["id"] == ip_id

    # Test disconnected path: doc is disconnected from ip
    resp_nopath = client.get(
        f"/scan/{job_id}/graph/path?source_id={doc_id}&target_id={ip_id}",
        headers=headers,
    )
    assert resp_nopath.status_code == 200
    nopath_data = resp_nopath.json()
    assert nopath_data["found"] is False
    assert nopath_data["path_length"] == -1

    # 4. Test /scan/{job_id}/evidence/{evidence_id}
    resp_ev = client.get(f"/scan/{job_id}/evidence/{ev_id}", headers=headers)
    assert resp_ev.status_code == 200
    ev_data = resp_ev.json()
    assert ev_data["source"] == "dns"
    assert ev_data["reliability"] == 1.0
    assert "resolves to 198.51.100.1" in ev_data["extracted_claim"]

    # 5. Test /scan/{job_id}/exposures
    resp_exp = client.get(f"/scan/{job_id}/exposures", headers=headers)
    assert resp_exp.status_code == 200
    exposures = resp_exp.json()
    assert len(exposures) >= 1
    assert any(e["type"] == "cloud_resource" for e in exposures)

    # 6. Test /scan/{job_id}/documents
    resp_doc = client.get(f"/scan/{job_id}/documents", headers=headers)
    assert resp_doc.status_code == 200
    docs = resp_doc.json()
    assert len(docs) >= 1
    assert any("whitepaper" in d["canonical_id"] for d in docs)

