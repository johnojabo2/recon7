import pytest
from storage.db import (
    init_db,
    get_db_session,
    create_tenant,
    create_scan_job,
    add_finding,
    get_findings_for_job,
    get_tenant_dashboard,
    get_scan_job,
)


def test_tenant_data_isolation():
    init_db()
    with get_db_session() as db:
        # Create two distinct tenants
        tenant_a = create_tenant(db, "Tenant Alpha")
        tenant_b = create_tenant(db, "Tenant Beta")

        # Create scan job and findings for Tenant A
        job_a = create_scan_job(db, tenant_a.id, "target-a.com")
        add_finding(
            db,
            tenant_id=tenant_a.id,
            scan_job_id=job_a.id,
            finding_type="subdomain",
            data={"subdomain": "secret.target-a.com"},
            severity="info",
            source_tool="subfinder",
        )

        # Create scan job and findings for Tenant B
        job_b = create_scan_job(db, tenant_b.id, "target-b.com")
        add_finding(
            db,
            tenant_id=tenant_b.id,
            scan_job_id=job_b.id,
            finding_type="vuln",
            data={"vuln": "CVE-2024-1234"},
            severity="critical",
            source_tool="nuclei",
        )

        # Verify Tenant A cannot access Tenant B findings
        findings_for_a = get_findings_for_job(db, tenant_id=tenant_a.id, scan_job_id=job_b.id)
        assert len(findings_for_a) == 0

        # Verify Tenant B cannot access Tenant A scan job
        job_access_b = get_scan_job(db, tenant_id=tenant_b.id, job_id=job_a.id)
        assert job_access_b is None

        # Verify dashboards are strictly scoped
        dash_a = get_tenant_dashboard(db, tenant_id=tenant_a.id)
        assert dash_a["scans"]["total"] == 1
        assert dash_a["findings_count"] == 1
        assert dash_a["severity_distribution"]["critical"] == 0

        dash_b = get_tenant_dashboard(db, tenant_id=tenant_b.id)
        assert dash_b["scans"]["total"] == 1
        assert dash_b["findings_count"] == 1
        assert dash_b["severity_distribution"]["critical"] == 1
