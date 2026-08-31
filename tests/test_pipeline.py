import pytest
from storage.db import init_db, get_db_session, create_tenant, create_scan_job, get_scan_job, get_ai_report_for_job
from worker import execute_pipeline_for_job, _should_run_step


def test_should_run_step_logic():
    # From init -> all steps run
    assert _should_run_step("init", "1.company_resolve") is True
    assert _should_run_step("init", "5.fingerprint") is True

    # Checkpoint at step 5
    assert _should_run_step("5.fingerprint", "1.company_resolve") is False
    assert _should_run_step("5.fingerprint", "4.ports") is False
    assert _should_run_step("5.fingerprint", "5.fingerprint") is True
    assert _should_run_step("5.fingerprint", "10.report_writer") is True


def test_pipeline_execution_end_to_end(monkeypatch):
    init_db()
    with get_db_session() as db:
        tenant = create_tenant(db, "Pipeline Test Tenant")
        job = create_scan_job(db, tenant.id, "example.com")
        job_id = job.id
        tenant_id = tenant.id

    # Execute pipeline
    success = execute_pipeline_for_job(job_id, tenant_id, "example.com")
    assert success is True

    with get_db_session() as db:
        finished_job = get_scan_job(db, tenant_id, job_id)
        assert finished_job.status == "complete"
        assert finished_job.current_step == "completed"

        report = get_ai_report_for_job(db, tenant_id, job_id)
        assert report is not None
        assert "# Reconnaissance & Attack-Surface Assessment: example.com" in report.report_text
        assert len(report.prioritized_findings) > 0

        from storage.db import get_investigation_graph
        graph = get_investigation_graph(db, tenant_id, job_id)
        assert graph["nodes_count"] > 0
        assert graph["edges_count"] > 0

