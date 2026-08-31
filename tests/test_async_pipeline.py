import time
import pytest
import asyncio
import threading
from unittest.mock import patch, MagicMock
from storage.db import init_db, get_db_session, create_tenant, create_scan_job, get_scan_job
from worker import execute_pipeline_for_job, execute_pipeline_dag_async, _should_run_step, PIPELINE_STEPS


def test_async_pipeline_concurrency():
    """
    Verifies that independent stages (Company, Subdomains, People) run concurrently
    in parallel threads, not sequentially blocking each other.
    """
    events = []
    
    def mock_company(tenant_id, job_id, context, lock):
        events.append(("company_start", time.time()))
        time.sleep(0.3)
        with lock:
            context["company_info"] = {"org_name": "Async Test Corp", "primary_ips": ["1.2.3.4"]}
        events.append(("company_end", time.time()))

    def mock_subs(tenant_id, job_id, context, lock):
        events.append(("subs_start", time.time()))
        time.sleep(0.3)
        with lock:
            context["subdomains"] = [{"subdomain": "api.test.com", "sources": ["mock"]}]
        events.append(("subs_end", time.time()))

    def mock_ip_resolve(tenant_id, job_id, context, lock):
        events.append(("ip_start", time.time()))
        time.sleep(0.1)
        with lock:
            context["ip_resolutions"] = [{"subdomain": "api.test.com", "ips": ["1.2.3.4"], "is_cdn": False}]
        events.append(("ip_end", time.time()))

    def mock_ports(tenant_id, job_id, context, lock):
        events.append(("ports_start", time.time()))
        time.sleep(0.2)
        with lock:
            context["ports"] = [{"ip": "1.2.3.4", "port": 443, "service": "https"}]
        events.append(("ports_end", time.time()))

    def mock_fp(tenant_id, job_id, context, lock):
        events.append(("fp_start", time.time()))
        time.sleep(0.2)
        with lock:
            context["fingerprints"] = [{"url": "https://api.test.com", "technologies": [{"name": "Nginx"}]}]
            context["technologies"] = [{"name": "Nginx"}]
        events.append(("fp_end", time.time()))

    def mock_nuclei(tenant_id, job_id, context, lock):
        events.append(("nuclei_start", time.time()))
        time.sleep(0.1)
        with lock:
            context["vulns"] = []
        events.append(("nuclei_end", time.time()))

    def mock_cve(tenant_id, job_id, context, lock):
        events.append(("cve_start", time.time()))
        time.sleep(0.1)
        events.append(("cve_end", time.time()))

    def mock_people(tenant_id, job_id, context, lock):
        events.append(("people_start", time.time()))
        time.sleep(0.3)
        with lock:
            context["people"] = {"employees": []}
        events.append(("people_end", time.time()))

    def mock_triage(tenant_id, job_id, context, lock):
        with lock:
            context["triage"] = {"prioritized_findings": [], "executive_summary": "Clean"}

    def mock_report(tenant_id, job_id, context, lock):
        with lock:
            context["report_text"] = "# Mock Report"

    init_db()
    from core.scope import extract_root_domain
    extract_root_domain("asynctest.com")  # Warm up tldextract suffix cache

    with get_db_session() as db:
        tenant = create_tenant(db, "Async Concurrency Test Tenant")
        job = create_scan_job(db, tenant.id, "asynctest.com")
        job_id = job.id
        tenant_id = tenant.id

    t_start = time.time()
    with patch("worker.step_1_company_resolve", side_effect=mock_company), \
         patch("worker.step_2_subdomains", side_effect=mock_subs), \
         patch("worker.step_3_ip_resolve", side_effect=mock_ip_resolve), \
         patch("worker.step_4_ports", side_effect=mock_ports), \
         patch("worker.step_5_fingerprint", side_effect=mock_fp), \
         patch("worker.step_6_nuclei", side_effect=mock_nuclei), \
         patch("worker.step_7_cve", side_effect=mock_cve), \
         patch("worker.step_8_people", side_effect=mock_people), \
         patch("worker.step_9_ai_triage", side_effect=mock_triage), \
         patch("worker.step_10_report", side_effect=mock_report):

        t_pipeline_start = time.time()
        success = execute_pipeline_for_job(job_id, tenant_id, "asynctest.com")
        pipeline_duration = time.time() - t_pipeline_start

    for name, ts in events:
        print(f"EVENT {name} at {ts - t_pipeline_start:.3f}s")
    assert success is True

    # Check that execution time is significantly LESS than the sequential sum of sleeps (1.6s):
    # In concurrent DAG: max(company=0.3, subs=0.3) + ip=0.1 + max(ports=0.2, fp=0.2 + nuclei=0.1) ~= 0.7s
    assert pipeline_duration < 1.1, f"Pipeline execution took {pipeline_duration:.2f}s, expected < 1.1s"


    # Verify that company and subdomains started within 50ms of each other (parallel start)
    event_dict = dict(events)
    company_start = event_dict.get("company_start", 0)
    subs_start = event_dict.get("subs_start", 0)
    assert abs(company_start - subs_start) < 0.1, "Company and Subdomain steps did not launch in parallel!"

    # Verify final state
    with get_db_session() as db:
        finished = get_scan_job(db, tenant_id, job_id)
        assert finished.status == "complete"
        assert finished.current_step == "completed"
