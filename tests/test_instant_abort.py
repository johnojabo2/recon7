import pytest
import threading
import asyncio
from unittest.mock import patch, MagicMock
from worker import (
    ScanAbortedException,
    _check_if_aborted,
    _checkpoint_step,
    execute_pipeline_dag_async,
)
from storage.models import ScanJob


def test_check_if_aborted_with_event():
    event = threading.Event()
    event.set()
    context = {"abort_event": event}

    with pytest.raises(ScanAbortedException):
        _check_if_aborted("tenant-1", "job-1", context)


def test_checkpoint_step_aborts_immediately():
    event = threading.Event()
    event.set()
    context = {"abort_event": event}

    with pytest.raises(ScanAbortedException):
        _checkpoint_step("tenant-1", "job-1", "1.company_resolve", context)


@pytest.mark.asyncio
async def test_execute_pipeline_instant_abort():
    with patch("worker.get_db_session") as mock_get_db, \
         patch("worker._sync_tenant_integrations_for_job"), \
         patch("worker.classify_target", return_value="domain"), \
         patch("worker.extract_root_domain", return_value="example.com"), \
         patch("worker.get_findings_for_job", return_value=[]), \
         patch("worker.update_scan_job"), \
         patch("worker.step_1_company_resolve"), \
         patch("worker.step_2_subdomains"), \
         patch("worker.step_8_people"):

        mock_db = MagicMock()
        mock_get_db.return_value.__enter__.return_value = mock_db

        mock_job = MagicMock()
        mock_job.id = "job-abort-123"
        mock_job.tenant_id = "tenant-1"
        mock_job.status = "cancelled"
        mock_job.current_step = "aborted"
        mock_job.scan_params = {}
        mock_job.scan_profile = "standard"

        mock_db.query.return_value.filter.return_value.first.return_value = mock_job

        # Run DAG - must abort immediately (< 0.5s)
        success = await execute_pipeline_dag_async("job-abort-123", "tenant-1", "example.com")
        assert success is False
