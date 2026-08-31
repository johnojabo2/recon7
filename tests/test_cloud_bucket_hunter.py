import pytest
from recon.exposure_engine import check_cloud_storage_exposure, CLOUD_PATTERNS


def test_cloud_patterns_permutation_coverage():
    providers = {p["provider"] for p in CLOUD_PATTERNS}
    assert "AWS S3" in providers
    assert "Azure Blob" in providers
    assert "Google Cloud Storage" in providers
    assert "DigitalOcean Spaces" in providers
    assert len(CLOUD_PATTERNS) >= 20


def test_check_cloud_storage_short_slug_ignored():
    assert check_cloud_storage_exposure("ab") == []
    assert check_cloud_storage_exposure("x.com") == []
