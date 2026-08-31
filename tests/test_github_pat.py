import pytest
import os
from unittest.mock import patch, MagicMock
from core.config import settings
from people.github_enum import get_github_headers, enumerate_github_commits


def test_github_headers_default_unauthenticated():
    """Verify that absent token produces default unauthenticated headers without Authorization."""
    with patch.object(settings, "GITHUB_TOKEN", None), patch.dict(os.environ, {}, clear=True):
        headers = get_github_headers(token=None)
        assert "Authorization" not in headers
        assert headers["Accept"] == "application/vnd.github.v3+json"
        assert headers["User-Agent"] == "R7-ReconEngine/1.0"


def test_github_headers_with_explicit_pat():
    """Verify that providing an explicit PAT token adds the Bearer / token authorization header."""
    headers = get_github_headers(token="ghp_testpersonalaccesstoken123456789")
    assert "Authorization" in headers
    assert headers["Authorization"] == "Bearer ghp_testpersonalaccesstoken123456789"
    assert headers["X-GitHub-Api-Version"] == "2022-11-28"


def test_github_headers_from_settings():
    """Verify that settings.GITHUB_TOKEN is automatically used when token is not passed explicitly."""
    with patch.object(settings, "GITHUB_TOKEN", "github_pat_11AAAAAA_abcdef"):
        headers = get_github_headers(token=None)
        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer github_pat_11AAAAAA_abcdef"
        assert headers["X-GitHub-Api-Version"] == "2022-11-28"


def test_enumerate_github_commits_mocked_success():
    """Verify commit and member parsing with mocked GitHub API response."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "items": [
            {
                "commit": {
                    "author": {
                        "name": "Jane Doe",
                        "email": "jane.doe@example.com",
                    }
                },
                "author": {
                    "html_url": "https://github.com/janedoe"
                }
            }
        ]
    }

    with patch("httpx.Client.get", return_value=mock_resp):
        results = enumerate_github_commits("example.com", org_name="Example", token="ghp_dummy123")
        assert len(results) >= 1
        assert results[0]["name"] == "Jane Doe"
        assert results[0]["email"] == "jane.doe@example.com"
        assert results[0]["source"] == "github_commits"
