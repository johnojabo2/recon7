import pytest
from unittest.mock import patch, MagicMock
from core.google_search import query_google_search, is_google_search_available
from core.config import settings


def test_is_google_search_available():
    with patch.object(settings, "GOOGLE_SEARCH_API_KEY", "test_key"), \
         patch.object(settings, "GOOGLE_SEARCH_ENGINE_ID", "test_cx"):
        assert is_google_search_available() is True


def test_query_google_search_mocked():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "items": [
            {
                "title": "Jane Doe - Chief Technology Officer - Acme | LinkedIn",
                "link": "https://www.linkedin.com/in/janedoe",
                "snippet": "View Jane Doe's profile on LinkedIn, a professional community...",
            }
        ]
    }

    with patch.object(settings, "GOOGLE_SEARCH_API_KEY", "test_key"), \
         patch.object(settings, "GOOGLE_SEARCH_ENGINE_ID", "test_cx"), \
         patch("httpx.Client.get", return_value=mock_resp):
        results = query_google_search("site:linkedin.com/in/ Acme", num=5)
def test_is_serpapi_available():
    from core.google_search import is_serpapi_available
    with patch.object(settings, "SERPAPI_API_KEY", "serp_secret_123"):
        assert is_serpapi_available() is True


def test_serpapi_query_parsing_and_knowledge_graph():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "organic_results": [
            {
                "title": "Jane Doe - Chief Technology Officer - Acme | LinkedIn",
                "link": "https://www.linkedin.com/in/janedoe",
                "snippet": "View Jane Doe's profile on LinkedIn...",
            }
        ],
        "knowledge_graph": {
            "title": "Acme Corporation",
            "type": "Software Company",
            "description": "Acme is a global cybersecurity leader founded in 2012.",
            "website": "https://acme.example.com",
        }
    }

    with patch.object(settings, "SERPAPI_API_KEY", "test_serp_key"), \
         patch("httpx.Client.get", return_value=mock_resp):
        # use_cache=False to test pure parsing
        results = query_google_search("site:linkedin.com/in/ Acme Corp Test Unique", num=5, use_cache=False)
        assert len(results) == 2  # Knowledge graph prepended + organic result
        assert "[Knowledge Graph]" in results[0]["title"]
        assert results[0]["link"] == "https://acme.example.com"
        assert "Jane Doe" in results[1]["title"]


def test_persistent_search_cache_hit_and_miss():
    import uuid
    from storage.db import init_db
    init_db()

    unique_query = f"cache_test_query_{uuid.uuid4().hex}"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "organic_results": [
            {
                "title": "Cached Target Result",
                "link": "https://example.com/cached",
                "snippet": "Snippet content for cache verification",
            }
        ]
    }

    # First call: Cache MISS -> calls SerpAPI and saves to SQLite
    with patch.object(settings, "SERPAPI_API_KEY", "test_serp_key"), \
         patch("httpx.Client.get", return_value=mock_resp) as mock_get:
        res1 = query_google_search(unique_query, use_cache=True)
        assert len(res1) == 1
        assert res1[0]["title"] == "Cached Target Result"
        assert mock_get.call_count == 1

    # Second call: Cache HIT -> returns from SQLite without calling HTTP
    with patch.object(settings, "SERPAPI_API_KEY", "test_serp_key"), \
         patch("httpx.Client.get", side_effect=Exception("Should not make HTTP request on Cache HIT")) as mock_fail_get:
        res2 = query_google_search(unique_query, use_cache=True)
        assert len(res2) == 1
        assert res2[0]["title"] == "Cached Target Result"
        assert res2[0]["link"] == "https://example.com/cached"
        mock_fail_get.assert_not_called()

