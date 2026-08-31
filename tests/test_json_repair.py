import json
from ai.triage import parse_and_repair_json

def test_parse_and_repair_json_valid():
    sample = '{"executive_summary": "Clean", "prioritized_findings": []}'
    result = parse_and_repair_json(sample)
    assert result["executive_summary"] == "Clean"

def test_parse_and_repair_json_markdown_wrapped():
    sample = '```json\n{"executive_summary": "Wrapped in markdown", "prioritized_findings": []}\n```'
    result = parse_and_repair_json(sample)
    assert result["executive_summary"] == "Wrapped in markdown"

def test_parse_and_repair_json_truncated_string():
    # Simulated truncated JSON from reaching max_tokens
    sample = '{"executive_summary": "All good", "prioritized_findings": [{"id": "FIND-001", "title": "Exposed'
    result = parse_and_repair_json(sample)
    assert "executive_summary" in result
    assert len(result["prioritized_findings"]) == 1
