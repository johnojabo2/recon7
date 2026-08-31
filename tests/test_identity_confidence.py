import pytest
from core.confidence import calculate_confidence, get_source_reliability
from core.identity.resolution import resolve_identities, ResolvedPerson


def test_confidence_calculation_corroboration():
    # Single source
    conf_1, exp_1 = calculate_confidence(sources=["dns"])
    assert conf_1 >= 0.85
    assert exp_1["level"] == "confirmed"
    assert exp_1["corroboration_count"] == 1

    # Multiple independent sources should boost confidence
    conf_multi, exp_multi = calculate_confidence(sources=["official_website", "dns", "corporate_document"])
    assert conf_multi >= conf_1
    assert exp_multi["corroboration_count"] == 3
    assert exp_multi["contradiction_count"] == 0


def test_confidence_contradiction_penalty():
    # With contradictions
    conf_clean, _ = calculate_confidence(sources=["search_engine_snippet"], contradiction_count=0)
    conf_contra, exp_contra = calculate_confidence(sources=["search_engine_snippet"], contradiction_count=1)

    assert conf_contra < conf_clean
    assert exp_contra["level"] == "possible_match"
    assert exp_contra["contradiction_penalty"] > 0


def test_identity_resolution_merges_matching_profiles():
    candidates = [
        {
            "name": "Jane Doe",
            "email": "jane.doe@acme.corp",
            "title": "Security Lead",
            "org": "Acme Corp",
            "source": "official_website",
        },
        {
            "name": "Jane A. Doe",
            "email": "jane.doe@acme.corp",
            "username": "jdoe_sec",
            "org": "Acme Corp",
            "source": "direct_profile",
            "profile_url": "https://linkedin.com/in/janedoe",
        },
    ]

    resolved = resolve_identities(candidates, target_org="Acme Corp")
    # Should merge into 1 resolved person because emails and compatible names match
    assert len(resolved) == 1
    person = resolved[0]
    assert person.primary_name in ["Jane Doe", "Jane A. Doe"]
    assert "jane.doe@acme.corp" in person.emails
    assert "jdoe_sec" in person.usernames
    assert "Security Lead" in person.job_titles
    assert len(person.supporting_evidence) >= 2
    assert person.confidence >= 0.85
    assert person.status in ["confirmed", "likely"]


def test_identity_resolution_contradiction_separation():
    # Spec Section 14: Candidate A in Lagos, Candidate B in Canada with different org
    candidates = [
        {
            "name": "John Smith",
            "org": "Example Corp",
            "location": "Lagos",
            "source": "official_website",
        },
        {
            "name": "John Smith",
            "org": "Another Global Corp",
            "location": "Canada",
            "source": "unverified_directory",
        },
    ]

    resolved = resolve_identities(candidates, target_org="Example Corp")
    # Must NOT merge merely because names match!
    assert len(resolved) == 2
    
    # One of them should have contradiction recorded
    statuses = [p.status for p in resolved]
    assert "possible_match" in statuses
    
    contra_person = next(p for p in resolved if p.status == "possible_match")
    assert len(contra_person.contradicting_evidence) > 0
    assert "Conflicting" in contra_person.contradicting_evidence[0]


def test_department_and_hvt_classification():
    candidates = [
        {
            "name": "Sarah Connor",
            "title": "Chief Information Security Officer (CISO)",
            "email": "sarah.connor@cyberdyne.com",
            "source": "official_website",
        },
        {
            "name": "Miles Dyson",
            "title": "Lead DevOps Architect",
            "email": "miles.dyson@cyberdyne.com",
            "source": "official_website",
        },
        {
            "name": "John Connor",
            "title": "Senior Talent Acquisition Recruiter",
            "email": "john.connor@cyberdyne.com",
            "source": "wayback_archive",
        }
    ]

    resolved = resolve_identities(candidates, target_org="Cyberdyne")
    assert len(resolved) == 3

    ciso = next(p for p in resolved if p.primary_name == "Sarah Connor")
    assert ciso.is_hvt is True
    assert ciso.department == "Cybersecurity & SecOps"
    assert ciso.seniority == "Executive / C-Suite"
    assert ciso.temporal_status == "active"

    devops = next(p for p in resolved if p.primary_name == "Miles Dyson")
    assert devops.is_hvt is True
    assert devops.department == "DevOps & Infrastructure"

    recruiter = next(p for p in resolved if p.primary_name == "John Connor")
    assert recruiter.is_hvt is False
    assert recruiter.is_het is True
    assert recruiter.department == "HR & Recruiting"
    assert recruiter.temporal_status == "historical"

