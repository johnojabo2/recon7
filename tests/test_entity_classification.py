import pytest
from core.identity.resolution import (
    classify_entity_type,
    is_valid_human_name,
    resolve_identities_and_footprint,
)


def test_classify_human_names():
    humans = [
        "Bashir Bayo Ojulari",
        "Maryamu Idris",
        "Jane Chen",
        "Nicolas Foucart",
        "Sarah Connor",
        "Miles Dyson",
    ]
    for h in humans:
        entity_type, reason = classify_entity_type(h)
        assert entity_type == "human", f"Expected '{h}' to be human, got {entity_type} ({reason})"
        assert is_valid_human_name(h) is True


def test_classify_corporate_and_regional_handles():
    # Corporate Handles / Suffixes
    entity_type, _ = classify_entity_type("NNPC, Inc.")
    assert entity_type in ["corporate_directory", "subsidiary_brand"]
    assert is_valid_human_name("NNPC, Inc.") is False

    entity_type, _ = classify_entity_type("Antan Producing Limited")
    assert entity_type in ["subsidiary_brand", "corporate_directory"]
    assert is_valid_human_name("Antan Producing Limited") is False

    # Regional Platform Accounts
    entity_type, _ = classify_entity_type("Linkedin Iran")
    assert entity_type == "regional_account"
    assert is_valid_human_name("Linkedin Iran") is False

    # Scraper Noise
    entity_type, _ = classify_entity_type("Organization Staff")
    assert entity_type == "system_bot"
    assert is_valid_human_name("Organization Staff") is False

    entity_type, _ = classify_entity_type("Official Corporate Website Directory")
    assert entity_type == "corporate_directory"


def test_resolve_identities_and_footprint_separation():
    candidates = [
        {
            "name": "Bashir Bayo Ojulari",
            "title": "Group CEO",
            "profile_url": "https://ng.linkedin.com/in/bashir-bayo-ojulari-bbo",
            "source": "linkedin",
        },
        {
            "name": "NNPC, Inc.",
            "title": "Official Directory",
            "profile_url": "https://nnpcgroup.com/contact",
            "source": "corporate_website",
        },
        {
            "name": "Linkedin Iran",
            "title": "Regional Office",
            "profile_url": "https://ir.linkedin.com/in/nnpc-iran",
            "source": "linkedin",
        },
        {
            "name": "Maryamu Idris",
            "title": "Managing Director",
            "profile_url": "https://ng.linkedin.com/in/maryamu-idris",
            "source": "linkedin",
        },
    ]

    result = resolve_identities_and_footprint(candidates, target_org="NNPC")
    resolved_humans = result["resolved_persons"]
    unresolved_footprint = result["unresolved_footprint"]

    assert len(resolved_humans) == 2
    human_names = [p.primary_name for p in resolved_humans]
    assert "Bashir Bayo Ojulari" in human_names
    assert "Maryamu Idris" in human_names

    assert len(unresolved_footprint) == 2
    footprint_names = [f["name"] for f in unresolved_footprint]
    assert "NNPC, Inc." in footprint_names
    assert "Linkedin Iran" in footprint_names
