import pytest
from people.linkedin_enum import (
    clean_human_name,
    is_valid_human_name,
    _parse_linkedin_title_and_slug,
    JOB_ROLE_WORDS,
)
from people.search_dork import _extract_name_and_role_from_text


def test_job_roles_rejected_as_human_names():
    # Technical & Departmental roles must NEVER be classified as a human person's name
    assert clean_human_name("Media EO") == ""
    assert clean_human_name("Media Eo") == ""
    assert clean_human_name("Devops Engineer") == ""
    assert clean_human_name("People &amp; Culture Engineer") == ""
    assert clean_human_name("Talent Strategy") == ""
    assert clean_human_name("Chief Technology Officer") == ""
    assert clean_human_name("Lead Cloud Architect") == ""
    assert clean_human_name("Frontend Developer") == ""
    assert clean_human_name("Head of Security") == ""
    assert clean_human_name("Product Designer") == ""


def test_genuine_human_names_accepted():
    assert clean_human_name("John Ojabo") == "John Ojabo"
    assert clean_human_name("Oche Ojabo") == "Oche Ojabo"
    assert clean_human_name("Jane Doe") == "Jane Doe"
    assert clean_human_name("Frank Miller") == "Frank Miller"


def test_reversed_linkedin_title_disambiguation():
    # 1. Reversed format: [Role] - [Name] | LinkedIn
    name, role = _parse_linkedin_title_and_slug(
        "Media EO - Oche Ojabo | LinkedIn",
        "https://linkedin.com/in/oche-ojabo-12345",
        "Ojabo",
    )
    assert name == "Oche Ojabo"
    assert role == "Media EO"

    # 2. Reversed format: [Role] - [Name] | LinkedIn with engineering title
    name, role = _parse_linkedin_title_and_slug(
        "Devops Engineer - John Ojabo | LinkedIn",
        "https://linkedin.com/in/john-ojabo-67890",
        "Ojabo",
    )
    assert name == "John Ojabo"
    assert role == "Devops Engineer"

    # 3. Standard format: [Name] - [Role] | LinkedIn
    name, role = _parse_linkedin_title_and_slug(
        "John Ojabo - Devops Engineer - Ojabo | LinkedIn",
        "https://linkedin.com/in/john-ojabo",
        "Ojabo",
    )
    assert name == "John Ojabo"
    assert role == "Devops Engineer"


def test_search_dork_name_role_extraction():
    name, role = _extract_name_and_role_from_text(
        "Devops Engineer - John Ojabo | LinkedIn",
        "Ojabo",
    )
    assert name == "John Ojabo"
    assert role == "Devops Engineer"

    name, role = _extract_name_and_role_from_text(
        "Oche Ojabo - Media Director - Ojabo",
        "Ojabo",
    )
    assert name == "Oche Ojabo"
    assert role == "Media Director"
