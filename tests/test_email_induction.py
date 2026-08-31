import pytest
from people.verifier import (
    induce_email_pattern,
    synthesize_candidate_email,
)


def test_induce_first_dot_last_pattern():
    observed = [
        "john.doe@acme.com",
        "jane.smith@acme.com",
        "michael.brown@acme.com",
        "info@acme.com",  # Generic should be ignored
    ]
    pattern_info = induce_email_pattern(observed, "acme.com")
    assert pattern_info["pattern_code"] == "first.last"
    assert pattern_info["pattern"] == "{first}.{last}@acme.com"
    assert pattern_info["confidence"] >= 90


def test_induce_flast_pattern():
    observed = [
        "jdoe@target.org",
        "jsmith@target.org",
        "mbrown@target.org",
    ]
    pattern_info = induce_email_pattern(observed, "target.org")
    assert pattern_info["pattern_code"] == "flast"
    assert pattern_info["pattern"] == "{f}{last}@target.org"


def test_synthesize_candidate_emails():
    email1 = synthesize_candidate_email("Alice Cooper", "first.last", "acme.com")
    assert email1 == "alice.cooper@acme.com"

    email2 = synthesize_candidate_email("Bob Marley", "flast", "acme.com")
    assert email2 == "bmarley@acme.com"

    email3 = synthesize_candidate_email("David Gilmour", "first_last", "pinkfloyd.com")
    assert email3 == "david_gilmour@pinkfloyd.com"
