import pytest
from people.verifier import (
    is_role_mailbox,
    induce_email_pattern,
    synthesize_candidate_email,
    batch_verify_emails,
)


def test_is_role_mailbox():
    role_boxes = [
        "info@acme.com",
        "contactus@acme.com",
        "investorrelations@acme.com",
        "careers@acme.com",
        "support@acme.com",
        "nuims@nnpcgroup.com",
        "netco.enquiries@nnpcgroup.com",
        "nnpcretailcontact@nnpcgroup.com",
    ]
    for r in role_boxes:
        assert is_role_mailbox(r) is True, f"Expected '{r}' to be recognized as a role mailbox"

    human_boxes = [
        "john.doe@acme.com",
        "sarah.connor@cyberdyne.com",
        "b.ojulari@nnpcgroup.com",
        "midris@nnpcgroup.com",
    ]
    for h in human_boxes:
        assert is_role_mailbox(h) is False, f"Expected '{h}' to be recognized as human mailbox"


def test_induce_pattern_zero_human_seeds_unverified_default():
    # Only role mailboxes observed
    observed = [
        "contactus@target.org",
        "investorrelations@target.org",
        "info@target.org",
        "careers@target.org",
    ]
    pattern_info = induce_email_pattern(observed, "target.org")
    assert pattern_info["status"] == "UNVERIFIED_DEFAULT"
    assert pattern_info["confidence"] == 45
    assert pattern_info["human_seed_count"] == 0
    assert pattern_info["role_mailbox_count"] == 4


def test_induce_pattern_with_human_seeds():
    observed = [
        "info@target.org",              # Role mailbox (ignored)
        "support@target.org",           # Role mailbox (ignored)
        "john.doe@target.org",          # Human seed 1
        "jane.smith@target.org",        # Human seed 2
        "alex.turner@target.org",       # Human seed 3
    ]
    pattern_info = induce_email_pattern(observed, "target.org")
    assert pattern_info["status"] == "HIGH_CONFIDENCE_INDUCED"
    assert pattern_info["pattern_code"] == "first.last"
    assert pattern_info["human_seed_count"] == 3
    assert pattern_info["confidence"] >= 90


def test_batch_verify_skips_synthetic_emails_for_corporate_handles():
    records = [
        {
            "name": "Bashir Bayo Ojulari",
            "title": "Group CEO",
            "is_human": True,
            "entity_type": "human",
        },
        {
            "name": "NNPC, Inc.",
            "title": "Official Directory",
            "is_human": False,
            "entity_type": "corporate_directory",
        },
        {
            "name": "Linkedin Iran",
            "title": "Regional Handle",
            "is_human": False,
            "entity_type": "regional_account",
        },
    ]

    verified = batch_verify_emails(records, "nnpcgroup.com")
    ceo = next(p for p in verified if p["name"] == "Bashir Bayo Ojulari")
    assert ceo.get("email") is not None
    assert "@nnpcgroup.com" in ceo["email"]

    nnpc_corp = next(p for p in verified if p["name"] == "NNPC, Inc.")
    assert nnpc_corp.get("email") in ["", None]
    assert nnpc_corp.get("verification_status") == "Corporate Handle"

    iran_corp = next(p for p in verified if p["name"] == "Linkedin Iran")
    assert iran_corp.get("email") in ["", None]
    assert iran_corp.get("verification_status") == "Corporate Handle"
