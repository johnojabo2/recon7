import pytest
from people.subsidiaries import (
    evaluate_subsidiary_relationship,
    discover_corporate_subsidiaries,
    VENDOR_BLACKLIST,
)


def test_vendor_blacklist_exclusion():
    for vendor in ["google.com", "cloudflare.com", "salesforce.com", "twitter.com"]:
        result = evaluate_subsidiary_relationship(
            parent_domain="nnpcgroup.com",
            candidate_domain=vendor,
            parent_org_name="NNPC",
        )
        assert result["is_subsidiary"] is False
        assert result["confidence_score"] == 0


def test_subsidiary_brand_and_document_anchors():
    # Brand token containment + document organogram mention
    doc_snippets = [
        "NNPC Limited Group Structure: Strategic Business Units include NNPC Retail Limited (nnpcretail.com) and NETCO Engineering.",
        "Annual Financial Statement for National Engineering and Technical Company (NETCO).",
    ]

    result1 = evaluate_subsidiary_relationship(
        parent_domain="nnpcgroup.com",
        candidate_domain="nnpcretail.com",
        parent_org_name="NNPC Limited",
        evidence_hints=doc_snippets,
    )
    # Brand token containment (+30) + Document organogram (+35) = 65% (>=50% confirmed)
    assert result1["is_subsidiary"] is True
    assert result1["confidence_score"] >= 50
    assert result1["candidate_domain"] == "nnpcretail.com"

    result2 = evaluate_subsidiary_relationship(
        parent_domain="nnpcgroup.com",
        candidate_domain="netco.com.ng",
        parent_org_name="NNPC Limited",
        evidence_hints=doc_snippets,
    )
    assert result2["is_subsidiary"] is True
    assert result2["confidence_score"] >= 35


def test_discover_corporate_subsidiaries_filters_noise():
    candidate_urls = [
        "https://www.google.com/search",
        "https://twitter.com/NNPCgroup",
        "https://retail.nnpcretail.com/portal",
        "https://www.netco.com.ng/services",
        "https://salesforce.com/login",
    ]
    doc_snippets = [
        "Operations executed via nnpcretail.com and netco.com.ng.",
    ]

    subs = discover_corporate_subsidiaries(
        parent_domain="nnpcgroup.com",
        org_name="NNPC",
        candidate_urls_and_domains=candidate_urls,
        document_snippets=doc_snippets,
    )

    sub_domains = [s["candidate_domain"] for s in subs]
    assert "nnpcretail.com" in sub_domains
    assert "google.com" not in sub_domains
    assert "salesforce.com" not in sub_domains
    assert "twitter.com" not in sub_domains
