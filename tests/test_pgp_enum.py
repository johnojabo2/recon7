import pytest
from people.pgp_enum import _parse_hkp_index_text, enumerate_pgp_keys


def test_parse_hkp_machine_readable_index():
    sample_hkp_output = """
info:1:2
pub:4A88B3F21F77412A:1:2048:1620000000::
uid:Bashir Bayo Ojulari <bojulari@nnpcgroup.com>:1620000000::
uid:Bayo Ojulari (Work Key) <bojulari@nnpcgroup.com>:1620000000::
pub:9B22C4E33A11884B:1:4096:1580000000::
uid:Maryamu Idris <midris@nnpcgroup.com>:1580000000::
pub:1111222233334444:1:2048:1500000000::
uid:External Contractor <contractor@otherdomain.com>:1500000000::
"""

    results = _parse_hkp_index_text(sample_hkp_output, "nnpcgroup.com")
    
    assert len(results) == 2
    
    emails = [r["email"] for r in results]
    assert "bojulari@nnpcgroup.com" in emails
    assert "midris@nnpcgroup.com" in emails
    assert "contractor@otherdomain.com" not in emails
    
    ceo = next(r for r in results if r["email"] == "bojulari@nnpcgroup.com")
    assert ceo["name"] == "Bashir Bayo Ojulari"
    assert ceo["confidence"] == 98
    assert ceo["is_human"] is True
    assert ceo["key_id"] == "4A88B3F21F77412A"
    assert ceo["platform"] == "PGP Public Keyserver"


def test_parse_hkp_url_encoded_uids():
    encoded_hkp = """
pub:FEDCBA9876543210:1:2048:1600000000::
uid:Sarah%20Connor%20%28SecOps%29%20%3Csarah.connor%40cyberdyne.com%3E:1600000000::
"""
    results = _parse_hkp_index_text(encoded_hkp, "cyberdyne.com")
    assert len(results) == 1
    record = results[0]
    assert record["name"] == "Sarah Connor"
    assert record["email"] == "sarah.connor@cyberdyne.com"
    assert record["confidence"] == 98
