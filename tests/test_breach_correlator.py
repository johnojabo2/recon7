import pytest
from people.breach_correlator import (
    check_hibp_password_hash_exposure,
    correlate_email_breach_signals,
)


def test_hibp_invalid_hash_prefix():
    assert check_hibp_password_hash_exposure("123") == 0
    assert check_hibp_password_hash_exposure("") == 0


def test_correlate_email_breach_signals_empty():
    assert correlate_email_breach_signals([]) == []
    assert correlate_email_breach_signals(["invalid-no-at-sign"]) == []
