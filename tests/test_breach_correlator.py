import pytest
from people.breach_correlator import (
    correlate_email_breach_signals,
)


def test_correlate_email_breach_signals_empty():
    assert correlate_email_breach_signals([]) == []
    assert correlate_email_breach_signals(["invalid-no-at-sign"]) == []

