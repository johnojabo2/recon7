import time
from collections import defaultdict
from typing import Dict, Tuple, Optional
import threading

# Thread-safe in-memory sliding window rate limiter
_lock = threading.Lock()
# Mapping: key (ip or email) -> list of timestamp failures
_login_failures: Dict[str, list] = defaultdict(list)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = 600  # 10 minutes
BACKOFF_PENALTY_SECONDS = 300  # 5 minutes


def record_failed_login(identifier: str):
    """Records a failed authentication attempt for an IP or email identifier."""
    now = time.time()
    with _lock:
        failures = _login_failures[identifier]
        # Prune failures outside the window
        failures = [ts for ts in failures if now - ts < LOCKOUT_WINDOW_SECONDS]
        failures.append(now)
        _login_failures[identifier] = failures


def check_rate_limit(identifier: str) -> Tuple[bool, int]:
    """
    Checks if an identifier is currently rate limited.
    Returns (is_limited: bool, retry_after_seconds: int).
    """
    now = time.time()
    with _lock:
        failures = _login_failures.get(identifier, [])
        # Prune old
        valid_failures = [ts for ts in failures if now - ts < LOCKOUT_WINDOW_SECONDS]
        _login_failures[identifier] = valid_failures

        if len(valid_failures) >= MAX_FAILED_ATTEMPTS:
            oldest_relevant = valid_failures[-MAX_FAILED_ATTEMPTS]
            time_elapsed = now - oldest_relevant
            remaining_lockout = max(1, int(BACKOFF_PENALTY_SECONDS - time_elapsed))
            return True, remaining_lockout

        return False, 0


def clear_failed_logins(identifier: str):
    """Clears failed login attempts upon successful authentication."""
    with _lock:
        if identifier in _login_failures:
            del _login_failures[identifier]
