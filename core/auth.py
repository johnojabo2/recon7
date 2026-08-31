import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Optional, Dict, Any, Tuple
from core.config import settings

# 600,000 rounds of PBKDF2-HMAC-SHA256 (NIST SP 800-63B / OWASP Recommended)
PBKDF2_ITERATIONS = 600000
SALT_SIZE_BYTES = 32
TOKEN_EXPIRATION_SECONDS = 7 * 24 * 3600  # 7 days

# Constant-time dummy hash for preventing user enumeration timing attacks
DUMMY_TIMING_HASH = "pbkdf2_sha256$600000$ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff$ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

COMMON_WEAK_PASSWORDS = {
    "password", "password123", "12345678", "123456789", "admin123",
    "recon7admin", "qwerty123", "letmein123", "administrator", "iloveyou1"
}


def validate_password_complexity(password: str) -> None:
    """
    Enforces enterprise password complexity and anti-DoS length constraints.
    """
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if len(password) > 128:
        raise ValueError("Password cannot exceed 128 characters.")
    if password.lower() in COMMON_WEAK_PASSWORDS:
        raise ValueError("Password is too common and easily guessed. Please choose a stronger password.")


def hash_password(password: str) -> str:
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with 600,000 rounds and a 32-byte salt.
    Format: pbkdf2_sha256$iterations$salt_hex$hash_hex
    """
    validate_password_complexity(password)
    
    salt = secrets.token_bytes(SALT_SIZE_BYTES)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${key.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies a password against a stored PBKDF2 hash using constant-time comparison.
    """
    if not password or not stored_hash:
        return False

    parts = stored_hash.split("$")
    if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
        return False

    try:
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected_key = bytes.fromhex(parts[3])

        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )
        return hmac.compare_digest(key, expected_key)
    except Exception:
        return False


def create_access_token(user_id: str, tenant_id: str, email: str, role: str = "operator") -> str:
    """
    Generates an HMAC-SHA256 signed bearer token with expiration.
    Structure: base64(header).base64(payload).base64(signature)
    """
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "email": email,
        "role": role,
        "iat": now,
        "exp": now + TOKEN_EXPIRATION_SECONDS,
    }

    header_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode("utf-8")).decode("utf-8").rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("utf-8").rstrip("=")

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    secret = settings.SECRET_KEY.encode("utf-8")
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verifies signature, algorithm header, and expiration of an access token.
    Returns decoded claims dictionary or None if invalid/expired.
    """
    if not token or not isinstance(token, str):
        return None

    # Handle optional "Bearer " prefix
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    parts = token.split(".")
    if len(parts) != 3:
        return None

    header_b64, payload_b64, sig_b64 = parts

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    secret = settings.SECRET_KEY.encode("utf-8")
    expected_sig = hmac.new(secret, signing_input, hashlib.sha256).digest()

    try:
        # Re-pad base64 strings
        sig_padding = "=" * (4 - len(sig_b64) % 4 if len(sig_b64) % 4 != 0 else 0)
        actual_sig = base64.urlsafe_b64decode(sig_b64 + sig_padding)

        # Constant time signature verification
        if not hmac.compare_digest(actual_sig, expected_sig):
            return None

        # Verify Header Claims
        header_padding = "=" * (4 - len(header_b64) % 4 if len(header_b64) % 4 != 0 else 0)
        header_json = base64.urlsafe_b64decode(header_b64 + header_padding).decode("utf-8")
        header = json.loads(header_json)
        if header.get("alg") != "HS256" or header.get("typ") != "JWT":
            return None

        # Verify Payload
        payload_padding = "=" * (4 - len(payload_b64) % 4 if len(payload_b64) % 4 != 0 else 0)
        payload_json = base64.urlsafe_b64decode(payload_b64 + payload_padding).decode("utf-8")
        payload = json.loads(payload_json)

        # Check expiration
        exp = payload.get("exp")
        if not exp or int(time.time()) > int(exp):
            return None

        return payload
    except Exception:
        return None


def sanitize_input(value: str, max_length: int = 255) -> str:
    """
    Sanitizes string inputs: strips whitespace, removes dangerous control chars and HTML tags.
    """
    if not value:
        return ""
    # Strip HTML tags
    clean = re.sub(r"<[^>]*>", "", value)
    # Strip non-printable/control characters
    clean = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", clean)
    return clean.strip()[:max_length]


def validate_email_format(email: str) -> str:
    """
    Validates email format according to RFC specifications.
    Returns normalized lowercase email string or raises ValueError.
    """
    if not email:
        raise ValueError("Email address is required.")
    email = email.strip().lower()
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.match(email_regex, email) or len(email) > 255:
        raise ValueError("Invalid email format.")
    return email
