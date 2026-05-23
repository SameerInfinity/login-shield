import re
import hashlib
from passlib.context import CryptContext
from app.config import (
    MIN_PASSWORD_LENGTH,
    REQUIRE_UPPERCASE,
    REQUIRE_NUMBERS,
    REQUIRE_SPECIAL,
    RISK_POINTS_WEAK_PASSWORD
)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)


def validate_password_strength(password: str) -> tuple[bool, str, int]:
    """
    Validate password against security policy.
    Returns: (is_valid, message, risk_points)
    """
    risk_points = 0
    issues = []

    if len(password) < MIN_PASSWORD_LENGTH:
        issues.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
        risk_points += RISK_POINTS_WEAK_PASSWORD

    if REQUIRE_UPPERCASE and not re.search(r"[A-Z]", password):
        issues.append("Password must contain at least one uppercase letter")
        risk_points += 1

    if REQUIRE_NUMBERS and not re.search(r"\d", password):
        issues.append("Password must contain at least one number")
        risk_points += 1

    if REQUIRE_SPECIAL and not re.search(r"[!@#$%^&*()_+\-=\[\]{};:'\",.<>?/]", password):
        issues.append("Password must contain at least one special character")
        risk_points += 1

    # Check for common weak patterns
    weak_patterns = [
        r"^123\d+",  # 123...
        r"^password",  # password
        r"^admin",  # admin
        r"^qwerty",  # qwerty
        r"^abc\d+",  # abc...
    ]

    for pattern in weak_patterns:
        if re.search(pattern, password, re.IGNORECASE):
            issues.append("Password contains a common weak pattern")
            risk_points += RISK_POINTS_WEAK_PASSWORD
            break

    # Check for repeated characters (e.g., "aaaa", "1111")
    if re.search(r"(.)\1{3,}", password):
        issues.append("Password contains too many repeated characters")
        risk_points += 1

    is_valid = len(issues) == 0
    message = "; ".join(issues) if issues else "Password meets security requirements"

    return is_valid, message, risk_points


def get_password_hash_for_storage(username: str, password: str) -> str:
    """
    Create a salted hash suitable for storage.
    Includes username in the hash for per-user uniqueness.
    """
    combined = f"{username}:{password}"
    return hashlib.sha256(combined.encode()).hexdigest()
