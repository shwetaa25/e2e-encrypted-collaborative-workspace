# app/security/password_policy.py
# ─────────────────────────────────────────────────────────
# Strong-password rules + email canonicalisation.
#
# Pure Python (no third-party imports) so it can be unit-tested
# on its own and mirrored 1:1 by the frontend checklist
# (frontend/src/utils/passwordPolicy.ts).
# ─────────────────────────────────────────────────────────

import re

MIN_LENGTH = 12
MAX_LENGTH = 128

# Small built-in deny-list of very common passwords. Compared against the
# lower-cased password with non-letters removed AND the raw lower-cased value.
COMMON_PASSWORDS = frozenset({
    "password", "passw0rd", "p@ssword", "p@ssw0rd", "password1", "password12",
    "password123", "password1234", "123456", "1234567", "12345678", "123456789",
    "1234567890", "12345678910", "qwerty", "qwerty123", "qwertyuiop", "asdfghjkl",
    "zxcvbnm", "abc123", "abcd1234", "iloveyou", "admin", "admin123", "administrator",
    "welcome", "welcome1", "welcome123", "letmein", "monkey", "dragon", "football",
    "baseball", "master", "sunshine", "princess", "login", "starwars", "whatever",
    "trustno1", "111111", "000000", "123123", "654321", "superman", "batman",
    "changeme", "secret", "testpass", "testpassword", "test1234", "hello123",
    "freedom", "shadow", "michael", "jennifer", "computer", "internet", "cricket",
    "india123", "mumbai", "krishna", "ganesh", "lovely", "pass1234", "guest",
})


def canonicalize_email(raw: str) -> str:
    """
    One canonical identity per mailbox:
      - trims whitespace, lower-cases
      - drops a "+tag" from the local part  (alice+work@x.com == alice@x.com)
    This stops someone creating several accounts by only tweaking the
    address (case changes, +tags) while reusing the same password.
    """
    value = raw.strip().lower()
    if "@" not in value:
        return value
    local, _, domain = value.rpartition("@")
    local = local.split("+", 1)[0]
    return f"{local}@{domain}"


def password_problems(
    password: str, email: str | None = None, username: str | None = None
) -> list[str]:
    """Returns a list of human-readable problems. Empty list == strong enough."""
    problems: list[str] = []

    if len(password) < MIN_LENGTH:
        problems.append(f"Use at least {MIN_LENGTH} characters")
    if len(password) > MAX_LENGTH:
        problems.append(f"Use at most {MAX_LENGTH} characters")
    if not re.search(r"[a-z]", password):
        problems.append("Add a lowercase letter (a-z)")
    if not re.search(r"[A-Z]", password):
        problems.append("Add an uppercase letter (A-Z)")
    if not re.search(r"[0-9]", password):
        problems.append("Add a number (0-9)")
    if not re.search(r"[^A-Za-z0-9]", password):
        problems.append("Add a special character (e.g. ! @ # $ %)")
    if re.search(r"(.)\1\1", password):
        problems.append("Avoid repeating the same character 3 or more times in a row")
    if re.search(r"\s", password):
        problems.append("Do not use spaces")

    lowered = password.lower()
    letters_only = re.sub(r"[^a-z]", "", lowered)
    if lowered in COMMON_PASSWORDS or (len(letters_only) >= 4 and letters_only in COMMON_PASSWORDS):
        problems.append("This password is too common")

    if email:
        local = canonicalize_email(email).split("@", 1)[0]
        if len(local) >= 3 and local in lowered:
            problems.append("Do not include your email name in the password")

    if username and len(username) >= 3 and username.strip().lower() in lowered:
        problems.append("Do not include your username in the password")

    return problems


def is_strong(password: str, email: str | None = None, username: str | None = None) -> bool:
    return not password_problems(password, email, username)
