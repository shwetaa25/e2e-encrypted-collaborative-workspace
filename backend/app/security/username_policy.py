# app/security/username_policy.py
# ─────────────────────────────────────────────────────────
# Usernames are the PUBLIC handle used to find and add people.
# Emails stay private (used only to sign in), so nobody can add or
# look someone up just by knowing their email address.
#
# Rules: 3-20 chars, letters / digits / underscore, must start with a letter,
# case-insensitive (always stored lower-case). Mirrored by
# frontend/src/utils/usernamePolicy.ts.
# ─────────────────────────────────────────────────────────

import re

MIN_LENGTH = 3
MAX_LENGTH = 20

_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")

RESERVED = frozenset({
    "admin", "administrator", "root", "system", "support", "security", "staff",
    "moderator", "mod", "help", "info", "null", "undefined", "anonymous",
    "everyone", "owner", "api", "www", "me", "you", "user", "test",
})


def normalize_username(raw: str) -> str:
    return raw.strip().lower()


def username_problems(raw: str) -> list[str]:
    """Human-readable problems with a username. Empty list == acceptable."""
    value = normalize_username(raw)
    problems: list[str] = []
    if len(value) < MIN_LENGTH or len(value) > MAX_LENGTH:
        problems.append(f"Use {MIN_LENGTH}-{MAX_LENGTH} characters")
    if value and not value[0].isalpha():
        problems.append("Start with a letter")
    if value and not re.fullmatch(r"[a-z0-9_]+", value):
        problems.append("Use only letters, numbers and underscores")
    if "__" in value:
        problems.append("Do not use two underscores in a row")
    if value.endswith("_"):
        problems.append("Do not end with an underscore")
    if value in RESERVED:
        problems.append("This username is reserved")
    return problems


def suggest_username(email: str, taken: set[str]) -> str:
    """
    Derives a valid, unused username from an email's local part.
    Used ONCE to back-fill accounts created before usernames existed.
    """
    local = email.split("@", 1)[0].lower()
    base = re.sub(r"[^a-z0-9_]", "_", local)
    base = re.sub(r"_+", "_", base).strip("_")
    if not base or not base[0].isalpha():
        base = "user_" + base
    base = base[: MAX_LENGTH - 4].rstrip("_")
    if len(base) < MIN_LENGTH or base in RESERVED:
        base = (base + "_user")[: MAX_LENGTH - 4]
    candidate, n = base, 1
    while candidate in taken:
        n += 1
        candidate = f"{base}{n}"
    taken.add(candidate)
    return candidate
