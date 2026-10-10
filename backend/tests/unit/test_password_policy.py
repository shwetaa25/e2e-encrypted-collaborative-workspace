# tests/unit/test_password_policy.py
# Pure-Python tests — no database, no network.

import pytest
from app.security.password_policy import (
    canonicalize_email, password_problems, is_strong, MIN_LENGTH,
)


class TestCanonicalizeEmail:
    def test_lowercases_and_trims(self):
        assert canonicalize_email("  Alice@Example.COM ") == "alice@example.com"

    def test_drops_plus_tag(self):
        assert canonicalize_email("alice+work@example.com") == "alice@example.com"

    def test_variants_collapse_to_one_identity(self):
        variants = ["bob@x.com", "BOB@x.com", " bob+a@x.com", "Bob+spam@X.com"]
        assert len({canonicalize_email(v) for v in variants}) == 1

    def test_different_mailboxes_stay_different(self):
        assert canonicalize_email("bob@x.com") != canonicalize_email("rob@x.com")
        assert canonicalize_email("bob@x.com") != canonicalize_email("bob@y.com")


class TestPasswordPolicy:
    def test_strong_password_accepted(self):
        assert is_strong("Vx9$kLm2#qPz", "alice@example.com")

    @pytest.mark.parametrize("pw", [
        "Short1!aB",              # too short
        "alllowercase123!!",      # no uppercase
        "ALLUPPERCASE123!!",      # no lowercase
        "NoNumbersHere!!xy",      # no digit
        "NoSpecialChars1234",     # no special character
        "Aaaa1111!!xxYY",         # 3+ repeated characters
        "Has Space 1!aBcDeF",     # whitespace
    ])
    def test_weak_passwords_rejected(self, pw):
        assert password_problems(pw)

    @pytest.mark.parametrize("pw", ["Password123!", "Qwerty123!!!", "Welcome123!!"])
    def test_common_passwords_rejected(self, pw):
        assert "This password is too common" in password_problems(pw)

    def test_password_containing_email_name_rejected(self):
        problems = password_problems("Alice#Strong99x", "alice@example.com")
        assert any("email name" in p for p in problems)

    def test_min_length_constant(self):
        assert MIN_LENGTH == 12
        assert any("12" in p for p in password_problems("Ab1!"))


class TestUsernamePolicy:
    def test_valid_usernames(self):
        from app.security.username_policy import username_problems
        for name in ("alice", "Alice_01", "bob_2000", "abc"):
            assert username_problems(name) == [], name

    def test_invalid_usernames(self):
        from app.security.username_policy import username_problems
        for name in ("ab", "1abc", "has space", "a__b", "trail_", "admin", "x" * 21, "bad-name", "e@mail"):
            assert username_problems(name), name

    def test_backfill_generates_unique_valid_names(self):
        from app.security.username_policy import suggest_username, username_problems
        taken: set[str] = set()
        names = [suggest_username(e, taken) for e in
                 ("john.doe@x.com", "john.doe@y.com", "42@z.com", "a@z.com", "admin@z.com")]
        assert len(set(names)) == len(names)
        assert all(username_problems(n) == [] for n in names), names

    def test_password_may_not_contain_username(self):
        from app.security.password_policy import password_problems
        assert any("username" in p for p in password_problems("Vx9$kLm2#qPz", None, "kLm2"))
