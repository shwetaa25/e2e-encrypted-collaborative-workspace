import pytest
from app.security.username_policy import username_problems, normalize_username, suggest_username
from app.security.password_policy import password_problems


@pytest.mark.parametrize("name", ["alice", "Bob_99", "  carol_dev  ", "a_b_c"])
def test_valid_usernames(name):
    assert username_problems(name) == []


@pytest.mark.parametrize("name", ["ab", "1abc", "has space", "bad-dash", "admin", "a__b", "trail_", "x" * 21, "émile"])
def test_invalid_usernames(name):
    assert username_problems(name)


def test_normalize_lowercases_and_trims():
    assert normalize_username("  AliCE ") == "alice"


def test_suggest_username_is_valid_and_unique():
    taken: set[str] = set()
    names = [suggest_username(e, taken) for e in ("john.doe@x.com", "john.doe@y.com", "42@z.com", "a@z.com")]
    assert len(set(names)) == 4
    assert all(username_problems(n) == [] for n in names)


def test_password_cannot_contain_username():
    assert any("username" in p for p in password_problems("Vx9$kLm2#qPz", "a@b.com", "kLm2"))
