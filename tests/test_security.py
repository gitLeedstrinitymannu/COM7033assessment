import pytest

import security


def test_password_policy():
    assert security.password_problems("Str0ngPassw0rd!") == []
    assert "at least 12 characters" in security.password_problems("Ab1")
    assert "a number" in security.password_problems("NoNumbersHereAtAll")
    assert "no more than 128 characters" in security.password_problems("Aa1" * 50)


def test_password_is_hashed_with_argon2id_and_verifies():
    hashed = security.hash_password("Str0ngPassw0rd!")
    assert hashed.startswith("$argon2id$") and "Str0ngPassw0rd!" not in hashed
    assert security.verify_password(hashed, "Str0ngPassw0rd!")
    assert not security.verify_password(hashed, "wrong-password")


def test_encryption_round_trip_and_tamper_detection(app):
    with app.app_context():
        token = security.encrypt_text("private wellbeing details")
        assert b"private" not in token
        assert security.decrypt_text(token) == "private wellbeing details"
        assert "could not be decrypted" in security.decrypt_text(token[:-4] + b"AAAA")


def test_clean_text_removes_control_characters():
    assert security.clean_text("  hello\x00 world\x07  ") == "hello world"


@pytest.mark.parametrize("field,value", [
    ("full_name", "R0bert"), ("student_id", "abc"), ("email", "not-an-email"), ("course", "Hacking 101"),
])
def test_registration_rejects_bad_fields(field, value):
    form = {"full_name": "Manish Test", "student_id": "123456", "email": "a@b.com",
            "course": "LLB Law", "password": "Str0ngPassw0rd!", "confirm_password": "Str0ngPassw0rd!"}
    form[field] = value
    assert security.validate_registration(form)[1]


def test_registration_accepts_valid_input():
    form = {"full_name": "Zoë O'Neil-Smith", "student_id": "123456", "email": "A@B.com",
            "course": "LLB Law", "password": "Str0ngPassw0rd!", "confirm_password": "Str0ngPassw0rd!"}
    values, errors = security.validate_registration(form)
    assert errors == [] and values["email"] == "a@b.com"


@pytest.mark.parametrize("target,safe", [
    ("/dashboard", True), ("https://evil.example", False), ("//evil.example", False),
    ("/\\evil.example", False), ("", False), (None, False),
])
def test_is_safe_next(target, safe):
    assert security.is_safe_next(target) is safe
