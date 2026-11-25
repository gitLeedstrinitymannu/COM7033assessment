import database as db

GENERIC = b"couldn&#39;t log you in"
VALID = {"full_name": "Manish Test", "student_id": "123456", "email": "manish@example.com",
         "course": "BSc Cyber Security", "password": "Str0ngPassw0rd!", "confirm_password": "Str0ngPassw0rd!"}


def register(client, **overrides):
    return client.post("/register", data={**VALID, **overrides}, follow_redirects=True)


def test_registration_stores_hashed_password_and_student_role(client):
    assert b"Your account has been created" in register(client).data
    user = db.get_user_by_email("manish@example.com")
    assert user["role"] == "student" and user["password_hash"].startswith("$argon2id$")


def test_weak_password_and_duplicates_rejected(client):
    assert b"Your password needs" in register(client, password="short", confirm_password="short").data
    assert db.get_user_by_email("manish@example.com") is None
    register(client)
    assert b"already exists" in register(client, student_id="654321").data
    assert b"already exists" in register(client, email="other@example.com").data


def test_user_cannot_choose_own_role(client):
    register(client, role="admin")  # extra form field must be ignored
    assert db.get_user_by_email("manish@example.com")["role"] == "student"


def test_sql_injection_in_login_fails_safely(client, make_user, login):
    make_user()
    assert GENERIC in login(client, email="' OR '1'='1' --", password="x").data


def test_dashboard_requires_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302 and "/login" in response.headers["Location"]


def test_login_success_and_each_role_dashboard(client, make_user, login, app):
    for role, marker in [("student", b"support requests stand"), ("staff", b"case queue"), ("admin", b"System overview")]:
        make_user(f"{role}@example.com", role=role)
        browser = app.test_client()
        assert marker in login(browser, f"{role}@example.com", follow_redirects=True).data


def test_wrong_password_and_unknown_email_give_same_message(client, make_user, login):
    make_user()
    assert GENERIC in login(client, password="WrongPassw0rd!!").data
    assert GENERIC in login(client, email="nobody@example.com").data


def test_account_locks_after_repeated_failures_then_unlocks(client, make_user, login, app):
    make_user()
    for _ in range(app.config["MAX_FAILED_LOGINS"]):
        login(client, password="WrongPassw0rd!!")
    assert GENERIC in login(client).data  # correct password, but the account is locked
    db.execute("UPDATE users SET locked_until = '2000-01-01 00:00:00'")
    assert b"Hello, Test" in login(client, follow_redirects=True).data


def test_disabled_account_cannot_log_in_and_is_signed_out(client, make_user, login):
    make_user()
    login(client)
    db.execute("UPDATE users SET is_active = 0")
    assert client.get("/dashboard").status_code == 302  # existing session ends immediately
    assert GENERIC in login(client).data


def test_open_redirect_blocked_and_safe_next_followed(client, make_user):
    make_user()
    data = {"email": "stu@example.com", "password": "Str0ngPassw0rd!"}
    assert client.post("/login?next=https://evil.example", data=data).headers["Location"].endswith("/dashboard")


def test_logout_requires_post_and_ends_session(client, make_user, login):
    make_user()
    login(client)
    assert client.get("/logout").status_code == 405
    client.post("/logout")
    assert client.get("/dashboard").status_code == 302


def test_session_cookie_flags(client, make_user, login):
    make_user()
    cookie = login(client).headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_security_headers_present(client):
    headers = client.get("/").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


def test_csrf_is_enforced_when_enabled(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet
    from app import create_app
    monkeypatch.setenv("SQLITE_PATH", str(tmp_path / "csrf.db"))
    app = create_app({"TESTING": True, "SECRET_KEY": "x", "FIELD_ENCRYPTION_KEY": Fernet.generate_key().decode()})
    assert app.test_client().post("/register", data=VALID).status_code == 400


def test_app_refuses_to_start_without_secrets(monkeypatch):
    import pytest
    from app import create_app
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        create_app()
    with pytest.raises(RuntimeError):
        create_app({"SECRET_KEY": "x", "FIELD_ENCRYPTION_KEY": "not-a-valid-key"})


def test_auth_events_are_audited_without_passwords(client, make_user, login, mongo_db):
    make_user()
    login(client, password="WrongPassw0rd!!")
    login(client)
    actions = [e["action"] for e in mongo_db["audit_log"].find()]
    assert "login_failed" in actions and "login_success" in actions
    assert "WrongPassw0rd" not in str(list(mongo_db["audit_log"].find()))
