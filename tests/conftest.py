import itertools

import mongomock
import pytest
from cryptography.fernet import Fernet

import database as db
import security
from app import create_app

PASSWORD = "Str0ngPassw0rd!"
_numbers = itertools.count(100000)


@pytest.fixture(autouse=True)
def mongo_db(monkeypatch):
    """Every test gets a fresh in-memory MongoDB (mongomock), so tests never touch Atlas."""
    fake = mongomock.MongoClient()["test_db"]
    monkeypatch.setattr("database.get_mongo_db", lambda: fake)
    return fake


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("SQLITE_PATH", str(tmp_path / "test.db"))
    return create_app({"TESTING": True, "SECRET_KEY": "test-secret",
                       "FIELD_ENCRYPTION_KEY": Fernet.generate_key().decode(),
                       "WTF_CSRF_ENABLED": False})


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def make_user(app):
    def _make(email="stu@example.com", role="student", password=PASSWORD):
        number = str(next(_numbers)) if role == "student" else None
        return db.create_user("Test User", email, security.hash_password(password), role=role, student_id=number)
    return _make


@pytest.fixture
def login():
    def _login(client, email="stu@example.com", password=PASSWORD, **kwargs):
        return client.post("/login", data={"email": email, "password": password}, **kwargs)
    return _login
