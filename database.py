"""Databases: SQLite for user accounts, MongoDB (Atlas) for support cases and the audit log.

Every SQL statement uses ? placeholders and every Mongo query is built from fixed keys,
so user input is never joined into a query (SQL / NoSQL injection prevention).
"""
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone

import certifi
from dotenv import load_dotenv
from flask import g, has_request_context, request
from pymongo import MongoClient, ReturnDocument

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "support_cms")
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# Connects lazily. certifi supplies trusted CA certificates (fixes CERTIFICATE_VERIFY_FAILED).
mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, tlsCAFile=certifi.where())


def now_text():
    return datetime.now(timezone.utc).strftime(TIME_FORMAT)


# ================================================================ SQLite (users)
def get_sqlite():
    path = os.getenv("SQLITE_PATH", "instance/app.db")  # read at call time so tests can override it
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def query(sql, params=(), one=False):
    with closing(get_sqlite()) as conn:
        rows = conn.execute(sql, params).fetchall()
    return (rows[0] if rows else None) if one else rows


def execute(sql, params=()):
    with closing(get_sqlite()) as conn:
        with conn:  # commit on success, roll back on error
            return conn.execute(sql, params).lastrowid


def init_sqlite():
    execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "student_id TEXT UNIQUE, "                     # empty for staff and admin
        "full_name TEXT NOT NULL, "
        "email TEXT NOT NULL UNIQUE, "
        "course TEXT, "
        "password_hash TEXT NOT NULL, "                # Argon2id hash, never the password
        "role TEXT NOT NULL CHECK (role IN ('student','staff','admin')), "
        "is_active INTEGER NOT NULL DEFAULT 1, "
        "failed_logins INTEGER NOT NULL DEFAULT 0, "
        "locked_until TEXT, "
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, "
        "last_login_at TEXT)"
    )


def get_user_by_email(email):
    return query("SELECT * FROM users WHERE email = ?", (email,), one=True)


def get_user_by_id(user_id):
    return query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)


def student_number_exists(student_id):
    return query("SELECT 1 FROM users WHERE student_id = ?", (student_id,), one=True) is not None


def create_user(full_name, email, password_hash, role="student", student_id=None, course=None):
    return execute(
        "INSERT INTO users (student_id, full_name, email, course, password_hash, role) VALUES (?, ?, ?, ?, ?, ?)",
        (student_id, full_name, email.lower(), course, password_hash, role),
    )


def list_users():
    return query("SELECT id, full_name, email, role, student_id, is_active, locked_until, last_login_at "
                 "FROM users ORDER BY role, full_name")


def list_staff():
    return query("SELECT id, full_name FROM users WHERE role = 'staff' AND is_active = 1 ORDER BY full_name")


def set_user_active(user_id, active):
    """Enable or disable an account. Also clears any lockout."""
    execute("UPDATE users SET is_active = ?, failed_logins = 0, locked_until = NULL WHERE id = ?",
            (1 if active else 0, user_id))


def record_failed_login(user, max_failures, lock_minutes):
    failures = user["failed_logins"] + 1
    if failures >= max_failures:
        until = (datetime.now(timezone.utc) + timedelta(minutes=lock_minutes)).strftime(TIME_FORMAT)
        execute("UPDATE users SET failed_logins = 0, locked_until = ? WHERE id = ?", (until, user["id"]))
    else:
        execute("UPDATE users SET failed_logins = ? WHERE id = ?", (failures, user["id"]))


def record_successful_login(user_id):
    execute("UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = ? WHERE id = ?",
            (now_text(), user_id))


# ================================================================ MongoDB (cases + audit)
def get_mongo_db():
    return mongo_client[MONGO_DB_NAME]


def cases():
    return get_mongo_db()["cases"]


def audit_collection():
    return get_mongo_db()["audit_log"]


def init_mongo():
    """Create indexes. Never stops the app starting if MongoDB is offline."""
    try:
        cases().create_index("reference", unique=True)
        cases().create_index("student_id")
        audit_collection().create_index("timestamp")
    except Exception as error:
        print("MongoDB index setup skipped:", error)


def next_reference():
    """Atomic counter, so two requests at once can never get the same reference."""
    doc = get_mongo_db()["counters"].find_one_and_update(
        {"_id": "case_reference"}, {"$inc": {"seq": 1}}, upsert=True, return_document=ReturnDocument.AFTER)
    return f"SSR-{datetime.now(timezone.utc).year}-{doc['seq']:04d}"


def create_case(student, category, description_enc):
    """Names are copied into the case so staff screens need no cross-database lookups."""
    reference = next_reference()
    now = datetime.now(timezone.utc)
    cases().insert_one({
        "reference": reference,
        "student_id": student["id"],
        "student_name": student["full_name"],
        "student_number": student["student_id"],
        "student_course": student["course"],
        "category": category,
        "description_enc": description_enc,   # encrypted, never plain text
        "status": "New",
        "priority": "Normal",
        "assigned_to_id": None,
        "assigned_to_name": None,
        "notes": [],                          # staff-only, encrypted
        "submitted_at": now,
        "updated_at": now,
        "is_archived": False,                 # "delete" = archive, so history is kept
    })
    return reference


def log_event(action, user=None, details=None):
    """Audit trail: who did what, when, from where. Never log passwords or case content."""
    try:
        user = user or (g.get("user") if has_request_context() else None)
        audit_collection().insert_one({
            "timestamp": datetime.now(timezone.utc),
            "action": action,
            "actor_id": user["id"] if user else None,
            "actor_role": user["role"] if user else None,
            "ip_address": request.remote_addr if has_request_context() else None,
            "details": details,
        })
    except Exception as error:
        # A Mongo outage must not stop users working, but it is reported loudly.
        print("AUDIT LOG ERROR:", error)


def check_sqlite():
    try:
        query("SELECT 1")
        return "connected"
    except Exception as error:
        print("SQLite error:", error)
        return "failed"


def check_mongo():
    try:
        mongo_client.admin.command("ping")
        return "connected"
    except Exception as error:
        print("MongoDB error:", error)
        return "failed"
