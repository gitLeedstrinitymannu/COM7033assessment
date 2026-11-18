"""Database connections: SQLite (relational) and MongoDB (document)."""
import os
import sqlite3
import certifi

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

SQLITE_PATH = os.getenv("SQLITE_PATH", "instance/app.db")
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "support_cms")

# certifi supplies trusted CA certificates, which fixes CERTIFICATE_VERIFY_FAILED on Windows/macOS.
mongo_client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=5000,
    tlsCAFile=certifi.where(),
)

# ---------- SQLite ----------
def get_sqlite_connection():
    os.makedirs(os.path.dirname(SQLITE_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_sqlite():
    """Create a starter table so the connection is proven."""
    conn = get_sqlite_connection()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "email TEXT NOT NULL UNIQUE, "
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
    )
    conn.commit()
    conn.close()


# ---------- MongoDB ----------
def get_mongo_db():
    return mongo_client[MONGO_DB_NAME]


# ---------- Health checks ----------
def check_sqlite():
    try:
        conn = get_sqlite_connection()
        conn.execute("SELECT 1")
        conn.close()
        return "connected"
    except Exception as error:
        print("SQLite error:", error)  # details stay in the console, not in the response
        return "failed"


def check_mongo():
    try:
        mongo_client.admin.command("ping")
        return "connected"
    except Exception as error:
        print("MongoDB error:", error)
        return "failed"
