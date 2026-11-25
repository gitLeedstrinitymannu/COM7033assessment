"""Security helpers: password hashing, input validation, field encryption.

Everything that decides "is this input allowed?" lives here, so it is easy to find and test.
"""
import re
from urllib.parse import urlparse

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from flask import current_app

# ---- Allowed values (whitelists). Anything not on these lists is rejected. ----
COURSES = ["BSc Computer Science", "BSc Cyber Security", "BSc Games Design", "BA Business Management",
           "BSc Psychology", "LLB Law", "MSc Data Science", "Other"]
CATEGORIES = ["Academic", "Financial", "Wellbeing", "Disability", "Accommodation", "Other"]
STATUSES = ["New", "In Progress", "Awaiting Student", "Closed"]
PRIORITIES = ["Low", "Normal", "High", "Urgent"]

NAME_RE = re.compile(r"^[^\W\d_](?:[^\W\d_]|[ '\-.])+$")  # letters, spaces, hyphens, apostrophes
STUDENT_ID_RE = re.compile(r"^\d{6,10}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


# ---------------------------------------------------------------- passwords
ph = PasswordHasher()  # Argon2id with library defaults
DUMMY_HASH = ph.hash("not-a-real-password")  # checked for unknown emails so timing doesn't leak accounts


def hash_password(password):
    return ph.hash(password)


def verify_password(password_hash, password):
    try:
        return ph.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_problems(password):
    """Return a list of unmet password rules (empty list = strong enough)."""
    problems = []
    if len(password) < 12:
        problems.append("at least 12 characters")
    if len(password) > 128:  # stops huge inputs being used to slow down hashing
        problems.append("no more than 128 characters")
    if not re.search(r"[a-z]", password):
        problems.append("a lower-case letter")
    if not re.search(r"[A-Z]", password):
        problems.append("an upper-case letter")
    if not re.search(r"\d", password):
        problems.append("a number")
    return problems


# ---------------------------------------------------------------- input validation
def clean_text(value):
    """Remove control characters and surrounding whitespace. HTML is escaped by Jinja on output."""
    return CONTROL_CHARS.sub("", value or "").strip()


def validate_registration(form):
    """Returns (clean values, list of error messages)."""
    values = {
        "full_name": clean_text(form.get("full_name")),
        "student_id": (form.get("student_id") or "").strip(),
        "email": (form.get("email") or "").strip().lower(),
        "course": form.get("course") or "",
    }
    password = form.get("password") or ""
    errors = []
    if not (2 <= len(values["full_name"]) <= 100 and NAME_RE.match(values["full_name"])):
        errors.append("Enter your full name using letters, spaces, hyphens and apostrophes only.")
    if not STUDENT_ID_RE.match(values["student_id"]):
        errors.append("Student ID should be 6 to 10 digits.")
    if len(values["email"]) > 254 or not EMAIL_RE.match(values["email"]):
        errors.append("Enter a valid email address.")
    if values["course"] not in COURSES:
        errors.append("Please choose your course.")
    problems = password_problems(password)
    if problems:
        errors.append("Your password needs: " + ", ".join(problems) + ".")
    if password != (form.get("confirm_password") or ""):
        errors.append("Passwords do not match.")
    return values, errors


def validate_case(form, require_consent):
    values = {"category": form.get("category") or "", "description": clean_text(form.get("description"))}
    errors = []
    if values["category"] not in CATEGORIES:
        errors.append("Please choose a category.")
    if not 20 <= len(values["description"]) <= 3000:
        errors.append("Please write between 20 and 3000 characters.")
    if require_consent and not form.get("consent"):
        errors.append("Please confirm that staff will read your request.")
    return values, errors


def is_safe_next(target):
    """Only allow redirects to paths on this site (prevents open redirects)."""
    if not target:
        return False
    parts = urlparse(target)
    return (not parts.scheme and not parts.netloc and target.startswith("/")
            and not target.startswith("//") and "\\" not in target)


# ---------------------------------------------------------------- field encryption
def _fernet():
    return Fernet(current_app.config["FIELD_ENCRYPTION_KEY"])  # AES-128-CBC + HMAC authentication


def encrypt_text(text):
    return _fernet().encrypt(text.encode("utf-8"))


def decrypt_text(token):
    try:
        return _fernet().decrypt(bytes(token)).decode("utf-8")
    except InvalidToken:
        return "[This content could not be decrypted]"  # tampered data or wrong key: fail safe
