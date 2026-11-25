# Student Support Case Management System

COM7033 Secure Software Development, Assessment 1.

A secure Flask web application for a university Student Support Service. Students submit support
requests (wellbeing, academic, financial, disability, accommodation) and staff manage the cases.
It replaces email and spreadsheets, which had poor security, no audit trail and inconsistent handling.

## What each role can do

| Role | Can do |
|---|---|
| **Student** | Register, log in, submit a request, follow its status, edit or withdraw it while it is still *New* |
| **Staff** | See the case queue (filter by view, status, category), read cases, assign, change status and priority, add internal notes, archive closed cases |
| **Admin** | See user and case counts, enable or disable accounts (also clears lockouts), read the audit log. **Cannot read case content** |

Staff and admin accounts cannot self-register. They are created from the command line.

## Tech

Python, Flask, SQLite (user accounts), MongoDB Atlas (cases and audit log), Argon2, Fernet (cryptography), pytest.

## Setup

1. Create and activate a virtual environment
   - Windows: `python -m venv venv` then `venv\Scripts\activate`
   - Mac/Linux: `python3 -m venv venv` then `source venv/bin/activate`
2. `pip install -r requirements.txt`
3. Copy `.env.example` to `.env` and fill it in (**never commit `.env`**)
   - Secret key: `python -c "import secrets; print(secrets.token_hex(32))"`
   - Encryption key: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
   - **Back up the encryption key.** Without it, encrypted case data can never be read again.
   - `MONGO_URI`: your MongoDB Atlas connection string (or `mongodb://localhost:27017`)
4. Create staff and admin accounts:
   ```
   python create_user.py --role admin
   python create_user.py --role staff
   ```
5. `python app.py` then open http://127.0.0.1:5001 (database check: `/api/db-status`)

## Run the tests

```
pytest -v
```
The tests use an in-memory fake MongoDB (mongomock), so they never touch Atlas.

## Project structure

```
app.py           routes for all roles (the application)
database.py      SQLite (users) and MongoDB (cases, audit log) access
security.py      password hashing, input validation, field encryption
create_user.py   create staff/admin accounts
templates/ static/   user interface
tests/           unit and integration tests
docs/            requirements, threat model (STRIDE), evaluation, deployment
```

## Security features

| Threat | Control |
|---|---|
| Stolen passwords | Argon2id hashing, 12+ character policy |
| Brute force | Lockout after 5 failures for 15 minutes, generic login error, timing-safe unknown-user check |
| Session theft or fixation | HttpOnly + SameSite cookies, new session on login, 30 minute lifetime, user re-checked on every request |
| Forged requests | CSRF token on every POST form |
| Injection | Parameterised SQL, fixed-key Mongo queries, whitelist validation |
| XSS | Jinja auto-escaping, Content-Security-Policy |
| Data theft | Case text and staff notes encrypted at rest (Fernet) |
| Access to other people's data | Role checks on every route; owner id inside every student query |
| Unauthorised changes | Edit/withdraw only while *New*; delete is archive; filters include owner and state |
| Denying actions | Audit log of logins, case access and changes (never passwords or case text) |
| Misconfiguration | App refuses to start without valid secrets; security headers; generic error pages |

More detail: [requirements](docs/requirements.md), [threat model](docs/threat-model.md),
[evaluation](docs/evaluation.md), [deployment](docs/deployment.md).

## AI use statement

