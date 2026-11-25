# Evaluation report

## 1. Design decisions and justification
| Decision | Reason | Alternative considered |
|---|---|---|
| **SQLite for users** | Accounts are relational with unique constraints (email, student ID); built into Python; zero setup | PostgreSQL: better for many users at once, more setup |
| **MongoDB Atlas for cases and audit log** | Cases are documents with variable parts (notes list); audit events are append-only records; Atlas is hosted, TLS-protected and scalable | Everything in SQLite: simpler, but no separation between identity data and case data |
| **Two separate databases** | The scenario asks for separate databases; a breach of one does not expose the other; separate trust zones | One database |
| **Argon2id** | Memory-hard, current best practice for password storage | bcrypt (also acceptable) |
| **Fernet field encryption** | Authenticated encryption, simple, well reviewed (cryptography library) | Whole-database encryption: does not protect against a compromised app or query access |
| **Server-side sessions via signed cookie, user re-checked every request** | Simple, and disabling a user takes effect at once | JWT: harder to revoke |
| **Delete means archive** | Keeps history for accountability and for disputes | Hard delete: simpler, loses evidence |
| **Admin cannot read cases** | Least privilege; reduces insider risk | Admin sees everything: simpler support, higher risk |
| **Names copied into each case** | Staff screens need no cross-database lookups | Join at read time: always current, slower, more code |

## 2. How well do the controls work?
- Every threat T1 to T21 in the threat model has at least one control, and 56 automated tests check the
  important ones (access control, encryption, validation, lockout, audit, CSRF).
- The controls are layered. For example, a student opening another student's case is stopped by the login
  check, the role check and the owner id in the query, and the response (404) reveals nothing.
- The riskiest data (case text and notes) is protected even if the database is stolen, as long as the key is safe.

## 3. Residual risks
| Risk | Why it remains | Possible improvement |
|---|---|---|
| Encryption key theft or loss | The key sits in an environment variable; losing it destroys all cases | Key vault (for example a cloud secrets manager), key rotation with MultiFernet, tested backups |
| Brute force across many accounts | Lockout is per account; there is no per-IP rate limit, so an attacker can lock a victim out on purpose | Rate limiting (Flask-Limiter), CAPTCHA, alerts |
| Audit log can be altered by someone with database rights | MongoDB has no built-in append-only mode | Atlas user that can only insert, forward events to a separate log service |
| No multi-factor authentication | Not in scope for the time available | TOTP for staff and admins |
| No password reset or email verification | Needs an email service | Add a reset flow with expiring tokens |
| Registration shows "already exists" | This helps legitimate users but allows account enumeration | Email-based sign-up confirmation |
| Metadata is not encrypted | Category and status need to be searchable | Accept; protected by access control |
| Retention | Archived cases are kept forever | Retention policy and scheduled deletion agreed with the university |
| Request-size limit is untested | Hard to test reliably with the test client | Add an integration test |
| HTTPS is a deployment matter | The Flask development server is HTTP only | Reverse proxy with TLS (see deployment.md) |

## 4. Trade-offs: usability, performance, security
- **Lockout (security) vs availability.** Five failed logins lock the account for 15 minutes. This stops
  guessing but lets an attacker annoy a student. An admin can unlock accounts at once.
- **12-character passwords (security) vs convenience.** The live checklist and show/hide button reduce the friction.
- **Argon2 (security) vs speed.** Hashing takes tens of milliseconds per login, which is acceptable for this
  user base and makes the tests slower.
- **30 minute sessions (security) vs convenience.** Staff may need to log in again after a break.
- **Locked-after-handling cases (integrity) vs flexibility.** Students cannot edit once staff start work; they
  must contact support. This keeps records trustworthy.
- **Re-checking the user on every request (security) vs performance.** One small SQLite read per request;
  negligible here and it lets admins revoke access immediately.

## 5. Testing
- **Unit tests** (`tests/test_security.py`): password policy, hashing, encryption and tamper detection,
  input validation, safe redirects.
- **Integration tests** (`tests/test_auth.py`, `test_cases.py`, `test_admin.py`): full journeys through the
  real Flask routes with an in-memory MongoDB: register, log in, create, read, edit, withdraw, staff
  update, notes, archive, admin controls, and the attack cases (IDOR, injection, XSS, CSRF, privilege checks).
- **Not done:** browser-level end-to-end tests (for example Playwright) and load tests. The integration
  tests simulate each user journey, but they do not drive a real browser.

## 6. Ethical reflection
Students may disclose mental health or disability information at a vulnerable moment. The design tries to
respect that: encryption, access limited to staff, no admin access to content, an audit trail that makes
staff browsing visible, a consent notice, and an emergency message on the request form. The system also
raises questions it cannot answer alone: how long to keep data, who may see which categories (for example
only trained wellbeing staff for wellbeing cases), and how students can ask for their data to be corrected
or deleted. These need decisions by the university, not just code.

## 7. Limitations and future work
Case-category-based staff permissions, file attachments (with malware scanning), email notifications,
student replies when a case is *Awaiting Student*, multi-factor authentication, password reset, pagination
for the queue, containerisation, and browser-level end-to-end tests.
