# Requirements specification

## 1. Scenario
A university Student Support Service handles requests about wellbeing, academic support, finance,
disability and accommodation. It currently uses email and spreadsheets, causing security concerns, poor
auditing and inconsistent case management. The system must let students submit requests and let staff
manage them securely.

## 2. Stakeholders
| Stakeholder | Interest |
|---|---|
| Students | Ask for help easily; keep very personal information private; see progress |
| Support staff | Work through cases efficiently and consistently; keep internal notes |
| Administrators | Control who has access; oversee the system without reading sensitive content |
| The university (data controller) | Legal compliance, reputation, accountability |
| Attackers / misuse | Out of scope as users, but drive the security requirements |

## 3. Business requirements
| ID | Role | Requirement |
|---|---|---|
| BR1 | Student | Register and log in |
| BR2 | Student | Submit a support request in a category |
| BR3 | Student | Follow the status of their own requests |
| BR4 | Student | Correct or withdraw a request until staff start handling it |
| BR5 | Staff | See all open cases and filter them |
| BR6 | Staff | Assign cases, set status and priority |
| BR7 | Staff | Keep internal notes that students cannot see |
| BR8 | Staff | Archive closed cases |
| BR9 | Admin | Create staff and admin accounts |
| BR10 | Admin | Disable or re-enable accounts and clear lockouts |
| BR11 | Admin | Read an audit trail of who did what |
| BR12 | Admin | Oversee the system without reading case content |
| BR13 | All | Every access to and change of case data is accountable |

## 4. Data classification
| Data | Sensitivity | Why | Protection |
|---|---|---|---|
| Case description, staff notes | **High** (may include health and disability details, special category data) | Harm if disclosed | Encrypted (Fernet), staff-only (notes) |
| Student name, ID, course, email | Medium (personal data) | Identifies a person | Access control, not shown to other students |
| Password hash | **High** | Account takeover | Argon2id, never shown or logged |
| Case category, status, priority | Medium | Reveals that a person asked for help | Access control |
| Audit log | Medium, integrity-critical | Evidence of actions | Admin-only, contains no content |

## 5. Security requirements (derived from the business requirements)
| ID | Requirement | Supports |
|---|---|---|
| SR1 | Strong password policy; store only Argon2id hashes | BR1 |
| SR2 | Lock the account after repeated failed logins; use one generic error | BR1 |
| SR3 | Secure sessions: HttpOnly, SameSite, expiry, new session at login, account re-checked each request | BR1, BR10 |
| SR4 | Server-side role checks on every route; owner id in every student query | BR3, BR5, BR12 |
| SR5 | Whitelist validation of all input on the server | BR2, BR4, BR6 |
| SR6 | Escape all output | BR2, BR7 |
| SR7 | CSRF token on every state-changing form | BR2, BR4, BR6 |
| SR8 | Encrypt case descriptions and staff notes at rest | BR2, BR7 |
| SR9 | Integrity: edit or withdraw only while *New*; delete means archive | BR4, BR8 |
| SR10 | Audit log without secrets or case content | BR11, BR13 |
| SR11 | Admins have no route to case content (least privilege) | BR12 |
| SR12 | Secrets in environment variables; refuse to start without them | all |
| SR13 | Parameterised SQL and fixed-key Mongo queries | all |
| SR14 | Security headers, generic error pages, request size limit | all |

## 6. Ethical, legal and professional considerations
- **Data protection (UK GDPR and Data Protection Act 2018).** Support requests can contain health
  information (special category data), so the system applies data minimisation (only needed fields),
  confidentiality (encryption, least privilege) and accountability (audit log). A lawful basis, a privacy
  notice and a retention period would be set by the university; the consent tick-box is for transparency
  (students are told staff will read the request).
- **Ethical responsibility.** Wellbeing and disability disclosures are sensitive. Staff access is logged so
  that curiosity-browsing can be detected. Admins are deliberately kept away from content.
- **Secure coding standards.** The design follows the OWASP Top 10 and ASVS ideas (validation, access
  control, cryptography, logging). Code is commented and tested.
- **Transparency.** Students see who is handling their case and its status. Use of generative AI in this
  project is declared in the README.
