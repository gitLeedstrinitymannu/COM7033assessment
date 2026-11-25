"""Student Support Case Management System (Flask).

Roles:  student = submits and tracks own requests
        staff   = manages all cases (assign, update, internal notes)
        admin   = manages user accounts and reads the audit log (cannot read case content)
"""
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

from cryptography.fernet import Fernet
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFError, CSRFProtect

import database as db
import security
from security import CATEGORIES, PRIORITIES, STATUSES

DUPLICATE_MESSAGE = "An account with that email or student ID already exists."
LOGIN_FAILED_MESSAGE = "We couldn't log you in. Check your details or try again later."
PRIORITY_RANK = {"Urgent": 0, "High": 1, "Normal": 2, "Low": 3}


def db_now():
    return datetime.now(timezone.utc)


def roles_required(*roles):
    """Only logged-in users with one of these roles may open the page. Checked on the server."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login", next=request.path))
            if g.user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def authenticate(email, password, max_failures, lock_minutes):
    """Check a login. Returns (user or None, reason). The reason is for the audit log only."""
    if len(password) > 128:
        return None, "bad_input"
    user = db.get_user_by_email(email)
    if user is None:
        security.verify_password(security.DUMMY_HASH, password)  # same work, so timing doesn't reveal accounts
        return None, "unknown_user"
    if user["locked_until"] and user["locked_until"] > db.now_text():
        return None, "locked"
    if not security.verify_password(user["password_hash"], password):
        db.record_failed_login(user, max_failures, lock_minutes)
        return None, "bad_password"
    if not user["is_active"]:
        return None, "disabled"
    db.record_successful_login(user["id"])
    return user, "ok"


def status_counts(extra=None):
    """Number of (non-archived) cases per status."""
    counts = {status: 0 for status in STATUSES}
    for case in db.cases().find({"is_archived": False, **(extra or {})}, {"status": 1}):
        counts[case["status"]] += 1
    return counts


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY"),
        FIELD_ENCRYPTION_KEY=os.getenv("FIELD_ENCRYPTION_KEY"),
        SESSION_COOKIE_HTTPONLY=True,                         # JavaScript cannot read the cookie
        SESSION_COOKIE_SAMESITE="Lax",                        # blocks most cross-site request forgery
        SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") == "production",  # HTTPS only in production
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),     # idle sessions expire
        MAX_CONTENT_LENGTH=1024 * 1024,                       # 1 MB request limit (denial of service)
        MAX_FAILED_LOGINS=5,
        LOCKOUT_MINUTES=15,
    )
    if test_config:
        app.config.update(test_config)

    # Fail closed: refuse to run with missing or invalid secrets.
    if not app.config.get("SECRET_KEY"):
        raise RuntimeError('SECRET_KEY is not set. See .env.example '
                           '(python -c "import secrets; print(secrets.token_hex(32))").')
    try:
        Fernet(app.config.get("FIELD_ENCRYPTION_KEY") or "")
    except (ValueError, TypeError):
        raise RuntimeError("FIELD_ENCRYPTION_KEY is missing or invalid. See .env.example.")

    CSRFProtect(app)  # every POST form must carry a valid token
    db.init_sqlite()
    db.init_mongo()

    # ------------------------------------------------------------ request setup
    @app.before_request
    def load_current_user():
        """Look the user up on every request, so disabling an account takes effect immediately."""
        g.user = None
        user_id = session.get("user_id")
        if user_id is not None:
            user = db.get_user_by_id(user_id)
            if user and user["is_active"]:
                g.user = user
            else:
                session.clear()

    @app.context_processor
    def inject_user():
        return {"user": g.get("user")}

    @app.template_filter("fmt_dt")
    def fmt_dt(value):
        return value.strftime("%d %b %Y, %H:%M") if hasattr(value, "strftime") else value

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'self'")
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"  # sensitive pages are never cached
        return response

    def error_page(code, message):
        return render_template("error.html", code=code, message=message), code

    # Friendly, generic error pages: no stack traces or internals are shown to users.
    app.register_error_handler(403, lambda e: error_page(403, "You don't have permission to view this page."))
    app.register_error_handler(404, lambda e: error_page(404, "We couldn't find that page."))
    app.register_error_handler(500, lambda e: error_page(500, "Something went wrong on our side."))
    app.register_error_handler(CSRFError, lambda e: error_page(400, "Your form expired. Please go back, refresh and try again."))

    # ------------------------------------------------------------ public pages
    @app.route("/")
    def home():
        return render_template("home.html")

    @app.route("/api/db-status")
    def db_status():
        return {"sqlite": db.check_sqlite(), "mongodb": db.check_mongo()}

    # ------------------------------------------------------------ registration and login
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if g.user:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            values, errors = security.validate_registration(request.form)
            user_id = None
            if not errors and (db.get_user_by_email(values["email"]) or db.student_number_exists(values["student_id"])):
                errors.append(DUPLICATE_MESSAGE)
            if not errors:
                try:
                    # The role is set here on the server: a user can never choose their own role.
                    user_id = db.create_user(values["full_name"], values["email"],
                                             security.hash_password(request.form["password"]),
                                             role="student", student_id=values["student_id"],
                                             course=values["course"])
                except sqlite3.IntegrityError:  # two people registering at once
                    errors.append(DUPLICATE_MESSAGE)
            if errors:
                for message in errors:
                    flash(message, "error")
                return render_template("register.html", form=values, courses=security.COURSES)
            db.log_event("user_registered", user={"id": user_id, "role": "student"})
            flash("Your account has been created. Please log in.", "success")
            return redirect(url_for("login"))
        return render_template("register.html", form={}, courses=security.COURSES)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user:
            return redirect(url_for("dashboard"))
        email = ""
        if request.method == "POST":
            email = (request.form.get("email") or "").strip().lower()
            user, reason = authenticate(email, request.form.get("password") or "",
                                        app.config["MAX_FAILED_LOGINS"], app.config["LOCKOUT_MINUTES"])
            if user is None:
                # One message for every failure, so attackers can't tell which emails exist.
                # Only the reason is logged: people sometimes type their password into the email box.
                db.log_event("login_failed", details=f"reason={reason}")
                flash(LOGIN_FAILED_MESSAGE, "error")
                return render_template("login.html", email=email)
            session.clear()                  # new session on login prevents session fixation
            session["user_id"] = user["id"]
            session.permanent = True         # applies the 30 minute lifetime
            db.log_event("login_success", user=user)
            target = request.args.get("next")
            return redirect(target if security.is_safe_next(target) else url_for("dashboard"))
        return render_template("login.html", email=email)

    @app.route("/logout", methods=["POST"])  # POST + CSRF token: a stray link cannot log you out
    @roles_required("student", "staff", "admin")
    def logout():
        db.log_event("logout")
        session.clear()
        flash("You've been logged out.", "success")
        return redirect(url_for("home"))

    # ------------------------------------------------------------ dashboard
    @app.route("/dashboard")
    @roles_required("student", "staff", "admin")
    def dashboard():
        role = g.user["role"]
        if role == "student":
            data = {"counts": status_counts({"student_id": g.user["id"]})}
        elif role == "staff":
            open_cases = {"is_archived": False, "status": {"$ne": "Closed"}}
            data = {
                "counts": status_counts(),
                "mine": db.cases().count_documents({**open_cases, "assigned_to_id": g.user["id"]}),
                "unassigned": db.cases().count_documents({**open_cases, "assigned_to_id": None}),
            }
        else:  # admins see counts and activity only, never case content
            rows = db.query("SELECT role, COUNT(*) AS n FROM users GROUP BY role")
            data = {
                "by_role": {r["role"]: r["n"] for r in rows},
                "counts": status_counts(),
                "recent": list(db.audit_collection().find().sort("timestamp", -1).limit(6)),
            }
        return render_template("dashboard.html", **data)

    # ------------------------------------------------------------ student: create, read, update, withdraw
    def load_own_case(reference):
        """The owner's id is part of the query, so one student can never open another's case (IDOR)."""
        case = db.cases().find_one({"reference": reference, "student_id": g.user["id"], "is_archived": False},
                                   {"notes": 0})  # staff notes are never loaded for students
        if case is None:
            abort(404)  # same answer whether it doesn't exist or isn't yours
        case["description"] = security.decrypt_text(case.pop("description_enc"))
        return case

    @app.route("/cases")
    @roles_required("student")
    def my_cases():
        found = db.cases().find({"student_id": g.user["id"], "is_archived": False},
                                {"description_enc": 0, "notes": 0}).sort("updated_at", -1)
        return render_template("cases.html", cases=list(found), staff_view=False)

    @app.route("/cases/new", methods=["GET", "POST"])
    @roles_required("student")
    def new_case():
        if request.method == "POST":
            values, errors = security.validate_case(request.form, require_consent=True)
            if errors:
                for message in errors:
                    flash(message, "error")
                return render_template("case_form.html", form=values, categories=CATEGORIES, editing=False)
            reference = db.create_case(g.user, values["category"], security.encrypt_text(values["description"]))
            db.log_event("case_created", details=f"reference={reference}")
            flash(f"Your request {reference} has been submitted. We'll be in touch soon.", "success")
            return redirect(url_for("view_case", reference=reference))
        return render_template("case_form.html", form={}, categories=CATEGORIES, editing=False)

    @app.route("/cases/<reference>")
    @roles_required("student")
    def view_case(reference):
        return render_template("case_detail.html", case=load_own_case(reference), staff_view=False)

    @app.route("/cases/<reference>/edit", methods=["GET", "POST"])
    @roles_required("student")
    def edit_case(reference):
        case = load_own_case(reference)
        if case["status"] != "New":  # once staff pick it up, the record is frozen for integrity
            flash("This request is already being handled, so it can't be edited. Please contact support.", "error")
            return redirect(url_for("view_case", reference=reference))
        if request.method == "POST":
            values, errors = security.validate_case(request.form, require_consent=False)
            if errors:
                for message in errors:
                    flash(message, "error")
                return render_template("case_form.html", form=values, categories=CATEGORIES, editing=True, case=case)
            # Owner, status and archive state are all part of the update filter (race-safe).
            db.cases().update_one(
                {"reference": reference, "student_id": g.user["id"], "status": "New", "is_archived": False},
                {"$set": {"category": values["category"],
                          "description_enc": security.encrypt_text(values["description"]),
                          "updated_at": db_now()}})
            db.log_event("case_edited", details=f"reference={reference}")
            flash("Your request has been updated.", "success")
            return redirect(url_for("view_case", reference=reference))
        return render_template("case_form.html", form=case, categories=CATEGORIES, editing=True, case=case)

    @app.route("/cases/<reference>/withdraw", methods=["POST"])
    @roles_required("student")
    def withdraw_case(reference):
        case = load_own_case(reference)
        result = db.cases().update_one(
            {"reference": reference, "student_id": g.user["id"], "status": "New", "is_archived": False},
            {"$set": {"is_archived": True, "updated_at": db_now()}})  # archived, not erased
        if result.modified_count:
            db.log_event("case_withdrawn", details=f"reference={reference}")
            flash("Your request has been withdrawn.", "success")
            return redirect(url_for("my_cases"))
        flash("This request is already being handled, so it can't be withdrawn. Please contact support.", "error")
        return redirect(url_for("view_case", reference=case["reference"]))

    # ------------------------------------------------------------ staff: queue, update, notes, archive
    @app.route("/staff/cases")
    @roles_required("staff")
    def staff_queue():
        status = request.args.get("status", "")
        category = request.args.get("category", "")
        view = request.args.get("view", "all")
        query = {"is_archived": False}
        if status in STATUSES:          # filters are checked against whitelists first
            query["status"] = status
        if category in CATEGORIES:
            query["category"] = category
        if view == "mine":
            query["assigned_to_id"] = g.user["id"]
        elif view == "unassigned":
            query["assigned_to_id"] = None
        found = list(db.cases().find(query, {"description_enc": 0, "notes": 0}).limit(200))
        found.sort(key=lambda c: c["updated_at"], reverse=True)
        found.sort(key=lambda c: PRIORITY_RANK.get(c["priority"], 4))  # urgent first, then newest
        return render_template("cases.html", cases=found, staff_view=True, statuses=STATUSES,
                               categories=CATEGORIES, filters={"status": status, "category": category, "view": view})

    def load_case_for_staff(reference):
        case = db.cases().find_one({"reference": reference, "is_archived": False})
        if case is None:
            abort(404)
        return case

    @app.route("/staff/cases/<reference>")
    @roles_required("staff")
    def staff_case(reference):
        case = load_case_for_staff(reference)
        db.log_event("case_viewed_by_staff", details=f"reference={reference}")  # reading is auditable too
        case["description"] = security.decrypt_text(case.pop("description_enc"))
        notes = [{**n, "text": security.decrypt_text(n["text_enc"])} for n in case.pop("notes")]
        return render_template("case_detail.html", case=case, notes=notes, staff_view=True,
                               staff_list=db.list_staff(), statuses=STATUSES, priorities=PRIORITIES)

    @app.route("/staff/cases/<reference>/update", methods=["POST"])
    @roles_required("staff")
    def update_case(reference):
        load_case_for_staff(reference)
        status = request.form.get("status", "")
        priority = request.form.get("priority", "")
        assignee_id = request.form.get("assigned", "")
        staff_by_id = {str(s["id"]): s for s in db.list_staff()}  # only real, active staff can be assigned
        if status not in STATUSES or priority not in PRIORITIES or (assignee_id and assignee_id not in staff_by_id):
            flash("We couldn't update the case. Please check the values and try again.", "error")
            return redirect(url_for("staff_case", reference=reference))
        assignee = staff_by_id.get(assignee_id)
        db.cases().update_one(
            {"reference": reference, "is_archived": False},
            {"$set": {"status": status, "priority": priority,
                      "assigned_to_id": assignee["id"] if assignee else None,
                      "assigned_to_name": assignee["full_name"] if assignee else None,
                      "updated_at": db_now()}})
        db.log_event("case_updated", details=f"reference={reference}; status={status}; priority={priority}")
        flash("Case updated.", "success")
        return redirect(url_for("staff_case", reference=reference))

    @app.route("/staff/cases/<reference>/notes", methods=["POST"])
    @roles_required("staff")
    def add_note(reference):
        load_case_for_staff(reference)
        text = security.clean_text(request.form.get("note"))
        if not 1 <= len(text) <= 2000:
            flash("Please write a note (up to 2000 characters).", "error")
        else:
            db.cases().update_one({"reference": reference}, {
                "$push": {"notes": {"author_name": g.user["full_name"], "text_enc": security.encrypt_text(text),
                                    "created_at": db_now()}},
                "$set": {"updated_at": db_now()}})
            db.log_event("note_added", details=f"reference={reference}")
            flash("Note added.", "success")
        return redirect(url_for("staff_case", reference=reference))

    @app.route("/staff/cases/<reference>/archive", methods=["POST"])
    @roles_required("staff")
    def archive_case(reference):
        load_case_for_staff(reference)
        result = db.cases().update_one({"reference": reference, "status": "Closed", "is_archived": False},
                                       {"$set": {"is_archived": True, "updated_at": db_now()}})
        if result.modified_count:
            db.log_event("case_archived", details=f"reference={reference}")
            flash("Case archived.", "success")
            return redirect(url_for("staff_queue"))
        flash("Only closed cases can be archived.", "error")
        return redirect(url_for("staff_case", reference=reference))

    # ------------------------------------------------------------ admin: users and audit log
    @app.route("/admin/users")
    @roles_required("admin")
    def admin_users():
        return render_template("admin_users.html", people=db.list_users(), now=db.now_text())

    @app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
    @roles_required("admin")
    def toggle_user(user_id):
        target = db.get_user_by_id(user_id)
        if target is None:
            abort(404)
        if target["id"] == g.user["id"]:
            flash("You can't disable your own account.", "error")
        else:
            enable = not target["is_active"]
            db.set_user_active(user_id, enable)  # re-enabling also clears a lockout
            db.log_event("user_enabled" if enable else "user_disabled", details=f"user_id={user_id}")
            flash("Account enabled." if enable else "Account disabled.", "success")
        return redirect(url_for("admin_users"))

    @app.route("/admin/audit")
    @roles_required("admin")
    def audit_log():
        events = list(db.audit_collection().find().sort("timestamp", -1).limit(100))
        return render_template("audit_log.html", events=events)

    return app


if __name__ == "__main__":
    # debug mode is for local development only
    create_app().run(debug=os.getenv("FLASK_ENV") == "development", port=5001)
