import database as db
from test_cases import TEXT, new_reference, student


def admin_browser(app, make_user, login):
    make_user("a@example.com", role="admin")
    browser = app.test_client()
    login(browser, "a@example.com")
    return browser


def test_only_admins_can_open_admin_pages(app, make_user, login):
    owner = student(app, make_user, login)
    assert owner.get("/admin/users").status_code == 403
    assert owner.get("/admin/audit").status_code == 403
    make_user("t@example.com", role="staff")
    staff_browser = app.test_client()
    login(staff_browser, "t@example.com")
    assert staff_browser.get("/admin/users").status_code == 403


def test_admin_can_list_users(app, make_user, login):
    make_user("someone@example.com")
    assert b"someone@example.com" in admin_browser(app, make_user, login).get("/admin/users").data


def test_admin_can_disable_and_enable_accounts(app, make_user, login):
    target = make_user("victim@example.com")
    admin = admin_browser(app, make_user, login)
    admin.post(f"/admin/users/{target}/toggle")
    assert db.get_user_by_id(target)["is_active"] == 0
    assert b"couldn&#39;t log you in" in login(app.test_client(), "victim@example.com").data
    admin.post(f"/admin/users/{target}/toggle")
    assert db.get_user_by_id(target)["is_active"] == 1


def test_enabling_clears_a_lockout(app, make_user, login):
    target = make_user("locked@example.com")
    db.execute("UPDATE users SET is_active = 0, locked_until = '2999-01-01 00:00:00'")
    admin_browser(app, make_user, login).post(f"/admin/users/{target}/toggle")
    assert db.get_user_by_id(target)["locked_until"] is None


def test_admin_cannot_disable_themselves(app, make_user, login):
    admin = admin_browser(app, make_user, login)
    admin_id = db.get_user_by_email("a@example.com")["id"]
    assert b"can&#39;t disable your own" in admin.post(f"/admin/users/{admin_id}/toggle", follow_redirects=True).data
    assert db.get_user_by_id(admin_id)["is_active"] == 1


def test_audit_log_page_shows_events_but_never_content(app, make_user, login):
    new_reference(student(app, make_user, login))
    page = admin_browser(app, make_user, login).get("/admin/audit").data
    assert b"case_created" in page and TEXT.encode() not in page


def test_admin_dashboard_has_counts_but_no_case_content(app, make_user, login):
    new_reference(student(app, make_user, login))
    page = admin_browser(app, make_user, login).get("/dashboard").data
    assert b"Cases by status" in page and TEXT.encode() not in page
