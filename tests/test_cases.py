import database as db

TEXT = "I am struggling to pay my rent this month and need help."


def submit(client, **overrides):
    data = {"category": "Financial", "description": TEXT, "consent": "y", **overrides}
    return client.post("/cases/new", data=data)


def new_reference(client):
    response = submit(client)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[1]


def student(app, make_user, login, email="stu@example.com"):
    make_user(email)
    browser = app.test_client()
    login(browser, email)
    return browser


def staff(app, make_user, login, email="t@example.com"):
    staff_id = make_user(email, role="staff")
    browser = app.test_client()
    login(browser, email)
    return browser, staff_id


# ------------------------------------------------------------ student: create / read
def test_student_can_submit_view_and_list_case(app, make_user, login):
    browser = student(app, make_user, login)
    reference = new_reference(browser)
    assert TEXT.encode() in browser.get(f"/cases/{reference}").data
    assert reference.encode() in browser.get("/cases").data


def test_description_is_encrypted_at_rest(app, make_user, login, mongo_db):
    browser = student(app, make_user, login)
    new_reference(browser)
    assert TEXT.encode() not in bytes(mongo_db["cases"].find_one()["description_enc"])


def test_references_are_sequential(app, make_user, login, mongo_db):
    browser = student(app, make_user, login)
    new_reference(browser)
    new_reference(browser)
    refs = sorted(c["reference"] for c in mongo_db["cases"].find())
    assert refs[0].endswith("0001") and refs[1].endswith("0002")


def test_invalid_case_input_rejected(app, make_user, login, mongo_db):
    browser = student(app, make_user, login)
    assert b"between 20 and 3000" in submit(browser, description="too short").data
    assert b"choose a category" in submit(browser, category="Hacked").data
    assert b"confirm that staff" in submit(browser, consent="").data
    assert mongo_db["cases"].count_documents({}) == 0


def test_script_in_description_is_escaped(app, make_user, login):
    browser = student(app, make_user, login)
    response = submit(browser, description="<script>alert(1)</script> padding text to reach the length")
    page = browser.get(response.headers["Location"]).data
    assert b"<script>alert(1)</script>" not in page and b"&lt;script&gt;" in page


def test_other_students_cannot_open_the_case(app, make_user, login):
    owner = student(app, make_user, login, "a@example.com")
    reference = new_reference(owner)
    other = student(app, make_user, login, "b@example.com")
    assert other.get(f"/cases/{reference}").status_code == 404  # IDOR blocked
    assert other.post(f"/cases/{reference}/withdraw").status_code == 404
    assert other.get('/cases/{"$ne": null}').status_code == 404  # NoSQL injection attempt


def test_roles_and_anonymous_users_are_kept_out_of_student_pages(app, client, make_user, login):
    staff_browser, _ = staff(app, make_user, login)
    assert staff_browser.get("/cases/new").status_code == 403
    assert client.get("/cases").status_code == 302


def test_case_creation_is_audited_without_content(app, make_user, login, mongo_db):
    browser = student(app, make_user, login)
    new_reference(browser)
    event = mongo_db["audit_log"].find_one({"action": "case_created"})
    assert event and TEXT not in str(event)


# ------------------------------------------------------------ student: update / delete
def test_student_can_edit_while_new_but_not_after(app, make_user, login, mongo_db):
    browser = student(app, make_user, login)
    reference = new_reference(browser)
    updated = "Updated: I now also need help with my deposit and council tax."
    browser.post(f"/cases/{reference}/edit", data={"category": "Accommodation", "description": updated})
    page = browser.get(f"/cases/{reference}").data
    assert updated.encode() in page and b"Accommodation" in page

    mongo_db["cases"].update_one({"reference": reference}, {"$set": {"status": "In Progress"}})
    response = browser.post(f"/cases/{reference}/edit", data={"category": "Other", "description": "x" * 30},
                            follow_redirects=True)
    assert b"can&#39;t be edited" in response.data
    assert updated.encode() in browser.get(f"/cases/{reference}").data  # unchanged


def test_student_can_withdraw_while_new_but_not_after(app, make_user, login, mongo_db):
    browser = student(app, make_user, login)
    first, second = new_reference(browser), new_reference(browser)
    browser.post(f"/cases/{first}/withdraw")
    assert browser.get(f"/cases/{first}").status_code == 404
    assert mongo_db["cases"].find_one({"reference": first})["is_archived"] is True  # archived, not erased

    mongo_db["cases"].update_one({"reference": second}, {"$set": {"status": "In Progress"}})
    assert b"can&#39;t be withdrawn" in browser.post(f"/cases/{second}/withdraw", follow_redirects=True).data
    assert browser.get(f"/cases/{second}").status_code == 200


def test_dashboard_shows_student_counts(app, make_user, login):
    browser = student(app, make_user, login)
    new_reference(browser)
    assert 'tile-n">1<' in browser.get("/dashboard").data.decode()


# ------------------------------------------------------------ staff
def test_staff_queue_filters_and_priority_order(app, make_user, login, mongo_db):
    owner = student(app, make_user, login)
    first, urgent = new_reference(owner), new_reference(owner)
    mongo_db["cases"].update_one({"reference": urgent}, {"$set": {"priority": "Urgent", "status": "Closed"}})
    browser, _ = staff(app, make_user, login)
    page = browser.get("/staff/cases").data.decode()
    assert page.index(urgent) < page.index(first)
    assert first not in browser.get("/staff/cases?status=Closed").data.decode()
    assert browser.get('/staff/cases?status={"$ne": ""}&category[$gt]=x&view=zzz').status_code == 200


def test_staff_can_read_case_and_it_is_audited(app, make_user, login, mongo_db):
    reference = new_reference(student(app, make_user, login))
    browser, _ = staff(app, make_user, login)
    assert TEXT.encode() in browser.get(f"/staff/cases/{reference}").data
    assert mongo_db["audit_log"].find_one({"action": "case_viewed_by_staff"})
    assert browser.get("/staff/cases/SSR-0000-0000").status_code == 404


def test_students_and_admins_cannot_read_cases_as_staff(app, make_user, login):
    owner = student(app, make_user, login)
    reference = new_reference(owner)
    assert owner.get(f"/staff/cases/{reference}").status_code == 403
    make_user("a@example.com", role="admin")
    admin = app.test_client()
    login(admin, "a@example.com")
    assert admin.get(f"/staff/cases/{reference}").status_code == 403  # least privilege


def test_staff_can_update_assign_and_student_sees_it(app, make_user, login, mongo_db):
    owner = student(app, make_user, login)
    reference = new_reference(owner)
    browser, staff_id = staff(app, make_user, login)
    browser.post(f"/staff/cases/{reference}/update",
                 data={"status": "Awaiting Student", "priority": "High", "assigned": str(staff_id)})
    doc = mongo_db["cases"].find_one({"reference": reference})
    assert (doc["status"], doc["priority"], doc["assigned_to_id"]) == ("Awaiting Student", "High", staff_id)
    page = owner.get(f"/cases/{reference}").data
    assert b"Awaiting Student" in page and b"Test User" in page


def test_invalid_staff_updates_rejected(app, make_user, login, mongo_db):
    owner = student(app, make_user, login)
    reference = new_reference(owner)
    browser, _ = staff(app, make_user, login)
    student_id = db.get_user_by_email("stu@example.com")["id"]
    for data in ({"status": "Hacked", "priority": "Normal", "assigned": ""},
                 {"status": "New", "priority": "Whenever", "assigned": ""},
                 {"status": "New", "priority": "Normal", "assigned": str(student_id)}):  # not a staff member
        assert b"couldn&#39;t update" in browser.post(f"/staff/cases/{reference}/update", data=data,
                                                      follow_redirects=True).data
    assert mongo_db["cases"].find_one({"reference": reference})["status"] == "New"


def test_notes_are_encrypted_and_hidden_from_students(app, make_user, login, mongo_db):
    owner = student(app, make_user, login)
    reference = new_reference(owner)
    browser, _ = staff(app, make_user, login)
    note = "Internal: follow up with finance team on hardship fund."
    assert note.encode() in browser.post(f"/staff/cases/{reference}/notes", data={"note": note},
                                         follow_redirects=True).data
    assert note.encode() not in bytes(mongo_db["cases"].find_one()["notes"][0]["text_enc"])
    assert note.encode() not in owner.get(f"/cases/{reference}").data
    browser.post(f"/staff/cases/{reference}/notes", data={"note": "x" * 2001})
    assert len(mongo_db["cases"].find_one()["notes"]) == 1


def test_only_closed_cases_can_be_archived(app, make_user, login, mongo_db):
    reference = new_reference(student(app, make_user, login))
    browser, _ = staff(app, make_user, login)
    assert b"Only closed cases" in browser.post(f"/staff/cases/{reference}/archive", follow_redirects=True).data
    mongo_db["cases"].update_one({"reference": reference}, {"$set": {"status": "Closed"}})
    browser.post(f"/staff/cases/{reference}/archive")
    assert mongo_db["cases"].find_one({"reference": reference})["is_archived"] is True
