import frappe


def require_login():
    # This app belongs on a separate site. Realtime is disabled in the PoC gateway.
    if frappe.session.user not in (None, "", "Guest"):
        return
    command = frappe.form_dict.get("cmd")
    if frappe.request.path == "/login" and frappe.request.method == "GET" and not command:
        return
    if (frappe.request.path == "/api/method/login" and frappe.request.method == "POST"
            and command in (None, "", "login")):
        return
    raise frappe.AuthenticationError("Login required")
