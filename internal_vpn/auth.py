import frappe

GUEST_PAGES = {"/login", "/update-password", "/website_script.js"}
GUEST_METHODS = {
    ("GET", "frappe.translate.get_boot_translations"),
    ("POST", "login"),
    ("POST", "frappe.core.doctype.user.user.update_password"),
    ("POST", "frappe.core.doctype.user.user.test_password_strength"),
    ("POST", "frappe.core.doctype.user.user.reset_password"),
}


def require_login():
    """Allow guests only login and Frappe's invitation/password flow."""
    if frappe.session.user not in (None, "", "Guest"):
        return
    path, method, command = frappe.request.path, frappe.request.method, frappe.form_dict.get("cmd")
    if not command and method == "GET" and path in GUEST_PAGES:
        return
    if not command and path.startswith("/api/method/"):
        command = path.removeprefix("/api/method/")
    if (method, command) not in GUEST_METHODS:
        raise frappe.AuthenticationError("Login required")
