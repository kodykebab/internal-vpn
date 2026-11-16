import os

import frappe
import frappe.app
from werkzeug.wrappers import Response


def application(environ, start_response):
    """Headless entrypoint for one site. Realtime is disabled."""
    frappe.app._site = os.environ["VPN_SITE"]
    if environ.get("PATH_INFO", "").rstrip("/") == "/socket.io":
        return Response("Realtime is disabled", status=403)(environ, start_response)
    return frappe.app.application(environ, start_response)


def require_login():
    """Allow guests only login and Frappe's invitation/password flow."""
    if frappe.session.user not in (None, "", "Guest"):
        return
    path, method, command = frappe.request.path, frappe.request.method, frappe.form_dict.get("cmd")
    if path in ("/login", "/update-password", "/website_script.js") and method == "GET" and not command:
        return
    endpoint = command or path.removeprefix("/api/method/")
    if (
        method == "GET"
        and endpoint == "frappe.translate.get_boot_translations"
        and (command or path.startswith("/api/method/"))
    ):
        return
    if (
        method == "POST"
        and endpoint
        in (
            "login",
            "frappe.core.doctype.user.user.update_password",
            "frappe.core.doctype.user.user.test_password_strength",
            "frappe.core.doctype.user.user.reset_password",
        )
        and (command or path.startswith("/api/method/"))
    ):
        return
    raise frappe.AuthenticationError("Login required")
