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
    """Deny guests everything except the login routes."""
    if frappe.session.user not in (None, "", "Guest"):
        return
    path, method, command = frappe.request.path, frappe.request.method, frappe.form_dict.get("cmd")
    if path == "/login" and method == "GET" and not command:
        return
    if path == "/api/method/login" and method == "POST" and command in (None, "", "login"):
        return
    raise frappe.AuthenticationError("Login required")
