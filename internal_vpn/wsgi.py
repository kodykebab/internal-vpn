"""Headless PoC entrypoint: no realtime server or static/file shortcut routes."""

import os

import frappe.app
from werkzeug.wrappers import Response


def application(environ, start_response):
    frappe.app._site = os.environ["VPN_SITE"]
    if environ.get("PATH_INFO", "").rstrip("/") == "/socket.io":
        return Response("Realtime is disabled in this PoC", status=403)(environ, start_response)
    return frappe.app.application(environ, start_response)
