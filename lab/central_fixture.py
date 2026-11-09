"""Create/remove only this run's users on Central's existing test.local site."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets

import frappe

BENCH = Path("/home/vagrant/central-rescue-3174d144")
parser = argparse.ArgumentParser()
parser.add_argument("operation", choices=("create", "remove"))
parser.add_argument("--file", type=Path, required=True)
parser.add_argument("--run-id", required=True)
args = parser.parse_args()
if not args.run_id.isalnum() or os.geteuid() == 0:
    raise RuntimeError("Expected a non-root lab run with an alphanumeric ID")
os.chdir(BENCH / "sites")
frappe.init("test.local")
frappe.connect()
if "central" not in frappe.get_installed_apps() or not frappe.conf.allow_tests:
    raise RuntimeError("Expected the Central test site")

try:
    if args.operation == "create":
        fixture = {}
        for label, roles in (("operator", ["System Manager"]), ("customer", ["Central User"])):
            email = f"ivpn-central-{args.run_id}-{label}@example.invalid"
            user = frappe.get_doc({"doctype": "User", "email": email, "first_name": label,
                                   "send_welcome_email": 0, "user_type": "System User",
                                   "roles": [{"role": role} for role in roles]})
            user.insert(ignore_permissions=True)
            key, secret = secrets.token_hex(10), secrets.token_hex(24)
            user.api_key, user.api_secret = key, secret
            user.save(ignore_permissions=True)
            fixture[label] = {"user": email, "token": f"{key}:{secret}"}
        source = Path(frappe.get_app_path("central"))
        fixture["source_sha256"] = {
            str(path): hashlib.sha256((source / path).read_bytes()).hexdigest()
            for path in ("api/identity.py", "iam.py", "hooks.py")
        }
        descriptor = os.open(args.file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as file:
            json.dump(fixture, file)
    else:
        for label in ("operator", "customer"):
            email = f"ivpn-central-{args.run_id}-{label}@example.invalid"
            if frappe.db.exists("User", email):
                frappe.delete_doc("User", email, ignore_permissions=True, force=True)
    frappe.db.commit()
finally:
    frappe.destroy()
