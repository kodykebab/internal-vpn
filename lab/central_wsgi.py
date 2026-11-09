"""Run the real Central test site, with no VPN application hooks or route patches."""

import frappe.app

frappe.app._site = "test.local"
application = frappe.app.application
