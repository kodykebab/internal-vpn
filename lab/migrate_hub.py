"""Update only the empty disposable VPN test site for the hub schema."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.chdir("/home/vagrant/internal-vpn-lab/sites")
import frappe

frappe.init("test.local")
frappe.connect()
try:
    if frappe.conf.db_name != "ivpn_poc" or frappe.db.count("VPN Peer"):
        raise RuntimeError("Expected the empty disposable VPN site; do not auto-convert a deployed mesh")
    for doctype in ("vpn_peer", "vpn_network"):
        frappe.reload_doc("internal_vpn", "doctype", doctype, force=True)
    frappe.db.commit()
    frappe.clear_cache()
    print("Empty lab site ready for hub configuration")
finally:
    frappe.destroy()
