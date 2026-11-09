import frappe


def after_install():
    for role in ("VPN Manager", "VPN Engineer", "VPN Host"):
        if not frappe.db.exists("Role", role):
            frappe.get_doc({"doctype": "Role", "role_name": role, "desk_access": 1}).insert()
    if not frappe.db.exists("VPN Network", "default"):
        doc = frappe.get_doc({"doctype": "VPN Network", "name": "default", "revision": 0})
        doc.flags.vpn_mutation = True
        doc.insert()
