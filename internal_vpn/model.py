import frappe
from frappe.model.document import Document


class ManagedDocument(Document):
    def validate(self):
        if not self.flags.vpn_mutation:
            raise frappe.PermissionError("Use the VPN API to change membership")

    def on_trash(self):
        raise frappe.PermissionError("Disable VPN membership through the API")
