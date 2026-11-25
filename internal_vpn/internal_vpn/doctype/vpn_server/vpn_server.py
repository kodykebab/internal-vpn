import re

import frappe
from frappe import _
from frappe.share import add_docshare

from internal_vpn.internal_vpn.doctype.vpn_network.vpn_network import VPNMember, VPNNetwork


class VPNServer(VPNMember):
    """A hub or service host. Its host user acts for it through the `agent` permission."""

    system_fields = ("address", "reported_revision", "apply_success", "reported_at", "reported_digest")

    def validate(self):
        super().validate()
        if not self.is_new():
            return
        if not VPNNetwork.is_eligible(self.user, self.doctype):
            frappe.throw(_("The host user must be enabled and have the VPN Host role"))
        if frappe.db.exists(self.doctype, {"user": self.user}):
            frappe.throw(_("Use one dedicated host user per server"))

    def after_insert(self):
        add_docshare(
            self.doctype, self.name, self.user, read=1, agent=1, flags={"ignore_share_permission": True}
        )

    @frappe.whitelist(methods=["POST"])
    def get_configuration(self) -> dict:
        self.check_permission("agent")
        return self.load_locked().get_configuration(self)

    @frappe.whitelist(methods=["POST"])
    def report(self, revision: int, success: bool, digest: str | None = None) -> dict:
        """Record applied state. Status compares its digest with current membership."""
        self.check_permission("agent")
        if revision < 1:
            frappe.throw(_("Expected a positive integer revision"))
        if success and not re.fullmatch(r"[0-9a-f]{64}", digest or ""):
            frappe.throw(_("Expected the applied configuration digest"))
        network = self.load_locked()
        if not (self.reported_revision or 0) <= revision <= network.revision:
            frappe.throw(_("Report revision is out of order"))
        self.db_set(
            {
                "reported_revision": revision,
                "apply_success": success,
                "reported_digest": digest if success else None,
                "reported_at": frappe.utils.now_datetime(),
            },
            update_modified=False,
        )
        return {"accepted": True}
