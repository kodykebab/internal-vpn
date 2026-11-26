import frappe
from frappe import _
from frappe.model.document import Document

from internal_vpn.host import WireGuard
from internal_vpn.internal_vpn.doctype.vpn_network.vpn_network import VPNNetwork, parse


class VPNAccess(Document):
    """Lets one engineer's devices reach one server while access control is on."""

    # begin: auto-generated types
    # This code is auto-generated. Do not modify anything in this block.

    from typing import TYPE_CHECKING

    if TYPE_CHECKING:
        from frappe.types import DF

        ports: DF.Data | None
        server: DF.Link
        user: DF.Link
    # end: auto-generated types

    def validate(self):
        network = VPNNetwork.load_locked()
        self.ports = parse(WireGuard.parse_ports, self.ports or "")
        if self.server == network.hub:
            frappe.throw(_("The hub is not a service; grant access to a spoke"))
        if frappe.db.exists(
            self.doctype, {"server": self.server, "user": self.user, "name": ("!=", self.name)}
        ):
            frappe.throw(_("This engineer already has access to this server"), frappe.UniqueValidationError)

    def on_update(self):
        if self.flags.in_insert or any(
            self.has_value_changed(field) for field in ("server", "user", "ports")
        ):
            self.advance_revision()

    def on_trash(self):
        self.advance_revision()

    @staticmethod
    def advance_revision():
        network = VPNNetwork.load_locked()
        if network.access_control:
            network.advance_revision()
