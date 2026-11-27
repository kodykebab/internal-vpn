import frappe

from internal_vpn.internal_vpn.doctype.vpn_network.vpn_network import VPNMember


class VPNDevice(VPNMember):
    """An engineer's device. The engineer who creates it owns it."""

    # begin: auto-generated types
    # This code is auto-generated. Do not modify anything in this block.

    from typing import TYPE_CHECKING

    if TYPE_CHECKING:
        from frappe.types import DF

        address: DF.Data | None
        enabled: DF.Check
        label: DF.Data
        last_handshake: DF.Datetime | None
        public_key: DF.Data
    # end: auto-generated types

    def onload(self):
        network = frappe.get_doc("VPN Network")
        if network.hub:
            self.set_onload("configuration", network.get_configuration(self))
