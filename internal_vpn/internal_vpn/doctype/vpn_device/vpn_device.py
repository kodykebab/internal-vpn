import frappe

from internal_vpn.internal_vpn.doctype.vpn_network.vpn_network import VPNMember


class VPNDevice(VPNMember):
    """An engineer's device. The engineer who creates it owns it."""

    @frappe.whitelist(methods=["GET"])
    def get_configuration(self) -> dict:
        return self.load_locked().get_configuration(self)
