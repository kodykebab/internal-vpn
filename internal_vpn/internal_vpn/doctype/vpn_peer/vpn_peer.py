import re

import frappe
from frappe.model.document import Document

from internal_vpn.host import WireGuard
from internal_vpn.internal_vpn.doctype.vpn_network.vpn_network import ROLE_FOR_KIND, VPNNetwork


class VPNPeer(Document):
    """A service host or engineer device. A disabled peer keeps its address until `release`, so a host that has
    not yet removed it can never route that address to a new peer."""

    def validate(self):
        try:
            WireGuard.validate_public_key(self.public_key)
            if self.endpoint:
                self.endpoint = WireGuard.parse_endpoint(self.endpoint)
        except (TypeError, ValueError) as error:
            frappe.throw(str(error))

    def on_trash(self):
        frappe.throw("Disable the peer, then release it")

    def lock(self) -> VPNNetwork:
        """Lock the network, then this peer, in the same order as every membership change."""
        network = VPNNetwork.get_locked()
        self.update(frappe.db.get_value(self.doctype, self.name, "*", as_dict=True, for_update=True))
        return network

    def lock_for_owner(self) -> VPNNetwork:
        network = self.lock()
        if self.user != frappe.session.user:
            raise frappe.PermissionError("This credential belongs to another peer")
        frappe.only_for(ROLE_FOR_KIND[self.kind])
        return network

    def lock_for_editor(self) -> VPNNetwork:
        network = self.lock()
        if "VPN Manager" not in frappe.get_roles():
            frappe.only_for("VPN Engineer")
            if self.kind != "Device" or self.user != frappe.session.user:
                raise frappe.PermissionError("Not your device")
        return network

    def save_membership(self, network: VPNNetwork) -> dict:
        self.save(ignore_permissions=True)
        return {"revision": network.advance_revision()}

    @frappe.whitelist(methods=["GET"])
    def get_configuration(self):
        return self.lock_for_owner().get_configuration(self)

    @frappe.whitelist(methods=["POST"])
    def report(self, revision, success, digest=None):
        """Record what a host applied. `get_status` compares the digest with desired state, so a report for an
        older revision is accepted and simply shows as not current."""
        if type(revision) is not int or revision < 1:
            frappe.throw("Expected a positive integer revision")
        if type(success) is not bool:
            frappe.throw("Expected boolean success")
        if success and not (isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)):
            frappe.throw("Expected the applied configuration digest")
        network = self.lock_for_owner()
        if self.kind != "Service":
            raise frappe.PermissionError("Only service hosts report application")
        if not (self.reported_revision or 0) <= revision <= network.revision:
            frappe.throw("Report revision is out of order")
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

    @frappe.whitelist(methods=["POST"])
    def set_enabled(self, enabled):
        if type(enabled) not in (bool, int) or enabled not in (0, 1):
            frappe.throw("enabled must be 0 or 1")
        network = self.lock_for_editor()
        if self.name == network.hub and not enabled:
            frappe.throw("The hub must stay enabled")
        self.enabled = int(enabled)
        return self.save_membership(network)

    @frappe.whitelist(methods=["POST"])
    def rotate_key(self, public_key):
        network = self.lock_for_editor()
        self.public_key = public_key
        return self.save_membership(network)

    @frappe.whitelist(methods=["POST"])
    def release(self):
        """Delete a disabled peer and free its address once the hub has applied its removal."""
        network = self.lock_for_editor()
        if self.enabled:
            frappe.throw("Disable the peer first")
        hub, members = network.get_membership()
        if not network.is_current(hub, hub, members):
            frappe.throw("Wait until the hub has applied the removal")
        frappe.delete_doc(self.doctype, self.name, ignore_permissions=True, ignore_on_trash=True)
        return {"released": self.address}

    @frappe.whitelist(methods=["POST"])
    def set_endpoint(self, endpoint):
        network = self.lock_for_editor()
        if self.kind != "Service":
            frappe.throw("Device endpoints are learned by WireGuard")
        self.endpoint = endpoint
        return self.save_membership(network)


def has_permission(doc, ptype, user):
    return "VPN Manager" in frappe.get_roles(user) or doc.user == user


def get_permission_query_conditions(user):
    if "VPN Manager" not in frappe.get_roles(user):
        return f"`tabVPN Peer`.user = {frappe.db.escape(user)}"
