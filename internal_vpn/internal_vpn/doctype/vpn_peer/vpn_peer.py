import re

import frappe
from frappe.model.document import Document

from internal_vpn.host import WireGuard
from internal_vpn.internal_vpn.doctype.vpn_network.vpn_network import (
    ACCESS_ROLE_PREFIX,
    ACTION_WRITE,
    ROLE_FOR_KIND,
    VPNNetwork,
)


class VPNPeer(Document):
    """A host or device. Reserve its address until the hub applies removal and `release` frees it."""

    def before_validate(self):
        if self.flags.vpn_action is not ACTION_WRITE:
            frappe.throw("Use the VPN action methods to change membership")

    def validate(self):
        try:
            WireGuard.validate_public_key(self.public_key)
            if self.endpoint:
                self.endpoint = WireGuard.parse_endpoint(self.endpoint)
        except (TypeError, ValueError) as error:
            frappe.throw(str(error))

    def on_trash(self):
        frappe.throw("Disable the peer, then release it")

    def before_rename(self, *args, **kwargs):
        frappe.throw("VPN records cannot be renamed")

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
        network.save_document(self)
        return {"revision": network.advance_revision()}

    @frappe.whitelist(methods=["GET"])
    def get_configuration(self):
        return self.lock_for_owner().get_configuration(self)

    @frappe.whitelist(methods=["POST"])
    def report(self, revision, success, digest=None):
        """Record applied state. Status compares its digest with current membership."""
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
        if self.enabled == int(enabled):
            return {"revision": network.revision}
        self.enabled = int(enabled)
        return self.save_membership(network)

    @frappe.whitelist(methods=["POST"])
    def rotate_key(self, public_key):
        network = self.lock_for_editor()
        if self.public_key == public_key:
            return {"revision": network.revision}
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
    def set_access(self, rows):
        """Replace the access roles, with optional ports, that let devices reach this service."""
        network = self.lock_for_editor()
        if self.kind != "Service":
            frappe.throw("Access applies to services")
        wanted = []
        for row in frappe.parse_json(rows) if isinstance(rows, str) else rows or []:
            name = (
                str(row.get("role") or "").removeprefix(ACCESS_ROLE_PREFIX).strip()
                if isinstance(row, dict)
                else ""
            )
            if not re.fullmatch(r"[\w .-]{1,60}", name):
                frappe.throw("Name each access role with letters, digits, spaces, dots or dashes")
            try:
                ports = WireGuard.parse_ports(row.get("ports") or "")
            except (TypeError, ValueError) as error:
                frappe.throw(str(error))
            wanted.append({"role": ACCESS_ROLE_PREFIX + name, "ports": ports})
        if wanted == [{"role": row.role, "ports": row.ports or ""} for row in self.access]:
            return {"revision": network.revision}
        for row in wanted:
            if not frappe.db.exists("Role", row["role"]):
                frappe.get_doc({"doctype": "Role", "role_name": row["role"], "desk_access": 0}).insert(
                    ignore_permissions=True
                )
        self.set("access", wanted)
        return self.save_membership(network)

    @frappe.whitelist(methods=["POST"])
    def set_endpoint(self, endpoint):
        network = self.lock_for_editor()
        if self.kind != "Service" or (network.hub and self.name != network.hub):
            frappe.throw("Only the hub endpoint is used; others are learned by WireGuard")
        if self.name == network.hub and not endpoint:
            frappe.throw("The hub requires a UDP endpoint")
        try:
            endpoint = WireGuard.parse_endpoint(endpoint) if endpoint else None
        except (TypeError, ValueError) as error:
            frappe.throw(str(error))
        if (self.endpoint or None) == endpoint:
            return {"revision": network.revision}
        self.endpoint = endpoint
        return self.save_membership(network)


def has_permission(doc, ptype, user):
    return "VPN Manager" in frappe.get_roles(user) or doc.user == user


def get_permission_query_conditions(user):
    if "VPN Manager" not in frappe.get_roles(user):
        return f"`tabVPN Peer`.user = {frappe.db.escape(user)}"
