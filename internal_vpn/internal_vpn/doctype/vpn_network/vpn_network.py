import frappe
from frappe.model.document import Document

from internal_vpn.host import WireGuard

ROLE_FOR_KIND = {"Service": "VPN Host", "Device": "VPN Engineer"}


class VPNNetwork(Document):
    """The single `default` network. Every membership change locks this row first, which serializes
    address allocation and revisions."""

    def lock(self, new_transaction: bool = True) -> "VPNNetwork":
        # Frappe auth fixes this request's snapshot before the lock, and MariaDB rejects a locking read of a
        # row changed since then (error 1020). Methods write nothing before locking, so they commit first:
        # every later read then sees all committed membership changes. The User hook cannot commit, because
        # the User save is still in its transaction.
        if new_transaction:
            frappe.db.commit()
        self.update(frappe.db.get_value(self.doctype, self.name, "*", as_dict=True, for_update=True))
        return self

    def advance_revision(self) -> int:
        self.db_set("revision", self.revision + 1, update_modified=False)
        return self.revision

    @staticmethod
    def get_locked() -> "VPNNetwork":
        return frappe.get_doc("VPN Network", "default").lock()

    @staticmethod
    def get_peers() -> list[dict]:
        return frappe.db.sql("SELECT * FROM `tabVPN Peer` ORDER BY name FOR UPDATE", as_dict=True)

    @staticmethod
    def is_eligible(user: str, kind: str) -> bool:
        return bool(
            frappe.db.get_value("User", user, "enabled")
            and frappe.db.exists(
                "Has Role", {"parent": user, "parenttype": "User", "role": ROLE_FOR_KIND[kind]}
            )
        )

    def get_membership(self) -> tuple[dict, list[dict]]:
        """Active members in one query: enabled peers whose owner is enabled and has the kind's role."""
        members = frappe.db.sql(
            """SELECT peer.* FROM `tabVPN Peer` peer
            JOIN `tabUser` account ON account.name = peer.user AND account.enabled = 1
            WHERE peer.enabled = 1 AND EXISTS (
                SELECT 1 FROM `tabHas Role` role
                WHERE role.parent = peer.user AND role.parenttype = 'User'
                AND role.role = IF(peer.kind = 'Service', %(service)s, %(device)s))
            ORDER BY peer.name""",
            {"service": ROLE_FOR_KIND["Service"], "device": ROLE_FOR_KIND["Device"]},
            as_dict=True,
        )
        hub = next((peer for peer in members if peer.name == self.hub), None)
        if not hub:
            frappe.throw("Select an active hub before configuring the network")
        return hub, members

    def is_current(self, peer, hub, members) -> bool:
        """The host's last successful report matches its desired state now. This does not prove the tunnel is live."""
        desired = WireGuard.digest(self.build_configuration(peer, hub, members, self.subnet, self.revision))
        return bool(peer.apply_success and peer.reported_digest == desired)

    def get_configuration(self, peer) -> dict:
        return self.build_configuration(peer, *self.get_membership(), self.subnet, self.revision)

    @staticmethod
    def build_configuration(peer, hub, members, subnet: str, revision: int) -> dict:
        """Protocol v2 snapshot. The hub lists every member as a /32; a spoke lists only the hub."""

        def entry(member, endpoint, allowed_ips):
            return {
                "public_key": member.public_key,
                "address": member.address,
                "endpoint": endpoint,
                "allowed_ips": allowed_ips,
            }

        is_hub = peer.name == hub.name
        if not any(member.name == peer.name for member in members):
            peers = []
        elif is_hub:
            others = sorted((m for m in members if m.name != peer.name), key=lambda member: member.name)
            peers = [entry(member, None, f"{member.address}/32") for member in others]
        else:
            peers = [entry(hub, hub.endpoint, subnet)]
        return {
            "version": 2,
            "topology": "hub" if is_hub else "spoke",
            "name": peer.name,
            "revision": revision,
            "subnet": subnet,
            "address": peer.address,
            "public_key": peer.public_key,
            "peers": peers,
        }

    def add_peer(self, kind: str, user: str, public_key: str, endpoint: str | None = None) -> dict:
        self.lock()
        if not self.subnet:
            frappe.throw("Initialize the subnet first")
        if not self.is_eligible(user, kind):
            frappe.throw("Owner must be enabled and have the required VPN role")
        peers = self.get_peers()
        if kind == "Service" and any(peer.user == user and peer.kind == "Service" for peer in peers):
            frappe.throw("Use one dedicated user per service")
        used = {peer.address for peer in peers}
        address = next(
            (str(ip) for ip in WireGuard.parse_subnet(self.subnet).hosts() if str(ip) not in used), None
        )
        if not address:
            frappe.throw("Subnet exhausted")

        peer = frappe.get_doc(
            {
                "doctype": "VPN Peer",
                "kind": kind,
                "user": user,
                "public_key": public_key,
                "endpoint": endpoint,
                "address": address,
            }
        ).insert(ignore_permissions=True)
        return {"name": peer.name, "address": address, "revision": self.advance_revision()}

    @frappe.whitelist(methods=["POST"])
    def initialize(self, subnet):
        frappe.only_for("VPN Manager")
        try:
            subnet = str(WireGuard.parse_subnet(subnet))
        except (TypeError, ValueError) as error:
            frappe.throw(str(error))
        self.lock()
        if self.subnet and self.subnet != subnet:
            frappe.throw("Readdressing an existing network is not supported")
        if not self.subnet:
            self.db_set("subnet", subnet)
            self.advance_revision()
        return {"subnet": subnet}

    @frappe.whitelist(methods=["POST"])
    def register_service(self, user, public_key, endpoint=None):
        frappe.only_for("VPN Manager")
        return self.add_peer("Service", user, public_key, endpoint)

    @frappe.whitelist(methods=["POST"])
    def register_device(self, public_key):
        frappe.only_for("VPN Engineer")
        return self.add_peer("Device", frappe.session.user, public_key)

    @frappe.whitelist(methods=["POST"])
    def set_hub(self, peer):
        frappe.only_for("VPN Manager")
        self.lock()
        if self.hub and self.hub != peer:
            frappe.throw("Replacing the hub needs explicit reprovisioning")
        hub = frappe.get_doc("VPN Peer", peer, for_update=True)
        if (
            hub.kind != "Service"
            or not hub.endpoint
            or not hub.enabled
            or not self.is_eligible(hub.user, "Service")
        ):
            frappe.throw("The hub must be an active service with a UDP endpoint")
        if not self.hub:
            self.db_set("hub", peer)
            self.advance_revision()
        return {"hub": peer}

    @frappe.whitelist(methods=["GET"])
    def get_status(self):
        """Last application report per service."""
        frappe.only_for("VPN Manager")
        self.lock()
        status = {
            "revision": self.revision,
            "hub": self.hub,
            "hub_current": False,
            "hosts": [],
            "all_current": False,
        }
        if not self.hub:
            return status

        hub, members = self.get_membership()
        active = {member.name for member in members}
        for peer in self.get_peers():
            if peer.kind != "Service":
                continue
            status["hosts"].append(
                {
                    "name": peer.name,
                    "enabled": peer.enabled,
                    "reported_revision": peer.reported_revision,
                    "apply_success": peer.apply_success,
                    "reported_at": peer.reported_at,
                    "required": peer.name in active,
                    "current": self.is_current(peer, hub, members),
                }
            )
        status["hub_current"] = next(host["current"] for host in status["hosts"] if host["name"] == self.hub)
        status["all_current"] = all(host["current"] for host in status["hosts"] if host["required"])
        return status

    def on_user_change(self, user, method: str):
        """Advance membership when a peer owner's enablement or VPN roles change. The hub owner must keep both."""
        relevant = set(ROLE_FOR_KIND.values())
        roles = {row.role for row in user.roles}
        previous = user.get_doc_before_save()
        unchanged = (
            previous
            and previous.enabled == user.enabled
            and {row.role for row in previous.roles} & relevant == roles & relevant
        )
        if method != "on_trash" and unchanged:
            return

        self.lock(new_transaction=False)
        peers = self.get_peers()
        hub_user = next((peer.user for peer in peers if peer.name == self.hub), None)
        if hub_user == user.name and (method == "on_trash" or not user.enabled or "VPN Host" not in roles):
            frappe.throw("The hub account must stay enabled with the VPN Host role")
        if any(peer.user == user.name and peer.enabled for peer in peers):
            self.advance_revision()


def on_user_change(user, method=None):
    if frappe.db.table_exists("VPN Network") and frappe.db.exists("VPN Network", "default"):
        frappe.get_doc("VPN Network", "default").on_user_change(user, method)


def after_install():
    for role in ("VPN Manager", *ROLE_FOR_KIND.values()):
        if not frappe.db.exists("Role", role):
            frappe.get_doc({"doctype": "Role", "role_name": role, "desk_access": 1}).insert()
    if not frappe.db.exists("VPN Network", "default"):
        frappe.get_doc({"doctype": "VPN Network", "name": "default", "revision": 0}).insert()
