import subprocess

import frappe
from frappe.desk.doctype.notification_log.notification_log import enqueue_create_notification
from frappe.model.document import Document
from frappe.utils import add_to_date, cint, now_datetime

from internal_vpn.host import MAX_PEERS, WireGuard

ACTION_WRITE = object()
ROLE_FOR_KIND = {"Service": "VPN Host", "Device": "VPN Engineer"}
ACCESS_ROLE_PREFIX = "VPN Access: "


class VPNNetwork(Document):
    """The `default` network; its row lock serializes allocation and revisions."""

    def before_validate(self):
        if self.flags.vpn_action is not ACTION_WRITE:
            frappe.throw("Use the VPN action methods to change membership")

    def on_trash(self):
        frappe.throw("The VPN network cannot be deleted")

    def before_rename(self, *args, **kwargs):
        frappe.throw("VPN records cannot be renamed")

    @staticmethod
    def save_document(doc):
        # An identity marker cannot be supplied through a serialized document.
        doc.flags.vpn_action = ACTION_WRITE
        try:
            doc.save(ignore_permissions=True)
        finally:
            doc.flags.pop("vpn_action", None)

    def lock(self, new_transaction: bool = True) -> "VPNNetwork":
        # Refresh the auth snapshot to avoid MariaDB error 1020. Call before any writes.
        # User hooks keep their enclosing transaction instead.
        if new_transaction:
            frappe.db.commit()
        self.update(frappe.db.get_value(self.doctype, self.name, "*", as_dict=True, for_update=True))
        return self

    def advance_revision(self) -> int:
        self.revision += 1
        self.hub_digest = None
        self.save_document(self)
        if self.hub:
            frappe.db.after_commit.add(self.request_hub_update)
        return self.revision

    @staticmethod
    def request_hub_update():
        """Wake the local updater after commit; the timer handles missed wakeups."""
        try:
            subprocess.run(
                [
                    "/usr/bin/sudo",
                    "-n",
                    "/usr/bin/systemctl",
                    "start",
                    "--no-block",
                    "internal-vpn-update.service",
                ],
                check=True,
                capture_output=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            frappe.logger("internal_vpn", allow_site=True).error(
                "Could not start the hub updater. Check sudoers and the update timer."
            )

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

    def get_membership(self, peer=None) -> tuple[dict, dict[str, dict]]:
        """Enabled peers with enabled, eligible owners."""
        names = (self.hub, peer.name) if peer and peer.name != self.hub else None
        members = frappe.db.sql(
            """SELECT peer.* FROM `tabVPN Peer` peer
            JOIN `tabUser` account ON account.name = peer.user AND account.enabled = 1
            WHERE peer.enabled = 1 AND EXISTS (
                SELECT 1 FROM `tabHas Role` role
                WHERE role.parent = peer.user AND role.parenttype = 'User'
                AND role.role = IF(peer.kind = 'Service', %(service)s, %(device)s))
            """
            + (" AND peer.name IN %(names)s" if names else "")
            + " ORDER BY peer.name",
            {"service": ROLE_FOR_KIND["Service"], "device": ROLE_FOR_KIND["Device"], "names": names},
            as_dict=True,
        )
        members = {peer.name: peer for peer in members}
        hub = members.get(self.hub)
        if not hub:
            frappe.throw("Select an active hub before configuring the network")
        return hub, members

    def is_current(self, peer, hub, members) -> bool:
        """Match the applied state, not tunnel health."""
        desired = WireGuard.digest(self.build_configuration(peer, hub, members))
        return bool(
            peer.apply_success
            and peer.reported_digest == desired
            and (peer.name != hub.name or peer.reported_revision == self.revision)
        )

    def get_configuration(self, peer) -> dict:
        snapshot = self.build_configuration(peer, *self.get_membership(peer))
        if peer.name == self.hub:
            self.issue_hub_digest(snapshot)
        return snapshot

    def issue_hub_digest(self, snapshot: dict):
        """One hub digest per revision, so owner changes that skip User hooks still advance it."""
        digest = WireGuard.digest(snapshot)
        if self.hub_digest == digest:
            return
        if self.hub_digest:
            snapshot["revision"] = self.advance_revision()
        self.db_set("hub_digest", digest, update_modified=False)
        # Configuration is fetched with GET, which Frappe rolls back.
        frappe.db.commit()

    def build_configuration(self, peer, hub, members) -> dict:
        """Protocol v3 snapshot. The hub lists every member as a /32; a spoke lists only the hub."""

        def entry(member, endpoint, allowed_ips):
            return {
                "public_key": member.public_key,
                "address": member.address,
                "endpoint": endpoint,
                "allowed_ips": allowed_ips,
            }

        is_hub = peer.name == hub.name
        if peer.name not in members:
            peers = []
        elif is_hub:
            others = sorted(
                (m for m in members.values() if m.name != peer.name), key=lambda member: member.name
            )
            peers = [entry(member, None, f"{member.address}/32") for member in others]
        else:
            peers = [entry(hub, hub.endpoint, self.subnet)]
        return {
            "version": 3,
            "topology": "hub" if is_hub else "spoke",
            "name": peer.name,
            "revision": self.revision,
            "subnet": self.subnet,
            "address": peer.address,
            "public_key": peer.public_key,
            "peers": peers,
            "access": self.build_access(members) if is_hub else None,
        }

    def build_access(self, members) -> dict:
        """Hub rules: servers reach each other, devices reach servers, and nothing opens a device.
        With access control on, a device reaches a server only through an access role its owner holds."""
        services = sorted(
            (m for m in members.values() if m.kind == "Service" and m.name != self.hub), key=lambda m: m.name
        )
        access = {
            "restricted": bool(self.access_control),
            "services": [s.address for s in services],
            "rules": [],
        }
        if not self.access_control:
            return access
        devices = sorted((m for m in members.values() if m.kind == "Device"), key=lambda m: m.name)
        grants = frappe.get_all(
            "VPN Access",
            filters={"parenttype": "VPN Peer", "parent": ("in", [s.name for s in services] or [""])},
            fields=["parent", "role", "ports"],
            parent_doctype="VPN Peer",
        )
        held = {}
        for row in frappe.get_all(
            "Has Role",
            filters={
                "parenttype": "User",
                "parent": ("in", [d.user for d in devices] or [""]),
                "role": ("like", ACCESS_ROLE_PREFIX + "%"),
            },
            fields=["parent", "role"],
            parent_doctype="User",
        ):
            held.setdefault(row.parent, set()).add(row.role)
        for device in devices:
            for service in services:
                ports = [
                    grant.ports or ""
                    for grant in grants
                    if grant.parent == service.name and grant.role in held.get(device.user, ())
                ]
                if ports:
                    joined = "" if "" in ports else WireGuard.parse_ports(",".join(ports))
                    access["rules"].append(
                        {"source": device.address, "destination": service.address, "ports": joined}
                    )
        return access

    def add_peer(
        self, kind: str, user: str, public_key: str, label: str, endpoint: str | None = None
    ) -> dict:
        label = (label or "").strip()
        if not label:
            frappe.throw("Name the peer")
        self.lock()
        if not self.subnet:
            frappe.throw("Initialize the subnet first")
        if not self.is_eligible(user, kind):
            frappe.throw("Owner must be enabled and have the required VPN role")
        peers = self.get_peers()
        # Reserve capacity for disabled peers too, so re-enabling cannot overflow the hub.
        if len(peers) >= MAX_PEERS + 1:
            frappe.throw("Network peer limit reached; release unused peers first")
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
                "label": label,
                "user": user,
                "public_key": public_key,
                "endpoint": endpoint,
                "address": address,
            }
        )
        self.save_document(peer)
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
            self.subnet = subnet
            self.advance_revision()
        return {"subnet": subnet}

    @frappe.whitelist(methods=["POST"])
    def register_service(self, user, public_key, label, endpoint=None):
        frappe.only_for("VPN Manager")
        return self.add_peer("Service", user, public_key, label, endpoint)

    @frappe.whitelist(methods=["POST"])
    def add_engineer(self, email, first_name=None):
        """Give a user the engineer role. A new user gets an initial password for the operator to hand
        over, or Frappe's email link when `internal_vpn_invite_email` is set."""
        frappe.only_for("VPN Manager")
        password = None
        if frappe.db.exists("User", email):
            user = frappe.get_doc("User", email)
        else:
            by_email = bool(frappe.conf.get("internal_vpn_invite_email"))
            password = None if by_email else frappe.generate_hash(length=24)
            user = frappe.get_doc(
                {
                    "doctype": "User",
                    "email": email,
                    "first_name": first_name or email.split("@")[0],
                    "send_welcome_email": int(by_email),
                    "new_password": password,
                }
            )
        user.flags.ignore_permissions = True
        user.add_roles(ROLE_FOR_KIND["Device"])
        return {"user": user.name, "password": password}

    @frappe.whitelist(methods=["GET"])
    def get_access_roles(self, user):
        """Every VPN access role, marked when the user holds it."""
        frappe.only_for("VPN Manager")
        roles = frappe.get_all(
            "Role", filters={"name": ("like", ACCESS_ROLE_PREFIX + "%")}, pluck="name", order_by="name"
        )
        held = frappe.get_all(
            "Has Role",
            filters={"parenttype": "User", "parent": user, "role": ("in", roles or [""])},
            pluck="role",
            parent_doctype="User",
        )
        return [{"role": role, "held": role in held} for role in roles]

    @frappe.whitelist(methods=["POST"])
    def set_access_roles(self, user, roles):
        """Replace a user's VPN access roles; their other roles stay."""
        frappe.only_for("VPN Manager")
        roles = set(frappe.parse_json(roles) if isinstance(roles, str) else roles or [])
        if any(
            not isinstance(role, str)
            or not role.startswith(ACCESS_ROLE_PREFIX)
            or not frappe.db.exists("Role", role)
            for role in roles
        ):
            frappe.throw("Grant only existing VPN access roles")
        doc = frappe.get_doc("User", user)
        kept = [row.role for row in doc.roles if not row.role.startswith(ACCESS_ROLE_PREFIX)]
        if {row.role for row in doc.roles} - set(kept) != roles:
            doc.set("roles", [{"role": role} for role in kept + sorted(roles)])
            doc.flags.ignore_permissions = True
            doc.save()
        return {"roles": sorted(roles)}

    @frappe.whitelist(methods=["POST"])
    def set_access_control(self, enabled):
        frappe.only_for("VPN Manager")
        if type(enabled) not in (bool, int) or enabled not in (0, 1):
            frappe.throw("enabled must be 0 or 1")
        self.lock()
        if self.access_control != int(enabled):
            self.access_control = int(enabled)
            self.advance_revision()
        return {"access_control": self.access_control}

    @frappe.whitelist(methods=["POST"])
    def register_device(self, public_key, label):
        frappe.only_for(ROLE_FOR_KIND["Device"])
        return self.add_peer("Device", frappe.session.user, public_key, label)

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
            self.hub = peer
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
        deadline = self.report_deadline()
        for peer in self.get_peers():
            if peer.kind != "Service":
                continue
            status["hosts"].append(
                {
                    "name": peer.name,
                    "address": peer.address,
                    "user": peer.user,
                    "enabled": peer.enabled,
                    "reported_revision": peer.reported_revision,
                    "apply_success": peer.apply_success,
                    "reported_at": peer.reported_at,
                    "required": peer.name in members,
                    "current": self.is_current(peer, hub, members),
                    "stale": bool(peer.reported_at and peer.reported_at < deadline),
                }
            )
        status["hub_current"] = next(host["current"] for host in status["hosts"] if host["name"] == self.hub)
        status["all_current"] = all(
            host["current"] and not host["stale"] for host in status["hosts"] if host["required"]
        )
        return status

    @staticmethod
    def report_deadline():
        """Reports older than this are stale: the alert threshold, or 5 minutes when alerts are off."""
        minutes = cint(frappe.conf.get("internal_vpn_hub_alert_minutes")) or 5
        return add_to_date(now_datetime(), minutes=-minutes)

    def check_hub(self):
        """Notify VPN Managers once when the hub stops reporting or lags membership, and once on recovery."""
        if not cint(frappe.conf.get("internal_vpn_hub_alert_minutes")) or not self.hub:
            return
        status = self.get_status()
        hub = next(host for host in status["hosts"] if host["name"] == self.hub)
        since = self.report_deadline()
        problem = None
        if (hub["reported_at"] or self.modified) < since:
            problem = "The VPN hub has stopped reporting"
        elif not status["hub_current"] and self.modified < since:
            problem = "The VPN hub has not applied the latest membership"
        if (problem or "") == (self.hub_alert or ""):
            return
        subject = problem or f"Resolved: {self.hub_alert}"
        self.db_set("hub_alert", problem, update_modified=False)
        frappe.logger("internal_vpn", allow_site=True).warning(subject)
        managers = frappe.get_all("Has Role", {"role": "VPN Manager", "parenttype": "User"}, pluck="parent")
        enqueue_create_notification(
            managers,
            {"type": "Alert", "document_type": self.doctype, "document_name": self.name, "subject": subject},
        )

    def on_user_change(self, user, method: str):
        """Track owner eligibility and access role changes; keep the hub eligible."""

        def relevant(doc):
            return {
                row.role
                for row in doc.roles
                if row.role in ROLE_FOR_KIND.values() or row.role.startswith(ACCESS_ROLE_PREFIX)
            }

        roles = {row.role for row in user.roles}
        previous = user.get_doc_before_save()
        unchanged = previous and previous.enabled == user.enabled and relevant(previous) == relevant(user)
        if method != "on_trash" and unchanged:
            return

        self.lock(new_transaction=False)
        peers = self.get_peers()
        hub_user = next((peer.user for peer in peers if peer.name == self.hub), None)
        if hub_user == user.name and (method == "on_trash" or not user.enabled or "VPN Host" not in roles):
            frappe.throw("The hub account must stay enabled with the VPN Host role")
        if any(peer.user == user.name and peer.enabled for peer in peers):
            self.advance_revision()


def has_desk_access():
    return frappe.has_permission("VPN Network", "read")


def check_hub():
    frappe.get_doc("VPN Network", "default").check_hub()


def on_user_change(user, method=None):
    if frappe.db.table_exists("VPN Network") and frappe.db.exists("VPN Network", "default"):
        frappe.get_doc("VPN Network", "default").on_user_change(user, method)


def after_install():
    for role in ("VPN Manager", *ROLE_FOR_KIND.values()):
        if not frappe.db.exists("Role", role):
            frappe.get_doc({"doctype": "Role", "role_name": role, "desk_access": 1}).insert()
    if not frappe.db.exists("VPN Network", "default"):
        VPNNetwork.save_document(
            frappe.get_doc({"doctype": "VPN Network", "name": "default", "revision": 0, "__islocal": 1})
        )
