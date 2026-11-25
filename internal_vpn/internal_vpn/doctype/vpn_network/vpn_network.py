import subprocess

import frappe
from frappe import _
from frappe.desk.doctype.notification_log.notification_log import enqueue_create_notification
from frappe.model.document import Document
from frappe.query_builder import DocType
from frappe.utils import add_to_date, cint, get_datetime, now_datetime
from frappe.utils.user import get_users_with_role

from internal_vpn.host import MAX_PEERS, WireGuard

MEMBER_ROLES = {"VPN Server": "VPN Host", "VPN Device": "VPN Engineer"}
MEMBER_OWNERS = {"VPN Server": "user", "VPN Device": "owner"}
SYSTEM_FIELDS = ("revision", "hub_digest", "hub_alert")


class VPNNetwork(Document):
    """Network settings. The row lock serializes allocation and revisions."""

    @staticmethod
    def load_locked() -> "VPNNetwork":
        return frappe.get_doc("VPN Network", "VPN Network", for_update=True)

    def validate(self):
        frappe.db.get_singles_dict(self.doctype, for_update=True)
        before = self.get_doc_before_save() or frappe._dict()
        for field in SYSTEM_FIELDS:
            self.set(field, before.get(field))
        if self.subnet:
            self.subnet = str(parse(WireGuard.parse_subnet, self.subnet))
        if before.subnet and self.subnet != before.subnet:
            frappe.throw(_("Readdressing an existing network is not supported"))
        if self.hub_endpoint:
            self.hub_endpoint = parse(WireGuard.parse_endpoint, self.hub_endpoint)
        self.validate_hub(before.hub)
        if any(self.get(field) != before.get(field) for field in ("subnet", "hub", "hub_endpoint")):
            self.revision = cint(self.revision) + 1
            self.hub_digest = None
            frappe.db.after_commit.add(self.request_hub_update)

    def validate_hub(self, previous: str | None):
        if previous and self.hub != previous:
            frappe.throw(_("Replacing the hub needs explicit reprovisioning"))
        if not self.hub:
            return
        if not self.subnet or not self.hub_endpoint:
            frappe.throw(_("The hub requires a subnet and a UDP endpoint"))
        hub = frappe.db.get_value("VPN Server", self.hub, ["user", "enabled"], as_dict=True)
        if not hub or not hub.enabled or not self.is_eligible(hub.user, "VPN Server"):
            frappe.throw(_("The hub must be an enabled server whose user has the VPN Host role"))

    def advance_revision(self) -> int:
        self.db_set({"revision": cint(self.revision) + 1, "hub_digest": None})
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
    def is_eligible(user: str, doctype: str) -> bool:
        enabled = frappe.db.get_value("User", user, "enabled")
        return bool(enabled) and MEMBER_ROLES[doctype] in frappe.get_roles(user)

    def allocate_address(self) -> str:
        """Reserve capacity for disabled members too, so enabling one cannot overflow the hub."""
        if not self.subnet:
            frappe.throw(_("Set the network subnet first"))
        used = {
            address
            for doctype in MEMBER_ROLES
            for address in frappe.get_all(doctype, pluck="address", limit=0)
        }
        if len(used) >= MAX_PEERS + 1:
            frappe.throw(_("Network member limit reached; delete unused members first"))
        address = next(
            (str(ip) for ip in WireGuard.parse_subnet(self.subnet).hosts() if str(ip) not in used), None
        )
        if not address:
            frappe.throw(_("Subnet exhausted"))
        return address

    def get_membership(self, member=None) -> tuple[dict, dict[str, dict]]:
        """Enabled members with enabled, eligible owners. With `member`, only it and the hub."""
        names = [self.hub, member.name] if member and member.name != self.hub else None
        members = {}
        for doctype, role in MEMBER_ROLES.items():
            for row in self.query_members(doctype, role, names):
                members[row.name] = frappe._dict(row, doctype=doctype)
        hub = members.get(self.hub)
        if not hub:
            frappe.throw(_("Select an active hub before configuring the network"))
        return hub, dict(sorted(members.items()))

    @staticmethod
    def query_members(doctype: str, role: str, names: list[str] | None) -> list[dict]:
        member, user, has_role = DocType(doctype), DocType("User"), DocType("Has Role")
        owner = member[MEMBER_OWNERS[doctype]]
        owners_with_role = (
            frappe.qb.from_(has_role)
            .select(has_role.parent)
            .where((has_role.role == role) & (has_role.parenttype == "User"))
        )
        query = (
            frappe.qb.from_(member)
            .join(user)
            .on(user.name == owner)
            .select(member.star)
            .where((member.enabled == 1) & (user.enabled == 1) & owner.isin(owners_with_role))
        )
        if names:
            query = query.where(member.name.isin(names))
        return query.run(as_dict=True)

    def is_current(self, member, hub, members) -> bool:
        """Match the applied state, not tunnel health."""
        desired = WireGuard.digest(self.build_configuration(member, hub, members))
        return bool(
            member.apply_success
            and member.reported_digest == desired
            and (member.name != hub.name or member.reported_revision == self.revision)
        )

    def get_configuration(self, member) -> dict:
        snapshot = self.build_configuration(member, *self.get_membership(member))
        if member.name == self.hub:
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

    def build_configuration(self, member, hub, members) -> dict:
        """Protocol v3 snapshot. The hub lists every member as a /32, plus the servers for its rules;
        a spoke lists only the hub."""

        def entry(peer, endpoint, allowed_ips):
            return {
                "public_key": peer.public_key,
                "address": peer.address,
                "endpoint": endpoint,
                "allowed_ips": allowed_ips,
            }

        is_hub = member.name == hub.name
        if member.name not in members:
            peers = []
        elif is_hub:
            peers = [
                entry(peer, None, f"{peer.address}/32") for name, peer in members.items() if name != hub.name
            ]
        else:
            peers = [entry(hub, self.hub_endpoint, self.subnet)]
        return {
            "version": 3,
            "topology": "hub" if is_hub else "spoke",
            "name": member.name,
            "revision": self.revision,
            "subnet": self.subnet,
            "address": member.address,
            "public_key": member.public_key,
            "peers": peers,
            "access": {
                "services": [
                    peer.address
                    for name, peer in members.items()
                    if peer.doctype == "VPN Server" and name != hub.name
                ]
            }
            if is_hub
            else None,
        }

    @frappe.whitelist(methods=["POST"])
    def add_engineer(self, email: str, first_name: str | None = None) -> dict:
        """Give a user the engineer role. A new user gets an initial password for the operator to hand
        over, or Frappe's email link when `internal_vpn_invite_email` is set."""
        self.check_permission("write")
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
        user.add_roles(MEMBER_ROLES["VPN Device"])
        return {"user": user.name, "password": password}

    @frappe.whitelist(methods=["GET"])
    def get_status(self) -> dict:
        """Last application report per server."""
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
        for server in frappe.get_all("VPN Server", fields=["*"], order_by="name asc", limit=0):
            server = frappe._dict(server, doctype="VPN Server")
            status["hosts"].append(
                {
                    "name": server.name,
                    "label": server.label,
                    "address": server.address,
                    "user": server.user,
                    "enabled": server.enabled,
                    "reported_revision": server.reported_revision,
                    "apply_success": server.apply_success,
                    "reported_at": server.reported_at,
                    "required": server.name in members,
                    "current": self.is_current(server, hub, members),
                    "stale": bool(server.reported_at and server.reported_at < deadline),
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
        modified = get_datetime(self.modified)
        if (hub["reported_at"] or modified) < since:
            problem = "The VPN hub has stopped reporting"
        elif not status["hub_current"] and modified < since:
            problem = "The VPN hub has not applied the latest membership"
        if (problem or "") == (self.hub_alert or ""):
            return
        subject = problem or f"Resolved: {self.hub_alert}"
        self.db_set("hub_alert", problem, update_modified=False)
        frappe.logger("internal_vpn", allow_site=True).warning(subject)
        enqueue_create_notification(
            get_users_with_role("VPN Manager"),
            {"type": "Alert", "document_type": self.doctype, "document_name": self.name, "subject": subject},
        )

    def on_user_change(self, user, method: str):
        """Track owner eligibility changes; keep the hub eligible."""
        relevant = set(MEMBER_ROLES.values())
        roles = {row.role for row in user.roles}
        previous = user.get_doc_before_save()
        unchanged = (
            previous
            and previous.enabled == user.enabled
            and {row.role for row in previous.roles} & relevant == roles & relevant
        )
        if method != "on_trash" and unchanged:
            return

        hub_user = frappe.db.get_value("VPN Server", self.hub, "user") if self.hub else None
        if hub_user == user.name and (method == "on_trash" or not user.enabled or "VPN Host" not in roles):
            frappe.throw(_("The hub account must stay enabled with the VPN Host role"))
        if any(
            frappe.db.exists(doctype, {owner: user.name, "enabled": 1})
            for doctype, owner in MEMBER_OWNERS.items()
        ):
            self.advance_revision()


class VPNMember(Document):
    """A VPN Server or VPN Device. It holds one address until deleted; membership changes advance
    the network revision."""

    system_fields = ("address",)

    def before_insert(self):
        for field in self.system_fields:
            self.set(field, None)
        self.address = VPNNetwork.load_locked().allocate_address()

    def validate(self):
        network = VPNNetwork.load_locked()
        before = self.get_doc_before_save()
        if before:
            for field in self.system_fields:
                self.set(field, before.get(field))
        self.public_key = parse(WireGuard.validate_public_key, self.public_key)
        if any(
            frappe.db.exists(doctype, {"public_key": self.public_key, "name": ("!=", self.name)})
            for doctype in MEMBER_ROLES
        ):
            frappe.throw(_("This WireGuard key is already in use"), frappe.UniqueValidationError)
        if not self.enabled and self.name == network.hub:
            frappe.throw(_("The hub must stay enabled"))

    def on_update(self):
        if self.flags.in_insert or self.has_value_changed("enabled") or self.has_value_changed("public_key"):
            VPNNetwork.load_locked().advance_revision()

    def on_trash(self):
        """Free the address only once the hub has applied the removal."""
        network = VPNNetwork.load_locked()
        if self.enabled:
            frappe.throw(_("Disable it first, then delete it once the hub has applied the change"))
        if network.hub:
            hub, members = network.get_membership()
            if not network.is_current(hub, hub, members):
                frappe.throw(_("Wait until the hub has applied the removal"))

    def load_locked(self) -> VPNNetwork:
        """Lock the network, then reload this member from the database with a row lock."""
        network = VPNNetwork.load_locked()
        self.flags.for_update = True
        self.reload()
        return network


def parse(parser, value):
    try:
        return parser(value)
    except (TypeError, ValueError) as error:
        frappe.throw(str(error))


def has_desk_access() -> bool:
    return bool(frappe.has_permission("VPN Device", "read") or frappe.has_permission("VPN Network", "read"))


def check_hub():
    VPNNetwork.load_locked().check_hub()


def on_user_change(user, method=None):
    if frappe.db.table_exists("VPN Server"):
        VPNNetwork.load_locked().on_user_change(user, method)
