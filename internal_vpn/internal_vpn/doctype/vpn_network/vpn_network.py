import subprocess

import frappe
from frappe import _
from frappe.model.document import Document
from frappe.query_builder import DocType
from frappe.utils import add_to_date, cint, get_datetime, now_datetime

from internal_vpn.host import MAX_PEERS, WireGuard

MEMBER_ROLES = {"VPN Server": "VPN Host", "VPN Device": "VPN Engineer"}
MEMBER_OWNERS = {"VPN Server": "user", "VPN Device": "owner"}
SYSTEM_FIELDS = ("revision", "hub_digest")


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

    def on_update(self):
        if self.has_value_changed("revision") or self.has_value_changed("stale_minutes"):
            self.refresh_statuses()

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
        self.refresh_statuses()
        return self.revision

    def refresh_statuses(self):
        """Store each server's status. A change runs the VPN Server Health notification."""
        if not self.hub:
            return
        hub, members = self.get_membership()
        deadline = add_to_date(now_datetime(), minutes=-(cint(self.stale_minutes) or 5))
        for server in frappe.get_all("VPN Server", fields=["*"], order_by="name asc", limit=0):
            status = self.server_status(server, hub, members, deadline)
            if status != server.status:
                frappe.get_doc("VPN Server", server.name).db_set("status", status, update_modified=False)

    def server_status(self, server, hub, members, deadline) -> str:
        """A missing report outranks the applied state: the host may have stopped running."""
        if get_datetime(server.reported_at or server.creation) < deadline:
            return "Stale"
        if self.is_current(server, hub, members):
            return "Current"
        if server.reported_at and not server.apply_success:
            return "Failed"
        return "Pending"

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


def refresh_statuses():
    """Scheduled, so servers that stop reporting turn Stale."""
    frappe.get_doc("VPN Network").refresh_statuses()


def on_user_change(user, method=None):
    if frappe.db.table_exists("VPN Server"):
        VPNNetwork.load_locked().on_user_change(user, method)


def after_install():
    """Sign in with an email link only; Administrator gets in with `bench browse`."""
    frappe.db.set_single_value("System Settings", {"login_with_email_link": 1, "disable_user_pass_login": 1})
