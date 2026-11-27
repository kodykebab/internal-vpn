import re
from pathlib import Path
from urllib.parse import urlencode

import frappe
from frappe import _
from frappe.share import add_docshare
from frappe.utils import add_to_date, get_datetime, get_url, now_datetime

import internal_vpn.host
from internal_vpn.host import WireGuard
from internal_vpn.internal_vpn.doctype.vpn_network.vpn_network import VPNMember, VPNNetwork

ENROLL_MINUTES = 30


class VPNServer(VPNMember):
    """A hub or service host. Its host user acts for it through the `agent` permission."""

    # begin: auto-generated types
    # This code is auto-generated. Do not modify anything in this block.

    from typing import TYPE_CHECKING

    if TYPE_CHECKING:
        from frappe.types import DF

        address: DF.Data | None
        agent_outdated: DF.Check
        apply_success: DF.Check
        enabled: DF.Check
        enroll_before: DF.Datetime | None
        label: DF.Data
        last_handshake: DF.Datetime | None
        public_key: DF.Data | None
        reported_at: DF.Datetime | None
        reported_digest: DF.Data | None
        reported_revision: DF.Int
        status: DF.Literal["Pending", "Current", "Failed", "Stale", "Never Reported"]
        user: DF.Link | None
    # end: auto-generated types

    system_fields = (
        "address",
        "last_handshake",
        "status",
        "reported_revision",
        "apply_success",
        "reported_at",
        "reported_digest",
        "agent_outdated",
        "enroll_before",
    )

    def before_insert(self):
        super().before_insert()
        if not self.user:
            self.user = self.create_host_user()
        self.enroll_before = add_to_date(now_datetime(), minutes=ENROLL_MINUTES)

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
        self.issue_token()

    def onload(self):
        """The enrollment command for a server that has no key yet, while its window is open."""
        if self.public_key or not self.has_permission("write"):
            return
        expired = not self.enroll_before or now_datetime() > get_datetime(self.enroll_before)
        user = frappe.get_doc("User", self.user)
        token = f"{user.api_key}:{user.get_password('api_secret')}"
        agent = get_url("/api/method/run_doc_method?") + urlencode(
            {"dt": self.doctype, "dn": self.name, "method": "agent"}
        )
        command = (
            f'curl -fsS -H "Authorization: token {token}" "{agent}" -o /tmp/ivpn-host.py && '
            f"sudo python3 /tmp/ivpn-host.py enroll --url {get_url()} --server {self.name} --token {token}"
        )
        self.set_onload("enrollment", {"expired": expired, "expires": self.enroll_before, "command": command})

    def create_host_user(self) -> str:
        """A dedicated user with only the VPN Host role, which has no Desk access."""
        email = f"{frappe.scrub(self.label)}-{frappe.generate_hash(length=6)}@vpn-host.invalid"
        user = frappe.get_doc(
            {
                "doctype": "User",
                "email": email,
                "first_name": self.label,
                "send_welcome_email": 0,
                "roles": [{"role": "VPN Host"}],
            }
        )
        user.insert(ignore_permissions=True)
        return user.name

    def issue_token(self) -> str:
        """A new API secret for the host user. The previous one stops working."""
        user = frappe.get_doc("User", self.user)
        user.api_key = user.api_key or frappe.generate_hash(length=15)
        secret = frappe.generate_hash(length=15)
        user.api_secret = secret
        user.save(ignore_permissions=True)
        return f"{user.api_key}:{secret}"

    @frappe.whitelist(methods=["POST"])
    def enroll(self, public_key: str) -> dict:
        """Accept the host's public key once, before the window closes, and replace its token."""
        self.check_permission("agent")
        network = self.load_locked()
        if not network.hub or self.name == network.hub:
            frappe.throw(_("Enroll spokes only, after the hub is set up"))
        if self.public_key:
            frappe.throw(_("This server is already enrolled. A manager can start a new enrollment."))
        if not self.enroll_before or now_datetime() > get_datetime(self.enroll_before):
            frappe.throw(_("The enrollment window has closed. A manager can start a new enrollment."))
        self.public_key = public_key
        self.flags.ignore_permissions = True
        self.save()
        return {
            "subnet": network.subnet,
            "address": self.address,
            "hub_public_key": frappe.db.get_value("VPN Server", network.hub, "public_key", for_update=True),
            "token": self.issue_token(),
        }

    @frappe.whitelist(methods=["GET"])
    def agent(self):
        """This app's host.py, for its own host to enroll or upgrade."""
        self.check_permission("agent")
        frappe.local.response.update(
            {
                "type": "download",
                "filename": "host.py",
                "filecontent": Path(internal_vpn.host.__file__).read_bytes(),
                "content_type": "text/x-python",
            }
        )

    @frappe.whitelist(methods=["POST"])
    def new_enrollment(self):
        """For a rebuilt host: drop its key and token, and open a new window."""
        self.check_permission("write")
        if self.name == self.load_locked().hub:
            frappe.throw(_("Set up the hub by hand"))
        self.public_key = None
        self.save()
        self.db_set(
            "enroll_before", add_to_date(now_datetime(), minutes=ENROLL_MINUTES), update_modified=False
        )
        self.issue_token()

    @frappe.whitelist(methods=["POST"])
    def get_configuration(self) -> dict:
        self.check_permission("agent")
        return self.load_locked().get_configuration(self)

    @frappe.whitelist(methods=["POST"])
    def report(self, revision: int, success: bool, agent: str, digest: str | None = None) -> dict:
        """Record applied state. Status compares its digest with current membership."""
        self.check_permission("agent")
        if revision < 1:
            frappe.throw(_("Expected a positive integer revision"))
        if success and not re.fullmatch(r"[0-9a-f]{64}", digest or ""):
            frappe.throw(_("Expected the applied configuration digest"))
        self.record_report(self.load_locked(), revision, digest if success else None, agent)
        return {"accepted": True}

    def record_report(self, network, revision: int, digest: str | None, agent: str | None = None):
        """Record what the host applied; None means applying failed. A spoke sends the digest of its
        agent; the hub runs the app's own code."""
        if not (self.reported_revision or 0) <= revision <= network.revision:
            frappe.throw(_("Report revision is out of order"))
        self.db_set(
            {
                "reported_revision": revision,
                "apply_success": digest is not None,
                "reported_digest": digest,
                "reported_at": frappe.utils.now_datetime(),
                "agent_outdated": self.name != network.hub and agent != WireGuard.agent_digest(),
            },
            update_modified=False,
        )
        network.refresh_statuses()
