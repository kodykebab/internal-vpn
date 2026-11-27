import base64
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import frappe
from frappe.core.api.user_invitation import invite_by_email
from frappe.handler import run_doc_method
from frappe.tests import IntegrationTestCase
from frappe.utils import add_to_date, now_datetime
from werkzeug.wrappers import Request

from internal_vpn.host import Host, WireGuard
from internal_vpn.internal_vpn.doctype.vpn_network.vpn_network import VPNNetwork, apply_hub

IGNORE_TEST_RECORD_DEPENDENCIES = ["User", "VPN Server"]
MODULE = "internal_vpn.internal_vpn.doctype.vpn_network.vpn_network"
MANAGER = "vpn-manager@example.test"
ENGINEER = "vpn-engineer@example.test"
OTHER = "vpn-other@example.test"
HUB = "vpn-hub@example.test"
SPOKE = "vpn-spoke@example.test"
ROLES = {
    MANAGER: "VPN Manager",
    ENGINEER: "VPN Engineer",
    OTHER: "VPN Engineer",
    HUB: "VPN Host",
    SPOKE: "VPN Host",
}


def key(byte):
    return base64.b64encode(bytes([byte]) * 32).decode()


class VPNTestCase(IntegrationTestCase):
    """A network with a hub, built inside each test and rolled back after it. Each simulated request
    runs in a savepoint, so a refused one leaves nothing behind."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        wakeup = patch.object(VPNNetwork, "enqueue_hub_apply")
        cls.wakeup = wakeup.start()
        cls.addClassCleanup(wakeup.stop)
        frappe.flags.mute_emails = True
        frappe.set_user("Administrator")
        for email, role in ROLES.items():
            if not frappe.db.exists("User", email):
                frappe.get_doc(
                    {
                        "doctype": "User",
                        "email": email,
                        "first_name": email.split("@")[0],
                        "send_welcome_email": 0,
                        "roles": [{"role": role}],
                    }
                ).insert()
        frappe.db.commit()  # keep shared users past per-test rollback  # nosemgrep

    def setUp(self):
        super().setUp()
        frappe.set_user("Administrator")
        self.addCleanup(frappe.set_user, "Administrator")
        self.addCleanup(frappe.db.rollback)
        for doctype in ("VPN Access", "VPN Device", "VPN Server"):
            frappe.db.delete(doctype)
            frappe.db.delete("DocShare", {"share_doctype": doctype})
        frappe.db.set_single_value(
            "VPN Network",
            {
                "subnet": None,
                "hub": None,
                "hub_endpoint": None,
                "revision": 0,
                "hub_digest": None,
                "stale_minutes": 5,
                "access_control": 0,
                "vpn_only_desk": 0,
                "onboarding_minutes": 30,
            },
        )
        for email in (ENGINEER, OTHER, HUB, SPOKE):
            user = frappe.get_doc("User", email)
            user.enabled = 1
            user.set("roles", [{"role": ROLES[email]}])
            user.save()
        self.save_network(subnet="100.100.64.0/24")
        self.hub = self.server(HUB, key(1))
        self.save_network(hub=self.hub.name, hub_endpoint="192.0.2.1:51820")
        self.wakeup.reset_mock()

    @staticmethod
    def act(actor, action):
        """One request as `actor`, in a savepoint so a refused request leaves nothing behind."""
        frappe.set_user(actor)
        frappe.db.savepoint("vpn_request")
        try:
            return action()
        except Exception:
            frappe.db.rollback(save_point="vpn_request")
            raise

    def save_network(self, actor=MANAGER, **values):
        def save():
            network = frappe.get_doc("VPN Network")
            network.update(values)
            network.save()
            return network

        return self.act(actor, save)

    def server(self, user, public_key, label="service"):
        doc = {"doctype": "VPN Server", "label": label, "user": user, "public_key": public_key}
        return self.act(MANAGER, lambda: frappe.get_doc(doc).insert())

    def device(self, public_key=None, actor=ENGINEER):
        doc = {"doctype": "VPN Device", "label": "laptop", "public_key": public_key or key(3)}
        return self.act(actor, lambda: frappe.get_doc(doc).insert())

    def update(self, doctype, name, actor=MANAGER, **values):
        def save():
            doc = frappe.get_doc(doctype, name)
            doc.update(values)
            doc.save()
            return doc

        return self.act(actor, save)

    def delete(self, doctype, name, actor=MANAGER):
        self.act(actor, lambda: frappe.delete_doc(doctype, name))

    def call(self, actor, doctype, name, method, http_method="POST", **args):
        def run():
            frappe.local.request = Request.from_values(method=http_method)
            frappe.local.form_dict = frappe._dict()
            frappe.local.response = frappe._dict(docs=[])
            run_doc_method(method, dt=doctype, dn=name, args=args)
            return frappe.response.message

        return self.act(actor, run)

    def hub_configuration(self, actor=HUB):
        return self.call(actor, "VPN Server", self.hub.name, "get_configuration")

    def report_hub(self):
        snapshot = self.hub_configuration()
        self.call(
            HUB,
            "VPN Server",
            self.hub.name,
            "report",
            revision=snapshot["revision"],
            success=True,
            digest=WireGuard.digest(snapshot),
            agent=WireGuard.agent_digest(),
        )

    def hub_status(self):
        return frappe.db.get_value("VPN Server", self.hub.name, "status")

    @staticmethod
    def revision():
        return frappe.db.get_single_value("VPN Network", "revision")

    def grant(self, server, user=ENGINEER, ports=""):
        doc = {"doctype": "VPN Access", "server": server, "user": user, "ports": ports}
        return self.act(MANAGER, lambda: frappe.get_doc(doc).insert())

    def new_server(self, label="atlas"):
        return self.act(MANAGER, lambda: frappe.get_doc({"doctype": "VPN Server", "label": label}).insert())

    def enrollment(self, name, actor=MANAGER):
        def load():
            doc = frappe.get_doc("VPN Server", name)
            doc.run_method("onload")
            return doc.get_onload().get("enrollment")

        return self.act(actor, load)

    def peers(self):
        return [peer["address"] for peer in self.hub_configuration()["peers"]]


class TestVPNNetwork(VPNTestCase):
    """Network settings, revisions, the hub job, status and user changes."""

    def test_network_settings_are_fixed_once_set_and_validated(self):
        other = self.server(SPOKE, key(2))
        revision = self.revision()
        for values in (
            {"subnet": "100.100.65.0/24"},
            {"hub": other.name},
            {"hub_endpoint": ""},
            {"hub_endpoint": "invalid"},
            {"hub_endpoint": "0.0.0.0:1"},
        ):
            with self.subTest(values=values), self.assertRaises(frappe.ValidationError):
                self.save_network(**values)
        self.assertEqual(frappe.db.get_single_value("VPN Network", "hub_endpoint"), "192.0.2.1:51820")
        self.assertEqual(
            self.save_network(hub_endpoint="[2001:DB8::1]:51820").hub_endpoint, "[2001:db8::1]:51820"
        )
        self.assertEqual(self.revision(), revision + 1)
        with self.assertRaises(frappe.PermissionError):
            self.save_network(actor=ENGINEER, hub_endpoint="192.0.2.9:51820")

    def test_managers_invite_engineers(self):
        email = f"vpn-invited-{frappe.generate_hash(length=8)}@example.test"

        def invite(actor, roles=("VPN Engineer",)):
            return self.act(
                actor, lambda: invite_by_email(email, list(roles), "/desk/vpn-device", "internal_vpn")
            )

        with self.assertRaises(frappe.PermissionError):
            invite(ENGINEER)
        with self.assertRaises(frappe.ValidationError):
            invite(MANAGER, ["VPN Manager"])
        with patch(
            "frappe.core.doctype.user_invitation.user_invitation.UserInvitation.send_invitation_mail"
        ) as mail:
            self.assertEqual(invite(MANAGER)["invited_emails"], [email])
        mail.assert_called_once()
        invitation = frappe.get_doc("User Invitation", {"email": email})
        self.act("Guest", lambda: invitation.accept(ignore_permissions=True))
        self.assertIn("VPN Engineer", frappe.get_roles(email))
        self.assertTrue(self.device(key(4), actor=email).name)

    def test_hub_job_applies_and_records_reports(self):
        self.device()
        self.assertEqual(self.wakeup.call_count, 1)
        with (
            tempfile.TemporaryDirectory() as state,
            patch.object(Host, "apply") as apply,
            patch.object(WireGuard, "handshakes", return_value={}),
        ):
            self.act("Administrator", apply_hub)
            apply.assert_not_called()
            with patch.dict(
                frappe.conf, {"internal_vpn_interface": "ivpn0", "internal_vpn_state_dir": state}
            ):
                self.act("Administrator", apply_hub)
                self.assertEqual(self.hub_status(), "Current")
                self.assertEqual(len(apply.call_args.args[0]["peers"]), 1)
                self.assertTrue((Path(state) / "revision.json").exists())

                apply.side_effect = OSError("wg failed")
                self.device(key(4))
                self.act("Administrator", apply_hub)
                self.assertEqual(self.hub_status(), "Failed")
                failures = frappe.get_all("Error Log", {"method": "Internal VPN hub apply failed at apply"})
                self.assertTrue(failures)

    def test_hub_job_records_handshakes(self):
        device = self.device()
        atlas = self.server(SPOKE, key(2), label="atlas")
        now = int(time.time())

        def run(seconds):
            with (
                tempfile.TemporaryDirectory() as state,
                patch.dict(frappe.conf, {"internal_vpn_interface": "ivpn0", "internal_vpn_state_dir": state}),
                patch.object(Host, "apply"),
                patch.object(WireGuard, "handshakes", return_value={key(3): seconds, key(2): 0}),
            ):
                self.act("Administrator", apply_hub)
            return frappe.db.get_value("VPN Device", device.name, "last_handshake")

        first = run(now)
        self.assertLess(abs((first - now_datetime()).total_seconds()), 5)
        self.assertIsNone(frappe.db.get_value("VPN Server", atlas.name, "last_handshake"))
        self.assertEqual(run(now + 30), first)
        self.assertGreater(run(now + 120), first)

    def test_system_fields_keep_their_values(self):
        device = self.device()
        self.report_hub()
        revision = self.revision()
        self.update("VPN Device", device.name, address="100.100.64.99")
        self.update("VPN Server", self.hub.name, reported_revision=999, apply_success=0)
        self.save_network(revision=999, hub_digest="forged")
        self.assertEqual(frappe.db.get_value("VPN Device", device.name, "address"), device.address)
        self.assertEqual(frappe.db.get_value("VPN Server", self.hub.name, "reported_revision"), revision)
        self.assertEqual(self.revision(), revision)
        self.assertEqual(self.hub_status(), "Current")

    def test_member_changes_leave_the_network_unedited(self):
        modified = frappe.db.get_single_value("VPN Network", "modified")
        open_form = frappe.get_doc("VPN Network")
        revision = self.revision()
        self.device()
        self.assertEqual(self.revision(), revision + 1)
        self.assertEqual(frappe.db.get_single_value("VPN Network", "modified"), modified)

        def save_open_form():
            open_form.stale_minutes = 7
            open_form.save()

        self.act(MANAGER, save_open_form)
        self.assertEqual(self.revision(), revision + 1)
        self.assertEqual(frappe.db.get_single_value("VPN Network", "stale_minutes"), 7)

    def test_unchanged_saves_do_not_advance_revision_or_wake_hub(self):
        device = self.device()
        self.report_hub()
        revision = self.revision()
        self.wakeup.reset_mock()
        self.update("VPN Device", device.name, actor=ENGINEER, label="work laptop")
        self.update("VPN Device", device.name, actor=ENGINEER, public_key=key(3))
        self.save_network(hub_endpoint="192.0.2.1:051820")
        self.assertEqual(self.revision(), revision)
        self.wakeup.assert_not_called()
        self.assertEqual(self.hub_status(), "Current")

    def test_spoke_lookup_is_bounded_and_matches_full_snapshot(self):
        service = self.server(SPOKE, key(2))
        self.device()
        frappe.set_user("Administrator")
        network = VPNNetwork.load_locked()
        full = network.build_configuration(service, *network.get_membership())
        with patch.object(VPNNetwork, "query_members", wraps=VPNNetwork.query_members) as query:
            hub, members = network.get_membership(service)
        self.assertEqual(set(members), {self.hub.name, service.name})
        self.assertTrue(all(call.args[2] == [self.hub.name, service.name] for call in query.call_args_list))
        self.assertEqual(network.build_configuration(service, hub, members), full)
        self.update("VPN Server", service.name, enabled=0)
        self.assertEqual(self.call(SPOKE, "VPN Server", service.name, "get_configuration")["peers"], [])

    def test_manual_recovery_advances_past_preserved_watermarks(self):
        snapshot = self.hub_configuration()
        highest_observed_revision = snapshot["revision"] + 10
        with tempfile.TemporaryDirectory() as directory:
            watermark = Path(directory) / "revision.json"
            Host.accept_revision(watermark, highest_observed_revision, "previous-state")
            with self.assertRaises(ValueError):
                Host.accept_revision(watermark, snapshot["revision"], WireGuard.digest(snapshot))

            def recover():
                network = VPNNetwork.load_locked()
                network.revision = max(network.revision, highest_observed_revision)
                network.advance_revision()

            self.act("Administrator", recover)
            recovered = self.hub_configuration()
            self.assertEqual(recovered["revision"], highest_observed_revision + 1)
            Host.accept_revision(watermark, recovered["revision"], WireGuard.digest(recovered))
            with self.assertRaises(ValueError):
                Host.accept_revision(watermark, snapshot["revision"], WireGuard.digest(snapshot))
        self.report_hub()
        self.assertEqual(self.hub_status(), "Current")

    def test_reports_reject_future_and_out_of_order_revisions(self):
        self.report_hub()
        revision = self.revision()
        for value in (revision - 1, revision + 1):
            with self.subTest(revision=value), self.assertRaises(frappe.ValidationError):
                self.call(
                    HUB,
                    "VPN Server",
                    self.hub.name,
                    "report",
                    revision=value,
                    success=False,
                    agent=WireGuard.agent_digest(),
                )
        self.assertEqual(self.hub_status(), "Current")

    def test_desktop_entry_is_scoped_to_vpn_desk_roles(self):
        from frappe.apps import get_apps

        for user, allowed in ((MANAGER, True), (ENGINEER, True), (HUB, False), ("Guest", False)):
            frappe.set_user(user)
            with self.subTest(user=user):
                frappe.local.request_cache.clear()
                apps = {app["name"]: app for app in get_apps()}
                self.assertEqual("internal_vpn" in apps, allowed)
                if allowed:
                    self.assertEqual(apps["internal_vpn"]["route"], "/desk/vpn-device")

    def test_user_changes_revoke_devices_and_protect_the_hub(self):
        device = self.device()
        self.report_hub()
        revision = self.revision()
        self.update("User", ENGINEER, actor="Administrator", enabled=0)
        snapshot = self.hub_configuration()
        self.assertGreater(snapshot["revision"], revision)
        self.assertNotIn(device.address, [peer["address"] for peer in snapshot["peers"]])
        self.assertEqual(self.hub_status(), "Pending")

        self.update("User", ENGINEER, actor="Administrator", enabled=1, roles=[])
        self.assertEqual(self.hub_configuration()["peers"], [])
        with self.assertRaises(frappe.PermissionError):
            self.device(key(4))

        for values in ({"enabled": 0}, {"roles": []}):
            with self.subTest(values=values), self.assertRaises(frappe.ValidationError):
                self.update("User", HUB, actor="Administrator", **values)

    def test_owner_change_without_hooks_advances_hub_revision(self):
        device = self.device()
        first = self.hub_configuration()
        self.assertEqual(self.hub_configuration(), first)
        frappe.db.set_value("User", ENGINEER, "enabled", 0)
        snapshot = self.hub_configuration()
        self.assertEqual(snapshot["revision"], first["revision"] + 1)
        self.assertNotIn(device.address, [peer["address"] for peer in snapshot["peers"]])
        self.assertEqual(self.hub_configuration(), snapshot)
        with tempfile.TemporaryDirectory() as directory:
            watermark = Path(directory) / "revision.json"
            Host.accept_revision(watermark, first["revision"], WireGuard.digest(first))
            Host.accept_revision(watermark, snapshot["revision"], WireGuard.digest(snapshot))

    def test_status_follows_reports_and_notifies_managers_of_problems(self):
        service = self.server(SPOKE, key(2))
        notify = "frappe.email.doctype.notification.notification.enqueue_create_notification"

        def refresh(minutes=0):
            with patch(f"{MODULE}.now_datetime", return_value=add_to_date(now_datetime(), minutes=minutes)):
                self.act("Administrator", lambda: frappe.get_doc("VPN Network").refresh_statuses())

        def statuses():
            return dict(frappe.get_all("VPN Server", fields=["name", "status"], as_list=True))

        with patch(notify) as alerts:
            self.assertEqual(statuses(), {self.hub.name: "Pending", service.name: "Pending"})
            self.report_hub()
            self.assertEqual(statuses()[self.hub.name], "Current")
            self.device()
            self.assertEqual(statuses()[self.hub.name], "Pending")
            self.report_hub()
            self.assertEqual(statuses()[self.hub.name], "Current")
            # Only the new-device notice; no server alert for routine changes.
            self.assertEqual(
                [call.args[1]["document_type"] for call in alerts.call_args_list], ["VPN Device"]
            )
            alerts.reset_mock()

            refresh(minutes=10)
            # The hub stopped reporting; the other server was never set up, which is not an outage.
            self.assertEqual(statuses(), {self.hub.name: "Stale", service.name: "Never Reported"})
            subjects = [call.args[1]["subject"] for call in alerts.call_args_list]
            self.assertEqual(subjects, ["VPN server service is Stale"])
            self.assertIn(MANAGER, alerts.call_args.args[0])
            refresh(minutes=10)
            self.assertEqual(alerts.call_count, 1)

            alerts.reset_mock()
            self.report_hub()
            self.assertEqual(statuses()[self.hub.name], "Current")
            self.assertEqual(
                [call.args[1]["subject"] for call in alerts.call_args_list], ["VPN server service is Current"]
            )

            alerts.reset_mock()
            self.call(
                HUB,
                "VPN Server",
                self.hub.name,
                "report",
                revision=self.revision(),
                success=False,
                agent=WireGuard.agent_digest(),
            )
            self.assertEqual(statuses()[self.hub.name], "Failed")
            self.assertEqual(
                [call.args[1]["subject"] for call in alerts.call_args_list], ["VPN server service is Failed"]
            )

    def test_hub_snapshot_lists_servers_and_spokes_get_no_rules(self):
        service = self.server(SPOKE, key(2))
        self.device()
        self.assertEqual(
            self.hub_configuration()["access"],
            {"restricted": False, "services": [service.address], "rules": []},
        )
        self.assertIsNone(self.call(SPOKE, "VPN Server", service.name, "get_configuration")["access"])
