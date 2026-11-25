import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

import frappe
import frappe.app
from frappe.core.api.user_invitation import invite_by_email
from frappe.handler import run_doc_method
from frappe.utils import add_to_date, now_datetime
from test_host import key
from werkzeug.test import Client
from werkzeug.wrappers import Request, Response

from internal_vpn.host import Host, WireGuard
from internal_vpn.internal_vpn.doctype.vpn_network.vpn_network import VPNNetwork

SITES = os.environ.get("VPN_TEST_SITES_PATH")
SITE = os.environ.get("VPN_TEST_SITE")
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


@unittest.skipUnless(SITES and SITE, "Requires an isolated VPN test site")
class MembershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        wakeup = patch.object(VPNNetwork, "request_hub_update")
        cls.wakeup = wakeup.start()
        cls.addClassCleanup(wakeup.stop)
        frappe.init(SITE, sites_path=SITES)
        if not frappe.conf.get("internal_vpn_test_site"):
            frappe.destroy()
            raise RuntimeError("Refusing to reset a site without internal_vpn_test_site=1")
        frappe.connect()
        frappe.set_user("Administrator")
        frappe.flags.mute_emails = True
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
        frappe.db.commit()

    @classmethod
    def tearDownClass(cls):
        frappe.destroy()

    def setUp(self):
        frappe.set_user("Administrator")
        frappe.db.rollback()
        for doctype in ("VPN Device", "VPN Server"):
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
                "hub_alert": None,
            },
        )
        for email in (ENGINEER, OTHER, HUB, SPOKE):
            user = frappe.get_doc("User", email)
            user.enabled = 1
            user.set("roles", [{"role": ROLES[email]}])
            user.save()
        frappe.db.commit()
        self.save_network(subnet="100.100.64.0/24")
        self.hub = self.server(HUB, key(1))
        self.save_network(hub=self.hub.name, hub_endpoint="192.0.2.1:51820")
        self.wakeup.reset_mock()

    def tearDown(self):
        frappe.db.rollback()
        frappe.set_user("Administrator")

    @staticmethod
    def act(actor, action):
        """Run one request as `actor`: a fresh transaction, committed like Frappe does after a POST."""
        frappe.db.rollback()
        frappe.set_user(actor)
        try:
            result = action()
            frappe.db.commit()
            return result
        except Exception:
            frappe.db.rollback()
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
        )

    def status(self):
        return self.call(MANAGER, "VPN Network", "VPN Network", "get_status", http_method="GET")

    @staticmethod
    def revision():
        frappe.db.rollback()
        return frappe.db.get_single_value("VPN Network", "revision")

    @contextmanager
    def http(self, **options):
        """A WSGI client for this site; the test's own connection is restored afterwards."""
        frappe.destroy()
        try:
            with patch("frappe.app._site", SITE), patch("frappe.app._sites_path", SITES):
                yield Client(frappe.app.application, Response, **options)
        finally:
            frappe.init(SITE, sites_path=SITES)
            frappe.connect()

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

    def test_engineers_own_and_manage_only_their_devices(self):
        device = self.device()
        self.assertEqual(frappe.db.get_value("VPN Device", device.name, "owner"), ENGINEER)
        with self.assertRaises(frappe.PermissionError):
            self.device(key(4), actor=MANAGER)
        with self.assertRaises(frappe.ValidationError):
            self.update("VPN Device", device.name, actor=ENGINEER, label="")
        for action in (
            lambda: self.update("VPN Device", device.name, actor=OTHER, enabled=0),
            lambda: self.delete("VPN Device", device.name, actor=OTHER),
            lambda: self.call(OTHER, "VPN Device", device.name, "get_configuration", http_method="GET"),
            lambda: self.call(ENGINEER, "VPN Network", "VPN Network", "get_status", http_method="GET"),
        ):
            with self.assertRaises(frappe.PermissionError):
                action()
        self.update("VPN Device", device.name, actor=ENGINEER, public_key=key(5))
        self.assertEqual(frappe.db.get_value("VPN Device", device.name, "public_key"), key(5))

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

    def test_sign_in_is_email_link_only(self):
        settings = frappe.get_single("System Settings")
        self.assertTrue(settings.login_with_email_link and settings.disable_user_pass_login)
        with self.http(use_cookies=False) as client:
            with client.post("/api/method/login", json={"usr": "Administrator", "pwd": "admin"}) as response:
                self.assertEqual(response.status_code, 401)
            with client.get("/api/resource/VPN Device") as response:
                self.assertEqual(response.status_code, 403)

    def test_hub_wakeup_waits_for_commit_and_is_discarded_on_rollback(self):
        for commit in (False, True):
            frappe.set_user(ENGINEER)
            frappe.get_doc({"doctype": "VPN Device", "label": "laptop", "public_key": key(3)}).insert()
            self.wakeup.assert_not_called()
            if commit:
                frappe.db.commit()
            else:
                frappe.db.rollback()
                self.wakeup.assert_not_called()
        self.wakeup.assert_called_once_with()

    def test_capacity_reserves_disabled_members_and_delete_frees_it(self):
        with patch(f"{MODULE}.MAX_PEERS", 1):
            device = self.device()
            self.update("VPN Device", device.name, enabled=0)
            with self.assertRaises(frappe.ValidationError):
                self.device(key(4))
            self.report_hub()
            self.delete("VPN Device", device.name, actor=ENGINEER)
            self.assertEqual(self.device(key(4)).address, device.address)

    def test_delete_waits_for_hub_and_reserves_address(self):
        device = self.device()
        self.report_hub()
        with self.assertRaises(frappe.ValidationError):
            self.delete("VPN Device", device.name)
        self.update("VPN Device", device.name, enabled=0)
        with self.assertRaises(frappe.ValidationError):
            self.delete("VPN Device", device.name)
        self.assertNotEqual(self.device(key(4)).address, device.address)
        self.report_hub()
        self.delete("VPN Device", device.name)
        self.assertEqual(self.device(key(5)).address, device.address)

    def test_delete_requires_fresh_report_when_membership_returns_to_old_digest(self):
        device = self.device()
        self.update("VPN Device", device.name, enabled=0)
        self.report_hub()
        self.update("VPN Device", device.name, enabled=1)
        # The hub may apply this configuration without successfully reporting it.
        self.hub_configuration()
        self.update("VPN Device", device.name, enabled=0)
        self.assertFalse(self.status()["hub_current"])
        with self.assertRaises(frappe.ValidationError):
            self.delete("VPN Device", device.name)
        self.report_hub()
        self.assertTrue(self.status()["hub_current"])
        self.delete("VPN Device", device.name)

    def test_hub_cannot_be_disabled_or_deleted(self):
        with self.assertRaises(frappe.ValidationError):
            self.update("VPN Server", self.hub.name, enabled=0)
        with self.assertRaises(frappe.ValidationError):
            self.delete("VPN Server", self.hub.name)

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
        self.assertTrue(self.status()["hub_current"])

    def test_membership_edits_use_native_versions_but_reports_do_not(self):
        device = self.device()
        self.update("VPN Device", device.name, actor=ENGINEER, public_key=key(4))
        versions = frappe.get_all(
            "Version", filters={"ref_doctype": "VPN Device", "docname": device.name}, fields=["owner", "data"]
        )
        self.assertTrue(
            any(
                v.owner == ENGINEER and ["public_key", key(3), key(4)] in frappe.parse_json(v.data).changed
                for v in versions
            )
        )
        count = frappe.db.count("Version")
        self.report_hub()
        self.assertEqual(frappe.db.count("Version"), count)

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
        self.assertTrue(self.status()["hub_current"])

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
        frappe.db.rollback()
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
        self.assertTrue(self.status()["hub_current"])

    def test_polling_and_revocation_leave_consistent_snapshots(self):
        service = self.server(SPOKE, key(2))
        device = self.device()
        barrier = Barrier(3)

        def poll(actor, name):
            frappe.init(SITE, sites_path=SITES)
            frappe.connect()
            snapshots = []
            try:
                barrier.wait(timeout=10)
                for _ in range(8):
                    # A conflicting change makes a poll fail; the host retries on its next run.
                    try:
                        snapshots.append(self.call(actor, "VPN Server", name, "get_configuration"))
                    except frappe.QueryDeadlockError:
                        pass
                return snapshots
            finally:
                frappe.destroy()

        with ThreadPoolExecutor(max_workers=2) as pool:
            hub_reads = pool.submit(poll, HUB, self.hub.name)
            spoke_reads = pool.submit(poll, SPOKE, service.name)
            barrier.wait(timeout=10)
            self.retry(lambda: self.update("VPN Device", device.name, enabled=0))
            revision = self.revision()
            for snapshot in hub_reads.result(timeout=20):
                if snapshot["revision"] >= revision:
                    self.assertNotIn(device.address, [p["address"] for p in snapshot["peers"]])
            for snapshot in spoke_reads.result(timeout=20):
                self.assertEqual(len(snapshot["peers"]), 1)
        self.assertNotIn(device.address, [p["address"] for p in self.hub_configuration()["peers"]])

    def test_service_credentials_are_scoped(self):
        service = self.server(SPOKE, key(2))
        self.assertEqual(
            self.call(SPOKE, "VPN Server", service.name, "get_configuration")["topology"], "spoke"
        )
        for action in (
            lambda: self.call(SPOKE, "VPN Server", self.hub.name, "get_configuration"),
            lambda: self.call(MANAGER, "VPN Server", self.hub.name, "get_configuration"),
            lambda: self.update("VPN Server", service.name, actor=SPOKE, public_key=key(4)),
        ):
            with self.assertRaises(frappe.PermissionError):
                action()
        for user in (SPOKE, ENGINEER):
            with self.subTest(user=user), self.assertRaises(frappe.ValidationError):
                self.server(user, key(4))

    def test_keys_are_unique_across_servers_and_devices(self):
        device = self.device()
        revision = self.revision()
        for action in (
            lambda: self.device(),
            lambda: self.device(key(1)),
            lambda: self.server(SPOKE, key(3)),
        ):
            with self.assertRaises(frappe.UniqueValidationError):
                action()
        self.assertEqual(frappe.db.count("VPN Device") + frappe.db.count("VPN Server"), 2)
        self.assertEqual(self.revision(), revision)
        self.assertEqual(frappe.db.get_value("VPN Device", device.name, "public_key"), key(3))

    def test_reports_reject_future_and_out_of_order_revisions(self):
        self.report_hub()
        revision = self.revision()
        for value in (revision - 1, revision + 1):
            with self.subTest(revision=value), self.assertRaises(frappe.ValidationError):
                self.call(HUB, "VPN Server", self.hub.name, "report", revision=value, success=False)
        self.assertTrue(self.status()["hub_current"])

    def test_http_host_authentication_and_method_restrictions(self):
        frappe.set_user("Administrator")
        user = frappe.get_doc("User", HUB)
        user.api_key = frappe.generate_hash(length=16)
        user.api_secret = frappe.generate_hash(length=32)
        headers = {"Authorization": f"token {user.api_key}:{user.api_secret}"}
        user.save()
        frappe.db.commit()
        path = "/api/method/run_doc_method"
        payload = {"dt": "VPN Server", "dn": self.hub.name, "method": "get_configuration", "args": {}}
        with self.http() as client:
            with client.post(path, json=payload) as response:
                self.assertEqual(response.status_code, 403)
            with client.get(path, query_string={**payload, "args": "{}"}, headers=headers) as response:
                self.assertEqual(response.status_code, 403)
            with client.post(path, json=payload, headers=headers) as response:
                self.assertEqual(response.status_code, 200)
                snapshot = response.get_json()["message"]
            payload.update(
                method="report",
                args={
                    "revision": snapshot["revision"],
                    "success": True,
                    "digest": WireGuard.digest(snapshot),
                },
            )
            with client.post(path, json=payload, headers=headers) as response:
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.get_json()["message"]["accepted"])

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

    def test_owner_eligibility_changes_membership_and_revision(self):
        device = self.device()
        self.report_hub()
        revision = self.revision()
        self.update("User", ENGINEER, actor="Administrator", enabled=0)
        snapshot = self.hub_configuration()
        self.assertGreater(snapshot["revision"], revision)
        self.assertNotIn(device.address, [peer["address"] for peer in snapshot["peers"]])
        self.assertFalse(self.status()["hub_current"])

    def test_owner_change_without_hooks_advances_hub_revision(self):
        device = self.device()
        first = self.hub_configuration()
        self.assertEqual(self.hub_configuration(), first)
        frappe.db.set_value("User", ENGINEER, "enabled", 0)
        frappe.db.commit()
        snapshot = self.hub_configuration()
        self.assertEqual(snapshot["revision"], first["revision"] + 1)
        self.assertNotIn(device.address, [peer["address"] for peer in snapshot["peers"]])
        self.assertEqual(self.hub_configuration(), snapshot)
        with tempfile.TemporaryDirectory() as directory:
            watermark = Path(directory) / "revision.json"
            Host.accept_revision(watermark, first["revision"], WireGuard.digest(first))
            Host.accept_revision(watermark, snapshot["revision"], WireGuard.digest(snapshot))

    def test_hub_alerts_notify_once_per_problem_and_on_recovery(self):
        def check(at=None):
            def run():
                with patch(f"{MODULE}.now_datetime", return_value=at or now_datetime()):
                    VPNNetwork.load_locked().check_hub()

            # As the scheduler runs jobs.
            self.act("Administrator", run)
            return [call.args[1]["subject"] for call in notify.call_args_list]

        with patch(f"{MODULE}.enqueue_create_notification") as notify:
            self.assertEqual(check(add_to_date(now_datetime(), minutes=10)), [])
            with patch.dict(frappe.conf, {"internal_vpn_hub_alert_minutes": 5}):
                later = add_to_date(now_datetime(), minutes=10)
                self.assertEqual(check(later), ["The VPN hub has stopped reporting"])
                self.assertEqual(len(check(later)), 1)
                self.assertIn(MANAGER, notify.call_args.args[0])
                self.report_hub()
                self.assertEqual(check()[-1], "Resolved: The VPN hub has stopped reporting")
                self.device()
                frappe.db.set_single_value(
                    "VPN Network", "modified", add_to_date(now_datetime(), minutes=-10), update_modified=False
                )
                frappe.db.commit()
                self.assertEqual(check()[-1], "The VPN hub has not applied the latest membership")

    def test_status_marks_hosts_stale(self):
        self.report_hub()
        self.assertTrue(self.status()["all_current"])
        with patch(f"{MODULE}.now_datetime", return_value=add_to_date(now_datetime(), minutes=10)):
            status = self.status()
        hub = next(host for host in status["hosts"] if host["name"] == self.hub.name)
        self.assertTrue(hub["current"] and hub["stale"])
        self.assertFalse(status["all_current"])

    def test_hub_snapshot_lists_servers_and_spokes_get_no_rules(self):
        service = self.server(SPOKE, key(2))
        self.device()
        self.assertEqual(self.hub_configuration()["access"], {"services": [service.address]})
        self.assertIsNone(self.call(SPOKE, "VPN Server", service.name, "get_configuration")["access"])

    def test_hub_owner_must_keep_role_and_enablement(self):
        for values in ({"enabled": 0}, {"roles": []}):
            with self.subTest(values=values), self.assertRaises(frappe.ValidationError):
                self.update("User", HUB, actor="Administrator", **values)

    def test_role_removal_revokes_device_membership(self):
        self.device()
        self.update("User", ENGINEER, actor="Administrator", roles=[])
        self.assertEqual(self.hub_configuration()["peers"], [])
        with self.assertRaises(frappe.PermissionError):
            self.device(key(4))

    def test_concurrent_registration_allocates_distinct_addresses_and_revisions(self):
        revision = self.revision()
        barrier = Barrier(4)

        def register(number):
            frappe.init(SITE, sites_path=SITES)
            frappe.connect()
            try:
                barrier.wait(timeout=10)
                return self.retry(lambda: self.device(key(number)))
            finally:
                frappe.destroy()

        with ThreadPoolExecutor(max_workers=4) as pool:
            devices = list(pool.map(register, range(10, 14)))
        self.assertEqual(len({device.address for device in devices}), 4)
        self.assertEqual(self.revision(), revision + 4)

    @staticmethod
    def retry(action, attempts=5):
        """Retry a request that lost a conflict, as a user or host would."""
        for attempt in range(attempts):
            try:
                return action()
            except frappe.QueryDeadlockError:
                if attempt == attempts - 1:
                    raise
