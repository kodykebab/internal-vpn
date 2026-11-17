import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Barrier
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import frappe
import frappe.app
from frappe.handler import run_doc_method
from frappe.utils import add_to_date, now_datetime
from frappe.utils.password import check_password
from test_host import key
from werkzeug.test import Client
from werkzeug.wrappers import Request, Response

from internal_vpn.host import Host, WireGuard
from internal_vpn.internal_vpn.doctype.vpn_network.vpn_network import VPNNetwork

SITES = os.environ.get("VPN_TEST_SITES_PATH")
SITE = os.environ.get("VPN_TEST_SITE")
MANAGER = "vpn-manager@example.test"
ENGINEER = "vpn-engineer@example.test"
OTHER = "vpn-other@example.test"
HUB = "vpn-hub@example.test"
SPOKE = "vpn-spoke@example.test"


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
        for email, role in (
            (MANAGER, "VPN Manager"),
            (ENGINEER, "VPN Engineer"),
            (OTHER, "VPN Engineer"),
            (HUB, "VPN Host"),
            (SPOKE, "VPN Host"),
        ):
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
        frappe.db.delete("VPN Peer")
        frappe.db.set_value(
            "VPN Network", "default", {"hub": None, "subnet": None, "revision": 0, "hub_alert": None}
        )
        for email in (ENGINEER, OTHER, HUB, SPOKE):
            user = frappe.get_doc("User", email)
            user.enabled = 1
            user.set("roles", [{"role": "VPN Host" if email in (HUB, SPOKE) else "VPN Engineer"}])
            user.save()
        frappe.db.commit()
        self.network("initialize", subnet="100.100.64.0/24")
        self.hub = self.network(
            "register_service", user=HUB, label="service", public_key=key(1), endpoint="192.0.2.1:51820"
        )
        self.network("set_hub", peer=self.hub["name"])
        self.wakeup.reset_mock()

    def tearDown(self):
        frappe.db.rollback()
        frappe.set_user("Administrator")

    @staticmethod
    def call(actor, doctype, name, method, **args):
        frappe.set_user(actor)
        frappe.local.request = Request.from_values(method="GET" if method.startswith("get_") else "POST")
        frappe.local.form_dict = frappe._dict()
        frappe.local.response = frappe._dict(docs=[])
        try:
            run_doc_method(method, dt=doctype, dn=name, args=args)
            result = frappe.response.message
            frappe.db.commit()
            return result
        except Exception:
            frappe.db.rollback()
            raise

    def network(self, method, actor=MANAGER, **args):
        return self.call(actor, "VPN Network", "default", method, **args)

    def peer(self, name, method, actor=MANAGER, **args):
        return self.call(actor, "VPN Peer", name, method, **args)

    def device(self, public_key=None, actor=ENGINEER):
        return self.network("register_device", actor=actor, public_key=public_key or key(3), label="laptop")

    def report_hub(self):
        snapshot = self.peer(self.hub["name"], "get_configuration", actor=HUB)
        self.peer(
            self.hub["name"],
            "report",
            actor=HUB,
            revision=snapshot["revision"],
            success=True,
            digest=WireGuard.digest(snapshot),
        )

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

    def test_hub_endpoint_cannot_be_cleared(self):
        revision = frappe.db.get_value("VPN Network", "default", "revision")
        for endpoint in (None, "", "invalid", "0.0.0.0:1"):
            with self.subTest(endpoint=endpoint), self.assertRaises(frappe.ValidationError):
                self.peer(self.hub["name"], "set_endpoint", endpoint=endpoint)
        self.assertEqual(frappe.db.get_value("VPN Peer", self.hub["name"], "endpoint"), "192.0.2.1:51820")
        self.assertEqual(frappe.db.get_value("VPN Network", "default", "revision"), revision)

    def test_only_the_hub_endpoint_can_change(self):
        service = self.network(
            "register_service", user=SPOKE, label="service", public_key=key(2), endpoint="192.0.2.2:51820"
        )
        device = self.device()
        revision = frappe.db.get_value("VPN Network", "default", "revision")
        for name in (service["name"], device["name"]):
            with self.subTest(name=name), self.assertRaises(frappe.ValidationError):
                self.peer(name, "set_endpoint", endpoint="192.0.2.3:51820")
        self.assertEqual(frappe.db.get_value("VPN Network", "default", "revision"), revision)
        self.assertEqual(
            self.peer(self.hub["name"], "set_endpoint", endpoint="192.0.2.9:51820")["revision"], revision + 1
        )

    def test_engineers_register_only_their_own_named_devices(self):
        with self.assertRaises(frappe.PermissionError):
            self.network("register_device", public_key=key(3), label="laptop")
        with self.assertRaises(TypeError):
            self.network("register_device", actor=OTHER, user=ENGINEER, public_key=key(3), label="laptop")
        device = self.network("register_device", actor=OTHER, public_key=key(3), label="laptop")
        self.assertEqual(
            frappe.db.get_value("VPN Peer", device["name"], ["user", "label"]), (OTHER, "laptop")
        )
        with self.assertRaises(frappe.ValidationError):
            self.network("register_device", actor=ENGINEER, public_key=key(4), label=" ")

    def test_managers_add_engineers(self):
        email = f"vpn-added-{frappe.generate_hash(length=8)}@example.test"
        with self.assertRaises(frappe.PermissionError):
            self.network("add_engineer", actor=ENGINEER, email=email, first_name="Added")
        added = self.network("add_engineer", email=email, first_name="Added")
        self.assertEqual(check_password(email, added["password"]), email)
        self.assertIn("VPN Engineer", frappe.get_roles(email))
        self.assertEqual(frappe.db.get_value("User", email, "user_type"), "System User")
        self.assertTrue(
            self.network("register_device", actor=email, public_key=key(4), label="laptop")["name"]
        )
        self.assertIsNone(self.network("add_engineer", email=HUB)["password"])
        self.assertTrue({"VPN Host", "VPN Engineer"} <= set(frappe.get_roles(HUB)))
        with patch.dict(frappe.conf, {"internal_vpn_invite_email": 1}):
            emailed = f"vpn-emailed-{frappe.generate_hash(length=8)}@example.test"
            self.assertIsNone(self.network("add_engineer", email=emailed, first_name="Emailed")["password"])

    def test_hub_wakeup_waits_for_commit_and_is_discarded_on_rollback(self):
        for commit in (False, True):
            frappe.set_user(ENGINEER)
            frappe.get_doc("VPN Network", "default").register_device(key(3), "laptop")
            self.wakeup.assert_not_called()
            if commit:
                frappe.db.commit()
            else:
                frappe.db.rollback()
                self.wakeup.assert_not_called()
        self.wakeup.assert_called_once_with()

    def test_capacity_reserves_disabled_members_and_release_frees_it(self):
        with patch("internal_vpn.internal_vpn.doctype.vpn_network.vpn_network.MAX_PEERS", 1):
            device = self.device()
            self.peer(device["name"], "set_enabled", enabled=0)
            with self.assertRaises(frappe.ValidationError):
                self.device(key(4))
            self.report_hub()
            self.peer(device["name"], "release")
            replacement = self.device(key(4))
            self.assertEqual(replacement["address"], device["address"])

    def test_release_waits_for_hub_and_reserves_address(self):
        device = self.device()
        self.report_hub()
        self.peer(device["name"], "set_enabled", enabled=0)
        with self.assertRaises(frappe.ValidationError):
            self.peer(device["name"], "release")
        other = self.device(key(4))
        self.assertNotEqual(other["address"], device["address"])
        self.report_hub()
        self.peer(device["name"], "release")
        self.assertEqual(self.device(key(5))["address"], device["address"])

    def test_release_requires_fresh_report_when_membership_returns_to_old_digest(self):
        device = self.device()
        self.peer(device["name"], "set_enabled", enabled=0)
        self.report_hub()
        self.peer(device["name"], "set_enabled", enabled=1)
        # The hub may apply this configuration without successfully reporting it.
        self.peer(self.hub["name"], "get_configuration", actor=HUB)
        self.peer(device["name"], "set_enabled", enabled=0)
        self.assertFalse(self.network("get_status")["hub_current"])
        with self.assertRaises(frappe.ValidationError):
            self.peer(device["name"], "release")
        self.report_hub()
        self.assertTrue(self.network("get_status")["hub_current"])
        self.peer(device["name"], "release")
        self.assertEqual(self.device(key(4))["address"], device["address"])

    def test_owners_cannot_read_or_mutate_other_peers(self):
        device = self.device()
        for method, args in (
            ("get_configuration", {}),
            ("set_enabled", {"enabled": 0}),
            ("rotate_key", {"public_key": key(4)}),
            ("release", {}),
        ):
            with self.subTest(method=method), self.assertRaises(frappe.PermissionError):
                self.peer(device["name"], method, actor=OTHER, **args)
        with self.assertRaises(frappe.PermissionError):
            self.network("get_status", actor=ENGINEER)
        with self.assertRaises(frappe.PermissionError):
            self.peer(self.hub["name"], "get_configuration", actor=MANAGER)

    def test_administrator_cannot_bypass_membership_actions(self):
        device = self.device()
        frappe.set_user("Administrator")
        for doctype, name, field, value in (
            ("VPN Peer", device["name"], "enabled", 0),
            ("VPN Peer", device["name"], "address", "100.100.64.99"),
            ("VPN Network", "default", "revision", 999),
        ):
            doc = frappe.get_doc(doctype, name)
            doc.set(field, value)
            doc.flags.update(ignore_validate=True, vpn_action=True)
            with self.subTest(doctype=doctype, field=field), self.assertRaises(frappe.ValidationError):
                doc.save()
            frappe.db.rollback()
            with self.assertRaises(frappe.ValidationError):
                frappe.rename_doc(doctype, name, name + "-renamed", force=True)
            frappe.db.rollback()
        with self.assertRaises(frappe.ValidationError):
            frappe.get_doc(
                {
                    "doctype": "VPN Peer",
                    "kind": "Device",
                    "user": ENGINEER,
                    "public_key": key(8),
                    "address": "100.100.64.99",
                }
            ).insert()
        frappe.db.rollback()
        with self.assertRaises(frappe.ValidationError):
            frappe.delete_doc("VPN Network", "default", force=True)
        frappe.db.rollback()

    def test_released_peer_cannot_be_restored_generically(self):
        from frappe.core.doctype.deleted_document.deleted_document import restore

        device = self.device()
        self.peer(device["name"], "set_enabled", enabled=0)
        self.report_hub()
        self.peer(device["name"], "release")
        frappe.set_user("Administrator")
        deleted = frappe.db.get_value("Deleted Document", {"deleted_name": device["name"]}, "name")
        self.assertTrue(deleted)
        with self.assertRaises(frappe.ValidationError):
            restore(deleted)
        frappe.db.rollback()
        self.assertFalse(frappe.db.exists("VPN Peer", device["name"]))

    def test_membership_edits_use_native_versions_but_reports_do_not(self):
        device = self.device()
        self.peer(device["name"], "rotate_key", actor=ENGINEER, public_key=key(4))
        versions = frappe.get_all(
            "Version",
            filters={"ref_doctype": "VPN Peer", "docname": device["name"]},
            fields=["owner", "data"],
        )
        self.assertTrue(
            any(
                v.owner == ENGINEER and ["public_key", key(3), key(4)] in frappe.parse_json(v.data).changed
                for v in versions
            )
        )
        self.assertTrue(frappe.db.exists("Version", {"ref_doctype": "VPN Network", "docname": "default"}))
        count = frappe.db.count("Version")
        self.report_hub()
        self.assertEqual(frappe.db.count("Version"), count)

    def test_unchanged_actions_do_not_write_or_wake_hub(self):
        device = self.device()
        self.report_hub()
        revision = frappe.db.get_value("VPN Network", "default", "revision")
        count = frappe.db.count("Version")
        self.wakeup.reset_mock()
        for name, method, args in (
            (device["name"], "set_enabled", {"enabled": 1}),
            (device["name"], "rotate_key", {"public_key": key(3)}),
            (self.hub["name"], "set_endpoint", {"endpoint": "192.0.2.1:051820"}),
        ):
            self.assertEqual(self.peer(name, method, **args)["revision"], revision)
        self.assertEqual(frappe.db.count("Version"), count)
        self.wakeup.assert_not_called()
        self.assertTrue(self.network("get_status")["hub_current"])

    def test_spoke_lookup_is_bounded_and_matches_full_snapshot(self):
        service = self.network("register_service", user=SPOKE, label="service", public_key=key(2))
        self.device()
        network = frappe.get_doc("VPN Network", "default").lock()
        peer = frappe.get_doc("VPN Peer", service["name"])
        full = network.build_configuration(peer, *network.get_membership())
        with patch.object(frappe.db, "sql", wraps=frappe.db.sql) as query:
            hub, members = network.get_membership(peer)
        self.assertEqual(set(members), {self.hub["name"], service["name"]})
        self.assertEqual(query.call_args.args[1]["names"], (self.hub["name"], service["name"]))
        self.assertEqual(network.build_configuration(peer, hub, members), full)
        frappe.db.rollback()
        self.peer(service["name"], "set_enabled", enabled=0)
        self.assertEqual(self.peer(service["name"], "get_configuration", actor=SPOKE)["peers"], [])

    def test_manual_recovery_advances_past_preserved_watermarks(self):
        snapshot = self.peer(self.hub["name"], "get_configuration", actor=HUB)
        highest_observed_revision = snapshot["revision"] + 10
        with tempfile.TemporaryDirectory() as directory:
            watermark = Path(directory) / "revision.json"
            Host.accept_revision(watermark, highest_observed_revision, "previous-state")
            with self.assertRaises(ValueError):
                Host.accept_revision(watermark, snapshot["revision"], WireGuard.digest(snapshot))
            frappe.set_user("Administrator")
            network = frappe.get_doc("VPN Network", "default").lock()
            network.revision = max(network.revision, highest_observed_revision)
            network.advance_revision()
            frappe.db.commit()
            recovered = self.peer(self.hub["name"], "get_configuration", actor=HUB)
            self.assertEqual(recovered["revision"], highest_observed_revision + 1)
            Host.accept_revision(watermark, recovered["revision"], WireGuard.digest(recovered))
            with self.assertRaises(ValueError):
                Host.accept_revision(watermark, snapshot["revision"], WireGuard.digest(snapshot))
        self.report_hub()
        self.assertTrue(self.network("get_status")["hub_current"])

    def test_polling_and_revocation_leave_consistent_snapshots(self):
        service = self.network("register_service", user=SPOKE, label="service", public_key=key(2))
        device = self.device()
        barrier = Barrier(3)

        def poll(actor, name):
            frappe.init(SITE, sites_path=SITES)
            frappe.connect()
            try:
                barrier.wait(timeout=10)
                return [self.peer(name, "get_configuration", actor=actor) for _ in range(8)]
            finally:
                frappe.destroy()

        with ThreadPoolExecutor(max_workers=2) as pool:
            hub_reads = pool.submit(poll, HUB, self.hub["name"])
            spoke_reads = pool.submit(poll, SPOKE, service["name"])
            barrier.wait(timeout=10)
            self.peer(device["name"], "set_enabled", enabled=0)
            revision = frappe.db.get_value("VPN Network", "default", "revision")
            for snapshot in hub_reads.result(timeout=20):
                if snapshot["revision"] >= revision:
                    self.assertNotIn(device["address"], [p["address"] for p in snapshot["peers"]])
            for snapshot in spoke_reads.result(timeout=20):
                self.assertEqual(len(snapshot["peers"]), 1)
        final = self.peer(self.hub["name"], "get_configuration", actor=HUB)
        self.assertNotIn(device["address"], [p["address"] for p in final["peers"]])

    def test_generic_writes_are_denied(self):
        device = self.device()
        for actor in (MANAGER, ENGINEER):
            frappe.set_user(actor)
            peer = frappe.get_doc("VPN Peer", device["name"])
            peer.enabled = 0
            with self.subTest(actor=actor), self.assertRaises(frappe.PermissionError):
                peer.save()
            frappe.db.rollback()

    def test_service_credentials_are_scoped_and_cannot_edit_membership(self):
        service = self.network("register_service", user=SPOKE, label="service", public_key=key(2))
        snapshot = self.peer(service["name"], "get_configuration", actor=SPOKE)
        self.assertEqual(snapshot["topology"], "spoke")
        with self.assertRaises(frappe.PermissionError):
            self.peer(self.hub["name"], "get_configuration", actor=SPOKE)
        with self.assertRaises(frappe.PermissionError):
            self.peer(service["name"], "rotate_key", actor=SPOKE, public_key=key(4))
        with self.assertRaises(frappe.ValidationError):
            self.network("register_service", user=SPOKE, label="service", public_key=key(4))

    def test_duplicate_key_rolls_back_membership(self):
        device = self.device()
        revision = frappe.db.get_value("VPN Network", "default", "revision")
        with self.assertRaises(frappe.UniqueValidationError):
            self.device()
        self.assertEqual(frappe.db.count("VPN Peer"), 2)
        self.assertEqual(frappe.db.get_value("VPN Network", "default", "revision"), revision)
        self.assertEqual(frappe.db.get_value("VPN Peer", device["name"], "public_key"), key(3))

    def test_reports_reject_future_and_out_of_order_revisions(self):
        self.report_hub()
        revision = frappe.db.get_value("VPN Network", "default", "revision")
        for value in (revision - 1, revision + 1, True):
            with self.subTest(revision=value), self.assertRaises(frappe.ValidationError):
                self.peer(self.hub["name"], "report", actor=HUB, revision=value, success=False)
        self.assertTrue(self.network("get_status")["hub_current"])

    def test_http_host_authentication_and_method_restrictions(self):
        frappe.set_user("Administrator")
        user = frappe.get_doc("User", HUB)
        user.api_key = frappe.generate_hash(length=16)
        user.api_secret = frappe.generate_hash(length=32)
        headers = {"Authorization": f"token {user.api_key}:{user.api_secret}"}
        user.save()
        frappe.db.commit()
        payload = {"dt": "VPN Peer", "dn": self.hub["name"], "method": "get_configuration"}
        with self.http() as client:
            path = "/api/method/run_doc_method"
            with client.get(path, query_string=payload) as response:
                self.assertEqual(response.status_code, 401)
            with client.get(path, query_string=payload, headers=headers) as response:
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
            with client.get(
                path,
                query_string={
                    "dt": "VPN Peer",
                    "dn": self.hub["name"],
                    "method": "report",
                },
                headers=headers,
            ) as response:
                self.assertEqual(response.status_code, 403)

    def test_desktop_entry_is_scoped_to_vpn_desk_roles(self):
        from frappe.apps import get_apps

        for user, allowed in ((MANAGER, True), (ENGINEER, True), (HUB, False), ("Guest", False)):
            frappe.set_user(user)
            with self.subTest(user=user):
                frappe.local.request_cache.clear()
                apps = {app["name"]: app for app in get_apps()}
                self.assertEqual("internal_vpn" in apps, allowed)
                if allowed:
                    self.assertEqual(apps["internal_vpn"]["route"], "/desk/vpn-network/default")

    def test_guest_page_assets_do_not_allow_other_commands(self):
        with self.http(use_cookies=False) as client:
            paths = (
                "/website_script.js",
                "/api/method/frappe.translate.get_boot_translations",
            )
            for path in paths:
                with self.subTest(path=path), client.get(path) as response:
                    self.assertEqual(response.status_code, 200)
                with client.get(path, query_string={"cmd": "frappe.client.get_list"}) as response:
                    self.assertEqual(response.status_code, 401)
            with client.get("/api/resource/VPN Peer") as response:
                self.assertEqual(response.status_code, 401)
            with client.post("/website_script.js") as response:
                self.assertEqual(response.status_code, 401)

    def test_invitation_password_setup_uses_frappes_token_validation(self):
        frappe.set_user("Administrator")
        link = frappe.get_doc("User", ENGINEER)._reset_password(send_email=False)
        token = parse_qs(urlsplit(link).query)["key"][0]
        frappe.db.commit()
        with self.http(use_cookies=False) as client:
            path = "/api/method/frappe.core.doctype.user.user.update_password"
            password = "Unique-Test-Password-" + frappe.generate_hash(length=20)
            with client.get("/update-password", query_string={"key": token}) as response:
                self.assertEqual(response.status_code, 200)
            with client.post(
                "/",
                headers={"Accept": "application/json"},
                data={
                    "cmd": "frappe.core.doctype.user.user.test_password_strength",
                    "new_password": password,
                },
            ) as response:
                self.assertEqual(response.status_code, 200)
            with client.post(path, json={"key": "invalid", "new_password": password}) as response:
                self.assertEqual(response.status_code, 410)
            with client.post(path, json={"key": token, "new_password": password}) as response:
                self.assertEqual(response.status_code, 200)
            with client.post(path, json={"key": token, "new_password": password + "-again"}) as response:
                self.assertEqual(response.status_code, 410)
            with client.post(
                "/",
                headers={"Accept": "application/json"},
                data={"cmd": "frappe.client.get_list", "doctype": "User"},
            ) as response:
                self.assertEqual(response.status_code, 401)

    def test_owner_eligibility_changes_membership_and_revision(self):
        device = self.device()
        self.report_hub()
        revision = frappe.db.get_value("VPN Network", "default", "revision")
        frappe.set_user("Administrator")
        owner = frappe.get_doc("User", ENGINEER)
        owner.enabled = 0
        owner.save()
        frappe.db.commit()
        snapshot = self.peer(self.hub["name"], "get_configuration", actor=HUB)
        self.assertGreater(snapshot["revision"], revision)
        self.assertNotIn(device["address"], [peer["address"] for peer in snapshot["peers"]])
        self.assertFalse(self.network("get_status")["hub_current"])

    def test_owner_change_without_hooks_advances_hub_revision(self):
        device = self.device()
        first = self.peer(self.hub["name"], "get_configuration", actor=HUB)
        self.assertEqual(self.peer(self.hub["name"], "get_configuration", actor=HUB), first)
        frappe.db.set_value("User", ENGINEER, "enabled", 0)
        frappe.db.commit()
        snapshot = self.peer(self.hub["name"], "get_configuration", actor=HUB)
        self.assertEqual(snapshot["revision"], first["revision"] + 1)
        self.assertNotIn(device["address"], [peer["address"] for peer in snapshot["peers"]])
        self.assertEqual(self.peer(self.hub["name"], "get_configuration", actor=HUB), snapshot)
        with tempfile.TemporaryDirectory() as directory:
            watermark = Path(directory) / "revision.json"
            Host.accept_revision(watermark, first["revision"], WireGuard.digest(first))
            Host.accept_revision(watermark, snapshot["revision"], WireGuard.digest(snapshot))

    def test_hub_alerts_notify_once_per_problem_and_on_recovery(self):
        module = "internal_vpn.internal_vpn.doctype.vpn_network.vpn_network"

        def check(at=None):
            frappe.set_user("Administrator")  # as the scheduler runs jobs
            with patch(f"{module}.now_datetime", return_value=at or now_datetime()):
                frappe.get_doc("VPN Network", "default").check_hub()
            return [call.args[1]["subject"] for call in notify.call_args_list]

        with patch(f"{module}.enqueue_create_notification") as notify:
            self.assertEqual(check(add_to_date(now_datetime(), minutes=10)), [])
            with patch.dict(frappe.conf, {"internal_vpn_hub_alert_minutes": 5}):
                later = add_to_date(now_datetime(), minutes=10)
                self.assertEqual(check(later), ["The VPN hub has stopped reporting"])
                self.assertEqual(len(check(later)), 1)
                self.assertIn(MANAGER, notify.call_args.args[0])
                self.report_hub()
                self.assertEqual(check()[-1], "Resolved: The VPN hub has stopped reporting")
                self.device()
                frappe.db.set_value(
                    "VPN Network",
                    "default",
                    "modified",
                    add_to_date(now_datetime(), minutes=-10),
                    update_modified=False,
                )
                self.assertEqual(check()[-1], "The VPN hub has not applied the latest membership")

    def test_status_marks_hosts_stale_and_accepts_ipv6_hub_endpoint(self):
        self.peer(self.hub["name"], "set_endpoint", endpoint="[2001:DB8::1]:51820")
        self.assertEqual(frappe.db.get_value("VPN Peer", self.hub["name"], "endpoint"), "[2001:db8::1]:51820")
        self.report_hub()
        frappe.set_user(MANAGER)
        status = frappe.get_doc("VPN Network", "default").get_status()
        self.assertTrue(status["all_current"])
        later = add_to_date(now_datetime(), minutes=10)
        with patch(
            "internal_vpn.internal_vpn.doctype.vpn_network.vpn_network.now_datetime", return_value=later
        ):
            status = frappe.get_doc("VPN Network", "default").get_status()
        hub = next(host for host in status["hosts"] if host["name"] == self.hub["name"])
        self.assertTrue(hub["current"] and hub["stale"])
        self.assertFalse(status["all_current"])

    def test_hub_owner_must_keep_role_and_enablement(self):
        for change in ("enabled", "roles"):
            frappe.set_user("Administrator")
            owner = frappe.get_doc("User", HUB)
            owner.set(change, 0 if change == "enabled" else [])
            with self.subTest(change=change), self.assertRaises(frappe.ValidationError):
                owner.save()
            frappe.db.rollback()

    def test_role_removal_revokes_device_membership(self):
        self.device()
        frappe.set_user("Administrator")
        owner = frappe.get_doc("User", ENGINEER)
        owner.set("roles", [])
        owner.save()
        frappe.db.commit()
        snapshot = self.peer(self.hub["name"], "get_configuration", actor=HUB)
        self.assertEqual(snapshot["peers"], [])
        with self.assertRaises(frappe.PermissionError):
            self.device(key(4))

    def test_owner_save_conflict_rolls_back_and_can_be_retried(self):
        self.device()
        frappe.set_user("Administrator")
        owner = frappe.get_doc("User", ENGINEER)
        frappe.get_doc("VPN Network", "default")

        def register():
            frappe.init(SITE, sites_path=SITES)
            frappe.connect()
            try:
                return self.device(key(4))
            finally:
                frappe.destroy()

        with ThreadPoolExecutor(max_workers=1) as pool:
            peer = pool.submit(register).result(timeout=15)
        owner.enabled = 0
        try:
            owner.save()
        except frappe.QueryDeadlockError:
            frappe.db.rollback()
            owner = frappe.get_doc("User", ENGINEER)
            self.assertEqual(owner.enabled, 1)
            self.assertEqual(frappe.db.get_value("VPN Network", "default", "revision"), peer["revision"])
            owner.enabled = 0
            owner.save()
        frappe.db.commit()
        snapshot = self.peer(self.hub["name"], "get_configuration", actor=HUB)
        self.assertGreater(snapshot["revision"], peer["revision"])
        self.assertEqual(snapshot["peers"], [])

    def test_concurrent_registration_allocates_distinct_addresses_and_revisions(self):
        barrier = Barrier(4)

        def register(number):
            frappe.init(SITE, sites_path=SITES)
            frappe.connect()
            try:
                barrier.wait(timeout=10)
                return self.device(key(number))
            finally:
                frappe.destroy()

        with ThreadPoolExecutor(max_workers=4) as pool:
            devices = list(pool.map(register, range(10, 14)))
        self.assertEqual(len({device["address"] for device in devices}), 4)
        self.assertEqual(len({device["revision"] for device in devices}), 4)
