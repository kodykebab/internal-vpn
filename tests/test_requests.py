import os
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

import frappe
import frappe.app
from frappe.handler import run_doc_method
from frappe.utils import add_to_date, now_datetime
from test_host import key
from werkzeug.test import Client
from werkzeug.wrappers import Request, Response

from internal_vpn.host import WireGuard
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
        wakeup = patch.object(VPNNetwork, "enqueue_hub_apply")
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

    @staticmethod
    def api_headers(user):
        frappe.set_user("Administrator")
        doc = frappe.get_doc("User", user)
        doc.api_key, secret = frappe.generate_hash(length=16), frappe.generate_hash(length=32)
        doc.api_secret = secret
        doc.save()
        frappe.db.commit()
        return {"Authorization": f"token {doc.api_key}:{secret}"}

    def test_vpn_only_desk_keeps_staff_on_the_vpn(self):
        manager, engineer, host = (self.api_headers(user) for user in (MANAGER, ENGINEER, HUB))
        self.save_network(vpn_only_desk=1)
        path = "/api/method/frappe.auth.get_logged_user"
        public, vpn = {"X-Real-IP": "203.0.113.9"}, {"X-Real-IP": "100.100.64.9"}

        def status(headers, **extra):
            with (
                self.http(use_cookies=False) as client,
                client.get(path, headers={**headers, **extra}) as response,
            ):
                return response.status_code

        self.assertEqual(status(manager, **public), 403)
        self.assertEqual(status(manager, **public, **{"X-Forwarded-For": "100.100.64.9"}), 403)
        self.assertEqual(status(manager), 403)
        self.assertEqual(status(manager, **vpn), 200)
        self.assertEqual(status(host, **public), 200)
        self.assertEqual(status(engineer, **public), 200)
        self.device()
        self.assertEqual(status(engineer, **public), 200)
        with patch(f"{MODULE}.now_datetime", return_value=add_to_date(now_datetime(), minutes=31)):
            self.assertEqual(status(engineer, **public), 403)
            self.assertEqual(status(engineer, **vpn), 200)
        self.save_network(vpn_only_desk=0)
        self.assertEqual(status(manager, **public), 200)

    def test_sign_in_links_move_vpn_only_staff_to_the_vpn(self):
        self.save_network(vpn_only_desk=1)

        def open_link(user, address):
            key = frappe.generate_hash()
            frappe.cache.set_value(f"one_time_login_key:{key}", user, expires_in_sec=600)
            path = "/api/method/frappe.www.login.login_via_key"
            with self.http(use_cookies=False) as client:
                response = client.get(path, query_string={"key": key}, headers={"X-Real-IP": address})
                location, used = (
                    response.headers.get("Location", ""),
                    not frappe.cache.get_value(f"one_time_login_key:{key}"),
                )
                response.close()
            return key, location, used

        key, location, used = open_link(MANAGER, "203.0.113.9")
        self.assertEqual(
            location, f"http://{self.hub.address}/api/method/frappe.www.login.login_via_key?key={key}"
        )
        self.assertFalse(used)
        _, location, used = open_link(MANAGER, "100.100.64.9")
        self.assertTrue(used)
        self.assertNotIn(self.hub.address, location)
        _, location, used = open_link(ENGINEER, "203.0.113.9")
        self.assertTrue(used)

    def test_sign_in_is_email_link_only(self):
        settings = frappe.get_single("System Settings")
        self.assertTrue(settings.login_with_email_link and settings.disable_user_pass_login)
        with self.http(use_cookies=False) as client:
            with client.post("/api/method/login", json={"usr": "Administrator", "pwd": "admin"}) as response:
                self.assertEqual(response.status_code, 401)
            with client.get("/api/resource/VPN Device") as response:
                self.assertEqual(response.status_code, 403)

    def new_server(self, label="atlas"):
        return self.act(MANAGER, lambda: frappe.get_doc({"doctype": "VPN Server", "label": label}).insert())

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

    def test_host_tokens_reach_only_their_own_server_over_http(self):
        import internal_vpn.host

        other = self.new_server("cargo")
        frappe.set_user("Administrator")
        user = frappe.get_doc("User", HUB)
        user.api_key = frappe.generate_hash(length=16)
        user.api_secret = frappe.generate_hash(length=32)
        headers = {"Authorization": f"token {user.api_key}:{user.api_secret}"}
        user.save()
        cargo = frappe.get_doc("User", other.user)
        foreign = {"Authorization": f"token {cargo.api_key}:{cargo.get_password('api_secret')}"}
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
                    "agent": WireGuard.agent_digest(),
                },
            )
            with client.post(path, json=payload, headers=headers) as response:
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.get_json()["message"]["accepted"])
            agent = {"dt": "VPN Server", "dn": self.hub.name, "method": "agent"}
            with client.get(path, query_string=agent, headers=headers) as response:
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_data(), Path(internal_vpn.host.__file__).read_bytes())
            with client.get(path, query_string=agent, headers=foreign) as response:
                self.assertEqual(response.status_code, 403)

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

    # Frappe records no Version history under its own test runner (`ignore_version = frappe.in_test`).
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
