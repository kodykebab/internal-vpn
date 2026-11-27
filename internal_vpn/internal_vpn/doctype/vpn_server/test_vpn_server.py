from unittest.mock import patch

import frappe
from frappe.utils import add_to_date, now_datetime

from internal_vpn.host import WireGuard
from internal_vpn.internal_vpn.doctype.vpn_network.test_vpn_network import (
    ENGINEER,
    HUB,
    MANAGER,
    SPOKE,
    VPNTestCase,
    key,
)

IGNORE_TEST_RECORD_DEPENDENCIES = ["User", "VPN Server"]


class TestVPNServer(VPNTestCase):
    """Servers: the hub, host credentials, enrollment and agent versions."""

    def test_hub_cannot_be_disabled_or_deleted(self):
        with self.assertRaises(frappe.ValidationError):
            self.update("VPN Server", self.hub.name, enabled=0)
        with self.assertRaises(frappe.ValidationError):
            self.delete("VPN Server", self.hub.name)

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

    def test_outdated_spoke_agents_are_flagged(self):
        atlas = self.server(SPOKE, key(2), label="atlas")
        self.report_hub()

        def report(**agent):
            snapshot = self.call(SPOKE, "VPN Server", atlas.name, "get_configuration")
            self.call(
                SPOKE,
                "VPN Server",
                atlas.name,
                "report",
                revision=snapshot["revision"],
                success=True,
                digest=WireGuard.digest(snapshot),
                **agent,
            )
            return frappe.db.get_value("VPN Server", atlas.name, "agent_outdated")

        self.assertEqual(report(agent=WireGuard.agent_digest()), 0)
        self.assertEqual(report(agent="0" * 64), 1)
        with self.assertRaises(TypeError):
            report()
        self.assertEqual(frappe.db.get_value("VPN Server", self.hub.name, "agent_outdated"), 0)

    def test_servers_enroll_once_with_the_command_from_their_form(self):
        server = self.new_server()
        host = server.user
        self.assertIn("VPN Host", frappe.get_roles(host))
        self.assertEqual(frappe.db.get_value("User", host, "user_type"), "Website User")
        self.assertNotIn(server.address, self.peers())
        enrollment = self.enrollment(server.name)
        self.assertFalse(enrollment["expired"])
        self.assertIn("enroll --url http", enrollment["command"])
        self.assertIn(f"--server {server.name}", enrollment["command"])
        old_secret = frappe.get_doc("User", host).get_password("api_secret")
        self.assertIn(old_secret, enrollment["command"])

        revision = self.revision()
        result = self.call(host, "VPN Server", server.name, "enroll", public_key=key(7))
        self.assertEqual(
            (result["address"], result["subnet"], result["hub_public_key"]),
            (server.address, "100.100.64.0/24", key(1)),
        )
        new_secret = frappe.get_doc("User", host).get_password("api_secret")
        self.assertNotEqual(new_secret, old_secret)
        self.assertEqual(result["token"].split(":")[1], new_secret)
        self.assertEqual(self.revision(), revision + 1)
        self.assertIn(server.address, self.peers())
        with self.assertRaises(frappe.ValidationError):
            self.call(host, "VPN Server", server.name, "enroll", public_key=key(8))
        self.assertIsNone(self.enrollment(server.name))

    def test_enrollment_is_refused_late_for_the_hub_and_restarts_on_request(self):
        server = self.new_server()
        later = add_to_date(now_datetime(), minutes=31)
        with patch(
            "internal_vpn.internal_vpn.doctype.vpn_server.vpn_server.now_datetime", return_value=later
        ):
            with self.assertRaises(frappe.ValidationError):
                self.call(server.user, "VPN Server", server.name, "enroll", public_key=key(7))
            self.assertTrue(self.enrollment(server.name)["expired"])
        with self.assertRaises(frappe.ValidationError):
            self.call(HUB, "VPN Server", self.hub.name, "enroll", public_key=key(8))
        with self.assertRaises(frappe.PermissionError):
            self.call(server.user, "VPN Server", server.name, "new_enrollment")

        self.call(server.user, "VPN Server", server.name, "enroll", public_key=key(7))
        self.call(MANAGER, "VPN Server", server.name, "new_enrollment")
        self.assertIsNone(frappe.db.get_value("VPN Server", server.name, "public_key"))
        self.assertNotIn(server.address, self.peers())
        self.assertFalse(self.enrollment(server.name)["expired"])
        self.call(server.user, "VPN Server", server.name, "enroll", public_key=key(9))
        self.assertIn(server.address, self.peers())
