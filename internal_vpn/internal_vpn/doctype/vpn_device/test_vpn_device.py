from unittest.mock import patch

import frappe

from internal_vpn.internal_vpn.doctype.vpn_network.test_vpn_network import (
    ENGINEER,
    MANAGER,
    MODULE,
    OTHER,
    SPOKE,
    VPNTestCase,
    key,
)

IGNORE_TEST_RECORD_DEPENDENCIES = ["User", "VPN Server"]


class TestVPNDevice(VPNTestCase):
    """Engineers' devices: ownership, keys, capacity and removal."""

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
            lambda: self.act(OTHER, lambda: frappe.get_doc("VPN Device", device.name, check_permission=True)),
            lambda: self.act(ENGINEER, lambda: frappe.get_doc("VPN Network").check_permission("read")),
        ):
            with self.assertRaises(frappe.PermissionError):
                action()
        self.update("VPN Device", device.name, actor=ENGINEER, public_key=key(5))
        self.assertEqual(frappe.db.get_value("VPN Device", device.name, "public_key"), key(5))

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

    def test_delete_waits_for_the_hub_and_disabled_members_keep_their_place(self):
        with patch(f"{MODULE}.MAX_PEERS", 2):
            device = self.device()
            self.report_hub()
            with self.assertRaises(frappe.ValidationError):
                self.delete("VPN Device", device.name)
            self.update("VPN Device", device.name, enabled=0)
            with self.assertRaises(frappe.ValidationError):
                self.delete("VPN Device", device.name)
            self.assertNotEqual(self.device(key(4)).address, device.address)
            with self.assertRaises(frappe.ValidationError):
                self.device(key(5))
            self.report_hub()
            self.delete("VPN Device", device.name, actor=ENGINEER)
            self.assertEqual(self.device(key(5)).address, device.address)

    def test_delete_requires_fresh_report_when_membership_returns_to_old_digest(self):
        device = self.device()
        self.update("VPN Device", device.name, enabled=0)
        self.report_hub()
        self.update("VPN Device", device.name, enabled=1)
        # The hub may apply this configuration without successfully reporting it.
        self.hub_configuration()
        self.update("VPN Device", device.name, enabled=0)
        self.assertEqual(self.hub_status(), "Pending")
        with self.assertRaises(frappe.ValidationError):
            self.delete("VPN Device", device.name)
        self.report_hub()
        self.assertEqual(self.hub_status(), "Current")
        self.delete("VPN Device", device.name)

    def test_managers_are_told_about_new_devices(self):
        with patch("frappe.email.doctype.notification.notification.enqueue_create_notification") as alerts:
            device = self.device()
        self.assertEqual(alerts.call_args.args[1]["subject"], f"{ENGINEER} registered VPN device laptop")
        self.assertIn(MANAGER, alerts.call_args.args[0])
        self.assertEqual(alerts.call_args.args[1]["document_name"], device.name)
