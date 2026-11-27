import frappe

from internal_vpn.internal_vpn.doctype.vpn_network.test_vpn_network import (
    ENGINEER,
    OTHER,
    SPOKE,
    VPNTestCase,
    key,
)

IGNORE_TEST_RECORD_DEPENDENCIES = ["User", "VPN Server"]


class TestVPNAccess(VPNTestCase):
    """Grants and the hub rules they produce."""

    def test_access_control_limits_devices_to_granted_servers(self):
        atlas = self.server(SPOKE, key(2), label="atlas")
        laptop, phone = self.device(), self.device(key(4), actor=OTHER)
        revision = self.revision()
        grant = self.grant(atlas.name, ports=" 443, 22")
        self.assertEqual(grant.ports, "22,443")
        self.assertEqual(self.revision(), revision)
        access = self.hub_configuration()["access"]
        self.assertEqual(access, {"restricted": False, "services": [atlas.address], "rules": []})

        self.save_network(access_control=1)
        self.assertEqual(self.revision(), revision + 1)
        access = self.hub_configuration()["access"]
        self.assertTrue(access["restricted"])
        self.assertEqual(
            access["rules"], [{"source": laptop.address, "destination": atlas.address, "ports": "22,443"}]
        )
        self.assertNotIn(phone.address, str(access["rules"]))

        self.update("VPN Access", grant.name, ports="")
        self.assertEqual(self.hub_configuration()["access"]["rules"][0]["ports"], "")
        self.update("VPN Device", laptop.name, actor=ENGINEER, enabled=0)
        self.assertEqual(self.hub_configuration()["access"]["rules"], [])
        self.update("VPN Device", laptop.name, actor=ENGINEER, enabled=1)
        self.delete("VPN Access", grant.name)
        self.assertEqual(self.hub_configuration()["access"]["rules"], [])

    def test_only_managers_grant_valid_access(self):
        atlas = self.server(SPOKE, key(2), label="atlas")
        self.grant(atlas.name)
        for action, error in (
            (lambda: self.grant(atlas.name), frappe.UniqueValidationError),
            (lambda: self.grant(self.hub.name, user=OTHER), frappe.ValidationError),
            (lambda: self.grant(atlas.name, user=OTHER, ports="22; drop"), frappe.ValidationError),
            (lambda: self.act(ENGINEER, lambda: frappe.get_list("VPN Access")), frappe.PermissionError),
        ):
            with self.assertRaises(error):
                action()
