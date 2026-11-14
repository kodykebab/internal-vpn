import unittest
from copy import deepcopy

from frappe import _dict
from test_host import key

from internal_vpn.host import Host, WireGuard
from internal_vpn.internal_vpn.doctype.vpn_network.vpn_network import VPNNetwork

SUBNET = "100.100.64.0/24"


class TopologyTests(unittest.TestCase):
    def setUp(self):
        self.hub = _dict(
            name="central", public_key=key(1), address="100.100.64.1", endpoint="192.0.2.1:51820"
        )
        self.spoke = _dict(name="atlas", public_key=key(2), address="100.100.64.2")
        self.device = _dict(name="engineer", public_key=key(3), address="100.100.64.3")
        self.members = [self.hub, self.spoke, self.device]

    def configuration(self, peer, members=None, revision=1):
        members = self.members if members is None else members
        return VPNNetwork.build_configuration(peer, self.hub, members, SUBNET, revision)

    def host(self, peer, topology):
        return Host(
            dict(
                peer,
                topology=topology,
                subnet=SUBNET,
                interface="ivpn0",
                hub_public_key=self.hub.public_key,
            )
        )

    def test_hub_lists_members_as_host_routes_with_learned_endpoints(self):
        snapshot = self.configuration(self.hub)
        self.assertEqual(len(snapshot["peers"]), 2)
        self.assertTrue(
            all(p["endpoint"] is None and p["allowed_ips"] == p["address"] + "/32" for p in snapshot["peers"])
        )
        self.host(self.hub, "hub").validate(snapshot)

    def test_spoke_routes_subnet_only_through_pinned_hub(self):
        snapshot = self.configuration(self.spoke)
        self.assertEqual(
            snapshot["peers"],
            [
                {
                    "public_key": key(1),
                    "address": "100.100.64.1",
                    "endpoint": "192.0.2.1:51820",
                    "allowed_ips": SUBNET,
                }
            ],
        )
        self.host(self.spoke, "spoke").validate(snapshot)

    def test_member_removal_changes_only_hub_desired_state(self):
        remaining = [self.hub, self.spoke]
        for peer, changes in ((self.hub, True), (self.spoke, False)):
            before = WireGuard.digest(self.configuration(peer))
            after = WireGuard.digest(self.configuration(peer, remaining, revision=2))
            self.assertEqual(before != after, changes)
        self.assertEqual(self.configuration(self.device, remaining)["peers"], [])

    def test_hub_endpoint_change_invalidates_spokes(self):
        before = WireGuard.digest(self.configuration(self.spoke))
        self.hub.endpoint = "192.0.2.4:51820"
        self.assertNotEqual(before, WireGuard.digest(self.configuration(self.spoke, revision=2)))

    def test_spoke_rejects_broad_routes_direct_peers_and_unpinned_hubs(self):
        mutations = [
            lambda d: d["peers"][0].update(allowed_ips="0.0.0.0/0"),
            lambda d: d["peers"][0].update(allowed_ips="100.64.0.0/10"),
            lambda d: d["peers"][0].update(public_key=key(7)),
            lambda d: d["peers"][0].update(endpoint=None),
            lambda d: d["peers"].append(deepcopy(d["peers"][0])),
            lambda d: d.update(topology="hub"),
        ]
        for mutate in mutations:
            snapshot = self.configuration(self.spoke)
            mutate(snapshot)
            with self.subTest(snapshot=snapshot), self.assertRaises(ValueError):
                self.host(self.spoke, "spoke").validate(snapshot)


if __name__ == "__main__":
    unittest.main()
