import unittest
from copy import deepcopy
from unittest.mock import patch

from frappe import _dict
from test_host import key

from internal_vpn.host import Host, WireGuard
from internal_vpn.internal_vpn.doctype.vpn_network.vpn_network import VPNNetwork

SUBNET = "100.100.64.0/24"


class HubApplyTests(unittest.TestCase):
    def test_only_the_hub_site_enqueues_the_apply_job(self):
        for conf, enqueued in (({}, False), ({"internal_vpn_interface": "ivpn0"}, True)):
            with (
                self.subTest(conf=conf),
                patch("frappe.conf", _dict(conf)),
                patch("frappe.enqueue") as enqueue,
            ):
                VPNNetwork.enqueue_hub_apply()
                self.assertEqual(enqueue.called, enqueued)
        self.assertTrue(enqueue.call_args.kwargs["enqueue_after_commit"])


class TopologyTests(unittest.TestCase):
    def setUp(self):
        self.hub = _dict(
            name="dedicated-hub", doctype="VPN Server", public_key=key(1), address="100.100.64.1"
        )
        self.spoke = _dict(name="atlas", doctype="VPN Server", public_key=key(2), address="100.100.64.2")
        self.device = _dict(name="engineer", doctype="VPN Device", public_key=key(3), address="100.100.64.3")
        self.members = [self.hub, self.spoke, self.device]
        self.endpoint = "192.0.2.1:51820"

    def network(self, revision=1):
        network = VPNNetwork.__new__(VPNNetwork)
        network.subnet, network.revision, network.hub_endpoint = SUBNET, revision, self.endpoint
        network.access_control = 0
        return network

    def configuration(self, peer, members=None, revision=1):
        members = self.members if members is None else members
        return self.network(revision).build_configuration(
            peer, self.hub, {member.name: member for member in members}
        )

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

    def test_unrelated_revision_keeps_spoke_current_but_requires_hub_acknowledgement(self):
        network = self.network(revision=2)
        members = {peer.name: peer for peer in self.members}
        for peer in (self.hub, self.spoke):
            peer.apply_success = 1
            peer.reported_revision = 1
            peer.reported_digest = WireGuard.digest(self.configuration(peer))
        self.assertTrue(network.is_current(self.spoke, self.hub, members))
        self.assertFalse(network.is_current(self.hub, self.hub, members))
        self.hub.reported_revision = 2
        self.assertTrue(network.is_current(self.hub, self.hub, members))

    def test_hub_endpoint_change_invalidates_spokes(self):
        before = WireGuard.digest(self.configuration(self.spoke))
        self.endpoint = "192.0.2.4:51820"
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
            with self.subTest(snapshot=snapshot), self.assertRaises((TypeError, ValueError)):
                self.host(self.spoke, "spoke").validate(snapshot)


if __name__ == "__main__":
    unittest.main()
