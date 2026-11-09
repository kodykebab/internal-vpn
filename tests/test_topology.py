import unittest
from copy import deepcopy

from test_host import key

from internal_vpn.host import validate_snapshot
from internal_vpn.topology import build_configuration, desired_digest


class HubTopologyTests(unittest.TestCase):
    def setUp(self):
        self.pool = "100.100.64.0/24"
        self.hub = {
            "name": "central",
            "public_key": key(1),
            "address": "100.100.64.1",
            "endpoint": "192.0.2.1:51820",
        }
        self.spoke = {"name": "atlas", "public_key": key(2), "address": "100.100.64.2"}
        self.device = {"name": "engineer", "public_key": key(3), "address": "100.100.64.3"}
        self.members = [self.hub, self.spoke, self.device]

    def snapshot(self, peer, members=None, revision=1, enabled=True):
        return build_configuration(
            peer, self.hub, self.members if members is None else members, self.pool, revision, enabled
        )

    def local(self, peer, role):
        return dict(peer, topology=role, subnet=self.pool, hub_public_key=self.hub["public_key"])

    def test_hub_assigns_individual_addresses_and_learns_endpoints(self):
        data = self.snapshot(self.hub)
        self.assertEqual(len(data["peers"]), 2)
        self.assertTrue(
            all(p["endpoint"] is None and p["allowed_ips"] == p["address"] + "/32" for p in data["peers"])
        )
        validate_snapshot(data, self.local(self.hub, "hub"))

    def test_spoke_routes_only_allocated_subnet_via_pinned_hub(self):
        data = self.snapshot(self.spoke)
        self.assertEqual(len(data["peers"]), 1)
        self.assertEqual(data["peers"][0]["public_key"], self.hub["public_key"])
        self.assertEqual(data["peers"][0]["allowed_ips"], self.pool)
        validate_snapshot(data, self.local(self.spoke, "spoke"))

    def test_hub_removal_changes_only_hub_desired_state(self):
        remaining = [self.hub, self.spoke]
        self.assertNotEqual(
            desired_digest(self.snapshot(self.hub)), desired_digest(self.snapshot(self.hub, remaining, 2))
        )
        self.assertEqual(
            desired_digest(self.snapshot(self.spoke)), desired_digest(self.snapshot(self.spoke, remaining, 2))
        )
        self.assertEqual(self.snapshot(self.device, remaining, 2, enabled=False)["peers"], [])

    def test_hub_endpoint_change_invalidates_spoke_configuration(self):
        old = desired_digest(self.snapshot(self.spoke))
        self.hub["endpoint"] = "192.0.2.4:51820"
        self.assertNotEqual(old, desired_digest(self.snapshot(self.spoke, revision=2)))

    def test_agent_rejects_broad_hub_routes_direct_peers_and_unpinned_hubs(self):
        spoke = self.snapshot(self.spoke)
        mutations = [
            lambda d: d["peers"][0].update(allowed_ips="0.0.0.0/0"),
            lambda d: d["peers"][0].update(allowed_ips="100.64.0.0/10"),
            lambda d: d["peers"][0].update(public_key=key(7)),
            lambda d: d["peers"][0].update(endpoint=None),
            lambda d: d["peers"].append(deepcopy(d["peers"][0])),
            lambda d: d.update(topology="hub"),
        ]
        for mutate in mutations:
            data = deepcopy(spoke)
            mutate(data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                validate_snapshot(data, self.local(self.spoke, "spoke"))
        hub = self.snapshot(self.hub)
        hub["peers"][0]["allowed_ips"] = self.pool
        with self.assertRaises(ValueError):
            validate_snapshot(hub, self.local(self.hub, "hub"))
