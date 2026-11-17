import base64
import io
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from internal_vpn.host import ControlPlane, Host, NoRedirect, WireGuard, main


def key(byte):
    return base64.b64encode(bytes([byte]) * 32).decode()


CONFIG = {
    "name": "service-1",
    "subnet": "100.100.64.0/24",
    "address": "100.100.64.1",
    "public_key": key(1),
    "interface": "ivpn0",
    "topology": "hub",
    "url": "https://vpn.example",
    "token": "never-print-me",
}
SNAPSHOT = {
    "version": 3,
    "revision": 3,
    "topology": "hub",
    "name": "service-1",
    "subnet": "100.100.64.0/24",
    "address": "100.100.64.1",
    "public_key": key(1),
    "peers": [
        {"public_key": key(2), "address": "100.100.64.2", "endpoint": None, "allowed_ips": "100.100.64.2/32"}
    ],
    "access": {"services": ["100.100.64.2"]},
}


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.host = Host(CONFIG)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)

    def test_rejects_untrusted_shapes_and_addresses(self):
        mutations = [
            lambda d: d.update(post_up="echo dangerous"),
            lambda d: d.update(revision=True),
            lambda d: d.update(version=True),
            lambda d: d.update(name="another-service"),
            lambda d: d.update(public_key=key(3)),
            lambda d: d["peers"][0].update(address="0.0.0.0/0"),
            lambda d: d["peers"][0].update(address="100.100.65.2"),
            lambda d: d["peers"][0].update(address=1684291586),
            lambda d: d["peers"][0].update(address="100.100.64.255"),
            lambda d: d["peers"][0].update(address=CONFIG["address"]),
            lambda d: d["peers"].append(deepcopy(d["peers"][0])),
            lambda d: d["peers"][0].update(public_key=key(0)),
            lambda d: d["peers"][0].update(allowed_ips="100.100.64.0/24"),
            lambda d: d.update(access=None),
            lambda d: d.update(access={"services": ["10.0.0.1"]}),
            lambda d: d.update(access={"services": [], "extra": 1}),
        ]
        self.host.validate(SNAPSHOT)
        for mutate in mutations:
            snapshot = deepcopy(SNAPSHOT)
            mutate(snapshot)
            with self.subTest(snapshot=snapshot), self.assertRaises((TypeError, ValueError)):
                self.host.validate(snapshot)

    def test_endpoint_parser_rejects_commands_and_ports(self):
        for endpoint in (
            "host;echo bad:123",
            "192.0.2.2:65536",
            "0.0.0.0:1",
            None,
            "169.254.1.1:51820",
            "2001:db8::1:51820",
            "[2001:db8::1]",
            "[::]:51820",
            "[fe80::1]:51820",
            "[ff02::1]:51820",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises((TypeError, ValueError)):
                WireGuard.parse_endpoint(endpoint)

    def test_endpoint_parser_normalizes_ipv4_and_ipv6(self):
        self.assertEqual(WireGuard.parse_endpoint("192.0.2.1:051820"), "192.0.2.1:51820")
        self.assertEqual(WireGuard.parse_endpoint("[2001:DB8:0::0001]:51820"), "[2001:db8::1]:51820")

    def test_revision_survives_restart_rejects_stale_and_conflict(self):
        path = self.state / "revision.json"
        Host.accept_revision(path, 3, "three")
        Host.accept_revision(path, 3, "three")
        for revision, digest in ((2, "two"), (3, "different")):
            with self.assertRaises(ValueError):
                Host.accept_revision(path, revision, digest)
        Host.accept_revision(path, 4, "four")
        self.assertEqual(json.loads(path.read_text())["revision"], 4)

    def apply(self, *rows, host=None, snapshot=SNAPSHOT):
        """Apply over live `wg show` rows of (key, allowed IPs, endpoint, keepalive)."""
        columns = ["\n".join(f"{row[0]}\t{row[i]}" for row in rows) for i in (1, 2, 3)]
        with (
            patch.object(WireGuard, "show", side_effect=[(host or self.host).public_key, *columns]),
            patch.object(WireGuard, "set_peer") as set_peer,
            patch.object(WireGuard, "execute") as execute,
        ):
            (host or self.host).apply(snapshot)
        self.nft = [call.kwargs["input"] for call in execute.call_args_list if call.args[0] == "nft"]
        return [call.args for call in set_peer.call_args_list]

    def test_hub_rules_let_members_reach_servers_but_never_open_devices(self):
        link = 'iifname "ivpn0" oifname "ivpn0"'
        self.apply()
        (script,) = self.nft
        self.assertTrue(
            script.startswith("table inet internal_vpn_access\ndelete table inet internal_vpn_access\n")
        )
        for line in (
            f"{link} ct state established,related accept",
            f"{link} ip saddr {{ 100.100.64.2 }} ip daddr {{ 100.100.64.2 }} accept",
            f"{link} ip daddr {{ 100.100.64.2 }} accept",
            f"{link} counter drop",
        ):
            self.assertIn(line, script)
        spoke = Host(dict(CONFIG, topology="spoke", address="100.100.64.2", public_key=key(2)))
        hub = {"public_key": key(1), "address": "100.100.64.1", "endpoint": "192.0.2.1:51820"}
        spoke_snapshot = dict(
            SNAPSHOT, topology="spoke", access=None, peers=[dict(hub, allowed_ips="100.100.64.0/24")]
        )
        self.apply(host=spoke, snapshot=spoke_snapshot)
        self.assertEqual(self.nft, [])

    def test_removal_precedes_updates_and_private_key_is_untouched(self):
        calls = self.apply((key(3), "100.100.64.3/32", "(none)", "off"))
        self.assertEqual(calls[0], (key(3), "remove"))
        self.assertIn("100.100.64.2/32", calls[1])
        self.assertNotIn("private-key", str(calls))

    def test_unchanged_peers_are_skipped_and_drift_is_corrected(self):
        self.assertEqual(self.apply((key(2), "100.100.64.2/32", "198.51.100.7:4000", "off")), [])
        for drift in (("100.100.64.9/32", "(none)", "off"), ("100.100.64.2/32", "(none)", "25")):
            with self.subTest(drift=drift):
                self.assertEqual(len(self.apply((key(2), *drift))), 1)

    def test_spoke_pins_hub_endpoint_and_keepalive(self):
        spoke = Host(dict(CONFIG, topology="spoke", address="100.100.64.2", public_key=key(2)))
        hub = {"public_key": key(1), "address": "100.100.64.1", "endpoint": "192.0.2.1:51820"}
        snapshot = dict(SNAPSHOT, topology="spoke", peers=[dict(hub, allowed_ips="100.100.64.0/24")])
        current = (key(1), "100.100.64.0/24", "192.0.2.1:51820", "25")
        self.assertEqual(self.apply(current, host=spoke, snapshot=snapshot), [])
        moved = (key(1), "100.100.64.0/24", "192.0.2.5:51820", "25")
        self.assertIn("192.0.2.1:51820", self.apply(moved, host=spoke, snapshot=snapshot)[0])
        ipv6 = dict(snapshot, peers=[dict(snapshot["peers"][0], endpoint="[2001:db8::1]:51820")])
        current = (key(1), "100.100.64.0/24", "[2001:db8::1]:51820", "25")
        self.assertEqual(self.apply(current, host=spoke, snapshot=ipv6), [])

    def test_wrong_interface_identity_prevents_mutation(self):
        with (
            patch.object(WireGuard, "show", return_value=key(7)),
            patch.object(WireGuard, "set_peer") as set_peer,
            self.assertRaises(ValueError),
        ):
            self.host.apply(SNAPSHOT)
        set_peer.assert_not_called()

    def test_namespace_config_cannot_target_the_host_interface(self):
        with self.assertRaises(ValueError):
            Host(dict(CONFIG, namespace="old-lab"))

    def update(self, snapshot=SNAPSHOT, apply=None, report=None):
        with (
            patch.object(ControlPlane, "get_configuration", return_value=snapshot),
            patch.object(ControlPlane, "report", side_effect=report) as reported,
            patch.object(Host, "apply", side_effect=apply) as applied,
        ):
            try:
                self.host.update(self.state)
            finally:
                self.reported, self.applied = reported, applied

    def test_failed_apply_keeps_watermark_and_reports_failure(self):
        with self.assertRaises(OSError):
            self.update(apply=OSError)
        self.assertEqual(json.loads((self.state / "revision.json").read_text())["revision"], 3)
        self.reported.assert_called_once_with(3, None)

    def test_stale_response_after_restart_never_reaches_wireguard(self):
        Host.accept_revision(self.state / "revision.json", 4, "newer")
        with self.assertRaises(ValueError):
            self.update()
        self.applied.assert_not_called()
        self.reported.assert_not_called()

    def test_unavailable_control_plane_does_not_apply_cached_membership(self):
        with (
            patch.object(ControlPlane, "get_configuration", side_effect=OSError),
            patch.object(Host, "apply") as applied,
            self.assertRaises(OSError),
        ):
            self.host.update(self.state)
        applied.assert_not_called()

    def test_report_failure_does_not_undo_applied_membership(self):
        with self.assertRaises(OSError):
            self.update(report=OSError("report unreachable"))
        self.applied.assert_called_once_with(SNAPSHOT)
        self.reported.assert_called_once_with(3, WireGuard.digest(SNAPSHOT))

    def test_https_only_and_no_redirects(self):
        for url in (
            "http://example.com",
            "https://user:password@example.com",
            "https://example.com?token=value",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                ControlPlane(dict(CONFIG, url=url))
        with self.assertRaises(ValueError):
            NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.example")

    def test_cli_failure_reports_stage_without_exception_details(self):
        config = self.state / "host.json"
        config.write_text(json.dumps(CONFIG))
        for target, stage in (
            ("internal_vpn.host.Host.__init__", "configuration"),
            ("internal_vpn.host.ControlPlane.get_configuration", "fetch"),
            ("internal_vpn.host.Host.validate", "validation"),
            ("internal_vpn.host.Host.accept_revision", "state"),
            ("internal_vpn.host.Host.apply", "apply"),
            ("internal_vpn.host.ControlPlane.report", "report"),
        ):
            output = io.StringIO()
            with (
                self.subTest(stage=stage),
                patch("sys.argv", ["host.py", "update", "--config", str(config), "--state", str(self.state)]),
                patch("os.geteuid", return_value=0),
                patch("pathlib.Path.stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)),
                patch.object(ControlPlane, "get_configuration", return_value=SNAPSHOT),
                patch.object(ControlPlane, "report"),
                patch.object(Host, "apply"),
                patch(target, side_effect=OSError("secret-must-not-appear")),
                patch("sys.stdout", output),
                self.assertRaises(SystemExit) as error,
            ):
                main()
            self.assertEqual(error.exception.code, 1)
            self.assertEqual(
                json.loads(output.getvalue()),
                {"ok": False, "error": "update failed", "stage": stage},
            )

    def test_apply_and_failure_report_errors_keep_apply_stage(self):
        with self.assertRaises(OSError):
            self.update(apply=OSError("apply secret"), report=OSError("report secret"))
        self.assertEqual(self.host.stage, "apply")


class MeasureTests(unittest.TestCase):
    def setUp(self):
        self.host = Host(CONFIG)

    def test_measurements_have_no_secrets_and_only_read(self):
        shown = [key(1), f"{key(2)} 90\n{key(3)} 0", f"{key(2)} 100 200\n{key(3)} 0 0", key(1)]
        with patch.object(WireGuard, "show", side_effect=shown) as show, patch("time.time", return_value=100):
            result = self.host.measure()
        peers = {peer["public_key"]: peer for peer in result["peers"]}
        self.assertEqual(peers[key(2)]["handshake_age_seconds"], 10)
        self.assertIsNone(peers[key(3)]["handshake_age_seconds"])
        self.assertEqual(peers[key(2)]["rx_bytes"], 100)
        self.assertNotIn(CONFIG["token"], json.dumps(result))
        self.assertEqual(
            [call.args[0] for call in show.call_args_list],
            ["public-key", "latest-handshakes", "transfer", "public-key"],
        )

    def test_future_handshake_has_no_age(self):
        shown = [key(1), f"{key(2)} 101", f"{key(2)} 1 2", key(1)]
        with patch.object(WireGuard, "show", side_effect=shown), patch("time.time", return_value=100):
            self.assertIsNone(self.host.measure()["peers"][0]["handshake_age_seconds"])

    def test_changed_membership_or_identity_fails(self):
        for shown in ([key(9)], [key(1), f"{key(2)} 10", "", key(1)], [key(1), "", "", key(9)]):
            with patch.object(WireGuard, "show", side_effect=shown), self.assertRaises(ValueError):
                self.host.measure()

    def test_probes_must_be_other_vpn_addresses(self):
        for address in (
            "1.1.1.1",
            "example.com",
            "100.100.64.0",
            "100.100.64.255",
            "100.100.64.1",
            "100.100.64.2;id",
        ):
            with patch.object(WireGuard, "show") as show, self.assertRaises(ValueError):
                self.host.measure([address])
            show.assert_not_called()

    def test_probe_distinguishes_no_reply_error_and_latency(self):
        for code, output, reachable in ((0, "64 bytes time=1.25 ms", True), (1, "", False)):
            with patch.object(
                WireGuard, "execute", return_value=SimpleNamespace(returncode=code, stdout=output)
            ):
                result = self.host.ping("100.100.64.2")
            self.assertEqual(result["reachable"], reachable)
            self.assertEqual(result["rtt_ms"], 1.25 if reachable else None)
        with (
            patch.object(WireGuard, "execute", return_value=SimpleNamespace(returncode=2, stdout="")),
            self.assertRaises(ValueError),
        ):
            self.host.ping("100.100.64.2")

    def test_malformed_counters_fail(self):
        for raw in (f"{key(2)} -1", f"{key(2)} nan", f"{key(2)} 1 2", f"{key(2)} 1\n{key(2)} 2"):
            with self.assertRaises(ValueError):
                Host.parse_counters(raw, 1)

    def test_unit_that_never_ran_has_no_result(self):
        output = (
            "LoadState=loaded\nActiveState=inactive\nResult=success\n"
            "ExecMainStatus=0\nExecMainExitTimestampMonotonic=0\n"
        )
        with patch("subprocess.run", return_value=SimpleNamespace(stdout=output)):
            result = Host.read_unit("internal-vpn-update.service")
        self.assertIsNone(result["last_result"])
        self.assertIsNone(result["last_exit_status"])
        with (
            patch(
                "subprocess.run", return_value=SimpleNamespace(stdout=output.replace("loaded", "not-found"))
            ),
            self.assertRaises(ValueError),
        ):
            Host.read_unit("missing.service")


if __name__ == "__main__":
    unittest.main()
