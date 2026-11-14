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
    "version": 2,
    "revision": 3,
    "topology": "hub",
    "name": "service-1",
    "subnet": "100.100.64.0/24",
    "address": "100.100.64.1",
    "public_key": key(1),
    "peers": [
        {"public_key": key(2), "address": "100.100.64.2", "endpoint": None, "allowed_ips": "100.100.64.2/32"}
    ],
}


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.host = Host(CONFIG)
        self.state = Path(tempfile.mkdtemp())

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
        ]
        self.host.validate(SNAPSHOT)
        for mutate in mutations:
            snapshot = deepcopy(SNAPSHOT)
            mutate(snapshot)
            with self.subTest(snapshot=snapshot), self.assertRaises(ValueError):
                self.host.validate(snapshot)

    def test_endpoint_parser_rejects_commands_and_ports(self):
        for endpoint in ("host;echo bad:123", "192.0.2.2:65536", "0.0.0.0:1", None):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                WireGuard.parse_endpoint(endpoint)

    def test_revision_survives_restart_rejects_stale_and_conflict(self):
        path = self.state / "revision.json"
        Host.accept_revision(path, 3, "three")
        Host.accept_revision(path, 3, "three")
        for revision, digest in ((2, "two"), (3, "different")):
            with self.assertRaises(ValueError):
                Host.accept_revision(path, revision, digest)
        Host.accept_revision(path, 4, "four")
        self.assertEqual(json.loads(path.read_text())["revision"], 4)

    def test_removal_precedes_updates_and_private_key_is_untouched(self):
        with (
            patch.object(WireGuard, "show", side_effect=[key(1), key(3)]),
            patch.object(WireGuard, "set_peer") as set_peer,
        ):
            self.host.apply(SNAPSHOT)
        calls = [call.args for call in set_peer.call_args_list]
        self.assertEqual(calls[0], (key(3), "remove"))
        self.assertIn("100.100.64.2/32", calls[1])
        self.assertNotIn("private-key", str(calls))

    def test_wrong_interface_identity_prevents_mutation(self):
        with (
            patch.object(WireGuard, "show", return_value=key(7)),
            patch.object(WireGuard, "set_peer") as set_peer,
            self.assertRaises(ValueError),
        ):
            self.host.apply(SNAPSHOT)
        set_peer.assert_not_called()

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

    def test_cli_failure_hides_errors(self):
        config = self.state / "host.json"
        config.write_text(json.dumps(CONFIG))
        output = io.StringIO()
        with (
            patch("sys.argv", ["host.py", "update", "--config", str(config), "--state", str(self.state)]),
            patch("os.geteuid", return_value=0),
            patch("pathlib.Path.stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)),
            patch.object(Host, "update", side_effect=OSError("secret-must-not-appear")),
            patch("sys.stdout", output),
            self.assertRaises(SystemExit) as error,
        ):
            main()
        self.assertEqual(error.exception.code, 1)
        self.assertEqual(json.loads(output.getvalue()), {"ok": False, "error": "update failed"})


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
