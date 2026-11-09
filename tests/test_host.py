import base64
import io
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from internal_vpn.host import (
    ControlPlaneClient,
    NoRedirect,
    accept_revision,
    apply,
    main,
    reconcile,
    validate_snapshot,
)


def key(byte):
    return base64.b64encode(bytes([byte]) * 32).decode()


class HostTests(unittest.TestCase):
    def setUp(self):
        self.local = {
            "name": "service-1",
            "subnet": "100.100.64.0/24",
            "address": "100.100.64.1",
            "public_key": key(1),
            "interface": "ivpn0",
            "topology": "hub",
        }
        self.data = dict(
            version=2,
            revision=3,
            **{k: v for k, v in self.local.items() if k != "interface"},
            peers=[
                {
                    "public_key": key(2),
                    "address": "100.100.64.2",
                    "endpoint": None,
                    "allowed_ips": "100.100.64.2/32",
                }
            ],
        )

    def test_valid_snapshot_and_learned_device_endpoint(self):
        validate_snapshot(self.data, self.local)

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
            lambda d: d["peers"][0].update(address=self.local["address"]),
            lambda d: d["peers"].append(deepcopy(d["peers"][0])),
            lambda d: d["peers"][0].update(public_key=key(0)),
            lambda d: d["peers"][0].update(endpoint="host;echo bad:123"),
            lambda d: d["peers"][0].update(endpoint="192.0.2.2:65536"),
        ]
        for mutate in mutations:
            data = deepcopy(self.data)
            mutate(data)
            with self.subTest(data=data), self.assertRaises((ValueError, TypeError)):
                validate_snapshot(data, self.local)

    def test_revision_survives_restart_rejects_stale_and_conflict(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "revision.json"
            accept_revision(path, 3, "hash-three")
            accept_revision(path, 3, "hash-three")
            with self.assertRaises(ValueError):
                accept_revision(path, 2, "hash-two")
            with self.assertRaises(ValueError):
                accept_revision(path, 3, "different")
            accept_revision(path, 4, "hash-four")
            self.assertEqual(json.loads(path.read_text())["revision"], 4)

    def test_removal_precedes_updates_and_private_key_is_untouched(self):
        with patch("internal_vpn.host.wg", side_effect=[key(1), key(3), "", ""]) as wg:
            apply(self.data, self.local)
        calls = [call.args[1:] for call in wg.call_args_list]
        self.assertEqual(calls[2], ("set", "ivpn0", "peer", key(3), "remove"))
        self.assertIn("100.100.64.2/32", calls[3])
        self.assertNotIn("private-key", str(calls))

    def test_wrong_interface_identity_prevents_mutation(self):
        with patch("internal_vpn.host.wg", return_value=key(7)) as wg, self.assertRaises(ValueError):
            apply(self.data, self.local)
        self.assertEqual(wg.call_count, 1)

    def test_failed_apply_keeps_watermark_and_reports_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            with (
                patch("internal_vpn.host.ControlPlaneClient") as controller,
                patch("internal_vpn.host.apply", side_effect=OSError),
            ):
                controller.return_value.request.return_value = self.data
                with self.assertRaises(OSError):
                    reconcile(self.local, state)
                self.assertEqual(json.loads((state / "revision.json").read_text())["revision"], 3)
                self.assertEqual(
                    controller.return_value.request.call_args.args,
                    ("report", {"name": "service-1", "revision": 3, "success": False}, True),
                )

    def test_stale_response_after_restart_never_reaches_wireguard(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            accept_revision(state / "revision.json", 4, "newer")
            with (
                patch("internal_vpn.host.ControlPlaneClient") as controller,
                patch("internal_vpn.host.apply") as apply_mock,
            ):
                controller.return_value.request.return_value = self.data
                with self.assertRaises(ValueError):
                    reconcile(self.local, state)
                apply_mock.assert_not_called()
                self.assertEqual(controller.return_value.request.call_count, 1)

    def test_unavailable_control_plane_does_not_apply_cached_membership(self):
        with tempfile.TemporaryDirectory() as temporary:
            with (
                patch("internal_vpn.host.ControlPlaneClient") as controller,
                patch("internal_vpn.host.apply") as apply_mock,
            ):
                controller.return_value.request.side_effect = OSError
                with self.assertRaises(OSError):
                    reconcile(self.local, Path(temporary))
                apply_mock.assert_not_called()

    def test_report_failure_does_not_undo_applied_membership(self):
        with tempfile.TemporaryDirectory() as temporary:
            with (
                patch("internal_vpn.host.ControlPlaneClient") as controller,
                patch("internal_vpn.host.apply") as apply_mock,
            ):
                controller.return_value.request.side_effect = [self.data, OSError("report unreachable")]
                with self.assertRaises(OSError):
                    reconcile(self.local, Path(temporary))
                apply_mock.assert_called_once_with(self.data, self.local)
                self.assertEqual(json.loads((Path(temporary) / "revision.json").read_text())["revision"], 3)

    def test_cli_failure_does_not_claim_no_apply_or_expose_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "host.json"
            config.write_text("{}")
            output = io.StringIO()
            with (
                patch("sys.argv", ["run-host.py", "--config", str(config), "--state", temporary]),
                patch("internal_vpn.host.os.geteuid", return_value=0),
                patch(
                    "internal_vpn.host.Path.stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)
                ),
                patch("internal_vpn.host.reconcile", side_effect=OSError("secret-must-not-appear")),
                patch("sys.stdout", output),
                self.assertRaises(SystemExit) as error,
            ):
                main()
            self.assertEqual(error.exception.code, 1)
            result = json.loads(output.getvalue())
            self.assertFalse(result["ok"])
            self.assertNotIn("applied", result)
            self.assertNotIn("secret-must-not-appear", output.getvalue())

    def test_https_and_no_credential_redirects(self):
        for url in (
            "http://example.com",
            "https://user:password@example.com",
            "https://example.com?token=value",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                ControlPlaneClient({"url": url})
        with self.assertRaises(ValueError):
            NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.example")


if __name__ == "__main__":
    unittest.main()
