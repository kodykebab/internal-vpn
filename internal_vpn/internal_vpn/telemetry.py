from datetime import UTC, datetime
from pathlib import Path

import frappe
import tomllib
from frappe import _
from frappe.integrations.utils import make_post_request
from frappe.utils import cint, get_bench_path

from internal_vpn.host import Host, WireGuard

CONNECTED_SECONDS = 180
KINDS = {"VPN Server": "server", "VPN Device": "device"}


class Telemetry:
    """VPN health for Datum, sent by the hub. It reads what the hub's interface has and the stored
    statuses without the network lock, so a slow Datum never holds up membership changes."""

    def __init__(self, network):
        self.network = network
        self.now = datetime.now(UTC)
        self.rows = []

    def credential(self) -> tuple[str, str]:
        """The Datum endpoint and token of the chosen source."""
        if self.network.telemetry == "Pilot":
            path = Path(get_bench_path()).parent / "common_config.toml"
            config = tomllib.loads(path.read_text()).get("telemetry", {}) if path.exists() else {}
            if not config.get("enabled", True):
                frappe.throw(_("Pilot telemetry is turned off on this server"))
            endpoint, token = config.get("endpoint"), config.get("token")
        else:
            endpoint = frappe.conf.get("internal_vpn_datum_endpoint")
            token = frappe.conf.get("internal_vpn_datum_token")
        if not endpoint or not token:
            frappe.throw(_("No Datum endpoint and token for {0} telemetry").format(_(self.network.telemetry)))
        return endpoint.rstrip("/"), token

    def send(self):
        endpoint, token = self.credential()
        make_post_request(
            f"{endpoint}/v1/ingest",
            headers={"Authorization": f"Bearer {token}"},
            json={"samples": self.samples()},
            timeout=10,
        )

    def samples(self) -> list[dict]:
        wireguard = WireGuard(frappe.conf.get("internal_vpn_interface"), sudo=True)
        self.add_peers(wireguard.handshakes(), Host.parse_counters(wireguard.show("transfer"), 2))
        self.add_statuses()
        return self.rows

    def add(self, metric: str, value: float, **labels: str):
        self.rows.append(
            {"metric": f"internal_vpn_{metric}", "value": value, "ts": self.now.isoformat(), "labels": labels}
        )

    def add_peers(self, handshakes: dict[str, int], transfer: dict[str, list[int]]):
        """Peers on the hub's interface, and per server its handshake age and bytes. Devices are only
        counted, so the number of series does not grow with engineers."""
        members = {
            row.public_key: frappe._dict(row, kind=kind)
            for doctype, kind in KINDS.items()
            for row in frappe.get_all(
                doctype, fields=["name", "label", "public_key"], filters={"public_key": ("is", "set")}
            )
        }
        peers = [members[key] for key in handshakes if key in members]
        age = {peer.public_key: self.now.timestamp() - handshakes[peer.public_key] for peer in peers}
        for kind in KINDS.values():
            of_kind = [peer for peer in peers if peer.kind == kind]
            self.add("peers", len(of_kind), kind=kind)
            self.add(
                "peers_connected",
                sum(age[peer.public_key] < CONNECTED_SECONDS for peer in of_kind),
                kind=kind,
            )
        for server in (peer for peer in peers if peer.kind == "server"):
            labels = {"server": server.name, "label": server.label}
            if handshakes[server.public_key]:
                self.add("server_handshake_age_seconds", age[server.public_key], **labels)
            received, sent = transfer.get(server.public_key, [0, 0])
            self.add("server_received_bytes_total", received, **labels)
            self.add("server_sent_bytes_total", sent, **labels)

    def add_statuses(self):
        """Servers by status, with zeros, and whether the hub applied the current revision."""
        counts = dict.fromkeys(frappe.get_meta("VPN Server").get_field("status").options.split("\n"), 0)
        for status in frappe.get_all("VPN Server", pluck="status"):
            if status in counts:
                counts[status] += 1
        for status, count in counts.items():
            self.add("servers", count, status=frappe.scrub(status))
        hub = frappe.db.get_value(
            "VPN Server", self.network.hub, ["reported_revision", "apply_success"], as_dict=True
        )
        self.add("hub_revision_lag", cint(self.network.revision) - cint(hub.reported_revision))
        self.add("hub_apply_success", cint(hub.apply_success))


def send_telemetry():
    """Scheduled. Only the hub's site, with Datum Telemetry chosen, sends."""
    network = frappe.get_doc("VPN Network")
    if frappe.conf.get("internal_vpn_interface") and network.hub and network.telemetry:
        Telemetry(network).send()
