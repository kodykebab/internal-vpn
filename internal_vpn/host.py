import argparse
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

VPN_RANGE = ipaddress.IPv4Network("100.64.0.0/10")
SNAPSHOT_FIELDS = {"version", "topology", "name", "revision", "subnet", "address", "public_key", "peers"}
PEER_FIELDS = {"public_key", "address", "endpoint", "allowed_ips"}
UNIT_FIELDS = ("LoadState", "ActiveState", "Result", "ExecMainStatus", "ExecMainExitTimestampMonotonic")
MAX_PEERS = 10000
MAX_PROBES = 8
# About 140 bytes per hub peer, so the response cap leaves room for MAX_PEERS.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class WireGuard:
    """A local WireGuard interface. The static parsers are shared with the VPN DocTypes."""

    def __init__(self, interface: str, namespace: str | None = None):
        if not isinstance(interface, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,15}", interface):
            raise ValueError("Invalid local interface")
        self.interface = interface
        self.namespace = namespace

    def execute(self, *command: str, timeout: int = 15, check: bool = True) -> subprocess.CompletedProcess:
        if self.namespace:
            command = ("ip", "netns", "exec", self.namespace, *command)
        return subprocess.run(
            command,
            check=check,
            text=True,
            capture_output=True,
            timeout=timeout,
            env=dict(os.environ, LC_ALL="C"),
        )

    def show(self, field: str) -> str:
        # Never read dump or showconf: they contain private and preshared keys.
        return self.execute("wg", "show", self.interface, field).stdout.strip()

    def set_peer(self, public_key: str, *arguments: str):
        self.execute("wg", "set", self.interface, "peer", public_key, *arguments)

    @staticmethod
    def validate_public_key(value) -> str:
        if not isinstance(value, str) or len(value) != 44:
            raise ValueError("Expected a WireGuard public key")
        raw = base64.b64decode(value, validate=True)
        if len(raw) != 32 or raw == bytes(32) or base64.b64encode(raw).decode() != value:
            raise ValueError("Invalid WireGuard public key")
        return value

    @staticmethod
    def parse_subnet(value) -> ipaddress.IPv4Network:
        network = ipaddress.IPv4Network(value)
        if not network.subnet_of(VPN_RANGE) or network.prefixlen > 29:
            raise ValueError("Choose a subnet inside 100.64.0.0/10 with room for peers")
        return network

    @staticmethod
    def parse_address(value, subnet: ipaddress.IPv4Network) -> ipaddress.IPv4Address:
        if not isinstance(value, str):
            raise ValueError("Expected an IPv4 address")
        address = ipaddress.IPv4Address(value)
        if address not in subnet or address in (subnet.network_address, subnet.broadcast_address):
            raise ValueError("Address outside the usable subnet")
        return address

    @staticmethod
    def parse_endpoint(value) -> str:
        if not isinstance(value, str):
            raise ValueError("Expected an IPv4 endpoint and UDP port")
        host, port = value.split(":")
        address = ipaddress.IPv4Address(host)
        if (
            address.is_unspecified
            or address.is_multicast
            or not port.isdecimal()
            or not 1 <= int(port) <= 65535
        ):
            raise ValueError("Invalid endpoint")
        return f"{address}:{int(port)}"

    @staticmethod
    def digest(snapshot: dict) -> str:
        """Identify desired state without the global revision, so unrelated membership changes keep it."""
        desired = {key: value for key, value in snapshot.items() if key != "revision"}
        return hashlib.sha256(json.dumps(desired, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("Control-plane redirects are not allowed")


class ControlPlane:
    """Calls this host's own VPN Peer methods over HTTPS, without proxies or redirects."""

    def __init__(self, config: dict):
        url = urlsplit(config["url"])
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
        ):
            raise ValueError("Control plane requires HTTPS")
        self.url = config["url"].rstrip("/") + "/api/method/run_doc_method"
        self.name = config["name"]
        self.token = config["token"]
        context = ssl.create_default_context(cafile=config.get("ca_file"))
        self.opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=context))

    def get_configuration(self) -> dict:
        return self._call("get_configuration")

    def report(self, revision: int, digest: str | None):
        """Report the applied digest, or None when applying failed."""
        self._call("report", {"revision": revision, "success": digest is not None, "digest": digest})

    def _call(self, method: str, args: dict | None = None):
        payload = {"dt": "VPN Peer", "dn": self.name, "method": method}
        url, body = self.url, None
        if args is None:
            url += "?" + urlencode(payload)
        else:
            body = json.dumps({**payload, "args": args}).encode()
        headers = {"Authorization": "token " + self.token, "Content-Type": "application/json"}
        with self.opener.open(Request(url, data=body, headers=headers), timeout=15) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("Response too large")
        return json.loads(raw)["message"]


class Host:
    """A VPN member host. Provisioning owns its key and interface; the control plane sends only public peers.

    This module is copied alone to each host and run as root, so it uses only the standard library."""

    def __init__(self, config: dict):
        self.config = config
        self.wireguard = WireGuard(config["interface"], config.get("namespace"))
        self.subnet = WireGuard.parse_subnet(config["subnet"])
        self.address = WireGuard.parse_address(config["address"], self.subnet)
        self.public_key = WireGuard.validate_public_key(config["public_key"])

    def update(self, state: Path) -> dict:
        """Fetch, validate, apply and report current membership. Runs are serialized per host."""
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (state / "lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            control_plane = ControlPlane(self.config)
            snapshot = control_plane.get_configuration()
            self.validate(snapshot)
            digest = WireGuard.digest(snapshot)
            self.accept_revision(state / "revision.json", snapshot["revision"], digest)
            try:
                self.apply(snapshot)
            except Exception:
                control_plane.report(snapshot["revision"], None)
                raise
            control_plane.report(snapshot["revision"], digest)
            return {"revision": snapshot["revision"], "applied": True}

    def validate(self, snapshot: dict):
        """Reject the whole snapshot before any peer changes."""
        if set(snapshot) != SNAPSHOT_FIELDS:
            raise ValueError("Unexpected configuration fields")
        if type(snapshot["version"]) is not int or snapshot["version"] != 2:
            raise ValueError("Unsupported configuration version")
        if type(snapshot["revision"]) is not int or snapshot["revision"] < 1:
            raise ValueError("Invalid revision")
        for field in ("topology", "name", "subnet", "address", "public_key"):
            if snapshot[field] != self.config[field]:
                raise ValueError("Host identity or network changed; reprovision the host")
        if snapshot["topology"] not in ("hub", "spoke"):
            raise ValueError("Unknown topology")
        peers = snapshot["peers"]
        if not isinstance(peers, list) or len(peers) > MAX_PEERS:
            raise ValueError("Invalid peer list")
        if snapshot["topology"] == "spoke" and len(peers) > 1:
            raise ValueError("A spoke may connect only to the pinned hub")

        keys, addresses = {self.public_key}, {self.address}
        for peer in peers:
            if set(peer) != PEER_FIELDS:
                raise ValueError("Unexpected peer fields")
            key = WireGuard.validate_public_key(peer["public_key"])
            address = WireGuard.parse_address(peer["address"], self.subnet)
            if key in keys or address in addresses:
                raise ValueError("Duplicate key or address")
            keys.add(key)
            addresses.add(address)
            if snapshot["topology"] == "hub":
                if peer["allowed_ips"] != f"{address}/32" or peer["endpoint"] is not None:
                    raise ValueError("Hub peers require individual addresses and learned endpoints")
            else:
                if key != self.config.get("hub_public_key") or peer["allowed_ips"] != str(self.subnet):
                    raise ValueError("Only the pinned hub may route the subnet")
                WireGuard.parse_endpoint(peer["endpoint"])

    @staticmethod
    def accept_revision(path: Path, revision: int, digest: str):
        """Persist the revision before changing peers, so a partial apply cannot accept an older snapshot."""
        if path.exists():
            previous = json.loads(path.read_text())
            if revision < previous["revision"] or (
                revision == previous["revision"] and digest != previous["digest"]
            ):
                raise ValueError("Stale or conflicting configuration")
            if revision == previous["revision"]:
                return
        descriptor, temporary = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(descriptor, "w") as file:
                json.dump({"revision": revision, "digest": digest}, file)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def apply(self, snapshot: dict):
        """Remove unwanted peers first, then set the wanted ones. The private key is never touched."""
        if self.wireguard.show("public-key") != self.public_key:
            raise ValueError("Interface public key does not match host identity")
        wanted = {peer["public_key"] for peer in snapshot["peers"]}
        for key in sorted(set(self.wireguard.show("peers").splitlines()) - wanted):
            self.wireguard.set_peer(key, "remove")
        for peer in snapshot["peers"]:
            arguments = [
                "allowed-ips",
                peer["allowed_ips"],
                "persistent-keepalive",
                "25" if peer["endpoint"] else "0",
            ]
            if peer["endpoint"]:
                arguments += ["endpoint", peer["endpoint"]]
            self.wireguard.set_peer(peer["public_key"], *arguments)

    def measure(self, probes: list[str] = (), unit: str | None = None) -> dict:
        """Read-only sample: per-peer handshake age and counters, optional VPN pings and updater result."""
        if len(probes) > MAX_PROBES:
            raise ValueError("Too many probes")
        targets = [WireGuard.parse_address(probe, self.subnet) for probe in probes]
        if self.address in targets:
            raise ValueError("Probe another VPN address")
        if self.wireguard.show("public-key") != self.public_key:
            raise ValueError("Interface identity changed")
        handshakes = self.parse_counters(self.wireguard.show("latest-handshakes"), 1)
        transfers = self.parse_counters(self.wireguard.show("transfer"), 2)
        if handshakes.keys() != transfers.keys() or self.wireguard.show("public-key") != self.public_key:
            raise ValueError("Interface membership changed during measurement")

        now = int(time.time())
        peers = [
            {
                "public_key": key,
                "last_handshake_unix": handshakes[key][0] or None,
                "handshake_age_seconds": now - handshakes[key][0] if 0 < handshakes[key][0] <= now else None,
                "rx_bytes": transfers[key][0],
                "tx_bytes": transfers[key][1],
            }
            for key in sorted(handshakes)
        ]
        return {
            "ok": True,
            "version": 1,
            "observed_at_unix": now,
            "name": self.config["name"],
            "interface": self.wireguard.interface,
            "address": str(self.address),
            "peers": peers,
            "probes": [self.ping(str(target)) for target in targets],
            "updater": self.read_unit(unit) if unit else None,
        }

    @staticmethod
    def parse_counters(raw: str, width: int) -> dict[str, list[int]]:
        rows = {}
        for line in raw.splitlines():
            fields = line.split()
            if len(fields) != width + 1:
                raise ValueError("Malformed WireGuard measurement")
            key = WireGuard.validate_public_key(fields[0])
            if key in rows or not all(value.isdecimal() for value in fields[1:]):
                raise ValueError("Invalid WireGuard measurement")
            rows[key] = [int(value) for value in fields[1:]]
        return rows

    def ping(self, address: str) -> dict:
        command = ("ping", "-n", "-c", "1", "-W", "1", "-I", self.wireguard.interface, "--", address)
        result = self.wireguard.execute(*command, timeout=3, check=False)
        # Exit 1 is a measured "no reply"; exit 2 means the probe itself failed.
        if result.returncode not in (0, 1):
            raise ValueError("Probe could not execute")
        match = re.search(r"time[=<]([0-9.]+) ms", result.stdout)
        if result.returncode == 0 and match is None:
            raise ValueError("Missing probe latency")
        return {
            "address": address,
            "reachable": result.returncode == 0,
            "rtt_ms": float(match[1]) if match else None,
        }

    @staticmethod
    def read_unit(unit: str) -> dict:
        if not re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", unit) or unit.startswith("-"):
            raise ValueError("Invalid service unit")
        output = subprocess.run(
            ["systemctl", "show", unit, "--property=" + ",".join(UNIT_FIELDS)],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
        values = dict(line.split("=", 1) for line in output.splitlines())
        if set(values) != set(UNIT_FIELDS) or values["LoadState"] != "loaded":
            raise ValueError("Service unit unavailable")
        # A unit that never ran reports Result=success, so use the exit time to tell them apart.
        exited = int(values["ExecMainExitTimestampMonotonic"]) > 0
        return {
            "unit": unit,
            "active_state": values["ActiveState"],
            "last_result": values["Result"] if exited else None,
            "last_exit_status": int(values["ExecMainStatus"]) if exited else None,
        }


def main():
    parser = argparse.ArgumentParser(description="Internal VPN host agent")
    commands = parser.add_subparsers(dest="command", required=True)
    update = commands.add_parser("update", help="apply current membership")
    update.add_argument("--state", type=Path, required=True)
    measure = commands.add_parser("measure", help="print a read-only measurement")
    measure.add_argument("--probe", action="append", default=[], metavar="VPN_IP")
    measure.add_argument("--unit", help="updater service unit to report")
    for command in (update, measure):
        command.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()

    try:
        metadata = args.config.stat()
        if os.geteuid() != 0 or metadata.st_uid != 0 or metadata.st_mode & 0o077:
            raise ValueError("Expected root and a root-only configuration")
        host = Host(json.loads(args.config.read_text()))
        result = host.update(args.state) if args.command == "update" else host.measure(args.probe, args.unit)
        print(json.dumps(result))
    except Exception:
        # Errors can contain credentials, commands or response bodies.
        print(json.dumps({"ok": False, "error": f"{args.command} failed"}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
