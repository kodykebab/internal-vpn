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
SNAPSHOT_FIELDS = {
    "version",
    "topology",
    "name",
    "revision",
    "subnet",
    "address",
    "public_key",
    "peers",
    "access",
}
PEER_FIELDS = {"public_key", "address", "endpoint", "allowed_ips"}
ACCESS_FIELDS = {"restricted", "services", "rules"}
RULE_FIELDS = {"source", "destination", "ports"}
ACCESS_TABLE = "inet internal_vpn_access"
# Absolute paths, so a hub sudoers rule can name the exact commands.
WG, NFT, SUDO = "/usr/bin/wg", "/usr/sbin/nft", "/usr/bin/sudo"
UNIT_FIELDS = ("LoadState", "ActiveState", "Result", "ExecMainStatus", "ExecMainExitTimestampMonotonic")
MAX_PEERS = 10000
# Paths a spoke uses; enrollment writes them.
WIREGUARD_DIR = Path("/etc/wireguard")
CONFIG_DIR = Path("/etc/internal-vpn")
AGENT_DIR = Path("/opt/internal-vpn")
UNIT_DIR = Path("/etc/systemd/system")
UPDATE_SERVICE = """[Unit]
Description=Apply current internal VPN membership
After=network-online.target wg-quick@ivpn0.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/internal-vpn/host.py update --config /etc/internal-vpn/host.json --state /var/lib/internal-vpn
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
StateDirectory=internal-vpn
StateDirectoryMode=0700
PrivateTmp=true
CapabilityBoundingSet=CAP_NET_ADMIN
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
PrivateDevices=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
"""
UPDATE_TIMER = """[Unit]
Description=Refresh internal VPN membership

[Timer]
OnBootSec=10s
OnUnitInactiveSec=15s
AccuracySec=1s
Unit=internal-vpn-update.service

[Install]
WantedBy=timers.target
"""
MAX_PROBES = 8
# About 140 bytes per hub peer, so the response cap leaves room for MAX_PEERS.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class WireGuard:
    """A local WireGuard interface. The static parsers are shared with the VPN DocTypes."""

    def __init__(self, interface: str, sudo: bool = False):
        if not isinstance(interface, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,15}", interface):
            raise ValueError("Invalid local interface")
        self.interface = interface
        self.prefix = (SUDO, "-n") if sudo else ()

    def execute(
        self, *command: str, timeout: int = 15, check: bool = True, input: str | None = None
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [*self.prefix, *command],
            input=input,
            check=check,
            text=True,
            capture_output=True,
            timeout=timeout,
            env=dict(os.environ, LC_ALL="C"),
        )

    def show(self, field: str) -> str:
        # Never read dump or showconf: they contain private and preshared keys.
        return self.execute(WG, "show", self.interface, field).stdout.strip()

    def peers(self) -> dict[str, tuple[str, str | None, str]]:
        """Live allowed IPs, endpoint and keepalive per peer."""
        fields = [
            dict(line.split("\t", 1) for line in self.show(field).splitlines())
            for field in ("allowed-ips", "endpoints", "persistent-keepalive")
        ]
        return {
            key: (allowed, None if fields[1][key] == "(none)" else fields[1][key], fields[2][key])
            for key, allowed in fields[0].items()
        }

    def handshakes(self) -> dict[str, int]:
        """Unix time of each peer's latest handshake; 0 when there has been none."""
        return {
            key: int(seconds)
            for key, seconds in (line.split("\t", 1) for line in self.show("latest-handshakes").splitlines())
        }

    def set_peer(self, public_key: str, *arguments: str):
        self.execute(WG, "set", self.interface, "peer", public_key, *arguments)

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
            raise TypeError("Expected an IPv4 address")
        address = ipaddress.IPv4Address(value)
        if address not in subnet or address in (subnet.network_address, subnet.broadcast_address):
            raise ValueError("Address outside the usable subnet")
        return address

    @staticmethod
    def parse_endpoint(value) -> str:
        """`ipv4:port` or `[ipv6]:port`, normalized as `wg show` prints it."""
        if not isinstance(value, str):
            raise TypeError("Expected an IP endpoint and UDP port")
        host, _, port = value.rpartition(":")
        if host.startswith("[") and host.endswith("]"):
            address = ipaddress.IPv6Address(host[1:-1])
        else:
            address = ipaddress.IPv4Address(host)
        if (
            address.is_unspecified
            or address.is_multicast
            or address.is_link_local
            or not port.isdecimal()
            or not 1 <= int(port) <= 65535
        ):
            raise ValueError("Invalid endpoint")
        return f"[{address}]:{int(port)}" if address.version == 6 else f"{address}:{int(port)}"

    @staticmethod
    def parse_ports(value) -> str:
        """`""` for all ports, else merged ports and ranges such as `22,443,8000-8005`."""
        if not isinstance(value, str):
            raise TypeError("Expected ports")
        ranges = []
        for part in [part.strip() for part in value.split(",") if part.strip()]:
            low, _, high = part.partition("-")
            if not low.isdecimal() or (high and not high.isdecimal()):
                raise ValueError("Invalid ports")
            low, high = int(low), int(high or low)
            if not 1 <= low <= high <= 65535:
                raise ValueError("Invalid ports")
            ranges.append((low, high))
        merged = []
        for low, high in sorted(ranges):
            if merged and low <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], high)
            else:
                merged.append([low, high])
        return ",".join(f"{low}-{high}" if high > low else str(low) for low, high in merged)

    @staticmethod
    def agent_digest() -> str:
        """SHA-256 of this file. The app compares it with its own copy to find outdated agents."""
        return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    @staticmethod
    def digest(snapshot: dict) -> str:
        """Identify desired state without the global revision, so unrelated membership changes keep it."""
        desired = {key: value for key, value in snapshot.items() if key != "revision"}
        return hashlib.sha256(json.dumps(desired, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("Control-plane redirects are not allowed")


class ControlPlane:
    """Calls this host's own VPN Server methods over HTTPS, without proxies or redirects."""

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
        return self._call("get_configuration", {})

    def report(self, revision: int, digest: str | None):
        """Report the applied digest, or None when applying failed."""
        args = {"revision": revision, "success": digest is not None, "digest": digest}
        self._call("report", {**args, "agent": WireGuard.agent_digest()})

    def enroll(self, public_key: str) -> dict:
        return self._call("enroll", {"public_key": public_key})

    def fetch_agent(self) -> bytes:
        """This app's host.py, refused unless it is Python."""
        query = urlencode({"dt": "VPN Server", "dn": self.name, "method": "agent"})
        request = Request(f"{self.url}?{query}", headers={"Authorization": "token " + self.token})
        with self.opener.open(request, timeout=15) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("Response too large")
        compile(raw, "host.py", "exec")
        return raw

    def _call(self, method: str, args: dict):
        body = json.dumps({"dt": "VPN Server", "dn": self.name, "method": method, "args": args}).encode()
        headers = {"Authorization": "token " + self.token, "Content-Type": "application/json"}
        with self.opener.open(Request(self.url, data=body, headers=headers), timeout=15) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("Response too large")
        return json.loads(raw)["message"]


class Host:
    """Apply public peers; provisioning owns the interface and private key."""

    def __init__(self, config: dict, sudo: bool = False):
        self.config = config
        self.stage = "configuration"
        if config.get("namespace"):
            raise ValueError("Run the agent in its host network namespace")
        self.wireguard = WireGuard(config["interface"], sudo)
        self.subnet = WireGuard.parse_subnet(config["subnet"])
        self.address = WireGuard.parse_address(config["address"], self.subnet)
        self.public_key = WireGuard.validate_public_key(config["public_key"])

    def update(self, state: Path) -> dict:
        """Fetch membership from the control plane, then converge."""
        control_plane = ControlPlane(self.config)
        return self.converge(state, control_plane.get_configuration, control_plane.report)

    def converge(self, state: Path, fetch, report) -> dict:
        """Fetch, validate, apply and report current membership. Runs are serialized per host.
        `report(revision, digest)` gets None as the digest when applying failed."""
        self.stage = "state"
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (state / "lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.stage = "fetch"
            snapshot = fetch()
            self.stage = "validation"
            self.validate(snapshot)
            digest = WireGuard.digest(snapshot)
            self.stage = "state"
            self.accept_revision(state / "revision.json", snapshot["revision"], digest)
            self.stage = "apply"
            try:
                self.apply(snapshot)
            except Exception:
                report(snapshot["revision"], None)
                raise
            self.stage = "report"
            report(snapshot["revision"], digest)
            return {"revision": snapshot["revision"], "applied": True}

    def validate(self, snapshot: dict):
        """Reject the whole snapshot before any peer changes."""
        if set(snapshot) != SNAPSHOT_FIELDS:
            raise ValueError("Unexpected configuration fields")
        if type(snapshot["version"]) is not int or snapshot["version"] != 3:
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
        self.validate_access(snapshot)

    def validate_access(self, snapshot: dict):
        """The hub always gets rules and spokes none; every address and port list must be well formed."""
        access = snapshot["access"]
        if snapshot["topology"] == "spoke":
            if access is not None:
                raise ValueError("Invalid access rules")
            return
        if (
            not isinstance(access, dict)
            or set(access) != ACCESS_FIELDS
            or type(access["restricted"]) is not bool
            or not isinstance(access["services"], list)
            or not isinstance(access["rules"], list)
            or (access["rules"] and not access["restricted"])
        ):
            raise ValueError("Invalid access rules")
        for address in access["services"]:
            WireGuard.parse_address(address, self.subnet)
        for rule in access["rules"]:
            if not isinstance(rule, dict) or set(rule) != RULE_FIELDS:
                raise ValueError("Invalid access rules")
            WireGuard.parse_address(rule["source"], self.subnet)
            WireGuard.parse_address(rule["destination"], self.subnet)
            if WireGuard.parse_ports(rule["ports"]) != rule["ports"]:
                raise ValueError("Invalid access rules")

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
        """Remove unwanted peers first, then set changed ones. The private key is never touched."""
        if self.wireguard.show("public-key") != self.public_key:
            raise ValueError("Interface public key does not match host identity")
        live = self.wireguard.peers()
        wanted = {peer["public_key"] for peer in snapshot["peers"]}
        for key in sorted(set(live) - wanted):
            self.wireguard.set_peer(key, "remove")
        for peer in snapshot["peers"]:
            key, endpoint = peer["public_key"], peer["endpoint"]
            current = live.get(key)
            # Hub peers have learned endpoints, so only a pinned endpoint is compared.
            if current and current == (
                peer["allowed_ips"],
                endpoint or current[1],
                "25" if endpoint else "off",
            ):
                continue
            arguments = [
                "allowed-ips",
                peer["allowed_ips"],
                "persistent-keepalive",
                "25" if endpoint else "0",
            ]
            if endpoint:
                arguments += ["endpoint", endpoint]
            self.wireguard.set_peer(key, *arguments)
        if snapshot["topology"] == "hub":
            self.apply_access(snapshot["access"])

    def apply_access(self, access: dict):
        """Replace the hub's member-to-member rules in one nft transaction. Servers reach each other,
        devices reach servers (only granted ones when restricted), and nothing opens a device."""
        link = f'iifname "{self.wireguard.interface}" oifname "{self.wireguard.interface}"'
        rules = [f"{link} ct state established,related accept"]
        if access["services"]:
            services = f"{{ {', '.join(access['services'])} }}"
            rules.append(f"{link} ip saddr {services} ip daddr {services} accept")
            if not access["restricted"]:
                rules.append(f"{link} ip daddr {services} accept")
        for rule in access["rules"]:
            match = f"{link} ip saddr {rule['source']} ip daddr {rule['destination']}"
            if rule["ports"]:
                ports = rule["ports"].replace(",", ", ")
                rules += [
                    f"{match} tcp dport {{ {ports} }} accept",
                    f"{match} udp dport {{ {ports} }} accept",
                    f"{match} icmp type echo-request accept",
                ]
            else:
                rules.append(f"{match} accept")
        rules.append(f"{link} counter drop")
        body = "".join(f"\t\t{rule}\n" for rule in rules)
        self.wireguard.execute(
            NFT,
            "-f",
            "-",
            input=f"table {ACCESS_TABLE}\ndelete table {ACCESS_TABLE}\n"
            f"table {ACCESS_TABLE} {{\n\tchain forward {{\n"
            f"\t\ttype filter hook forward priority 10; policy accept;\n{body}\t}}\n}}\n",
        )

    def measure(self, probes: list[str] = (), unit: str | None = None) -> dict:
        """Read-only sample: per-peer handshake age and counters, optional VPN pings and updater result."""
        self.stage = "measurement"
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


class Spoke:
    """Enrollment and upgrade of a spoke. Keys are made on the host; only the public key is sent."""

    def __init__(self, interface: str = "ivpn0"):
        self.wireguard = WireGuard(interface)
        self.stage = "preflight"

    def enroll(self, url: str, name: str, token: str, ca_file: str | None = None) -> dict:
        interface = self.wireguard.interface
        tunnel, config = WIREGUARD_DIR / f"{interface}.conf", CONFIG_DIR / "host.json"
        if tunnel.exists() or config.exists():
            raise ValueError("This host is already enrolled")
        control_plane = ControlPlane({"url": url, "name": name, "token": token, "ca_file": ca_file})
        self.stage = "keys"
        private_key = self.wireguard.execute(WG, "genkey").stdout.strip()
        public_key = self.wireguard.execute(WG, "pubkey", input=private_key + "\n").stdout.strip()
        self.stage = "enroll"
        result = control_plane.enroll(public_key)
        subnet = WireGuard.parse_subnet(result["subnet"])
        address = WireGuard.parse_address(result["address"], subnet)
        self.stage = "files"
        CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.write(
            tunnel,
            f"[Interface]\nPrivateKey = {private_key}\nAddress = {address}/{subnet.prefixlen}\n",
            0o600,
        )
        host = {
            "name": name,
            "subnet": str(subnet),
            "address": str(address),
            "public_key": public_key,
            "interface": interface,
            "topology": "spoke",
            "hub_public_key": WireGuard.validate_public_key(result["hub_public_key"]),
            "url": url,
            "token": result["token"],
        }
        if ca_file:
            host["ca_file"] = ca_file
        self.write(config, json.dumps(host, indent=2) + "\n", 0o600)
        self.write(AGENT_DIR / "host.py", Path(__file__).read_text(), 0o644)
        self.write(UNIT_DIR / "internal-vpn-update.service", UPDATE_SERVICE, 0o644)
        self.write(UNIT_DIR / "internal-vpn-update.timer", UPDATE_TIMER, 0o644)
        self.stage = "start"
        for command in (
            ("daemon-reload",),
            ("enable", "--now", f"wg-quick@{interface}"),
            ("enable", "--now", "internal-vpn-update.timer"),
        ):
            self.wireguard.execute("/usr/bin/systemctl", *command, timeout=60)
        return {"name": name, "address": str(address), "enrolled": True}

    def upgrade(self, config: dict) -> dict:
        self.stage = "fetch"
        raw = ControlPlane(config).fetch_agent()
        self.stage = "install"
        target = AGENT_DIR / "host.py"
        before = hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None
        self.write(target, raw.decode(), 0o644)
        after = hashlib.sha256(raw).hexdigest()
        return {"agent": after, "changed": before != after}

    @staticmethod
    def write(path: Path, text: str, mode: int):
        """Replace a file atomically, root-owned with `mode` from the start."""
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(dir=path.parent)
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "w") as file:
                file.write(text)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description="Internal VPN host agent")
    commands = parser.add_subparsers(dest="command", required=True)
    update = commands.add_parser("update", help="apply current membership")
    update.add_argument("--state", type=Path, required=True)
    measure = commands.add_parser("measure", help="print a read-only measurement")
    measure.add_argument("--probe", action="append", default=[], metavar="VPN_IP")
    measure.add_argument("--unit", help="updater service unit to report")
    upgrade = commands.add_parser("upgrade", help="install this app's current agent")
    for command in (update, measure, upgrade):
        command.add_argument("--config", type=Path, required=True)
    enroll = commands.add_parser("enroll", help="join the network as a spoke")
    enroll.add_argument("--url", required=True)
    enroll.add_argument("--server", required=True)
    enroll.add_argument("--token", required=True)
    enroll.add_argument("--ca-file")
    args = parser.parse_args()

    worker = None
    try:
        if os.geteuid() != 0:
            raise ValueError("Expected root")
        if args.command == "enroll":
            worker = Spoke()
            result = worker.enroll(args.url, args.server, args.token, args.ca_file)
        else:
            metadata = args.config.stat()
            if metadata.st_uid != 0 or metadata.st_mode & 0o077:
                raise ValueError("Expected a root-only configuration")
            config = json.loads(args.config.read_text())
            if args.command == "upgrade":
                worker = Spoke(config["interface"])
                result = worker.upgrade(config)
            else:
                worker = Host(config)
                result = (
                    worker.update(args.state)
                    if args.command == "update"
                    else worker.measure(args.probe, args.unit)
                )
        print(json.dumps(result))
    except Exception:  # noqa: BLE001 - never expose credentials from command or HTTP errors
        stage = worker.stage if worker is not None else "configuration"
        print(json.dumps({"ok": False, "error": f"{args.command} failed", "stage": stage}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
