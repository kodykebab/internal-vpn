"""Root-owned, one-shot peer updater. Private keys and interface setup stay local."""

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from internal_vpn import validation


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("Control-plane redirects are not allowed")


def validate_snapshot(data, local):
    if set(data) != {"version", "name", "revision", "subnet", "address", "public_key", "peers"}:
        raise ValueError("Unexpected configuration fields")
    if type(data["version"]) is not int or data["version"] != 1 or type(data["revision"]) is not int or data["revision"] < 1:
        raise ValueError("Invalid configuration version")
    for field in ("name", "subnet", "address", "public_key"):
        if data[field] != local[field]:
            raise ValueError("Host identity or network changed; local reprovisioning required")
    network = validation.subnet(data["subnet"])
    validation.public_key(data["public_key"])
    own = ipaddress.IPv4Address(data["address"])
    if own not in network or own in (network.network_address, network.broadcast_address):
        raise ValueError("Invalid local address")
    if not isinstance(data["peers"], list) or len(data["peers"]) > 10000:
        raise ValueError("Invalid peer list")
    keys, addresses = {data["public_key"]}, {data["address"]}
    for peer in data["peers"]:
        if set(peer) != {"public_key", "address", "endpoint"}:
            raise ValueError("Unexpected peer fields")
        key = validation.public_key(peer["public_key"])
        if not isinstance(peer["address"], str):
            raise ValueError("Peer address must be a string")
        address = ipaddress.IPv4Address(peer["address"])
        if address not in network or address in (network.network_address, network.broadcast_address):
            raise ValueError("Peer address outside usable subnet")
        if key in keys or str(address) in addresses:
            raise ValueError("Duplicate key or address")
        keys.add(key)
        addresses.add(str(address))
        if peer["endpoint"] is not None:
            validation.endpoint(peer["endpoint"])
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def accept_revision(path, revision, digest):
    if path.exists():
        previous = json.loads(path.read_text())
        if revision < previous["revision"] or (revision == previous["revision"] and digest != previous["digest"]):
            raise ValueError("Stale or conflicting configuration")
        if revision == previous["revision"]:
            return
    # Persist the highest accepted revision BEFORE any changes, including partial failures.
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w") as file:
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


def wg(local, *args):
    command = ["wg", *args]
    if local.get("namespace"):
        command = ["ip", "netns", "exec", local["namespace"], *command]
    return subprocess.run(command, check=True, text=True, capture_output=True, timeout=15).stdout.strip()


def apply(data, local):
    interface = local["interface"]
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,15}", interface):
        raise ValueError("Invalid local interface")
    if wg(local, "show", interface, "public-key") != local["public_key"]:
        raise ValueError("Interface public key does not match host identity")
    wanted = {p["public_key"] for p in data["peers"]}
    existing = set(wg(local, "show", interface, "peers").splitlines())
    for key in sorted(existing - wanted):
        wg(local, "set", interface, "peer", key, "remove")
    for peer in data["peers"]:
        arguments = ["set", interface, "peer", peer["public_key"], "allowed-ips", peer["address"] + "/32",
                     "persistent-keepalive", "25" if peer["endpoint"] else "0"]
        if peer["endpoint"]:
            arguments += ["endpoint", peer["endpoint"]]
        wg(local, *arguments)


class Controller:
    def __init__(self, local):
        self.local = local
        url = urlsplit(local["url"])
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("Control plane requires HTTPS")
        context = ssl.create_default_context(cafile=local.get("ca_file"))
        self.opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=context))

    def request(self, method, data, post=False):
        url = self.local["url"].rstrip("/") + "/api/method/internal_vpn.api." + method
        body = json.dumps(data).encode() if post else None
        if not post:
            url += "?" + urlencode(data)
        request = Request(url, data=body, headers={"Authorization": "token " + self.local["token"],
                                                  "Content-Type": "application/json"})
        with self.opener.open(request, timeout=15) as response:
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError("Response too large")
            return json.loads(raw)["message"]


def reconcile(local, state):
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (state / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        controller = Controller(local)
        data = controller.request("configuration", {"name": local["name"]})
        digest = validate_snapshot(data, local)
        accept_revision(state / "revision.json", data["revision"], digest)
        try:
            apply(data, local)
        except Exception:
            controller.request("report", {"name": local["name"], "revision": data["revision"], "success": False}, True)
            raise
        controller.request("report", {"name": local["name"], "revision": data["revision"], "success": True}, True)
        return {"revision": data["revision"], "applied": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Updater must run as root")
    metadata = args.config.stat()
    if metadata.st_uid != 0 or metadata.st_mode & 0o077:
        parser.error("Configuration must be root-owned and mode 0600")
    try:
        print(json.dumps(reconcile(json.loads(args.config.read_text()), args.state)))
    except Exception:
        # HTTP and subprocess exceptions can contain credentials or response bodies.
        print(json.dumps({"ok": False, "error": "Configuration fetch, validation, apply, or report failed"}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
