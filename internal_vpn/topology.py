"""Hub-only WireGuard peer graph and revision-independent desired-state identity."""

import hashlib
import json


def build_configuration(peer, hub, members, subnet, revision, enabled):
    is_hub = peer["name"] == hub["name"]
    if not enabled:
        peers = []
    elif is_hub:
        peers = [
            {
                "public_key": member["public_key"],
                "address": member["address"],
                "endpoint": None,
                "allowed_ips": member["address"] + "/32",
            }
            for member in sorted(members, key=lambda member: member["name"])
            if member["name"] != peer["name"]
        ]
    else:
        peers = [
            {
                "public_key": hub["public_key"],
                "address": hub["address"],
                "endpoint": hub["endpoint"],
                "allowed_ips": subnet,
            }
        ]
    return {
        "version": 2,
        "topology": "hub" if is_hub else "spoke",
        "name": peer["name"],
        "revision": revision,
        "subnet": subnet,
        "address": peer["address"],
        "public_key": peer["public_key"],
        "peers": peers,
    }


def desired_digest(snapshot):
    desired = {key: value for key, value in snapshot.items() if key != "revision"}
    return hashlib.sha256(json.dumps(desired, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
