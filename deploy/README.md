# Host operations

The host's existing provisioning owns the interface, private key, address, route and firewall. These steps install only the agent.

## Prerequisites

- Python 3.10 or later and `wg` for root.
- A dedicated `ivpn0` interface with a locally generated key and the address from `register_service`.
- On the hub: IPv4 forwarding, redirects off and [hub-forward.nft](hub-forward.nft) merged into the firewall. Do not NAT VPN traffic.
- HTTPS access to the VPN app that does not depend on the tunnel.

## Configuration

`/etc/internal-vpn/host.json`, owned by root, mode `0600`:

| Field | Value |
| --- | --- |
| `name` | `VPN Peer` name |
| `address`, `subnet`, `public_key` | Values from enrollment |
| `interface` | `ivpn0` |
| `topology` | `hub` or `spoke` |
| `hub_public_key` | Pinned hub key (spokes) |
| `url`, `token`, `ca_file` | App URL, `api_key:api_secret` of the host user, optional CA bundle |

## Install

```sh
sudo install -d -m 0755 /opt/internal-vpn
sudo install -m 0644 internal_vpn/host.py /opt/internal-vpn/
sudo install -m 0644 deploy/internal-vpn-update.service deploy/internal-vpn-update.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now internal-vpn-update.timer
```

The timer runs the agent 15 seconds after each run ends. The agent keeps its revision watermark in `/var/lib/internal-vpn`. Keep that directory: it rejects stale or conflicting snapshots. Do not delete it to clear a rejection.

## Operate

| Task | Steps |
| --- | --- |
| Enroll a device | Engineer runs `register_device` with a new public key, then configures the hub peer from `get_configuration`. |
| Enroll a service | Manager runs `register_service`, provisions `ivpn0` and `host.json`, then starts the timer. |
| Remove a member | `set_enabled(0)`, then confirm `hub_current` in `get_status`. |
| Free an address | After the removal, `release` the disabled peer. It fails until the hub has applied the removal. Frappe keeps the record in Deleted Document. |
| Rotate a key | `rotate_key`, then set the new private key and `public_key` in `host.json`. For the hub, also update `hub_public_key` on every spoke. |
| Rotate a host credential | Change the user's API secret, then update `token` in `host.json`. Membership does not change. |

A failed apply is not rolled back. The next run applies current membership. Stopping the timer does not remove peers.

## Measure

```sh
sudo python3 /opt/internal-vpn/host.py measure --config /etc/internal-vpn/host.json --probe 100.100.64.1 --unit internal-vpn-update.service
```

The output is JSON: per-peer handshake age and byte counters, optional ping results and the agent's last systemd result. It never reads private keys. A handshake or ping does not prove that an application is healthy.
