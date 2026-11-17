# Host guide

Host provisioning owns `ivpn0`, its private key, address and firewall. This guide installs the agent and runs the network.

## Decide at deployment

- **Hub endpoint:** `203.0.113.10:51820` or `[2001:db8::1]:51820`. Engineers on IPv4-only networks cannot reach an IPv6-only hub.
- **Subnet:** inside `100.64.0.0/10`. It cannot change later.
- **Spokes:** which servers join, and which ports each opens on `ivpn0`. Every member can reach every spoke.

## Prerequisites

- Root, Python 3.10+ and `wg`. Run the agent in the host's own network namespace.
- `ivpn0` with a key generated on the host and the address from registration.
- Hub only: IPv4 forwarding on, redirects off, no NAT, and [hub.nft](hub.nft) loaded. It blocks hub services from members.
- HTTPS to the VPN app that does not go through the tunnel.

## Install

```sh
sudo install -d -m 0755 /opt/internal-vpn
sudo install -m 0644 internal_vpn/host.py /opt/internal-vpn/
sudo install -m 0644 deploy/internal-vpn-update.service deploy/internal-vpn-update.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now internal-vpn-update.timer
```

Write `/etc/internal-vpn/host.json`, owned by root, mode `0600`:

| Field | Value |
| --- | --- |
| `name` | VPN Peer name |
| `address`, `subnet`, `public_key` | From registration |
| `interface` | `ivpn0` |
| `topology` | `hub` or `spoke` |
| `hub_public_key` | Hub key, spokes only |
| `url`, `token`, `ca_file` | App URL, the host user's `api_key:api_secret`, optional CA file |

Run the same `host.py` version as the app on every host. The timer runs the agent 15 seconds after each run. Keep `/var/lib/internal-vpn`: its revision watermark rejects stale data.

Hub only: install [internal-vpn.sudoers](internal-vpn.sudoers) as `/etc/sudoers.d/internal-vpn`, mode `0440`, with the bench user. Check it with `visudo -cf`. It lets Frappe start the updater right after a change; otherwise the timer catches up. Grant nothing else, and keep the agent files root-owned.

## Bring up

1. Initialize the subnet.
2. Register the hub service with its endpoint, set up its host, then **Set Hub**.
3. Register each spoke service and set up its host.

## Operate

| Task | Steps |
| --- | --- |
| Add an engineer | Manager: **Add Engineer**, then hand over the initial password. Engineer: log in, **Register Device**, import the configuration. |
| Disable a device | **Disable**. Status shows the hub Current once applied. |
| Revoke a user | Disable the user or remove their VPN role. |
| Free an address | **Release** a disabled peer after the hub has applied the removal. |
| Rotate a key | **Rotate Key**, install the new private key on `ivpn0`, update `public_key` in `host.json`. For the hub, also update `hub_public_key` on every spoke. |
| Rotate a host token | Change the user's API secret and `token` in `host.json`. |

Agent errors print a `stage` without details. Read them in the unit journal. A failed apply is retried on the next run. Stopping the timer keeps the current peers.

## Optional settings

All are off by default.

| Setting | Turn on |
| --- | --- |
| Email invites | `bench --site <site> set-config internal_vpn_invite_email 1`, plus outgoing email |
| Two-factor login | System Settings > Enable Two Factor Auth |
| Backups | Schedule site backups. Keep each host's `/var/lib/internal-vpn` |
| Hub alerts | `bench --site <site> set-config internal_vpn_hub_alert_minutes 10`, scheduler on. Managers get one notification per outage and one on recovery |

## Database recovery

1. Stop the updater on every host and pause changes. Keep VPN traffic isolated: the backup may miss revocations.
2. Note the highest revision in any host's `/var/lib/internal-vpn/revision.json`. Keep hosts without one isolated until reprovisioned.
3. Fix owners, keys and enablement with VPN actions. Reapply missing revocations. Do not restore released peers from Deleted Document.
4. Raise the revision above that maximum in `bench --site <site> console`:

    ```python
    network = frappe.get_doc("VPN Network", "default").lock()
    network.revision = max(network.revision, highest_observed_revision)
    network.advance_revision()
    frappe.db.commit()
    ```

5. Start the updaters, confirm fresh reports and reachability, then restore traffic. Never delete watermarks or lower revisions.

## Measure

```sh
sudo python3 /opt/internal-vpn/host.py measure --config /etc/internal-vpn/host.json --probe 100.100.64.1 --unit internal-vpn-update.service
```

Prints handshake age, byte counters, ping results and the updater's last result. It reads no private keys.
