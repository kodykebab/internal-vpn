# Host operations

The host's existing provisioning owns the interface, private key, address, route and firewall. These steps install only the agent.

## Prerequisites

- Python 3.10 or later and `wg` for root.
- A dedicated `ivpn0` interface with a locally generated key and the address from `register_service`.
- Run the agent in the host network namespace.
- On the hub: IPv4 forwarding, redirects off and [hub-forward.nft](hub-forward.nft) merged into the firewall. Do not NAT VPN traffic.
- HTTPS access to the VPN app that does not depend on the tunnel.

For a dedicated 4-vCPU/8-GiB hub bench limited to four Gunicorn workers, raise the count to six with `bench config set-common-config -c gunicorn_workers 6`. Keep Nginx in front and regenerate and apply the existing Supervisor or systemd configuration. Check CPU and memory under concurrent polling and hub updates; more workers do not increase CPU capacity.

## Configuration

`/etc/internal-vpn/host.json`, owned by root, mode `0600`:

| Field | Value |
| --- | --- |
| `name` | `VPN Peer` name |
| `address`, `subnet`, `public_key` | Allocated peer address, network subnet and locally generated public key |
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

On the hub, install [internal-vpn.sudoers](internal-vpn.sudoers) as `/etc/sudoers.d/internal-vpn` with mode `0440`, replacing `frappe` with the bench OS user. Validate it with `visudo -cf` before installation. Keep the unit, `/opt/internal-vpn`, its script and `/etc/internal-vpn` owned by root and unwritable by the bench user. Do not grant sudo access to Python or arbitrary `wg` commands.

Frappe starts the hub updater after membership commits using `sudo -n /usr/bin/systemctl start --no-block internal-vpn-update.service`. A failed start goes to `logs/internal_vpn.log`; the timer retries current membership. Provision the hub and its dedicated host credential before selecting it in Desk.

## Operate

| Task | Steps |
| --- | --- |
| Enroll a device | Administrator invites the engineer with `VPN Engineer`. Manager registers their public key, or the approved engineer registers it after login. The engineer copies Configuration in Desk. |
| Enroll a service | Manager runs `register_service`, provisions `ivpn0` and `host.json`, then starts the timer. |
| Disable a device | `set_enabled(0)`, then confirm `hub_current` in `get_status`. An eligible engineer can re-enable their device or register another. |
| Revoke a user | Disable the User, or remove their `VPN Engineer` / `VPN Host` role, then confirm `hub_current`. The hub account must remain eligible. |
| Free an address | After the removal, `release` the disabled peer. It fails until the hub has applied the removal. Frappe keeps the record in Deleted Document. |
| Rotate a key | `rotate_key`, then set the new private key and `public_key` in `host.json`. For the hub, also update `hub_public_key` on every spoke. |
| Rotate a host credential | Change the user's API secret, then update `token` in `host.json`. Membership does not change. |

Agent errors include a safe `stage` (configuration, state, fetch, validation, apply, report or measurement); exception details and credentials are omitted. Check the JSON in the unit journal.

A failed apply is not rolled back. The next run applies current membership. Stopping the timer does not remove peers.

## Database recovery

1. Stop and runtime-mask the updater service and timer on every host and pause membership changes. Isolate VPN traffic while reconciling the restored database; its membership may predate revocations.
2. Keep each host's `/var/lib/internal-vpn/revision.json`. Record the highest revision across all hosts and the restored network. If any watermark is unavailable, keep that host isolated until it is explicitly reprovisioned.
3. Reconcile owners, keys, enablement and released addresses against Frappe's Version history and your incident records. Use VPN actions; do not restore released peers through Deleted Document. Reapply any revocations missing from the backup.
4. Unmask the hub updater. In `bench --site <site> console`, set the network revision above the recorded maximum using the existing controller, then commit:

```python
network = frappe.get_doc("VPN Network", "default").lock()
network.revision = max(network.revision, highest_observed_revision)
network.advance_revision()
frappe.db.commit()
```

The commit wakes the hub updater. After reconciliation, unmask and run the updater on each host, confirm fresh successful reports and test VPN reachability before restoring traffic and timers. Do not erase watermarks or lower revisions. Reprovision identity changes explicitly.

## Measure

```sh
sudo python3 /opt/internal-vpn/host.py measure --config /etc/internal-vpn/host.json --probe 100.100.64.1 --unit internal-vpn-update.service
```

The output is JSON: per-peer handshake age and byte counters, optional ping results and the agent's last systemd result. It never reads private keys. A handshake or ping does not prove that an application is healthy.
