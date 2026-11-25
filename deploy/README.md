# Host guide

Host provisioning owns `ivpn0`, its private key, address and firewall. This guide installs the agent and runs the network.

## Decide at deployment

- **Hub endpoint:** `203.0.113.10:51820` or `[2001:db8::1]:51820`. Engineers on IPv4-only networks cannot reach an IPv6-only hub.
- **Subnet:** inside `100.64.0.0/10`. It cannot change later.
- **Spokes:** which servers join, and which ports each opens on `ivpn0`. Every member can reach every spoke.

## Prerequisites

- Root, Python 3.10+, `wg`, and `nft` on the hub. Run the agent in the host's own network namespace.
- `ivpn0` with a key generated on the host and the address from registration.
- Hub only: no NAT. [Start at boot](#start-at-boot) sets forwarding, redirects and the firewall.
- HTTPS to the VPN app that does not go through the tunnel.

## Frappe Cloud

- Hub: a Frappe image server with a public IP. WireGuard does not pass through the platform's web proxy.
- Use paid plans. Free trials sleep and lock SSH, the web console and Pilot.
- If the server firewall is on, allow the hub's UDP port inbound. Spokes need no inbound rule.
- Install the app with Pilot: **Import app** from the repository, then **New site** with Internal VPN.
- Run host steps as root in the server's **Web console**. Install `wireguard-tools`, and `nftables` on the hub.

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
| `name` | VPN Server name |
| `address`, `subnet`, `public_key` | From registration |
| `interface` | `ivpn0` |
| `topology` | `hub` or `spoke` |
| `hub_public_key` | Hub key, spokes only |
| `url`, `token`, `ca_file` | App URL, the host user's `api_key:api_secret`, optional CA file |

Give each host user only the VPN Host role, which has no Desk access. Optionally set **Restrict IP** on it to the host's address.

Run the same `host.py` version as the app on every host. The timer runs the agent 15 seconds after each run. Keep `/var/lib/internal-vpn`: its revision watermark rejects stale data.

Hub only: install [internal-vpn.sudoers](internal-vpn.sudoers) as `/etc/sudoers.d/internal-vpn`, mode `0440`, with the bench user. Check it with `visudo -cf`. It lets Frappe start the updater right after a change; otherwise the timer catches up. Grant nothing else, and keep the agent files root-owned.

## Start at boot

On every host, `/etc/wireguard/ivpn0.conf`, root, mode `0600`:

```ini
[Interface]
PrivateKey = <key generated on this host>
Address = <address from registration>/<subnet prefix>
ListenPort = 51820
```

Keep `ListenPort` on the hub only. Leave out `[Peer]` sections: the agent manages peers. Enable it with `sudo systemctl enable --now wg-quick@ivpn0`.

On the hub, set the interface and subnet in [hub.nft](hub.nft), then:

```sh
printf 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.send_redirects=0\nnet.ipv4.conf.default.send_redirects=0\n' | sudo tee /etc/sysctl.d/90-internal-vpn.conf
sudo sysctl --system
sudo install -d -m 0700 /etc/internal-vpn
sudo install -m 0600 deploy/hub.nft /etc/internal-vpn/hub.nft
sudo install -m 0644 deploy/internal-vpn-firewall.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now internal-vpn-firewall.service
```

The firewall loads before `ivpn0` and the agent. It blocks hub services from members and starts closed: members reach nothing new until the agent's first run sets current rules. Loading it again resets it.

## Bring up

1. In **VPN Network**, set the subnet.
2. Create a VPN Server for the hub and set up its host. In **VPN Network**, set **Hub** and **Hub Endpoint**.
3. Create a VPN Server for each spoke and set up its host.

## Operate

| Task | Steps |
| --- | --- |
| Add an engineer | Manager: **Invite Engineer** on VPN Network. Engineer: accept the email, create a VPN Device, import the configuration it shows. Later sign-ins use the email link on the login page. |
| Disable a member | Clear **Enabled**. The hub's status in the VPN Server list turns Current once applied. |
| Watch servers | The VPN Server list shows each server Current, Pending, Failed or Stale. **VPN Server Health** notifies managers when one turns Failed or Stale, and when it recovers. Set **Stale After (Minutes)** on VPN Network. Status needs the scheduler. To stop alerts, disable the notification. |
| Revoke a user | Disable the user or remove their VPN role. |
| Free an address | Delete a disabled member after the hub has applied the change. |
| Rotate a key | Change **WireGuard Public Key**, install the new private key on `ivpn0`, update `public_key` in `host.json`. For the hub, also update `hub_public_key` on every spoke. |
| Rotate a host token | Change the user's API secret and `token` in `host.json`. |

Agent errors print a `stage` without details. Read them in the unit journal. A failed apply is retried on the next run. Stopping the timer keeps the current peers.

## Optional settings

All are off by default.

| Setting | Turn on |
| --- | --- |
| Two-factor login | System Settings > Enable Two Factor Auth |
| Backups | Schedule site backups. Keep each host's `/var/lib/internal-vpn` |

## Database recovery

1. Stop the updater on every host and pause changes. Keep VPN traffic isolated: the backup may miss revocations.
2. Note the highest revision in any host's `/var/lib/internal-vpn/revision.json`. Keep hosts without one isolated until reprovisioned.
3. Fix owners, keys and enablement in the VPN forms. Reapply missing revocations.
4. Raise the revision above that maximum in `bench --site <site> console`:

    ```python
    from internal_vpn.internal_vpn.doctype.vpn_network.vpn_network import VPNNetwork

    network = VPNNetwork.load_locked()
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
