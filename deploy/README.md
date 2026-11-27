# Host guide

Host provisioning owns `ivpn0`, its private key, address and firewall. This guide installs the agent and runs the network.

## Decide at deployment

- **Hub endpoint:** `203.0.113.10:51820` or `[2001:db8::1]:51820`. Engineers on IPv4-only networks cannot reach an IPv6-only hub.
- **Subnet:** inside `100.64.0.0/10`. It cannot change later.
- **Spokes:** which servers join, and which ports each opens on `ivpn0`. Every member can reach every spoke.

## Prerequisites

- Root, Python 3.10+ and `wg` on spokes; `wg`, `nft` and the bench on the hub. Run everything in the host's own network namespace.
- `ivpn0` with a key generated on the host and the address from registration.
- Hub only: no NAT. [Start at boot](#start-at-boot) sets forwarding, redirects and the firewall.
- Spokes: HTTPS to the VPN app that does not go through the tunnel.

## Frappe Cloud

- Hub: a Frappe image server with a public IP. WireGuard does not pass through the platform's web proxy.
- Use paid plans. Free trials sleep and lock SSH, the web console and Pilot.
- If the server firewall is on, allow the hub's UDP port inbound. Spokes need no inbound rule.
- Install the app with Pilot: **Import app** from the repository, then **New site** with Internal VPN.
- Run host steps as root in the server's **Web console**. Install `wireguard-tools`, and `nftables` on the hub.

## Install on the hub

The app applies membership to the hub itself. A job runs right after each change and once a minute.

```sh
sudo install -d -m 0700 -o frappe -g frappe /var/lib/internal-vpn
sudo install -m 0440 deploy/internal-vpn.sudoers /etc/sudoers.d/internal-vpn
sudo visudo -cf /etc/sudoers.d/internal-vpn
bench --site <site> set-config internal_vpn_interface ivpn0
```

Replace `frappe` with the bench user, in both places. The sudoers rule lets that user read and set `ivpn0` peers and replace nftables rules, and nothing else. Keep the bench's scheduler and a worker for the `short` queue running. Keep `/var/lib/internal-vpn`: its revision watermark rejects stale data. Set `internal_vpn_state_dir` to use another folder.

## Install on spokes

1. Create a VPN Server with a name. The app creates its host user (VPN Host only, no Desk access) and an API key, and shows an enrollment command on the form for 30 minutes.
2. Run that command as root on the spoke, or put it in the server's cloud-init user data. It downloads this app's `host.py` with the server's token, makes the WireGuard keys on the host, and enrolls with the public key only.
3. Enrollment writes `/etc/wireguard/ivpn0.conf` and `/etc/internal-vpn/host.json` (root only), installs the agent in `/opt/internal-vpn` with its systemd timer, and brings `ivpn0` up. It replaces the token, so the command works once.

The timer runs the agent 15 seconds after each run. Keep `/var/lib/internal-vpn`, as on the hub. If the window closes or the host is rebuilt, use **New Enrollment** on the form. Optionally set **Restrict IP** on the host user to the host's address. A host that is not on systemd or has no `curl` can still run the same steps by hand.

## Start at boot

Enrollment writes this file on spokes. On the hub, write `/etc/wireguard/ivpn0.conf` yourself, root, mode `0600`:

```ini
[Interface]
PrivateKey = <key generated on this host>
Address = <address from registration>/<subnet prefix>
ListenPort = 51820
```

Leave out `[Peer]` sections: the app manages them. Enable it with `sudo systemctl enable --now wg-quick@ivpn0`.

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

The firewall loads before `ivpn0`. It blocks hub services from members and starts closed: members reach nothing new until the hub job's first run sets current rules. Loading it again resets it.

## Bring up

1. In **VPN Network**, keep the default subnet `100.100.0.0/20` (4,094 members) or set another inside `100.64.0.0/10`. It is fixed once servers or devices exist.
2. Create a VPN Server for the hub and paste its public key. Set up its host as above. In **VPN Network**, set **Hub** and **Hub Endpoint**.
3. Create a VPN Server for each spoke and run its enrollment command on the spoke.

## Operate

| Task | Steps |
| --- | --- |
| Add an engineer | Manager: **Invite Engineer** on VPN Network. Engineer: accept the email, create a VPN Device, import the configuration it shows. Later sign-ins use the email link on the login page. |
| Disable a member | Clear **Enabled**. The hub's status in the VPN Server list turns Current once applied. |
| Watch connections | The VPN Device list shows each device Connected, Seen some time ago, or Never connected, from the hub's latest WireGuard handshake. Servers show **Last Handshake** too. Never connected while the hub is Current points at the device's network. |
| Watch servers | The VPN Server list shows each server Current, Pending, Failed, Stale or Never Reported (its host is not set up yet). **VPN Server Health** notifies managers when one turns Failed or Stale, and when it recovers. Set **Stale After (Minutes)** on VPN Network. Status needs the scheduler. To stop alerts, disable the notification. |
| Limit access | Create a VPN Access record per engineer and server, with ports if needed. Then turn on **Access Control** on VPN Network. Until then, every device reaches every server. |
| Revoke a user | Disable the user or remove their VPN role. |
| Free an address | Delete a disabled member after the hub has applied the change. |
| Rotate a key | For a device, **New Configuration**. For a spoke, **New Enrollment**, then run the new command on it. For the hub, change **WireGuard Public Key**, install the new private key on `ivpn0`, and update `hub_public_key` on every spoke. |
| Upgrade a spoke's agent | When the VPN Server list shows **Outdated Agent**, run `sudo python3 /opt/internal-vpn/host.py upgrade --config /etc/internal-vpn/host.json` on that spoke. The timer's next run uses the new agent. |
| Rotate a host token | Change the user's API secret and `token` in `host.json`. |

Agent errors print a `stage` without details. Read them in the unit journal. A failed apply is retried on the next run. Stopping the timer keeps the current peers.

## VPN-only Desk

Staff then use this site only over the VPN, at `http://<hub VPN address>`. Host users, customers of other sites and an engineer's first device are not affected.

1. Fill in [internal-vpn-desk.conf](internal-vpn-desk.conf) and install it as `/etc/nginx/conf.d/internal-vpn-desk.conf`. Run `sudo nginx -t`, then `sudo systemctl reload nginx`. Pilot leaves this file alone. Because Pilot already listens on port 80 for every address, nginx still starts while `ivpn0` is down.
2. The hub firewall from [Start at boot](#start-at-boot) lets VPN members reach it on port 80 and nothing else.
3. Open `http://<hub VPN address>` from a device on the VPN and sign in. Then set **VPN-Only Desk** on VPN Network.

The app decides "over the VPN" from `X-Real-IP`, which only nginx sets: Pilot from the address it verified, and this file from the WireGuard peer. A forged `X-Forwarded-For` does not count. Administrator, managers and other staff are limited at once. An engineer is limited when their first device is older than **Onboarding Window (Minutes)**, so they can copy its configuration from outside the VPN until then. Sign-in links opened outside the VPN send staff to the VPN address before the link is used. Realtime updates do not run over the VPN address.

If the VPN is down, run `ssh -L 8080:<hub VPN address>:80 <hub>` and open `http://localhost:8080`. If `ivpn0` itself is down, clear the switch in `bench --site <site> console` on the hub:

```python
network = frappe.get_doc("VPN Network")
network.vpn_only_desk = 0
network.save()
frappe.db.commit()
```

## Optional settings

All are off by default.

| Setting | Turn on |
| --- | --- |
| Two-factor login | System Settings > Enable Two Factor Auth |
| Backups | Schedule site backups. Keep each host's `/var/lib/internal-vpn` |
| Datum telemetry | VPN Network > **Datum Telemetry**. **Pilot** uses this server's Pilot credential and honors its `[telemetry] enabled`. **Site Config** uses `internal_vpn_datum_endpoint` and `internal_vpn_datum_token`; renew the token before it expires. The hub sends `internal_vpn_*` every 5 minutes: peers and connected peers by kind, servers by status, hub revision lag and apply result, and per server its handshake age and bytes. Needs the `transfer` line of the sudoers rule |

## Database recovery

1. Stop the updater timer on every spoke. On the hub, run `bench --site <site> set-config internal_vpn_interface ""`. Pause changes. Keep VPN traffic isolated: the backup may miss revocations.
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

5. Set `internal_vpn_interface` back on the hub and start the spoke timers. Confirm every server is Current and reachable, then restore traffic. Never delete watermarks or lower revisions.

## Measure

```sh
sudo python3 /opt/internal-vpn/host.py measure --config /etc/internal-vpn/host.json --probe 100.100.64.1 --unit internal-vpn-update.service
```

Run it on a spoke. It prints handshake age, byte counters, ping results and the updater's last result, and reads no private keys.
