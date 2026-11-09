# Host installation and operation

Use the host's existing provisioning owner for the interface, keys, routes and firewall. These steps install only the constrained updater. The management Frappe process remains non-root. Do not run these example installation commands on an existing host until its dedicated interface and allocation are selected.

## Prerequisites

- Python 3 and `wg` available to root.
- A dedicated `ivpn0` interface with a locally generated private key, the enrolled public key/address, and an allocated-subnet route. Keep private keys and interface setup outside the management API.
- On the hub: IPv4 forwarding, redirects disabled and the allocated-subnet forwarding policy in [hub-forward.nft](hub-forward.nft), integrated with the existing firewall. Do not apply SNAT to VPN traffic. This policy does not isolate application INPUT traffic.
- On spokes: the hub public key pinned in the root-owned configuration. Only the hub needs a published UDP endpoint.
- Authenticated HTTPS access to the VPN management app independently of the tunnel, with the appropriate CA trust and a dedicated host credential.

See [the host configuration contract](../README.md#host-installation-contract) for `host.json`. Keep the configuration, program and their parent directories root-owned. Do not place credentials in shell command arguments, Git, or unit environment variables.

## Install the updater

From a reviewed checkout, using the existing provisioning account:

```sh
sudo install -d -m 0755 /opt/internal-vpn /opt/internal-vpn/internal_vpn
sudo install -d -m 0700 /etc/internal-vpn
sudo install -m 0644 run-host.py run-metrics.py /opt/internal-vpn/
sudo install -m 0644 internal_vpn/__init__.py internal_vpn/host.py internal_vpn/validation.py internal_vpn/metrics.py /opt/internal-vpn/internal_vpn/
# Provision /etc/internal-vpn/host.json separately, owned by root with mode 0600.
sudo install -m 0644 deploy/internal-vpn-update.service deploy/internal-vpn-update.timer /etc/systemd/system/
sudo systemd-analyze verify /etc/systemd/system/internal-vpn-update.service /etc/systemd/system/internal-vpn-update.timer
sudo systemctl daemon-reload
sudo systemctl start internal-vpn-update.service
sudo systemctl enable --now internal-vpn-update.timer
```

Systemd creates `/var/lib/internal-vpn` as root with mode `0700` and permits writes there despite `ProtectSystem=strict`. Preserve that directory across program upgrades and normal restarts: its revision watermark rejects old or conflicting responses. It contains ordering state, not cached membership for offline replay.

The unit orders after `wg-quick@ivpn0.service` when that service is part of the startup transaction; it does not start or own the interface. If another provisioning component owns the interface, adapt ordering to that owner. A missing interface produces an apply failure; a later timer activation retries current desired configuration. Full boot ordering still needs deployment acceptance.

The timer first activates ten seconds after boot (or immediately when enabled later), then requests refresh fifteen seconds after the updater finishes, with one-second scheduling accuracy. This is not a guaranteed fifteen-second revocation deadline: execution time, scheduling, controller availability and failures affect convergence. See [systemd.timer](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html) for scheduling semantics.

For enrollment, removal and coordinated key/credential rotation, see [OPERATIONS.md](OPERATIONS.md).

See [METRICS.md](METRICS.md) for read-only counters, handshake age, explicit probes and the updater’s last execution result.

## Check and stop

```sh
sudo systemctl status internal-vpn-update.timer internal-vpn-update.service
sudo journalctl -u internal-vpn-update.service -n 20 --no-pager
sudo systemctl disable --now internal-vpn-update.timer
sudo systemctl stop internal-vpn-update.service
```

Stopping refresh does not revoke membership or remove existing kernel peers. To retire a spoke, disable its membership through the management API and confirm the hub applied removal. The selected hub cannot be retired through ordinary membership edits. Interface teardown remains the provisioning owner's responsibility.

Keep private keys, credentials and raw WireGuard dumps out of shared diagnostics. Do not delete the watermark to work around a rejected revision; reconcile the intended control-plane/host state explicitly.

## What was tested

`lab/verify.py --systemd --central` creates unique runtime units under `/run/systemd/system`, using these templates with only executable/config/state paths and unit names substituted. It preserves the capability bounding set, filesystem restrictions and timer interval. The lab copies its public CA certificate into the root-owned test directory because `ProtectHome` correctly prevents using the certificate under the application user's home directory.

For the unit test, one disposable spoke interface moves temporarily into the host namespace with its address removed and no host routes installed. This allows the real updater to reach the loopback management API and operate WireGuard using only `CAP_NET_ADMIN`, without granting namespace-switching privileges. The interface then returns to its namespace for the transport suite.

The scenario verifies successful application, private state creation, credential permissions, rejection of unsafe configuration modes, failed application when the interface is absent, timer recovery, repair of peer drift, and watermark preservation after restarting the service. It removes the runtime units and state afterward. It does not install permanent units, enable anything across boot, reboot the machine, or validate the final infrastructure provisioning integration.
