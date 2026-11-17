# Internal VPN

A Frappe app that runs a hub-and-spoke WireGuard network for internal servers and engineer devices ([frappe/central#641](https://github.com/frappe/central/issues/641)). Proof of concept, tested on `ubuntu-dev` only.

```text
Engineer devices --WireGuard--> Hub --WireGuard--> Servers (Central, Atlas, Cargo, ...)
                                 |
                       VPN app + local updater
```

- The app runs on the hub and owns membership. It never sees a private key.
- Every host runs `host.py` as root. It fetches its peer list, applies it to `ivpn0` and reports back.
- Revocation takes effect when the hub applies it. Spokes need no refresh.
- The VPN adds reachability only. Services keep their own login.

## Code

| Path | Purpose |
| --- | --- |
| `internal_vpn/internal_vpn/doctype/vpn_network` | The network: addresses, revisions, hub, status, alerts, user hooks |
| `internal_vpn/internal_vpn/doctype/vpn_peer` | One service or device: key, endpoint, enablement, configuration, reports |
| `internal_vpn/host.py` | Host agent (`update`, `measure`). Standard library only |
| `internal_vpn/auth.py` | Blocks guests except login and password pages |
| `deploy/` | systemd units, hub firewall, sudoers rule and the [host guide](deploy/README.md) |

## Roles

In Desk, **Internal VPN** opens the network. Form buttons call whitelisted DocType methods. Hosts call the same methods through `run_doc_method`.

| Role | Can |
| --- | --- |
| VPN Manager | Initialize, register services, add engineers, set the hub, view status. Disable, rotate or release any peer |
| VPN Engineer | Register, view, disable, rotate and release their own devices |
| VPN Host | Fetch its configuration and report back. One user per host |

No role can edit VPN records directly. The network holds one hub and up to 10,000 other peers.

The hub enforces who reaches whom: servers reach each other, members reach servers, and nothing on the VPN can open a connection to a device.

## Install

1. Create a dedicated site with this app, using Pilot or bench and Python 3.14+.
2. Finish the setup wizard as Administrator. Until then, Frappe sends other users to it.
3. Give operators `VPN Manager` and turn off signup in Website Settings.
4. Set up the hosts with the [host guide](deploy/README.md).

## Tests

```sh
PYTHONPATH=.:tests python -m unittest discover -s tests
```

Use a bench Python. Database tests run only with a throwaway site that has this app and `internal_vpn_test_site: 1`. Set `VPN_TEST_SITE` and an absolute `VPN_TEST_SITES_PATH`. They wipe VPN records.

## Open work

- Per-engineer access to services.
- Restrict internal endpoints of Central, Atlas and Cargo to the VPN.
- Install the agent through host provisioning.
- Send metrics to Datum and alert through Insights and Raven.
