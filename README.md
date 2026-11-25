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
| `internal_vpn/internal_vpn/doctype/vpn_network` | The network settings (Single): subnet, hub, revisions, server status, user hooks. Shared member rules |
| `internal_vpn/internal_vpn/doctype/vpn_server` | A hub or service host: key, enablement, configuration, reports, status |
| `internal_vpn/internal_vpn/notification` | **VPN Server Health**: notifies managers when a server turns Failed or Stale, and when it recovers |
| `internal_vpn/internal_vpn/doctype/vpn_device` | An engineer's device: key, enablement, configuration |
| `internal_vpn/host.py` | Host agent (`update`, `measure`). Standard library only |
| `deploy/` | systemd units, hub firewall, sudoers rule and the [host guide](deploy/README.md) |

## Roles

In Desk, **Internal VPN** opens the device list. Servers and devices use the standard forms: create, edit the key or **Enabled**, delete. The controllers allocate addresses, enforce the hub rules and advance the revision. Hosts call `get_configuration` and `report` on their VPN Server through `run_doc_method`.

| Role | Can |
| --- | --- |
| VPN Manager | Edit the network settings, invite engineers, view status. Create, edit and delete servers. Edit and delete any device |
| VPN Engineer | Create, edit and delete their own devices |
| VPN Host | Fetch its server's configuration and report back, through the `agent` right on its shared VPN Server. One user per server |

A member keeps its address until deleted, and can be deleted only when disabled and after the hub has applied that. The network holds one hub and up to 10,000 other members.

The hub enforces who reaches whom: servers reach each other, members reach servers, and nothing on the VPN can open a connection to a device.

## Install

1. Create a dedicated site with this app, using Pilot or bench and Python 3.14+.
2. Set up an outgoing Email Account. Installing the app turns on email link sign-in and turns off password sign-in for every user, Administrator included.
3. Open Desk as Administrator with Pilot's login as Administrator (or `bench --site <site> browse --user Administrator`) and finish the setup wizard. Until then, Frappe sends other users to it.
4. Create operator users with `VPN Manager`. Keep signup off in Website Settings.
5. Managers invite engineers with **Invite Engineer** on VPN Network. Frappe emails the invitation; accepting it adds `VPN Engineer`.
6. Set up the hosts with the [host guide](deploy/README.md).

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
