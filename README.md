# Internal VPN

A Frappe app that runs a hub-and-spoke WireGuard network for internal servers and engineer devices ([frappe/central#641](https://github.com/frappe/central/issues/641)). Proof of concept, tested on `ubuntu-dev` only.

```text
Engineer devices --WireGuard--> Hub --WireGuard--> Servers (Central, Atlas, Cargo, ...)
                                 |
                    VPN app applies hub peers
```

- The app runs on the hub and owns membership. It never sees a private key.
- The app applies the hub's peers itself, in a job after each change and once a minute, through a narrow sudoers rule.
- Every spoke runs `host.py` as root. It fetches its peer list, applies it to `ivpn0` and reports back.
- Revocation takes effect when the hub applies it. Spokes need no refresh.
- The VPN adds reachability only. Services keep their own login.

## Code

| Path | Purpose |
| --- | --- |
| `internal_vpn/internal_vpn/doctype/vpn_network` | The network settings (Single): subnet, hub, revisions, server status, user hooks. Shared member rules |
| `internal_vpn/internal_vpn/doctype/vpn_server` | A hub or service host: key, enablement, configuration, reports, status |
| `internal_vpn/internal_vpn/notification` | **VPN Server Health** tells managers when a server turns Failed or Stale and when it recovers. **VPN Device Registered** tells them about every new device |
| `internal_vpn/internal_vpn/doctype/vpn_device` | An engineer's device: key, enablement, configuration |
| `internal_vpn/internal_vpn/doctype/vpn_access` | Grants one engineer's devices access to one server, optionally limited to ports |
| `internal_vpn/host.py` | Host agent: `enroll`, `update`, `upgrade`, `measure`. Standard library only. The hub job imports it |
| `deploy/` | Hub firewall and its unit, sudoers rule, the VPN Desk entrance for nginx, and the [host guide](deploy/README.md) |

## Roles

In Desk, **Internal VPN** opens the device list. Servers and devices use the standard forms: create, edit the key or **Enabled**, delete. The controllers allocate addresses, enforce the hub rules and advance the revision. Hosts call `get_configuration` and `report` on their VPN Server through `run_doc_method`.

| Role | Can |
| --- | --- |
| VPN Manager | Edit the network settings, invite engineers, grant VPN Access, view status. Create, edit and delete servers. Edit and delete any device |
| VPN Engineer | Create, edit and delete their own devices |
| VPN Host | Fetch its server's configuration and report back, through the `agent` right on its shared VPN Server. One user per server |

A member keeps its address until deleted, and can be deleted only when disabled and after the hub has applied that. The network holds one hub and up to 10,000 other members.

The hub enforces who reaches whom: servers reach each other, devices reach servers, and nothing on the VPN can open a connection to a device. With **Access Control** on VPN Network, a device reaches only the servers its owner is granted in VPN Access, on the granted ports.

## Install

1. Create a dedicated site with this app, using Pilot or bench and Python 3.14+.
2. Set up an outgoing Email Account. Installing the app turns on email link sign-in and turns off password sign-in for every user, Administrator included.
3. Open Desk as Administrator with Pilot's login as Administrator (or `bench --site <site> browse --user Administrator`) and finish the setup wizard. Until then, Frappe sends other users to it.
4. Create operator users with `VPN Manager`. Keep signup off in Website Settings.
5. Managers invite engineers with **Invite Engineer** on VPN Network. Frappe emails the invitation; accepting it adds `VPN Engineer`.
6. Set up the hosts with the [host guide](deploy/README.md).

## Tests

DocType tests use Frappe's `IntegrationTestCase` and run with the bench:

```sh
bench --site <test site> run-tests --app internal_vpn
```

Tests in `tests/` need what that runner cannot give: real HTTP requests, several connections at once, and Frappe's Version history, which its runner turns off. Run them with a bench Python:

```sh
PYTHONPATH=.:tests python -m unittest discover -s tests
```

The host agent tests need no site. The others need a throwaway site with this app and `internal_vpn_test_site: 1`; set `VPN_TEST_SITE` and an absolute `VPN_TEST_SITES_PATH`. Both kinds wipe VPN records.

## Open work

- Restrict internal endpoints of Central, Atlas and Cargo to the VPN, as [VPN-only Desk](deploy/README.md#vpn-only-desk) does for this site.
- Send metrics to Datum and alert through Insights and Raven.
