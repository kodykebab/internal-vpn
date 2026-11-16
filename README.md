# Internal VPN

A Frappe app that manages a hub-and-spoke WireGuard network for internal services and engineer devices ([frappe/central#641](https://github.com/frappe/central/issues/641)).

Status: proof of concept, tested only on `ubuntu-dev`. Central's internal endpoints are not yet restricted to the VPN.

## Design

```text
Engineer devices --WireGuard--> Dedicated hub --WireGuard--> Central / Atlas / Cargo
                                     |
                           VPN app + local updater
```

- The VPN app runs on the dedicated hub. Central, Atlas, Cargo and engineer devices are spokes.
- The app owns membership. It never sees a private key.
- Each host runs `host.py` as root. The agent fetches its own public peer list, validates it, applies it to a dedicated interface (`ivpn0`) and reports the result.
- After a membership commit, Frappe uses one restricted sudo command to start the local hub updater. The timers keep all hosts current.
- Disabling a member takes effect when the hub applies the change. Spokes need no refresh.
- Central, Atlas and Cargo keep their own authentication. The VPN adds network reachability only.

## Code

| Path | Owns |
| --- | --- |
| `internal_vpn/internal_vpn/doctype/vpn_network` | Address allocation, revisions, hub selection, snapshots, status, User change hook |
| `internal_vpn/internal_vpn/doctype/vpn_peer` | One service or device: key, endpoint, enablement, configuration fetch, apply report |
| `internal_vpn/host.py` | Host agent: `update` applies membership, `measure` prints read-only metrics. Standard library only. |
| `internal_vpn/wsgi.py` | Headless entrypoint and guest denial |
| `deploy/` | systemd units, hub firewall template and [host operations](deploy/README.md) |

## API

All methods are whitelisted on the DocTypes. In Desk, select **Internal VPN** to open `VPN Network/default`, or open a `VPN Peer`: the form buttons call these methods, and a device's Configuration button shows a `wg-quick` file. The host agent uses `/api/method/run_doc_method` with `dt`, `dn`, `method` and `args`.

| Role | Methods |
| --- | --- |
| VPN Manager | `VPN Network`: `initialize`, `register_service`, `register_device` for an approved engineer, `set_hub`, `get_status`. `VPN Peer`: `set_enabled`, `rotate_key`, `release` on any peer; `set_endpoint` on the hub |
| VPN Engineer | `VPN Network`: `register_device`. `VPN Peer`: `get_configuration`, `set_enabled`, `rotate_key`, `release` on their own devices |
| VPN Host | `VPN Peer`: `get_configuration` and `report` on its own service. Use one user per host. |

Managers can read all peers; other VPN users can read only their own. Membership changes use action methods, including for Administrator; Frappe Version records edits. VPN roles have no generic write permission. Enrollment is capped at one hub and 10,000 other peers, including disabled peers. This is an input limit; sustainable capacity has not been established.

## Install

Install `internal_vpn` on a dedicated Frappe site on the hub, with Python 3.14 or later. Guest access is limited to login and password setup/recovery. Use the standard bench web process; `internal_vpn.wsgi:application` is an optional single-site entrypoint selected with `VPN_SITE`. See [host operations](deploy/README.md) for the updater and sudoers rule.

Bootstrap the site's Administrator with `bench --site <site> set-admin-password`. Use User in Desk to invite engineers and assign `VPN Engineer`; give VPN operators `VPN Manager`. Creating accounts and assigning roles requires Administrator or System Manager. Disable public signup in Website Settings.

An administrator can register an engineer's device using its locally generated public key. Invited engineers can then view their configuration, rotate keys and manage their own devices. Service accounts receive `VPN Host` and a separate API credential per host. Central does not manage VPN membership.

## Tests

Run the unit tests with a bench Python, so that Frappe can be imported:

```sh
PYTHONPATH=.:tests python -m unittest discover -s tests
```

Database tests require a disposable site with this app installed and `internal_vpn_test_site: 1` in its site config. They reset VPN records. Set `VPN_TEST_SITE` and the absolute `VPN_TEST_SITES_PATH` when running the command above; otherwise these tests are skipped.

## Open work

- Add Central's API-group policy in its authentication hook, including `cmd` dispatch and direct backend access. Keep customer APIs available; Central's `/socket.io` remains outside the VPN restriction.
- Install the agent through the existing host provisioning.
- Send measurements to Datum and alert through Insights and Raven.
- Verify real addressing, UDP reachability, DNS, TLS and cross-region paths.
