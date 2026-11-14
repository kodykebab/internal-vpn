# Internal VPN

A Frappe app that manages a hub-and-spoke WireGuard network for internal services and engineer devices ([frappe/central#641](https://github.com/frappe/central/issues/641)).

Status: proof of concept, tested only on `ubuntu-dev`. Central's internal endpoints are not yet restricted to the VPN.

## Design

```text
Engineer device --WireGuard--> Central host (hub) --WireGuard--> Atlas / Cargo hosts
                                      |
            VPN app (Frappe, non-root) <-- host agent (root, one-shot, timer)
```

- Central's host is the only hub. Every other host and device peers only with the hub.
- The app owns membership. It never sees a private key.
- Each host runs `host.py` as root. The agent fetches its own public peer list, validates it, applies it to a dedicated interface (`ivpn0`) and reports the result.
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

All methods are whitelisted on the DocTypes. In Desk, open `VPN Network/default` or a `VPN Peer`: the form buttons call these methods, and a device's Configuration button shows a `wg-quick` file. The host agent uses `/api/method/run_doc_method` with `dt`, `dn`, `method` and `args`.

| Role | Methods |
| --- | --- |
| VPN Manager | `VPN Network`: `initialize`, `register_service`, `set_hub`, `get_status`. `VPN Peer`: `set_enabled`, `rotate_key`, `set_endpoint`, `release` on any peer |
| VPN Engineer | `VPN Network`: `register_device`. `VPN Peer`: `get_configuration`, `set_enabled`, `rotate_key`, `release` on their own devices |
| VPN Host | `VPN Peer`: `get_configuration` and `report` on its own service. Use one user per host. |

Users can read only their own peers. No role can write VPN records through the generic document API.

## Tests

Run the unit tests with a bench Python, so that Frappe can be imported:

```sh
PYTHONPATH=.:tests python -m unittest discover -s tests
```

## Open work

- Restrict Central's internal operations to the VPN without breaking customer APIs, signed callbacks and public key discovery.
- Define how approved employees get the VPN Engineer role and how hosts get credentials.
- Install the agent through the existing host provisioning.
- Send measurements to Datum and alert through Insights and Raven.
- Verify real addressing, UDP reachability, DNS, TLS and cross-region paths.
