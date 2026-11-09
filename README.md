# Internal VPN PoC

A separate Frappe app controls a hub-and-spoke WireGuard network. A non-root management process owns membership; a root-owned, one-shot updater owns peers on a dedicated interface. Central’s host is the sole hub; every service/device spoke peers only with that hub. Central, its WireGuard service and its connectivity are assumed to have 100% uptime. HA/failover is outside scope.

The previous direct-peer implementation is preserved on `mesh-direct-peers` at `056e307`. `main` uses configuration protocol v2 and requires fresh hub/spoke provisioning; mixed mesh/hub operation is unsupported. Remove all old direct peer relationships before relying on hub-only revocation.

The first slice is implemented and tested on `ubuntu-dev`. [PLAN.md](PLAN.md) remains the requirements and phase plan. This is not yet the complete implementation of [frappe/central#641](https://github.com/frappe/central/issues/641).

[INTEGRATION.md](INTEGRATION.md) records the real Central integration tests and deployment contract. Central authentication and revocation work over the lab tunnel; its operator API is still reachable on the non-VPN path. Ingress isolation remains required work.

## Implemented boundary

- Service identities and engineer-owned devices, using Frappe Users, roles, and API keys.
- Public-key registration, atomic address allocation, key/endpoint changes, disablement, and owner disablement/role removal handling.
- Structured per-host configuration; host credentials cannot administer membership or fetch another host's configuration.
- A serialized updater with TLS verification, strict peer validation, local key/interface ownership, persisted revision ordering, and application reports.
- Guest denial on the management app. Realtime is disabled entirely in the supplied WSGI entrypoint; both polling and upgrade requests are rejected. The login API is the bootstrap exception. No custom UI is built.
- A read-only [measurement command](deploy/METRICS.md) for handshake age, traffic counters, explicit VPN ICMP probes and optional systemd updater results.
- Reproducible tests using a real Frappe HTTPS server, MariaDB, kernel WireGuard, three simulated services (one hub and two spokes), and an engineer device.

Not implemented: VPN gates on actual Central/Atlas/Cargo routes, production provisioning, a working authenticated realtime service, Datum ingestion, Insights/Raven delivery, actual cross-region acceptance, and fleet-scale capacity measurements. The hub routes the allocated VPN subnet without resource ACLs or source NAT. Spokes initiate to the hub and need no published endpoint. The hub endpoint must currently be numeric IPv4.

## Run on ubuntu-dev

Sync this project without Git metadata or credentials:

```sh
rsync -a --exclude .git --exclude __pycache__ ./ ubuntu-dev:/home/vagrant/internal-vpn/
ssh ubuntu-dev
/home/vagrant/atlas-stack/bench/env/bin/python /home/vagrant/internal-vpn/lab/bootstrap.py
cd /home/vagrant/internal-vpn
python3 -m unittest discover -s tests -v
/home/vagrant/atlas-stack/bench/env/bin/python lab/verify.py
# Include the real Central development backend:
/home/vagrant/atlas-stack/bench/env/bin/python lab/verify.py --central --systemd --network
```

For an existing **empty** mesh lab database, run `lab/migrate_hub.py` with the same Frappe Python runtime before verification. It refuses a populated database; this is schema setup for the disposable PoC, not a deployment migration.

Run these as `vagrant`, with its existing sudo access. The bootstrap script is specific to this development machine. It reuses the installed Frappe runtime and MariaDB server, creates a separate database `ivpn_poc`, and creates `/home/vagrant/internal-vpn-lab/sites/test.local`. It does not install the app into the existing Central/Atlas test site. It reads the local database administrator credential without printing or storing it in this repository.

Retained development resources:

| Resource | Location |
| --- | --- |
| Source checkout | `/home/vagrant/internal-vpn` |
| Separate bench/site | `/home/vagrant/internal-vpn-lab`, site `test.local` |
| Database | `ivpn_poc` in the existing lab MariaDB container |
| Separate Redis process | `127.0.0.1:16411`; PID/log under the lab bench |
| Lab-only TLS certificate/key | `internal-vpn-lab/config/`; certificate valid for 14 days |

Each verification run starts a non-root HTTPS server on `127.0.0.1:18441`, copies the updater/configuration into a root-owned `/run/internal-vpn-poc-*` directory, and creates `ivpn-poc-*` network namespaces. Private WireGuard keys are generated locally and never sent to the app. The lab subnet is `100.100.64.0/24`; this is not a deployment allocation. WireGuard UDP sockets are born in the host namespace and use loopback endpoints on ports `56441`–`56445`.

The workerless lab discards its framework fixture jobs from its dedicated Redis queue between runs; it does not execute or verify those background jobs. The runner stops its HTTP processes and removes its namespaces, root updater directory, private keys, and test users/peers in `finally`. It retains the reusable bench, database/schema, Redis process, TLS material, logs, `lab-results.json`, `lab-timings.json`, and `lab-network.json`. Do not run two copies of the lab runner concurrently; the lab ports are fixed. The updater itself is serialized and is tested with concurrent invocations.

Existing `wg0`, VM namespaces, application services, proxy rules, and source repositories are not part of the PoC's mutation scope.

## Control-plane contract

Install this app on its own Frappe site. Run `internal_vpn.wsgi:application` with `VPN_SITE` fixed to that site's name and `SITES_PATH` pointing at its sites directory. Use TLS and no separate Socket.IO server for this headless PoC. The app-level auth hook is not a substitute for controlling a separately deployed realtime backend or a proxy's static-file routes.

Use Frappe's normal `Authorization: token <api_key>:<api_secret>` credentials or an authenticated session. Provision accounts and their credentials through Frappe administration. An ordinary logged-in account has no VPN enrollment privileges.

| Role | Authority |
| --- | --- |
| VPN Manager | Initialize the pool, enroll services, change membership, inspect application status |
| VPN Engineer | Register/change their own devices and fetch their device configuration |
| VPN Host | Fetch/report for its own enrolled service only; use one dedicated user per host |

All endpoints are under `/api/method/internal_vpn.api.`:

| Method | HTTP | Input / result |
| --- | --- | --- |
| `initialize` | POST | `subnet`; only an unused or identical allocation is accepted |
| `register` | POST | `kind`, `public_key`; service registration also needs `user`; `endpoint` is required only for the hub. Returns `name`, `address`, `revision` |
| `set_hub` | POST | `name`; select an active Service with an endpoint once; replacement requires explicit reprovisioning |
| `update_peer` | POST | `name`, optional `enabled`, `public_key`, `endpoint` |
| `configuration` | GET | `name`; returns revision, pinned host identity/address/subnet, public peers |
| `report` | POST | `name`, `revision`, boolean `success` |
| `status` | GET | Current desired revision and each host's last application report |

Frappe wraps the result in `message`. Reports require a JSON integer revision and boolean success. Invalid input receives a Frappe validation error. VPN DocTypes are read-only through generic document APIs; membership changes must use these endpoints. Disabled records retain addresses, avoiding reuse while a host may still have stale membership. Address reclamation and host readdressing are outside this slice.

There are two DocTypes: one `VPN Network` record for subnet/revision/hub and `VPN Peer` records for services/devices. Host report fields, including the applied desired-configuration digest, live on the service record. There is no extra job queue or history table.

### Transactions and revocation

The network row serializes membership changes, allocation, configuration snapshots, and reporting. Current locking reads prevent Frappe's earlier authentication snapshot from mixing an old membership list with a new revision. Relevant User enablement/role changes advance the same revision for enabled memberships; profile edits do not. Concurrent Frappe transactions can return HTTP 508 `QueryDeadlockError`; the lab retries only that explicit rolled-back outcome. API callers must handle transaction conflicts. Do not blindly retry registration after an ambiguous timeout; first check whether it succeeded.

Each updater holds a local file lock across fetch/validate/apply/report. Before modifying WireGuard, it persists the highest accepted revision and content digest. It refuses older revisions and changed content at the same revision, including after a failed apply or process restart. This file is an ordering watermark, not a cached configuration to replay. Losing it or restoring an older control-plane database requires explicit operator intervention; database disaster recovery is not implemented.

The updater removes unwanted peers before adding/updating authorized peers. It never reads the interface private key. It reports success only after every command succeeds. Application is not a kernel-wide atomic transaction; a command failure can leave a partial configuration and is reported as a failure. The next run reapplies current desired membership.

`status.hub_current` means the hub acknowledged its current desired membership. `status.all_current` means every active service acknowledged its own current desired configuration. Neither is a health measurement. The server compares a configuration digest excluding the global revision: unrelated membership changes do not invalidate an unchanged spoke's acknowledgement. Reports must still reference the current revision, and the host's anti-rollback watermark still includes it.

Revocation is complete at the routing boundary after the hub successfully removes the key. Other spokes do not need updated peer lists. Disabled services no longer block later acknowledgements; their retained local hub peer cannot communicate through a hub that has removed their key. Disabled records retain their addresses. This guarantee requires exclusive hub-only topology: old direct mesh peers must be removed. The selected hub and its account cannot be disabled; hub replacement is explicit reprovisioning, outside this slice. Re-enabling a removed peer may require a fresh WireGuard session.

### Host installation contract

The lab exercises both the root-owned updater directly and, with `--systemd`, the supplied oneshot/timer using temporary runtime units and the production sandbox settings. Systemd creates private state storage; the timer requests refresh 15 seconds after completion with one-second accuracy. See [deployment instructions and test boundaries](deploy/README.md). Permanent installation and whole-host boot ordering remain deployment work.

For a real host, provisioning must create the dedicated interface, local private key, assigned address/route, UDP listener/firewall rule, and root-owned updater/configuration. Do not share ownership with Atlas/Metal interfaces. The updater does not accept interface names, file paths, private keys, shell commands, or hooks from the API.

Expected root-only `/etc/internal-vpn/host.json` structure:

```json
{
  "url": "https://vpn-management.example.com",
  "token": "HOST_API_KEY:HOST_API_SECRET",
  "name": "ENROLLED_SERVICE_RECORD",
  "subnet": "100.100.64.0/24",
  "address": "100.100.64.2",
  "public_key": "HOST_WIREGUARD_PUBLIC_KEY",
  "interface": "ivpn0",
  "topology": "spoke",
  "hub_public_key": "PINNED_HUB_WIREGUARD_PUBLIC_KEY"
}
```

For the Central host use `topology: "hub"`; it does not need `hub_public_key`. A spoke accepts only the pinned hub key and allocated-subnet AllowedIPs; the hub accepts only each member’s individual `/32`. A hub key change requires updating local spoke pins and host provisioning.

Provision an allocated-subnet route through the dedicated interface on every participant. On the hub enable IPv4 forwarding, disable ICMP redirects, and integrate [deploy/hub-forward.nft](deploy/hub-forward.nft) into the existing firewall owner. Permit forwarding only within the allocated VPN subnet, and do not masquerade/SNAT it. Other forwarding chains can still drop accepted packets. This template does not protect application INPUT traffic or public Central endpoints. The lab applies these settings only inside its disposable hub namespace.

Pin the allocated values from enrollment. The example subnet is lab-only. The private key stays in root-owned interface provisioning. `ca_file` is optional for a private CA; system trust is otherwise used. `namespace` is a local lab-only option. Never put credentials in Git. Keep the executable, configuration parent directories, and `/var/lib/internal-vpn` root-owned; configuration mode must be `0600`. The lab's application user cannot modify WireGuard or the installed updater copy.

## Verification limits

See [TESTING.md](TESTING.md) for results and discovered boundaries. This PoC proves enrollment through the actual control plane can change live hub-routed tunnels and revoke access. It does not prove real regional reachability, deployment readiness, actual Frappe application network isolation, or the issue's monitoring/alerting acceptance criteria.
