# Internal VPN plan

Status: the separate control-plane PoC works with direct WireGuard peers and a real Central development backend. It does **not** yet enforce Central's public/private ingress boundary. Atlas/Cargo application integration and observability remain unimplemented.

## Requirements and authority

[frappe/central#641](https://github.com/frappe/central/issues/641) and its [November 4 comment](https://github.com/frappe/central/issues/641#issuecomment-6623450831) are authoritative. The meeting handoff supports them where it does not conflict. The user subsequently chose a separate project and `ubuntu-dev` as the only testing environment.

| Requirement | Current evidence | Remaining acceptance |
| --- | --- | --- |
| Service-to-service connectivity | Two service namespaces communicate directly; a service peer reaches the real Central test backend | Actual deployed Central/Atlas/Cargo callers, DNS/TLS and cross-region paths |
| Engineer registration/access | Real Frappe API enrollment creates usable tunnels; access to real Central is verified | Employee login/bootstrap and operator onboarding procedure |
| Desk/internal endpoints VPN-only | A VPN-bound Central listener works; Central still serves an operator-only API on the non-VPN listener | Protect actual internal operations and backend paths while retaining customer traffic |
| Separate app, later merge into Central | Separate Frappe app/site; no changes to Central source | Define the later migration only when requested |
| `100.64.0.0/10` addressing | Pool validation and serialized unique allocation; lab uses `100.100.64.0/24` | Check a deployment allocation against host, region, engineer and existing VPN networks |
| Service and engineer identities | Separate Frappe roles; dedicated host users; engineer-owned device records | Decide how approved employees receive enrollment authority; ordinary Central login is insufficient |
| Broad initial VPN access | Membership distributed without resource ACLs | Real reachable endpoints; engineer-to-engineer reachability is not provided automatically through NAT |
| Guest denial, including realtime, in the separate app | Guest API/resource denial; Socket.IO polling/upgrades disabled entirely | Working browser login/assets and authenticated realtime if realtime is enabled later |
| Datum, Insights alerts, Raven | Earlier ingestion experiments only; no collector in this PoC | Collect real measurements, ingest, query, trigger and deliver a test alert |

The handoff's open placement/addressing questions and mandatory initial granular ACLs are superseded by the issue comment. The guest-denial requirement for the separate app must not become a blanket public API or Socket.IO ban on Central.

## Chosen PoC boundary

Use a separate Frappe management app, normal Frappe Users/API credentials, and a dedicated WireGuard interface on each service host. Service hosts peer directly. Engineer devices initiate to reachable service endpoints. The control plane distributes membership and carries no application traffic.

Keep Atlas/Metal's regional IPv6 interfaces and the customer VPN under their existing owners. Prior experiments showed that their peer reconciliation can replace IPv4 AllowedIPs added by another owner. A dedicated interface avoids that ownership conflict without adding a hub.

```text
Engineer identity --> VPN app <-- Service identity
                         |
               authenticated desired peers
                         |
                  root host updater

Engineer device -- WireGuard --> Central / Atlas / Cargo hosts
Service hosts   -- WireGuard --> other enrolled service hosts
```

The service app stays non-root. Host provisioning owns the private key, interface/address/route, UDP port and updater installation. The updater accepts public peer data only. Interface selection, file paths and executable commands never come from the API. Exact contracts and commands are in [README.md](README.md).

No hub, relay, network ACL engine, custom dashboard, background reconciliation queue, automatic rollback, checkpoints, recovery orchestration or production HA is included. Reconsider these only against a concrete requirement or observed failure boundary.

## State and lifecycle invariants

| State | Owner and reason |
| --- | --- |
| `VPN Network` subnet/revision | One management record serializes allocation, membership snapshots and reporting. Current locking reads prevent a pre-existing Frappe transaction snapshot from mixing old membership with a newer revision. |
| `VPN Peer` identity/key/address/enabled | A service or device has an explicit owner and unique key/address. Disabled records reserve their addresses while old host configurations may exist. |
| Host's accepted revision/digest | A root-owned watermark rejects stale or conflicting snapshots, including after partial application or process restart. It is not a configuration cache to replay. |
| Host's application report | Existing fields on its service record distinguish current acknowledgement from pending/failed application. They do not establish live reachability. |
| Existing application permissions | Central IAM and the other services' own authentication/authorization remain authoritative after packets arrive through the VPN. |

User enablement and relevant VPN-role changes advance membership when they affect enabled peers. Profile edits and changes to owners whose peers are all disabled do not. Generic document mutation cannot bypass the membership API.

The updater serializes fetch, validation, apply and report. It validates the whole response before peer mutation, persists its accepted revision, removes unwanted peers first, and reports success only after application succeeds. A partial command failure is not rolled back automatically; the next run reapplies current desired membership. A report failure does not mean application never happened.

Concurrent Frappe transactions may return HTTP 508 `QueryDeadlockError`. Retry that explicit rolled-back response with a bound. Do not blindly retry registration after an ambiguous timeout. The lab tests concurrent allocation and concurrent host updates.

Device removal, role removal and owner disablement are tested. Re-enabling a removed device may require a fresh WireGuard session. Authorized owners can manage their devices; disabling a device is not a permanent ban on its still-authorized owner enrolling again.

**Retirement remains a design task:** disabled service records still participate in application reporting. Permanently removing a host needs a clear completion rule before it can stop reporting. Otherwise later revisions can remain pending forever. Do not silently exclude a disabled host that might retain old permissions, or add a retention/recovery subsystem to solve this narrow lifecycle question.

## Central integration boundary

[INTEGRATION.md](INTEGRATION.md) defines the tested topology, credential boundaries, route categories and remaining integration work.

The real Central test backend serves authenticated profile requests through WireGuard. Guest and wrong-app credentials are denied, and Central's role/team/capability rules remain in force. Device revocation blocks its new Central connections while another service peer retains access.

A non-VPN request with valid operator credentials still reads `System Settings`. This is direct evidence that issue #641's ingress requirement remains open. Binding an additional listener to the VPN does not close the existing public path.

Do not restrict all of `/api`, all generic resources, all `allow_guest` methods, or all Central realtime. Customer APIs, user-selection APIs, machine credentials, signed callbacks and public key discovery have distinct contracts. Protect operations as well as HTML routes and cover aliases, `cmd` dispatch, generic resource/document methods, HTTP methods, polling/upgrades and backend bypasses.

## Next implementation sequence

### 1. Complete the Central route and trust contract

- [ ] Inventory the actual deployed public/customer, bootstrap, machine and operator surfaces, including aliases and framework routes.
- [ ] Decide how shared endpoints distinguish customer operations from operator/internal operations.
- [ ] Define the proxy/network boundary and trusted source-address handling. Caller-supplied forwarded headers cannot establish VPN membership.
- [ ] Define employee login/enrollment authority and host credential provisioning using existing identity machinery.

Exit: reviewable route/operation matrix, identity mapping and trust boundary. This precedes Central source changes.

### 2. Enforce and validate Central ingress

- [ ] Implement the agreed boundary in Central and the existing proxy owner, preserving Central IAM.
- [ ] Deny non-VPN internal operations even with valid operator credentials.
- [ ] Deny unauthenticated/unauthorized requests from VPN members.
- [ ] Preserve customer APIs, bootstrap/key discovery, required signed callbacks and legitimate machine callers.
- [ ] Exercise browser login/Desk, alternate API dispatch, generic resources/document methods, downloads, realtime and direct backend paths.

Exit: the currently observed non-VPN admin access fails for the intended network reason, while required public flows succeed. A redirect or unavailable backend is not a passing access-control result.

### 3. Carry the contract to Atlas/Cargo and provisioning

- [ ] Adapt each application's actual authentication and routes independently; do not copy Central exceptions blindly.
- [ ] Install/test the dedicated interface and root updater through the host's existing provisioning owner.
- [ ] Exercise the supplied systemd oneshot/timer under its intended permissions; current live tests run the updater executable directly.
- [ ] Define service key replacement and permanent retirement completion without inventing a general recovery system.
- [ ] Verify management API bootstrap remains reachable before VPN setup and during membership changes.

Exit: repeatable installation/startup and honest failure/removal behavior for the selected development topology.

### 4. Implement observability

- [ ] Collect handshake age, traffic counters, application failures and active service probes/latency.
- [ ] Send actual measurements through Datum's existing authenticated ingestion API.
- [ ] Query ClickHouse through Insights and exercise a failed-probe alert.
- [ ] Deliver through Insights' existing webhook channel to a designated test Raven destination.

A recent handshake does not prove reachability, and an idle engineer laptop is not necessarily failed infrastructure. Metric names, scrape interval, thresholds and an operational revocation deadline remain to be defined. Upstream Insights' inspected HTTPS webhook transport rejects non-global destinations, including `100.64.0.0/10`; verify the deployed version/destination before choosing a VPN-only Raven endpoint.

### Deployment acceptance

- [ ] Confirm real address availability, UDP/NAT reachability, DNS/TLS, MTU and cross-region paths.
- [ ] Measure configuration size, lock contention, convergence and expected traffic volume; the global revision/full peer distribution is a small-PoC design.
- [ ] Verify deployed application/proxy and Insights/Raven revisions.

Only `ubuntu-dev` is available. Actual cross-region acceptance remains later work and is not inferred from namespaces.

## Review and evidence

The latest review exercised 11 focused updater tests, 85 live expected-result checks including Central, and 11 existing Central IAM/guard integration tests. These include failures observed as expected and cleanup; they are not independent production acceptance tests. [TESTING.md](TESTING.md) records the commands, revisions, corrections and limitations.

Review fixes include correctly creating Frappe test credentials, rejecting malformed API types as client errors, authorizing before peer lookup, avoiding unnecessary membership revisions, reporting an empty network as not ready, and avoiding a false claim that a failed report means nothing was applied. The installer no longer force-reinstalls apps merely because a local marker is missing.

Earlier direct/NAT/ownership and Datum experiments remain supporting evidence in `../.tmp/internal-vpn-experiment/`. They do not establish this app's current integration or alerting acceptance.

## Working constraints

Keep the project separate. Use `ubuntu-dev` and only `test.local` for Frappe tests. Preserve existing host interfaces, VM namespaces, applications, source changes, databases and disks outside the explicitly created fixtures. No staging/production changes, commits, pushes or remote repository creation are included. Review material scope/architecture changes before adding new subsystems.
