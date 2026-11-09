# Internal VPN integration and implementation debt

## What works now?

The separate VPN app can enroll a device, distribute membership to root-owned host updaters, and give that device access to a real Central development backend over WireGuard. Central still authenticates the request and applies its own permissions. Removing the device blocks its new Central connections.

This is transport and application-authentication integration. **Central's public/internal ingress isolation is not implemented.** The same operator-only `System Settings` API is reachable with valid operator credentials through a non-VPN listener. Closing that path is integration debt required to complete issue #641. It does not prevent using the standalone transport PoC.

Authority: [issue #641](https://github.com/frappe/central/issues/641) and its [decision comment](https://github.com/frappe/central/issues/641#issuecomment-6623450831). [PLAN.md](PLAN.md) tracks the remaining scope. [README.md](README.md) owns the VPN API/host configuration contract.

## What did the Central test actually run?

The `--central` scenario uses:

- The VPN app on its separate `test.local` site/database, `ivpn_poc`.
- Central's existing `test.local` site under `/home/vagrant/central-rescue-3174d144`.
- The actual Central/Frappe WSGI application in a non-root Gunicorn process, with real database-backed Users and API credentials.
- Disposable service/engineer namespaces running kernel WireGuard and the real updater.
- TLS byte relays to a Unix socket. Central terminates TLS; the relay does not implement authentication or fabricate responses.

```text
Engineer namespace                       Host namespace
  device key + Central credential
          |
       WireGuard
          |
Central hub namespace                     real Central test.local
  VPN IP:8443 ---- TLS byte relay ---->  Gunicorn Unix socket
                                        Central auth + permissions
Service spoke namespace                            ^
  service peer reaches hub over WireGuard        |
                                        non-VPN loopback relay
                                        127.0.0.1:18442
```

This arrangement keeps Central's database/cache connectivity intact without changing host routes or existing proxies. It proves inbound HTTPS over the tunnel reaches actual Central code. It does not put the Central process itself inside the namespace, test its outgoing regional clients, establish a trusted proxy source-address contract, or prove a real WAN path.

The test uses a short-lived certificate for `central.poc.test` and verifies it. curl's `--connect-to` chooses the lab destination while preserving the TLS name. No `--insecure` transport is used. Credentials are passed to curl through stdin, not process arguments.

Central's pre-existing Redis Queue listener at `13381` is unavailable. The test starts a temporary Redis Unix socket and sets `FRAPPE_REDIS_QUEUE` only for its Central fixture/server subprocesses. It does not edit the existing site's configuration, start workers, or repair/change the running Central service. The temporary Redis process and queued test data disappear at cleanup.

## Which Central behaviors were verified?

| Scenario | Observed result | Interpretation |
| --- | --- | --- |
| Engineer tunnel + valid Central customer credential, `central.api.identity.my_profile` | 200, correct fixture identity | Real authenticated Central API over WireGuard |
| Engineer tunnel without application credentials | 401/403 | VPN membership does not log the caller into Central |
| VPN management API credential sent to Central | 401/403 | The two applications' credentials are separate |
| Customer reads `System Settings` over VPN | 403 | VPN membership does not grant operator permissions |
| Operator reads `System Settings` over VPN | 200 | An authorized internal operation works over the tunnel |
| Other service peer makes authenticated Central request | 200 | Service-to-service transport works in the lab; this uses a lab API credential, not a regional production token |
| Customer profile through the non-VPN listener | 200 | The required public customer path remains available |
| Malformed input to public `central.api.auth.send_code` | 417 | The public handler is reached and validates input; no email is sent |
| Customer queries capabilities and teams through VPN | Empty lists for the unassigned fixture | Network membership grants no team or capability |
| Customer sends forged `X-Forwarded-For` while reading System Settings | 403 | A header does not grant an application role; this does not validate a future proxy's VPN source checks |
| Device membership removed and hub updated | Engineer's new Central connection fails; service peer still succeeds | Revocation affects actual Central connectivity |
| Operator reads System Settings through the non-VPN listener | **200** | **Unmet requirement: the admin API is not yet VPN-only** |

The runner records the last row as an expected observation of the gap. It must not be reported as a passing ingress-security acceptance test.

A first test assumed listing User names was an operator-only operation. Frappe grants a selection path for User names, so that was the wrong authorization assertion. The final test uses System Settings, whose permission contract is explicitly System Manager-only. Route classification must follow real application permissions, not assumptions about a resource name.

In the preceding review, existing Central tests also passed (not rerun for this topology change): 3 capability-guard integration tests and 8 IAM integration tests. They cover team resolution, suspended-team denial, operator bypass, capability implications, role behavior and team-scoped claims. They are supplementary framework/application tests, not browser or network tests.

## Which source version was tested?

The Central runtime directory is an **unversioned development copy**. Do not attribute these tests to the local Central checkout's commit `16921e26f450167b3e477becc6bd98fabcc585ed`.

| Tested Central file | SHA-256 |
| --- | --- |
| `central/api/identity.py` | `b6f3e6eacdaf95320b9c05c73d4b0c3d2e1e7d472f11ad74c082e91f4c7191e6` |
| `central/iam.py` | `ad51c03113da489d8b4865cbbfb87d10409e3bafa23fd251fd8ae400f9f0ddf6` |
| `central/hooks.py` | `20d180f4ade69b7ff0b1ca10ffd751b8b33eb4526795fcf0bad8266d339d3f30` |

The identity API file matches the local checkout; IAM and hooks do not. These hashes identify the exercised files, not the entire deployment. Repeat integration acceptance on the selected target revision before deployment. Frappe checkout HEAD is `249b5f0f481989f7481a0244d1b2862d559b165a`, using Python 3.14.6. The host updater runs on Python 3.12.3.

## How should Central connect in the intended deployment?

1. Provision a dedicated WireGuard interface and private key through the host's existing provisioning owner. Confirm the chosen subnet/port do not collide with existing networks.
2. Create a dedicated service account in the VPN app, grant VPN Host, and issue its API credential through normal Frappe User handling.
3. A VPN Manager registers the Central hub public key and reachable UDP endpoint, then calls `set_hub`. Other services register without endpoints. Copy the returned service record/address and public identity into root-owned host configuration. Pin the hub key on every spoke and the topology role on every host.
4. Provision the allocated-subnet routes, hub IPv4 forwarding and VPN-only forwarding firewall without SNAT. Install the constrained updater, its state directory and startup/refresh units. Keep the management API reachable over authenticated HTTPS before VPN setup; do not create a circular bootstrap dependency.
5. Apply membership and inspect acknowledgements. Check actual HTTPS/service probes separately from configuration status.
6. Give approved engineers VPN Engineer authority in the VPN app. Their device generates its private key locally and submits only the public key. Do not infer employee access from an ordinary Central customer account.
7. Keep Central's existing application sessions, API credentials, signing keys, capability checks and team boundaries. WireGuard membership is not a Central role or a replacement token.
8. Apply the agreed ingress restrictions, then verify both protected operations and preserved public flows.

The PoC does not implement Central SSO/OIDC enrollment into the VPN app. It uses manually provisioned Frappe identities. Choose that mapping before production rollout; do not copy customer/team VPN enrollment semantics into the employee VPN by default.

The current host credential is a Frappe user credential. The VPN APIs limit it to its own configuration/reporting; it is not a new cryptographically scoped token that disables every unrelated Frappe endpoint. Audit the deployment's baseline roles and exposed framework surfaces accordingly.

## Does putting the hub on Central isolate Central?

No. Hub routing centralizes membership enforcement, but packets addressed to Central itself traverse its INPUT path, not the forwarding firewall. Public proxy listeners and backend bypasses still need application/network enforcement. Keep the normal public customer routes and Central IAM; define a trusted VPN ingress path for internal operations. The non-root Frappe process neither forwards packets nor needs WireGuard privileges.

Central’s host, WireGuard and connectivity are assumed to have 100% uptime. No secondary hub or failover lifecycle is planned. Hub bandwidth, CPU, latency and cross-region routing still need measurement. The source-preservation lab verifies routing without SNAT at a spoke HTTP server; it does not validate the Unix-relayed Central backend's proxy trust boundary.

## Which ingress rules are still needed?

The following table is a classification starting point, **not a deployable allowlist**:

| Surface | Required treatment / unresolved decision |
| --- | --- |
| Separate VPN management app | Deny guests except explicit bootstrap/login paths. Realtime is currently entirely disabled. Browser assets/login and authenticated realtime need their own tests if enabled. |
| Central Desk and operator-only operations | Require a verified VPN path plus normal application permissions. Cover generic resources and document methods, not just `/desk` HTML. |
| Customer API examples such as `central.api.identity.my_profile` | Preserve normal public customer access and IAM behavior. |
| Shared customer/operator methods | Classify the operation or effective privilege inside the application where path matching cannot distinguish it. Do not silently grant the operator bypass to public callers merely because the path also serves customers. |
| Central customer realtime | Preserve authenticated customer behavior. Decide how administrative realtime is separated; disabling all `/socket.io` is not compatible with the customer dashboard. |
| Public login/code verification, required assets and key discovery/JWKS | Preserve explicit bootstrap/discovery contracts. Confirm allowed methods and aliases. |
| Pilot credentials and signed service/state callbacks | Preserve their existing authentication. `allow_guest=True` can mean non-session machine authentication, not anonymous access. Enroll callers before moving a path behind the VPN. |
| Required external callbacks, such as GitHub deliveries | Keep the explicitly required independently authenticated entrypoints reachable. |
| Direct Gunicorn/backend listeners | Prevent access around the enforcing proxy/network boundary. |

Central's integration clients remain in `central/integrations/`; do not move remote calls into API/controllers to add VPN transport. Central IAM remains the owner of team/capability authorization. Customer WireGuard devices and regional VM networking remain distinct systems.

Before choosing a proxy rule, enumerate `/api/method`, `/api/v1/method`, `/api/v2/method`, legacy `cmd` dispatch, resource/document methods, route aliases, downloads, HTTP methods, polling/upgrades and proxy-normalized paths. A prefix-only rule does not cover all of these. Accept source information only from an enforced trusted proxy path, never directly from a caller-controlled VPN marker or forwarded header.

## What did the review change in the PoC?

| Finding | Resolution |
| --- | --- |
| Test credentials bypassed the User document lifecycle; a later save removed the secret | Fixtures now set `User.api_key` and `User.api_secret` and save normally. Profile changes, role removal/restoration and disable/re-enable now exercise valid credentials. Earlier denial observations alone were insufficient evidence. |
| Malformed public keys/subnets/endpoints escaped as server errors | API-boundary validation translates parser errors into Frappe client validation errors; real HTTP regressions verify 417. |
| Numeric coercion accepted float revisions/flags and numeric success | Reports require an integer revision and boolean success; membership flags reject floats. |
| Unauthorized mutation attempted peer lookup/locking first | Role authorization now precedes that lookup; another engineer still cannot access or mutate the device. |
| Every profile change invalidated every host's acknowledgement | User hooks now compare enablement and relevant VPN roles, and only enabled memberships trigger revisions. |
| Empty host set was reported current | An empty network is not reported ready. |
| Updater printed `applied: false` when reporting might have failed after a successful apply | Failure output now describes overall failure without asserting that no application occurred. Diagnostics still omit credentials and raw response bodies. |
| Repeated identical snapshots rewrote/fsynced the watermark | Preserve the watermark file for the same accepted revision/digest while still reconciling live peers. |
| Missing lab marker triggered force installation/reset behavior | Removed that marker-driven reinstall path. Bootstrap refuses a pre-existing database without its site configuration. |

The review also checked generic DocType mutation with spoofed client flags. Frappe rejected it; it was not a confirmed bypass.

## Integration and implementation debt

This is the consolidated debt register for the standalone hub PoC. These items are documented follow-up work, not an instruction to start application integration now. The existing enrollment, routing, revocation and acknowledgement behavior remains usable independently. [PLAN.md](PLAN.md) provides the broader issue requirements and implementation sequence.

### Integration debt

| Area | Remaining work / completion evidence |
| --- | --- |
| Central ingress isolation | Classify public/customer and internal operations, enforce the trusted VPN ingress boundary, and prevent backend bypasses. Verify non-VPN internal requests fail even with valid operator credentials while public customer flows continue working. Include Desk, API aliases, generic resources/document methods, downloads and realtime. No Central or existing proxy rules have been changed. |
| Atlas and Cargo | Integrate each application's actual service callers, routes and authentication independently. Verify both directions of service communication with intended credentials; the current Central test covers inbound requests using fixture credentials. |
| Identity and onboarding | Define approved employee enrollment and dedicated service-account provisioning using existing identity machinery. Current users and credentials are provisioned manually; Central SSO/OIDC mapping and an engineer device setup procedure are not implemented. Review baseline Frappe permissions for host accounts. |
| Host provisioning | Integrate dedicated interfaces, private keys, addresses/routes, hub forwarding, firewall rules, TLS and the updater with the existing host provisioning owner. Preserve existing Atlas/Metal/customer VPN ownership. Validate management API bootstrap without requiring an already-working tunnel. |
| Observability delivery | Connect measurements to Datum, query them through Insights and deliver a test alert to Raven. Verify the deployed webhook transport and destination restrictions before selecting a VPN-only Raven endpoint. |
| Target deployment acceptance | Repeat application/proxy acceptance against explicitly selected source revisions. The Central runtime tested here is an unversioned development copy, identified above by exercised file hashes. |

### Remaining implementation and verification debt

| Area | Current boundary and remaining work |
| --- | --- |
| Updater deployment | The executable is tested directly; supplied systemd oneshot/timer units are templates. Verify installation permissions, startup ordering, scheduled refresh and whole-host boot behavior on the development host. |
| Operational key lifecycle | Device key rotation is tested. Document and verify service key replacement, credential rotation and explicit hub reprovisioning, including updating root-owned spoke hub-key pins. Recreating the hub interface loses learned endpoints/sessions; the current test explicitly reconnects a spoke and establishes no automatic recovery deadline. |
| Convergence and reporting | `hub_current` and `all_current` are configuration acknowledgements, not live health. Define and measure an operational application/revocation deadline, including failed application/reporting and transaction conflicts. Unchanged spokes need no new acknowledgement for unrelated membership edits. |
| Metric collection | Implement collection of handshake age, traffic counters, apply failures and active reachability/latency probes. Define intervals, thresholds and idle-device treatment before wiring alerts. A recent handshake alone is insufficient health evidence. |
| Capacity and performance | Measure hub bandwidth/CPU, routing latency, configuration size, global-row lock contention and fleet convergence. Central's assumed 100% uptime does not establish capacity. |
| Real network acceptance | Verify deployed device-to-device use, hub UDP/NAT reachability, subnet collisions, DNS/TLS, WAN MTU/loss and cross-region paths. Current tests use namespaces and loopback UDP on the only available host, `ubuntu-dev`; they cannot establish real cross-region behavior. |
| Management UI/realtime boundary | The PoC is headless and disables Socket.IO. If browser login/assets or authenticated realtime are introduced, implement and test their access contract explicitly. Current guest-denial tests do not establish functioning authenticated realtime. |

### Implemented boundaries and explicitly deferred scope

- Hub-only retirement is implemented: the hub removes the key and inactive service reports do not block later revisions. Disabled records keep their addresses; address reclamation is outside the current scope.
- `mesh-direct-peers` preserves the previous implementation. A populated mesh-to-hub migration is not supplied; the lab schema helper accepts only an empty membership database. Any future cutover must remove all old direct peer relationships before relying on hub-only revocation. Mixed topology is unsupported.
- Central's host, WireGuard and connectivity are assumed to have 100% uptime. Secondary hubs, HA and failover are outside scope, not outstanding implementation requirements.
- Broad VPN connectivity is intentional for the initial issue scope. Granular network resource ACLs are deferred; existing application permissions remain required.
- A later merge of the separate app into Central remains deferred. Database disaster recovery, automatic rollback, address reuse and general recovery orchestration need separate scope decisions if required; no such subsystem is implied by this debt register.

## How can this be rerun?

From this repository, sync to the authorized development machine, then run:

```sh
rsync -a --exclude .git --exclude __pycache__ --exclude '*results.json' ./ ubuntu-dev:/home/vagrant/internal-vpn/
ssh ubuntu-dev
cd /home/vagrant/internal-vpn
python3 -m unittest discover -s tests -v
/home/vagrant/atlas-stack/bench/env/bin/python lab/verify.py --central
```

For the existing Central tests:

```sh
/home/vagrant/v2/fleet-sources/pilot/bin/pilot -b /home/vagrant/central-rescue-3174d144 frappe --site test.local run-tests --app central --module central.tests.test_guards --test-category integration --skip-before-tests
/home/vagrant/v2/fleet-sources/pilot/bin/pilot -b /home/vagrant/central-rescue-3174d144 frappe --site test.local run-tests --app central --module central.tests.test_iam --test-category integration --skip-before-tests
```

The hub run passed 16 updater/topology tests and 96 live expected-result checks. The preceding review passed 11 existing Central integration tests. Results are in local `lab-results.json` and `central-results.json`; these generated artifacts are ignored by Git. The live checks include the known non-VPN admin exposure and cleanup, so their count is not a count of satisfied issue requirements.

Cleanup stops test servers/relays/Redis, removes both apps' fixture users, deletes lab peers, and removes generated keys, root updater directories and namespaces. The reusable VPN site/database/Redis remain. Local branch/commit changes are confined to this project. No staging/production changes or pushes were made.
