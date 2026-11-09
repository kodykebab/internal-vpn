# PoC review and verification

## Current evidence

The review uses only `ubuntu-dev`, the VPN app's separate `test.local` database, and Central's existing development `test.local` site. [INTEGRATION.md](INTEGRATION.md) describes the exact Central topology, exercised files and remaining ingress gap.

- **16 focused updater/topology tests passed**, locally and on Ubuntu.
- **96 live expected-result checks passed** in the expanded run, which covers the real VPN API/database, root updater, WireGuard namespaces and actual Central HTTPS backend. See `lab-results.json` for individual observations and `central-results.json` for Central results/source hashes.
- **11 existing Central integration tests passed in the preceding review (not rerun for this topology change):** 3 in `central.tests.test_guards`, 8 in `central.tests.test_iam`.

A bootstrap rerun also preserved the existing Administrator password hash and network revision. Python syntax, JSON, Markdown links/fences and whitespace checks passed.

Expected-result checks include observed shortcomings and cleanup. In particular, non-VPN Central admin access is recorded as a gap; hub-only retirement now passes. A successful test run does not mean those issue requirements are satisfied.

Runtime: application Python 3.14.6, updater Python 3.12.3, Linux `6.8.0-142-generic`, wireguard-tools `1.0.20210914`, Frappe checkout HEAD `249b5f0f481989f7481a0244d1b2862d559b165a`. Central's runtime is an unversioned copy; do not attribute its tests to the local checkout. Exact file hashes and the differences are in INTEGRATION.md.

## Commands

On `ubuntu-dev`:

```sh
cd /home/vagrant/internal-vpn
python3 -m unittest discover -s tests -v
/home/vagrant/atlas-stack/bench/env/bin/python lab/verify.py --central
```

Omit `--central` for just the VPN scenario. Central's existing test commands are in INTEGRATION.md. Frappe tests run only on `test.local`.

## Review coverage

| Boundary | Checks |
| --- | --- |
| Input and application authority | Guest denial; explicit login exception; legacy command dispatch; generic resources; other engineer/host access; generic DocType writes with spoofed flags; malformed key/subnet/endpoint values and strict report/enablement types |
| Transaction consistency | Unique addresses/revisions under concurrent enrollment; current locking reads; explicit retry of rolled-back conflicts; invalid requests leave the revision unchanged |
| User lifecycle | Profile edits preserve credentials and revision; role removal removes network access and config authority; role restoration plus reconnect works; owner disablement rejects both tunnel access and API credentials |
| Privilege and transport | Non-root Frappe; root-owned installed updater; app user denied WireGuard mutation; concurrent updater serialization; hub-routed service/device traffic, pinned single-peer spokes, source-preserving forwarding and outside-subnet firewall denial; unknown keys and source spoofing denied |
| Ordering and application | Accepted revision persists before mutation; stale/conflicting responses rejected; no cached replay when the controller is unavailable; private key ownership checked; missing interface reports failure; recreated interface reconciles current peers |
| Revocation | Pending removal and hub-only completed removal; outdated acknowledgements rejected; service traffic survives device removal; renewed session after re-enablement; rotated key succeeds and old key is absent |
| Real Central | Correct authenticated profile, separate credentials, role/team/capability preservation, valid operator access, public customer flow, actual connection failure after VPN removal |
| Known gaps | Authorized operator still reaches Central admin API without VPN |
| Cleanup | Temporary users/peers, keys, updater files, namespace processes, relays and namespaces removed; reusable lab remains |

The focused updater tests substitute controller/WireGuard calls to inspect specific failure boundaries. Live tests execute the real API, database and WireGuard commands. They serve different purposes; their counts are not independent acceptance coverage.

## Hub branch change

`mesh-direct-peers` preserves the original mesh implementation at `056e307`. The `main` branch uses a single Central hub under the agreed 100% uptime assumption. The new tests verify single-peer spokes, `/32` hub authorizations, refusal of broader routes/unpinned hubs, spoke-to-spoke forwarding, loss of spoke paths when hub forwarding is disabled, source preservation without SNAT, and firewall rejection of outside-subnet forwarding. Only the hub needs a new configuration for member removal. Unchanged spoke reports remain current and retired spokes no longer block future revisions.

The first live run caught a Frappe Document/dictionary mismatch in snapshot construction; normalization now occurs at the API boundary. A source-address fixture initially could not read its script as `nobody`; it now receives the nonsecret fixture code directly. Both required rerunning the full scenario.

## Findings corrected during review

1. **Credential fixture lifecycle:** Direct password-store writes left the User document's password field unset. A later User save removed the secret. Fixtures now set/save `api_key` and `api_secret` through the normal User lifecycle. The suite verifies credentials remain valid after profile edits and role restoration. Earlier disabled-credential failures alone did not prove correct disablement behavior.
2. **API parser failures:** Invalid keys, subnets and endpoints raised server errors. The API now converts these into Frappe validation responses. Float revisions/flags and numeric `success` are refused rather than coerced.
3. **Unnecessary revisions:** Profile edits and changes to an owner with only disabled peers no longer invalidate otherwise-current acknowledgements. Relevant enablement/role changes still propagate.
4. **Premature lookup and status:** Nonmembers are rejected before mutation lookup. An empty host set no longer appears ready.
5. **Ambiguous updater failure:** A report can fail after peer changes succeed. CLI failure output no longer falsely states `applied: false`; it reports overall failure without exposing credentials or raw error bodies.
6. **Installer behavior:** Missing-marker force reinstallation was removed. Bootstrap refuses a pre-existing lab database without its corresponding site configuration.

An attempted generic save with client-supplied permission/mutation flags was rejected by Frappe. It was checked and was not a confirmed bypass.

## Test corrections and limits

The initial User-list authorization assertion was wrong: Frappe has a User-name selection path. The final operator-only check uses System Settings and verifies both denial and success against its actual role permissions.

Recreating the hub interface discards learned endpoints and sessions. The restart check explicitly reconnects a spoke before verifying traffic and does not establish an automatic recovery deadline.

Re-enabling an existing WireGuard peer did not restore an old session within the original one-second check. The passing re-enablement test explicitly reconnects. It does not promise immediate old-session recovery.

Concurrent registration can return MariaDB snapshot conflicts as HTTP 508. The test retries only that explicit rolled-back result. Ambiguous network failures are not automatically retried.

Central's existing Redis Queue at `13381` is unavailable. The live integration scenario uses its own temporary Redis Unix socket through a subprocess-only environment override. This is not evidence that the original Central workload's queue is healthy.

The byte relay preserves TLS and application credentials but does not preserve a real client source-address contract at the WSGI backend. These tests do not validate proxy CIDR rules, browser/Desk sessions, customer realtime, external callbacks, actual regional service tokens, outbound Central integration clients or backend-bypass protection.

The management app disables Socket.IO entirely. Its polling/upgrade denial tests do not prove functioning authenticated realtime.

The suite runs on one machine with loopback UDP endpoints. Earlier NAT experiments are separate evidence; there is no actual cross-region acceptance or fleet-scale load test here. The systemd unit files remain proposed, not active deployment-tested units. No Datum collector or Insights/Raven notification pipeline is implemented.

## Cleanup and artifacts

The test runner creates fresh fixture users, using an explicit run ID, and removes only those users. Private keys and API credentials are temporary and do not enter result artifacts. The generated result files contain booleans and source hashes and are ignored by Git.

The reusable VPN bench/site/database and its separate Redis process remain available. Central test users and its additional server/relays/Redis are temporary. Existing `wg0`, the three original VM/management namespaces and application services are preserved. No source changes were made in Central, Atlas, Cargo or Pilot, and local commits preserve the two implementations; no push was made.
