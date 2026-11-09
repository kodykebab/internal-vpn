# PoC review and verification

## Current evidence

The review uses only `ubuntu-dev`, the VPN app's separate `test.local` database, and Central's existing development `test.local` site. [INTEGRATION.md](INTEGRATION.md) describes the exact Central topology, exercised files and remaining ingress gap.

- **24 focused updater/topology/measurement tests passed**, locally and on Ubuntu.
- **157 live expected-result checks passed** in the expanded run, which covers the real VPN API/database, root updater, WireGuard namespaces and actual Central HTTPS backend. See `lab-results.json` for individual observations and `central-results.json` for Central results/source hashes.
- **11 existing Central integration tests passed in the preceding review (not rerun for this topology change):** 3 in `central.tests.test_guards`, 8 in `central.tests.test_iam`.

A bootstrap rerun also preserved the existing Administrator password hash and network revision. Python syntax, JSON, Markdown links/fences and whitespace checks passed.

Expected-result checks include observed shortcomings and cleanup. In particular, non-VPN Central admin access is recorded as a gap; hub-only retirement now passes. A successful test run does not mean those issue requirements are satisfied.

Runtime: application Python 3.14.6, updater Python 3.12.3, Linux `6.8.0-142-generic`, wireguard-tools `1.0.20210914`, Frappe checkout HEAD `249b5f0f481989f7481a0244d1b2862d559b165a`. Central's runtime is an unversioned copy; do not attribute its tests to the local checkout. Exact file hashes and the differences are in INTEGRATION.md.

## Commands

On `ubuntu-dev`:

```sh
cd /home/vagrant/internal-vpn
python3 -m unittest discover -s tests -v
/home/vagrant/atlas-stack/bench/env/bin/python lab/verify.py --central --systemd --network
```

Omit `--central` for just the VPN scenario. Omit `--systemd` to skip the eleven runtime-unit checks. Omit `--network` to skip the bounded peer-count and traffic-shaping scenario. Central's existing test commands are in INTEGRATION.md. Frappe tests run only on `test.local`.

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

## Systemd lifecycle coverage

The optional `--systemd` scenario exercises the supplied service/timer templates with unique runtime paths on Ubuntu systemd 255. It verifies successful sandboxed application, private state creation, denial of application-user credential reads, rejection of unsafe configuration permissions, missing-interface failure, recovery on a timer activation, repair of peer drift, persisted revision state across service restarts, and removal of its runtime units/state.

The unit now uses `StateDirectory` with mode `0700` rather than assuming a pre-created writable path. The timer sets one-second accuracy so the default scheduling slack does not dominate its fifteen-second interval. No additional worker or recovery subsystem was added.

The lifecycle test temporarily moves an addressless disposable spoke interface into the host namespace, leaving host routes untouched, then restores it before the transport checks. The unit's capability and filesystem restrictions are unchanged. It copies the public CA certificate out of the home directory to respect `ProtectHome`. See [deployment notes](deploy/README.md) for exact installation and scope limits. This is not a whole-machine reboot or permanent provisioning test.

## Key and credential lifecycle coverage

The live runner also exercises service key replacement through the management API, hub removal of the old key, failure with stale local identity, and restoration after local key provisioning. Host API-secret rotation uses Frappe's normal User save path: the old credential is rejected, membership revision is unchanged, and an existing tunnel remains usable even though its updater can no longer authenticate. Installing the new token restores reconciliation/reporting.

The final scenario rekeys the same hub record. It verifies old local identity and spoke pins reject the new configuration, old pins cannot reach the rekeyed hub, and explicit reprovisioning restores access while removing the old hub peer. Changing to another hub record is rejected. This does not test a production secret manager, persistent keys across reboot or automated distribution to employee devices.

## Interruption and convergence coverage

The live runner uses a root-owned, lab-only wrapper around the real updater. It pauses immediately after a successful WireGuard peer-removal command, or after application finishes but before sending the success report. The parent sends SIGKILL to that exact process. No production failure flag or recovery worker is introduced.

Checks require the accepted revision to be persisted before either interruption. After interrupted removal, the key stays absent and tunnel access stays revoked; the next normal invocation completes application/reporting. After interruption before reporting, the tunnel can already work while `hub_current` remains false; the next invocation reconciles and acknowledges it. The test also confirms the process lock is released by termination. These are process-crash tests, not power-loss/filesystem durability tests or exhaustive interruption at every instruction.

`lab-timings.json` records three direct API-to-acknowledgement samples each for disabling and re-enabling an existing engineer device, the next-run duration after both interruptions, and one timer-driven peer-drift repair sample. Direct samples include the membership HTTP request and an immediately invoked hub updater through its success report; they exclude the subsequent reachability probe. Timer repair ends when the kernel peer reappears, not when a report is accepted. All measurements use the one-host loopback lab and are observations, not a fleet percentile or revocation SLA. The generated timing artifact contains no credentials and is ignored by Git.

Observed on `ubuntu-dev` in the latest run:

| Measurement | Samples | Seconds |
| --- | --- | --- |
| Direct device revocation, API request through hub acknowledgement | 3 | 0.180, 0.169, 0.174 |
| Direct device re-enablement, API request through hub acknowledgement | 3 | 0.175, 0.179, 0.193 |
| Next normal run after interrupted removal | 1 | 0.147 |
| Next normal run after interruption before reporting | 1 | 0.151 |
| Timer-driven repair of removed spoke peer | 1 | 15.296 |

## Measurement command coverage

Focused tests check the read-only WireGuard command allowlist, cumulative-counter parsing, missing/future handshakes, identity/membership changes during reads, invalid probe targets, no-reply versus probe execution failure, systemd units without retained execution metadata (including an in-progress run whose Result has reset to success) and sanitized errors. Live checks exercise handshake observations, increasing counters after actual traffic, successful VPN probes, revoked-device no-reply, missing-interface collection failure, refusal of outside-subnet probes and successful/failed updater execution outcomes.

The command emits no private keys, API tokens or raw subprocess error bodies. Probe traffic intentionally changes byte counters; sampling never changes configured peers or controller membership. See [METRICS.md](deploy/METRICS.md) for non-atomic sampling, counter resets and the distinction between collection success and service health.

## Bounded scale and network-condition coverage

The optional `--network` scenario registers 64 additional device records through the real API with four concurrent callers. It checks unique allocation/revisions, measures enrollment and hub snapshot/apply/report durations and JSON snapshot size, and confirms unchanged spokes still have one hub peer. It disables the batch, reapplies the hub, and checks removal without refreshing spokes. These additional peers exercise configuration size and reconciliation; they are not 64 independently active machines.

A non-root TCP fixture transfers exactly 2 MiB from one service spoke to another through the hub, checking received length and SHA-256. Three runs use a 20 Mbit/s cap on both spoke egress interfaces: a baseline, 20 ms added delay plus 1% random loss on each spoke, and a reduced hub interface MTU. Queue counters must show actual dropped packets in the loss scenario, and ICMP samples must show the added delay. The reduced-MTU check sets only the hub to 1280, verifies a fitting DF packet passes and an oversized DF packet reports that MTU, then verifies TCP integrity after path-MTU discovery.

The test applies `tc netem` only to the disposable WireGuard interfaces and restores qdiscs/MTUs before continuing. Its impairment is on overlay data packets, not the host UDP underlay or handshake path. `lab-network.json` records timings, sample goodput and configuration sizes; it is ignored by Git. A single shaped flow on one host does not measure maximum hub capacity, CPU saturation, fleet load, NAT behavior or actual WAN performance. No existing host interface, route or global traffic policy is changed.

Observed in the bounded network run:

| Measurement | Result |
| --- | --- |
| Additional device enrollments, four concurrent callers | 64 in 2.235 seconds |
| Per-enrollment request duration, min / median / max (including explicit conflict retries) | 0.038 / 0.153 / 0.336 seconds |
| Hub snapshot with 67 peers | 9,358 JSON bytes; fetched in 0.062 seconds |
| Hub apply/report with 67 peers | 0.321 seconds |
| Disable 64 peers / apply their removal | 1.568 / 0.264 seconds |
| Baseline TCP goodput under 20 Mbit/s shaping | 19.19 Mbit/s |
| TCP goodput with 20 ms delay and 1% loss on each spoke egress | 4.94 Mbit/s; 19 qdisc drops observed |
| ICMP RTT under the impairment | 40.5–40.9 ms for four replies out of five probes |
| TCP goodput with hub MTU 1280 | 19.14 Mbit/s; fitting/oversized DF behavior verified |

Every TCP sample delivered exactly 2 MiB with matching SHA-256. These are single-run observations under an intentional cap, not maximum-throughput or fleet-capacity claims.

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

The suite runs on one machine with loopback UDP endpoints. Earlier NAT experiments are separate evidence; there is no actual cross-region acceptance or fleet-scale load test here. The supplied systemd units are exercised with temporary runtime units and production sandbox restrictions; permanent installation and whole-host boot ordering remain unverified. The local read-only sampler is implemented; no Datum ingestion adapter or Insights/Raven notification pipeline is implemented.

## Consolidation review

The review kept production scope to the local sampler and the two systemd template corrections; the additional scripts remain development fixtures. No new worker, persistent metric store, recovery orchestration or application ingress change was introduced.

A targeted Ubuntu systemd check reproduced a failed oneshot (`Result=exit-code`, exit status 7), followed by a new invocation with `ActiveState=activating`, `Result=success` and a zero exit timestamp. The sampler already treated that timestamp as unknown; the focused regression now explicitly covers the activating state. The temporary review unit was removed. This check does not imply whole-host boot acceptance.

## Repeated-run lab queue cleanup

Repeated User lifecycle tests accumulated 550 framework jobs in the dedicated, workerless VPN Redis and caused Frappe QueueOverloaded errors, including fixture deletion. The lab now empties only that queue before fixtures and around teardown, guarded by the exact `test.local` site, `ivpn_poc` database and `127.0.0.1:16411` queue URL; it refuses cleanup if workers are registered. It does not touch Central's queue or other Redis instances. These discarded fixture jobs are not background-job integration coverage.

## Cleanup and artifacts

The test runner creates fresh fixture users, using an explicit run ID, and removes only those users. Private keys and API credentials are temporary and do not enter result artifacts. The generated result files contain booleans and source hashes and are ignored by Git.

The reusable VPN bench/site/database and its separate Redis process remain available. Central test users and its additional server/relays/Redis are temporary. Existing `wg0`, the three original VM/management namespaces and application services are preserved. No source changes were made in Central, Atlas, Cargo or Pilot, and local commits preserve the two implementations; no push was made.
