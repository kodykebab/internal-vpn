# Local VPN measurements

`run-metrics.py` is a read-only, one-shot sampler. It reads the root-owned host configuration and live WireGuard interface, optionally sends bounded ICMP probes, and emits one JSON object. It does not call the management API, change peers, read private keys, write state, schedule itself, or send data to another service.

## Run

After installing the files listed in [README.md](README.md):

```sh
sudo python3 /opt/internal-vpn/run-metrics.py --config /etc/internal-vpn/host.json
sudo python3 /opt/internal-vpn/run-metrics.py --config /etc/internal-vpn/host.json --probe 100.100.64.2 --unit internal-vpn-update.service
```

Replace the example probe address with another usable address in the host's allocated subnet. Repeat `--probe` for up to eight explicit targets. DNS names, addresses outside that subnet, the local address and network/broadcast addresses are refused. Probes bind to the configured WireGuard interface, use one ICMP request per target and a one-second reply timeout. ICMP permission and `ping` are required only when probing; the lab-only namespace option uses the existing namespace command path.

No probe runs unless explicitly requested. Targets come from local operator arguments, not from remote management configuration. A scheduled deployment must choose its interval and targets through the existing monitoring owner; no new timer or daemon is supplied.

## Output contract

| Field | Meaning |
| --- | --- |
| `ok`, `version` | Collection outcome and measurement schema version (currently 1; independent of configuration protocol v2) |
| `observed_at_unix` | Host wall-clock time after reading WireGuard counters, before optional probes |
| `name`, `interface`, `address` | Locally pinned service identity and VPN interface/address |
| `peers[].public_key` | Public peer identifier; no private/preshared key or endpoint is emitted |
| `peers[].last_handshake_unix` | Last recorded handshake timestamp, or null if no handshake has occurred |
| `peers[].handshake_age_seconds` | Age at observation; null for no handshake or a timestamp ahead of the host clock |
| `peers[].rx_bytes`, `tx_bytes` | Cumulative WireGuard receive/transmit bytes for the current peer instance, not instantaneous throughput |
| `probes[].address`, `reachable` | Target and whether this ICMP request received a reply |
| `probes[].rtt_ms` | Reported round-trip time, or null for no reply |
| `probes[].rtt_is_upper_bound` | True when ping reports a value such as `time<1 ms` |
| `updater` | Optional local systemd execution result, or null when `--unit` is omitted |
| `updater.active_state` | Current service state at query time |
| `updater.last_result`, `last_exit_status`, `last_exit_code` | systemd's latest completed execution result, status and termination code; null if no completed execution metadata is retained |
| `updater.last_exit_monotonic_us` | Last exit timestamp measured since this boot, or null; do not compare across boots |

A completed sample exits 0 with `ok: true`, even if a probe receives no reply or the updater's last execution failed. These are measured outcomes, not sampler failures. Missing/mismatched interfaces, invalid input, unavailable requested units, probe execution errors or malformed command output exit 1 with a sanitized `ok: false` object. Unknown values are not converted to zero traffic or a healthy result.

The sampler reads only `public-key`, `latest-handshakes` and `transfer`; it never requests WireGuard `dump` or `showconf`. Separate kernel reads are not an atomic snapshot. A detected peer-set/interface-key change fails the sample so the next scheduled collection can retry, but transient removal/readdition with the same key can still reset counters between reads.

## Interpretation and downstream integration

- Handshake age is not application health. An idle engineer laptop can have an old handshake without representing failed infrastructure.
- ICMP reachability and round-trip time are not authenticated application probes, available bandwidth or cross-region acceptance. A firewall can deny ICMP while applications still work.
- Byte counters reset on interface/peer recreation. A downstream rate calculation needs sample timestamps and reset handling; the sampler does not retain counter history.
- systemd execution state is distinct from the management app's configuration acknowledgement. A report can fail after kernel changes succeed, and a successful past execution does not prove current connectivity. A new invocation can clear the previous exit metadata and reset `Result` to `success` before work finishes. A zero exit timestamp therefore remains unknown, including while the service is activating. Systemd can unload an unreferenced inactive oneshot and discard its execution metadata; a zero exit timestamp is treated as unknown, not success. Keep the normal updater timer enabled for operation and use its journal for historical diagnosis.
- WireGuard, ICMP and systemd observations happen sequentially. Do not treat the output as a single atomic health verdict.

Datum ingestion, stable peer-to-record label mapping, collection cadence, retention, thresholds and Insights-to-Raven delivery remain integration work in [INTEGRATION.md](../INTEGRATION.md). The initial sampler supplies observations without inventing health policy or a parallel monitoring service.
