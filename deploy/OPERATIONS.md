# Enrollment and key operations

These procedures use the existing management API and host provisioning. They add no rotation daemon, parallel credential store, automatic rollback or failover. Use authenticated HTTPS, keep secrets in protected files or a credential manager, and never put private keys or API tokens in Git, command arguments or shared logs.

API methods below are under `/api/method/internal_vpn.api.`; Frappe wraps successful results in `message`. See [the API contract](../README.md#control-plane-contract) and [host installation](README.md). Address allocation is automatic within the initialized pool. Do not manually edit membership DocTypes.

## Enroll an engineer device

1. An administrator provisions the approved person's Frappe account with `VPN Engineer` in the separate VPN app. An ordinary Central/customer login is insufficient; employee identity integration remains separate debt.
2. Generate the WireGuard private key on the engineer device using its normal WireGuard tooling. Retain the private key locally and derive its public key.
3. As the engineer, POST `register` with `kind: "Device"` and `public_key`. Save the returned peer `name` and allocated `address`.
4. GET `configuration` with that `name` using the same engineer identity. Verify the returned identity, allocated subnet, and hub public key against trusted enrollment information. Configure the device with its local private key, assigned address, the single hub peer, hub UDP endpoint, and only the allocated subnet as AllowedIPs. Use persistent keepalive for a device behind NAT, as in the lab's 25-second configuration. Do not configure a default Internet route.
5. Wait for the hub to apply membership, then verify a VPN path and an authenticated application request. VPN enrollment does not grant Central application roles or log the user into Central.

Devices currently require manual local configuration; the root updater is for service identities and reports application only for services. No device installer, desktop application or authenticated realtime UI is supplied. Keep the peer name so changes affect the existing device instead of enrolling duplicates after an ambiguous timeout.

## Enroll a service spoke

1. Provision one dedicated enabled Frappe user with `VPN Host` and its normal API credential.
2. Generate the private key on the service host. As VPN Manager, POST `register` with `kind: "Service"`, that user's identifier, and the public key. Spokes do not need published endpoints.
3. Install the assigned address/route and a root-owned configuration with the returned identity, `topology: "spoke"`, and the pinned hub public key. Install the updater as described in [README.md](README.md).
4. Apply the hub and spoke configurations, verify their current acknowledgements and then test actual traffic. Keep the API reachable before tunnel establishment.

## Remove a member

POST `update_peer` with `name` and `enabled: 0`, using VPN Manager authority or the engineer's authority over their own device. Confirm the hub applies its desired membership (`hub_current`) and that the removed key is absent; check actual denial where available. Other spokes need no membership update.

Stopping a timer, deleting an API credential or losing a configuration report is not network revocation. Disabling an owner/removing their required VPN role also removes their active membership when the hub reconciles. For a service retirement, optionally drain its local peers before removing its local provisioning. Disabled records retain their addresses; do not reclaim them manually. An authorized engineer can enroll another device, so disabling one device is not an account ban.

## Rotate an engineer or service WireGuard key

Rotation is a coordinated operation and can interrupt the member's connectivity. The existing implementation has one key per member, without overlapping old/new keys.

1. Generate the replacement key locally. Keep the existing record and address.
2. POST `update_peer` with that record's `name` and replacement `public_key`, using the engineer owner for a device or VPN Manager for a service.
3. Apply the hub's new membership and confirm the old key is absent. The member's old key then loses access.
4. Provision the replacement private key locally. For a service, also replace the root-owned configuration's own `public_key`; preserve its name/address/subnet and revision watermark. Use a protected temporary configuration and atomic replacement while the updater is stopped, then resume it. Update persistent interface provisioning as well as the running interface so a later restart does not restore the old key.
5. Reconcile the service or reconnect the device. Verify a fresh handshake, application connectivity, and (for services) the current report. Remove superseded key material according to the existing host/device secret-management procedure.

A service updater with its old pinned identity rejects the changed snapshot without mutating its peers. Changing only the JSON public key also fails if the live interface still has the old key. Fix the provisioning mismatch; do not reset the watermark.

## Rotate a host API credential

Use Frappe's existing User credential administration/save lifecycle to replace the API secret. No VPN-specific credential endpoint is introduced. The lab exercises a System Manager updating `User.api_secret` through the normal User resource API.

1. Stop the host updater timer and wait for any active invocation to finish. This stops refresh, not the tunnel.
2. Replace the dedicated host user's API secret and securely deliver the new credential to the host.
3. Atomically replace `token` in the root-owned mode-0600 configuration, retaining all network identity/pin fields and the watermark.
4. Run one reconciliation, verify its report and restore the timer. Confirm the old credential can no longer fetch configuration.

Credential-only rotation does not change membership or its revision. An expired credential prevents fetch/report but leaves existing kernel peers in place. If the intent is to revoke network access after a credential compromise, also disable the affected member/owner and verify hub removal. Existing application credentials remain separate from WireGuard keys.

## Reprovision the existing hub key

This procedure changes the key on the same selected hub record and host. It does not switch to a new hub record, provide failover, or promise uninterrupted tunnels during maintenance. The assumption of Central's 100% uptime does not make key replacement atomic across participants.

1. Inventory all enrolled services and engineer devices, including disabled/offline ones, and arrange secure delivery of the new hub public key. Keep management access independent of the VPN.
2. Generate the new private key on the hub. Coordinate updater pauses and device configuration changes so pins and keys can be installed deliberately.
3. As VPN Manager, POST `update_peer` for the existing hub record with the new public key. Existing host reports become stale as their desired configurations change; old local hub identity and spoke pins reject the new snapshots.
4. Replace the hub's persistent/live private key and root-owned own-public-key field. Apply hub configuration, preserving its assigned address, record identity and watermark.
5. Replace every service spoke's root-owned `hub_public_key` pin through trusted provisioning, then reconcile. The updater removes the old hub peer and installs the new one. Engineer devices must replace their hub peer through local WireGuard tooling and reconnect.
6. Verify fresh connectivity and active service acknowledgements. Before re-enabling offline/disabled participants, ensure they also have the new hub pin. Remove old key material through existing secret-management procedures.

A new hub key is deliberately not auto-trusted just because the management API returned it. `set_hub` rejects switching to another record; replacing the host/record or migrating a populated network needs a separate reviewed procedure. Do not clear `VPN Network.hub` directly to bypass this restriction.

## Interrupted updates and acknowledgement

The updater persists its highest accepted revision before modifying peers, removes unwanted peers first, then applies additions/changes and reports. If killed partway through, the kernel may hold a partial desired configuration. There is no automatic rollback; run the normal updater again or let the existing timer do so. It fetches current desired state rather than replaying a cached configuration.

A missing success report does not prove nothing changed. A removed key may already be revoked, or an added peer may already work before its report reaches the server. Use configuration status and live connectivity for their distinct purposes. Preserve the watermark; do not delete it to recover from an interrupted process. The next successful run releases the pending acknowledgement without requiring every unchanged spoke to refresh.

The lab measures direct API-to-ack timings and timer reconciliation separately in `lab-timings.json`. Its loopback measurements do not establish a production deadline; include timer delay, fetch/application/report time, transaction conflicts and failed attempts when defining one.

## Evidence and limits

The Ubuntu scenario verifies service key replacement, old-key connectivity loss, stale-local-identity rejection, API-secret replacement and rejection of the old credential, tunnel persistence during credential failure, and explicit hub rekeying with pin updates. It uses temporary files and kernel interfaces; it does not test a production secret manager, persistent WireGuard provisioning across reboot, or every engineer operating system. Those integrations remain in [INTEGRATION.md](../INTEGRATION.md).
