"""Exercise explicit key/credential replacement using existing APIs and provisioning."""
import json
from urllib.parse import urlencode


def verify(directory, host_root, configs, hosts, public_keys, manager_token,
           api, request, run, net, update, ping, check):
    import secrets

    def install_config(index):
        path = directory / f'rotation-host{index}.json'
        path.write_text(json.dumps(configs[index]))
        path.chmod(0o600)
        run('sudo', 'install', '-m', '0600', str(path), str(host_root / f'host{index}.json'))
        path.unlink()

    def new_key(label):
        private = run('wg', 'genkey').stdout.strip()
        public = run('wg', 'pubkey', input=private).stdout.strip()
        path = directory / (label + '.key')
        path.write_text(private)
        path.chmod(0o600)
        return path, public

    def peer_keys(index):
        return set(net(index, 'wg', 'show', 'ivpn0', 'peers').stdout.split())

    # The active second spoke can rotate without changing unrelated peer graphs.
    spoke = configs[4]
    old_key = spoke['public_key']
    keyfile, new_public = new_key('service-rotation')
    api('update_peer', manager_token, {'name': spoke['name'], 'public_key': new_public})
    update(0)
    check('service_rotation_removes_old_key_at_hub', old_key not in peer_keys(0) and new_public in peer_keys(0))
    before = peer_keys(4)
    check('service_rotation_rejects_stale_local_identity', not update(4, expect=False) and peer_keys(4) == before)
    check('service_old_key_loses_connectivity', not ping(4, configs[0]['address']))
    spoke['public_key'] = new_public
    install_config(4)
    net(4, 'wg', 'set', 'ivpn0', 'private-key', str(keyfile))
    update(4)
    check('service_rotation_restores_connectivity', ping(4, configs[0]['address']) and api('status', manager_token, get=True)['all_current'])

    # Rotate only the existing Frappe credential, using the normal User save path.
    old_token = spoke['token']
    new_secret = secrets.token_hex(24)
    revision = api('status', manager_token, get=True)['revision']
    check('host_credential_rotation_saved', request('/api/resource/User/' + hosts[2][0], manager_token,
          {'api_secret': new_secret}, method='PUT')[0] == 200)
    check('credential_rotation_preserves_membership_revision', api('status', manager_token, get=True)['revision'] == revision)
    check('old_host_credential_rejected', request('/api/method/internal_vpn.api.configuration?' +
          urlencode({'name': spoke['name']}), old_token)[0] in (401, 403))
    before = peer_keys(4)
    check('expired_credential_cannot_update_but_keeps_tunnel', not update(4, expect=False) and peer_keys(4) == before and ping(4, configs[0]['address']))
    spoke['token'] = old_token.split(':', 1)[0] + ':' + new_secret
    install_config(4)
    update(4)
    check('replacement_host_credential_applies_and_reports', api('status', manager_token, get=True)['all_current'])

    # Reprovision the same hub identity; this is not replacement/failover to a new record.
    check('hub_record_replacement_rejected', request('/api/method/internal_vpn.api.set_hub', manager_token,
          {'name': spoke['name']})[0] == 417)
    hub = configs[0]
    old_hub_key = hub['public_key']
    keyfile, new_public = new_key('hub-rotation')
    api('update_peer', manager_token, {'name': hub['name'], 'public_key': new_public})
    check('hub_rotation_invalidates_active_reports', not api('status', manager_token, get=True)['all_current'])
    check('hub_rotation_rejects_stale_local_identity', not update(0, expect=False))
    before = peer_keys(4)
    check('hub_rotation_rejected_until_spoke_pin_updated', not update(4, expect=False) and peer_keys(4) == before)
    hub['public_key'] = new_public
    install_config(0)
    net(0, 'wg', 'set', 'ivpn0', 'private-key', str(keyfile))
    update(0)
    check('old_hub_pin_cannot_connect_to_rekeyed_hub', not ping(4, hub['address']))
    spoke['hub_public_key'] = new_public
    install_config(4)
    update(4)
    check('hub_reprovisioning_restores_spoke_connectivity', ping(4, hub['address']) and api('status', manager_token, get=True)['all_current'])
    check('hub_reprovisioning_removes_old_hub_peer', old_hub_key not in peer_keys(4) and peer_keys(4) == {new_public})
