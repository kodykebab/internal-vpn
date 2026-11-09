"""Read-only, one-shot local measurements. No secrets, scheduling or alert policy."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time

from internal_vpn import validation
from internal_vpn.host import wg


def numeric_rows(raw, width):
    rows = {}
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) != width + 1:
            raise ValueError('Malformed WireGuard measurement')
        key = validation.public_key(fields[0])
        if key in rows or any(not value.isdecimal() for value in fields[1:]):
            raise ValueError('Invalid WireGuard measurement')
        rows[key] = [int(value) for value in fields[1:]]
    return rows


def probe(local, address):
    command = ['ping', '-n', '-c', '1', '-W', '1', '-I', local['interface'], '--', address]
    if local.get('namespace'):
        command = ['ip', 'netns', 'exec', local['namespace'], *command]
    result = subprocess.run(command, capture_output=True, text=True, timeout=3,
                            env=dict(os.environ, LC_ALL='C'))
    # ping's exit 1 is a measured no-reply result; exit 2 is a probe execution error.
    if result.returncode not in (0, 1):
        raise ValueError('Probe could not execute')
    match = re.search(r'time([=<])([0-9.]+) ms', result.stdout) if result.returncode == 0 else None
    if result.returncode == 0 and match is None:
        raise ValueError('Missing probe latency')
    return {'address': address, 'reachable': result.returncode == 0,
            'rtt_ms': float(match[2]) if match else None,
            'rtt_is_upper_bound': match[1] == '<' if match else False}


def unit_result(unit):
    if not re.fullmatch(r'[A-Za-z0-9_.@-]+\.service', unit) or unit.startswith('-'):
        raise ValueError('Invalid local service unit')
    fields = ('LoadState', 'ActiveState', 'Result', 'ExecMainStatus', 'ExecMainCode', 'ExecMainExitTimestampMonotonic')
    result = subprocess.run(['systemctl', 'show', unit, '--property=' + ','.join(fields)],
                            check=True, capture_output=True, text=True, timeout=5)
    values = dict(line.split('=', 1) for line in result.stdout.splitlines())
    if set(values) != set(fields) or values['LoadState'] != 'loaded':
        raise ValueError('Service unit unavailable')
    exited = int(values['ExecMainExitTimestampMonotonic'])
    return {'unit': unit, 'active_state': values['ActiveState'],
            'last_exit_monotonic_us': exited or None,
            'last_result': values['Result'] if exited else None,
            'last_exit_status': int(values['ExecMainStatus']) if exited else None,
            'last_exit_code': int(values['ExecMainCode']) if exited else None}


def collect(local, targets=(), unit=None):
    interface = local['interface']
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}', interface):
        raise ValueError('Invalid local interface')
    network = validation.subnet(local['subnet'])
    own = ipaddress.IPv4Address(local['address'])
    if own not in network or own in (network.network_address, network.broadcast_address):
        raise ValueError('Invalid local address')
    validation.public_key(local['public_key'])
    if len(targets) > 8:
        raise ValueError('At most eight explicit probes per sample')
    addresses = []
    for target in targets:
        address = ipaddress.IPv4Address(target)
        if address not in network or address in (own, network.network_address, network.broadcast_address):
            raise ValueError('Probe requires another usable VPN address')
        addresses.append(str(address))
    if wg(local, 'show', interface, 'public-key') != local['public_key']:
        raise ValueError('Interface identity changed')
    # Never use dump/showconf: they contain private or preshared keys.
    handshakes = numeric_rows(wg(local, 'show', interface, 'latest-handshakes'), 1)
    transfers = numeric_rows(wg(local, 'show', interface, 'transfer'), 2)
    if handshakes.keys() != transfers.keys() or wg(local, 'show', interface, 'public-key') != local['public_key']:
        raise ValueError('Interface membership changed during measurement')
    now = int(time.time())
    peers = []
    for key in sorted(handshakes):
        latest = handshakes[key][0]
        peers.append({'public_key': key, 'last_handshake_unix': latest or None,
                      'handshake_age_seconds': now - latest if 0 < latest <= now else None,
                      'rx_bytes': transfers[key][0], 'tx_bytes': transfers[key][1]})
    return {'ok': True, 'version': 1, 'observed_at_unix': now, 'name': local['name'],
            'interface': interface, 'address': str(own), 'peers': peers,
            'probes': [probe(local, address) for address in addresses],
            'updater': unit_result(unit) if unit else None}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--probe', action='append', default=[], metavar='VPN_IP')
    parser.add_argument('--unit', help='Optional local updater service unit')
    args = parser.parse_args()
    try:
        metadata = args.config.stat()
        if os.geteuid() != 0 or metadata.st_uid != 0 or metadata.st_mode & 0o077:
            raise ValueError('Expected root and a root-only configuration')
        print(json.dumps(collect(json.loads(args.config.read_text()), args.probe, args.unit)))
    except Exception:
        # Do not echo commands, credentials, raw subprocess output or HTTP bodies.
        print(json.dumps({'ok': False, 'error': 'Measurement collection failed'}))
        raise SystemExit(1) from None
