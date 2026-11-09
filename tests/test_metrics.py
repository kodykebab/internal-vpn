import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from internal_vpn.metrics import collect, main, numeric_rows, probe, unit_result
from test_host import key


class MetricTests(unittest.TestCase):
    def setUp(self):
        self.local = dict(name='hub', interface='ivpn0', public_key=key(1),
                          address='100.100.64.1', subnet='100.100.64.0/24', token='never-print-me')

    def test_measurements_have_no_secrets_and_no_mutating_commands(self):
        with patch('internal_vpn.metrics.wg', side_effect=[key(1), key(2)+' 90\n'+key(3)+' 0',
                   key(2)+' 100 200\n'+key(3)+' 0 0', key(1)]) as wg, patch('time.time', return_value=100):
            result = collect(self.local)
        by_key = {peer['public_key']: peer for peer in result['peers']}
        self.assertEqual(by_key[key(2)]['handshake_age_seconds'], 10)
        self.assertIsNone(by_key[key(3)]['handshake_age_seconds'])
        self.assertEqual(by_key[key(2)]['rx_bytes'], 100)
        self.assertNotIn(self.local['token'], json.dumps(result))
        self.assertEqual([c.args[1:] for c in wg.call_args_list], [
            ('show', 'ivpn0', 'public-key'), ('show', 'ivpn0', 'latest-handshakes'),
            ('show', 'ivpn0', 'transfer'), ('show', 'ivpn0', 'public-key')])

    def test_future_handshake_is_not_reported_as_zero_age(self):
        with patch('internal_vpn.metrics.wg', side_effect=[key(1), key(2)+' 101', key(2)+' 1 2', key(1)]), patch('time.time', return_value=100):
            self.assertIsNone(collect(self.local)['peers'][0]['handshake_age_seconds'])

    def test_changed_membership_or_identity_fails_collection(self):
        for values in ([key(9)], [key(1), key(2)+' 10', '', key(1)], [key(1), '', '', key(9)]):
            with patch('internal_vpn.metrics.wg', side_effect=values), self.assertRaises(ValueError):
                collect(self.local)

    def test_probes_reject_outside_subnet_and_non_addresses_before_reading_interface(self):
        for address in ('1.1.1.1', 'example.com', '100.100.64.0', '100.100.64.255', '100.100.64.1', '100.100.64.2;id'):
            with patch('internal_vpn.metrics.wg') as wg, self.assertRaises(ValueError):
                collect(self.local, [address])
            wg.assert_not_called()

    def test_probe_distinguishes_no_reply_execution_error_and_latency(self):
        for code, output, reachable in ((0, '64 bytes time=1.25 ms', True), (1, '', False)):
            with patch('subprocess.run', return_value=SimpleNamespace(returncode=code, stdout=output)) as run:
                result = probe(self.local, '100.100.64.2')
            self.assertEqual(result['reachable'], reachable)
            self.assertEqual(result['rtt_ms'], 1.25 if reachable else None)
            self.assertIn('ivpn0', run.call_args.args[0])
        with patch('subprocess.run', return_value=SimpleNamespace(returncode=2, stdout='')), self.assertRaises(ValueError):
            probe(self.local, '100.100.64.2')

    def test_malformed_numeric_rows_fail(self):
        for raw in (key(2)+' -1', key(2)+' nan', key(2)+' 1 2', key(2)+' 1\n'+key(2)+' 2'):
            with self.assertRaises(ValueError):
                numeric_rows(raw, 1)

    def test_unit_result_does_not_report_never_run_as_success(self):
        output = 'LoadState=loaded\nActiveState=inactive\nResult=success\nExecMainStatus=0\nExecMainCode=0\nExecMainExitTimestampMonotonic=0\n'
        for state in ('inactive', 'activating'):
            with self.subTest(state=state), patch('subprocess.run', return_value=SimpleNamespace(stdout=output.replace('ActiveState=inactive', 'ActiveState=' + state))):
                result = unit_result('internal-vpn-update.service')
                self.assertIsNone(result['last_result'])
                self.assertIsNone(result['last_exit_status'])
                self.assertEqual(result['active_state'], state)
        with patch('subprocess.run', return_value=SimpleNamespace(stdout=output.replace('loaded','not-found'))), self.assertRaises(ValueError):
            unit_result('missing.service')

    def test_cli_errors_are_sanitized(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'config.json'
            path.write_text(json.dumps(self.local))
            output = io.StringIO()
            with patch('sys.argv', ['run-metrics.py','--config',str(path)]), patch('os.geteuid', return_value=0), \
                 patch('pathlib.Path.stat', return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)), \
                 patch('internal_vpn.metrics.collect', side_effect=OSError('never-print-me')), patch('sys.stdout', output), self.assertRaises(SystemExit):
                main()
            self.assertEqual(json.loads(output.getvalue()), {'ok': False, 'error': 'Measurement collection failed'})
