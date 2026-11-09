"""Lab-only barriers around real updater operations, killed by the test parent."""
import argparse
import json
import os
from pathlib import Path
import signal
import sys

from internal_vpn import host

parser = argparse.ArgumentParser()
parser.add_argument('--marker', type=Path, required=True)
parser.add_argument('--phase', choices=('remove', 'report'), required=True)
args, remaining = parser.parse_known_args()
sys.argv = [sys.argv[0], *remaining]


def pause():
    temporary = args.marker.with_suffix('.tmp')
    temporary.write_text(json.dumps({'pid': os.getpid(), 'phase': args.phase}))
    temporary.replace(args.marker)
    while True:
        signal.pause()


original_wg = host.wg
original_request = host.Controller.request


def wg(local, *arguments):
    result = original_wg(local, *arguments)
    if args.phase == 'remove' and arguments[0] == 'set' and arguments[-1] == 'remove':
        pause()
    return result


def request(self, method, data, post=False):
    if args.phase == 'report' and method == 'report' and data.get('success') is True:
        pause()
    return original_request(self, method, data, post)


host.wg = wg
host.Controller.request = request
host.main()
