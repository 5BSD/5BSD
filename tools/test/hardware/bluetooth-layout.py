#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check selected ports' firmware placement against base loader/devd contracts.

Reads make metadata only; does not build packages, load firmware or qualify devices.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--ports', type=Path, required=True)
    parser.add_argument('--osversion', type=int, required=True)
    args = parser.parse_args()
    rows = []
    for tool, port in (('iwmbtfw', 'iwmbt-firmware'), ('rtlbtfw', 'rtlbt-firmware')):
        directory = args.source / 'usr.sbin/bluetooth' / tool
        source = directory / 'main.c'
        defaults = re.findall(r'^#define\s+_DEFAULT_\w+_FIRMWARE_PATH\s+"([^"]+)"',
                              source.read_text(), re.M)
        if len(defaults) != 1:
            raise ValueError('ambiguous loader firmware default: ' + tool)
        destination = defaults[0].rstrip('/')
        if not destination.startswith('/usr/share/firmware/'):
            raise ValueError('firmware default is outside system firmware tree')
        portdir = args.ports / 'comms' / port
        command = ['make', '-C', str(portdir), '__MAKE_CONF=/dev/null',
                   'OSVERSION=' + str(args.osversion), 'BATCH=yes']
        values = subprocess.check_output(command + ['-V', '${DATADIR}',
                    '-V', '${PKGVERSION}', '-V', '${PLIST_DIRS}'], text=True).splitlines()
        if len(values) != 3 or values[0] != destination:
            raise ValueError('package and loader firmware directories disagree: ' + port)
        if destination not in values[2].split():
            raise ValueError('package does not declare firmware directory: ' + port)
        config = directory / (tool + '.conf')
        actions = re.findall(r'action\s+"([^"\n]+)"\s*;', config.read_text())
        if not actions or any(a != '/usr/sbin/' + tool + ' -d $cdev' for a in actions):
            raise ValueError('devd action overrides or bypasses loader default: ' + tool)
        plist = portdir / 'pkg-plist'
        payloads = [line for line in plist.read_text().splitlines() if line and not line.startswith('@')]
        if not payloads or any(not line.startswith('%%DATADIR%%/') for line in payloads):
            raise ValueError('firmware plist has payload outside declared destination: ' + port)
        rows.append(dict(port='comms/' + port, version=values[1], destination=destination,
                         payload_count=len(payloads), devd_action_count=len(actions),
                         source_sha256={str(p):hashlib.sha256(p.read_bytes()).hexdigest()
                                        for p in (source, config, portdir/'Makefile', plist)}))
    print(json.dumps(dict(result='PASS', scope='source and ports metadata contract',
                         packages_built=False, runtime_qualified=False, cases=rows), indent=2))


if __name__ == '__main__':
    main()
