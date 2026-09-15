#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Fetch pinned Pi radio firmware; image creation itself stays offline."""
import argparse
import hashlib
from pathlib import Path
import urllib.parse
import urllib.request

MANIFEST = Path(__file__).with_name('rpi-wifi-firmware.tsv')
REVISION = 'c91cd2804cf7463aab913e7247c176049f16bbd6'
BASE = 'https://raw.githubusercontent.com/RPi-Distro/firmware-nonfree/' + REVISION + '/'

def fetch(destination, board):
    destination.mkdir(parents=True, exist_ok=True)
    for line in MANIFEST.read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        owner, name, digest, source = line.split()
        if board != 'all' and owner not in ('all', board):
            continue
        target = destination / name
        if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == digest:
            continue
        with urllib.request.urlopen(BASE + urllib.parse.quote(source, safe='/'), timeout=60) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('Firmware checksum mismatch: ' + name)
        temporary = destination / (name + '.tmp')
        temporary.write_bytes(data)
        temporary.replace(target)
        print(name)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--board', choices=['all', 'rpi4', 'rpi-zero2'], default='all')
    args = parser.parse_args()
    fetch(args.destination, args.board)
