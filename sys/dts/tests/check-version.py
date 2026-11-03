#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check the generated C macro against its declared device-tree property."""
import argparse
from pathlib import Path
import re

parser = argparse.ArgumentParser()
parser.add_argument('--source', type=Path, required=True)
parser.add_argument('--header', type=Path, required=True)
args = parser.parse_args()
properties = re.findall(r'^\s*freebsd,dts-version\s*=\s*("(?:[^"\\]|\\.)*");\s*$',
                        args.source.read_text(), re.MULTILINE)
if len(properties) != 1:
    raise SystemExit('expected one declared device-tree version property')
expected = '#define LINUX_DTS_VERSION ' + properties[0] + '\n'
if args.header.read_text() != expected:
    raise SystemExit('generated kernel macro differs from the device-tree version')
