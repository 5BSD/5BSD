#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Run unprivileged qualification against the declared Bazel helpers."""
import os
from pathlib import Path
import subprocess
import sys

kit = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE'] / 'tools/test/bhyve-hosttest'
# Local FreeBSD test: shell fixtures use base utilities including /sbin/sha256.
env = dict(os.environ, SRTOOL=str(kit / 'srtool'),
           PATH='/bin:/usr/bin:/sbin:/usr/sbin')
subprocess.run([sys.executable, '-B', str(kit / 'lib/coverage-test.py')], env=env, check=True)
subprocess.run([sys.executable, '-B', str(kit / 'lib/l2-console-test.py'), str(kit / 'l2-console')], env=env, check=True)
