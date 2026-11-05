#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise console lifetime without a VM or privileged probes."""
import os
from pathlib import Path
import subprocess

root = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
kit = root / 'tests/sys/kern/vsock_e2e'
subprocess.run(['/bin/sh', str(kit / 'console-lifetime-selftest.sh'),
                str(kit / 'acmd-console.sh')], check=True)
