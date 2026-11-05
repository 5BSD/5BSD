# SPDX-License-Identifier: BSD-2-Clause
"""Configured rescue dispatcher and basic private-input behavior.

The configuration is an explicit declared input, not inferred from whichever
programs happened to build. Independent Make audits verify the selection itself.
"""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys
import unittest

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--dtrace", choices=["yes", "no"], required=True)
OPTIONS, remaining = parser.parse_known_args()
sys.argv = [sys.argv[0]] + remaining

ROOT = Path(os.environ["TEST_SRCDIR"]) / os.environ["TEST_WORKSPACE"]
PROGRAM = ROOT / "rescue/rescue/rescue_core"
CONFIG = ROOT / "rescue/rescue/core_dispatch.generated/rescue_core.conf"

class ConfiguredRescue(unittest.TestCase):
    def run_app(self, *args, data=b""):
        return subprocess.run([str(PROGRAM), *args], input=data,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            env=dict(os.environ, DTRACE_DOF_INIT_DISABLE="1", LC_ALL="C"), check=False)

    def test_configured_inventory(self):
        expected = []
        for line in CONFIG.read_text().splitlines():
            fields = shlex.split(line)
            if fields[0] == "progs":
                expected.extend(fields[1:])
            elif fields[0] == "ln":
                expected.extend(fields[2:])
        self.assertEqual(len(expected), len(set(expected)))
        p = self.run_app("--list")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.split(), [name.encode() for name in expected])

    def test_application_provider_selection(self):
        providers = []
        for line in CONFIG.read_text().splitlines():
            fields = shlex.split(line)
            if fields[:1] == ["special"] and fields[2] == "objs":
                providers.extend(name for name in fields[3:] if name.endswith("_provider.o"))
        if OPTIONS.dtrace == "no":
            self.assertEqual(providers, [])
        else:
            self.assertTrue(providers)

    def test_shell_builtin(self):
        p = self.run_app("sh", "-c", "printf '%s\\n' rescue-configured")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"rescue-configured\n", b""))

    def test_binary_stdin(self):
        data = bytes(range(256)) * 8
        p = self.run_app("cat", data=data)
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, data, b""))

    def test_compression_roundtrip(self):
        data = b"configured rescue\n" * 100
        compressed = self.run_app("gzip", "-cn", data=data)
        self.assertEqual(compressed.returncode, 0, compressed.stderr)
        result = self.run_app("gunzip", "-c", data=compressed.stdout)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, data, b""))

if __name__ == "__main__":
    unittest.main()
