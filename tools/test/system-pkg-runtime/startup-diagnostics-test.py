# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""Real reboot failure snippets must not pass normal-system qualification."""
import unittest
from startup_diagnostics import reject_failures


class StartupDiagnostics(unittest.TestCase):
    def test_recorded_service_failures(self):
        # Retained upgrade VM R1, 2026-11-07: authentication passed while these
        # service failures were omitted from the original acceptance checks.
        for message in (
            b"svc_exec system.SystemExtension/bsdextension: runtime container: File exists",
            b"startup: failed to launch 'system.Log/bsdlog'",
            b"on_demand: failed to launch 'system.SystemExtension': Resource temporarily unavailable",
            b"startup: system service launch failed",
            b"runtime cleanup: unlink container: Read-only file system",
        ):
            with self.subTest(message=message), self.assertRaises(RuntimeError):
                reject_failures(b"ordinary boot output\r\n" + message + b"\r\n")

    def test_existing_failure_gates(self):
        for message in (b"panic: test", b"Fatal trap 12", b"lock order reversal:",
                        b"non-sleepable locks held", b"rc: variable: parameter not set"):
            with self.subTest(message=message), self.assertRaises(RuntimeError):
                reject_failures(message)

    def test_normal_startup_and_expected_authentication_refusal(self):
        reject_failures(b"startup: 13 services loaded\nstartup: launched 13 services\n"
                        b"service system.Log/bsdlog: started pid 123 uid 977 gid 977\n"
                        b"Permission denied (publickey,password,keyboard-interactive).\n"
                        b"su: Sorry\nkill: 1: Permission denied\n")


if __name__ == "__main__":
    unittest.main()
