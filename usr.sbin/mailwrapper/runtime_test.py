# SPDX-License-Identifier: BSD-2-Clause
"""Exercise mailwrapper's real existing LOCALBASE configuration interface.

Every case supplies an existing private mailer.conf; none may enter the host
/etc/mail or default-MTA fallback. No messages are submitted to an MTA.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(os.environ["TEST_SRCDIR"]) / os.environ["TEST_WORKSPACE"]
PROGRAM = ROOT / "usr.sbin/mailwrapper/mailwrapper"
ECHO = ROOT / "bin/echo/echo"
LIBRARIES = [ROOT / name for name in ("lib/libutil", "lib/libc", "lib/libsys")]


class MailerDispatch(unittest.TestCase):
    def setUp(self):
        self.assertNotEqual(os.geteuid(), 0, "LOCALBASE tests require an unprivileged runner")
        self.temporary = tempfile.TemporaryDirectory(prefix="mailwrapper-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        directory = self.root / "etc/mail"
        directory.mkdir(parents=True)
        self.config = directory / "mailer.conf"
        self.environment = {"PATH": "", "LC_ALL": "C", "LOCALBASE": str(self.root),
                            "LD_LIBRARY_PATH": ":".join(map(str, LIBRARIES))}
        self.assertTrue(PROGRAM.is_file())
        self.assertTrue(ECHO.is_file())

    def invoke(self, text, *arguments):
        self.config.write_text(text)
        return subprocess.run(["mailq", *arguments], executable=PROGRAM, cwd=self.root,
            env=self.environment, capture_output=True, text=True, timeout=15)

    def test_dispatch_and_argument_order(self):
        result = self.invoke("# private configuration\n\nmailq " + str(ECHO) + " configured-one configured-two\n",
                             "caller-one", "caller-two")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "configured-one configured-two caller-one caller-two\n")
        self.assertEqual(result.stderr, "")

    def test_unmatched_mapping_is_config_error(self):
        result = self.invoke("sendmail " + str(ECHO) + "\n")
        self.assertEqual(result.returncode, 78, result.stderr)
        self.assertIn("no mapping in " + str(self.config), result.stderr)
        self.assertEqual(result.stdout, "")

    def test_malformed_mapping_is_config_error(self):
        result = self.invoke("mailq\n")
        self.assertEqual(result.returncode, 78, result.stderr)
        self.assertIn("parse error in " + str(self.config), result.stderr)
        self.assertEqual(result.stdout, "")

    def test_explicit_missing_target_is_exec_error(self):
        target = self.root / "missing-mailer"
        result = self.invoke("mailq " + str(target) + "\n")
        self.assertEqual(result.returncode, 71, result.stderr)
        self.assertIn("cannot exec " + str(target), result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
