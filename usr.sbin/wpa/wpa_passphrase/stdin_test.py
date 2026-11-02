# SPDX-License-Identifier: BSD-2-Clause
"""Passphrase input and echo restoration using pipes and disposable PTYs."""
import argparse
import hashlib
import os
from pathlib import Path
import select
import subprocess
import termios
import time
import unittest

PARSER = argparse.ArgumentParser(add_help=False)
PARSER.add_argument('--program', type=Path)
PARSER.add_argument('--library-directory', action='append', default=[], type=Path)
OPTIONS, TEST_ARGS = PARSER.parse_known_args()
if OPTIONS.program is None:
    ROOT = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
    PROGRAM = ROOT / 'usr.sbin/wpa/wpa_passphrase/wpa_passphrase'
    LIBRARIES = [ROOT / name for name in ['lib/libc', 'lib/libsys', 'lib/libutil',
                 'secure/lib/libssl', 'secure/lib/libcrypto', 'lib/libthr']]
else:
    PROGRAM = OPTIONS.program.resolve(strict=True)
    LIBRARIES = OPTIONS.library_directory
ENV = {'PATH': '', 'LC_ALL': 'C', 'LD_LIBRARY_PATH': ':'.join(map(str, LIBRARIES))}
SSID = 'IEEE'
PASSWORD = 'password'
EXPECTED = hashlib.pbkdf2_hmac('sha1', PASSWORD.encode(), SSID.encode(), 4096, 32).hex()


class Input(unittest.TestCase):
    def setUp(self):
        self.assertNotEqual(os.geteuid(), 0, 'run input cases as an ordinary user')

    def check_psk(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('\tpsk=' + EXPECTED + '\n', result.stdout)
        self.assertIn('\tssid="' + SSID + '"\n', result.stdout)

    def test_argument(self):
        result = subprocess.run([str(PROGRAM), SSID, PASSWORD], env=ENV,
                                capture_output=True, text=True, timeout=10)
        self.check_psk(result)
        self.assertEqual(result.stderr, '')

    def test_pipe(self):
        result = subprocess.run([str(PROGRAM), SSID], env=ENV, input=PASSWORD + '\n',
                                capture_output=True, text=True, timeout=10)
        self.check_psk(result)
        self.assertEqual(result.stderr, '# reading passphrase from stdin\n')

    def test_pipe_eof(self):
        result = subprocess.run([str(PROGRAM), SSID], env=ENV, input='',
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.assertIn('Failed to read passphrase\n', result.stderr)

    def terminal(self, echo, eof=False):
        master, slave = os.openpty()
        child = None
        try:
            initial = termios.tcgetattr(slave)
            self.assertTrue(initial[3] & termios.ICANON)
            initial[3] = initial[3] | termios.ECHO if echo else initial[3] & ~termios.ECHO
            termios.tcsetattr(slave, termios.TCSANOW, initial)
            child = subprocess.Popen([str(PROGRAM), SSID], env=ENV, stdin=slave,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            ready, _, _ = select.select([child.stderr], [], [], 5)
            self.assertTrue(ready, 'child did not announce stdin read')
            self.assertEqual(child.stderr.readline(), '# reading passphrase from stdin\n')
            if echo:
                deadline = time.monotonic() + 5
                while termios.tcgetattr(slave)[3] & termios.ECHO:
                    self.assertIsNone(child.poll(), 'child exited before disabling echo')
                    self.assertLess(time.monotonic(), deadline, 'echo was not disabled')
                    time.sleep(0.01)
            end = initial[6][termios.VEOF]
            os.write(master, end if eof else (PASSWORD + '\n').encode())
            stdout, stderr = child.communicate(timeout=10)
            self.assertEqual(bool(termios.tcgetattr(slave)[3] & termios.ECHO), echo,
                             'terminal echo was not restored')
            if eof:
                self.assertEqual(child.returncode, 1)
                self.assertEqual(stdout, '')
                self.assertEqual(stderr, 'Failed to read passphrase\n')
            else:
                self.check_psk(subprocess.CompletedProcess([], child.returncode, stdout, stderr))
                self.assertEqual(stderr, '')
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.communicate()
            os.close(slave)
            os.close(master)

    def test_tty_echo_on(self):
        self.terminal(True)

    def test_tty_echo_off(self):
        self.terminal(False)

    def test_tty_eof_restores_echo(self):
        self.terminal(True, eof=True)


if __name__ == '__main__':
    unittest.main(argv=[__file__, *TEST_ARGS])
