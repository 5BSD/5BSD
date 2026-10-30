# SPDX-License-Identifier: BSD-2-Clause
"""Loader build input/planning checks; successful compilation is tested separately."""
from pathlib import Path
import tempfile
import unittest
import loader_build


class LoaderBuild(unittest.TestCase):
    def test_isolated_explicit_profile(self):
        argv, env = loader_build.build_plan('/usr/obj/loader-profile-test', 16)
        self.assertEqual(argv[-1], 'efi-loader')
        for value in ('SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
                      'WITHOUT_LOADER_EFI_TRUST_DB=yes', 'WITH_LOADER_EFI_SECUREBOOT=yes',
                      'WITH_LOADER_VERIEXEC=yes'):
            self.assertIn(value, argv)
        self.assertIn('TRUST_ANCHORS=/usr/obj/loader-profile-test/anchors.pem', argv)
        self.assertEqual(env['MAKEOBJDIRPREFIX'], '/usr/obj/loader-profile-test/obj')
        self.assertNotIn('MAKEFLAGS', env)
        self.assertNotIn('CFLAGS', env)

    def test_unsafe_output_and_jobs(self):
        for output in ('/usr/obj', '/tmp/output', '/usr/obj/../etc/output',
                       '/usr/obj/make${X}', '/usr/obj/a b', 'relative'):
            with self.subTest(output=output), self.assertRaises(ValueError):
                loader_build.build_plan(output, 1)
        for jobs in (0, -1, True, 104858, '16'):
            with self.subTest(jobs=jobs), self.assertRaises(ValueError):
                loader_build.build_plan('/usr/obj/loader-profile-test', jobs)

    def test_private_or_invalid_input_never_copied(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'anchors'
            output = Path('/usr/obj') / ('loader-reject-' + Path(directory).name)
            self.assertFalse(output.exists())
            for payload in (b'-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n',
                            b'-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n',
                            b'not a certificate', b'x' * (4 * 1048576 + 1)):
                source.write_bytes(payload)
                with self.assertRaises(ValueError):
                    loader_build.build(source, output, 1)
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
