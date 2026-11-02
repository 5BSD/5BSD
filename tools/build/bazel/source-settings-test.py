#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Typed source setting serialization, without accepting native flag injection."""
import unittest
from source_graph import setting_arguments, platform_arguments, execution_log_format


class SettingsTest(unittest.TestCase):
    def test_scalars(self):
        self.assertEqual(setting_arguments({"//cfg:enabled": True, "//cfg:jobs": 16, "//cfg:name": "two words"}),
            ["--//cfg:enabled=true", "--//cfg:jobs=16", "--//cfg:name=two words"])

    def test_false_and_empty(self):
        self.assertEqual(setting_arguments({}), [])
        self.assertEqual(setting_arguments({"//:flag": False}), ["--//:flag=false"])

    def test_invalid_labels(self):
        for key in ("--spawn_strategy", "//cfg:flag=value", "//cfg:flag\n", "@external//cfg:flag", 1):
            with self.subTest(key=key), self.assertRaises(ValueError):
                setting_arguments({key: True})

    def test_invalid_values(self):
        for value in (None, 1.5, [], {}, "newline\n", "nul\0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                setting_arguments({"//cfg:flag": value})

    def test_invalid_container(self):
        for value in ([], None, "--flag"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                setting_arguments(value)


class PlatformTest(unittest.TestCase):
    def test_native_default(self):
        self.assertEqual(platform_arguments({'tests': []}, 'amd64'),
            ['--platforms=@bsd_sdk//toolchain:native', '--host_platform=@bsd_sdk//toolchain:native'])

    def test_kernel_execution_separate(self):
        for arch, platform in [('amd64', 'amd64'), ('aarch64', 'arm64'), ('riscv64', 'riscv64')]:
            flags = platform_arguments({'tests': ['//:host_artifact'], 'target-kind': 'kernel'}, arch)
            self.assertEqual(flags, ['--platforms=//tools/build/bazel/kernel_toolchain:' + platform,
                '--host_platform=@bsd_sdk//toolchain:native',
                '--extra_toolchains=//tools/build/bazel/kernel_toolchain:' + platform + '_registered'])

    def test_unqualified_profiles_rejected(self):
        for config, arch in [({'tests': []}, 'aarch64'), ({'tests': []}, 'riscv64'),
                ({'tests': [], 'target-kind': 'kernel'}, 'powerpc'),
                ({'tests': [], 'target-kind': '--extra_toolchains=//:escape'}, 'amd64')]:
            with self.subTest(config=config, arch=arch), self.assertRaises(ValueError):
                platform_arguments(config, arch)


class ExecutionLogFormatTest(unittest.TestCase):
    def test_default_and_explicit_formats(self):
        self.assertEqual(execution_log_format({}), 'json')
        for value in ('json', 'compact'):
            self.assertEqual(execution_log_format({'execution-log-format': value}), value)

    def test_invalid_formats_rejected(self):
        for value in (None, True, 1, [], {}, 'binary', 'COMPACT', '--execution_log_json_file=/escape'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                execution_log_format({'execution-log-format': value})


if __name__ == "__main__":
    unittest.main()
