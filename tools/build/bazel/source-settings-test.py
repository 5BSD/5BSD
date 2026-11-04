#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Typed source setting serialization, without accepting native flag injection."""
import unittest
import copy
from userland_sdk import verify_profile
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


class StandalonePlatformTest(unittest.TestCase):
    def receipt(self):
        return {'format': 1, 'target': 'x86_64-unknown-freebsd16.0',
                'freestanding_toolchains': 1, 'snapshot': {
                    'toolchain/BUILD.bazel': 'a'*64,
                    'toolchain/cc_toolchain_config.bzl': 'b'*64}}

    def test_native_sdk_targets_keep_native_execution(self):
        for arch in ['amd64', 'aarch64', 'riscv64']:
            label = '@bsd_sdk//toolchain:standalone_' + arch
            self.assertEqual(platform_arguments({'target-kind':'standalone'}, arch, self.receipt()),
                ['--platforms='+label, '--host_platform=@bsd_sdk//toolchain:native',
                 '--extra_toolchains='+label+'_registered'])

    def test_old_or_incomplete_capability_rejected(self):
        for value in [None, False, True, 0, 2, '1']:
            receipt = dict(self.receipt(), freestanding_toolchains=value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                platform_arguments({'target-kind':'standalone'}, 'amd64', receipt)
        for receipt in [None, dict(self.receipt(), snapshot={})]:
            with self.assertRaises(ValueError):
                platform_arguments({'target-kind':'standalone'}, 'amd64', receipt)

    def test_foreign_or_unbound_composite_sdk_rejected(self):
        for arch in ['aarch64', 'riscv64']:
            receipt = dict(self.receipt(), target=arch+'-unknown-freebsd16.0')
            for selected in ['amd64', arch]:
                with self.subTest(arch=arch,selected=selected), self.assertRaises(ValueError):
                    platform_arguments({'target-kind':'standalone'}, selected, receipt)


class CrossUserlandSDKTest(unittest.TestCase):
    def receipt(self, arch):
        host = {'workspace':'/usr/obj/sdk/workspace', 'receipt':'/usr/obj/sdk/toolchain-inputs.json',
                'receipt_sha256':'a'*64, 'snapshot_sha256':'b'*64}
        return {'format':2, 'target':arch+'-unknown-freebsd16.0',
                'execution_target':'x86_64-unknown-freebsd16.0', 'execution_sdk':host,
                'inputs':{host['receipt']:host['receipt_sha256']},
                'snapshot':{'toolchain/host/'+name:'c'*64 for name in
                            ['BUILD.bazel','cc_toolchain_config.bzl','bin/clang']}}

    def test_cross_target_and_native_execution_platforms(self):
        for arch in ['aarch64','riscv64']:
            self.assertEqual(platform_arguments({},arch,self.receipt(arch)),[
                '--platforms=@bsd_sdk//toolchain:' + arch,
                '--host_platform=@bsd_sdk//toolchain:native',
                '--extra_toolchains=@bsd_sdk//toolchain/host:registered'])

    def test_incomplete_or_foreign_execution_receipt_rejected(self):
        for arch in ['aarch64','riscv64']:
            original=self.receipt(arch)
            changes=[{'format':1}, {'execution_target':original['target']},
                     {'snapshot':{}}, {'inputs':{}}, {'execution_sdk':{}},
                     {'target':'x86_64-unknown-freebsd16.0'}]
            for change in changes:
                with self.subTest(arch=arch,change=change), self.assertRaises(ValueError):
                    platform_arguments({},arch,dict(copy.deepcopy(original),**change))

    def test_native_receipt_cannot_select_foreign_target(self):
        receipt={'format':1,'target':'x86_64-unknown-freebsd16.0'}
        self.assertEqual(platform_arguments({},'amd64',receipt), platform_arguments({},'amd64'))
        for arch in ['aarch64','riscv64']:
            with self.subTest(arch=arch), self.assertRaises(ValueError):
                platform_arguments({},arch,receipt)

    def test_kernel_profiles_keep_native_execution_sdk(self):
        native={'format':1,'target':'x86_64-unknown-freebsd16.0'}
        for arch in ['amd64','aarch64','riscv64']:
            self.assertEqual(platform_arguments({'target-kind':'kernel'},arch,native),
                             platform_arguments({'target-kind':'kernel'},arch))

    def test_kernel_composite_sdk_keeps_target_and_execution_separate(self):
        for arch in ['aarch64','riscv64']:
            expected = platform_arguments({'target-kind':'kernel'}, arch)
            self.assertEqual(platform_arguments({'target-kind':'kernel'},arch,self.receipt(arch)),
                             expected + ['--extra_toolchains=@bsd_sdk//toolchain/host:registered'])

    def test_kernel_mismatched_or_incomplete_composite_sdk_rejected(self):
        for arch in ['aarch64','riscv64']:
            original=self.receipt(arch)
            other='riscv64' if arch=='aarch64' else 'aarch64'
            for selected in ['amd64', other]:
                with self.subTest(arch=arch,selected=selected), self.assertRaises(ValueError):
                    platform_arguments({'target-kind':'kernel'},selected,original)
            for change in [{'format':1}, {'execution_target':original['target']},
                           {'snapshot':{}}, {'inputs':{}}, {'execution_sdk':{}}]:
                with self.subTest(arch=arch,change=change), self.assertRaises(ValueError):
                    platform_arguments({'target-kind':'kernel'},arch,dict(copy.deepcopy(original),**change))

    def test_recorded_world_pair_requires_explicit_selection(self):
        for name,machine,machine_arch in [('amd64','amd64','amd64'),
                ('aarch64','arm64','aarch64'),('riscv64','riscv','riscv64')]:
            values={'TARGET':machine,'TARGET_ARCH':machine_arch}
            verify_profile(values,name)
            if name != 'amd64':
                with self.assertRaises(ValueError):verify_profile(values)
            with self.assertRaises(ValueError):
                verify_profile(dict(values,TARGET='amd64' if machine!='amd64' else 'arm64'),name)


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
