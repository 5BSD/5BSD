#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Stage the declared Bazel C/C++ toolchain package shared by the pilot probes."""
import json
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent
TOOLS = ('clang', 'ld.lld', 'llvm-ar', 'llvm-nm', 'llvm-objcopy', 'llvm-strip')
STARLARK = ('cc_toolchain_config.bzl', 'bsd_component.bzl', 'bsd_generate.bzl', 'bsd_cc.bzl')


def stage_toolchain(tc, sysroot, objdump, awk, target, cpu, clang_version):
    """Copy the SDK and tools into workspace package `tc` and write its BUILD file.

    Development-header links are materialized into declared input files.
    Library links stay inside the copied complete runtime/SDK directories and
    must not escape the staged tree.
    """
    tc.mkdir()
    for directory in ('usr/include', 'usr/lib', 'lib'):
        shutil.copytree(sysroot / directory, tc / 'sysroot' / directory,
                        symlinks=(directory != 'usr/include'))
    for path in (tc / 'sysroot').rglob('*'):
        if path.is_symlink():
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(tc / 'sysroot'):
                raise ValueError('SDK link escapes staged tree: ' + str(path))
    (tc / 'bin').mkdir()
    for name in TOOLS:
        shutil.copy2(sysroot / 'usr/bin' / name, tc / 'bin' / name)
    shutil.copy2(objdump, tc / 'bin/llvm-objdump')
    shutil.copy2(awk, tc / 'bin/awk')
    for name in STARLARK:
        shutil.copy2(HERE / name, tc / name)
    config = ('bsd_cc_config(name="config", target=%s, cpu=%s, clang_version=%s)\n' %
              tuple(json.dumps(x) for x in (target, cpu, clang_version)))
    (tc / 'BUILD.bazel').write_text(
        'load(":cc_toolchain_config.bzl", "bsd_cc_config")\n'
        'package(default_visibility=["//visibility:public"])\n'
        'filegroup(name="inputs", srcs=glob(["bin/**", "sysroot/**"]))\n'
        'filegroup(name="compile_inputs", srcs=["bin/clang"] + glob(["sysroot/usr/include/**", "sysroot/usr/lib/clang/**"]))\n'
        'filegroup(name="link_inputs", srcs=["bin/clang", "bin/ld.lld"] + glob(["sysroot/usr/lib/**", "sysroot/lib/**"]))\n'
        'filegroup(name="archive_inputs", srcs=["bin/llvm-ar"])\n'
        'filegroup(name="objcopy_inputs", srcs=["bin/llvm-objcopy"])\n'
        'filegroup(name="strip_inputs", srcs=["bin/llvm-strip"])\n'
        'filegroup(name="empty")\n' + config +
        'cc_toolchain(name="compiler", toolchain_identifier="bsd-staged-clang", '
        'toolchain_config=":config", all_files=":inputs", compiler_files=":compile_inputs", as_files=":compile_inputs", '
        'linker_files=":link_inputs", ar_files=":archive_inputs", objcopy_files=":objcopy_inputs", '
        'strip_files=":strip_inputs", dwp_files=":empty", supports_param_files=1)\n'
        'cc_toolchain_suite(name="suite", toolchains={%s: ":compiler"})\n' % json.dumps(cpu))


def build_flags(cpu, jobs):
    """Bazel options selecting only the staged toolchain."""
    return ['--jobs=' + str(jobs), '--noshow_progress',
            '--action_env=PATH=/bin:/usr/bin', '--subcommands',
            '--crosstool_top=//toolchain:suite', '--cpu=' + cpu,
            '--host_crosstool_top=//toolchain:suite', '--host_cpu=' + cpu]


# The source tree's own (native) Bazel files.  The probes declare their
# targets in their overlay (targets/), so these are left out when component
# directories are copied into a probe workspace; the probes still refuse a
# workspace in which any other Bazel file appears.
SOURCE_BAZEL_FILES = ('BUILD', 'BUILD.bazel', '*.bzl', 'WORKSPACE', 'WORKSPACE.bazel',
                      'MODULE.bazel')
