#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Stage the declared Bazel C/C++ toolchain package shared by the pilot probes.

Two Bazel modes share the staged toolchain and Starlark files:

- WORKSPACE mode (default; Bazel 5): native C/C++ rules, the toolchain is
  selected with --crosstool_top/--cpu through a cc_toolchain_suite.
- Bzlmod mode (--bzlmod-inputs; Bazel 9): the workspace has a MODULE.bazel
  that pins rules_cc and platforms, the C/C++ symbols come from rules_cc and
  the toolchain is registered for toolchain resolution on the platform
  //toolchain:native.  Module resolution is offline: it may only use the
  repository cache, distdirs and lockfile named in the inputs file
  (--repository_disable_download, --lockfile_mode=error).  The lockfile is
  not regenerated: `bazel mod deps` evaluates every module extension of the
  dependency graph, including rules_python's pip extension, which needs a
  Python 3.11 toolchain that is not available offline; builds evaluate only
  the extensions their targets need.

cc_compat.bzl / cc_compat_bzlmod.bzl, staged as //toolchain:cc_compat.bzl,
give both modes the same bsd_* symbol names.
"""
import json
import os
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent
TOOLS = ('clang', 'ld.lld', 'llvm-ar', 'llvm-nm', 'llvm-objcopy', 'llvm-strip')
STARLARK = ('cc_toolchain_config.bzl', 'bsd_component.bzl', 'bsd_generate.bzl', 'bsd_cc.bzl')
# Bazel CPU names of the probe targets and their @platforms constraint.
PLATFORM_CPUS = {'k8': 'x86_64', 'aarch64': 'aarch64', 'riscv64': 'riscv64'}


def add_bazel_mode_arguments(parser):
    parser.add_argument('--bzlmod-inputs', type=Path, default=None,
                        help='JSON naming the Bzlmod module pins, lockfile, repository cache, '
                             'distdirs and JAVA_HOME; selects Bzlmod mode (Bazel 9)')


def load_bzlmod_inputs(path):
    """Validate a Bzlmod inputs file; None selects WORKSPACE mode.

    Required keys: modules (name -> version, must include rules_cc and
    platforms), lockfile, repository_cache, distdirs (list) and java_home.
    Every path must exist; nothing is fetched.
    """
    if path is None:
        return None
    data = json.loads(Path(path).read_text())
    for key in ('modules', 'lockfile', 'repository_cache', 'distdirs', 'java_home'):
        if key not in data:
            raise ValueError('bzlmod inputs lack ' + key)
    for name in ('rules_cc', 'platforms'):
        if name not in data['modules']:
            raise ValueError('bzlmod inputs must pin module ' + name)
    for key in ('lockfile', 'repository_cache', 'java_home'):
        data[key] = str(Path(data[key]).resolve(strict=True))
    data['distdirs'] = [str(Path(x).resolve(strict=True)) for x in data['distdirs']]
    data['source'] = str(Path(path).resolve(strict=True))
    return data


def apply_bazel_environment(bzlmod):
    """Bzlmod mode: Bazel's server JDK and no host C/C++ autodetection."""
    if bzlmod:
        os.environ['JAVA_HOME'] = bzlmod['java_home']
        os.environ['BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN'] = '1'


def write_workspace(ws, name, bzlmod):
    """WORKSPACE (Bazel 5) or MODULE.bazel plus the pinned lockfile (Bazel 9)."""
    if not bzlmod:
        (ws / 'WORKSPACE').write_text('workspace(name="%s")\n' % name)
        return
    lines = ['module(name="%s")' % name]
    lines += ['bazel_dep(name="%s", version="%s")' % (module, version)
              for module, version in sorted(bzlmod['modules'].items())]
    lines.append('register_toolchains("//toolchain:registered")')
    (ws / 'MODULE.bazel').write_text('\n'.join(lines) + '\n')
    shutil.copyfile(bzlmod['lockfile'], ws / 'MODULE.bazel.lock')


def stage_toolchain(tc, sysroot, objdump, awk, target, cpu, clang_version, bzlmod=None):
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
    shutil.copy2(HERE / ('cc_compat_bzlmod.bzl' if bzlmod else 'cc_compat.bzl'), tc / 'cc_compat.bzl')
    config = ('bsd_cc_config(name="config", target=%s, cpu=%s, clang_version=%s)\n' %
              tuple(json.dumps(x) for x in (target, cpu, clang_version)))
    head = ''
    tail = 'cc_toolchain_suite(name="suite", toolchains={%s: ":compiler"})\n' % json.dumps(cpu)
    if bzlmod:
        if cpu not in PLATFORM_CPUS:
            raise ValueError('no @platforms CPU for ' + cpu)
        constraints = json.dumps(['@platforms//os:freebsd', '@platforms//cpu:' + PLATFORM_CPUS[cpu],
                                  ':selected_sdk'])
        head = ('load("@rules_cc//cc/toolchains:cc_toolchain.bzl", "cc_toolchain")\n')
        # The constraint keeps toolchain resolution on this staged SDK only.
        tail = ('exports_files(glob(["bin/*"]))\n'
                'constraint_setting(name="sdk_identity")\n'
                'constraint_value(name="selected_sdk", constraint_setting=":sdk_identity")\n'
                'platform(name="native", constraint_values=%s)\n'
                'toolchain(name="registered", toolchain=":compiler", '
                'toolchain_type="@bazel_tools//tools/cpp:toolchain_type", '
                'exec_compatible_with=%s, target_compatible_with=%s)\n' % (constraints, constraints, constraints))
    (tc / 'BUILD.bazel').write_text(
        head +
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
        'strip_files=":strip_inputs", dwp_files=":empty", supports_param_files=1)\n' + tail)


def repository_flags(bzlmod):
    """Offline module inputs: cache and distdirs only, no downloads."""
    return (['--repository_cache=' + bzlmod['repository_cache'], '--repository_disable_download'] +
            ['--distdir=' + x for x in bzlmod['distdirs']])


def query_flags(bzlmod):
    """Loading-phase commands (query) need the same offline module inputs."""
    return (['--lockfile_mode=error'] + repository_flags(bzlmod)) if bzlmod else []


def build_flags(cpu, jobs, bzlmod=None):
    """Bazel options selecting only the staged toolchain."""
    common = ['--jobs=' + str(jobs), '--noshow_progress',
              '--action_env=PATH=/bin:/usr/bin', '--subcommands']
    if bzlmod:
        # Bazel 5 wrote link/archive params files for local actions; Bazel 9
        # writes them only on request, and the probes read them.
        return common + ['--platforms=//toolchain:native', '--host_platform=//toolchain:native',
                         '--extra_execution_platforms=//toolchain:native',
                         '--materialize_param_files',
                         '--lockfile_mode=error'] + repository_flags(bzlmod)
    return common + ['--crosstool_top=//toolchain:suite', '--cpu=' + cpu,
                     '--host_crosstool_top=//toolchain:suite', '--host_cpu=' + cpu]


def mode_record(bzlmod):
    """Receipt fragment naming the Bazel mode and its module inputs."""
    if not bzlmod:
        return {'mode': 'workspace'}
    return {'mode': 'bzlmod', 'modules': bzlmod['modules'], 'inputs_file': bzlmod['source'],
            'lockfile': bzlmod['lockfile'], 'repository_cache': bzlmod['repository_cache'],
            'distdirs': len(bzlmod['distdirs']), 'java_home': bzlmod['java_home'],
            'downloads': 'disabled (--repository_disable_download)'}


# The source tree's own (native) Bazel files.  The probes declare their
# targets in their overlay (targets/), so these are left out when component
# directories are copied into a probe workspace; the probes still refuse a
# workspace in which any other Bazel file appears.
SOURCE_BAZEL_FILES = ('BUILD', 'BUILD.bazel', '*.bzl', 'WORKSPACE', 'WORKSPACE.bazel',
                      'MODULE.bazel')
