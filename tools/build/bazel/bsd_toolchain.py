#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Stage the declared Bazel C/C++ toolchain package shared by the pilot probes.

Bazel 9 or later only, with Bzlmod and rules_cc.  Bazel 5 and the WORKSPACE
mode (native C/C++ rules, --crosstool_top) were removed on 2026-10-30; each
tool checks `bazel --version` first and refuses anything older than 9.

The probe workspace has a MODULE.bazel that pins rules_cc and platforms
(PINNED_MODULES) and a copy of the pinned lockfile bzlmod/MODULE.bazel.lock.
The C/C++ symbols come from rules_cc through cc_compat.bzl (staged as
//toolchain:cc_compat.bzl), and the toolchain is registered for toolchain
resolution on the platform //toolchain:native.

Module resolution is offline.  The offline inputs file (--bzlmod-inputs)
names the repository cache, the distdirs and optionally JAVA_HOME; nothing
is downloaded (--repository_disable_download) and the lockfile is used in
error mode (--lockfile_mode=error).  The lockfile is not regenerated here:
`bazel mod deps` evaluates every module extension of the dependency graph,
including rules_python's pip extension, which needs a Python 3.11
toolchain that is not available offline; builds evaluate only the
extensions their targets need.  See README.md ("Bazel 9 only") for how the
pins, lockfile and cache are refreshed when network access is allowed.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
TOOLS = ('clang', 'ld.lld', 'llvm-ar', 'llvm-nm', 'llvm-objcopy', 'llvm-strip')
STARLARK = ('cc_toolchain_config.bzl', 'bsd_component.bzl', 'bsd_generate.bzl', 'bsd_cc.bzl',
            'cc_compat.bzl')
# Bazel CPU names of the probe targets and their @platforms constraint.
PLATFORM_CPUS = {'k8': 'x86_64', 'aarch64': 'aarch64', 'riscv64': 'riscv64'}
# Where the bazel9 package installs the launcher (devel/bazel9 pkg-plist
# bin/bazel; CONFLICTS_INSTALL bazel[0-9]* keeps one Bazel per system).
DEFAULT_BAZEL = Path('/usr/local/bin/bazel')
MINIMUM_BAZEL_MAJOR = 9
# Module pins of the probe workspaces; bzlmod/MODULE.bazel.lock was
# resolved for them and is copied unchanged into every workspace.
PINNED_MODULES = {'platforms': '1.0.0', 'rules_cc': '0.2.17'}
PINNED_LOCKFILE = HERE / 'bzlmod' / 'MODULE.bazel.lock'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def add_bazel_arguments(parser):
    """--bazel (default /usr/local/bin/bazel) and the required offline inputs."""
    parser.add_argument('--bazel', type=Path, default=DEFAULT_BAZEL,
                        help='Bazel 9 or later executable (default %s)' % DEFAULT_BAZEL)
    parser.add_argument('--bzlmod-inputs', type=Path, required=True,
                        help='JSON naming the offline repository cache, distdirs and '
                             'optional JAVA_HOME (module pins and lockfile are in-tree)')


def check_bazel_version(bazel):
    """Return the version reported by `bazel --version`; refuse Bazel < 9.

    `--version` is answered by the client without starting a server.
    """
    path = Path(bazel)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise SystemExit('Bazel executable not found: %s (install the bazel9 package or pass --bazel)' % path)
    completed = subprocess.run([str(path), '--version'], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
    match = re.fullmatch(r'bazel (\d+)\.(\d+)\.(\d+)\S*\n?', completed.stdout)
    if completed.returncode or not match:
        raise SystemExit('cannot determine the Bazel version of %s: %r' % (path, completed.stdout.strip()))
    version = completed.stdout.split()[1]
    if int(match.group(1)) < MINIMUM_BAZEL_MAJOR:
        raise SystemExit('%s is Bazel %s; these tools require Bazel %d or later with Bzlmod '
                         '(Bazel 5 and the WORKSPACE mode are no longer supported). Install the '
                         'bazel9 package or pass --bazel PATH to a Bazel 9 executable.'
                         % (path, version, MINIMUM_BAZEL_MAJOR))
    return version


def verify_repository_cache(cache):
    """Check a content-addressed repository cache; return its digest.

    Only content_addressable/sha256/<hash>/ entries holding `file` (whose
    SHA-256 must equal <hash>) and empty canonical-id markers `id-*` are
    accepted; Bazel's derived repo contents cache (`contents/`) is ignored
    and not staged.  Links are rejected.
    """
    root = Path(cache) / 'content_addressable' / 'sha256'
    entries = []
    for entry in sorted(root.iterdir()):
        if entry.is_symlink() or not entry.is_dir() or not re.fullmatch(r'[0-9a-f]{64}', entry.name):
            raise ValueError('unexpected repository cache entry: ' + str(entry))
        names = sorted(x.name for x in entry.iterdir())
        if 'file' not in names or any(x != 'file' and not x.startswith('id-') for x in names):
            raise ValueError('unexpected repository cache entry content: ' + str(entry))
        for name in names:
            if (entry / name).is_symlink() or not (entry / name).is_file():
                raise ValueError('repository cache entries must be regular files: ' + str(entry / name))
        if sha(entry / 'file') != entry.name:
            raise ValueError('repository cache entry does not match its SHA-256: ' + str(entry))
        entries.append(entry.name + ' ' + ','.join(names))
    if not entries:
        raise ValueError('empty repository cache: ' + str(cache))
    return hashlib.sha256('\n'.join(entries).encode()).hexdigest(), len(entries)


def verify_distdirs(distdirs):
    """Each distdir holds regular files only; return a digest of name/SHA-256 pairs."""
    listing = []
    for directory in distdirs:
        for path in sorted(Path(directory).iterdir()):
            if path.is_symlink() or not path.is_file():
                raise ValueError('distdirs must hold regular files only: ' + str(path))
            listing.append('%s %s' % (path.name, sha(path)))
    return hashlib.sha256('\n'.join(sorted(listing)).encode()).hexdigest(), len(listing)


def load_bzlmod_inputs(path):
    """Validate the offline inputs file.

    Required: repository_cache, distdirs (list).  Optional: java_home (the
    Bazel server JDK; without it the launcher's built-in default is used,
    /usr/local/openjdk21 for the bazel9 package), and, for older inputs
    files, modules/lockfile, which must then equal the in-tree pins.
    Every path must exist; nothing is fetched.
    """
    data = json.loads(Path(path).read_text())
    for key in ('repository_cache', 'distdirs'):
        if key not in data:
            raise ValueError('bzlmod inputs lack ' + key)
    if 'modules' in data and data['modules'] != PINNED_MODULES:
        raise ValueError('bzlmod inputs pin modules %r; the probes are pinned to %r '
                         '(tools/build/bazel/bsd_toolchain.py)' % (data['modules'], PINNED_MODULES))
    if 'lockfile' in data and sha(data['lockfile']) != sha(PINNED_LOCKFILE):
        raise ValueError('bzlmod inputs name a lockfile that differs from the pinned '
                         + str(PINNED_LOCKFILE))
    result = {'modules': dict(PINNED_MODULES), 'lockfile': str(PINNED_LOCKFILE),
              'lockfile_sha256': sha(PINNED_LOCKFILE),
              'repository_cache': str(Path(data['repository_cache']).resolve(strict=True)),
              'distdirs': [str(Path(x).resolve(strict=True)) for x in data['distdirs']],
              'java_home': (str(Path(data['java_home']).resolve(strict=True))
                            if data.get('java_home') else None),
              'source': str(Path(path).resolve(strict=True)), 'source_sha256': sha(path)}
    result['repository_cache_digest'], result['repository_cache_entries'] = \
        verify_repository_cache(result['repository_cache'])
    result['distdir_digest'], result['distdir_files'] = verify_distdirs(result['distdirs'])
    return result


def apply_bazel_environment(bzlmod, host_toolchain=False):
    """Bazel's server JDK (when named); host C/C++ autodetection only on request."""
    if bzlmod['java_home']:
        os.environ['JAVA_HOME'] = bzlmod['java_home']
    if host_toolchain:
        os.environ.pop('BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN', None)
    else:
        os.environ['BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN'] = '1'


def prepare(parser, args, host_toolchain=False):
    """Common start of every tool: version gate, offline inputs, environment."""
    try:
        version = check_bazel_version(args.bazel)
        bzlmod = load_bzlmod_inputs(args.bzlmod_inputs)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    bzlmod['bazel_version'] = version
    apply_bazel_environment(bzlmod, host_toolchain)
    return bzlmod


def stage_repository_cache(bzlmod, destination, *, copy_function=shutil.copy2):
    """Copy the verified cache into the run's private output.

    Bazel writes to its repository cache (fetched archives and the repo
    contents cache), so the declared input is never handed to Bazel itself.
    """
    destination = Path(destination)
    shutil.copytree(Path(bzlmod['repository_cache']) / 'content_addressable',
                    destination / 'content_addressable', symlinks=False,
                    copy_function=copy_function)
    bzlmod['staged_repository_cache'] = str(destination)
    return destination


def write_workspace(ws, name, bzlmod, staged_toolchain=True):
    """MODULE.bazel (pinned bazel_dep, toolchain registration) and the pinned lockfile.

    Without staged_toolchain only rules_cc's own (autodetected host)
    toolchain is available; native-probe.py uses that.
    """
    lines = ['module(name="%s")' % name]
    lines += ['bazel_dep(name="%s", version="%s")' % (module, version)
              for module, version in sorted(bzlmod['modules'].items())]
    if staged_toolchain:
        lines.append('register_toolchains("//toolchain:registered")')
    (ws / 'MODULE.bazel').write_text('\n'.join(lines) + '\n')
    shutil.copyfile(bzlmod['lockfile'], ws / 'MODULE.bazel.lock')


def lockfile_unchanged(ws, bzlmod):
    return sha(Path(ws) / 'MODULE.bazel.lock') == bzlmod['lockfile_sha256']


def stage_toolchain(tc, sysroot, objdump, awk, target, cpu, clang_version):
    """Copy the SDK and tools into workspace package `tc` and write its BUILD file.

    Development-header links are materialized into declared input files.
    Library links stay inside the copied complete runtime/SDK directories and
    must not escape the staged tree.
    """
    if cpu not in PLATFORM_CPUS:
        raise ValueError('no @platforms CPU for ' + cpu)
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
    constraints = json.dumps(['@platforms//os:freebsd', '@platforms//cpu:' + PLATFORM_CPUS[cpu],
                              ':selected_sdk'])
    (tc / 'BUILD.bazel').write_text(
        'load("@rules_cc//cc/toolchains:cc_toolchain.bzl", "cc_toolchain")\n'
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
        'exports_files(glob(["bin/*"]))\n'
        # The constraint keeps toolchain resolution on this staged SDK only.
        'constraint_setting(name="sdk_identity")\n'
        'constraint_value(name="selected_sdk", constraint_setting=":sdk_identity")\n'
        'platform(name="native", constraint_values=%s)\n'
        'toolchain(name="registered", toolchain=":compiler", '
        'toolchain_type="@bazel_tools//tools/cpp:toolchain_type", '
        'exec_compatible_with=%s, target_compatible_with=%s)\n' % (constraints, constraints, constraints))


def repository_flags(bzlmod):
    """Offline module inputs: staged cache copy and distdirs only, no downloads."""
    return (['--lockfile_mode=error',
             '--repository_cache=' + bzlmod['staged_repository_cache'],
             '--repository_disable_download'] +
            ['--distdir=' + x for x in bzlmod['distdirs']])


def query_flags(bzlmod):
    """Loading-phase commands (query) need the same offline module inputs."""
    return repository_flags(bzlmod)


def build_flags(jobs, bzlmod):
    """Bazel options selecting only the staged toolchain."""
    # --materialize_param_files: the probes read link/archive params files,
    # which Bazel 9 writes for local actions only on request.
    return (['--jobs=' + str(jobs), '--noshow_progress',
             '--action_env=PATH=/bin:/usr/bin', '--subcommands',
             '--platforms=//toolchain:native', '--host_platform=//toolchain:native',
             '--extra_execution_platforms=//toolchain:native',
             '--materialize_param_files'] + repository_flags(bzlmod))


def mode_record(bzlmod):
    """Receipt fragment naming the Bazel version and its offline module inputs."""
    return {'mode': 'bzlmod', 'bazel_version': bzlmod['bazel_version'],
            'minimum_bazel_major': MINIMUM_BAZEL_MAJOR,
            'modules': bzlmod['modules'], 'inputs_file': bzlmod['source'],
            'inputs_file_sha256': bzlmod['source_sha256'],
            'lockfile': bzlmod['lockfile'], 'lockfile_sha256': bzlmod['lockfile_sha256'],
            'repository_cache': bzlmod['repository_cache'],
            'repository_cache_digest': bzlmod['repository_cache_digest'],
            'repository_cache_entries': bzlmod['repository_cache_entries'],
            'staged_repository_cache': bzlmod.get('staged_repository_cache'),
            'distdirs': len(bzlmod['distdirs']), 'distdir_digest': bzlmod['distdir_digest'],
            'java_home': bzlmod['java_home'] or 'launcher default',
            'downloads': 'disabled (--repository_disable_download)',
            'lockfile_mode': 'error'}


# The source tree's own (native) Bazel files.  The probes declare their
# targets in their overlay (targets/), so these are left out when component
# directories are copied into a probe workspace; the probes still refuse a
# workspace in which any other Bazel file appears.
SOURCE_BAZEL_FILES = ('BUILD', 'BUILD.bazel', '*.bzl', 'WORKSPACE', 'WORKSPACE.bazel',
                      'MODULE.bazel')
