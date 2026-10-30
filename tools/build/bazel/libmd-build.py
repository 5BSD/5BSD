#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Emit rules_cc BUILD graph from the maintained libmd configuration export."""
import argparse
import hashlib
import re
import json
from pathlib import Path
import shlex
import shutil
import atf_runtime
import library_install
import stage_install


def test_targets(plan, root, library):
    data = json.loads(plan.read_text())
    if data.get('status') != 'exported':
        raise ValueError('test inventory is not a completed export')
    for key in ('objtop', 'profile_assignments'):
        if data['build_environment'][key] != library['build_environment'][key]:
            raise ValueError('test/library configuration differs: ' + key)
    bound_inputs = dict(data['implementation_sha256'])
    bound_inputs.update(data['build_environment']['input_sha256'])
    for closure in data['program_make_include_closures'].values():
        bound_inputs.update(closure)
    for path, expected in bound_inputs.items():
        with Path(path).open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
                raise ValueError('test metadata input changed: ' + path)
    # Test consumers must use the exported library headers, not stale installed
    # copies. Retain the maintained library include search order.
    includes = []
    flags = iter(library['rewritten_cflags'])
    for flag in flags:
        if flag in ('-I', '-iquote', '-isystem'):
            includes.extend([flag, next(flags)])
        elif flag.startswith('-I'):
            includes.append(flag)
    lines, names = [], set()
    for driver in data['drivers']:
        name = driver['program']
        if not re.fullmatch(r'[A-Za-z0-9_]+driver', name) or name in names:
            raise ValueError('invalid or duplicate driver name')
        names.add(name)
        if driver['libadd'] != ['md']:
            raise ValueError('unsupported test library dependency')
        source = Path(driver['source'])
        if source.is_absolute() or '..' in source.parts or not source.parts or source.parts[0] != 'sources':
            raise ValueError('test source escapes snapshot')
        staged = plan.parent / source
        origin = Path(driver['source_origin'])
        for path in (staged, origin):
            if hashlib.sha256(path.read_bytes()).hexdigest() != driver['source_sha256']:
                raise ValueError('test source changed: ' + str(path))
        destination = root / source
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(staged, destination)
        copts = driver['cppflags'] + driver['cflags']
        if any(flag.startswith(('-I', '-iquote', '-isystem', '--sysroot')) for flag in copts):
            raise ValueError('test-specific include/sysroot flags require explicit snapshot mapping')
        lines.append('cc_binary(name=%s, srcs=%s, deps=[":md_runtime"], copts=%s, linkopts=%s, linkstatic=False)' %
                     tuple(json.dumps(value) for value in (driver['artifacts']['raw_output'], [str(source)], copts + includes, driver['ldflags'])))
        artifact = driver['artifacts']
        runtime = ':' + artifact['raw_output']
        if artifact['split_debug']:
            lines.append('bsd_debug_split(name=%s, src=%s, binary_name=%s, debug_name=%s, objcopy="//toolchain:bin/llvm-objcopy", objcopy_inputs="//toolchain:objcopy_inputs")' %
                         tuple(json.dumps(value) for value in (name, runtime, 'split/' + artifact['program_output'], 'split/' + artifact['debug_output'])))
            runtime = ':' + name
            lines.append('filegroup(name=%s, srcs=%s, output_group="debug_files")' % (json.dumps(name + '_debug'), json.dumps([runtime])))
        elif artifact['raw_output'] != name:
            lines.append('alias(name=%s, actual=%s)' % (json.dumps(name), json.dumps(runtime)))
        if artifact['install_strip_flags'] == ['-s']:
            lines.append('bsd_strip_binary(name=%s, src=%s, output=%s, strip="//toolchain:bin/llvm-strip", strip_inputs="//toolchain:strip_inputs")' %
                         tuple(json.dumps(value) for value in (name + '_install', runtime, 'install/' + artifact['installed_name'])))
        elif not artifact['install_strip_flags']:
            lines.append('alias(name=%s, actual=%s)' % (json.dumps(name + '_install'), json.dumps(runtime)))
        else:
            raise ValueError('unsupported test installation strip policy')
    if not names:
        raise ValueError('empty test inventory')
    for mapping in ('references', 'generator_inputs'):
        for origin, item in data[mapping].items():
            relative = Path(item['staged_path'])
            if relative.is_absolute() or '..' in relative.parts or relative.parts[0] != 'sources':
                raise ValueError('test data escapes snapshot')
            staged = plan.parent / relative
            for path in (Path(origin), staged):
                if hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
                    raise ValueError('test data changed: ' + str(path))
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(staged, destination)
    references = [item['staged_path'] for item in data['references'].values()]
    lines.append('filegroup(name="test_references", srcs=%s)' % json.dumps(references))
    harness = data['harness']
    for target in harness['targets']:
        if target['sed']:
            raise ValueError('ATF body transformation requires explicit support')
        lines.append('libmd_test_body(name=%s, output=%s, generator=%s, arguments=%s, shell="//toolchain:sh", shell_runtime=["//toolchain:sh_runtime"], redirect="//toolchain:stdout_redirect")' %
                     tuple(json.dumps(value) for value in ('gen_' + target['body_target'], target['body_target'], harness['generator'], harness['arguments'])))
        lines.append('bsd_script_wrapper(name=%s, body=%s, interpreter=%s, cat="//toolchain:cat", cat_runtime=["//toolchain:cat_runtime"], redirect="//toolchain:stdout_redirect")' %
                     tuple(json.dumps(value) for value in (target['target'], ':gen_' + target['body_target'], harness['interpreter'])))
    return lines


def install_targets(path, test_plan):
    data = json.loads(path.read_text())
    if data.get('status') != 'exported' or str(test_plan.resolve()) not in data['input_sha256']:
        raise ValueError('installation plan must bind the selected test inventory')
    for name, expected in data['input_sha256'].items():
        if hashlib.sha256(Path(name).read_bytes()).hexdigest() != expected:
            raise ValueError('installation policy input changed: ' + name)
    kyua = data['kyua']
    lines = ['load(":bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")']
    lines.append('bsd_kyuafile(name="test_kyuafile", suite=%s, names=%s, interfaces=%s)' % tuple(json.dumps(v) for v in (kyua['suite'], [t['name'] for t in kyua['tests']], {t['name']:t['interface'] for t in kyua['tests']})))
    labels = []
    for index, record in enumerate(sorted(data['files'], key=lambda r:r['destination'])):
        name = 'test_install_record_' + str(index)
        values = {'name':name, 'src':record['label']}
        values.update({k:record[k] for k in ('destination','owner','group','mode')})
        values['install_tags'] = record['tags']
        lines.append('bsd_install_file(' + ', '.join(k+'='+json.dumps(v) for k,v in values.items()) + ')')
        labels.append(':'+name)
    lines.append('bsd_install_manifest(name="test_install_manifest", entries=%s)' % json.dumps(labels))
    return lines


def emit(plan, test_plan=None, install_plan=None, test_runtime=None, library_policy=None, compression_tools=None, directory_policy=None, install_tools=None):
    if test_runtime is not None and test_plan is None:
        raise ValueError('ATF test runtime requires the test inventory')
    if (library_policy is None) != (compression_tools is None):
        raise ValueError('library policy and compression tool receipt must be selected together')
    if (directory_policy is None) != (install_tools is None):
        raise ValueError('directory policy and installer receipt must be selected together')
    if directory_policy is not None and (library_policy is None or install_plan is None):
        raise ValueError('native staging requires library and test payload policies')
    r = json.loads(plan.read_text())
    # rules_cc 0.2.17 legacy archiver_flags uses rcsD for non-macosx libc.
    # Current maintained -crsD has the same create/replace/index/deterministic
    # semantics. Other policies require explicit graph support, not silent reuse.
    if shlex.split(r['metadata']['ARFLAGS']) != ['-crsD']:
        raise ValueError('unsupported maintained ARFLAGS; candidate supports -crsD only')
    root = plan.parent / 'workspace'
    source = Path(__file__).parent
    shutil.copyfile(source / 'libmd_graph.bzl', root / 'libmd_graph.bzl')
    shutil.copyfile(source / 'native_version_map.bzl', root / 'version_map.bzl')
    shutil.copyfile(source / 'bsd_artifacts.bzl', root / 'bsd_artifacts.bzl')
    lines = ['load(":bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary", "bsd_script_wrapper")', 'load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import")',
             'load(":libmd_graph.bzl", "libmd_generated", "libmd_library", "libmd_shared_alias", "libmd_test_body")',
             'load(":version_map.bzl", "bsd_version_map")', '']
    for gen in r['generators']:
        attributes = {key:gen[key] for key in ('output','script','template','arguments','kind')}
        attributes['name'] = 'gen_' + gen['output']
        if gen['copyright'] is not None:
            attributes['copyright'] = gen['copyright']
        values = [key+'='+json.dumps(value) for key,value in attributes.items()]
        tools = ['sh', 'sed', 'mv', 'rm']
        if gen['kind'] == 'manual':
            values.append('cat="//toolchain:cat"')
            tools.append('cat')
        runtime = ['//toolchain:' + name + '_runtime' for name in tools]
        lines.append('libmd_generated(' + ', '.join(values) + ', shell="//toolchain:sh", sed="//toolchain:sed", mv="//toolchain:mv", rm="//toolchain:rm", execution_runtime=' + json.dumps(runtime) + ')')
    includes = []  # -I options retain their original order in rewritten_cflags.
    flags = r['rewritten_cflags']
    lines.append('libmd_library(name="md", srcs=%s, hdrs=%s, copts=%s, assembly_flags=%s, per_file_flags=%s, includes=%s, arflags=%s, archive_inputs="//toolchain:archive_inputs")' %
        tuple(json.dumps(x) for x in ([(':gen_' + s['path']) if s['generated'] else s['path'] for s in r['sources']], r['headers'], flags,
         r['rewritten_acflags'], r['per_file_rewritten'], includes, shlex.split(r['metadata']['ARFLAGS']))))
    lines.append('bsd_version_map(name="md_versions", symbols="sources/lib/libmd/Symbol.map", versions="sources/lib/libc/Versions.def", generator="sources/share/mk/version_gen.awk", compiler="//toolchain:bin/clang", compiler_inputs="//toolchain:compile_inputs", awk="//toolchain:awk", awk_runtime="//toolchain:awk_runtime", redirect="//toolchain:stdout_redirect", target=BSD_TARGET)')
    lines.insert(3, 'load("//toolchain:identity.bzl", "BSD_TARGET")')
    lines.append('filegroup(name="md_pic_archive", srcs=[":md"], output_group="pic_archive")')
    lines.append('cc_import(name="md_pic", static_library=":md_pic_archive", alwayslink=True)')
    if r['metadata']['MK_CTF'] != 'no' or r['metadata']['LDADD'].strip():
        raise ValueError('CTF transformation/additional link dependencies require explicit graph support')
    linkopts = []
    for flag in shlex.split(r['metadata']['LDFLAGS'] + ' ' + r['metadata']['SSP_CFLAGS'] + ' ' + r['metadata']['SOLINKOPTS']):
        if flag == '-shared':
            continue  # supplied by cc_binary(linkshared=True)
        if flag.startswith('-Wl,--version-script='):
            flag = '-Wl,--version-script=$(location :md_versions)'
        linkopts.append(flag)
    soname = r['metadata']['SHLIB_NAME']
    linked_name = r['metadata']['SHLIB_NAME_FULL']
    linkopts.append('-Wl,-soname,' + soname)
    lines.append('cc_binary(name=%s, deps=[":md_pic"], linkshared=True, linkstatic=True, additional_linker_inputs=[":md_versions"], linkopts=%s)' % (json.dumps(linked_name), json.dumps(linkopts)))
    if r['metadata']['MK_DEBUG_FILES'] == 'yes':
        lines.append('bsd_debug_split(name="md_split", src=%s, binary_name=%s, debug_name=%s, objcopy="//toolchain:bin/llvm-objcopy", objcopy_inputs="//toolchain:objcopy_inputs")' % tuple(json.dumps(value) for value in (":" + linked_name, "split/" + soname, "split/" + r['metadata']['DEBUGFILE'])))
        lines.append('filegroup(name="md_debug", srcs=[":md_split"], output_group="debug_files")')
    runtime = ':md_split' if r['metadata']['MK_DEBUG_FILES'] == 'yes' else ':' + linked_name
    if r['metadata']['STRIP'] == '-s':
        lines.append('bsd_strip_binary(name="md_runtime_install", src=%s, output=%s, strip="//toolchain:bin/llvm-strip", strip_inputs="//toolchain:strip_inputs")' % (json.dumps(runtime), json.dumps('install/' + soname)))
    elif r['metadata']['STRIP'] == '':
        lines.append('alias(name="md_runtime_install", actual=%s)' % json.dumps(runtime))
    else:
        raise ValueError('unsupported maintained installation strip policy')
    if test_plan is not None:
        lines.append('libmd_shared_alias(name="md_soname", library=%s, output=%s)' % (json.dumps(":" + linked_name), json.dumps(soname)))
        lines.append('cc_import(name="md_runtime", shared_library=":md_soname")')
        lines.extend(test_targets(test_plan, root, r))
    if install_plan is not None:
        if test_plan is None:
            raise ValueError('installation manifest requires a test inventory')
        for name in ('bsd_install.bzl', 'bsd_kyua_metadata.bzl'):
            shutil.copyfile(source / name, root / name)
        lines.extend(install_targets(install_plan, test_plan))
    if library_policy is not None:
        for name in ('bsd_install.bzl', 'bsd_kyua_metadata.bzl'):
            shutil.copyfile(source / name, root / name)
        if install_plan is None:
            lines.insert(0, 'load(":bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")')
        lines.extend(library_install.emit(root, library_policy, compression_tools, r))
    if directory_policy is not None:
        lines.extend(stage_install.emit(root, directory_policy, install_tools, r, library_policy, install_plan))
    if test_runtime is not None:
        lines.extend(atf_runtime.stage(root, test_plan, test_runtime, Path(r['source_root']), r['build_environment']))
    (root / 'BUILD.bazel').write_text('\n\n'.join(lines) + '\n')
    (root / 'MODULE.bazel').write_text('module(name="bsd_libmd_candidate")\nbazel_dep(name="rules_cc", version="0.2.17")\nbazel_dep(name="platforms", version="1.0.0")\nregister_toolchains("//toolchain:registered")\n')
    # Transitive module closure/toolchain execution runtime is an explicit prerequisite.
    return root

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan', required=True, type=Path)
    p.add_argument('--test-plan', type=Path, help='verified maintained digest-driver inventory')
    p.add_argument('--install-plan', type=Path, help='verified test payload installation metadata')
    p.add_argument('--test-runtime', type=Path, help='versioned ATF runtime receipt and SDK library configuration')
    p.add_argument('--library-install-plan', type=Path)
    p.add_argument('--compression-tools', type=Path)
    p.add_argument('--directory-policy', type=Path)
    p.add_argument('--install-tools', type=Path)
    args = p.parse_args()
    print(emit(args.plan, args.test_plan, args.install_plan, args.test_runtime, args.library_install_plan, args.compression_tools, args.directory_policy, args.install_tools))
