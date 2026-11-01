#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify native libmd graph/test/stage construction from explicit prepared inputs."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import stage_verify
import native_prepare
import component_qualify
import source_graph
import bsd_toolchain

PLAN_KEYS = ('plan', 'test-plan', 'install-plan', 'test-runtime', 'library-install-plan', 'compression-tools', 'directory-policy', 'install-tools')

def digest(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def path(value, exists=True):
    p = Path(value)
    if not p.is_absolute():
        raise ValueError('absolute input path required: ' + str(p))
    return p.resolve(strict=exists)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('src', 'objtop', 'bazel', 'output', 'inputs'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--jobs', type=int, required=True)
    parser.add_argument('--target-arch', choices=('amd64', 'aarch64', 'riscv64'), default='amd64')
    args = parser.parse_args()
    if args.jobs < 1: raise ValueError('positive jobs required')
    # Bazel 9 or later only; refused before any input is prepared or run.
    bsd_toolchain.check_bazel_version(args.bazel)
    config = json.loads(args.inputs.read_text())
    if isinstance(config, dict) and type(config.get("format")) is int and config["format"] == 5:
        source_graph.qualify(config, args)
        return
    if args.target_arch != 'amd64':
        raise ValueError('cross-target qualification requires format-5 source graph inputs')
    if isinstance(config, dict) and type(config.get('format')) is int and config['format'] == 2:
        native_prepare.prepare(config, args)
        return
    if isinstance(config, dict) and type(config.get('format')) is int and config['format'] in (3,4):
        component_qualify.qualify(config, args)
        return
    required = {'format', *PLAN_KEYS, 'toolchain-receipt', 'java-home', 'repository-cache', 'distdirs', 'output-user-root'}
    if set(config) != required or type(config['format']) is not int or config['format'] != 1:
        raise ValueError('native qualification input format 1 and exact documented fields required')
    plans = {k:path(config[k]) for k in PLAN_KEYS}
    workspace = plans['plan'].parent / 'workspace'
    if not workspace.is_dir() or not workspace.is_relative_to('/usr/obj'):
        raise ValueError('prepared workspace under /usr/obj required')
    output = path(args.output, False)
    if output.exists() or not output.is_relative_to('/usr/obj') or output == Path('/usr/obj') or output in workspace.parents or output.is_relative_to(workspace):
        raise ValueError('fresh non-overlapping evidence directory under /usr/obj required')
    lib = json.loads(plans['plan'].read_text())
    if path(lib['source_root']) != path(args.src) or path(lib['build_environment']['objtop']) != path(args.objtop):
        raise ValueError('source/object identity differs from selected plan')
    java = path(config['java-home'])
    if not (java/'bin/java').is_file(): raise ValueError('JDK home lacks bin/java')
    cache = path(config['repository-cache'])
    if not isinstance(config['distdirs'], list) or not config['distdirs']:
        raise ValueError('explicit distdirs required')
    distdirs = [path(p) for p in config['distdirs']]
    userroot = path(config['output-user-root'], False)
    if not userroot.is_relative_to('/usr/obj') or userroot == Path('/usr/obj'):
        raise ValueError('Bazel output user root must be below /usr/obj')
    receiptpath = path(config['toolchain-receipt'])
    toolchain = json.loads(receiptpath.read_text())
    bindings = {str(p):digest(p) for p in [*plans.values(), receiptpath, path(args.inputs), path(args.bazel)]}
    for field in ('inputs', 'execution_host_dependencies'):
        for p,h in toolchain[field].items():
            if digest(p) != h: raise ValueError('toolchain input changed: '+p)
            bindings[p] = h
    for p,h in toolchain['snapshot'].items():
        f = workspace/p
        if Path(p).is_absolute() or '..' in Path(p).parts: raise ValueError('invalid snapshot path')
        if digest(f) != h: raise ValueError('toolchain snapshot changed: '+p)
        bindings[str(f)] = h
    if not (workspace/'MODULE.bazel.lock').is_file(): raise ValueError('resolved module lockfile required')
    bindings[str(workspace/'MODULE.bazel.lock')] = digest(workspace/'MODULE.bazel.lock')
    with (workspace/'.native-qualification.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output.mkdir(parents=True)
        commands = []
        def run(name, command, env=None):
            start = time.monotonic()
            with (output/(name+'.stdout')).open('w') as out, (output/(name+'.stderr')).open('w') as err:
                result = subprocess.run(command, cwd=workspace, env=env, stdout=out, stderr=err)
            commands.append({'name':name, 'argv':command, 'exit_status':result.returncode, 'elapsed_seconds':time.monotonic()-start})
            (output/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
            if result.returncode: raise RuntimeError(name+' failed; see '+str(output/(name+'.stderr')))
        command = [sys.executable, '-B', str(path(args.src)/'tools/build/bazel/libmd-build.py')]
        for k,p in plans.items(): command += ['--'+k, str(p)]
        run('graph', command)
        bazel = [str(path(args.bazel)), '--batch', '--ignore_all_rc_files', '--output_user_root='+str(userroot), 'test', '--compilation_mode=opt', '--strip=never', '--lockfile_mode=error', '--repository_disable_download', '--repository_cache='+str(cache), '--platforms=//toolchain:native', '--host_platform=//toolchain:native', '--extra_execution_platforms=//toolchain:native', '--jobs='+str(args.jobs), '--test_output=errors', '--build_event_json_file='+str(output/'events.json'), '--noexecution_log_sort', '--execution_log_json_file='+str(output/'execution.json')]
        bazel += ['--distdir='+str(p) for p in distdirs] + ['//...']
        env = {'PATH':'/bin:/usr/bin:/usr/local/bin', 'HOME':os.environ['HOME'], 'LC_ALL':'C', 'JAVA_HOME':str(java), 'BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN':'1'}
        run('bazel-test', ['/usr/bin/time', '-l', *bazel], env)
        expected = {'//:atf_'+name for name in json.loads(plans['test-plan'].read_text())['harness']['arguments']}
        summaries = {}
        for line in (output/'events.json').read_text().splitlines():
            event=json.loads(line)
            if 'testSummary' in event: summaries[event['id']['testSummary']['label']]=event['testSummary']['overallStatus']
        if set(summaries)!=expected or any(v!='PASSED' for v in summaries.values()):
            raise ValueError('test event inventory/status differs from selected test plan')
        for name in ('native_stage.root','native_stage.METALOG'):
            if not (workspace/'bazel-bin'/name).exists(): raise ValueError('missing native stage output: '+name)
        parity = stage_verify.verify(workspace, plans['directory-policy'], plans['library-install-plan'], plans['install-plan'])
        (output/'stage-parity.json').write_text(json.dumps(parity,indent=2)+'\n')
        for p,h in bindings.items():
            if digest(p)!=h: raise ValueError('input changed during qualification: '+p)
        report={'status':'passed','scope':'native libmd graph, Bazel tests and stage construction','tests':summaries,'stage_parity':parity,'commands':commands,'inputs':bindings,'jobs':args.jobs,'workspace':str(workspace),'limitations':['Uses an explicitly prepared SDK/workspace; fresh bootstrap is not tested.','Installation parity uses the hash-bound existing Make reference; it is not rebuilt.','Sandbox enforcement, complete world/kernel/packages and comparative performance are not qualified.'],'host_installed':False}
        (output/'receipt.json').write_text(json.dumps(report,indent=2)+'\n')
        print(output/'receipt.json')

if __name__ == '__main__':
    try: main()
    except (ValueError, RuntimeError, OSError, KeyError) as e:
        raise SystemExit(str(e))
