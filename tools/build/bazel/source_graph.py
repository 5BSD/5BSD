# SPDX-License-Identifier: BSD-2-Clause
"""Run maintained BUILD targets through the build-bsd qualification frontend."""
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import time
import tempfile
import bep_artifacts
import test_reports
import bsd_toolchain
import userland_sdk
from libmd_environment import digest


def setting_arguments(settings):
    """Pass typed source build settings, never arbitrary native Bazel flags."""
    if not isinstance(settings, dict) or any(not isinstance(key, str) for key in settings):
        raise ValueError('build-settings must be an object')
    result = []
    for label, value in sorted(settings.items()):
        if not isinstance(label, str) or not re.fullmatch(r'//[A-Za-z0-9_./-]*:[A-Za-z0-9_.+-]+', label):
            raise ValueError('build setting must be a source target label')
        if type(value) not in (str, bool, int) or (isinstance(value, str) and any(ord(c) < 32 for c in value)):
            raise ValueError('build setting requires a scalar string, bool or integer')
        rendered = str(value).lower() if type(value) is bool else str(value)
        result.append('--' + label + '=' + rendered)
    return result



def execution_log_format(config):
    """Select Bazel's documented complete log encodings without implicit fallback."""
    value = config.get('execution-log-format', 'json')
    if value not in ('json', 'compact'):
        raise ValueError('execution-log-format must be json or compact')
    return value


def platform_arguments(config, target_arch, receipt=None):
    """Separate the execution SDK from the explicitly selected target kernel ABI."""
    kind = config.get('target-kind', 'userland')
    if kind not in ('userland', 'kernel'):
        raise ValueError('target-kind must be userland or kernel')
    if target_arch not in ('amd64', 'aarch64', 'riscv64'):
        raise ValueError('unsupported target architecture')
    native = '@bsd_sdk//toolchain:native'
    if kind == 'userland':
        if receipt is not None:
            userland_sdk.receipt_architecture(receipt, target_arch)
        if target_arch != 'amd64':
            if receipt is None:
                raise ValueError('cross userland requires an explicitly bound native execution SDK')
            return ['--platforms=@bsd_sdk//toolchain:' + target_arch, '--host_platform=' + native,
                    '--extra_toolchains=@bsd_sdk//toolchain/host:registered']
        return ['--platforms=' + native, '--host_platform=' + native]
    cross_execution = False
    if receipt is not None:
        sdk_arch = userland_sdk.target_architecture(receipt.get('target'))
        # A native SDK remains sufficient for freestanding cross kernels.
        # Owners needing target SDK headers must select a matching composite
        # SDK; its execution closure is independently bound to native amd64.
        if sdk_arch != 'amd64' and sdk_arch != target_arch:
            raise ValueError('kernel SDK target differs from selected architecture')
        userland_sdk.receipt_architecture(receipt, sdk_arch)
        cross_execution = sdk_arch != 'amd64'
    name = {'amd64': 'amd64', 'aarch64': 'arm64', 'riscv64': 'riscv64'}[target_arch]
    package = '//tools/build/bazel/kernel_toolchain:'
    result = ['--platforms=' + package + name, '--host_platform=' + native,
              '--extra_toolchains=' + package + name + '_registered']
    if cross_execution:
        result.append('--extra_toolchains=@bsd_sdk//toolchain/host:registered')
    return result


def test_inventory_command(argv, targets, tests, host_artifacts_only=False):
    """Ask the configured graph to expand requested tests/suites, preserving settings."""
    command = list(argv[:-len(targets)])
    command[command.index('test')] = 'cquery'
    command = [a for a in command if not a.startswith((
        '--build_event_json_file=', '--execution_log_json_file=', '--execution_log_compact_file=',
        '--noexecution_log_sort', '--output_groups='))]
    fields = '"label":str(target.label),"compatible":not any([key.endswith("IncompatiblePlatformProvider") for key in providers(target)])'
    if host_artifacts_only:
        fields += ',"host_artifact":any([key.endswith("BsdHostArtifactTestInfo") for key in providers(target)])'
    return command + ['--output=starlark', '--starlark:expr=json.encode({' + fields + '})',
                      'tests(set(' + ' '.join(json.dumps(label) for label in tests) + '))']


def parse_test_inventory(text, host_artifacts_only=False):
    active, incompatible, seen = set(), set(), set()
    fields = {'label', 'compatible'} | ({'host_artifact'} if host_artifacts_only else set())
    for line in text.splitlines():
        record = json.loads(line)
        if (not isinstance(record, dict) or set(record) != fields or
                not isinstance(record['label'], str) or type(record['compatible']) is not bool or
                (host_artifacts_only and type(record['host_artifact']) is not bool)):
            raise ValueError('configured test requires an explicit label and compatibility boolean')
        if host_artifacts_only and record['compatible'] and not record['host_artifact']:
            raise ValueError('cross or kernel profiles require explicitly declared host artifact tests: ' + record['label'])
        label = record['label']
        if label.startswith('@@//'):
            label = label[2:]
        if not label.startswith('//') or ':' not in label or label in seen:
            raise ValueError('invalid or duplicate configured test: ' + label)
        seen.add(label)
        (active if record['compatible'] else incompatible).add(label)
    if not active:
        raise ValueError('requested tests expand to no compatible configured tests')
    return sorted(active), sorted(incompatible)


def validate_selected_tests(expected, selected):
    if set(expected) != set(selected):
        raise ValueError('selected test targets differ from the explicit requested test inventory')


def test_results(events, expected):
    tests = {}
    for event in events:
        if 'testSummary' in event:
            label = event['id']['testSummary']['label']
            if label in tests:
                raise ValueError('duplicate test summary: ' + label)
            tests[label] = event['testSummary']['overallStatus']
    if set(tests) != set(expected) or any(v != 'PASSED' for v in tests.values()):
        raise ValueError('test inventory/status mismatch')
    return tests


def qualify(config, args):
    # A source checkout owns one persistent Bazel state directory. Configuration
    # and input changes remain Bazel's responsibility, not a new output root.
    src = args.src.resolve(strict=True)
    state = args.objtop.resolve(strict=True).parent / 'bazel-state' / hashlib.sha256(str(src).encode()).hexdigest()
    if not state.is_relative_to('/usr/obj') or state.is_relative_to(src):
        raise ValueError('persistent build state must be under /usr/obj outside source')
    out = args.output.resolve()
    if out == state or out.is_relative_to(state) or state.is_relative_to(out):
        raise ValueError('evidence output must not overlap persistent build state')
    state.mkdir(parents=True, exist_ok=True)
    with (state / 'frontend.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _qualify(config, args, state)


def _qualify(config, args, state):
    required={'format','toolchain-workspace','toolchain-receipt','java-home',
              'repository-cache','distdirs','targets','tests'}
    if not required <= set(config) or set(config) - required - {'build-settings', 'target-kind', 'execution-log-format'} or type(config['format']) is not int or config['format']!=5:
        raise ValueError('exact format-5 source graph configuration required')
    log_format = execution_log_format(config)
    log_path = args.output.resolve() / ('execution.' + log_format)
    settings = setting_arguments(config.get('build-settings', {}))
    for key in ('targets','tests'):
        values=config[key]
        if not isinstance(values,list) or len(values)!=len(set(values)) or any(
            not isinstance(v,str) or not v.startswith('//') or ':' not in v or
            any(c in v for c in '* \n\r') or '...' in v for v in values):
            raise ValueError('explicit unique source target labels required: '+key)
    if not config['targets']:raise ValueError('nonempty targets required')
    if not set(config['tests'])<=set(config['targets']):raise ValueError('tests must be selected targets')
    selected={}
    for key in ('toolchain-workspace','toolchain-receipt','java-home','repository-cache'):
        path=Path(config[key])
        if not path.is_absolute():raise ValueError('absolute input required: '+key)
        selected[key]=path.resolve(strict=True)
    if not isinstance(config['distdirs'],list):raise ValueError('distdirs must be a list')
    distdirs=[]
    for value in config['distdirs']:
        path=Path(value)
        if not path.is_absolute() or not path.is_dir():raise ValueError('absolute distdir required')
        distdirs.append(path.resolve())
    out=args.output.resolve();src=args.src.resolve(strict=True)
    protected=[src,args.objtop.resolve(strict=True),*selected.values(),*distdirs]
    if (not args.output.is_absolute() or args.output.is_symlink() or out.exists() or
        out==Path('/usr/obj') or not out.is_relative_to('/usr/obj') or
        any(p==out or p.is_relative_to(out) or (p.is_dir() and out.is_relative_to(p)) for p in protected)):
        raise ValueError('fresh nonoverlapping /usr/obj output required')
    sdk=selected['toolchain-workspace'];receipt=json.loads(selected['toolchain-receipt'].read_text())
    platforms = platform_arguments(config, args.target_arch, receipt)
    host_artifacts_only = config.get('target-kind') == 'kernel' or args.target_arch != 'amd64'
    for field in ('inputs','execution_host_dependencies'):
        for name,value in receipt[field].items():
            if digest(Path(name))!=value:raise ValueError('SDK input changed: '+name)
    for name,value in receipt['snapshot'].items():
        p=Path(name)
        if p.is_absolute() or '..' in p.parts or digest(sdk/p)!=value:raise ValueError('SDK snapshot changed: '+name)
    bindings={str(p):digest(p) for p in [args.inputs.resolve(),args.bazel.resolve(),selected['toolchain-receipt'],Path(__file__).resolve(),Path(bep_artifacts.__file__).resolve(),Path(test_reports.__file__).resolve(),Path(userland_sdk.__file__).resolve(),src/'MODULE.bazel',src/'MODULE.bazel.lock']}
    out.mkdir(parents=True)
    module = 'module(name="bsd_sdk",version="0.0.0")\nbazel_dep(name="rules_cc",version="0.2.17")\nbazel_dep(name="platforms",version="1.0.0")\n'
    sdk_key = hashlib.sha256(json.dumps(dict(snapshot=receipt['snapshot'], module=module),sort_keys=True).encode()).hexdigest()
    repositories=state/'sdks';repositories.mkdir(exist_ok=True)
    repository=repositories/sdk_key
    if not repository.exists():
        temporary=Path(tempfile.mkdtemp(prefix='staging-',dir=repositories))
        try:
            shutil.copytree(sdk/'toolchain',temporary/'toolchain',symlinks=True)
            (temporary/'MODULE.bazel').write_text(module)
            temporary.rename(repository)
        finally:
            if temporary.exists():shutil.rmtree(temporary)
    if repository.is_symlink() or (repository/'MODULE.bazel').read_text()!=module:
        raise ValueError('cached SDK module changed')
    actual={str(p.relative_to(repository)) for p in (repository/'toolchain').rglob('*') if p.is_file()}
    if actual!=set(receipt['snapshot']):raise ValueError('cached SDK file inventory changed')
    for name,value in receipt['snapshot'].items():
        if digest(repository/name)!=value:raise ValueError('cached SDK input changed: '+name)
    cache_digest, cache_entries = bsd_toolchain.verify_repository_cache(selected['repository-cache'])
    distdir_digest, distdir_files = bsd_toolchain.verify_distdirs(distdirs)
    staged_cache = out / 'repository-cache'
    bsd_toolchain.stage_repository_cache(
        {'repository_cache': str(selected['repository-cache'])}, staged_cache)
    staged_digest, staged_entries = bsd_toolchain.verify_repository_cache(staged_cache)
    if (staged_digest, staged_entries) != (cache_digest, cache_entries):
        raise ValueError('staged repository cache differs from the verified input')
    commands=[]
    try:
        argv=[str(args.bazel),'--ignore_all_rc_files','--max_idle_secs=300','--server_javabase='+str(selected['java-home']),'--output_user_root='+str(state/'bazel-root'),
              'test' if config['tests'] else 'build','--override_module=bsd_sdk='+str(repository),
              '--lockfile_mode=error','--repository_disable_download','--repository_cache='+str(staged_cache),
              *platforms,
              '--jobs='+str(args.jobs),'--compilation_mode=opt','--strip=never',
              # Extend Bazel defaults so build-only test targets retain runfiles.
              '--output_groups=+metadata,+directory_metadata',
              '--symlink_prefix='+str(out/'bazel-'),'--build_event_json_file='+str(out/'events.json'),
              '--execution_log_'+log_format+'_file='+str(log_path),'--noexecution_log_sort',
              *['--distdir='+str(p) for p in distdirs],*settings,*config['targets']]
        env=dict(os.environ,JAVA_HOME=str(selected['java-home']),LC_ALL='C',BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN='1')
        expected, incompatible = [], []
        if config['tests']:
            query = test_inventory_command(argv, config['targets'], config['tests'], host_artifacts_only=host_artifacts_only)
            start = time.monotonic()
            with (out/'test-inventory.stdout').open('w') as stdout, (out/'test-inventory.stderr').open('w') as stderr:
                result = subprocess.run(query, cwd=src, env=env, stdout=stdout, stderr=stderr)
            commands.append(dict(argv=query,exit_status=result.returncode,elapsed_seconds=time.monotonic()-start))
            (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
            if result.returncode:
                raise RuntimeError('configured test inventory failed; see test-inventory.stderr')
            expected, incompatible = parse_test_inventory((out/'test-inventory.stdout').read_text(), host_artifacts_only=host_artifacts_only)
            if host_artifacts_only:
                # bazel test executes test rules in targets even if the caller
                # omitted them from tests. Validate that whole selection first.
                query = test_inventory_command(argv, config['targets'], config['targets'], host_artifacts_only=True)
                with (out/'selected-test-inventory.stdout').open('w') as stdout, (out/'selected-test-inventory.stderr').open('w') as stderr:
                    result = subprocess.run(query, cwd=src, env=env, stdout=stdout, stderr=stderr)
                commands.append(dict(argv=query,exit_status=result.returncode))
                (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
                if result.returncode:
                    raise RuntimeError('selected target test inventory failed; see selected-test-inventory.stderr')
                selected_tests, excluded = parse_test_inventory((out/'selected-test-inventory.stdout').read_text(), host_artifacts_only=True)
                validate_selected_tests(expected, selected_tests)
                incompatible = sorted(set(incompatible) | set(excluded))
        start=time.monotonic()
        with (out/'bazel.stdout').open('w') as stdout,(out/'bazel.stderr').open('w') as stderr:
            result=subprocess.run(['/usr/bin/time','-l',*argv],cwd=src,
                env=env,stdout=stdout,stderr=stderr)
        commands.append(dict(argv=argv,exit_status=result.returncode,elapsed_seconds=time.monotonic()-start))
        (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        if result.returncode:raise RuntimeError('native source graph failed; see bazel.stderr')
        (out/'test-inventory.json').write_text(json.dumps(dict(requested=config['tests'],expanded=expected,incompatible=incompatible,selected_inventory_sha256=digest(out/'selected-test-inventory.stdout') if (out/'selected-test-inventory.stdout').exists() else None),indent=2)+'\n')
        with (out/'events.json').open() as stream:
            tests = test_results((json.loads(line) for line in stream), expected)
        with (out/'events.json').open() as stream:
            reports = test_reports.snapshot((json.loads(line) for line in stream), out/'test-reports', expected)
        artifacts = bep_artifacts.snapshot(out/'events.json', out/'artifacts', incompatible=incompatible)
        for name,value in bindings.items():
            if digest(Path(name))!=value:raise ValueError('qualification input changed: '+name)
        if bsd_toolchain.verify_repository_cache(selected['repository-cache']) != (cache_digest, cache_entries):
            raise ValueError('verified repository cache input changed during qualification')
        if bsd_toolchain.verify_distdirs(distdirs) != (distdir_digest, distdir_files):
            raise ValueError('verified distdir inputs changed during qualification')
        staged_cache_after = bsd_toolchain.verify_repository_cache(staged_cache)
        log_digest = digest(log_path)
        (out/'receipt.json').write_text(json.dumps(dict(status='passed',scope='selected maintained BUILD targets',target_architecture=args.target_arch,target_kind=config.get('target-kind','userland'),test_execution=('host-artifacts' if host_artifacts_only else 'userland') if config['tests'] else 'none',targets=config['targets'],tests=tests,test_reports=reports,test_inventory_sha256=digest(out/'test-inventory.json'),artifacts=artifacts,build_state=str(state),sdk_repository=str(repository),input_sha256=bindings,offline_inputs={'repository_cache':str(selected['repository-cache']),'repository_cache_sha256':cache_digest,'repository_cache_entries':cache_entries,'staged_repository_cache':str(staged_cache),'staged_repository_cache_before':{'sha256':staged_digest,'entries':staged_entries},'staged_repository_cache_after':{'sha256':staged_cache_after[0],'entries':staged_cache_after[1]},'distdirs':len(distdirs),'distdir_sha256':distdir_digest,'distdir_files':distdir_files,'source_inputs_unchanged':True},execution_log_sha256=log_digest,execution_log=dict(format=log_format,path=str(log_path),bytes=log_path.stat().st_size,sha256=log_digest),limitations=['Bazel PASSED describes action success; see test_reports for passing, skipped and expected-failure case counts.','Prepared Make-built SDK; no world/kernel/bootstrap qualification.','No installation, package parity, publication or performance comparison established.']),indent=2)+'\n')
        print(out/'receipt.json')
    except Exception as error:
        failure = dict(status='failed', error=str(error), input_sha256=bindings)
        if (out/'events.json').is_file():
            failure['events_sha256'] = digest(out/'events.json')
            try:
                failure['test_reports'] = test_reports.snapshot_failure(
                    out/'events.json', out/'failure-test-reports')
            except Exception as capture_error:
                # Keep the original build failure even if diagnostics are incomplete.
                failure['test_report_capture_error'] = str(capture_error)
        (out/'FAILED.json').write_text(json.dumps(failure,indent=2)+'\n')
        raise
