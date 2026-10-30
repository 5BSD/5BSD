# SPDX-License-Identifier: BSD-2-Clause
"""Audit configured ATF case inventories against Kyua's result database."""
import collections
import json
from pathlib import Path
import re
import subprocess
from libmd_environment import digest


def compare_cases(listing, rows):
    names = re.findall(r'^ident: (.+)$', listing, re.M)
    if not names or len(names) != len(set(names)):
        raise ValueError('ATF listing must contain unique cases')
    if not isinstance(rows, list) or len(rows) != len(names) or {row['name'] for row in rows} != set(names):
        raise ValueError('ATF listing and result case inventory differ')
    counts = collections.Counter(row['result_type'] for row in rows)
    if set(counts) - {'passed', 'skipped', 'expected_failure'}:
        raise ValueError('ATF case failed, broken, or lacks a result')
    return dict(counts)


def artifact_path(value):
    """Require a normalized, nonempty path relative to the emitted workspace."""
    if not isinstance(value, str) or not value:
        raise ValueError('nonempty workspace-relative artifact path required')
    path = Path(value)
    if path.is_absolute() or '..' in path.parts or str(path) != value or value == '.':
        raise ValueError('normalized workspace-relative artifact path required: ' + value)
    return path


def runtime_binary(workspace, check):
    """Use a declared suite invocation only when it is the built artifact's copy."""
    root=Path(workspace)/'bazel-bin'
    binary=root/artifact_path(check['binary'])
    invocation=root/artifact_path(check.get('invocation',check['binary']))
    if digest(invocation)!=digest(binary):
        raise ValueError('runtime invocation differs from built executable')
    return invocation


def verify_modules(workspace, directory, modules):
    receipts={}
    for module in modules:
        name=module['name']
        if not name or Path(name).name!=name or name in ('.','..') or name in receipts:
            raise ValueError('unique module basename required')
        path=directory/('module-runtime-'+name)/'receipt.json'
        receipt=json.loads(path.read_text())
        if (receipt['status']!='passed' or receipt.get('execution_mode')!='trace-only' or
            receipt.get('arguments')!=[] or
            receipt['binary_sha256']!=digest(workspace/'bazel-bin'/artifact_path(module['binary'])) or
            receipt['driver_sha256']!=digest(workspace/'elf-runtime-check.py') or
            set(receipt['libraries'])!=set(module['libraries'])):
            raise ValueError('module loader receipt identity differs: '+name)
        for soname,artifact in module['libraries'].items():
            if receipt['libraries'][soname]['sha256']!=digest(workspace/'bazel-bin'/artifact_path(artifact)):
                raise ValueError('module dependency digest differs: '+soname)
        receipts[name]=digest(path)
    return receipts


def verify(workspace, sqlite, output):
    workspace = Path(workspace).resolve(strict=True)
    sqlite = Path(sqlite).resolve(strict=True)
    tool_hash = digest(sqlite)
    policies = json.loads((workspace/'configured-test-policy.json').read_text())
    inventory = json.loads((workspace/'native-test-inventory.json').read_text())
    checks = {c['name']:c for c in inventory['runtime_checks']}
    if len(checks) != len(inventory['runtime_checks']):
        raise ValueError('duplicate runtime check identity')
    totals = collections.Counter(); results = {}
    for name in policies:
        if name not in checks:
            raise ValueError('configured ATF test lacks runtime/listing check: '+name)
        check = checks[name]
        if check.get('args') != ['-l']:
            raise ValueError('configured ATF runtime check must list cases')
        test_path = artifact_path(name)
        binary_path = artifact_path(check['binary'])
        library_paths = {soname:artifact_path(path) for soname,path in check['libraries'].items()}
        directory = workspace/'bazel-testlogs'/test_path/'test.outputs'
        database = directory/'results.db'
        runtime = directory/'runtime'
        receipt = json.loads((runtime/'receipt.json').read_text())
        if (receipt['status'] != 'passed' or
            receipt['binary_sha256'] != digest(workspace/'bazel-bin'/binary_path) or
            receipt['driver_sha256'] != digest(workspace/'elf-runtime-check.py') or
            set(receipt['libraries']) != set(check['libraries'])):
            raise ValueError('ATF native runtime receipt identity differs: '+name)
        for soname, artifact in library_paths.items():
            if receipt['libraries'][soname]['sha256'] != digest(workspace/'bazel-bin'/artifact):
                raise ValueError('ATF native library digest differs: '+soname)
        module_receipts=verify_modules(workspace,directory,check.get('modules',[]))
        sql = ('SELECT name,result_type,result_reason FROM test_cases '
               'LEFT JOIN test_results USING(test_case_id) ORDER BY name')
        before = digest(database)
        def query(statement):
            return json.loads(subprocess.check_output(
                [str(sqlite),'-init','/dev/null','-readonly','-batch','-json',str(database),statement],
                env={'PATH':'/bin:/usr/bin','LC_ALL':'C'},text=True))
        programs = query('SELECT relative_path,interface FROM test_programs')
        if programs != [dict(relative_path=binary_path.name, interface='atf')]:
            raise ValueError('Kyua program identity differs: '+name)
        rows = query(sql)
        counts = compare_cases((runtime/'runtime.stdout').read_text(),rows)
        if digest(database) != before:
            raise ValueError('Kyua database changed during audit')
        totals.update(counts)
        results[name] = dict(cases=rows,counts=counts,database_sha256=before,
                             runtime_receipt_sha256=digest(runtime/'receipt.json'),module_receipt_sha256=module_receipts)
    if not results:
        raise ValueError('nonempty configured ATF inventory required')
    if digest(sqlite) != tool_hash:
        raise ValueError('SQLite tool changed during audit')
    result = dict(status='passed',scope='configured ATF case inventory and recorded outcomes',
                  programs=len(results),cases=sum(totals.values()),case_counts=dict(totals),
                  all_cases_passed=set(totals)=={'passed'},checks=results,
                  sqlite=str(sqlite),sqlite_sha256=tool_hash,
                  limitations=['Skipped and expected-failure cases are not passing cases.',
                               'Host kernel and execution tools remain in use.'])
    Path(output).write_text(json.dumps(result,indent=2)+'\n')
    return result
