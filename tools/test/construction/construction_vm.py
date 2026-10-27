# SPDX-License-Identifier: BSD-2-Clause
"""Disposable builder VM only; real executors, fixture package inputs."""
import contextlib
import ctypes as C
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

spec = importlib.util.spec_from_file_location('construction', '/tests/construction.py')
construction = importlib.util.module_from_spec(spec)
spec.loader.exec_module(construction)


def require(value, message):
    if not value:
        raise AssertionError(message)


def fixture(base, program, argv, output):
    root = base / 'root'
    root.mkdir(mode=0o755)
    files = {'/tool': (Path(program).read_bytes(), 0o755),
             '/input': (b'fixture:value#29:\n', 0o644)}
    if program.endswith('cap_mkdb'):
        stale = base / 'stale'
        stale.write_text('fixture:value#11:\n')
        subprocess.run([program, str(stale)], check=True)
        files['/input.db'] = ((base / 'stale.db').read_bytes(), 0o644)
    action = {'name': 'derive', 'argv': argv, 'inputs': ['/input'],
              'outputs': {output: {'type': 'file', 'uid': 0, 'gid': 0,
                                   'mode': 0o644, 'flags_set': 0, 'replace': False}}}
    manifest = {'name': 'construction-fixture', 'version': '1',
                'files': {p: {} for p in files},
                'annotations': {'5bsd.construction': json.dumps({'format': 1, 'actions': [action]})}}
    archive_path = base / 'fixture.pkg'
    with tarfile.open(archive_path, 'w:gz') as archive:
        encoded = json.dumps(manifest).encode()
        header = tarfile.TarInfo('+MANIFEST'); header.size = len(encoded)
        archive.addfile(header, io.BytesIO(encoded))
        for path, (data, mode) in files.items():
            target = root / path.lstrip('/')
            target.write_bytes(data); target.chmod(mode)
            os.utime(target, (1700000000, 1700000000))
            header = tarfile.TarInfo(path)
            header.size, header.mode, header.mtime = len(data), mode, 1700000000
            archive.addfile(header, io.BytesIO(data))
    inventory = construction.pkg.inventory_packages([archive_path])
    initial = {'format': 1, 'entries': {'/': {'type': 'directory', 'uid': 0,
        'gid': 0, 'mode': 0o755, 'flags_set': 0, 'source': 'explicit VM fixture root', 'replaces': []}}}
    (base / 'inventory.json').write_text(json.dumps(inventory))
    (base / 'initial.json').write_text(json.dumps(initial))
    return root, inventory, initial


def read_value(base):
    libc = C.CDLL(None)
    libc.cgetent.argtypes = [C.POINTER(C.c_void_p), C.POINTER(C.c_char_p), C.c_char_p]
    libc.cgetnum.argtypes = [C.c_void_p, C.c_char_p, C.POINTER(C.c_long)]
    libc.free.argtypes = [C.c_void_p]
    paths = (C.c_char_p * 2)(os.fsencode(base), None)
    entry, number = C.c_void_p(), C.c_long()
    require(libc.cgetent(C.byref(entry), paths, b'fixture') == 0, 'read generated database')
    try:
        require(libc.cgetnum(entry, b'value', C.byref(number)) == 0, 'read generated value')
        return number.value
    finally:
        libc.free(entry)


@contextlib.contextmanager
def workspace():
    with tempfile.TemporaryDirectory(prefix='construction-vm-') as directory:
        try:
            yield directory
        finally:
            for record in sorted(Path(directory).rglob('report/*')):
                if record.is_file():
                    print('CONSTRUCTION_RECORD ' + str(record), flush=True)
                    print(record.read_text(), flush=True)


def main():
    require(os.geteuid() == 0, 'installation fixture requires actual root')
    subprocess.run(['/usr/local/bin/python3.12', '-I', '-S', '-B', '/tests/installation_policy_test.py'],
        env=dict(os.environ, BSD_BUILD_CONSTRUCTION_HELPER='/tests/construction.py'),
        check=True, timeout=120)
    print('CONSTRUCTION_VM_PASS installation_configuration', flush=True)
    before = construction.jail_list()
    with workspace() as directory:
        base = Path(directory)
        good = base / 'good'; good.mkdir()
        root, inventory, initial = fixture(good, '/tests/cap_mkdb',
            ['/tool', '-l', '-f', '/output', '/input'], '/output.db')
        # Exercise the production CLI, including archive re-reading and root checks.
        subprocess.run(['/usr/local/bin/python3.12', '-I', '-S', '-B', '/tests/construction.py',
            '--root', str(root), '--inventory', str(good / 'inventory.json'),
            '--generated', str(good / 'initial.json'), '--output', str(good / 'report')], check=True)
        report = json.loads((good / 'report/construction.json').read_text())
        require(report['result'] == 'PASS' and len(report['receipts']) == 1, 'missing receipt')
        require(not report['inputs_authenticated'] and not report['generation_authenticated'], 'incorrect trust claim')
        require(read_value(root / 'output') == 29 and read_value(root / 'input') == 11, 'stale input selection')
        print('CONSTRUCTION_VM_PASS actual_generator_and_receipt', flush=True)

        bad = base / 'undeclared'; bad.mkdir()
        root, inventory, initial = fixture(bad, '/tests/cap_mkdb',
            ['/tool', '-l', '-f', '/rogue', '/input'], '/output.db')
        try:
            construction.construct(root, inventory, initial, bad / 'report')
        except ValueError as error:
            require('unaliased regular file' in str(error), str(error))
        else:
            raise AssertionError('undeclared output accepted')
        require(not (bad / 'report/generated.json').exists(), 'failed generation approved')
        require((root / 'rogue.db').is_file(), 'negative generator never ran')
        print('CONSTRUCTION_VM_PASS undeclared_output_rejected', flush=True)

        sentinel = base / 'host-only'; sentinel.write_text('outside jail')
        isolated = base / 'isolation'; isolated.mkdir()
        root, inventory, initial = fixture(isolated, '/tests/jail_probe',
            ['/tool', 'descendant', str(sentinel)], '/output')
        report = construction.construct(root, inventory, initial, isolated / 'report')
        require(report['result'] == 'PASS', 'isolation result')
        require((root / 'output').read_bytes() == b'checked\n', 'probe did not run')
        descendant = int((isolated / 'report/action-0.log').read_text().split('DESCENDANT ')[1].strip())
        try:
            os.kill(descendant, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError('descendant survived accepted receipt')
        require(construction.jail_list() == before, 'jail survived accepted receipt')
        print('CONSTRUCTION_VM_PASS isolation_and_descendant_cleanup', flush=True)

        changed = base / 'metadata'; changed.mkdir()
        root, inventory, initial = fixture(changed, '/tests/jail_probe',
            ['/tool', 'metadata', str(sentinel)], '/output')
        try:
            construction.construct(root, inventory, initial, changed / 'report')
        except ValueError as error:
            require('undeclared construction change: /input' in str(error), str(error))
        else:
            raise AssertionError('input metadata change accepted')
        require(not (changed / 'report/generated.json').exists(), 'metadata change approved')
        require((root / 'output').is_file(), 'metadata probe never executed')
        require(construction.jail_list() == before, 'metadata probe jail survived')
        print('CONSTRUCTION_VM_PASS undeclared_metadata_rejected', flush=True)

        timed = base / 'timeout'; timed.mkdir()
        root, inventory, initial = fixture(timed, '/tests/jail_probe',
            ['/tool', 'timeout', str(sentinel)], '/output')
        try:
            construction.construct(root, inventory, initial, timed / 'report', timeout=1)
        except subprocess.TimeoutExpired:
            pass
        else:
            raise AssertionError('timeout not enforced')
        require(not (timed / 'report/generated.json').exists(), 'timeout approved')
        require(json.loads((timed / 'report/construction.json').read_text())['result'] == 'FAIL', 'missing failure record')
        require(construction.jail_list() == before, 'timed-out jail survived')
        require(sentinel.read_text() == 'outside jail', 'outside input modified')
        print('CONSTRUCTION_VM_PASS timeout_cleanup', flush=True)

        runtime_spec = importlib.util.spec_from_file_location('runtime_fixture', '/tests/runtime_fixture.py')
        runtime = importlib.util.module_from_spec(runtime_spec)
        runtime_spec.loader.exec_module(runtime)
        runtime.run(base, construction)
        certificate_spec = importlib.util.spec_from_file_location('certificate_construction', '/tests/certificate_construction.py')
        certificate = importlib.util.module_from_spec(certificate_spec)
        certificate_spec.loader.exec_module(certificate)
        certificate.run(base, construction)
        module_spec = importlib.util.spec_from_file_location('module_construction', '/tests/module_construction.py')
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        module.run(base, construction)

        subprocess.run(['/usr/local/bin/python3.12', '-I', '-S', '-B',
                        '/tests/audit-kldxref.py', '--kldxref', '/usr/sbin/kldxref',
                        '--module', '/tests/selected.ko', '--work', '/tmp/kldxref-audit'],
                       check=True, user=65534, group=65534, extra_groups=[],
                       cwd='/tmp', timeout=90)
        print('CONSTRUCTION_VM_PASS module_hints_error_handling', flush=True)
        library_settings = Path('/tests/library-hints-settings.json')
        if library_settings.exists():
            settings = json.loads(library_settings.read_text())
            require(set(settings) == {'program', 'directory'}, 'invalid library hints fixture settings')
            subprocess.run(['/usr/local/bin/python3.12', '-I', '-S', '-B',
                            '/tests/audit-ldconfig.py', '--ldconfig', settings['program'],
                            '--directory', settings['directory'], '--strict',
                            '--work', '/tmp/library-hints-audit'],
                           check=True, user=65534, group=65534, extra_groups=[],
                           cwd='/tmp', timeout=90)
            print('CONSTRUCTION_VM_PASS library_hints_strict_inputs', flush=True)
            library_spec = importlib.util.spec_from_file_location('library_construction', '/tests/library_construction.py')
            library = importlib.util.module_from_spec(library_spec)
            library_spec.loader.exec_module(library)
            library.run(base, construction)

        subprocess.run(['/usr/local/bin/python3.12', '-I', '-S', '-B',
                        '/tests/audit-pnp.py', '--kldxref', '/usr/sbin/kldxref',
                        '--fixtures', '/tests/pnp', '--work', '/tmp/pnp-audit'],
                       check=True, user=65534, group=65534, extra_groups=[],
                       cwd='/tmp', timeout=90)
        print('CONSTRUCTION_VM_PASS module_pnp_validation', flush=True)
        subprocess.run(['/usr/local/bin/python3.12', '-I', '-S', '-B',
                        '/tests/audit-module-inputs.py', '--kldxref', '/usr/sbin/kldxref',
                        '--fixtures', '/tests/pnp', '--work', '/tmp/module-input-audit'],
                       check=True, user=65534, group=65534, extra_groups=[],
                       cwd='/tmp', timeout=90)
        print('CONSTRUCTION_VM_PASS module_explicit_inputs', flush=True)
        subprocess.run(['/usr/local/bin/python3.12', '-I', '-S', '-B',
                        '/tests/media_hints_fixture.py'], check=True,
                       user=65534, group=65534, extra_groups=[], cwd='/tmp', timeout=90)

        # Permission failures must run without UID zero or supplemental groups.
        subprocess.run(['/usr/local/bin/python3.12', '-I', '-S', '-B',
                        '/tests/certctl_failure_test.py', '-v'],
                       check=True, user=65534, group=65534, extra_groups=[],
                       cwd='/tmp', timeout=90)
        print('CONSTRUCTION_VM_PASS certificate_input_and_output_failures', flush=True)
        subprocess.run(['/usr/local/bin/python3.12', '-I', '-S', '-B',
                        '/tests/certificate_fixture.py'],
                       check=True, user=65534, group=65534, extra_groups=[],
                       cwd='/tmp', timeout=90)



if __name__ == '__main__':
    main()
