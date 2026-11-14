# SPDX-License-Identifier: BSD-2-Clause
"""Bind original Make provider construction to an explicit Make-built drti."""
import json
from pathlib import Path, PurePosixPath
import shlex
import stat

from install_reference_libraries import digest, reference_compiler, safe_path, verify


def load(config_path, architecture, source_root, compiler):
    config_path = safe_path(str(config_path))
    config_sha = digest(config_path)
    value = json.loads(config_path.read_text())
    if (not isinstance(value, dict) or set(value) != {'format', 'runtime'} or
            type(value['format']) is not int or value['format'] != 1):
        raise ValueError('exact DTrace runtime input format 1 required')
    item = value['runtime']
    if not isinstance(item, dict) or set(item) != {'receipt', 'receipt_sha256', 'artifact', 'artifact_sha256'}:
        raise ValueError('exact original runtime receipt/artifact binding required')
    reference = safe_path(item['receipt'], True)
    if digest(reference) != item['receipt_sha256']:
        raise ValueError('DTrace runtime receipt digest mismatch')
    receipt = json.loads(reference.read_text())
    scope = 'native-amd64-Make-installation-reference' if architecture == 'amd64' else 'cross-Make-installation-reference'
    if (not isinstance(receipt, dict) or type(receipt.get('format')) is not int or receipt.get('format') != 1 or
            receipt.get('status') != 'passed' or receipt.get('scope') != scope or
            receipt.get('target_architecture') != architecture):
        raise ValueError('DTrace runtime requires a passed original Make target reference')
    component = safe_path(receipt.get('component'))
    if component != source_root / 'cddl/lib/drti':
        raise ValueError('DTrace runtime reference must own the drti component')
    environment = receipt.get('environment', {})
    selected, compiler_sha = reference_compiler(environment, compiler)
    relative = item['artifact']
    if (not isinstance(relative, str) or PurePosixPath(relative).is_absolute() or
            '..' in relative.split('/') or str(PurePosixPath(relative)) != relative):
        raise ValueError('canonical relative DTrace runtime artifact required')
    expected = reference.parent / 'objects' / str(component).lstrip('/') / 'drti.o'
    unresolved = reference.parent / relative
    artifact = safe_path(str(unresolved), True)
    if artifact != unresolved or artifact != expected or not stat.S_ISREG(artifact.lstat().st_mode):
        raise ValueError('regular original drti.o in the component object tree required')
    if digest(artifact) != item['artifact_sha256']:
        raise ValueError('DTrace runtime artifact digest mismatch')
    machine = {'amd64': 62, 'aarch64': 183, 'riscv64': 243}[architecture]
    with artifact.open('rb') as stream:
        header = stream.read(20)
    if (len(header) != 20 or header[:6] != b'\x7fELF\x02\x01' or
            int.from_bytes(header[16:18], 'little') != 1 or
            int.from_bytes(header[18:20], 'little') != machine):
        raise ValueError('DTrace runtime must be a target ELF64 relocatable object')
    record = dict(receipt=str(reference), receipt_sha256=item['receipt_sha256'],
                  artifact=str(artifact), artifact_sha256=item['artifact_sha256'],
                  syslibdir=str(artifact.parent), component=str(component))
    bindings = {str(config_path): config_sha, str(reference): item['receipt_sha256'],
                str(artifact): item['artifact_sha256'], str(selected): compiler_sha}
    verify(bindings)
    return record, bindings


def audit_recipes(objects, record, generator):
    """Require actual direct -G recipes to select exactly the bound syslibdir.

    Make metadata witnesses the completed recipe, not an observed exec event.
    Input digests are separately rechecked around every original Make phase.
    """
    if not generator or any(not isinstance(arg, str) or not arg for arg in generator):
        raise ValueError('explicit DTrace generator command required')
    matches = []
    expected = 'syslibdir=' + record['syslibdir']
    for metadata in sorted(objects.rglob('*.meta')):
        for line in metadata.read_text().splitlines():
            if not line.startswith('CMD '):
                continue
            argv = shlex.split(line[4:])
            if argv[:len(generator)] != generator or '-G' not in argv[len(generator):]:
                continue
            locations = [i for i, arg in enumerate(argv)
                         if arg.startswith(('syslibdir=', '-xsyslibdir='))]
            if (len(locations) != 1 or argv[locations[0]] != expected or
                    locations[0] == 0 or argv[locations[0] - 1] != '-x'):
                raise ValueError('DTrace provider recipe does not select exactly the bound runtime')
            matches.append(dict(metadata=str(metadata), metadata_sha256=digest(metadata), command=line[4:]))
    if not matches:
        raise ValueError('bound DTrace runtime missing from completed provider recipes')
    return matches
