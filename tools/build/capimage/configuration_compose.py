# SPDX-License-Identifier: BSD-2-Clause
"""Compose explicit top-level changes against an exact JSON base document.

This is the semantic composition core, not a UCL parser or authority issuer.
Callers must authenticate the source and validate the resulting service policy.
Arrays and objects are replaced whole; no implicit recursive merge occurs.
"""
import argparse
import copy
import hashlib
import json
import subprocess
from pathlib import Path


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate configuration key: ' + key)
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError('non-finite JSON constant: ' + value)


def decode(data):
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=True, allow_nan=False).encode('ascii')


def compose(base_bytes, changes, *, normalized=None):
    base = decode(base_bytes if normalized is None else normalized)
    if not isinstance(base, dict):
        raise ValueError('base must be an object')
    fields = {'format', 'base_sha256', 'replace', 'add', 'remove'}
    if (not isinstance(changes, dict) or set(changes) != fields or
            type(changes['format']) is not int or changes['format'] != 1):
        raise ValueError('invalid composition fields or format')
    base_hash = hashlib.sha256(base_bytes).hexdigest()
    if changes['base_sha256'] != base_hash:
        raise ValueError('base differs from reviewed changes')
    seen = set()
    for operation in ('replace', 'add', 'remove'):
        rows = changes[operation]
        if not isinstance(rows, dict):
            raise ValueError('operation must be an object')
        for key in rows:
            if not isinstance(key, str) or not key or key in seen:
                raise ValueError('empty or conflicting operation key')
            seen.add(key)
    result = copy.deepcopy(base)
    for key, value in changes['add'].items():
        if key in base:
            raise ValueError('addition already exists: ' + key)
        result[key] = copy.deepcopy(value)
    for key, row in changes['replace'].items():
        if not isinstance(row, dict) or set(row) != {'expected', 'value'}:
            raise ValueError('replacement requires expected and value')
        if key not in base or encode(base[key]) != encode(row['expected']):
            raise ValueError('replacement precondition differs: ' + key)
        result[key] = copy.deepcopy(row['value'])
    for key, expected in changes['remove'].items():
        if key not in base or encode(base[key]) != encode(expected):
            raise ValueError('removal precondition differs: ' + key)
        del result[key]
    output = encode(result) + b'\n'
    receipt = {'format': 1, 'scope': 'explicit-configuration-composition',
        'base_sha256': base_hash, 'changes_sha256': hashlib.sha256(encode(changes)).hexdigest(),
        'output_sha256': hashlib.sha256(output).hexdigest(),
        'preserved_keys': sorted(set(base) - seen),
        'replaced_keys': sorted(changes['replace']), 'added_keys': sorted(changes['add']),
        'removed_keys': sorted(changes['remove']),
        'inputs_authenticated': False, 'service_policy_validated': False,
        'runtime_authority_assigned': False}
    return output, receipt



def compose_ucl(base_bytes, changes, parser, parser_sha256):
    parser = Path(parser)
    if (not parser.is_absolute() or parser.is_symlink() or not parser.is_file() or
            parser.resolve(strict=True) != parser):
        raise ValueError('parser must be a canonical regular file')
    def parser_digest():
        with parser.open('rb') as stream:
            return hashlib.file_digest(stream, 'sha256').hexdigest()
    if parser_digest() != parser_sha256:
        raise ValueError('parser differs from explicit hash')
    # Refuse stale input before executing even the explicitly selected parser.
    if not isinstance(changes, dict) or changes.get('base_sha256') != hashlib.sha256(base_bytes).hexdigest():
        raise ValueError('base differs from reviewed changes')
    if len(base_bytes) > 1024 * 1024:
        raise ValueError('base exceeds UCL policy size limit')
    result = subprocess.run([str(parser)], input=base_bytes, capture_output=True,
        timeout=30, check=True, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    if parser_digest() != parser_sha256:
        raise ValueError('parser changed during normalization')
    if len(result.stdout) > 16 * 1024 * 1024:
        raise ValueError('normalized policy exceeds size limit')
    output, receipt = compose(base_bytes, changes, normalized=result.stdout)
    receipt.update(base_format='ucl', parser_sha256=parser_sha256,
        normalized_base_sha256=hashlib.sha256(result.stdout).hexdigest())
    return output, receipt


def validate_capsule(configuration, validator, expected_hash, *, log_path=None):
    validator, configuration = Path(validator), Path(configuration)
    if (not validator.is_absolute() or validator.is_symlink() or not validator.is_file() or
            validator.resolve(strict=True) != validator):
        raise ValueError('Capsule validator must be a canonical regular file')
    def digest(path):
        with path.open('rb') as stream:
            return hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest(validator) != expected_hash:
        raise ValueError('Capsule validator differs from selected hash')
    before = digest(configuration)
    result = subprocess.run([str(validator), '-n', '-j', '-f', str(configuration.resolve(strict=True))],
        env={'PATH': '/sbin:/bin:/usr/sbin:/usr/bin', 'LC_ALL': 'C'},
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60, close_fds=True)
    log = Path(log_path) if log_path is not None else configuration.parent / 'capsule-validation.log'
    log.write_text(result.stdout + result.stderr)
    result.check_returncode()
    if digest(validator) != expected_hash or digest(configuration) != before:
        raise ValueError('Capsule validator or configuration changed during validation')
    selection = decode(result.stdout)
    if (not isinstance(selection, dict) or
            set(selection) != {'format', 'scope', 'service_manager', 'boot_configuration', 'normal_boot_configuration'} or
            type(selection['format']) is not int or selection['format'] != 2 or
            selection['scope'] != 'capsule-effective-manager' or
            not isinstance(selection['service_manager'], str) or
            '\0' in selection['service_manager'] or
            not isinstance(selection['boot_configuration'], str) or
            not selection['boot_configuration'].startswith('/') or
            '\0' in selection['boot_configuration'] or
            not isinstance(selection['normal_boot_configuration'], str) or
            not selection['normal_boot_configuration'].startswith('/') or
            '\0' in selection['normal_boot_configuration']):
        raise ValueError('invalid Capsule effective-manager report')
    return dict(scope='capsule-syntax-and-static-constraints', result='PASS',
                effective_manager=selection,
                configured_manager_coverage_complete=False,
                validator_sha256=expected_hash, configuration_sha256=before,
                inputs_authenticated=False, runtime_authority_assigned=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'changes', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--capsule-validator', type=Path)
    parser.add_argument('--capsule-validator-sha256')
    parser.add_argument('--ucl-parser', type=Path)
    parser.add_argument('--ucl-parser-sha256')
    args = parser.parse_args()
    if (args.ucl_parser is None) != (args.ucl_parser_sha256 is None):
        parser.error('UCL parser and its hash must be supplied together')
    if (args.capsule_validator is None) != (args.capsule_validator_sha256 is None):
        parser.error('Capsule validator and its hash must be supplied together')
    base = args.base.read_bytes()
    changes = decode(args.changes.read_bytes())
    output, receipt = (compose_ucl(base, changes, args.ucl_parser, args.ucl_parser_sha256)
                       if args.ucl_parser is not None else compose(base, changes))
    # Both artifacts share a fresh directory; partial output has no receipt.
    args.output.mkdir(mode=0o700)
    with (args.output / 'configuration.json').open('xb') as stream:
        stream.write(output)
    if args.capsule_validator is not None:
        receipt['capsule_static_validation'] = validate_capsule(args.output / 'configuration.json',
            args.capsule_validator, args.capsule_validator_sha256)
    with (args.output / 'receipt.json').open('x') as stream:
        json.dump(receipt, stream, indent=2); stream.write('\n')


if __name__ == '__main__':
    main()
