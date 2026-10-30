# SPDX-License-Identifier: BSD-2-Clause
"""Transport explicit installation inputs into a disposable builder VM.

This binds transport bytes and path translation, not policy approval.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate installation transport JSON key')
        result[key] = value
    return result


def regular(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('installation transport input must be canonical and unaliased')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('installation transport input must be regular')
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def invalid_constant(value):
    raise ValueError('invalid JSON constant: ' + value)


def load(path):
    with regular(path) as stream:
        raw = stream.read()
    value = json.loads(raw, object_pairs_hook=unique,
        parse_constant=invalid_constant)
    return value, hashlib.sha256(raw).hexdigest()


def translate(policy):
    if (not isinstance(policy, dict) or set(policy) != {'format', 'entries'} or
            type(policy['format']) is not int or policy['format'] not in (1, 2, 3, 4, 5) or
            not isinstance(policy['entries'], dict) or not policy['entries']):
        raise ValueError('invalid installation transport policy')
    translated = copy.deepcopy(policy)
    for index, name in enumerate(sorted(policy['entries'])):
        entry = policy['entries'][name]
        if is_candidate_path(policy, entry):
            if (set(entry) != {'operation', 'target', 'package', 'requirement'} or
                    any(not isinstance(entry[key], str) or not entry[key]
                        for key in ('target', 'package', 'requirement'))):
                raise ValueError('invalid installation transport alias')
            # Candidate paths are policy bytes, never host input filenames.
            # Destination ownership and resolution belong to the constructor.
            continue
        if (not isinstance(entry, dict) or not isinstance(entry.get('source'), str) or
                type(entry.get('size')) is not int or entry['size'] < 0 or
                not isinstance(entry.get('sha256'), str) or len(entry['sha256']) != 64 or
                any(c not in '0123456789abcdef' for c in entry['sha256'])):
            raise ValueError('invalid installation transport source identity')
        translated['entries'][name]['source'] = '/tests/installation-inputs/' + str(index)
    return translated


def is_candidate_path(policy, entry):
    return (isinstance(entry, dict) and
            ((policy['format'] >= 3 and entry.get('operation') == 'alias') or
             (policy['format'] >= 4 and entry.get('operation') == 'relocate')))


def check_bytes(path, entry):
    with regular(path) as stream:
        if os.fstat(stream.fileno()).st_size != entry['size']:
            raise ValueError('installation transport source size differs')
        if hashlib.file_digest(stream, 'sha256').hexdigest() != entry['sha256']:
            raise ValueError('installation transport source digest differs')


def stage(policy_path, fixture):
    policy_path = Path(policy_path)
    original, original_hash = load(policy_path)
    translated = translate(original)
    tests = fixture.extra / 'tests'
    # The fixture is a new private staging tree; refuse existing transport state.
    for name in ('system-installation-original.json', 'system-installation-policy.json',
                 'system-installation-transport.json', 'installation-inputs'):
        if (tests / name).exists() or (tests / name).is_symlink():
            raise ValueError('installation transport output already exists')
    for name, entry in original['entries'].items():
        if is_candidate_path(original, entry):
            continue
        source = Path(entry['source'])
        if str(source) != entry['source']:
            raise ValueError('installation source must be canonical')
        if source.is_relative_to(fixture.extra):
            raise ValueError('installation source must be outside fixture staging')
        check_bytes(source, entry)
        guest = translated['entries'][name]['source']
        target = fixture.extra / guest.lstrip('/')
        fixture.copy(source, target, source.parent)
        check_bytes(target, entry)
    destination = tests / 'system-installation-original.json'
    fixture.copy(policy_path, destination, policy_path.parent)
    if load(destination)[1] != original_hash:
        raise ValueError('installation policy changed during staging')
    data = (json.dumps(translated, sort_keys=True, indent=2) + '\n').encode()
    with (tests / 'system-installation-policy.json').open('xb') as stream:
        stream.write(data)
    report = dict(format=1, original_sha256=original_hash,
                  translated_sha256=hashlib.sha256(data).hexdigest())
    with (tests / 'system-installation-transport.json').open('x') as stream:
        json.dump(report, stream, sort_keys=True)
    verify(tests)
    return report


def verify(tests):
    tests = Path(tests)
    report, _ = load(tests / 'system-installation-transport.json')
    original, original_hash = load(tests / 'system-installation-original.json')
    translated, translated_hash = load(tests / 'system-installation-policy.json')
    if (report != dict(format=1, original_sha256=original_hash, translated_sha256=translated_hash) or
            type(report.get('format')) is not int):
        raise ValueError('installation transport record differs from policy bytes')
    if translate(original) != translated:
        raise ValueError('installation transport changed policy beyond source paths')
    for index, name in enumerate(sorted(original['entries'])):
        if is_candidate_path(original, original['entries'][name]):
            continue
        check_bytes(tests / 'installation-inputs' / str(index), original['entries'][name])
    return translated, report
