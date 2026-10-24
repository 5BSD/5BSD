# SPDX-License-Identifier: BSD-2-Clause
"""Read ATF's declared timeout and cleanup contract without running test bodies."""
import re
import json


def parse_listing(listing):
    sections = listing.strip().split('\n\n')
    if sections.pop(0) != 'Content-Type: application/X-atf-tp; version="1"':
        raise ValueError('invalid ATF content type')
    cases = {}
    for section in sections:
        fields = {}
        for line in section.splitlines():
            key, separator, value = line.partition(': ')
            if not separator or key in fields:
                raise ValueError('invalid/duplicate ATF metadata')
            fields[key] = value
        name = fields.get('ident', '')
        if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,126}', name) or name in cases:
            raise ValueError('invalid/duplicate ATF case')
        timeout = fields.get('timeout', '40')
        cleanup = fields.get('has.cleanup', 'false')
        if not re.fullmatch(r'[1-9][0-9]{0,3}', timeout) or int(timeout) > 3600:
            raise ValueError('unsupported ATF timeout')
        if cleanup not in ('true', 'false'):
            raise ValueError('invalid ATF cleanup flag')
        cases[name] = {'timeout': int(timeout), 'cleanup': cleanup == 'true'}
    if not cases:
        raise ValueError('empty ATF listing')
    return cases


def cases_completed(output, metadata):
    """Require body and declared cleanup evidence independently."""
    lines = output.splitlines()
    if not metadata or any('RUNTIME_CASE_FAIL' in line or
                           'RUNTIME_CLEANUP_FAIL' in line for line in lines):
        return False
    for case in metadata:
        identity = case['program'] + ':' + case['case']
        if lines.count('RUNTIME_CASE_PASS ' + identity) != 1:
            return False
        cleanups = lines.count('RUNTIME_CLEANUP_PASS ' + identity)
        if cleanups != int(case['cleanup']):
            return False
    return True


def apply_case_budgets(metadata, suites, specifications, vm_timeout):
    """Apply explicit budgets to exact selected source/case identities.

    Declared ATF limits remain recorded. Budgets change only the harness deadline,
    never completion, cleanup or failure requirements.
    """
    selected = {}
    for suite in suites:
        for case in suite['cases']:
            identity = suite['source'] + ':' + case
            selected.setdefault(identity, []).append(('/tests/' + suite['alias'], case))
    result = [dict(item) for item in metadata]
    seen = set()
    for specification in specifications:
        identity, separator, value = specification.rpartition('=')
        if (not separator or not re.fullmatch(r'[1-9][0-9]{0,4}', value) or
                not 1 <= int(value) <= 86400):
            raise ValueError('case budget requires exact source:case=seconds (1..86400)')
        if identity in seen:
            raise ValueError('duplicate case budget')
        seen.add(identity)
        matches = selected.get(identity, [])
        if len(matches) != 1:
            raise ValueError('case budget must identify exactly one selected source/case')
        if int(value) >= vm_timeout:
            raise ValueError('case budget must be below the outer VM timeout')
        program, case = matches[0]
        records = [item for item in result if item['program'] == program and item['case'] == case]
        if len(records) != 1:
            raise ValueError('case budget has missing or ambiguous runtime metadata')
        record = records[0]
        record['declared_timeout'] = record['timeout']
        record['timeout'] = int(value)
        record['budget_input'] = specification
    return result


def parse_runtime_description(text):
    """Require an explicit compatible helper contract before VM execution."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate runtime helper field')
            result[key] = value
        return result
    try:
        value = json.loads(text, object_pairs_hook=unique)
    except (ValueError, TypeError) as error:
        raise ValueError('invalid runtime helper description') from error
    if (not isinstance(value, dict) or set(value) != {
            'format', 'case_metadata_version', 'maximum_case_timeout', 'cleanup'} or
            type(value['format']) is not int or value['format'] != 1 or
            type(value['case_metadata_version']) is not int or value['case_metadata_version'] != 1 or
            type(value['maximum_case_timeout']) is not int or
            not 1 <= value['maximum_case_timeout'] <= 86400 or value['cleanup'] is not True):
        raise ValueError('incompatible runtime helper description; rebuild selected fixture')
    return value
