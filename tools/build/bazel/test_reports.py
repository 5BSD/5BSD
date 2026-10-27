# SPDX-License-Identifier: BSD-2-Clause
"""Retain BEP test reports and distinguish action status from case outcomes."""
import collections
import json
from pathlib import Path
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET
from libmd_environment import digest


def case_counts(xml):
    root = ET.fromstring(xml)
    if root.tag not in ('testsuites', 'testsuite'):
        raise ValueError('unrecognized test XML root')
    counts = collections.Counter()
    for case in root.iter('testcase'):
        if case.find('failure') is not None or case.find('error') is not None:
            outcome = 'failed'
        elif (skip := case.find('skipped')) is not None:
            outcome = ('expected_failure' if skip.get('message', '').startswith('expected_failure: ')
                       else 'skipped')
        else:
            outcome = 'passed'
        counts[outcome] += 1
    if not counts:
        raise ValueError('test XML contains no cases')
    return dict(counts)


def snapshot(events, destination, expected, *, diagnostic=False):
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    records = []
    identities = set()
    labels = set()
    totals = collections.Counter()
    for event in events:
        if 'testResult' not in event:
            continue
        identity = event['id']['testResult']
        label = identity['label']
        if label not in expected:
            raise ValueError('unexpected test report: ' + label)
        key = json.dumps(identity, sort_keys=True)
        if key in identities:
            raise ValueError('duplicate test result identity')
        identities.add(key)
        labels.add(label)
        record = dict(identity=identity, action_status=event['testResult']['status'], files={})
        directory = destination / str(len(records))
        directory.mkdir(mode=0o700)
        for output in event['testResult'].get('testActionOutput', []):
            name = output['name']
            if name not in ('test.log', 'test.xml'):
                continue
            if name in record['files']:
                raise ValueError('duplicate test report file')
            uri = urlsplit(output.get('uri', ''))
            if uri.scheme != 'file' or uri.netloc or uri.query or uri.fragment:
                raise ValueError('local test report URI required')
            source = Path(unquote(uri.path))
            if not source.is_absolute() or not source.is_file():
                raise ValueError('regular test report file required')
            before = digest(source)
            target = directory / name
            target.write_bytes(source.read_bytes())
            if digest(target) != before or digest(source) != before:
                raise ValueError('test report changed during capture')
            record['files'][name] = dict(path=str(target.relative_to(destination)), sha256=before)
            if name == 'test.xml':
                try:
                    record['case_counts'] = case_counts(target.read_bytes())
                except (ValueError, ET.ParseError) as error:
                    if not diagnostic:
                        raise
                    record['xml_error'] = str(error)
                else:
                    totals.update(record['case_counts'])
        if 'case_counts' not in record:
            if not diagnostic:
                raise ValueError('test result lacks XML case evidence: ' + label)
            record['case_evidence_missing'] = True
        records.append(record)
    if labels != set(expected):
        raise ValueError('test report inventory mismatch')
    result = dict(scope=('diagnostic reports from observed test attempts; not a complete test inventory'
                         if diagnostic else 'reported cases across all recorded test attempts'),
                  case_counts=dict(totals), all_reported_cases_passed=not diagnostic and bool(totals) and set(totals) == {'passed'},
                  results=records)
    manifest = destination / 'manifest.json'
    manifest.write_text(json.dumps(result, indent=2) + '\n')
    return dict(manifest_sha256=digest(manifest), case_counts=dict(totals),
                all_reported_cases_passed=result['all_reported_cases_passed'])


def snapshot_failure(event_file, destination):
    """Retain available reports after failure, without claiming full coverage."""
    events = []
    errors = []
    with Path(event_file).open() as stream:
        for number, line in enumerate(stream, 1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                errors.append(dict(line=number, error=str(error)))
                continue
            if 'testResult' in event:
                events.append(event)
    observed = sorted({event['id']['testResult']['label']
                       for event in events if 'testResult' in event})
    result = snapshot(events, destination, observed, diagnostic=True)
    return dict(result, observed_tests=observed, event_errors=errors,
                inventory_complete=False)
