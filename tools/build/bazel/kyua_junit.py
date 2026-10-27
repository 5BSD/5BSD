# SPDX-License-Identifier: BSD-2-Clause
"""Preserve typed Kyua outcomes in JUnit for a single-program Bazel suite.

Kyua schema v3 is defined in contrib/kyua/store/schema_v3.sql. Its legacy JUnit
exporter renders expected failures as passes; use the database, never log text.
"""
import argparse
from pathlib import Path
import subprocess
import json
import hashlib
import xml.etree.ElementTree as ET


def query(kyua, database, statement):
    output = subprocess.check_output([str(kyua), '-c', 'none',
        '--logfile=' + str(database) + '.query.log', 'db-exec', '--no-headers',
        '--results-file=' + str(database), statement], text=True)
    return [json.loads(line) for line in output.splitlines()]


def reconcile(database, report, program, kyua):
    # db-exec opens read/write; issue only fixed SELECTs and verify no mutation.
    before = hashlib.sha256(Path(database).read_bytes()).digest()
    version = query(kyua, database, 'SELECT json_array(MAX(schema_version)) FROM metadata')
    if version != [[3]]:
        raise ValueError('unsupported Kyua result schema: ' + str(version))
    rows = query(kyua, database, 'SELECT json_array(p.relative_path, c.name, r.result_type, r.result_reason) FROM test_results r JOIN test_cases c USING(test_case_id) JOIN test_programs p USING(test_program_id)')
    if hashlib.sha256(Path(database).read_bytes()).digest() != before:
        raise ValueError('Kyua database changed while reading results')
    results = {}
    for path, name, outcome, reason in rows:
        if path != program or name in results:
            raise ValueError('unexpected program or duplicate result')
        if outcome not in ('passed', 'failed', 'broken', 'skipped', 'expected_failure'):
            raise ValueError('unknown Kyua outcome: ' + str(outcome))
        if outcome != 'passed' and not reason:
            raise ValueError('non-passing outcome lacks a reason')
        results[name] = (outcome, reason)
    tree = ET.parse(report)
    if tree.getroot().tag != 'testsuite':
        raise ValueError('unexpected Kyua JUnit root')
    cases = list(tree.getroot().iter('testcase'))
    names = [case.get('name') for case in cases]
    if not results or len(names) != len(set(names)) or set(names) != set(results):
        raise ValueError('Kyua database and XML case inventories differ')
    for case in cases:
        if case.get('classname') != program.replace('/', '.'):
            raise ValueError('unexpected JUnit program identity')
        for node in list(case):
            if node.tag in ('failure', 'error', 'skipped'):
                case.remove(node)
        outcome, reason = results[case.get('name')]
        tag = {'failed': 'failure', 'broken': 'error', 'skipped': 'skipped',
               'expected_failure': 'skipped'}.get(outcome)
        if tag:
            message = ('expected_failure: ' if outcome == 'expected_failure' else '') + reason
            ET.SubElement(case, tag, message=message)
    temporary = Path(str(report) + '.tmp')
    tree.write(temporary, encoding='utf-8', xml_declaration=True)
    temporary.replace(report)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kyua', required=True)
    parser.add_argument('--database', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--program', required=True)
    args = parser.parse_args()
    reconcile(args.database, args.report, args.program, args.kyua)
