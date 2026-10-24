#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Evaluate a trusted ports tree for a pinned Bazel package; never build/install."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

VARIABLES = ('PKGNAME', 'JAVA_PORT', 'JAVA_HOME', 'BUILD_DEPENDS', 'RUN_DEPENDS',
             'LIB_DEPENDS', 'LICENSE', 'MAKE_JOBS_NUMBER', 'CONFLICTS_INSTALL')


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate configuration key: ' + key)
        result[key] = value
    return result


def load_config(path):
    config = json.loads(path.read_text(), object_pairs_hook=unique)
    if (not isinstance(config, dict) or
            set(config) != {'format', 'origin', 'package', 'java_origin'} or
            type(config['format']) is not int or config['format'] != 1):
        raise ValueError('requires format-1 origin/package/java_origin configuration')
    for key in ('origin', 'java_origin'):
        if (not isinstance(config[key], str) or
                not re.fullmatch(r'[A-Za-z0-9_+.-]+/[A-Za-z0-9_+.-]+', config[key]) or
                any(p in ('.', '..') for p in config[key].split('/'))):
            raise ValueError('invalid port origin: ' + key)
    if not isinstance(config['package'], str) or not re.fullmatch(r'[A-Za-z0-9_+.,-]+', config['package']):
        raise ValueError('invalid package identity')
    return config


def plan(ports, config, make):
    ports = ports.resolve(strict=True)
    port = (ports / config['origin']).resolve(strict=True)
    if not port.is_relative_to(ports):
        raise ValueError('origin resolves outside selected ports tree')
    argv = [str(make), '-C', str(port), 'PORTSDIR=' + str(ports)]
    for variable in VARIABLES:
        argv += ['-V', variable]
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=True)
    lines = result.stdout.splitlines()
    if len(lines) != len(VARIABLES):
        raise ValueError('unexpected make variable output')
    values = dict(zip(VARIABLES, lines))
    if values['PKGNAME'] != config['package']:
        raise ValueError('selected port package does not match pinned package: ' + values['PKGNAME'])
    if values['JAVA_PORT'] != config['java_origin']:
        raise ValueError('selected Java port does not match pin: ' + values['JAVA_PORT'])
    return {'format': 1, 'scope': 'trusted-ports-metadata-only',
            'configuration': config, 'ports': str(ports), 'command': argv,
            'makefile_sha256': hashlib.sha256((port / 'Makefile').read_bytes()).hexdigest(),
            'variables': values, 'stderr': result.stderr,
            'built': False, 'installed': False, 'runtime_qualified': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ports', type=Path, required=True)
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--make', type=Path, default=Path('/usr/bin/make'))
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    result = plan(a.ports, load_config(a.config), a.make)
    with a.output.open('x') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
