# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""Validate native parser headers against explicit options and source defaults."""
import re


def validate_header(text, expected):
    if not isinstance(expected, dict) or any(
            not isinstance(name, str) or not re.fullmatch(r'[A-Z0-9_]+', name) or
            type(value) is not bool for name, value in expected.items()):
        raise ValueError('explicit boolean kernel option expectations required')
    defined = set(re.findall(r'^#define\s+([A-Z0-9_]+)\b', text, re.M))
    for name, enabled in expected.items():
        if (name in defined) != enabled:
            raise ValueError('kernel option '+name+' differs from its declared setting/default; '
                             'reconcile the source configuration and Bazel option metadata')


def directory_text(directory):
    headers = sorted(directory.glob('opt*.h'))
    if not headers:
        raise ValueError('complete generated kernel option headers required')
    return '\n'.join(path.read_text() for path in headers)


def defined_options(directory):
    return set(re.findall(r'^#define\s+([A-Z0-9_]+)\b', directory_text(directory), re.M))


def validate_directory(directory, expected):
    validate_header(directory_text(directory), expected)
