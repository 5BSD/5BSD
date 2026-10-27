# SPDX-License-Identifier: BSD-2-Clause
"""Bazel package/label and output identities derived from source components."""
from pathlib import PurePosixPath


def relative(value):
    if not isinstance(value, str) or not value:
        raise ValueError('nonempty relative graph path required')
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or str(path) != value or value == '.' or any(c in value for c in ':\n\r'):
        raise ValueError('normalized relative graph path required: ' + value)
    return value


def package(component):
    source = component['component'] if isinstance(component, dict) else component
    return 'components/' + relative(source)


def label(component, target):
    return '//' + package(component) + ':' + relative(target)


def artifact(component, output):
    return package(component) + '/' + relative(output)


def generated_directory(component, output):
    return '$(GENDIR)/' + artifact(component, output)
