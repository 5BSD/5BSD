# SPDX-License-Identifier: BSD-2-Clause
"""Explicit FreeBSD userland ABI identities and separate execution SDK policy."""
import hashlib
import json
from pathlib import Path
import re

ARCHITECTURES = {
    'amd64': {'machine': 'amd64', 'machine_arch': 'amd64', 'triple_cpu': 'x86_64', 'platform_cpu': 'x86_64', 'toolchain_cpu': 'k8'},
    'aarch64': {'machine': 'arm64', 'machine_arch': 'aarch64', 'triple_cpu': 'aarch64', 'platform_cpu': 'aarch64', 'toolchain_cpu': 'aarch64'},
    'riscv64': {'machine': 'riscv', 'machine_arch': 'riscv64', 'triple_cpu': 'riscv64', 'platform_cpu': 'riscv64', 'toolchain_cpu': 'riscv64'},
}


def architecture(name):
    if name not in ARCHITECTURES:
        raise ValueError('unsupported FreeBSD userland architecture')
    return ARCHITECTURES[name]


def target_architecture(target):
    if not isinstance(target, str):
        raise ValueError('explicit compiler target triple required')
    for name, identity in ARCHITECTURES.items():
        if re.fullmatch(identity['triple_cpu'] + r'-unknown-freebsd[0-9]+(?:\.[0-9]+)*', target):
            return name
    raise ValueError('unsupported FreeBSD compiler target triple')


def verify_profile(values, requested='amd64'):
    identity = architecture(requested)
    if (values.get('TARGET'), values.get('TARGET_ARCH')) != (identity['machine'], identity['machine_arch']):
        raise ValueError('recorded profile differs from explicitly selected architecture')


def receipt_architecture(receipt, requested):
    """Keep old native receipts valid; cross receipts must bind a native host SDK."""
    architecture(requested)
    if target_architecture(receipt.get('target')) != requested:
        raise ValueError('SDK compiler target differs from requested userland architecture')
    if requested == 'amd64':
        if receipt.get('execution_target') is not None and target_architecture(receipt['execution_target']) != 'amd64':
            raise ValueError('native SDK execution target differs from this host')
        return
    if receipt.get('format') != 2 or target_architecture(receipt.get('execution_target')) != 'amd64':
        raise ValueError('cross userland requires a separate native execution SDK')
    host = receipt.get('execution_sdk')
    if not isinstance(host, dict) or set(host) != {'workspace', 'receipt', 'receipt_sha256', 'snapshot_sha256'}:
        raise ValueError('complete execution SDK origin binding required')
    for field in ['workspace', 'receipt']:
        path = Path(host[field])
        if not path.is_absolute() or not path.is_relative_to('/usr/obj') or '..' in path.parts:
            raise ValueError('execution SDK inputs must use explicit /usr/obj paths')
    for field in ['receipt_sha256', 'snapshot_sha256']:
        if not isinstance(host[field], str) or not re.fullmatch('[0-9a-f]{64}', host[field]):
            raise ValueError('execution SDK digest binding required')
    if receipt.get('inputs', {}).get(host['receipt']) != host['receipt_sha256']:
        raise ValueError('execution SDK receipt is not bound as an input')
    snapshot = receipt.get('snapshot', {})
    for name in ['BUILD.bazel', 'cc_toolchain_config.bzl', 'bin/clang']:
        if 'toolchain/host/' + name not in snapshot:
            raise ValueError('cross SDK lacks its declared host toolchain closure')


def verify_snapshot(workspace, receipt):
    """Verify a real SDK before composing it; never rewrite stale bindings."""
    workspace = Path(workspace).resolve(strict=True)
    if not workspace.is_relative_to('/usr/obj'):
        raise ValueError('SDK workspace must be below /usr/obj')
    for field in ['inputs', 'execution_host_dependencies']:
        bindings = receipt.get(field)
        if not isinstance(bindings, dict):
            raise ValueError('SDK source/runtime bindings required')
        for value, expected in bindings.items():
            path = Path(value)
            if not path.is_absolute() or digest(path) != expected:
                raise ValueError('SDK input changed: ' + value)
    snapshot = receipt.get('snapshot')
    if not isinstance(snapshot, dict) or not snapshot:
        raise ValueError('complete SDK snapshot required')
    actual = {str(path.relative_to(workspace)) for path in (workspace/'toolchain').rglob('*') if path.is_file()}
    if actual != set(snapshot):
        raise ValueError('SDK snapshot file inventory changed')
    for value, expected in snapshot.items():
        path = Path(value)
        if (path.is_absolute() or '..' in path.parts or
                not (workspace/path).resolve(strict=True).is_relative_to(workspace) or
                digest(workspace / path) != expected):
            raise ValueError('SDK snapshot changed: ' + value)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def snapshot_digest(receipt):
    return hashlib.sha256(json.dumps(receipt['snapshot'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
