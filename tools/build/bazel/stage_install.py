# SPDX-License-Identifier: BSD-2-Clause
"""Validate explicit stage policy/tool inputs and emit the native install action."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import os

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def emit(root, policy_path, receipt_path, library, library_policy=None, test_policy=None, *, payload_policies=None, manifest_labels=None):
    policy = json.loads(policy_path.read_text())
    receipt = json.loads(receipt_path.read_text())
    if type(policy.get('format')) is not int or policy['format'] != 1 or policy.get('status') != 'reconciled':
        raise ValueError('reconciled directory policy format 1 required')
    if type(receipt.get('format')) is not int or receipt['format'] != 1 or receipt.get('status') != 'passed' or set(receipt.get('tools', {})) != {'install'}:
        raise ValueError('verified installer tool receipt required')
    tool = receipt['tools']['install']
    if tool.get('static_elf') is not True:
        raise ValueError('installer must have a verified static execution closure')
    environments = policy['build_environment']
    if not isinstance(environments, list) or not environments:
        raise ValueError('directory build environments required')
    for key in ('objtop', 'target', 'profile_assignments'):
        for environment in [*environments, tool['environment']]:
            if environment[key] != library['build_environment'][key]:
                raise ValueError('stage profile differs: ' + key)
    inputs = dict(policy['input_sha256'])
    selected_policies = payload_policies if payload_policies is not None else [library_policy, test_policy]
    if not selected_policies or any(path is None for path in selected_policies):
        raise ValueError("explicit payload policies required")
    for path in selected_policies:
        if inputs.get(str(path)) != digest(path):
            raise ValueError('directory policy does not bind selected payload policy: ' + str(path))
    inputs.update(receipt['inputs'])
    inputs.update(receipt['source_hashes'])
    inputs.update(tool['environment']['input_sha256'])
    inputs.update(tool['configured_make_include_closure'])
    inputs[tool['binary']] = tool['sha256']
    for path in (policy_path, receipt_path, Path(__file__), Path(__file__).with_name('bsd_stage.bzl'), Path(__file__).with_name('bsd_install.bzl'), Path(__file__).with_name('bsd_kyua_metadata.bzl')):
        inputs[str(path)] = digest(path)
    def verify():
        for path, expected in inputs.items():
            if digest(path) != expected:
                raise ValueError('stage input changed: ' + path)
    verify()
    directories = {}
    for path, original in policy['directories'].items():
        meta = dict(original)
        if set(meta) - {'type', 'uname', 'gname', 'mode', 'tags', 'flags'}:
            raise ValueError('unsupported directory metadata: ' + path)
        if type(meta['mode']) is not int or not 0 <= meta['mode'] <= 0o7777:
            raise ValueError('invalid directory mode: ' + path)
        meta['mode'] = format(meta['mode'], '04o')
        directories[path] = json.dumps(meta, sort_keys=True)
    tools = root / 'install-tools'
    tools.mkdir(exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=tools, prefix='.installer-')
    os.close(fd)
    try:
        shutil.copyfile(tool['binary'], temporary)
        if digest(temporary) != tool['sha256']:
            raise ValueError('installer changed while staging')
        os.chmod(temporary, 0o755)
        os.replace(temporary, tools / 'install')
    finally:
        if os.path.exists(temporary): os.unlink(temporary)
    shutil.copyfile(Path(__file__).with_name('bsd_stage.bzl'), root / 'bsd_stage.bzl')
    verify()
    (root / 'stage-install-inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    values = dict(name='native_stage', manifests=manifest_labels if manifest_labels is not None else [':library_install_manifest', ':test_install_manifest'], directories=directories, installer='install-tools/install', shell='//toolchain:sh')
    return ['load(":bsd_stage.bzl", "bsd_stage")', 'bsd_stage(' + ', '.join(k+'='+json.dumps(v) for k,v in values.items()) + ')']
