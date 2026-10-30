# SPDX-License-Identifier: BSD-2-Clause
"""Emit native FIDL rules from the maintained component configuration contract."""
from pathlib import Path
import component_labels
from libmd_environment import digest


def emit(component, receipt, src, copy, rule):
    bindings = component.get('fidl_bindings', [])
    if not bindings:
        return [], {}, set()
    configuration = component.get('fidl_configuration')
    if not configuration:
        raise ValueError('FIDL execution/output configuration missing; regenerate component plan')
    for role, sdk_role in (('compiler', 'extra_fidlc'), ('python', 'extra_python')):
        selected = configuration['execution_tools'][role]
        if receipt['tool_origins'].get(sdk_role) != selected['path'] or receipt['inputs'].get(selected['path']) != selected['sha256']:
            raise ValueError('configured FIDL tool differs from staged SDK: ' + role)
    if not receipt.get('python_runtime') or 'toolchain/python-home/runtime.json' not in receipt['snapshot']:
        raise ValueError('FIDL requires a staged declared Python standard library')
    object_directory = Path(configuration['object_directory'])
    labels, directories, generated = [], {}, set()
    names = set()
    for binding in bindings:
        name = binding['name']
        if not name or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in name) or name in names:
            raise ValueError('unique simple FIDL binding names required')
        names.add(name)
        # Component qualification currently requires unique library/program names.
        prefix = (component['metadata']['LIB'] or component['metadata']['PROG']) + '_fidl_' + name
        root = Path(binding['generated_root'])
        if not root.is_absolute() or '..' in root.parts or root == object_directory or not root.is_relative_to(object_directory):
            raise ValueError('invalid FIDL output root')
        outputs = binding['sources'] + binding['headers']
        relative = binding['relative_sources'] + binding['relative_headers']
        if len(outputs) != len(relative) or not outputs or len(set(outputs)) != len(outputs):
            raise ValueError('invalid FIDL output inventory')
        for original, local in zip(outputs, relative):
            if Path(original).is_absolute() or '..' in Path(original).parts or Path(local).is_absolute() or '..' in Path(local).parts or not local:
                raise ValueError('unsafe FIDL output path')
            if object_directory / original != root / local or original in generated:
                raise ValueError('conflicting FIDL output mapping')
            generated.add(original)

        def source(record):
            path = src / record['path']
            if not path.resolve(strict=True).is_relative_to(src) or digest(path) != record['sha256']:
                raise ValueError('FIDL source differs from configuration: ' + str(path))
            return copy(path)

        generator = binding['generator']
        if generator not in binding['generator_inputs']:
            raise ValueError('FIDL generator missing from input inventory')
        modules, templates = [], []
        for record in binding['generator_inputs']:
            if record == generator:
                continue
            path = Path(record['path'])
            if str(path.parent) == binding['template_directory']:
                templates.append(source(record))
            elif path.suffix == '.py' and path.parent == Path(generator['path']).parent:
                modules.append(source(record))
            else:
                raise ValueError('unmapped FIDL generator input: ' + record['path'])
        if not templates:
            raise ValueError('FIDL templates missing')
        rule('bsd_fidl_ir', name=prefix + '_ir', schemas=[source(s) for s in binding['schemas']],
             available=binding['available'], flags=binding['flags'], compiler='//toolchain:extra_fidlc',
             runtime=['//toolchain:extra_fidlc_runtime'])
        rule('bsd_fidl_bindings', name=prefix, ir=':' + prefix + '_ir', generator=source(generator),
             modules=modules, templates=templates, sources=binding['relative_sources'], headers=binding['relative_headers'],
             python='//toolchain:extra_python', python_home='//toolchain:python-home/runtime.json',
             runtime=['//toolchain:python_stdlib'])
        labels.append(':' + prefix)
        directories[str(root)] = component_labels.generated_directory(component,prefix)
    return labels, directories, generated
