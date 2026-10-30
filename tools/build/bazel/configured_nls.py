# SPDX-License-Identifier: BSD-2-Clause
"""Describe bsd.nls.mk catalogue inputs and emit native generation actions."""
from pathlib import Path
import shlex
import shutil
from libmd_environment import digest


def export(src, component, query, extra, inputs):
    keys = ['NLS', 'MK_NLS', 'GENCAT', 'PATH', '.PATH', 'FILESGROUPS']
    base = query(component, keys, extra)
    if base['MK_NLS'] == 'no' or not base['NLS'].strip():
        return None
    if base['MK_NLS'] != 'yes' or 'NLS' not in shlex.split(base['FILESGROUPS']):
        raise ValueError('enabled NLS requires the maintained NLS file group')
    names = shlex.split(base['NLS'])
    if len(names) != len(set(names)) or any(Path(n).name != n or not n.endswith('.cat') for n in names):
        raise ValueError('unique NLS catalogue basenames required')
    command = shlex.split(base['GENCAT'])
    if len(command) != 1:
        raise ValueError('GENCAT must select one executable')
    selected = shutil.which(command[0], path=base['PATH'])
    if selected is None:
        raise ValueError('configured gencat not found')
    tool = Path(selected).resolve(strict=True)
    inputs[str(tool)] = digest(tool)
    fields = [prefix + n[:-4] for n in names for prefix in ('NLSSRCFILES_', 'NLSSRCDIR_')]
    values = query(component, fields, extra)
    search = [component] + [Path(p) if Path(p).is_absolute() else component / p
                            for p in shlex.split(base['.PATH'])]

    def source(path):
        path = path.resolve(strict=True)
        if not path.is_relative_to(src) or not path.is_file():
            raise ValueError('NLS source must be a maintained source file')
        inputs[str(path)] = digest(path)
        return dict(path=str(path.relative_to(src)), sha256=inputs[str(path)])

    outputs = []
    for name in names:
        stem = name[:-4]
        parts = shlex.split(values['NLSSRCFILES_' + stem])
        if parts:
            directory = Path(values['NLSSRCDIR_' + stem])
            if not directory.is_absolute():
                directory = component / directory
            sources = [source(directory / p) for p in parts]
        else:
            candidates = [p / (stem + '.msg') for p in search]
            selected_source = next((p for p in candidates if p.is_file()), None)
            if selected_source is None:
                raise ValueError('NLS input requires explicit source/prebuild metadata: ' + name)
            sources = [source(selected_source)]
        outputs.append(dict(name=name, sources=sources, concatenate=bool(parts)))
    if query(component, keys, extra) != base or query(component, fields, extra) != values:
        raise ValueError('NLS configuration changed during export')
    return dict(tool=dict(path=str(tool), sha256=inputs[str(tool)]), outputs=outputs)


def emit(component, receipt, src, copy, rule):
    record = component.get('nls_generation')
    if not record:
        return {}
    tool = record['tool']
    if (receipt['tool_origins'].get('extra_gencat') != tool['path'] or
            receipt['inputs'].get(tool['path']) != tool['sha256']):
        raise ValueError('configured gencat differs from staged SDK')
    name = component['metadata']['LIB'] or component['metadata']['PROG']
    labels = {}
    for output in record['outputs']:
        sources = []
        for source in output['sources']:
            origin = src / source['path']
            if not origin.resolve().is_relative_to(src) or digest(origin) != source['sha256']:
                raise ValueError('NLS source changed or escaped source tree')
            sources.append(copy(origin))
        target = name + '_catalogue_' + output['name']
        rule('bsd_catalogue', name=target, sources=sources, concatenate=output['concatenate'],
             output='generated/' + name + '/' + output['name'],
             gencat='//toolchain:extra_gencat', cat='//toolchain:cat',
             redirect='//toolchain:stdout_redirect',
             runtime=['//toolchain:extra_gencat_runtime', '//toolchain:cat_runtime'])
        labels[output['name']] = ':' + target
    return labels
