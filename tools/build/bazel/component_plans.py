# SPDX-License-Identifier: BSD-2-Clause
"""Compose independently exported plans without changing their input bindings."""
import json
from pathlib import Path
from libmd_environment import digest


def load(paths, src):
    paths=[Path(p).resolve(strict=True) for p in paths]
    if not paths or len(paths)!=len(set(paths)):
        raise ValueError('unique component plan files required')
    merged=None; origins={}; components=set(); provenance=[]
    for path in paths:
        before=digest(path)
        with path.open() as stream:plan=json.load(stream)
        if digest(path)!=before:raise ValueError('component plan changed during read: '+str(path))
        if type(plan.get('format')) is not int or plan['format']!=1 or plan.get('status')!='configured' or not plan.get('components'):
            raise ValueError('nonempty configured format-1 component plan required')
        env=plan['build_environment']
        first=Path(plan['components'][0]['component'])
        if first.is_absolute() or '..' in first.parts or env['component']!=str(src.resolve()/first):
            raise ValueError('component plan source root mismatch')
        identity={k:v for k,v in env.items() if k not in ('component','commands','input_sha256','make_include_closure')}
        if merged is None:
            baseline=identity;overrides=plan.get('execution_tool_overrides',[])
            merged=dict(plan,components=[],input_sha256={},build_environment=dict(env,input_sha256={},make_include_closure={},commands=[]))
        elif identity!=baseline or plan.get('execution_tool_overrides',[])!=overrides:
            raise ValueError('component plans use different build environments or tool selections')
        for key,target in (('input_sha256',merged['input_sha256']),):
            for name,value in plan[key].items():
                if name in target and target[name]!=value:raise ValueError('conflicting component input: '+name)
                target[name]=value
        for key in ('input_sha256','make_include_closure'):
            target=merged['build_environment'][key]
            for name,value in env[key].items():
                if name in target and target[name]!=value:raise ValueError('conflicting environment input: '+name)
                if plan['input_sha256'].get(name)!=value:raise ValueError('environment input missing from component bindings: '+name)
                target[name]=value
        for component in plan['components']:
            relative=Path(component['component'])
            if relative.is_absolute() or '..' in relative.parts:raise ValueError('source-relative component required')
            key=(component['component'],component.get('program_override'))
            if key in components:raise ValueError('duplicate component/program across plans: '+str(key))
            components.add(key);merged['components'].append(component)
        provenance.append(dict(path=str(path),sha256=before,components=len(plan['components'])))
        origins[str(path)]=before
    # Every original binding is checked, including inputs of retained components
    # which do not themselves contribute a compile action.
    for name,value in merged['input_sha256'].items():
        if digest(Path(name))!=value:raise ValueError('component input changed: '+name)
    merged['input_sha256'].update(origins)
    merged['component_plans']=provenance
    return merged
