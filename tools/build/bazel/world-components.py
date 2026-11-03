#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Query every discovered world directory; retain failures and all component kinds.

This is configured metadata coverage, not native action or package coverage.
"""
import argparse
import concurrent.futures
import json
from pathlib import Path
import shlex
import time
from importlib import import_module
from libmd_environment import BuildEnvironment,digest

VARIABLES=tuple(dict.fromkeys((*import_module("component-plan").VARIABLES,
    "ATF_TESTS_C", "ATF_TESTS_CXX", "ATF_TESTS_SH", "PLAIN_TESTS_C",
    "PLAIN_TESTS_CXX", "PLAIN_TESTS_SH", "PLAIN_TESTS_PORCH", "GTESTS",
    "ATF_TESTS_PYTEST", "TAP_TESTS_C", "TAP_TESTS_CXX", "TAP_TESTS_SH", "TAP_TESTS_PERL",
    "INCSGROUPS", "TESTS_SUBDIRS", "INTERNALLIB", "LIB_PRIVATE")))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('src','inventory','output'):
        parser.add_argument('--'+key,type=Path,required=True)
    parser.add_argument('--jobs',type=int,required=True)
    args=parser.parse_args()
    if args.jobs<1:parser.error('positive job count required')
    src=args.src.resolve(strict=True);inventory=args.inventory.resolve(strict=True)
    data=json.loads(inventory.read_text());out=args.output.resolve()
    if data['status']!='discovered' or data['exit_status']!=0:
        parser.error('successful configured world inventory required')
    prior=data['environment'];obj=Path(prior['objtop']);profile=Path(prior['profile'])
    if not args.output.is_absolute() or args.output.is_symlink() or out.exists() or out==Path('/usr/obj') or not out.is_relative_to('/usr/obj') or any(p==out or p.is_relative_to(out) or (p.is_dir() and out.is_relative_to(p)) for p in (src,obj,inventory,profile)):
        parser.error('fresh nonoverlapping output below /usr/obj required')
    bindings=dict(data['input_sha256']);bindings.update(prior['input_sha256'])
    for p in (inventory,Path(__file__),Path(__file__).with_name('component-plan.py'),Path(__file__).with_name('libmd_environment.py')):
        bindings[str(p.resolve())]=digest(p)
    def verify():
        for name,sha in bindings.items():
            if digest(Path(name))!=sha:raise ValueError('inventory input changed: '+name)
    verify()
    directories=data['directories']
    if not directories or len(directories)!=len(set(directories)):raise ValueError('nonempty unique directory inventory required')
    for name in directories:
        p=Path(name)
        if p.is_absolute() or '..' in p.parts or not (src/p).resolve(strict=True).is_relative_to(src):raise ValueError('invalid inventory directory')
    architecture=prior['profile_assignments']['TARGET_ARCH']
    if data.get('target_architecture',architecture)!=architecture:
        raise ValueError('inventory architecture differs from recorded profile')
    env=BuildEnvironment(src,obj,profile,Path('/usr/bin/make'),target_architecture=architecture)
    if env.assignments!=prior['profile_assignments']:raise ValueError('world configuration changed')
    anchors=data['trust_anchors']
    for name in anchors:
        p=Path(name)
        if not p.is_absolute() or any(c.isspace() or c=='$' for c in name) or name not in bindings:raise ValueError('unbound trust input')
    extra=['TRUST_ANCHORS='+' '.join(anchors)] if anchors else []
    start=time.monotonic();out.mkdir();records=[]
    def query(name):
        component=src/name
        def values():
            rows=env.query([v for key in VARIABLES for v in ('-v',key)],component=component,extra=extra).splitlines()
            if len(rows)!=len(VARIABLES):raise ValueError('ambiguous multiline metadata')
            metadata=dict(zip(VARIABLES,rows))
            groups=metadata['INCSGROUPS'].split()
            if len(groups)!=len(set(groups)):raise ValueError('duplicate include groups')
            missing=[name for name in groups if name not in metadata]
            extra_values=env.query([v for name in missing for v in ('-v',name)],component=component,extra=extra).splitlines() if missing else []
            if len(extra_values)!=len(missing):raise ValueError('ambiguous grouped header metadata')
            selected=dict(zip(missing,extra_values))
            return metadata,{name:metadata.get(name,selected.get(name,'')) for name in groups}
        try:
            metadata,header_groups=values();closure={}
            if (metadata['MACHINE'],metadata['MACHINE_ARCH'])!=(env.assignments['TARGET'],architecture):raise ValueError('component target differs from world')
            for value in shlex.split(metadata['.MAKE.MAKEFILES']):
                p=Path(value);p=(p if p.is_absolute() else component/p).resolve(strict=True)
                if p!=Path('/dev/null'):closure[str(p)]=digest(p)
            if values()!=(metadata,header_groups):raise ValueError('metadata changed during query')
            return {'component':name,'status':'queried','metadata':metadata,'header_groups':header_groups,'make_include_closure':closure}
        except (ValueError,OSError) as error:
            return {'component':name,'status':'failed','error':str(error)}
    with (out/'components.jsonl').open('w') as stream:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for record in pool.map(query,directories):
                records.append(record);stream.write(json.dumps(record)+'\n');stream.flush()
    failed=[r['component'] for r in records if r['status']=='failed']
    for record in records:
        for name,sha in record.get('make_include_closure',{}).items():
            if name in bindings and bindings[name]!=sha:raise ValueError('inconsistent include input: '+name)
            bindings[name]=sha
    env.verify();verify()
    summary={'format':1,'target_architecture':architecture,'status':'incomplete' if failed else 'queried',
             'scope':'all discovered directory metadata; not native action/build/package coverage',
             'inventory':str(inventory),'directory_count':len(directories),'queried_count':len(records)-len(failed),
             'failed_components':failed,'jobs':args.jobs,'elapsed_seconds':time.monotonic()-start,
             'input_sha256':bindings,'environment':env.receipt(),
             'records_sha256':digest(out/'components.jsonl'),
             'limitations':['Multi-program values have not been expanded per program.',
                            'Source and generated-file resolution is not performed by this survey.',
                            'Successful metadata queries do not establish Bazel support.']}
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:summary[k] for k in ('status','directory_count','queried_count','failed_components','elapsed_seconds')}))
    raise SystemExit(bool(failed))


if __name__=='__main__':main()
