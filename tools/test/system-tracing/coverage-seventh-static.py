#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
# Prepared native amd64 validation only; see COVERAGE-SEVENTH.
from pathlib import Path
import subprocess,importlib.util,json
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-seventh-validation');P=O/'static';P.mkdir(exist_ok=True)
(P/'mesh.c').write_text('''#include "mesh_key_refresh.h"
int main(void) {
    struct mesh_key_refresh state;
    mesh_kr_init(&state);
    if (mesh_kr_begin(&state) != 0) return 1;
    if (mesh_kr_beacon(&state, 1) != MESH_KR_PHASE_2) return 2;
    return mesh_kr_beacon(&state, 0) != MESH_KR_PHASE_3;
}
''')
spec=importlib.util.spec_from_file_location('dof',S/'tools/test/system-tracing/coverage-fourth-dof.py');d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
results=[]
for hooks in ['yes','no']:
 output=P/('mesh-'+hooks)
 cmd=['cc','-Wall','-Wextra','-Werror','-I'+str(S/'lib/libmesh'),str(P/'mesh.c'),str(O/'base'/('lib_libmesh-'+hooks)/'libblemesh.a'),'-lcrypto','-o',str(output)]
 r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,r.stderr
 r=subprocess.run([str(output)],capture_output=True,text=True);assert r.returncode==0,r.stderr
 probes=d.dof_probes(d.elf_sections(output).get('.SUNW_dof',b''));names=[p['name'] for p in probes if p['provider']=='mesh']
 assert ('mesh-keyrefresh-phase' in names)==(hooks=='yes'),names
 results.append(dict(hooks=hooks,command=cmd,status=0,probes=names))
(O/'static-results.json').write_text(json.dumps(results,indent=2)+'\n')
print('Static libblemesh links: probe metadata retained / no-hooks absent; state-machine smoke PASS')
