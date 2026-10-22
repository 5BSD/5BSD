#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Isolated actual-library pragma diagnostics; no tracing devices or execution."""
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys

ATTR = '#pragma D attributes Stable/Stable/Common '
CASES = {
    'provider-missing-name': (ATTR+'provider\nBEGIN { trace(1); }', False, 'malformed'),
    'provider-missing-component': (ATTR+'provider sample\nBEGIN { trace(1); }', False, 'malformed'),
    'provider-numeric-name': (ATTR+'provider 7 args\nBEGIN { trace(1); }', False, 'malformed'),
    'provider-numeric-component': (ATTR+'provider sample 7\nBEGIN { trace(1); }', False, 'malformed'),
    'provider-string-name': (ATTR+'provider "sample" args\nBEGIN { trace(1); }', False, 'malformed'),
    'provider-string-component': (ATTR+'provider sample "args"\nBEGIN { trace(1); }', False, 'malformed'),
    'option-missing': ('#pragma D option\nBEGIN { trace(1); }', False, 'malformed'),
    'option-extra': ('#pragma D option quiet extra\nBEGIN { trace(1); }', False, 'superfluous'),
    'option-unknown': ('#pragma D option no_such_97\nBEGIN { trace(1); }', False, 'failed to set'),
    'option-invalid-value': ('#pragma D option bufsize=-1\nBEGIN { trace(1); }', False, 'failed to set'),
    'option-quiet': ('#pragma D option quiet\nBEGIN { trace(1); }', True, ''),
    'unknown-d-pragma': ('#pragma D no_such_97\nBEGIN { trace(1); }', False, 'invalid D pragma'),
    'unknown-standard-pragma': ('#pragma no_such_97\nBEGIN { trace(1); }', True, ''),
    'error-directive': ('#error test_failure_97\nBEGIN { trace(1); }', False, 'test_failure_97'),
    'line-invalid': ('#line "wrong"\nBEGIN { trace(1); }', False, 'malformed'),
    'line-valid': ('#line 17 "fixture.d"\nBEGIN { trace(1); }', True, ''),
    'ident-ignored': ('#ident "fixture"\nBEGIN { trace(1); }', True, ''),
}
# Exercise deferred identifier metadata and errors without provider sysctls,
# module enumeration, filesystem library loading or invoking a preprocessor.
CASES.update({
    'attributes-missing': ('#pragma D attributes\nBEGIN { trace(1); }', False, 'malformed'),
    'attributes-bad-stability': ('#pragma D attributes Bogus/Stable/Common x\nint x; BEGIN { trace(x); }', False, 'invalid attributes'),
    'attributes-current': ('int x;\n'+ATTR+'x\nBEGIN { trace(x); }', True, ''),
    'attributes-deferred': (ATTR+'x\nint x; BEGIN { trace(x); }', True, ''),
    'attributes-unused': (ATTR+'never_defined_97\nBEGIN { trace(1); }', False, 'unused #pragma'),
    'attributes-builtin-scope': (ATTR+'timestamp\nBEGIN { trace(1); }', False, 'outside program scope'),
    'binding-missing': ('#pragma D binding\nBEGIN { trace(1); }', False, 'malformed'),
    'binding-unquoted': ('#pragma D binding 1.0 x\nint x; BEGIN { trace(x); }', False, 'malformed'),
    'binding-invalid-version': ('#pragma D binding "bogus" x\nint x; BEGIN { trace(x); }', False, 'invalid version'),
    'binding-current': ('int x;\n#pragma D binding "1.0" x\nBEGIN { trace(x); }', True, ''),
    'binding-deferred': ('#pragma D binding "1.0" x\nint x; BEGIN { trace(x); }', True, ''),
    'binding-unused': ('#pragma D binding "1.0" never_defined_97\nBEGIN { trace(1); }', False, 'unused #pragma'),
    'binding-builtin-scope': ('#pragma D binding "1.0" timestamp\nBEGIN { trace(1); }', False, 'outside program scope'),
    'metadata-both-deferred': (ATTR+'x\n#pragma D binding "1.0" x\nint x; BEGIN { trace(x); }', True, ''),
    'depends-missing': ('#pragma D depends_on\nBEGIN { trace(1); }', False, 'malformed'),
    'depends-missing-name': ('#pragma D depends_on module\nBEGIN { trace(1); }', False, 'malformed'),
    'depends-numeric-class': ('#pragma D depends_on 7 item\nBEGIN { trace(1); }', False, 'malformed'),
    'depends-numeric-name': ('#pragma D depends_on module 7\nBEGIN { trace(1); }', False, 'malformed'),
    'depends-invalid-class': ('#pragma D depends_on bogus item\nBEGIN { trace(1); }', False, 'invalid class'),
    'depends-main-library': ('#pragma D depends_on library missing_97.d\nBEGIN { trace(1); }', False, 'main program may not'),
    'directive-invalid': ('#bogus\nBEGIN { trace(1); }', False, 'invalid control directive'),
    'directive-string': ('#"bogus"\nBEGIN { trace(1); }', False, 'invalid control directive'),
    'directive-empty': ('#\nBEGIN { trace(1); }', True, ''),
    'line-no-filename': ('#line 17\nBEGIN { trace(1); }', True, ''),
    'line-bad-filename': ('#line 17 42\nBEGIN { trace(1); }', False, 'malformed'),
    'line-bad-state': ('#line 17 "test.d" "bad"\nBEGIN { trace(1); }', False, 'malformed'),
    'line-include-transitions': ('# 1 "include.d" 1\nint x;\n# 20 "main.d" 2\nBEGIN { trace(x); }', True, ''),
    'line-unmatched-return': ('# 20 "main.d" 2\nBEGIN { trace(1); }', True, ''),
    'line-master-fd': ('#line 1 "first.d"\n#line 2 "/dev/fd/3"\nBEGIN { trace(1); }', True, ''),
    'line-diagnostic-location': ('#line 73 "diagnostic_97.d"\nBEGIN { missing_97(); }', False, 'diagnostic_97.d'),
    'pragma-compile-context': ('#pragma D option cpppath=/nonexistent\nBEGIN { trace(1); }', False, 'failed to set'),
})
for part in ('provider','module','function','name','args'):
    CASES['provider-valid-'+part] = ('provider sample { probe tick(); };\n'+ATTR+
        'provider sample '+part+'\nBEGIN { trace(1); }', True, '')

def worker(binary, name):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    lib = C.CDLL(str(binary))
    lib.dtrace_open.argtypes = [C.c_int,C.c_int,C.POINTER(C.c_int)]
    lib.dtrace_open.restype = C.c_void_p
    lib.dtrace_close.argtypes = [C.c_void_p]
    lib.dtrace_program_strcompile.argtypes = [C.c_void_p,C.c_char_p,C.c_int,C.c_uint,C.c_int,C.c_void_p]
    lib.dtrace_program_strcompile.restype = C.c_void_p
    lib.dtrace_errno.argtypes = [C.c_void_p]
    lib.dtrace_errmsg.argtypes = [C.c_void_p,C.c_int]
    lib.dtrace_errmsg.restype = C.c_char_p
    error = C.c_int()
    handle = lib.dtrace_open(3,3,C.byref(error))
    if not handle: raise RuntimeError('NODEV/NOSYS open failed: '+str(error.value))
    source, expected, substring = CASES[name]
    try:
        compiled = bool(lib.dtrace_program_strcompile(handle,source.encode(),4,0x1004,0,None))
        diagnostic = '' if compiled else lib.dtrace_errmsg(handle,lib.dtrace_errno(handle)).decode(errors='replace')
        print(json.dumps({'case':name,'compiled':compiled,'diagnostic':diagnostic,
            'passed':compiled==expected and substring in diagnostic,'pid':os.getpid()}))
    finally:
        lib.dtrace_close(handle)

if len(sys.argv)==4 and sys.argv[1]=='--case':
    worker(Path(sys.argv[2]),sys.argv[3])
else:
    if len(sys.argv)!=3: raise SystemExit('usage: pragma-offline.py /usr/obj/output /usr/obj/libdtrace.so.2')
    out,binary = [Path(x).resolve() for x in sys.argv[1:]]
    if not all(p.is_relative_to('/usr/obj') for p in (out,binary)): raise SystemExit('Use isolated /usr/obj artifacts')
    out.mkdir(parents=True,exist_ok=True)
    results=[]
    for name in CASES:
        try:
            proc=subprocess.run([sys.executable,__file__,'--case',str(binary),name],capture_output=True,text=True,timeout=30)
            result=json.loads(proc.stdout) if proc.returncode==0 else {'case':name,'passed':False,'returncode':proc.returncode}
            result['stderr']=proc.stderr
            if 'LLVM Profile Error' in proc.stderr: result['passed']=False
        except subprocess.TimeoutExpired:
            result={'case':name,'passed':False,'timeout':True}
        results.append(result)
    (out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    (out/'provenance.json').write_text(json.dumps({'binary':str(binary),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'device_mode':'NODEV | NOSYS'},indent=2)+'\n')
    failed=[r for r in results if not r['passed']]
    for r in failed: print(json.dumps(r))
    print(f'{len(results)-len(failed)}/{len(results)} isolated pragma cases passed')
    raise SystemExit(bool(failed))
