#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Run the maintained bzip2 sample comparisons against explicit native outputs."""
import argparse,binascii,gzip,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for k in ('src','program','library','output'):p.add_argument('--'+k,type=Path,required=True)
p.add_argument('--runtime-library-dir',type=Path,action='append',required=True)
a=p.parse_args();program=a.program.resolve(strict=True);library=a.library.resolve(strict=True)
if a.output.exists():p.error('fresh result file required')
env={'PATH':'/bin:/usr/bin','LC_ALL':'C','LD_LIBRARY_PATH':':'.join(str(x) for x in [a.library.absolute().parent,*[p.resolve(strict=True) for p in a.runtime_library_dir]])}
trace=subprocess.check_output([str(program)],env={**env,'LD_TRACE_LOADED_OBJECTS':'1'},text=True)
m=re.search(r'^\s*'+re.escape(a.library.name)+r' => (\S+)',trace,re.M)
if not m or Path(m.group(1)).resolve()!=library:raise ValueError('loader did not select the supplied native library: '+trace)
def uudecode(path):
 lines=path.read_bytes().splitlines()
 if not lines or not lines[0].startswith(b'begin ') or lines[-1]!=b'end':raise ValueError('invalid maintained uuencoded fixture')
 return b''.join(binascii.a2b_uu(line) for line in lines[1:-1])
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
inputs={str(program):sha(program),str(library):sha(library)};checks=[]
for n in (1,2,3):
 raw=a.src/'contrib/bzip2'/('sample'+str(n)+'.ref.gz.uu');compressed=a.src/'contrib/bzip2'/('sample'+str(n)+'.bz2.uu')
 inputs[str(raw)]=sha(raw);inputs[str(compressed)]=sha(compressed)
 expected_raw=gzip.decompress(uudecode(raw));expected_bz2=uudecode(compressed)
 actual=subprocess.check_output([str(program),'-'+str(n)],input=expected_raw,env=env)
 if actual!=expected_bz2:raise ValueError('compression differs for sample '+str(n))
 decoded=subprocess.check_output([str(program),'-ds' if n==3 else '-d'],input=expected_bz2,env=env)
 if decoded!=expected_raw:raise ValueError('decompression differs for sample '+str(n))
 checks.append({'sample':n,'compression':'passed','decompression':'passed'})
a.output.write_text(json.dumps({'status':'passed','scope':'maintained compression/decompression sample cases; explicit native shared library selected','checks':checks,'inputs':inputs,'loader_trace':trace,'limitations':['Does not qualify bzip2recover runtime, Bazel test-rule integration or packaging.']},indent=2)+'\n');print(a.output)
