#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Run one immutable PF parity image with isolated user networking."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('directory',type=Path)
p.add_argument('tag')
p.add_argument('--qemu',type=Path,default=Path('/usr/local/bin/qemu-system-x86_64'))
p.add_argument('--attempt',help='new output name when retrying an unchanged image')
p.add_argument('--timeout',type=int,default=1200)
p.add_argument('--expect-fail',action='append',default=[])
a=p.parse_args()
b=a.directory.resolve()
if not str(b).startswith('/usr/obj/') or not re.fullmatch(r'[a-z0-9-]+',a.tag):
    p.error('use a directory under /usr/obj and an alphanumeric tag')
if a.timeout <= 0:p.error('timeout must be positive')
attempt=a.attempt or a.tag
if not re.fullmatch(r'[a-z0-9-]+',attempt):p.error('invalid attempt name')
image=b/('guest-'+a.tag+'.img'); logfile=b/(attempt+'-console.log')
manifest=json.loads((b/(a.tag+'-manifest.json')).read_text())
stage=b/(a.tag+'-stage.json')
if not stage.exists():stage=b/'stage.json'  # Legacy images before tagged metadata.
stage_meta=json.loads(stage.read_text())
cases=stage_meta['cases']
purpose=b/(a.tag+'-purpose.json')
if purpose.exists() and json.loads(purpose.read_text()).get('do_not_run'):
    p.error('image marked do_not_run: '+str(purpose))
if len(set(cases))!=len(cases) or not set(a.expect_fail)<=set(cases):
    p.error('duplicate cases or unknown expected failures')
if not image.is_file() or logfile.exists():p.error('missing image or existing output')
qemu=a.qemu.resolve()
version=subprocess.check_output([str(qemu),'--version'],text=True)
command=[str(qemu),'-L','/usr/local/share/qemu','-accel','tcg,thread=multi',
 '-machine','q35','-cpu','max','-m','2048','-smp','4',
 '-drive','file='+str(image)+',format=raw,if=virtio,snapshot=on',
 '-netdev','user,id=n0,restrict=on','-device','virtio-net-pci,netdev=n0',
 '-display','none','-monitor','none','-serial','stdio','-no-reboot']
with image.open('rb') as image_stream:
    image_digest=hashlib.file_digest(image_stream,'sha256').hexdigest()
started=time.time()
with logfile.open('xb') as log:
    child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
    (b/(attempt+'-process.json')).write_text(json.dumps({'pid':child.pid,'started':started,
        'command':command,'qemu_version':version,'qemu_sha256':hashlib.sha256(qemu.read_bytes()).hexdigest(),'image_sha256':image_digest},indent=2)+'\n')
    try:code=child.wait(timeout=a.timeout)
    except subprocess.TimeoutExpired:
        child.terminate()
        try:child.wait(timeout=15)
        except subprocess.TimeoutExpired:child.kill();child.wait()
        code=124
raw=logfile.read_bytes();s=raw.decode(errors='replace').replace('\r','')
errors=[]
if code:errors.append('QEMU exit '+str(code))
for marker in ['PF_PARITY_BEGIN','PF_PARITY_DONE','PF_PARITY_EXIT 0','All buffers synced.','all pools are healthy']:
    if s.count(marker)!=1:errors.append('missing or duplicate marker '+marker)
if re.search(r'^panic:|Fatal trap|UNEXPECTED_IPFW_',s,re.M):errors.append('kernel/isolation failure')
actual=re.findall(r'^SHA256 \((.+)\) = ([0-9a-f]{64})$',s,re.M)
if len(actual)!=len(manifest) or dict(actual)!=manifest:errors.append('artifact identity mismatch')
results=re.findall(r'^===> ([^\n]+)\nResult:\s+([^\n]+)',s,re.M)
if Counter(x[0] for x in results)!=Counter(cases):errors.append('missing/duplicate/unexpected results')
for case,result in results:
    if case in a.expect_fail:
        if not result.startswith('failed:'):errors.append(case+': expected regression failure, got '+result)
    elif result!='passed':errors.append(case+': '+result)
parser_results=re.findall(r'^PF_PARSER_CASE ([a-z0-9_]+) (accept|reject)$',s,re.M)
if 'parser_corpus' in stage_meta:
    expected_parser=stage_meta['parser_corpus']
    if Counter(parser_results)!=Counter(expected_parser.items()):
        errors.append('parser corpus results mismatch')
    if s.count('PF_PARSER_DONE '+str(len(expected_parser)))!=1:
        errors.append('parser corpus completion marker mismatch')
out={'harness_passed':not errors,'qemu_exit':code,'seconds':time.time()-started,
 'artifact_count':len(actual),'parser_cases':dict(parser_results),'cases':dict(results),'expected_failures':a.expect_fail,
 'qualification':'expected failures require assertion review' if a.expect_fail else 'selected guest tests',
 'log_sha256':hashlib.sha256(raw).hexdigest(),'errors':errors}
(b/(attempt+'-results.json')).write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps(out,indent=2))
raise SystemExit(bool(errors))
