#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import collections,hashlib,json,re,subprocess
import argparse
ap=argparse.ArgumentParser();ap.add_argument('--src',type=Path,default=Path('/usr/src'));ap.add_argument('--out',type=Path,required=True);ap.add_argument('--baseline',default='c2b7fe4a9e94a0edba9dd2772874928b565c4f9e');args=ap.parse_args();S=args.src;O=args.out;O.mkdir(parents=True,exist_ok=True)
BASE=args.baseline
ROOTS=['sys','bin','sbin','lib','libexec','usr.bin','usr.sbin','cddl','crypto','contrib','stand','rescue','secure','kerberos5','krb5','include','share']
PAT=r'SDT_PROBE_DEFINE|DTRACE_PROBE|ZFS_BSD_PROBE|MAC_CHECK_PROBE_DEFINE|MAC_GRANT_PROBE_DEFINE|MIB_PROBE|provider[[:space:]]+[A-Za-z_].*\{'
EXCLUDE={'test','tests','testing','unittests','testcases','example','examples','doc','docs','man','test-suite'}
def keep(p):
 parts=Path(p).parts
 return p != 'sys/cddl/dev/dtrace/dtrace_test.c' and Path(p).suffix in ('.c','.h','.cc','.cpp','.S','.d') and not any(x.lower() in EXCLUDE for x in parts) and '/os/linux/' not in p
# Keep quoted strings so identities written as strings remain inspectable.
lex=re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',re.S)
def clean(s):return lex.sub(lambda m:' ' if m[0].startswith(('/*','//')) else m[0],s)
def body_and_macros(s):
 # Splice preprocessor continuation lines before identifying function macros.
 s=re.sub(r'\\\n',' ',s);macros={}
 for m in re.finditer(r'^\s*#\s*define\s+(\w+)\(([^\n)]*)\)([^\n]*)',s,re.M):macros[m[1]]=(m[2].split(','),m[3])
 return re.sub(r'^\s*#[^\n]*','',s,flags=re.M),macros
ident=re.compile(r'^[A-Za-z_][A-Za-z_0-9]*$')
def norm(x):return x.strip().strip('"').replace('__','-')
def parse(files,label):
 contracts={};sites=[];unknown=[];allmac={};bodies={};rawmac={}
 for p,s in files.items():
  body,mac=body_and_macros(clean(s));bodies[p]=body;rawmac[p]=mac
  for n,v in mac.items():
   if n.startswith(('MAC_CHECK_PROBE_DEFINE','MAC_GRANT_PROBE_DEFINE','MIB_PROBE')):allmac[n]=v
 def add(kind,key,p,form):
  key=[norm(x) for x in key]
  if any(x and not re.match(r'^[\w-]+$',x) for x in key):unknown.append(dict(path=p,key=key,form=form));return
  k=(kind,*map(norm,key));entry=contracts.setdefault(k,dict(kind=kind,provider=k[1],module=k[2],function=k[3],name=k[4],sources=[],forms=[]))
  if p not in entry['sources']:entry['sources'].append(p)
  if form not in entry['forms']:entry['forms'].append(form)
 def definitions(p,b):
  for m in re.finditer(r'\bSDT_PROBE_DEFINE(?:\d+)?(?:_XLATE)?\s*\(\s*([^,]*),\s*([^,]*),\s*([^,]*),\s*([^,)]*)',b):
   add('kernel' if p.startswith('sys/') else 'c-sdt',list(m.groups()),p,'SDT_PROBE_DEFINE')
  for m in re.finditer(r'\bLIN_SDT_PROBE_DEFINE\d+\s*\(\s*([^,]*),\s*([^,]*),\s*([^,)]*)',b):
   add('kernel',['linuxulator',*m.groups()],p,'LIN_SDT_PROBE_DEFINE (ABI-neutral)')
  if p.startswith('sys/'):
   for m in re.finditer(r'\b(?:DTRACE_PROBE\d*|ZFS_BSD_PROBE\d*)\s*\(\s*(\w+)',b):add('kernel',['sdt','','',m[1]],p,'inline DTRACE/ZFS_BSD')
 for p,b in bodies.items():
  if p.endswith('.d'):
   for m in re.finditer(r'\bprovider\s+(\w+)\s*\{([^}]*)\}',b,re.S):
    for probe in re.finditer(r'\bprobe\s+(\w+)\s*\(',m[2]):add('user',[m[1],'','',probe[1]],p,'USDT provider')
  definitions(p,b)
  for n,(params,expansion) in allmac.items():
   for m in re.finditer(r'\b'+n+r'\s*\(\s*(\w+)',b):
    definitions(p,re.sub(r'\b'+params[0].strip()+r'\b',m[1],expansion))
  # Constant-name implicit probes inside macro bodies, such as DBUF_SET_STATE.
  for n,(params,expansion) in rawmac[p].items():
   if n.startswith(('SDT_','DTRACE_','ZFS_BSD_','MAC_','MIB_')):continue
   for m in re.finditer(r'\bDTRACE_PROBE\d*\s*\(\s*(\w+)',expansion):
    if m[1] not in [x.strip() for x in params] and p.startswith('sys/'):
     add('kernel',['sdt','','',m[1]],p,'constant macro-body DTRACE')
  # Source invocation evidence, deliberately separate from unique definitions.
  for m in re.finditer(r'\b(?:SDT_PROBE\d+|DTRACE_PROBE\d*|ZFS_BSD_PROBE\d*|MAC_(?:CHECK|GRANT)_PROBE\d+|(?:IP|TCP|UDP|UDPLITE|SCTP|CAM|MIB_SDT|LIN_SDT|USB_TRANSFER)_PROBE\d*|TRACE_[A-Z_]+)\s*\(',b):
   sites.append(dict(source=p,macro=m[0].split('(')[0].strip()))
 count=collections.Counter(x['kind'] for x in contracts.values());prov=collections.Counter(x['provider'] for x in contracts.values())
 result=dict(label=label,candidate_files=len(files),counts=dict(count),unique_contracts=len(contracts),providers=len(prov),by_provider=dict(prov.most_common()),known_invocation_sites=len(sites),contracts=sorted(contracts.values(),key=lambda x:(x['kind'],x['provider'],x['module'],x['function'],x['name'])),invocation_sites=sites,unresolved=unknown)
 (O/(label+'.json')).write_text(json.dumps(result,indent=2)+'\n');print(label,{k:result[k] for k in ('candidate_files','counts','unique_contracts','providers','known_invocation_sites')},flush=True)
 return contracts,result

# Use the same discovery expression for both trees. Include all .d files,
# including provider declarations split across lines. No cached baseline list.
DISC='SDT_PROBE_DEFINE|DTRACE_PROBE|ZFS_BSD_PROBE|MAC_CHECK_PROBE_DEFINE|MAC_GRANT_PROBE_DEFINE|MIB_PROBE|LIN_SDT_PROBE_DEFINE|provider'
def git(*a):return subprocess.check_output(['git',*a],cwd=S,text=True)
tracked=git('grep','-l','-E',DISC,'--',*ROOTS).splitlines()
visible=subprocess.check_output(['rg','-l',DISC,*[r for r in ROOTS if (S/r).exists()]],cwd=S,text=True).splitlines()
allcurrent=git('ls-files','--cached','--others','--exclude-standard','--',*ROOTS).splitlines()
paths=sorted({p for p in tracked+visible+allcurrent if keep(p) and (p in tracked or p in visible or p.endswith('.d')) and (S/p).is_file()})
current={p:(S/p).read_text(errors='replace') for p in paths};wc,wr=parse(current,'working-tree')
raw=git('grep','-l','-E',DISC,BASE,'--',*ROOTS)
paths=[x.split(':',1)[1] for x in raw.splitlines()]
paths+= [p for p in git('ls-tree','-r','--name-only',BASE,'--',*ROOTS).splitlines() if p.endswith('.d')]
paths=sorted({p for p in paths if keep(p)})
r=subprocess.run(['git','cat-file','--batch'],cwd=S,input=''.join(BASE+':'+p+'\n' for p in paths).encode(),capture_output=True,check=True);data=r.stdout;pos=0;files={}
for p in paths:
 end=data.index(b'\n',pos);size=int(data[pos:end].split()[2]);pos=end+1;files[p]=data[pos:pos+size].decode(errors='replace');pos+=size+1
bc,br=parse(files,'vanilla-freebsd')
assert not wr['unresolved'] and not br['unresolved']
added=sorted(wc.keys()-bc.keys());removed=sorted(bc.keys()-wc.keys())
report=dict(baseline=BASE,baseline_commit=git('show','-s','--format=fuller',BASE),head=git('rev-parse','HEAD').strip(),metric='source-level unique static contracts, not runtime probes',working=wr['counts'],vanilla=br['counts'],working_total=len(wc),vanilla_total=len(bc),total_ratio=len(wc)/len(bc),kernel_ratio=wr['counts']['kernel']/br['counts']['kernel'],added=len(added),removed=len(removed),added_contracts=[wc[k] for k in added],removed_contracts=[bc[k] for k in removed],roots=ROOTS,excluded_directory_names=sorted(EXCLUDE),excluded_foreign_path='/os/linux/',unresolved=0)
(O/'comparison.json').write_text(json.dumps(report,indent=2)+'\n')
(O/'working-source-hashes.json').write_text(json.dumps({p:hashlib.sha256((S/p).read_bytes()).hexdigest() for p in current},indent=2)+'\n')
print({k:v for k,v in report.items() if k in ('working','vanilla','working_total','vanilla_total','total_ratio','kernel_ratio','added','removed')})
