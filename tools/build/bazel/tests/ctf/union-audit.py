#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import hashlib,importlib.util,itertools,json,struct,subprocess,sys,types,zlib
from pathlib import Path
import argparse,os,shutil
parser=argparse.ArgumentParser(description='Explicit-library standalone CTF namespace-union qualification')
parser.add_argument('--driver',type=Path,required=True)
parser.add_argument('--fixtures',type=Path,required=True)
parser.add_argument('--semantic-reader',type=Path,required=True)
parser.add_argument('--ctfdump',type=Path,required=True)
parser.add_argument('--ctf-library',type=Path,action='append',default=[])
parser.add_argument('--work',type=Path)
args=parser.parse_args()
for name,path in [('ctf_semantics',args.semantic_reader),('fixtures',args.fixtures)]:
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
Graph=sys.modules['ctf_semantics'].Graph;m=sys.modules['fixtures'];path=args.fixtures
if args.work is None:
 if 'TEST_TMPDIR' not in os.environ:parser.error('--work is required outside a test runner')
 args.work=Path(os.environ['TEST_TMPDIR'])/'ctf-union'
work=args.work;work.mkdir(exist_ok=False)
ctf_environment=dict(os.environ);ctf_environment.pop('LD_LIBRARY_PATH',None)
if args.ctf_library:ctf_environment['LD_LIBRARY_PATH']=':'.join(dict.fromkeys(str(p.resolve(strict=True).parent) for p in args.ctf_library))
driver=args.driver;reports=[];fixtures=[]
inputs={str(p.resolve()):hashlib.sha256(p.read_bytes()).hexdigest() for p in [driver,path,args.semantic_reader,args.ctfdump,*args.ctf_library,Path(__file__)]}
commands=[]
for v,e,c,x in itertools.product((2,3),('<','>'),(False,True),(False,True)):
 tag=f'{v}-{e=="<"}-{c}-{x}';factory=m.fixture
 # Includes v2-long -> v3-short struct-member layout conversion.
 data,syms=factory(version=v,endian=e,compressed=c,external_names=x,mutation=lambda d:d[4].__setitem__(3,8192))
 h=struct.unpack_from(e+'HBB8I',data);body=zlib.decompress(data[36:]) if c else data[36:];ext=body[h[9]:] if x else b''
 graph=Graph(data,syms,ext);d=work/tag;d.mkdir();(d/'input.ctf').write_bytes(data);(d/'external').write_bytes(ext);(d/'symbols').write_text('1 1\n2 2\n');fixtures.append((d,graph,syms))
# Pair every input format with every other input format;
# vary output encoding independently. Each case checks exact edges and names.
for n,(a,b,outend,outzip) in enumerate(itertools.product(fixtures,fixtures,('<','>'),(False,True))):
 da,ga,sa=a;db,gb,sb=b
 out=work/f'union-{n}.ctf';refs=work/f'output-{n}.symbols'
 order=[(0,2,2),(1,1,1),(0,1,1),(1,2,2),(0,0xffffffff,2)]
 refs.write_text(''.join(f'{i} {idx} {t}\n' for i,idx,t in order))
 identities=[('left_'+sa[1][0],*sa[1][1:]),('right_'+sb[0][0],*sb[0][1:]),('left_'+sa[0][0],*sa[0][1:]),('right_'+sb[1][0],*sb[1][1:]),('new_function',2,1,0,'.text',64,16)]
 cmd=[str(driver),str(out),str(refs),'le' if outend=='<' else 'be','z' if outzip else 'raw',str(da/'input.ctf'),str(da/'symbols'),str(da/'external'),str(db/'input.ctf'),str(db/'symbols'),str(db/'external')]
 commands.append(cmd)
 r=subprocess.run(cmd,capture_output=True,text=True)
 assert r.returncode==0,(n,r.returncode,r.stderr)
 g=Graph(out.read_bytes(),identities)
 expected={};base=0
 for original in (ga,gb):
  for idx,(attrs,edges) in original.nodes.items():expected[idx+base]=(attrs,tuple(ref+base if ref else 0 for ref in edges))
  base+=len(original.nodes)
 assert g.nodes==expected,(n,'type graph')
 assert g.labels==('build',),(n,'label')
 for identity,(owner,index,kind) in zip(identities,order):
  if index==0xffffffff:assert g.symbols[(identity,False)]==();continue
  original=(ga,gb)[owner];base=len(ga.nodes) if owner else 0;old=(sa,sb)[owner][index-1]
  key=next(k for k in original.symbols if k[0]==old)
  assert g.symbols[(identity,key[1])]==tuple(ref+base if ref else 0 for ref in original.symbols[key]),(n,'symbol edge')
 if outend=='<' and not outzip:
  # Independent installed consumer: same fixture graph embedded in ELF64.
  elf=work/f'union-{n}.o';elf.write_bytes(m.elf(out.read_bytes(),identities))
  dump=subprocess.run([str(args.ctfdump),'-d','-f','-t',str(elf)],capture_output=True,text=True,env=ctf_environment)
  (work/f'union-{n}.dump').write_text(dump.stdout+dump.stderr)
  assert dump.returncode==0 and 'unexpected kind' not in dump.stdout,(n,dump.stdout,dump.stderr)
  import re
  actual_types={int(i) for i in re.findall(r'^\s*[<\[]([0-9]+)[>\]] ',dump.stdout.split('- Types ',1)[1],re.M)}
  assert actual_types==set(expected),(n,'independent type inventory')
  for identity in identities:
   if identity[1]==1:
    refs=g.symbols[(identity,False)]
    assert re.search(r'^\s*\[\d+\]\s+'+str(refs[0])+r'\s+'+re.escape(identity[0])+r' \(\d+\)$',dump.stdout,re.M),(n,'independent object edge')
   elif identity[0]!='new_function':
    key=next(k for k in g.symbols if k[0]==identity);refs=g.symbols[key]
    match=re.search(r'FUNC \('+re.escape(identity[0])+r'\) returns: (\d+) args: \(([^)]*)\)',dump.stdout)
    assert match and (int(match[1]),*[int(x.strip()) for x in match[2].split(',') if x.strip()])==refs,(n,'independent function edges')
 reports.append({'case':n,'left':da.name,'right':db.name,'endian':outend,'compressed':outzip,'sha256':hashlib.sha256(out.read_bytes()).hexdigest()})
# The string table must contain referenced names only, including external ones.
# Adding a large unused ELF string table must not inflate the merged output.
da,ga,sa=fixtures[0];db,gb,sb=fixtures[-1]
unused=work/'unused-external';unused.write_bytes((da/'external').read_bytes()+b'\0'+b'x'*(1024*1024)+b'\0')
refs=work/'unused.symbols';refs.write_text('0 1 1\n1 2 2\n')
def invoke(tag,left,external=None,output_refs=refs,right=db):
 output=work/(tag+'.ctf');cmd=[str(driver),str(output),str(output_refs),'le','raw',str(left/'input.ctf'),str(left/'symbols'),str(external or left/'external'),str(right/'input.ctf'),str(right/'symbols'),str(right/'external')]
 commands.append(cmd);r=subprocess.run(cmd,capture_output=True,text=True)
 return output,r
normal,r=invoke('string-normal',da);assert r.returncode==0,r.stderr
large,r=invoke('string-unused',da,unused);assert r.returncode==0 and normal.read_bytes()==large.read_bytes(),r.stderr
negative=[]
def reject(tag,data=None,needle=None,external=None,output_text=None):
 d=work/('reject-'+tag);d.mkdir();(d/'input.ctf').write_bytes(data if data is not None else good)
 (d/'symbols').write_text('1 1\n2 2\n');(d/'external').write_bytes(b'' if external is None else external)
 rf=d/'output.symbols';rf.write_text('0 1 1\n1 2 2\n' if output_text is None else output_text)
 output,r=invoke('reject-result-'+tag,d,output_refs=rf,right=gooddir)
 assert r.returncode==8 and not output.exists() and (needle is None or needle in r.stderr),(tag,r.returncode,r.stderr)
 negative.append({'case':tag,'exit':r.returncode,'stderr':r.stderr})
good,syms=m.fixture();h=list(struct.unpack_from('<HBB8I',good));gooddir=work/'good';gooddir.mkdir();(gooddir/'input.ctf').write_bytes(good);(gooddir/'symbols').write_text('1 1\n2 2\n');(gooddir/'external').write_bytes(b'')
def change(offset,value):
 b=bytearray(good);struct.pack_into('<I',b,offset,value);return bytes(b)
reject('parent',change(8,1),'parent dictionaries')
reject('partial-label',change(40,14),'partial label')
reject('different-label',good.replace(b'build\0',b'other\0'),'different label')
reject('bad-string',change(36+h[8],0x7fffffff),'string reference')
reject('external-missing',change(36+h[8],0x80000001),'string reference')
reject('external-unterminated',change(36+h[8],0x80000001),'unterminated',external=b'\0missing')
reject('reserved-info',change(36+h[8]+4,(1<<26)|(1<<24)|1),'reserved info bit')
reject('unsupported-kind',change(36+h[8]+4,14<<26),'unsupported type kind')
reject('discarded-object-reference',change(36+h[6],999),'dangling',output_text='0 2 2\n1 2 2\n')
reject('duplicate-output',needle='duplicate output',output_text='0 1 1\n0 1 1\n')
reject('unknown-namespace',needle='unknown output namespace',output_text='2 1 1\n')
reject('changed-type',needle='changed output',output_text='0 1 2\n')
reject('invalid-output-type',needle='invalid output symbol',output_text='0 1 3\n')
# Rejected label/type layouts and external zero remain distinct contracts.
body=good[36:];label=body[:8];second=struct.pack('<II',1,15)
def two_labels(reverse=False):
 hh=list(h);hh[6]+=8;hh[7]+=8;hh[8]+=8;hh[9]+=8
 return struct.pack('<HBB8I',*hh)+(second+label if reverse else label+second)+body[8:]
reject('duplicate-label',two_labels().replace(second,label,1),'duplicate label')
pointer=struct.pack('<III',0,3<<26,4);assert good.count(pointer)==1
reject('dangling-type',change(good.index(pointer)+8,999),'dangling')
v2,_=m.fixture(version=2);function=struct.pack('<IHH',0,(5<<11)|3,2);assert v2.count(function)==1
bad=bytearray(v2);bad[v2.index(function)+15]=1
reject('type-function-padding',bytes(bad),'nonzero function type padding')
# Full labels with the same membership are supported in either input order.
labeldirs=[]
for i in (0,1):
 d=work/('labels-'+str(i));d.mkdir();(d/'input.ctf').write_bytes(two_labels(bool(i)));(d/'symbols').write_text('1 1\n2 2\n');(d/'external').write_bytes(b'');labeldirs.append(d)
output,r=invoke('labels-result',labeldirs[0],right=labeldirs[1]);assert r.returncode==0,r.stderr
raw=output.read_bytes();hh=struct.unpack_from('<HBB8I',raw);assert hh[6]==16
names=raw[36+hh[9]:];found=[]
for at in (36,44):
 name,boundary=struct.unpack_from('<II',raw,at);found.append(names[name:names.index(b'\0',name)].decode());assert boundary==30
assert found==['build','char']
zero=work/'external-zero';zero.mkdir();(zero/'input.ctf').write_bytes(change(36+h[8],0x80000000));(zero/'symbols').write_text('1 1\n2 2\n');(zero/'external').write_bytes(b'\0')
output,r=invoke('external-zero-result',zero,right=gooddir);assert r.returncode==0,r.stderr
zero_graph=Graph(output.read_bytes(),[syms[0],('other_lookup',*syms[1][1:])]);assert zero_graph.nodes[1][0][2]==''
# Four boundary sizes exercise both member-layout thresholds independently.
for size in (8191,8192,(1<<29)-1,1<<29):
 data,syms=m.fixture(version=2 if size<65535 else 3,mutation=lambda d:d[4].__setitem__(3,size))
 d=work/('size-'+str(size));d.mkdir();(d/'input.ctf').write_bytes(data);(d/'symbols').write_text('1 1\n2 2\n');(d/'external').write_bytes(b'')
 output,r=invoke('size-result-'+str(size),d,right=gooddir);assert r.returncode==0,r.stderr
 g=Graph(output.read_bytes(),[syms[0],('other_lookup',*syms[1][1:])]);assert g.nodes[4]==Graph(data,syms).nodes[4]
assert inputs=={str(p.resolve()):hashlib.sha256(p.read_bytes()).hexdigest() for p in [driver,path,args.semantic_reader,args.ctfdump,*args.ctf_library,Path(__file__)]},'qualification inputs changed'
(work/'result.json').write_text(json.dumps({'passed':True,'cases':reports,'negative_cases':negative,'member_size_boundaries':4,'full_labels_reordered':True,'external_zero_reference':True,'independent_ctfdump_cases':256,'unused_external_bytes_do_not_inflate_output':True,'inputs':inputs,'commands':commands},indent=2)+'\n')
if 'TEST_UNDECLARED_OUTPUTS_DIR' in os.environ:
 shutil.copyfile(work/'result.json',Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR'])/'ctf-union-result.json')
print(len(reports),'union graph checks,',len(negative),'negative controls and 256 independent ctfdump checks passed')
