#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify archive links/metadata across fresh Bazel output bases and disk cache."""
import argparse,json,subprocess,os,hashlib,tarfile
from pathlib import Path
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--commands',type=Path,required=True)
parser.add_argument('--src',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
options=parser.parse_args()
src=options.src.resolve(strict=True)
out=options.output.resolve()
if out.exists() or not out.is_relative_to('/usr/obj'):
 raise ValueError('fresh output under /usr/obj required')
out.mkdir()
seed=json.loads(options.commands.read_text())[0]['argv']
base=[x for x in seed if not x.startswith(('--max_idle_secs=','--output_user_root=','--symlink_prefix=','--build_event_json_file=','--execution_log_json_file=')) and not x.startswith('//')]
base[base.index('test')]='build'
base.insert(1,'--batch')
results=[]
for name in ('cold','restored'):
 d=out/name;d.mkdir()
 args=base[:];args.insert(args.index('build'),'--output_user_root='+str(d/'user-root'))
 args+=['--disk_cache='+str(out/'disk-cache'),'--symlink_prefix='+str(d/'bazel-'),'//tools/build/bazel/tests/install_archive:archive']
 with (d/'build.log').open('w') as log:
  rc=subprocess.run(args,cwd=src,stdout=log,stderr=subprocess.STDOUT,env=dict(os.environ,BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN='1')).returncode
 assert rc==0,(name,rc)
 archive=d/'bazel-bin/tools/build/bazel/tests/install_archive/archive.tar'
 with tarfile.open(archive) as tar:
  members={x.name:x for x in tar.getmembers()}
  assert set(members)=={'.','z','a','b','s'}
  assert members['a'].islnk() and members['a'].linkname=='z'
  assert members['b'].islnk() and members['b'].linkname=='z'
  assert members['s'].issym() and members['s'].linkname=='z'
  assert all(x.uid==1234 and x.gid==2345 and x.mtime==42 for x in members.values())
  assert members['z'].mode==0o640 and members['.'].mode==0o750
 extracted=d/'extracted';extracted.mkdir()
 subprocess.run(['/usr/bin/tar','-xpf',str(archive),'--no-same-owner','-C',str(extracted)],check=True)
 assert (extracted/'a').samefile(extracted/'z') and (extracted/'b').samefile(extracted/'z')
 assert os.readlink(extracted/'s')=='z'
 assert (extracted/'z').read_bytes()==(src/'tools/build/bazel/tests/install_archive/payload.txt').read_bytes()
 assert ((extracted/'z').stat().st_mode & 0o7777)==0o640
 assert (extracted.stat().st_mode & 0o7777)==0o750
 hit='disk cache hit' in (d/'build.log').read_text()
 if name=='restored': assert hit
 results.append(dict(name=name,argv=args,sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),disk_cache_hit=hit,status='passed'))
 (out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
assert results[0]['sha256']==results[1]['sha256']
(out/'receipt.json').write_text(json.dumps(dict(status='passed',scope='archive fixture cold/cache restoration and external BSD tar extraction; not pkgbase construction',results=results,input_sha256={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),src/'tools/build/bazel/install_archive.py',src/'tools/build/bazel/archive_policy.py',src/'tools/build/bazel/directory_metadata.py',src/'tools/build/bazel/bsd_install_archive.bzl',src/'tools/build/bazel/bsd_install.bzl',src/'tools/build/bazel/bsd_kyua_metadata.bzl',src/'tools/build/bazel/tests/install_archive/BUILD.bazel',src/'tools/build/bazel/tests/install_archive/payload.txt']}),indent=2)+'\n')
print(out/'receipt.json')
