#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Stage a disposable PF parity guest from an existing root, never the host."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('seed', type=Path)
p.add_argument('directory', type=Path)
p.add_argument('--refresh-fixtures',action='store_true')
p.add_argument('--pf-module', type=Path, help='focused PF module built under /usr/obj')
p.add_argument('--case', dest='cases', action='append', required=True)
a = p.parse_args()
seed, directory = a.seed.resolve(), a.directory.resolve()
if not str(seed).startswith('/usr/obj/') or not str(directory).startswith('/usr/obj/'):
    p.error('seed and destination must be under /usr/obj')
if (directory.exists() and not a.refresh_fixtures) or directory == seed or seed in directory.parents:
    p.error('destination must be new and outside the seed')
import re
if any(not re.fullmatch(r'[a-z0-9_]+:[a-z0-9_]+', c) for c in a.cases):
    p.error('invalid test case')
src = Path(__file__).resolve().parents[3]
if src != Path('/usr/src'):
    p.error('use the maintained /usr/src harness')
for case in a.cases:
    program, name = case.split(':')
    fixture = src / ('tests/sys/netpfil/pf/' + program + '.sh')
    if not fixture.is_file():
        p.error('missing source fixture: ' + program)
    registered = set(re.findall(r"atf_add_test_case\s+[\"']?([a-z0-9_]+)", fixture.read_text()))
    if name not in registered:
        p.error('unregistered test case: ' + case)

for required in ['boot/kernel/kernel', 'boot/pmbr', 'boot/gptzfsboot',
                 'usr/tests/sys/netpfil/pf/Kyuafile', 'root/pf-artifacts']:
    if not (seed / required).is_file():
        p.error('missing seed file: ' + required)
module = a.pf_module.resolve() if a.pf_module else None
if module and (not str(module).startswith('/usr/obj/') or not module.is_file()):
    p.error('PF module must be an existing build under /usr/obj')
root = directory / 'root'
if a.refresh_fixtures:
    prior = json.loads((directory/'stage.json').read_text())
    if prior['seed'] != str(seed):p.error('seed differs from existing stage')
    import time
    shutil.copyfile(directory/'stage.json', directory/('stage-'+str(time.time_ns())+'.json'))
else:
    directory.mkdir(parents=True)
    print('Copying seed root to', root, flush=True)
    shutil.copytree(seed, root, symlinks=True)
def put(path, content, mode=0o644):
    dest = root / path
    if dest.exists() or dest.is_symlink():
        dest.unlink()
    dest.write_text(content)
    dest.chmod(mode)
put('root/pf-parity-disposable', 'Disposable PF parity test guest\n')
put('root/pf-parity.sh', (src/'tools/test/pf-parity/guest.sh').read_text(), 0o755)
put('root/pf-parser-corpus.sh', (src/'tools/test/pf-parity/parser-corpus.sh').read_text(), 0o755)
put('root/pf-cases', '\n'.join(a.cases) + '\n')
put('boot/loader.conf.local', 'init_path="/sbin/init"\ninit_rc="/root/pf-parity.sh"\n')
put('etc/rc.local', 'sh /root/pf-parity.sh\n', 0o755)
# ATF shell build output: interpreter plus source; no host test execution.
put('usr/tests/sys/netpfil/pf/limiters', '#!/usr/libexec/atf-sh\n' +
    (src/'tests/sys/netpfil/pf/limiters.sh').read_text(), 0o755)
extra_paths = []
for program, helper in [('fragmentation_pass', 'frag-direction.py'),
                        ('tcp', 'tcp-original-ack.py'),
                        ('icmp6', 'mld-group.py')]:
    if not any(c.startswith(program + ':') for c in a.cases):
        continue
    for name, content, mode in [
        (program, '#!/usr/libexec/atf-sh\n' + (src/('tests/sys/netpfil/pf/' + program + '.sh')).read_text(), 0o755),
        (helper, (src/('tests/sys/netpfil/pf/' + helper)).read_text(), 0o644),
    ]:
        path = 'usr/tests/sys/netpfil/pf/' + name
        put(path, content, mode)
        extra_paths.append('/' + path)
    kyuafile = 'usr/tests/sys/netpfil/pf/Kyuafile'
    config = (root/kyuafile).read_text()
    if 'name="' + program + '"' not in config:
        config += 'atf_test_program{name="' + program + '", execenv="jail", execenv_jail_params="vnet allow.raw_sockets allow.read_msgbuf"}\n'
        put(kyuafile, config)
    extra_paths.append('/' + kyuafile)
if module:
    dest = root/'boot/kernel/pf.ko'
    # Installed kernel modules are read-only even in an owned staging tree.
    dest.unlink()
    shutil.copy2(module, dest)
paths = set((root/'root/pf-artifacts').read_text().splitlines())
paths.update(extra_paths)
paths.update(['/boot/loader.conf.local', '/root/pf-parity.sh', '/root/pf-parser-corpus.sh', '/root/pf-cases', '/etc/rc.local',
              '/usr/tests/sys/netpfil/pf/limiters'])
put('root/pf-artifacts', '\n'.join(sorted(paths))+'\n')
meta = {'seed':str(seed),'cases':a.cases,'source_head':subprocess.check_output(
    ['git','-C',str(src),'rev-parse','HEAD'],text=True).strip(),
    'kernel_provenance':'Existing seed kernel; not a new kernel build or final qualification',
    'source_sha256':{str(x.relative_to(src)):hashlib.sha256(x.read_bytes()).hexdigest()
       for x in [src/'tests/sys/netpfil/pf/limiters.sh',Path(__file__),src/'tools/test/pf-parity/guest.sh',src/'tools/test/pf-parity/parser-corpus.sh']}}
meta['parser_corpus'] = dict(re.findall(r'^check ([a-z0-9_]+) (accept|reject) <<',
    (src/'tools/test/pf-parity/parser-corpus.sh').read_text(), re.M))
if module:
    meta['pf_module'] = {
        'path': str(module),
        'sha256': hashlib.sha256(module.read_bytes()).hexdigest(),
        'source_pf_c_sha256': hashlib.sha256((src/'sys/netpfil/pf/pf.c').read_bytes()).hexdigest(),
        'qualification': 'Focused module only; clean full build remains required',
    }
(directory/'stage.json').write_text(json.dumps(meta,indent=2)+'\n')
print('Staged',root,flush=True)
