#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Native FreeBSD amd64: ensure failed generation cannot become a reusable Make target."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import shlex
import json
import platform

p=argparse.ArgumentParser(description=__doc__)
for name in ('component','src','objtop','work'):
    p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args()
for path in (a.component,a.src,a.objtop,a.work):
    if not path.is_absolute() or any(c in str(path) for c in '$\n\r'):
        p.error('paths must be absolute with no Make expansion or control characters')
if platform.system() != 'FreeBSD' or platform.machine() != 'amd64':
    p.error('this qualification supports native FreeBSD amd64 only')
a.component=a.component.resolve(strict=True)
a.src=a.src.resolve(strict=True)
a.objtop=a.objtop.resolve(strict=True)
parent=a.work.parent.resolve(strict=True)
work=parent/a.work.name
if a.work.exists() or a.work.is_symlink() or not work.is_relative_to('/usr/obj') or work==Path('/usr/obj'):
    p.error('work must be a fresh directory below /usr/obj with no symlink escape')
a.work=work
a.work.mkdir()
commands=[]
def buildenv(command):
    env={'PATH':'/bin:/usr/bin:/usr/local/bin','HOME':os.environ['HOME'],
         'MAKEOBJDIRPREFIX':'/usr/obj','LC_ALL':'C'}
    argv=['/usr/bin/make','-C',str(a.src),'SRCCONF=/dev/null','__MAKE_CONF=/dev/null',
          'SRC_ENV_CONF=/dev/null','buildenv','BUILDENV_SHELL='+shlex.join(command)]
    done=subprocess.run(argv,env=env,capture_output=True,text=True)
    commands.append({'argv':argv,'status':done.returncode,'stdout':done.stdout,'stderr':done.stderr})
    (a.work/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
    if done.returncode:raise ValueError('buildenv query failed: '+done.stderr+done.stdout)
    return done.stdout

def make_target(target,obj,extra=()):
    return buildenv(['/usr/bin/env','MAKEOBJDIR='+str(obj),'/usr/bin/make','-C',str(a.component),
        'SRCTOP='+str(a.src),'OBJTOP='+str(a.objtop),'SRCCONF=/dev/null',
        '__MAKE_CONF=/dev/null','SRC_ENV_CONF=/dev/null',*extra,target])


class Failures(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(dir=a.work)
        self.root=Path(self.temporary.name)
        self.failing=self.root/'partial-tool'
        self.failing.write_text('#!/bin/sh\nprintf "deliberate partial output\\n"\nexit 17\n')
        self.failing.chmod(0o755)
    def tearDown(self):
        self.temporary.cleanup()
    def command(self,kind,output,fail):
        sed=str(self.failing) if fail=='sed' else '/usr/bin/sed'
        cat=str(self.failing) if fail=='cat' else '/bin/cat'
        mv='/usr/bin/false' if fail=='mv' else '/bin/mv'
        if kind=='hl':
            args=['16','md4','MD4','-',str(a.component/'mdXhl.c'),str(output),sed]
            script='genhl.sh'
        else:
            args=['md4','MD4',str(a.component/'mdX.3'),str(a.component/'md4.copyright'),str(output),sed,cat]
            script='genman.sh'
        return ['/bin/sh',str(a.component/script)]+args+[mv,'/bin/rm']
    def test_partial_tools_preserve_previous_or_absent_output(self):
        for kind,fail in [('hl','sed'),('manual','sed'),('manual','cat'),('hl','mv'),('manual','mv')]:
            for previous in (False,True):
                with self.subTest(kind=kind,fail=fail,previous=previous):
                    output=self.root/'output'
                    if previous:output.write_bytes(b'previous complete output\n')
                    result=subprocess.run(self.command(kind,output,fail),capture_output=True)
                    self.assertNotEqual(result.returncode,0)
                    if previous:self.assertEqual(output.read_bytes(),b'previous complete output\n')
                    else:self.assertFalse(output.exists())
                    self.assertEqual(list(self.root.glob('output.tmp.*')),[])
                    # A normal retry must succeed and contain no partial-tool marker.
                    subprocess.run(self.command(kind,output,None),check=True)
                    self.assertNotIn(b'deliberate partial',output.read_bytes())
                    output.unlink()
    def test_exclusive_temporary_collision_is_not_removed(self):
        # Exec preserves the shell PID, allowing an exact collision without a race.
        out=self.root/'collision-output'
        wrapper=self.root/'reserve.sh'
        wrapper.write_text('set -eu\nprintf sentinel > "$1.tmp.$$"\nshift\nexec "$@"\n')
        result=subprocess.run(['/bin/sh',str(wrapper),str(out)]+self.command('hl',out,None),capture_output=True)
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(out.exists())
        leftovers=list(self.root.glob('collision-output.tmp.*'))
        self.assertEqual(len(leftovers),1)
        self.assertEqual(leftovers[0].read_bytes(),b'sentinel')
    def test_make_failure_then_unforced_retry(self):
        identity=buildenv(['/usr/bin/make','-C',str(a.src/'lib/libmd'),'-v','OBJTOP'])
        self.assertEqual(identity.splitlines(),['Entering world for amd64:amd64',str(a.objtop)])
        for target,variable in [('md4hl.c','LIBMD_GEN_SED'),('md4.3','LIBMD_GEN_CAT')]:
            with self.subTest(target=target):
                obj=self.root/target;obj.mkdir()
                with self.assertRaisesRegex(ValueError,'buildenv query failed'):
                    make_target(target,obj,extra=[variable+'='+str(self.failing)])
                self.assertFalse((obj/target).exists())
                self.assertEqual(list(obj.glob(target+'.tmp.*')),[])
                # No -B, deletion or timestamp trick: ordinary Make must retry.
                make_target(target,obj)
                self.assertNotIn(b'deliberate partial',(obj/target).read_bytes())

unittest.main(argv=['shared-generator-test'])
