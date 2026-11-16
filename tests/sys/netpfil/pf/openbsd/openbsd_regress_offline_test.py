#!/usr/bin/env python3
"""Run wrapper fixtures with fake make/PF commands; no build, PF or root needed.

Usage: python3 openbsd_regress_offline_test.py [path/to/openbsd_regress.sh]
This is an offline developer check, not a registered live PF ATF case.
OPENBSD_REGRESS_OFFLINE_TIMEOUT sets the per-fixture deadline (1..300 seconds;
default 60). Timeouts remain failures and terminate the isolated process group.
"""
import json
import os
import re
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

WRAPPER=Path(sys.argv.pop(1)).resolve() if len(sys.argv)>1 else Path(__file__).with_name('openbsd_regress.sh')

def fixture_deadline(value):
    if not re.fullmatch(r'[0-9]+', value) or not 1 <= int(value) <= 300:
        raise ValueError('OPENBSD_REGRESS_OFFLINE_TIMEOUT must be an integer in 1..300')
    return int(value)


DEADLINE=fixture_deadline(os.environ.get('OPENBSD_REGRESS_OFFLINE_TIMEOUT','60'))


def run_isolated(argv, *, input=None, cwd=None, env=None, deadline=DEADLINE,
                 started=None):
    # A new session makes this fixture's process group distinct from the test
    # runner and unrelated jobs. Kill the whole owned group, not only sh/make.
    process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,text=True,cwd=cwd,env=env,
                             start_new_session=True)
    try:
        if started is not None:
            started(process)
        stdout,stderr=process.communicate(input=input,timeout=deadline)
        return subprocess.CompletedProcess(argv,process.returncode,stdout,stderr)
    except BaseException as error:
        try:
            os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            stdout,stderr=process.communicate(timeout=60)
        except subprocess.TimeoutExpired as cleanup:
            raise RuntimeError('fixture group cleanup unconfirmed; inspect PGID '+str(process.pid)) from cleanup
        if isinstance(error,subprocess.TimeoutExpired):
            error.output=stdout;error.stderr=stderr
        raise


class Wrapper(unittest.TestCase):
 def run_fixture(self,records,output='',status=0,directory='suite',timeout=None):
    with tempfile.TemporaryDirectory() as tmp:
      root=Path(tmp);(root/'bin').mkdir()
      (root/'srctree/contrib/openbsd-pf/regress'/directory).mkdir(parents=True)
      (root/'records').write_text(records);(root/'output').write_text(output)
      fake=root/'bin/make'
      fake.write_text('''#!/bin/sh
log=
for arg in "$@"; do case "$arg" in REGRESS_LOG=*) log=${arg#REGRESS_LOG=};; esac; done
test -n "$log" || exit 91
cat "$FIXTURE/records" >> "$log"
cat "$FIXTURE/output"
for arg in "$@"; do printf 'MAKE_ARG: %s\n' "$arg"; done
exit "$MAKE_STATUS"
''');fake.chmod(0o755)
      # These shell functions prevent every native PF/sysctl probe. The
      # fake make only writes fixture records; env selects it via PATH.
      driver='''atf_get_srcdir() { printf '%s\\n' "$FIXTURE"; }
atf_config_get() { printf '%s\\n' "${TEST_TIMEOUT-$2}"; }
atf_skip() { echo "ATF_SKIP: $*"; exit 77; }
atf_fail() { echo "ATF_FAIL: $*"; exit 1; }
kldstat() { return 0; }
sysctl() { echo 0; }
. "$WRAPPER"
run_suite "$TEST_DIRECTORY"
echo ATF_PASS
'''
      env=dict(os.environ,FIXTURE=str(root),WRAPPER=str(WRAPPER),MAKE_STATUS=str(status),PATH=str(root/'bin')+':/bin:/usr/bin:/sbin:/usr/sbin',TEST_DIRECTORY=directory)
      if timeout is not None:env['TEST_TIMEOUT']=timeout
      return run_isolated(['/bin/sh','-s'],input=driver,cwd=root,env=env)
 def test_valid_success_and_expected_failure(self):
    for records in ('SUCCESS suite/a\n','XFAIL suite/a\n','SUCCESS suite/a\nSKIP suite/b\n','SKIP suite/a\nXFAIL suite/b\n'):
      with self.subTest(records=records):
        r=self.run_fixture(records);self.assertEqual(r.returncode,0,r.stdout+r.stderr);self.assertIn('ATF_PASS',r.stdout)
 def test_make_error_after_success_or_skip_never_passes(self):
    for records,output in [('SUCCESS suite/a\n','cleanup error\n'),('SKIP suite/a\n','SKIPPED\n'),('','SKIPPED\n')]:
      r=self.run_fixture(records,output,2)
      self.assertEqual(r.returncode,1,r.stdout+r.stderr);self.assertIn('make failed (status 2)',r.stdout)
 def test_failed_and_unexpected_pass_targets(self):
    for status in ('FAIL','XPASS'):
      r=self.run_fixture('SUCCESS suite/a\n'+status+' suite/b\n')
      self.assertEqual(r.returncode,1,r.stdout+r.stderr);self.assertIn('failed or unexpectedly passed',r.stdout)
 def test_legitimate_skips(self):
    for records,output in [('', 'Enable pf to run this regress.\nSKIPPED\n'),('SKIP suite/a\nSKIP suite/b\n','')]:
      r=self.run_fixture(records,output)
      self.assertEqual(r.returncode,77,r.stdout+r.stderr);self.assertIn('ATF_SKIP',r.stdout)
 def test_empty_or_misleading_skip_output(self):
    for output in ('','tool printed NOT_SKIPPED\n','SKIPPED something unrelated\n'):
      r=self.run_fixture('',output);self.assertEqual(r.returncode,1,r.stdout+r.stderr)
 def test_malformed_results(self):
    for records in ('garbage\n','PASS suite/a\n','SUCCESS\n','SUCCESS suite/a extra\n',' SUCCESS suite/a\n','SUCCESS suite/a\nFAIL\n','SUCCESS suite/a\n\n'):
      with self.subTest(records=records):
        r=self.run_fixture(records);self.assertEqual(r.returncode,1,r.stdout+r.stderr)
        self.assertIn('malformed per-target results',r.stdout)
 def test_complete_log_visible_even_on_make_failure(self):
    records='SUCCESS sys/net/pf_trans/dev-limit\nFAIL sys/net/pf_trans/iocmd-limit\n'
    r=self.run_fixture(records,status=2)
    self.assertEqual(r.returncode,1)
    self.assertIn('==== REGRESS_LOG BEGIN ====\n'+records+'==== REGRESS_LOG END ====',r.stdout)
 def test_pf_trans_timeout_bounds_and_forwarding(self):
    for value in (None,'1','60'):
      r=self.run_fixture('SUCCESS sys/net/pf_trans/dev-limit\nSUCCESS sys/net/pf_trans/iocmd-limit\n',directory='sys/net/pf_trans',timeout=value)
      self.assertEqual(r.returncode,0,r.stdout+r.stderr)
      self.assertIn('MAKE_ARG: TIMEOUT='+(value or '10')+'\n',r.stdout)
      self.assertNotIn('REGRESS_TARGETS=',r.stdout)
    for value in ('','0','61','-1','1.5','abc','2;cmd','999999999999999999999999999999999'):
      r=self.run_fixture('',directory='sys/net/pf_trans',timeout=value)
      self.assertEqual(r.returncode,1,r.stdout+r.stderr)
      self.assertIn('timeout must be an integer in 1..60',r.stdout)
      self.assertNotIn('MAKE_ARG:',r.stdout)
    r=self.run_fixture('SUCCESS suite/a\n',timeout='60')
    self.assertEqual(r.returncode,0,r.stdout+r.stderr)
    self.assertNotIn('MAKE_ARG: TIMEOUT=',r.stdout)
 def test_offline_deadline_validation(self):
    self.assertEqual(fixture_deadline('60'),60)
    for value in ('1','300'):
      self.assertEqual(fixture_deadline(value),int(value))
    for value in ('','0','301','-1','1.5','nan','60;true'):
      with self.assertRaises(ValueError):fixture_deadline(value)
 def test_timeout_kills_owned_descendant_group(self):
    with tempfile.TemporaryDirectory() as tmp:
      ready=Path(tmp)/'ready.json';identity={}
      child_script = (
        'import json,os,subprocess,sys,time\n'
        'child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(120)"])\n'
        'with open(sys.argv[1],"w") as f: json.dump({"leader":os.getpid(),"child":child.pid,"group":os.getpgrp(),"child_group":os.getpgid(child.pid)},f)\n'
        'time.sleep(120)\n')
      def started(process):
        end=time.monotonic()+DEADLINE
        while not ready.exists() or not ready.stat().st_size:
          if process.poll() is not None:raise AssertionError('controlled sleeper exited before ready')
          if time.monotonic() >= end:raise AssertionError('controlled sleeper readiness deadline')
          time.sleep(0.02)
        # A small file may be visible before its write completes.
        while True:
          try:identity.update(json.loads(ready.read_text()));break
          except json.JSONDecodeError:
            if time.monotonic() >= end:raise
            time.sleep(0.02)
        self.assertEqual(identity['leader'],process.pid)
        self.assertEqual(identity['group'],process.pid)
        self.assertEqual(identity['child_group'],process.pid)
        self.assertEqual(os.getpgid(identity['child']),process.pid)
        self.assertNotEqual(process.pid,os.getpgrp())
      with self.assertRaises(subprocess.TimeoutExpired):
        run_isolated([sys.executable,'-c',child_script,str(ready)],deadline=0.1,started=started)
      # The leader is reaped; an orphaned child may briefly be a zombie waiting
      # for init. Neither a zombie nor an absent PID is a running leaked child.
      with self.assertRaises(ProcessLookupError):os.kill(identity['leader'],0)
      status=run_isolated(['/bin/ps','-p',str(identity['child']),'-o','stat='])
      self.assertIn(status.returncode,(0,1),status.stdout+status.stderr)
      self.assertFalse(status.stderr.strip(),status.stderr)
      if status.returncode == 0:
        self.assertTrue(status.stdout.strip().startswith('Z'),status.stdout)
      else:
        self.assertFalse(status.stdout.strip(),status.stdout)
 def test_shell_syntax(self):
    subprocess.run(['/bin/sh','-n',str(WRAPPER)],check=True)

if __name__=='__main__':unittest.main()
