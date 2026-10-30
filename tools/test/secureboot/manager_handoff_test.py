# SPDX-License-Identifier: BSD-2-Clause
"""Real native fork/exec confinement observed before manager main.

Uses only a temporary ordinary file descriptor, never production authority.
Requires a running kernel/libc implementing the existing confinement syscalls.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]

PROBE = r'''
#include <sys/capsicum.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

static void __attribute__((constructor))
check_handoff(void)
{
 int fds[5], status, control=atoi(getenv("CONTROL_FD"));
 char value[32], key[32];
 assert(fcntl(control,F_GETFD)!=-1);
 fds[0]=atoi(getenv("MANAGER_FD"));
 if(getenv("SECOND_EXEC")!=NULL) {
  for(unsigned i=0;i<5;i++) {
   if(i!=0) {
    snprintf(key,sizeof(key),"ALIAS_%u",i);
    fds[i]=atoi(getenv(key));
   }
   assert(fcntl(fds[i],F_GETFD)==-1 && errno==EBADF);
  }
  return;
 }
 fds[1]=dup(fds[0]);
 fds[2]=fcntl(fds[0],F_DUPFD,0);
 fds[3]=fcntl(fds[0],F_DUPFD_CLOEXEC,0);
 fds[4]=dup(control);assert(fds[4]>=0);
 assert(dup2(fds[0],fds[4])==fds[4]);
 for(unsigned i=0;i<5;i++) {
  assert(fds[i]>=0 && fcntl(fds[i],F_GETFD)!=-1);
  /* Ordinary fd flags are independent of the monotonic propagation state. */
  assert(fcntl(fds[i],F_SETFD,0)==0);
  errno=0;assert(cap_clofork_limit(fds[i],CAP_CLOFORK_UNLOCKED)==-1 && errno==ENOTCAPABLE);
  errno=0;assert(cap_cloexec_limit(fds[i],CAP_CLOEXEC_UNLOCKED)==-1 && errno==ENOTCAPABLE);
  if(i!=0) {
   snprintf(key,sizeof(key),"ALIAS_%u",i);
   snprintf(value,sizeof(value),"%d",fds[i]);
   assert(setenv(key,value,1)==0);
  }
 }
 pid_t child=fork();assert(child>=0);
 if(child==0) {
  if(fcntl(control,F_GETFD)==-1)_exit(98);
  for(unsigned i=0;i<5;i++)
   if(fcntl(fds[i],F_GETFD)!=-1 || errno!=EBADF)_exit(99);
  _exit(37);
 }
 assert(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==37);
 assert(setenv("SECOND_EXEC","1",1)==0);
 execl(getenv("PROBE_PATH"),"handoff-probe",NULL);
 _exit(99);
}
int main(void) { return getenv("SECOND_EXEC")?0:98; }
'''
LAUNCHER = r'''
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include "bootstrap_exec.h"
int main(int argc,char **argv) {
 assert(argc==3);
 errno=0;assert(bootstrap_confine_manager_fd(-1)==-1 && errno==EBADF);
 int fd=open(argv[2],O_RDONLY|O_CLOEXEC);assert(fd>=0);
 assert(bootstrap_confine_manager_fd(fd)==0);
 char number[32];snprintf(number,sizeof(number),"%d",fd);
 assert(setenv("MANAGER_FD",number,1)==0);
 assert(setenv("PROBE_PATH",argv[1],1)==0);
 int control=open(argv[2],O_RDONLY);assert(control>=0);
 snprintf(number,sizeof(number),"%d",control);
 assert(setenv("CONTROL_FD",number,1)==0);
 execl(argv[1],"handoff-probe",NULL);return 99;
}
'''

class ManagerHandoff(unittest.TestCase):
    def test_constructor_cannot_propagate_manager_descriptor(self):
        with tempfile.TemporaryDirectory(prefix='manager-handoff-') as directory:
            work = Path(directory)
            (work / 'probe.c').write_text(PROBE)
            (work / 'launcher.c').write_text(LAUNCHER)
            source = ROOT / 'usr.sbin/capsule'
            commands = [
                ['cc', '-I' + str(ROOT / 'sys'), '-Wall', '-Wextra', '-Werror', str(work / 'probe.c'),
                 '-o', str(work / 'probe')],
                ['cc', '-I' + str(ROOT / 'sys'), '-Wall', '-Wextra', '-Werror', '-I' + str(source),
                 str(work / 'launcher.c'), str(source / 'bootstrap_exec.c'),
                 '-o', str(work / 'launcher')],
                [str(work / 'launcher'), str(work / 'probe'), str(work / 'probe.c')],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

if __name__ == '__main__':
    unittest.main()
