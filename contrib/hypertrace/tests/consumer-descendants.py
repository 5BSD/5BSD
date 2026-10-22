#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise production collector reaper decisions without tracing or VM activity."""
from pathlib import Path
import subprocess, sys, json
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root/'cddl/contrib/opensolaris/cmd/dtrace/dtrace.c').read_text()
a = source.index('static int g_consumer_reaper;')
b = source.index('static int\nconsumer_stop_quiesce(', a)
fixture = r'''
#include <sys/param.h>
#include <sys/procctl.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static int acquire_error, status_error, query_error, wait_error;
static unsigned descendants, flags = REAPER_STATUS_OWNED, waits, queries;
static pid_t reaper, waited;
static struct procctl_reaper_pidinfo entries[256];
static int fake_procctl(idtype_t type, id_t id, int command, void *data) {
 assert(type == P_PID && id == (id_t)getpid());
 if (command == PROC_REAP_ACQUIRE) {
  assert(data == NULL);
  if (acquire_error) { errno=acquire_error; return -1; }
  return 0;
 }
 if (command == PROC_REAP_STATUS) {
  if(status_error) { errno=status_error;return -1; }
  struct procctl_reaper_status *s=data;
  s->rs_flags=flags;s->rs_reaper=reaper;s->rs_descendants=descendants;
  return 0;
 }
 assert(command == PROC_REAP_GETPIDS);queries++;
 if(query_error) { errno=query_error;return -1; }
 struct procctl_reaper_pids *q=data;
 assert(q->rp_count == nitems(entries));
 memcpy(q->rp_pids,entries,sizeof(entries));return 0;
}
static pid_t fake_waitpid(pid_t pid, int *status, int options) {
 assert(status == NULL && options == WNOHANG);waits++;waited=pid;
 if(wait_error) { errno=wait_error;return -1; }
 return pid;
}
#define procctl fake_procctl
#define waitpid fake_waitpid
''' + source[a:b] + r'''
int main(void) {
 reaper=getpid();
 assert(consumer_descendants_step()==-1 && errno==EAGAIN);
 acquire_error=EPERM;
 assert(consumer_descendants_prepare()==-1 && errno==EPERM && !g_consumer_reaper);
 acquire_error=EBUSY;status_error=EIO;
 assert(consumer_descendants_prepare()==-1 && errno==EIO && !g_consumer_reaper);
 status_error=0;flags=0;
 assert(consumer_descendants_prepare()==-1 && errno==EPROTO);
 flags=REAPER_STATUS_OWNED;reaper=getpid()+1;
 assert(consumer_descendants_prepare()==-1 && errno==EPROTO);
 reaper=getpid();
 assert(consumer_descendants_prepare()==0 && g_consumer_reaper);
 g_consumer_reaper=0;acquire_error=0;
 assert(consumer_descendants_prepare()==0 && g_consumer_reaper);
 assert(consumer_descendants_step()==1 && queries==0 && waits==0);
 status_error=EIO;
 assert(consumer_descendants_step()==-1 && errno==EIO);
 status_error=0;flags=0;
 assert(consumer_descendants_step()==-1 && errno==ESTALE);
 flags=REAPER_STATUS_OWNED;reaper=getpid()+1;
 assert(consumer_descendants_step()==-1 && errno==ESTALE);
 reaper=getpid();descendants=300;query_error=EIO;
 assert(consumer_descendants_step()==-1 && errno==EIO);
 query_error=0;
 assert(consumer_descendants_step()==0 && waits==0);
 unsigned eligible=REAPER_PIDINFO_VALID|REAPER_PIDINFO_CHILD|REAPER_PIDINFO_ZOMBIE;
 entries[0].pi_pid=123;entries[0].pi_flags=eligible & ~REAPER_PIDINFO_VALID;
 entries[1].pi_pid=124;entries[1].pi_flags=eligible & ~REAPER_PIDINFO_CHILD;
 entries[2].pi_pid=125;entries[2].pi_flags=eligible & ~REAPER_PIDINFO_ZOMBIE;
 assert(consumer_descendants_step()==0 && waits==0);
 entries[255].pi_pid=126;entries[255].pi_flags=eligible;
 assert(consumer_descendants_step()==0 && waits==1 && waited==126);
 int errors[]={ECHILD,EINTR,EIO};
 for(unsigned i=0;i<nitems(errors);i++) {
  wait_error=errors[i];
  assert(consumer_descendants_step()==(i==2?-1:0));
  assert(errno==errors[i]);
 }
 wait_error=0;unsigned before=waits;
 for(int pid=-1;pid<=1;pid++) {
  entries[255].pi_pid=pid;
  assert(consumer_descendants_step()==-1 && errno==EPROTO && waits==before);
 }
 descendants=0;unsigned before_queries=queries;
 assert(consumer_descendants_step()==1 && queries==before_queries && waits==before);
 puts("PASS: collector reaper ownership, bounded zombie reaping, errors, and empty recensus");
 return 0;
}
'''
(out/'descendants.c').write_text(fixture)
command=['cc','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(out/'descendants.c'),'-o',str(out/'descendants')]
(out/'command.json').write_text(json.dumps(command,indent=2))
subprocess.run(command,check=True)
subprocess.run([str(out/'descendants')],check=True,timeout=30)

# Real, isolated process tree: no DTrace device, daemon, or VM is used.
native = r'''
#include <sys/param.h>
#include <sys/procctl.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
''' + source[a:b] + r'''
int main(void) {
 alarm(15);
 assert(consumer_descendants_prepare()==0);
 assert(consumer_descendants_step()==1);
 int release[2],ready[2];
 assert(pipe(release)==0 && pipe(ready)==0);
 pid_t child=fork();assert(child>=0);
 if(child==0) {
  close(release[1]);close(ready[0]);
  /* A nested reaper must not hide its surviving descendants. */
  assert(procctl(P_PID,getpid(),PROC_REAP_ACQUIRE,NULL)==0);
  pid_t grandchild=fork();assert(grandchild>=0);
  if(grandchild==0) {
   close(ready[1]);char byte;
   assert(read(release[0],&byte,1)==0);_exit(0);
  }
  assert(write(ready[1],&grandchild,sizeof(grandchild))==sizeof(grandchild));
  close(ready[1]);
  /* Leave the grandchild to be adopted when this child is reaped. */
  _exit(0);
 }
 close(release[0]);close(ready[1]);pid_t grandchild;
 assert(read(ready[0],&grandchild,sizeof(grandchild))==sizeof(grandchild));
 close(ready[0]);
 int adopted=0;
 for(unsigned i=0;i<1000 && !adopted;i++) {
  assert(consumer_descendants_step()==0);
  struct procctl_reaper_pidinfo children[8]={{0}};
  struct procctl_reaper_pids query={0};
  query.rp_count=nitems(children);query.rp_pids=children;
  assert(procctl(P_PID,getpid(),PROC_REAP_GETPIDS,&query)==0);
  for(unsigned j=0;j<nitems(children);j++)
   if(children[j].pi_pid==grandchild &&
       (children[j].pi_flags & (REAPER_PIDINFO_VALID|REAPER_PIDINFO_CHILD))==
       (REAPER_PIDINFO_VALID|REAPER_PIDINFO_CHILD))adopted=1;
  if(!adopted)usleep(1000);
 }
 assert(adopted && consumer_descendants_step()==0);
 close(release[1]);
 int done=0;
 for(unsigned i=0;i<1000;i++) {
  done=consumer_descendants_step();assert(done>=0);
  if(done==1)break;
  usleep(1000);
 }
 assert(done==1);
 assert(waitpid(-1,NULL,WNOHANG)==-1 && errno==ECHILD);
 puts("PASS: real nested reaper descendants remain pending until reaped and empty");
 return 0;
}
'''
(out/'descendants-native.c').write_text(native)
command=['cc','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(out/'descendants-native.c'),'-o',str(out/'descendants-native')]
(out/'native-command.json').write_text(json.dumps(command,indent=2))
subprocess.run(command,check=True)
subprocess.run([str(out/'descendants-native')],check=True,timeout=30)
