#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess,sys
root=Path(__file__).resolve().parents[3];out=Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True,exist_ok=True)
s=(root/'usr.sbin/bhyve/hypertrace.c').read_text();parts=[]
for sig in ('int\nhypertrace_retire_transport(', 'void\nhypertrace_destroy(', 'int\nhypertrace_session_retired('):
 a=s.index(sig);b=s.index('\n}',a)+2;parts.append(s[a:b])
f=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/hypertrace_wire.h>
static pthread_mutex_t lifecycle=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t reconnect=PTHREAD_COND_INITIALIZER;
static pthread_t connector;
static bool prepared=true,started=true,stopping;
static atomic_bool restore_mode;
static int inbound_dirfd=-1,sockdir=-1,session_gate_fd=-1,session_gate_error=0;
static struct channel {pthread_mutex_t mutex;int fd;} rx={PTHREAD_MUTEX_INITIALIZER,-1},wx={PTHREAD_MUTEX_INITIALIZER,-1};
static int fail_join=1,joins,exited;
static int test_join(pthread_t t,void **r) {joins++;if(fail_join){fail_join=0;return EBUSY;}return pthread_join(t,r);}
static void ht_disconnect(struct channel *c) {if(c->fd>=0)close(c->fd);c->fd=-1;}
static int test_ioctl(int fd,unsigned long cmd,void *arg) {
 struct hypertrace_epoch_query *q=arg;
 assert(fd==session_gate_fd&&fcntl(fd,F_GETFD)>=0&&cmd==HYPERTRACE_IOC_EPOCH_QUERY);
 assert(q->vmid==7&&q->epoch==9);q->live=0;return 0;
}
#define pthread_join test_join
#define ioctl test_ioctl
'''+ '\n'.join(parts)+r'''
static void *worker(void *arg) {
 int *ctx=arg;
 pthread_mutex_lock(&lifecycle);
 while(!stopping)pthread_cond_wait(&reconnect,&lifecycle);
 assert(*ctx==42);exited=1;
 pthread_mutex_unlock(&lifecycle);return NULL;
}
int main(void) {
 FILE *f=tmpfile();assert(f);
 inbound_dirfd=dup(fileno(f));sockdir=dup(fileno(f));session_gate_fd=dup(fileno(f));
 rx.fd=dup(fileno(f));wx.fd=dup(fileno(f));
 assert(inbound_dirfd>=0&&sockdir>=0&&session_gate_fd>=0&&rx.fd>=0&&wx.fd>=0);
 int ctx=42;assert(pthread_create(&connector,NULL,worker,&ctx)==0);
 assert(hypertrace_retire_transport()==EBUSY&&started&&!prepared&&stopping);
 assert(fcntl(inbound_dirfd,F_GETFD)>=0&&fcntl(session_gate_fd,F_GETFD)>=0);
 assert(hypertrace_retire_transport()==0&&!started&&exited&&joins==2);
 ctx=0; /* The connector is joined before its context is invalidated. */
 assert(rx.fd==-1&&wx.fd==-1&&inbound_dirfd==-1&&sockdir==-1);
 assert(hypertrace_session_retired(7,9)==0);
 assert(hypertrace_retire_transport()==0&&joins==2);
 assert(hypertrace_session_retired(7,9)==0);
 hypertrace_destroy();assert(session_gate_fd==-1&&session_gate_error==ENXIO);
 assert(hypertrace_session_retired(7,9)==-1&&errno==ENXIO);
 hypertrace_destroy();fclose(f);return 0;
}
'''
(out/'retire.c').write_text(f)
subprocess.run(['cc','-Wall','-Wextra','-Werror','-pthread','-fsanitize=address,undefined','-I'+str(root/'sys'),str(out/'retire.c'),'-o',str(out/'retire')],check=True)
subprocess.run([str(out/'retire')],check=True,timeout=30)
print('PASS: actual transport retirement joins worker before context invalidation, retries failed join and retains query capability until final teardown')
