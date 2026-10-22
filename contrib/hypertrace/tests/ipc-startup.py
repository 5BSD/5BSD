#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise actual IPC startup gate with real threads, without VM operations."""
from pathlib import Path
import subprocess, sys
root=Path(__file__).resolve().parents[3]
out=Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True,exist_ok=True)
s=(root/'usr.sbin/bhyve/ipc.c').read_text()
a=s.index('static pthread_mutex_t ipc_startup_mutex')
b=s.index('void\nipc_quarantine_vm(',a)
fixture=r'''
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <unistd.h>
'''+s[a:b]+r'''
static atomic_bool waiting, admitted;
static int startup_value;
static void *worker(void *unused) {
 (void)unused; atomic_store(&waiting,true);
 ipc_wait_for_startup();
 assert(startup_value==42);
 atomic_store(&admitted,true);
 return NULL;
}
int main(void) {
 pthread_t thread;
 assert(pthread_create(&thread,NULL,worker,NULL)==0);
 while (!atomic_load(&waiting)) usleep(100);
 /* Spurious wakeups cannot bypass the readiness predicate. */
 pthread_mutex_lock(&ipc_startup_mutex);
 pthread_cond_broadcast(&ipc_startup_cond);
 pthread_mutex_unlock(&ipc_startup_mutex);
 usleep(10000); assert(!atomic_load(&admitted));
 startup_value=42; ipc_startup_complete();
 assert(pthread_join(thread,NULL)==0 && atomic_load(&admitted));
 /* Publication before worker startup must not lose the wakeup. */
 ipc_startup_complete(); atomic_store(&admitted,false);
 assert(pthread_create(&thread,NULL,worker,NULL)==0);
 assert(pthread_join(thread,NULL)==0 && atomic_load(&admitted));
 return 0;
}
'''
(out/'startup.c').write_text(fixture)
subprocess.run(['cc','-Wall','-Wextra','-Werror','-pthread',
 '-fsanitize=address,undefined',str(out/'startup.c'),'-o',str(out/'startup')],check=True)
subprocess.run([str(out/'startup')],check=True,timeout=30)
# Check integration positions as well as the actual gate implementation.
thread=s[s.index('static void *\nipc_thread('):s.index('int\ninit_ipc_thread(')]
assert thread.index('ipc_wait_for_startup();') < thread.index('accept4(')
main=(root/'usr.sbin/bhyve/bhyverun.c').read_text()
assert main.rindex('vm_resume_cpu(') < main.index('ipc_startup_complete();') < main.index('mevent_dispatch();')
assert main.index('init_ipc_thread(') < main.index('caph_enter()') < main.index('ipc_startup_complete();')
body=main[main.index('int\nmain('):]
assert body.index('bhyve_init_platform_late(') < body.index('Awaiting inbound live migration')
assert body.index('bhyve_prepare_control(ctx);') < body.index('migration_prod_dest_serve_managed(')
assert body.count('bhyve_prepare_control(ctx);')==3
assert 'if (migrate_recv_fd < 0 && !migrate_reconstruct)' in body
# Reconstruction admission (may open /dev/vmmctl) precedes Capsicum entry;
# the reconstructed owner is served only after control preparation.
rebuild=body[body.index('} else if (migrate_reconstruct) {'):]
assert rebuild.index('migration_prod_dest_reconstruct_begin(') < rebuild.index('bhyve_prepare_control(ctx);') < rebuild.index('migration_prod_dest_reconstruct_managed(')
assert body.index('checkpoint_restore_startup_hold();') < body.index('} else if (migrate_reconstruct) {')
assert 'restore_file != NULL || migrate_recv_fd >= 0 || migrate_reconstruct)\n\t\tcheckpoint_restore_startup_hold();' in body

print('PASS: IPC waits for startup publication, survives spurious/early wakeups, and preserves Capsicum ordering')
