#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the actual IPC dispatcher after irreversible source retirement."""
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/bhyve/ipc.c').read_text()
start = source.index('static struct ipc_thread_ctx {')
end = source.index('/*\n * Listen for commands', start)
fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "ipc.h"
SET_DECLARE(ipc_cmd_set, struct ipc_command);
static int ipc_exit_status = -1;
#define IPC_COMMAND_FOREACH(pvar, set) SET_FOREACH(pvar, set)
'''
fixture += source[start:source.index('/* Bind the endpoint before Capsicum', start)]
fixture += source[source.index('void\nipc_quarantine_vm(', start):end]
fixture += r'''
static int calls;
static nvlist_t *mutate(struct vmctx *ctx, const nvlist_t *nvl) {
 assert(ctx == (struct vmctx *)1 && nvl != NULL);
 calls++; return nvlist_create(0);
}
IPC_COMMAND(mutate, mutate);
static nvlist_t *recover(struct vmctx *ctx, const nvlist_t *nvl) {
 assert(ctx == NULL && nvl != NULL); return nvlist_create(0);
}
IPC_COMMAND(migrate_recover, recover);
static int repairs;
static nvlist_t *repair(struct vmctx *ctx, const nvlist_t *nvl) {
 assert(ctx == NULL && nvl != NULL); repairs++; return nvlist_create(0);
}
IPC_COMMAND(migrate_repair, repair);
int main(void) {
 nvlist_t *request = nvlist_create(0), *reply;
 thr_ctx.vmctx = (struct vmctx *)1;
 /* Reversible wedge after a failed pre-COMMIT rollback: only status,
  * recovery and repair are admitted, without the stale context alias. */
 assert(ipc_unwedge_vm() == EPERM);
 ipc_wedge_vm();
 assert(thr_ctx.quarantined && thr_ctx.wedged && thr_ctx.vmctx == NULL);
 reply = handle_message((struct vmctx *)1, "mutate", request);
 assert(reply && nvlist_get_number(reply, "error_code") == ECANCELED && calls == 0);
 assert(strstr(nvlist_get_string(reply, "error"), "migrate_repair") != NULL);
 nvlist_destroy(reply);
 reply = handle_message((struct vmctx *)1, "migrate_repair", request);
 assert(reply && repairs == 1); nvlist_destroy(reply);
 /* A successful repair restores ordinary admission and the alias. */
 assert(ipc_unwedge_vm() == 0 && !thr_ctx.quarantined && thr_ctx.vmctx == (struct vmctx *)1);
 assert(ipc_unwedge_vm() == EPERM);
 /* Repair is not an ordinary command outside a wedge (no handler ctx). */
 /* Retirement upgrades a wedge irreversibly; a later wedge or unwedge
  * cannot weaken it. */
 ipc_wedge_vm(); ipc_quarantine_vm();
 assert(thr_ctx.quarantined && !thr_ctx.wedged && thr_ctx.vmctx == NULL);
 assert(ipc_unwedge_vm() == EPERM);
 ipc_wedge_vm();
 assert(!thr_ctx.wedged && thr_ctx.quarantined);
 reply = handle_message((struct vmctx *)1, "migrate_repair", request);
 assert(reply && nvlist_get_number(reply, "error_code") == ECANCELED && repairs == 1);
 nvlist_destroy(reply);
 thr_ctx.quarantined = false; thr_ctx.vmctx = (struct vmctx *)1;
 reply = handle_message(thr_ctx.vmctx, "mutate", request);
 assert(reply && calls == 1); nvlist_destroy(reply);
 ipc_quarantine_vm();
 assert(thr_ctx.quarantined && thr_ctx.vmctx == NULL);
 ipc_quarantine_vm(); /* Repeated retirement must not restore the alias. */
 const char *blocked[] = {"mutate", "migrate", "snapshot", "unknown"};
 for (unsigned i = 0; i < sizeof(blocked) / sizeof(blocked[0]); i++) {
  /* Even a stale caller argument cannot bypass quarantine. */
  reply = handle_message((struct vmctx *)1, blocked[i], request);
  assert(reply && nvlist_get_number(reply, "error_code") == ECANCELED);
  nvlist_destroy(reply);
 }
 reply = handle_message((struct vmctx *)1, "get_vm_pid", request);
 assert(reply && nvlist_get_number(reply, "pid") == (uint64_t)getpid());
 assert(calls == 1);
 nvlist_destroy(reply);
 reply = handle_message((struct vmctx *)1, "migrate_recover", request);
 assert(reply && !nvlist_exists_string(reply, "error"));
 nvlist_destroy(reply); nvlist_destroy(request);
 return 0;
}
'''
(out / 'quarantine.c').write_text(fixture)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
    '-I' + str(root / 'usr.sbin/bhyve'), str(out / 'quarantine.c'), '-lnv',
    '-o', str(out / 'quarantine')], check=True)
subprocess.run([str(out / 'quarantine')], cwd=out, check=True, timeout=30)
print('PASS: reversible rollback wedge admits only repair/status/recovery; irreversible IPC quarantine blocks stale-context commands and preserves PID query')
