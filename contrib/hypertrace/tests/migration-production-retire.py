#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Fault injection for production retirement; never opens a VM."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/bhyve/migration_session.c').read_text()
resume = source[source.index('static int\nprod_resume('):source.index('static int\nprod_dev_state(')]
quiesce = source[source.index('static int\nprod_quiesce('):source.index('static int\nprod_resume(')]
retire = source[source.index('/* The IPC controller owns this context'):source.index('static void\nprod_defunct(')]
fixture = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
static int quarantines;
static void ipc_quarantine_vm(void) { quarantines++; }
#include <stdbool.h>
#include <errno.h>
#include <stdint.h>
#include "hypertrace_session.h"
struct vmctx { int unused; };
/* Merged: capture session, stream descriptor and the active-vsock relay. */
struct vm_snapshot_capture { int active; };
struct migration_vsock_relay_endpoint { int fd, type; };
struct migration_prod_source {
    struct vmctx *ctx;
    int stream_fd;
    struct migration_vsock_relay_endpoint vsock_endpoints[4];
    uint32_t vsock_endpoint_count;
    bool vsock_relay_prepared;
    struct vm_snapshot_capture capture;
    bool quiesced, retirement_started, retired;
    bool fresh_stopped;
    uint8_t fresh_record[40];
};
static int stopped, destroyed, resumed, stop_error, destroy_error;
static int transport_error, transport_stops;
static int joins, join_error, closes;
#ifdef BHYVE_GDB
/* The debug server is permanently fenced before vCPU retirement and kernel
 * destruction begin, so it can never reuse the retiring vmctx. */
static int debugger_retires, retire_begins;
static void gdb_migration_retire(void) { debugger_retires++; }
static void fbsdrun_retire_cpus_begin(void) {
    retire_begins++; assert(debugger_retires == retire_begins);
}
#else
static void fbsdrun_retire_cpus_begin(void) {}
#endif
static int fbsdrun_retire_cpus_wait(void) { joins++; return join_error; }
static void vm_close(struct vmctx *ctx) { assert(ctx != NULL); closes++; }
static int stage, trace_error, cpu_error, pause_error;
static int device_resume_error, cpu_resume_error;
static bool tracing, input_paused, cpu_pause_wedged;
static void console_input_pause(void) { input_paused=true; }
static void console_input_resume(void) { input_paused=false; }
static int identity_destroys, witness_error;
static bool hypertrace_initialized(void) { return tracing; }
static int vm_migrate_stop_tracing(void *ctx, uint8_t *record) {
    (void)ctx; assert(++stage == 1); record[0] = 42; return trace_error;
}
static int fbsdrun_migration_pause_cpus(void *ctx, bool *runnable) {
    (void)ctx; assert(input_paused); assert(++stage == (tracing ? 2 : 1));
    *runnable=cpu_error!=0 && !cpu_pause_wedged; return cpu_error;
}
static int vm_pause_devices(void) {
    assert(input_paused); assert(++stage == (tracing ? 3 : 2)); return pause_error;
}
static int pci_vtdtr_checkpoint_stop(void) {
    assert(!destroyed && quarantines > 0); stopped++; return stop_error;
}
static int hypertrace_retire_transport(void) {
    assert(stopped > 0 && !destroyed); transport_stops++; return transport_error;
}
static int vm_destroy_request_checked(void *ctx) {
    (void)ctx; assert(stopped == 1); destroyed++;
    errno = destroy_error; return destroy_error ? -1 : 0;
}
static int vm_destroy_identity_request_checked(void *ctx, uint16_t vmid, uint64_t epoch) {
    assert(vmid == 7 && epoch == 9); identity_destroys++;
    return vm_destroy_request_checked(ctx);
}
static int hypertrace_session_retired(uint16_t vmid, uint64_t epoch) {
    assert(vmid == 7 && epoch == 9); errno = witness_error;
    return witness_error ? -1 : 0;
}
static int finishes, finish_error, warnings, finish_commit = -1;
static int vm_snapshot_dev_state_finish(struct vmctx *ctx, struct vm_snapshot_capture *capture, bool commit) {
    (void)ctx; assert(capture != NULL);
    /* Retirement finishes with commit after the transport stops and before
     * kernel destruction; rollback finishes without commit before anything
     * resumes. */
    if (commit) assert(stopped > 0 && destroyed == 0 && transport_stops > 0);
    else assert(resumed == 0);
    finishes++; finish_commit = commit; return finish_error;
}
static void warnx(const char *fmt, ...) { (void)fmt; warnings++; }
static int owner_prepares, owner_cancels, owner_activates;
static int prepare_error, cancel_error, activate_error;
static int migration_vsock_owner_prepare(int fd, struct migration_vsock_relay_endpoint *e, uint32_t count) {
    assert(fd == 5 && e != NULL && count == 2 && e[1].fd == 9); owner_prepares++; return prepare_error;
}
static int migration_vsock_owner_cancel(void) { owner_cancels++; return cancel_error; }
static int migration_vsock_owner_activate(void) { owner_activates++; return activate_error; }
static int vm_resume_devices(void) { resumed++; return device_resume_error; }
static int fbsdrun_migration_resume_cpus(void *ctx) {
 (void)ctx; resumed++; return cpu_resume_error;
}
'''
fixture += quiesce + resume + retire + r'''
int main(void) {
    for (int mode = 0; mode < 5; mode++) {
        struct migration_prod_source src = {0};
        bool runnable = false;
        tracing = mode != 4; stage = resumed = 0; input_paused=false;
        trace_error = mode == 1 ? EIO : 0;
        cpu_error = mode == 2 ? EBUSY : 0;
        pause_error = mode == 3 ? EACCES : 0;
        int expected = trace_error ? trace_error : cpu_error ? cpu_error : pause_error;
        assert(prod_quiesce(&src, &runnable) == expected);
        assert(src.fresh_stopped == (tracing && !trace_error));
        assert(src.quiesced == (expected == 0));
        assert(input_paused == (expected == 0));
        assert(runnable == (expected != 0));
        assert(stage == (trace_error ? 1 : cpu_error ? 2 : tracing ? 3 : 2));
        assert(resumed == (pause_error ? 2 : 0));
    }
    for (int failure=0; failure<2; failure++) {
        struct migration_prod_source src={0}; bool runnable=true;
        tracing=true; stage=resumed=0; trace_error=cpu_error=0;
        pause_error=EACCES;
        device_resume_error=failure==0?EIO:0;
        cpu_resume_error=failure==1?EBUSY:0;
        assert(prod_quiesce(&src,&runnable)==(failure==0?EIO:EBUSY));
        assert(!runnable && src.quiesced && src.fresh_stopped && input_paused);
        assert(resumed==(failure==0?1:2));
    }
    {
        struct migration_prod_source src={0}; bool runnable=true;
        tracing=true; stage=resumed=0; trace_error=0; cpu_error=EIO;
        cpu_pause_wedged=true; input_paused=false;
        assert(prod_quiesce(&src,&runnable)==EIO);
        assert(!runnable && src.quiesced && input_paused && resumed==0);
        cpu_pause_wedged=false; cpu_error=0;
    }
    device_resume_error=cpu_resume_error=0;
    for (int mode = 0; mode < 4; mode++) {
        struct migration_prod_source src = { .quiesced = mode != 3 };
        stopped = destroyed = resumed = 0;
        stop_error = mode == 1 ? EIO : 0;
        destroy_error = mode == 2 ? EACCES : 0;
        int expected = mode == 3 ? EBUSY : stop_error ? stop_error : destroy_error;
        assert(prod_retire(&src) == expected);
        assert(src.retirement_started);
        assert(src.retired == (mode == 0));
        assert(stopped == (mode != 3));
        assert(destroyed == (mode == 0 || mode == 2));
        assert(prod_resume(&src) == ECANCELED);
        assert(resumed == 0);
    }
    for (int mode = 0; mode < 4; mode++) {
        struct migration_prod_source fresh = { .quiesced = true,
            .fresh_stopped = true, .ctx = (void *)1 };
        struct hypertrace_session_record record = { .vmid = 7, .epoch = 9,
            .stop_token = 11, .features = HYPERTRACE_SESSION_FEATURES };
        assert(hypertrace_session_record_encode(fresh.fresh_record, 40, &record) == 0);
        if (mode == 3) fresh.fresh_record[0] ^= 1;
        stopped = destroyed = identity_destroys = 0; stop_error = 0;
        destroy_error = mode == 1 ? ESTALE : 0;
        witness_error = mode == 2 ? EBUSY : 0;
        int error = prod_retire(&fresh);
        if (mode == 3) assert(error != 0 && identity_destroys == 0 && stopped == 0);
        else assert(error == (mode == 1 ? ESTALE : witness_error) && identity_destroys == 1);
        assert(fresh.retired == (mode == 0));
        assert(fresh.ctx == (mode == 0 || mode == 2 ? NULL : (void *)1));
        assert(prod_resume(&fresh) == ECANCELED);
    }
    {
        struct migration_prod_source src = {.quiesced=true};
        stopped=destroyed=transport_stops=0; stop_error=0; transport_error=EBUSY;
        assert(prod_retire(&src)==EBUSY);
        assert(stopped==1 && transport_stops==1 && destroyed==0);
        assert(src.retirement_started && !src.retired);
        assert(prod_resume(&src)==ECANCELED);
        transport_error=0;
    }
    {
        struct migration_prod_source src = { .quiesced=true, .ctx=(void *)1 };
        stopped=destroyed=0; destroy_error=0; join_error=EBUSY;
        int before=closes;
        assert(prod_retire(&src)==EBUSY && src.ctx==NULL && !src.retired);
        assert(destroyed==1 && closes==before);
        assert(prod_retire_drain()==EBUSY && closes==before);
        join_error=0;
        assert(prod_retire_drain()==0 && closes==before+1 && destroyed==1);
        assert(prod_retire_drain()==0 && closes==before+1);
    }
    struct migration_prod_source src = { .quiesced = true };
    resumed = finishes = 0;
    finish_error = EIO;
    assert(prod_resume(&src) == EIO && resumed == 0 && src.quiesced);
    assert(finishes == 1 && finish_commit == 0);
    finish_error = 0;
    assert(prod_resume(&src) == 0);
    assert(!src.quiesced && resumed == 2 && finishes == 2 && finish_commit == 0);
    /* Retirement: a failed event-fence finish only warns; destruction goes on. */
    for (int failing = 0; failing < 2; failing++) {
        struct migration_prod_source r = { .quiesced = true, .ctx = (void *)1 };
        stopped = destroyed = transport_stops = finishes = warnings = 0;
        stop_error = destroy_error = transport_error = join_error = 0;
        finish_error = failing ? EIO : 0;
        assert(prod_retire(&r) == 0 && r.retired && destroyed == 1);
        assert(finishes == 1 && finish_commit == 1 && warnings == failing);
    }
    finish_error = 0;
    /* A refused or failed stop never reaches the commit finish. */
    {
        struct migration_prod_source r = { .quiesced = true };
        finishes = 0; stopped = destroyed = 0; stop_error = EIO;
        assert(prod_retire(&r) == EIO && finishes == 0);
        stop_error = 0;
        struct migration_prod_source q = { .quiesced = false };
        assert(prod_retire(&q) == EBUSY && finishes == 0);
    }
    /* Active-vsock relay: no endpoints is a no-op throughout. */
    {
        struct migration_prod_source v = { .stream_fd = 5 };
        assert(prod_prepare_vsock_relay(&v) == 0 && !v.vsock_relay_prepared);
        assert(prod_cancel_vsock_relay(&v) == 0 && prod_activate_vsock_relay(&v) == 0);
        assert(owner_prepares == 0 && owner_cancels == 0 && owner_activates == 0);
    }
    for (int mode = 0; mode < 5; mode++) {
        struct migration_prod_source v = { .stream_fd = 5, .vsock_endpoint_count = 2 };
        v.vsock_endpoints[1].fd = 9;
        owner_prepares = owner_cancels = owner_activates = 0;
        prepare_error = mode == 1 ? EIO : 0;
        cancel_error = mode == 3 ? EBUSY : 0;
        activate_error = mode == 4 ? EPIPE : 0;
        /* Prepared is recorded before the owner answers, so cancel runs
         * even after a prepare whose acknowledgement was lost. */
        assert(prod_prepare_vsock_relay(&v) == prepare_error);
        assert(v.vsock_relay_prepared && owner_prepares == 1);
        if (mode == 1 || mode == 3) {
            assert(prod_cancel_vsock_relay(&v) == cancel_error);
            assert(owner_cancels == 1 && v.vsock_relay_prepared == (mode == 3));
            if (mode == 3) {
                cancel_error = 0;
                assert(prod_cancel_vsock_relay(&v) == 0 && owner_cancels == 2);
            }
            assert(!v.vsock_relay_prepared);
            assert(prod_activate_vsock_relay(&v) == 0 && owner_activates == 0);
            continue;
        }
        assert(prod_activate_vsock_relay(&v) == activate_error && owner_activates == 1);
        assert(v.vsock_relay_prepared == (mode == 4));
        if (mode != 4) {
            assert(prod_activate_vsock_relay(&v) == 0 && owner_activates == 1);
            assert(prod_cancel_vsock_relay(&v) == 0 && owner_cancels == 0);
        }
    }
#ifdef BHYVE_GDB
    assert(debugger_retires > 0 && debugger_retires == retire_begins);
    printf("debugger fence retired before %d destruction attempts\n", retire_begins);
#endif
    return 0;
}
'''
(out / 'retire.c').write_text(fixture)
for variant, defines in (('retire', []), ('retire-gdb', ['-DBHYVE_GDB'])):
    subprocess.run(['cc', '-Wall', '-Wextra', '-Werror',
        '-fsanitize=address,undefined'] + defines + ['-I' + str(root / 'sys'),
        '-I' + str(root / 'usr.sbin/bhyve'), str(out / 'retire.c'),
        '-o', str(out / variant)], check=True)
    subprocess.run([str(out / variant)], check=True, timeout=30)
