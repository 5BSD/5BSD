#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Actual production quiesce/rollback/repair against stateful VM models.

Extracts prod_quiesce(), prod_resume() and the pre-COMMIT repair helper from
migration_session.c. Devices keep per-device pause ownership, the CPU barrier
keeps its hold until a resume succeeds, and console input is a flag, so the
repeated (idempotent) resume sequence is checked against real state rather
than call counts. No VM or device is used.
"""
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
s = (root / 'usr.sbin/bhyve/migration_session.c').read_text()
quiesce = s[s.index('static int\nprod_quiesce('):s.index('static int\nprod_resume(')]
resume = s[s.index('static int\nprod_resume('):s.index('static int\nprod_dev_state(')]
a = s.index('static const unsigned migration_repair_delay_ms[]')
repair = s[a:s.index('static const struct migration_source_ops migration_prod_source_ops', a)]
fixture = r'''
#include <sys/param.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
struct vmctx { int unused; };
/* Merged: the capture session keeps the event fence until it is finished. */
struct vm_snapshot_capture { bool active; };
struct migration_prod_source {
    struct vmctx *ctx;
    struct vm_snapshot_capture capture;
    bool quiesced, retirement_started, retired, intent_pending, fresh_stopped;
    uint8_t fresh_record[40];
};
#define NDEV 4
static bool owned[NDEV], hold, input_paused, retiring;
static int device_failures[NDEV], cpu_failures, pause_fail_at = -1;
static int device_resumes, cpu_resumes;
static bool hypertrace_initialized(void) { return false; }
static int vm_migrate_stop_tracing(struct vmctx *c, uint8_t *r) { (void)c; (void)r; return 0; }
static void console_input_pause(void) { input_paused = true; }
static void console_input_resume(void) {
    /* Input reopens only after every device and CPU resumed. */
    for (int i = 0; i < NDEV; i++) assert(!owned[i]);
    assert(!hold); input_paused = false;
}
static int fbsdrun_migration_pause_cpus(struct vmctx *c, bool *runnable) {
    (void)c; assert(!hold); hold = true; *runnable = false; return 0;
}
static int fbsdrun_migration_resume_cpus(struct vmctx *c) {
    (void)c; cpu_resumes++;
    /* CPUs may run only once every device has resumed. */
    for (int i = 0; i < NDEV; i++) assert(!owned[i]);
    if (cpu_failures > 0) { cpu_failures--; return EIO; }
    hold = false; return 0;
}
static bool fbsdrun_cpus_retiring(void) { return retiring; }
static int finish_failures, finishes;
static int vm_snapshot_dev_state_finish(struct vmctx *c, struct vm_snapshot_capture *capture, bool commit) {
    (void)c; assert(!commit);	/* rollback never commits deferred events */
    finishes++;
    /* Merge deferred events while everything is still paused. */
    for (int i = 0; i < NDEV; i++) if (capture->active) assert(owned[i] || !hold);
    if (!capture->active) return 0;
    if (finish_failures > 0) { finish_failures--; return EIO; }
    capture->active = false; return 0;
}
static int vm_resume_devices(void) {
    int error = 0;
    device_resumes++;
    for (int i = 0; i < NDEV; i++) {
        if (!owned[i]) continue;	/* never paused, or already resumed */
        if (device_failures[i] > 0) { device_failures[i]--; if (!error) error = EIO; continue; }
        owned[i] = false;
    }
    return error;
}
static int vm_pause_devices(void) {
    for (int i = 0; i < NDEV; i++) {
        if (i == pause_fail_at) {
            int e = vm_resume_devices();
            return e != 0 ? e : EACCES;
        }
        owned[i] = true;
    }
    return 0;
}
''' + quiesce + resume + repair + r'''
static double now(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}
static void reset(void) {
    memset(owned, 0, sizeof(owned)); memset(device_failures, 0, sizeof(device_failures));
    hold = input_paused = retiring = false; cpu_failures = 0; pause_fail_at = -1;
    finish_failures = finishes = 0;
    device_resumes = cpu_resumes = 0;
}
/* Wedge the source exactly as a failed rollback leaves it. */
static void wedge(struct migration_prod_source *src, int devfail, int cpufail) {
    bool runnable = true;
    reset();
    assert(prod_quiesce(src, &runnable) == 0 && src->quiesced && hold && input_paused);
    for (int i = 0; i < NDEV; i++) assert(owned[i]);
    device_failures[1] = devfail; cpu_failures = cpufail;
    if (devfail || cpufail) assert(prod_resume(src) == EIO);
    assert(src->quiesced && input_paused);
}
int main(void) {
    struct vmctx vm;
    unsigned attempts, checks = 0;
    for (int devfail = 0; devfail <= 3; devfail++)
        for (int cpufail = 0; cpufail <= 3; cpufail++) {
            if (devfail == 0 && cpufail == 0) continue;
            struct migration_prod_source src = { .ctx = &vm };
            wedge(&src, devfail, cpufail);
            /* The failed session rollback already used one attempt; repair
             * retries up to three more with backoff. */
            int remaining_dev = device_failures[1], remaining_cpu = cpu_failures;
            int needed = remaining_dev + remaining_cpu + 1;
            attempts = 0;
            double start = now();
            int error = prod_repair_rollback(&src, &attempts);
            double elapsed = now() - start;
            if (needed <= 3) {
                assert(error == 0 && attempts == (unsigned)needed);
                assert(!src.quiesced && !hold && !input_paused);
                for (int i = 0; i < NDEV; i++) assert(!owned[i]);
                if (needed >= 2) assert(elapsed >= 0.09);
                if (needed == 3) assert(elapsed >= 1.09);
            } else {
                assert(error == EIO && attempts == 3);
                assert(src.quiesced && input_paused);
                assert(hold || owned[1]);
                /* Operator retry later succeeds once the fault clears. */
                device_failures[1] = 0; cpu_failures = 0; attempts = 0;
                assert(prod_repair_rollback(&src, &attempts) == 0 && attempts == 1);
                assert(!src.quiesced && !hold && !input_paused);
            }
            /* Nothing left to repair. */
            attempts = 0;
            assert(prod_repair_rollback(&src, &attempts) == EALREADY && attempts == 0);
            checks++;
        }
    /* Device-pause rollback failure during quiesce leaves a wedged source
     * (devices partly owned, CPUs held); repair completes the rollback. */
    {
        struct migration_prod_source src = { .ctx = &vm };
        bool runnable = true;
        reset(); pause_fail_at = 2; device_failures[0] = 2;
        assert(prod_quiesce(&src, &runnable) == EIO && !runnable && src.quiesced);
        assert(owned[0] && hold && input_paused);
        attempts = 0;
        assert(prod_repair_rollback(&src, &attempts) == 0 && attempts == 1);
        assert(!owned[0] && !hold && !input_paused && !src.quiesced);
        checks++;
    }
    /* A failed capture finish is a failed resume attempt: nothing resumes
     * and the fence stays held until a retry finishes it. */
    {
        struct migration_prod_source src = { .ctx = &vm };
        bool runnable = true;
        reset();
        assert(prod_quiesce(&src, &runnable) == 0);
        src.capture.active = true; finish_failures = 2;
        assert(prod_resume(&src) == EIO && device_resumes == 0 && cpu_resumes == 0);
        assert(src.capture.active && src.quiesced && hold && input_paused);
        for (int i = 0; i < NDEV; i++) assert(owned[i]);
        attempts = 0;
        assert(prod_repair_rollback(&src, &attempts) == 0 && attempts == 2);
        assert(!src.capture.active && !src.quiesced && !hold && !input_paused);
        assert(finishes == 3 && device_resumes == 1 && cpu_resumes == 1);
        checks++;
    }
    /* Never after retirement began, and never without the owned context. */
    for (int refusal = 0; refusal < 5; refusal++) {
        struct migration_prod_source src = { .ctx = &vm };
        wedge(&src, 1, 0);
        if (refusal == 0) src.retirement_started = true;
        if (refusal == 1) src.intent_pending = true;
        if (refusal == 2) src.retired = true;
        if (refusal == 3) src.ctx = NULL;
        if (refusal == 4) retiring = true;
        int before_dev = device_resumes, before_cpu = cpu_resumes;
        attempts = 0;
        assert(prod_repair_rollback(&src, &attempts) == EPERM && attempts == 0);
        assert(device_resumes == before_dev && cpu_resumes == before_cpu);
        assert(src.quiesced && input_paused);
        checks++;
    }
    printf("PASS: %u rollback repair checks; idempotent resume sequence, bounded backoff, retirement refusal\n", checks);
    return 0;
}
'''
(out / 'repair.c').write_text(fixture)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
    '-Wno-unused-function', str(out / 'repair.c'), '-o', str(out / 'repair')], check=True)
subprocess.run([str(out / 'repair')], cwd=out, check=True, timeout=120)
