/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#define DTRACEIOC_AUGMENT 1
#define DTRACE_ACTIVITY_ACTIVE 1
#define DTRACE_IOCTL_PRINTF(...) ((void)0)
#define B_TRUE 1
typedef int dof_hdr_t;
typedef int dtrace_enabling_t;
typedef int dtrace_vstate_t;
typedef struct { int dts_activity; dtrace_vstate_t dts_vstate; } state_t;
typedef struct { void *td_ucred; } thread_t;
typedef struct { void *dof; int n_matched; uint16_t vmid; uint64_t epoch; } dtrace_enable_io_t;
static int cpu_lock = 1, dtrace_lock = 2, depth;
static uint16_t dtrace_curvmid;
static int token_error, slurp_error, match_error, retain_error, freed, destroyed;
static dof_hdr_t dof;
static dtrace_enabling_t enabling;
static void mutex_enter(int *lock) { assert(*lock == ++depth); }
static void mutex_exit(int *lock) { assert(*lock == depth--); }
static dof_hdr_t *dtrace_dof_copyin(uintptr_t p, int *error) { assert(p && error); return &dof; }
static void dtrace_dof_destroy(dof_hdr_t *p) { assert(p == &dof && depth == 0); freed++; }
static int check_epoch(uint16_t id, uint64_t epoch) {
    assert(depth == 2 && id == 7 && epoch == 42); return token_error;
}
static int (*hypertrace_check_epoch)(uint16_t, uint64_t) = check_epoch;
static int dtrace_dof_slurp(dof_hdr_t *p, dtrace_vstate_t *v, void *cred,
    dtrace_enabling_t **out, int a, int b, int c) {
    assert(p == &dof && v && cred == NULL && a == 0 && b == 0 && c == 1);
    assert(depth == 2 && dtrace_curvmid == 7);
    if (slurp_error) return slurp_error;
    *out = &enabling; return 0;
}
static int dtrace_enabling_match(dtrace_enabling_t *e, int *count) {
    assert(e == &enabling && depth == 2 && dtrace_curvmid == 7); *count = 1; return match_error;
}
static int dtrace_enabling_retain(dtrace_enabling_t *e) {
    assert(e == &enabling && depth == 2); return retain_error;
}
static void dtrace_enabling_destroy(dtrace_enabling_t *e) {
    assert(e == &enabling && depth == 2); destroyed++;
}
#include "augment.inc"
int main(void) {
    dtrace_enable_io_t request = { .dof = &dof, .vmid = 7, .epoch = 42 };
    state_t state = { .dts_activity = DTRACE_ACTIVITY_ACTIVE }; thread_t thread = {0};
    for (int test = 0; test < 6; test++) {
        token_error = slurp_error = match_error = retain_error = freed = destroyed = 0;
        state.dts_activity = test == 1 ? 0 : DTRACE_ACTIVITY_ACTIVE;
        int expected = 0;
        if (test == 0) expected = token_error = ESTALE;
        if (test == 1) expected = ESHUTDOWN;
        if (test == 2) expected = slurp_error = EINVAL;
        if (test == 3) expected = match_error = ENOMEM;
        if (test == 4) expected = retain_error = ENOSPC;
        assert(dispatch(&request, &state, &thread) == expected);
        assert(dtrace_curvmid == 0 && depth == 0 && freed == 1);
        assert(destroyed == (test == 3 || test == 4));
    }
    puts("PASS: actual augment namespace restoration, stale-token rejection and failure ownership");
}
