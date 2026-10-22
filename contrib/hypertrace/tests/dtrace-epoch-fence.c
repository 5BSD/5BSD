/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#define HYPERTRACE_MAX_VMS 1024
typedef uint16_t dtrace_vmid_t;
#define ASSERT(expr) assert(expr)
#define MUTEX_HELD(lock) 1
#define atomic_load_acq_64(ptr) __atomic_load_n((ptr), __ATOMIC_ACQUIRE)
#define atomic_store_rel_64(ptr, value) \
    __atomic_store_n((ptr), (value), __ATOMIC_RELEASE)
static int dtrace_lock;
static unsigned drains;
static void dtrace_sync(void);
#include "dtrace-epoch-fence.inc"

static void
dtrace_sync(void)
{
    /* The drain must happen only after the firing path sees revocation. */
    assert(!dtrace_hypertrace_epoch_active(7, 100));
    drains++;
}

int
main(void)
{
    assert(dtrace_lock == 0);
    assert(dtrace_hypertrace_epoch_publish(0, 100) == EINVAL);
    assert(dtrace_hypertrace_epoch_publish(7, 0) == EINVAL);
    assert(dtrace_hypertrace_epoch_publish(7, 100) == 0);
    assert(dtrace_hypertrace_epoch_publish(7, 101) == EBUSY);
    assert(dtrace_hypertrace_epoch_active(7, 100));
    assert(!dtrace_hypertrace_epoch_active(7, 101));
    assert(dtrace_hypertrace_epoch_revoke(7, 101) == ESTALE);
    assert(drains == 0 && dtrace_hypertrace_epoch_active(7, 100));
    assert(dtrace_hypertrace_epoch_suspend(7, 101) == ESTALE);
    assert(dtrace_hypertrace_epoch_suspend(7, 100) == 0);
    assert(drains == 1 && !dtrace_hypertrace_epoch_active(7, 100) &&
        dtrace_hypertrace_epoch_suspended(7, 100));
    assert(dtrace_hypertrace_epoch_suspend(7, 100) == 0 && drains == 1);
    assert(dtrace_hypertrace_epoch_publish(7, 101) == EBUSY);
    assert(dtrace_hypertrace_epoch_resume(7, 101) == ESTALE);
    assert(dtrace_hypertrace_epoch_resume(7, 100) == 0);
    assert(dtrace_hypertrace_epoch_resume(7, 100) == 0 &&
        dtrace_hypertrace_epoch_active(7, 100) &&
        !dtrace_hypertrace_epoch_suspended(7, 100) && drains == 1);
    assert(dtrace_hypertrace_epoch_revoke(7, 100) == 0);
    assert(drains == 2 && !dtrace_hypertrace_epoch_active(7, 100));
    assert(dtrace_hypertrace_epoch_publish(7, 101) == 0);
    assert(!dtrace_hypertrace_epoch_active(7, 100));
    assert(dtrace_hypertrace_epoch_active(7, 101));
    assert(dtrace_hypertrace_epoch_suspend(7, 101) == 0);
    assert(drains == 3 && dtrace_hypertrace_epoch_suspended(7, 101));
    assert(dtrace_hypertrace_epoch_revoke(7, 101) == 0);
    assert(drains == 4 && !dtrace_hypertrace_epoch_suspended(7, 101));
    assert(dtrace_hypertrace_epoch_publish(7, 102) == 0);
    assert(dtrace_hypertrace_epoch_resume(7, 101) == ESTALE &&
        dtrace_hypertrace_epoch_active(7, 102));
    puts("PASS: DTrace epoch publish/suspend/resume/revoke and stale-ECB fence");
}
