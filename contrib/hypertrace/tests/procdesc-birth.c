/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/procdesc.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>

struct proc_stats { struct timeval p_start; };
struct proc {
    pid_t p_pid;
    int p_flag;
    struct proc_stats *p_stats;
};
struct procdesc { struct proc *pd_proc; int pd_flags; uint32_t pd_reaper_exit; };
#define PDF_EXITED 4
#define PROCDESC_LOCK(pd) ((void)(pd))
#define PROCDESC_UNLOCK(pd) ((void)(pd))
struct file { void *f_data; };
struct ucred { int unused; };
struct thread { int unused; };
static int proctree_lock;
#define P_WEXIT 1
#define PROC_LOCK(p) ((void)(p))
#define PROC_UNLOCK(p) ((void)(p))
static void sx_slock(int *lock) { assert(lock == &proctree_lock); }
static void sx_sunlock(int *lock) { assert(lock == &proctree_lock); }
#include "procdesc-birth.inc"

int main(void)
{
    struct proc_stats stats = { .p_start = { 123, 456789 } };
    struct proc process = { .p_pid = 42, .p_stats = &stats };
    struct procdesc pd = { .pd_proc = &process };
    struct file fp = { .f_data = &pd };
    struct pd_birth_identity identity = {0};

    assert(procdesc_ioctl(&fp, PDIOC_GET_BIRTH_IDENTITY,
        &identity, NULL, NULL) == 0);
    assert(identity.pid == 42 && identity.reserved == 0 &&
        identity.start_sec == 123 && identity.start_usec == 456789);
    process.p_flag = P_WEXIT;
    assert(procdesc_ioctl(&fp, PDIOC_GET_BIRTH_IDENTITY,
        &identity, NULL, NULL) == ESRCH && identity.pid == 0);
    process.p_flag = 0;
    process.p_stats = NULL;
    assert(procdesc_ioctl(&fp, PDIOC_GET_BIRTH_IDENTITY,
        &identity, NULL, NULL) == ESRCH);
    pd.pd_proc = NULL;
    assert(procdesc_ioctl(&fp, PDIOC_GET_BIRTH_IDENTITY,
        &identity, NULL, NULL) == ESRCH);
    assert(procdesc_ioctl(&fp, PDIOC_GET_BIRTH_IDENTITY + 1,
        &identity, NULL, NULL) == ENOTTY);
    struct pd_reaper_exit snapshot;
    memset(&snapshot, 0xff, sizeof(snapshot));
    assert(procdesc_ioctl(&fp, PDIOC_GET_REAPER_EXIT,
        &snapshot, NULL, NULL) == 0 && snapshot.flags == 0 && snapshot.reserved == 0);
    pd.pd_flags = PDF_EXITED;
    unsigned flags[] = {PD_REAPER_EXITED, PD_REAPER_EXITED|PD_REAPER_OWNED,
        PD_REAPER_EXITED|PD_REAPER_OWNED|PD_REAPER_EMPTY};
    for (unsigned i=0; i<sizeof(flags)/sizeof(flags[0]); i++) {
        pd.pd_reaper_exit=flags[i];
        assert(procdesc_ioctl(&fp, PDIOC_GET_REAPER_EXIT,
            &snapshot, NULL, NULL) == 0);
        assert(snapshot.flags==flags[i] && snapshot.reserved==0);
    }
    puts("PASS: monotonic birth, exit rejection, and retained exit-reaper query");
}
