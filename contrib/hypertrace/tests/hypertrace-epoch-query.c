/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#define HYPERTRACE_MAX_VMS 1024
#define HYPERTRACE_IOC_EPOCH_QUERY 0x484501UL
#define HYPERTRACE_IOC_EPOCH_SUSPEND 0x484502UL
#define HYPERTRACE_IOC_EPOCH_RESUME 0x484503UL
#define HYPERTRACE_IOC_EPOCH_GATE_QUERY 0x484504UL
#define HYPERTRACE_IOC_HANDLE_QUERY 0x484505UL
typedef struct { uint64_t generation[2], serial; uint32_t retired, reserved; } dtrace_handle_lifetime_t;
#define PRIV_DTRACE_KERNEL 90
typedef char *caddr_t;
struct cdev { int unused; };
struct thread { int jailed; int privileged; };
struct hypertrace_epoch_query {
    uint64_t epoch;
    uint16_t vmid;
    uint16_t reserved[3];
    uint32_t live;
    uint32_t reserved2;
};
struct hypertrace_epoch_gate {
    uint64_t epoch;
    uint16_t vmid;
    uint16_t reserved[3];
    uint32_t suspended;
    uint32_t reserved2;
    uint8_t token[16];
    uint8_t previous_token[16];
};
static uint64_t hypertrace_vm_epochs[HYPERTRACE_MAX_VMS];
static uint8_t hypertrace_vm_gate_tokens[HYPERTRACE_MAX_VMS][16];
static uint64_t gated_epoch;
static int lock_depth, locks;
typedef struct { uint64_t htpb_epoch; } hypertrace_probe_t;
static struct {
    size_t nprobes[HYPERTRACE_MAX_VMS];
    hypertrace_probe_t **probes[HYPERTRACE_MAX_VMS];
} map_storage, *hypertrace_map __attribute__((unused)) = &map_storage;
static uint64_t hypertrace_priv_epoch_byid(uint16_t vmid) {
    assert(lock_depth == 1);
    return (hypertrace_vm_epochs[vmid]);
}
static int privcheck(struct thread *td) { return td->jailed ? EPERM : 0; }
static int priv_check(struct thread *td, int privilege) {
    assert(privilege == PRIV_DTRACE_KERNEL);
    return td->privileged ? 0 : EPERM;
}
static void dtrace_hypertrace_config_lock(void) {
    assert(lock_depth++ == 0); locks++;
}
static void dtrace_hypertrace_config_unlock(void) {
    assert(--lock_depth == 0);
}
static int dtrace_handle_query(dtrace_handle_lifetime_t *q) {
    assert(lock_depth == 1);
    if (q->serial != 3) return ESTALE;
    q->retired = 1; return 0;
}
static int dtrace_hypertrace_epoch_suspended(uint16_t vmid, uint64_t epoch) {
    assert(lock_depth == 1 && vmid == 7);
    return (gated_epoch == epoch);
}
static int dtrace_hypertrace_epoch_suspend(uint16_t vmid, uint64_t epoch) {
    assert(lock_depth == 1 && vmid == 7 && epoch == 42);
    gated_epoch = epoch;
    return (0);
}
static int dtrace_hypertrace_epoch_resume(uint16_t vmid, uint64_t epoch) {
    assert(lock_depth == 1 && vmid == 7 && epoch == 42);
    gated_epoch = 0;
    return (0);
}
#include "hypertrace-epoch-query.inc"

int
main(void)
{
    {
        struct thread admin = { .privileged = 1 }, denied = {0}, jailed = { .jailed = 1, .privileged = 1 };
        dtrace_handle_lifetime_t q = { .serial = 3 };
        assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_HANDLE_QUERY, (caddr_t)&q, 0, &denied) == EPERM);
        assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_HANDLE_QUERY, (caddr_t)&q, 0, &jailed) == EPERM);
        assert(q.retired == 0);
        assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_HANDLE_QUERY, (caddr_t)&q, 0, &admin) == 0 && q.retired == 1);
        q.serial = 4; q.retired = 0;
        assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_HANDLE_QUERY, (caddr_t)&q, 0, &admin) == ESTALE && q.retired == 0);
        locks = 0;
    }

    struct thread td = { .privileged = 1 };
    struct hypertrace_epoch_query query = { .epoch = 42, .vmid = 7 };
    assert(hypertrace_ioctl(NULL, 0, (caddr_t)&query, 0, &td) == ENOTTY);
    td.jailed = 1;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_QUERY,
        (caddr_t)&query, 0, &td) == EPERM);
    td.jailed = 0; td.privileged = 0;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_QUERY,
        (caddr_t)&query, 0, &td) == EPERM);
    td.privileged = 1;
    query.reserved[1] = 1;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_QUERY,
        (caddr_t)&query, 0, &td) == EINVAL);
    query.reserved[1] = 0;
    query.reserved2 = 1;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_QUERY,
        (caddr_t)&query, 0, &td) == EINVAL);
    query.reserved2 = 0;
    hypertrace_vm_epochs[7] = 42;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_QUERY,
        (caddr_t)&query, 0, &td) == 0 && query.live == 1);
    struct hypertrace_epoch_gate gate = { .vmid = 7, .epoch = 42,
        .token = { 0xa1 } };
    struct hypertrace_epoch_gate status = { .vmid = 7, .epoch = 42 };
    gate.token[0] = 0;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_SUSPEND,
        (caddr_t)&gate, 0, &td) == EINVAL && gated_epoch == 0);
    gate.token[0] = 0xa1;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_SUSPEND,
        (caddr_t)&gate, 0, &td) == 0 && gated_epoch == 42);
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_SUSPEND,
        (caddr_t)&gate, 0, &td) == 0);
    gate.token[0] = 0xb2;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_SUSPEND,
        (caddr_t)&gate, 0, &td) == EBUSY);
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_RESUME,
        (caddr_t)&gate, 0, &td) == ESTALE && gated_epoch == 42);
    gate.token[0] = 0xa1;
    dtrace_hypertrace_config_lock();
    assert(hypertrace_priv_check_epoch(7, 42) == EBUSY);
    dtrace_hypertrace_config_unlock();
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_GATE_QUERY,
        (caddr_t)&status, 0, &td) == 0 && status.suspended == 1 &&
        status.token[0] == 0xa1);
    status.suspended = 0;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_GATE_QUERY,
        (caddr_t)&status, 0, &td) == EINVAL);
    status.suspended = 1;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_RESUME,
        (caddr_t)&status, 0, &td) == EINVAL && gated_epoch == 42);
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_QUERY,
        (caddr_t)&query, 0, &td) == EINVAL);
    query.live = 0;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_QUERY,
        (caddr_t)&query, 0, &td) == 0 && query.live == 1);
    gate.reserved2 = 1;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_RESUME,
        (caddr_t)&gate, 0, &td) == EINVAL && gated_epoch == 42);
    gate.reserved2 = 0;
    gate.epoch = 43;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_RESUME,
        (caddr_t)&gate, 0, &td) == ESTALE && gated_epoch == 42);
    gate.epoch = 42;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_RESUME,
        (caddr_t)&gate, 0, &td) == 0 && gated_epoch == 0);
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_RESUME,
        (caddr_t)&gate, 0, &td) == 0);
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_SUSPEND,
        (caddr_t)&gate, 0, &td) == EBUSY && gated_epoch == 0);
    dtrace_hypertrace_config_lock();
    assert(hypertrace_priv_check_epoch(7, 42) == 0);
    assert(hypertrace_priv_check_epoch(7, 43) == ESTALE);
    dtrace_hypertrace_config_unlock();
    /* A probe of another lifetime under this VM ID is no longer a runtime
     * refusal: the kernel now treats "probes carry their creation epoch" as
     * an invariant (ASSERT under INVARIANTS; VM IDs are reused only after
     * the map namespace empties).  A matching probe passes. */
    hypertrace_probe_t current = { .htpb_epoch = 42 };
    hypertrace_probe_t *probes[] = { &current };
    map_storage.nprobes[7] = 1;
    map_storage.probes[7] = probes;
    dtrace_hypertrace_config_lock();
    assert(hypertrace_priv_check_epoch(7, 42) == 0);
    dtrace_hypertrace_config_unlock();
    map_storage.nprobes[7] = 0;
    memset(&status, 0, sizeof(status));
    status.vmid = 7;
    status.epoch = 42;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_GATE_QUERY,
        (caddr_t)&status, 0, &td) == 0 && status.suspended == 0 &&
        status.token[0] == 0xa1);
    gate.token[0] = 0xb2;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_SUSPEND,
        (caddr_t)&gate, 0, &td) == ESTALE && gated_epoch == 0);
    gate.previous_token[0] = 0xa1;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_SUSPEND,
        (caddr_t)&gate, 0, &td) == 0 && gated_epoch == 42);
    gate.token[0] = 0xa1;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_RESUME,
        (caddr_t)&gate, 0, &td) == EINVAL && gated_epoch == 42);
    gate.previous_token[0] = 0;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_RESUME,
        (caddr_t)&gate, 0, &td) == ESTALE && gated_epoch == 42);
    gate.token[0] = 0xb2;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_RESUME,
        (caddr_t)&gate, 0, &td) == 0 && gated_epoch == 0);
    gate.token[0] = 0xa1;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_SUSPEND,
        (caddr_t)&gate, 0, &td) == ESTALE && gated_epoch == 0);
    td.privileged = 0;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_SUSPEND,
        (caddr_t)&gate, 0, &td) == EPERM && gated_epoch == 0);
    td.privileged = 1;
    query.live = 0; query.epoch = 43;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_QUERY,
        (caddr_t)&query, 0, &td) == 0 && query.live == 0);
    query.epoch = 42;
    hypertrace_vm_epochs[7] = 0;
    assert(hypertrace_ioctl(NULL, HYPERTRACE_IOC_EPOCH_QUERY,
        (caddr_t)&query, 0, &td) == 0 && query.live == 0);
    assert(lock_depth == 0 && locks > 3);
    puts("PASS: privileged exact-epoch query and reversible DTrace gate");
}
