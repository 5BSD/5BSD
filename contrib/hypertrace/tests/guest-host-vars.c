/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "defines.inc"

typedef struct { uint64_t dttr_value; const void *dttr_vmhdl; } dtrace_reg_t;
struct pargs { char *ar_args; size_t ar_length; };
struct prison { int pr_id; char pr_name[32]; };
struct ucred { unsigned cr_uid, cr_gid; struct prison *cr_prison; };
struct proc {
    int p_pid;
    struct proc *p_pptr;
    struct pargs *p_args;
    char p_comm[32];
};
struct thread {
    int t_tid, td_errno;
    struct proc *td_proc;
    struct ucred *td_ucred;
};
struct probe { unsigned dtpr_vmid; };
struct htr_args {
    int htr_pid, htr_ppid, htr_tid, htr_errno, htr_jid;
    unsigned htr_uid, htr_gid, htr_curcpu;
    char *htr_execargs, *htr_execname, *htr_jailname;
    unsigned htr_execargs_len;
};
typedef struct { struct probe *dtms_probe; struct htr_args *dtms_htrargs;
    const void *dtms_vmhdl; uintptr_t dtms_scratch_base,
    dtms_scratch_ptr; size_t dtms_scratch_size; }
    dtrace_mstate_t;
typedef struct { int unused; } dtrace_state_t;

static struct proc proc0 = { .p_pid = 0 };
static struct proc *curproc;
static struct thread *curthread;
static unsigned curcpu = 6;
static uint64_t dtrace_node_id = 0xabc;
static int host_strings, guest_strings, host_args_copies, guest_args_copies;
static unsigned faults;
static const void *host_args_address, *guest_args_address;
static const void *expected_guest_vmhdl;
#define CPU_DTRACE_BADADDR 1U
#define CPU_DTRACE_NOSCRATCH 2U
#define CPU_DTRACE_FAULT 4U
#define DTRACE_CPUFLAG_SET(flag) (faults |= (flag))
#define DTRACE_CPUFLAG_ISSET(flag) ((faults & (flag)) != 0)
#define DTRACE_INSCRATCH(mstate, length) \
    ((length) <= (mstate)->dtms_scratch_size - \
    ((mstate)->dtms_scratch_ptr - (mstate)->dtms_scratch_base))
static int dtrace_priv_proc(dtrace_state_t *state) { (void)state; return 1; }
static int dtrace_priv_kernel(dtrace_state_t *state) { (void)state; return 1; }
static const char *hypertrace_getname(const void *vmhdl)
{
    assert(vmhdl == expected_guest_vmhdl);
    return "guest-vm";
}
static uint64_t hypertrace_getns(const void *vmhdl)
{
    assert(vmhdl == expected_guest_vmhdl);
    return 0xdef;
}
static uintptr_t
dtrace_dif_varstr(uintptr_t addr, dtrace_state_t *state,
    dtrace_mstate_t *mstate)
{
    (void)state; (void)mstate; host_strings++;
    return addr;
}
static uintptr_t
dtrace_dif_guest_varstr(uintptr_t addr, dtrace_state_t *state,
    dtrace_mstate_t *mstate)
{
    (void)state; (void)mstate; guest_strings++;
    return addr;
}
static void
dtrace_bcopy(const void *vmhdl, const void *source, void *target,
    size_t length)
{
    if (vmhdl == NULL) {
        assert(source == host_args_address);
        host_args_copies++;
    } else {
        assert(vmhdl == expected_guest_vmhdl &&
            source == guest_args_address);
        guest_args_copies++;
    }
    memcpy(target, source, length);
}
/* HELPER */

static dtrace_reg_t
builtin(dtrace_mstate_t *mstate, dtrace_state_t *state, uint64_t v)
{
    dtrace_reg_t retval = { 0, NULL };
    dtrace_reg_t nullretval = { 0, NULL };
    switch (v) {
#include "arms.inc"
    default:
        assert(0 && "missing DIF variable case");
        return nullretval;
    }
}

int
main(void)
{
    struct prison host_jail = { .pr_id = 51, .pr_name = "host-jail" };
    struct ucred host_cred = { .cr_uid = 10, .cr_gid = 11,
        .cr_prison = &host_jail };
    struct pargs host_args = { .ar_args = "host args", .ar_length = 10 };
    struct proc parent = { .p_pid = 22 };
    struct proc host_proc = { .p_pid = 23, .p_pptr = &parent,
        .p_args = &host_args, .p_comm = "bhyve" };
    struct thread host_thread = { .t_tid = 24, .td_errno = 25,
        .td_proc = &host_proc, .td_ucred = &host_cred };
    struct htr_args guest = { .htr_pid = 100, .htr_ppid = 101,
        .htr_tid = 102, .htr_uid = 103, .htr_gid = 104,
        .htr_errno = 105, .htr_curcpu = 3, .htr_jid = 106,
        .htr_execargs = "guest args", .htr_execargs_len = 11,
        .htr_execname = "guest", .htr_jailname = "guest-jail" };
    struct probe probe = { .dtpr_vmid = 7 };
    dtrace_mstate_t mstate = { .dtms_probe = &probe,
        .dtms_htrargs = &guest, .dtms_vmhdl = &guest };
    char scratch[256];
    dtrace_state_t state = { 0 };
    struct { uint64_t guest, host; unsigned guest_id, host_id; } cases[] = {
        { 100, 23, DIF_VAR_PID, DIF_VAR_HPID },
        { 101, 22, DIF_VAR_PPID, DIF_VAR_HPPID },
        { 102, 24, DIF_VAR_TID, DIF_VAR_HTID },
        { 103, 10, DIF_VAR_UID, DIF_VAR_HUID },
        { 104, 11, DIF_VAR_GID, DIF_VAR_HGID },
        { 105, 25, DIF_VAR_ERRNO, DIF_VAR_HERRNO },
        { 3, 6, DIF_VAR_CPU, DIF_VAR_HCPU },
        { 106, 51, DIF_VAR_JID, DIF_VAR_HJID },
    };

    curproc = &host_proc;
    curthread = &host_thread;
    host_args_address = host_args.ar_args;
    guest_args_address = guest.htr_execargs;
    expected_guest_vmhdl = mstate.dtms_vmhdl;
    mstate.dtms_scratch_base = mstate.dtms_scratch_ptr =
        (uintptr_t)scratch;
    mstate.dtms_scratch_size = sizeof(scratch);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        assert(builtin(&mstate, &state, cases[i].guest_id).dttr_value ==
            cases[i].guest);
        assert(builtin(&mstate, &state, cases[i].host_id).dttr_value ==
            cases[i].host);
    }
    assert(builtin(&mstate, &state, DIF_VAR_EXECNAME).dttr_value ==
        (uintptr_t)guest.htr_execname);
    assert(builtin(&mstate, &state, DIF_VAR_HEXECNAME).dttr_value ==
        (uintptr_t)host_proc.p_comm);
    assert(strcmp((char *)(uintptr_t)builtin(&mstate, &state,
        DIF_VAR_EXECARGS).dttr_value, "guest args") == 0);
    assert(strcmp((char *)(uintptr_t)builtin(&mstate, &state,
        DIF_VAR_HEXECARGS).dttr_value, "host args") == 0);
    assert(builtin(&mstate, &state, DIF_VAR_JAILNAME).dttr_value ==
        (uintptr_t)guest.htr_jailname);
    assert(builtin(&mstate, &state, DIF_VAR_HJAILNAME).dttr_value ==
        (uintptr_t)host_jail.pr_name);
    assert(builtin(&mstate, &state, DIF_VAR_HZONENAME).dttr_value ==
        (uintptr_t)host_jail.pr_name);
    assert(strcmp((char *)(uintptr_t)builtin(&mstate, &state,
        DIF_VAR_VMNAME).dttr_value, "guest-vm") == 0);
    assert(strcmp((char *)(uintptr_t)builtin(&mstate, &state,
        DIF_VAR_HVMNAME).dttr_value, "host") == 0);
    assert(builtin(&mstate, &state, DIF_VAR_HOSTID).dttr_value == 0xdef);
    assert(builtin(&mstate, &state, DIF_VAR_HHOSTID).dttr_value == 0xabc);
    assert(host_strings == 5 && guest_strings == 2 &&
        host_args_copies == 1 && guest_args_copies == 1 && faults == 0);
    probe.dtpr_vmid = 0;
    assert(builtin(&mstate, &state, DIF_VAR_PID).dttr_value == 23);
    assert(builtin(&mstate, &state, DIF_VAR_CPU).dttr_value == 6);
    puts("PASS: production guest and host DIF variable paths");
    return 0;
}
