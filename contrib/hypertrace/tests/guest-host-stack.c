/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "defines.inc"

typedef uintptr_t pc_t;
typedef struct { uint64_t dttr_value; const void *dttr_vmhdl; } dtrace_reg_t;
struct trapframe { unsigned id; };
struct thread {
    struct trapframe *t_dtrace_trapframe, *td_frame;
};
struct probe { unsigned dtpr_vmid, dtpr_aframes; };
struct hypertrace_args { uint64_t htr_stackdepth, htr_caller; };
typedef struct {
    struct probe *dtms_probe;
    uint64_t dtms_arg[10], dtms_stackdepth, dtms_ustackdepth;
    uint64_t dtms_caller, dtms_ucaller;
    unsigned dtms_present;
    const void *dtms_vmhdl;
    struct hypertrace_args *dtms_htrargs;
} dtrace_mstate_t;
typedef struct { int unused; } dtrace_state_t;
static struct thread *curthread;
static unsigned curcpu, flags, pcstacks;
static struct { uintptr_t cpuc_dtrace_illval; } cpu_core[1];
#define DTRACE_MSTATE_STACKDEPTH 1U
#define DTRACE_MSTATE_USTACKDEPTH 2U
#define DTRACE_MSTATE_CALLER 4U
#define DTRACE_MSTATE_UCALLER 8U
#define CPU_DTRACE_BADADDR 16U
#define CPU_DTRACE_NOFAULT 32U
#define CPU_DTRACE_ILLOP 64U
#define DTRACE_CPUFLAG_SET(flag) (flags |= (flag))
#define DTRACE_CPUFLAG_CLEAR(flag) (flags &= ~(flag))
#define DTRACE_ANCHORED(probe) 0
#define CPU 0
#define CPU_ON_INTR(cpu) 0
static int dtrace_priv_proc(dtrace_state_t *state) { (void)state; return 1; }
static int dtrace_priv_kernel(dtrace_state_t *state) { (void)state; return 1; }
static uint64_t dtrace_getreg(struct trapframe *frame, unsigned ndx)
{
    return frame->id * 10 + ndx;
}
static int dtrace_guest_reg_name(unsigned ndx)
{
    return ndx <= 32 ? (int)ndx : -1;
}
static int guest_getreg(const void *vmhdl, int reg, uint64_t *value)
{
    assert(vmhdl != NULL);
    if (reg == 3)
        return -1;
    *value = 0x1000 + reg;
    return 0;
}
static int (*hypertrace_getreg)(const void *, int, uint64_t *) = guest_getreg;
static int dtrace_guest_ureg(dtrace_mstate_t *mstate, unsigned ndx,
    uint64_t *value)
{
    assert(mstate->dtms_vmhdl != NULL);
    *value = 0x2000 + ndx;
    return 1;
}
static uint64_t dtrace_guest_ucaller(dtrace_mstate_t *mstate)
{
    assert(mstate->dtms_vmhdl != NULL);
    return 0xface;
}
static uint64_t dtrace_guest_ustackdepth(dtrace_mstate_t *mstate)
{
    assert(mstate->dtms_vmhdl != NULL);
    return 0x55;
}
static uint64_t dtrace_getstackdepth(int aframes)
{
    (void)aframes;
    return 7;
}
static uint64_t dtrace_getustackdepth(void) { return 8; }
static void dtrace_getpcstack(pc_t *stack, int count, int aframes,
    uint32_t *intrpc)
{
    (void)aframes;
    assert(intrpc == NULL && count == 2);
    pcstacks++;
    stack[0] = 0xa;
    stack[1] = 0xb;
}
static pc_t dtrace_caller(int aframes) { (void)aframes; return 0xc; }
static void dtrace_getupcstack(uint64_t *stack, int count)
{
    assert(count == 3);
    stack[2] = 0xd;
}
static dtrace_reg_t
builtin(dtrace_mstate_t *mstate, dtrace_state_t *state, unsigned v,
    unsigned ndx)
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
    struct trapframe probe_frame = { .id = 1 }, user_frame = { .id = 2 };
    struct thread thread = { .t_dtrace_trapframe = &probe_frame,
        .td_frame = &user_frame };
    struct probe probe = { .dtpr_vmid = 7 };
    struct hypertrace_args htrargs = { .htr_stackdepth = 0x77,
        .htr_caller = 0xbeef };
    dtrace_mstate_t mstate = { .dtms_probe = &probe,
        .dtms_arg[0] = UINT64_MAX, .dtms_vmhdl = &probe,
        .dtms_htrargs = &htrargs };
    dtrace_state_t state = { 0 };
    dtrace_reg_t value;

    curthread = &thread;
    value = builtin(&mstate, &state, DIF_VAR_REGS, 2);
    assert(value.dttr_value == 0x1002 && value.dttr_vmhdl == &probe);
    value = builtin(&mstate, &state, DIF_VAR_REGS, 99);
    assert(value.dttr_value == 0 && (flags & CPU_DTRACE_ILLOP) != 0);
    flags = 0;
    value = builtin(&mstate, &state, DIF_VAR_REGS, 3);
    assert(value.dttr_value == 0 && (flags & CPU_DTRACE_ILLOP) != 0);
    flags = 0;
    hypertrace_getreg = NULL;
    value = builtin(&mstate, &state, DIF_VAR_REGS, 2);
    assert(value.dttr_value == 0 && (flags & CPU_DTRACE_ILLOP) != 0);
    flags = 0;
    hypertrace_getreg = guest_getreg;
    value = builtin(&mstate, &state, DIF_VAR_UREGS, 2);
    assert(value.dttr_value == 0x2002 && value.dttr_vmhdl == &probe);
    value = builtin(&mstate, &state, DIF_VAR_STACKDEPTH, 0);
    assert(value.dttr_value == 0x77 && value.dttr_vmhdl == NULL);
    value = builtin(&mstate, &state, DIF_VAR_CALLER, 0);
    assert(value.dttr_value == 0xbeef && value.dttr_vmhdl == NULL);
    value = builtin(&mstate, &state, DIF_VAR_UCALLER, 0);
    assert(value.dttr_value == 0xface && value.dttr_vmhdl == NULL);
    value = builtin(&mstate, &state, DIF_VAR_USTACKDEPTH, 0);
    assert(value.dttr_value == 0x55 && value.dttr_vmhdl == NULL);
    mstate.dtms_htrargs = NULL;
    value = builtin(&mstate, &state, DIF_VAR_CALLER, 0);
    assert(value.dttr_value == 0 && (flags & CPU_DTRACE_ILLOP) != 0);
    flags = 0;
    mstate.dtms_htrargs = &htrargs;
    assert(pcstacks == 0 && mstate.dtms_present == 0 && flags == 0);
    value = builtin(&mstate, &state, DIF_VAR_HREGS, 2);
    assert(value.dttr_value == 12 && value.dttr_vmhdl == NULL);
    value = builtin(&mstate, &state, DIF_VAR_HUREGS, 2);
    assert(value.dttr_value == 22 && value.dttr_vmhdl == NULL);
    value = builtin(&mstate, &state, DIF_VAR_HSTACKDEPTH, 0);
    assert(value.dttr_value == 7 && value.dttr_vmhdl == NULL);
    value = builtin(&mstate, &state, DIF_VAR_HUSTACKDEPTH, 0);
    assert(value.dttr_value == 8 && value.dttr_vmhdl == NULL);
    value = builtin(&mstate, &state, DIF_VAR_HCALLER, 0);
    assert(value.dttr_value == 0xb && value.dttr_vmhdl == NULL);
    value = builtin(&mstate, &state, DIF_VAR_HUCALLER, 0);
    assert(value.dttr_value == 0xd && value.dttr_vmhdl == NULL);
    assert(pcstacks == 1 && flags == 0);
    puts("PASS: guest stack envelope and independent host stack/regs");
    return 0;
}
