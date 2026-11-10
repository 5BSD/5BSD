/* SPDX-License-Identifier: BSD-2-Clause */
#define main pagewalk_main
#include "pagewalk.c"
#undef main
#include <limits.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include "strtolctype.h"
#include "builtin-constants.inc"
typedef unsigned int uint_t;
typedef struct { int unused; } dtrace_vstate_t;
static struct { int dtpr_vmid; } guest_probe = { 1 };
typedef struct {
    typeof(guest_probe) *dtms_probe;
    const void *dtms_vmhdl;
    struct { uint32_t htr_pid; } *dtms_htrargs;
    unsigned dtms_access;
    uintptr_t dtms_scratch_ptr, dtms_scratch_base;
    size_t dtms_scratch_size;
    uintptr_t dtms_strtok, dtms_strtok_limit;
    const void *dtms_strtok_vmhdl;
} dtrace_mstate_t;
typedef struct { uint64_t dts_options[64]; dtrace_vstate_t dts_vstate; } dtrace_state_t;
typedef struct { uint64_t dttr_value; const void *dttr_vmhdl; } dtrace_reg_t;
typedef struct { uint64_t dttk_value; const void *dttk_vmhdl; } dtrace_key_t;
typedef struct { struct { int dtdt_kind; } dtdo_rtype; } dtrace_difo_t;
#define B_FALSE false
#define B_TRUE true
#define ipaddr_t in_addr_t
#define DTRACE_V4MAPPED_OFFSET (sizeof(uint32_t) * 3)
#define ASSERT assert
#define CPU_DTRACE_NOSCRATCH 4
#define CPU_DTRACE_ILLOP 8
#define CPU_DTRACE_KPRIV 16
#define CPU_DTRACE_UPRIV 32
#define DTRACE_ACCESS_KERNEL 1
#define DTRACE_CPUFLAG_SET(x) (cpu_core[0].cpuc_dtrace_flags |= (x))
#define DTRACE_CPUFLAG_CLEAR(x) (cpu_core[0].cpuc_dtrace_flags &= ~(x))
#define DTRACE_CPUFLAG_ISSET(x) ((cpu_core[0].cpuc_dtrace_flags & (x)) != 0)
#define P2ROUNDUP(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define DTRACE_INSCRATCH(m, size) ((size) <= (m)->dtms_scratch_size - ((m)->dtms_scratch_ptr - (m)->dtms_scratch_base))
#define DTRACE_STORE(type, dst, offset, value) (*(type *)((uintptr_t)(dst) + (offset)) = (type)(value))
static uint8_t dtrace_fuword8(const void *p) { return *(const uint8_t *)p; }
static uint32_t dtrace_load32(const void *h, uintptr_t addr)
{
    return h ? (uint32_t)dtrace_guest_load(h, addr, 4) :
        *(const uint32_t *)addr;
}
static void dtrace_copyin(uintptr_t src, uintptr_t dst, size_t len,
    volatile uint16_t *flags)
{
    (void)src; (void)dst; (void)len; (void)flags;
    abort(); /* A guest COPYIN must not read the host address space. */
}
static int dtrace_inscratch(uintptr_t p, size_t n, dtrace_mstate_t *m)
{
    return p >= m->dtms_scratch_base &&
        p - m->dtms_scratch_base <= m->dtms_scratch_size &&
        n <= m->dtms_scratch_size - (p - m->dtms_scratch_base);
}
static void dtrace_copyinstr(uintptr_t src, uintptr_t dst, size_t len,
    volatile uint16_t *flags)
{
    (void)src; (void)dst; (void)len; (void)flags;
    abort(); /* The guest COPYINSTR case must not take the host path. */
}
/* These tests model a privileged consumer; access-policy checks are separate. */
static int dtrace_canload(uintptr_t a, size_t n, dtrace_mstate_t *m, dtrace_vstate_t *v) { return 1; }
static int dtrace_strcanload(uintptr_t a, size_t n, const void *h, size_t *lim,
    dtrace_mstate_t *m, dtrace_vstate_t *v) { *lim = n; return 1; }
static struct vm_guest_paging pg;
static int allow_proc = 1, user_mapping_allowed = 1;
static int high_end_user_byte;
static unsigned user_copy_reads;
static int dtrace_priv_proc(dtrace_state_t *state)
{
    (void)state;
    if (allow_proc) return 1;
    cpu_core[0].cpuc_dtrace_flags |= CPU_DTRACE_UPRIV;
    return 0;
}
static int guest_user_copyin(const void *handle, uint64_t src, void *dst,
    size_t len)
{
    assert(handle == &pg && len > 0 && len <= 8);
    user_copy_reads++;
    if (!user_mapping_allowed) return EFAULT;
    if (high_end_user_byte && src == UINTPTR_MAX && len == 1) {
        *(uint8_t *)dst = 0;
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        uint64_t hva;
        if (dtrace_gla2hva(&pg, src + i, &hva) != 0)
            return EFAULT;
        ((uint8_t *)dst)[i] = *(const uint8_t *)(uintptr_t)hva;
    }
    return 0;
}
static int (*hypertrace_guest_user_copyin)(const void *, uint64_t,
    void *, size_t) = guest_user_copyin;
static size_t dtrace_memstr_max = 4096;
#include "builtin-helpers.inc"
static void builtin(uint_t subr, uint_t rd, dtrace_reg_t *regs,
    dtrace_key_t *tupregs, int nargs, dtrace_mstate_t *mstate, dtrace_state_t *state)
{
    volatile uint16_t *flags = &cpu_core[0].cpuc_dtrace_flags;
    uintptr_t invalid_address = 0;
    uintptr_t *illval = &invalid_address;
    dtrace_vstate_t *vstate = &state->dts_vstate;
    switch (subr) {
#include "builtin-arms.inc"
    default: abort();
    }
}
static unsigned char scratch[4096];
static dtrace_state_t state;
static dtrace_mstate_t mstate;
static typeof(*mstate.dtms_htrargs) guest_args = { .htr_pid = 77 };
static dtrace_reg_t regs[1];
static dtrace_key_t args[3];
static const uintptr_t text_address = PAGE_SIZE - 4;
static void input_bytes(const void *text, size_t length)
{
    assert(length >= 4 && length < PAGE_SIZE);
    memcpy((char *)pt(7) + PAGE_SIZE - 4, text, 4);
    memset(pt(11), 0, PAGE_SIZE);
    memcpy(pt(11), (const char *)text + 4, length - 4);
}
static void input(const char *text)
{
    char buffer[512] = { 0 };
    assert(strlen(text) < sizeof(buffer));
    strcpy(buffer, text);
    input_bytes(buffer, sizeof(buffer));
}
static void reset(void)
{
    memset(scratch, 0xa5, sizeof(scratch));
    memset(&mstate, 0, sizeof(mstate));
    mstate.dtms_probe = &guest_probe;
    mstate.dtms_vmhdl = &pg;
    mstate.dtms_htrargs = &guest_args;
    guest_args.htr_pid = 77;
    mstate.dtms_access = DTRACE_ACCESS_KERNEL;
    mstate.dtms_scratch_ptr = mstate.dtms_scratch_base = (uintptr_t)scratch;
    mstate.dtms_scratch_size = sizeof(scratch);
    state.dts_options[DTRACEOPT_STRSIZE] = 64;
    memset(args, 0, sizeof(args)); memset(regs, 0, sizeof(regs));
    args[0].dttk_value = text_address; args[0].dttk_vmhdl = &pg;
    cpu_core[0].cpuc_dtrace_flags = 0;
    allow_proc = user_mapping_allowed = 1;
    high_end_user_byte = 0;
    user_copy_reads = 0;
}
static const char *result(void) { assert(regs[0].dttr_vmhdl == NULL); return (const char *)(uintptr_t)regs[0].dttr_value; }
static void run(int op, int nargs) { builtin(op, 0, regs, args, nargs, &mstate, &state); assert(cpu_core[0].cpuc_dtrace_flags == 0); }
int main(void)
{
    void *arena = aligned_alloc(PAGE_SIZE, dmaplimit); assert(arena != NULL);
    memset(arena, 0, dmaplimit); kva_layout.dmap_low = (uintptr_t)arena;
    for (unsigned i = 0; i < 64; i++) pages[i].pa = i * PAGE_SIZE;
    struct pmap pm = { pt(0), PT_EPT, 0 };
    pg = (struct vm_guest_paging){ 3 * PAGE_SIZE, 0, &pm, PAGING_MODE_64 };
    pt(0)[0] = PAGE_SIZE | 1; pt(1)[0] = 2 * PAGE_SIZE | 1; pt(2)[0] = PG_PS | 1;
    pt(3)[0] = 4 * PAGE_SIZE | 1; pt(4)[0] = 5 * PAGE_SIZE | 1; pt(5)[0] = 6 * PAGE_SIZE | 1;
    pt(6)[0] = 7 * PAGE_SIZE | 1; pt(6)[1] = 11 * PAGE_SIZE | 1;
    /* A NUL at the end of one mapped page must not touch the next page. */
    input_bytes("abc\0", 4); pt(6)[1] = 0; reset();
    run(DIF_SUBR_COPYINSTR, 1);
    assert(strcmp(result(), "abc") == 0 && scratch[4] == 0xa5);
    assert(user_copy_reads == 4);
    reset(); high_end_user_byte = 1;
    args[0].dttk_value = UINTPTR_MAX;
    run(DIF_SUBR_COPYINSTR, 1);
    assert(result()[0] == '\0' && user_copy_reads == 1);
    pt(6)[1] = 11 * PAGE_SIZE | 1;
    reset(); state.dts_options[DTRACEOPT_STRSIZE] = 0;
    builtin(DIF_SUBR_COPYINSTR, 0, regs, args, 1, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_NOSCRATCH &&
        regs[0].dttr_value == 0 && scratch[0] == 0xa5);
    reset(); args[0].dttk_vmhdl = NULL;
    run(DIF_SUBR_COPYINSTR, 1);
    assert(strcmp(result(), "abc") == 0 && user_copy_reads == 4);
    reset(); user_mapping_allowed = 0;
    builtin(DIF_SUBR_COPYINSTR, 0, regs, args, 1, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        regs[0].dttr_value == 0 && scratch[0] == 0xa5);
    reset(); guest_args.htr_pid = 0;
    builtin(DIF_SUBR_COPYINSTR, 0, regs, args, 1, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        regs[0].dttr_value == 0 && scratch[0] == 0xa5 &&
        user_copy_reads == 0);
    input("abcd"); reset(); args[1].dttk_value = 4;
    run(DIF_SUBR_COPYIN, 2);
    assert(memcmp(result(), "abcd", 4) == 0);
    reset(); guest_args.htr_pid = 0; args[1].dttk_value = 4;
    builtin(DIF_SUBR_COPYIN, 0, regs, args, 2, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        regs[0].dttr_value == 0 && scratch[0] == 0xa5 &&
        user_copy_reads == 0);
    reset(); args[0].dttk_vmhdl = NULL;
    args[1].dttk_value = 4;
    run(DIF_SUBR_COPYIN, 2);
    assert(memcmp(result(), "abcd", 4) == 0 && user_copy_reads == 1);
    input("abcd"); reset(); args[1].dttk_value = 8;
    run(DIF_SUBR_COPYIN, 2);
    assert(memcmp(result(), "abcd\0\0\0\0", 8) == 0);
    pt(6)[1] = 0;
    reset(); args[1].dttk_value = 8;
    builtin(DIF_SUBR_COPYIN, 0, regs, args, 2, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        regs[0].dttr_value == 0 && scratch[0] == 0xa5);
    pt(6)[1] = 11 * PAGE_SIZE | 1;
    reset(); args[0].dttk_vmhdl = &guest_probe;
    args[1].dttk_value = 4;
    builtin(DIF_SUBR_COPYIN, 0, regs, args, 2, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP &&
        regs[0].dttr_value == 0 && scratch[0] == 0xa5);
    input("abcd"); reset(); args[1].dttk_value = 4;
    args[2].dttk_value = (uintptr_t)scratch;
    run(DIF_SUBR_COPYINTO, 3);
    assert(memcmp(scratch, "abcd", 4) == 0);
    reset(); guest_args.htr_pid = 0;
    args[1].dttk_value = 4;
    args[2].dttk_value = (uintptr_t)scratch;
    builtin(DIF_SUBR_COPYINTO, 0, regs, args, 3, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        scratch[0] == 0xa5 && user_copy_reads == 0);
    reset(); mstate.dtms_htrargs = NULL;
    args[1].dttk_value = 4;
    args[2].dttk_value = (uintptr_t)scratch;
    builtin(DIF_SUBR_COPYINTO, 0, regs, args, 3, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP &&
        scratch[0] == 0xa5 && user_copy_reads == 0);
    reset(); args[1].dttk_value = 4;
    args[2].dttk_value = (uintptr_t)scratch; args[2].dttk_vmhdl = &pg;
    builtin(DIF_SUBR_COPYINTO, 0, regs, args, 3, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP &&
        scratch[0] == 0xa5 && user_copy_reads == 0);
    reset(); args[0].dttk_vmhdl = NULL;
    args[1].dttk_value = 4; args[2].dttk_value = (uintptr_t)scratch;
    run(DIF_SUBR_COPYINTO, 3);
    assert(memcmp(scratch, "abcd", 4) == 0 && user_copy_reads == 1);
    reset(); allow_proc = 0; args[1].dttk_value = 4;
    args[2].dttk_value = (uintptr_t)scratch;
    builtin(DIF_SUBR_COPYINTO, 0, regs, args, 3, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_UPRIV &&
        scratch[0] == 0xa5 && user_copy_reads == 0);
    input("ab/c/def"); reset(); args[1].dttk_value = '/'; run(DIF_SUBR_STRCHR, 2);
    assert(regs[0].dttr_value == text_address + 2 && regs[0].dttr_vmhdl == &pg);
    run(DIF_SUBR_STRRCHR, 2); assert(regs[0].dttr_value == text_address + 4);
    reset(); args[1].dttk_value = (uintptr_t)"c/d"; run(DIF_SUBR_STRSTR, 2);
    assert(regs[0].dttr_value == text_address + 3 && regs[0].dttr_vmhdl == &pg);
    run(DIF_SUBR_INDEX, 2); assert(regs[0].dttr_value == 3);
    run(DIF_SUBR_RINDEX, 2); assert(regs[0].dttr_value == 3);
    reset(); args[0].dttk_value = 0; args[1].dttk_value = (uintptr_t)"x";
    builtin(DIF_SUBR_RINDEX, 0, regs, args, 2, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        regs[0].dttr_value == 0);
    input("ab/c/def"); memcpy((char *)pt(7) + 1, "c/", 3); reset();
    args[1].dttk_value = 1; args[1].dttk_vmhdl = &pg;
    run(DIF_SUBR_STRSTR, 2);
    assert(regs[0].dttr_value == text_address + 3 &&
        regs[0].dttr_vmhdl == &pg);
    reset(); args[1].dttk_value = 2; args[2].dttk_value = 4; run(DIF_SUBR_SUBSTR, 3);
    assert(strcmp(result(), "/c/d") == 0);
    reset(); state.dts_options[DTRACEOPT_STRSIZE] = 4; args[2].dttk_value = INT64_MAX;
    run(DIF_SUBR_SUBSTR, 3); assert(strcmp(result(), "ab/") == 0 && scratch[4] == 0xa5);
    reset(); run(DIF_SUBR_TOUPPER, 1); assert(strcmp(result(), "AB/C/DEF") == 0);
    input("AB/C/DEF"); reset(); run(DIF_SUBR_TOLOWER, 1); assert(strcmp(result(), "ab/c/def") == 0);
    input("/one/two"); reset(); run(DIF_SUBR_BASENAME, 1); assert(strcmp(result(), "two") == 0);
    reset(); run(DIF_SUBR_DIRNAME, 1); assert(strcmp(result(), "/one") == 0);
    input(""); reset(); run(DIF_SUBR_BASENAME, 1); assert(strcmp(result(), ".") == 0);
    reset(); run(DIF_SUBR_DIRNAME, 1); assert(strcmp(result(), ".") == 0);
    input("/one//two/../three"); reset(); run(DIF_SUBR_CLEANPATH, 1); assert(strcmp(result(), "/one/three") == 0);
    input("one,two,three"); reset(); args[1].dttk_value = (uintptr_t)",";
    run(DIF_SUBR_STRTOK, 2); assert(strcmp(result(), "one") == 0);
    args[0].dttk_value = 0; args[0].dttk_vmhdl = NULL;
    run(DIF_SUBR_STRTOK, 2); assert(strcmp(result(), "two") == 0);
    run(DIF_SUBR_STRTOK, 2); assert(strcmp(result(), "three") == 0);
    run(DIF_SUBR_STRTOK, 2); assert(regs[0].dttr_value == 0);
    input_bytes("\x7f\x00\x00\x01", 4); reset();
    run(DIF_SUBR_INET_NTOA, 1);
    assert(strcmp(result(), "127.0.0.1") == 0);
    uint8_t ip6bytes[16] = {0};
    input_bytes(ip6bytes, sizeof(ip6bytes)); reset();
    run(DIF_SUBR_INET_NTOA6, 1);
    assert(regs[0].dttr_value != 0 && *result() != '\0');
    reset(); args[0].dttk_value = (1ULL << 32) | AF_INET;
    args[1].dttk_value = text_address; args[1].dttk_vmhdl = &pg;
    builtin(DIF_SUBR_INET_NTOP, 0, regs, args, 2, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP &&
        regs[0].dttr_value == 0 &&
        mstate.dtms_scratch_ptr == (uintptr_t)scratch);
    /* The first page contains matches; the next guest page faults. Neither
     * a prior match nor strtok's saved cursor may survive that fault. */
    input_bytes("a/a/aa", 7); reset(); args[1].dttk_value = '/';
    pt(6)[1] = 0;
    reset(); args[0].dttk_value = text_address + 1;
    builtin(DIF_SUBR_INET_NTOA, 0, regs, args, 1, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        regs[0].dttr_value == 0 &&
        mstate.dtms_scratch_ptr == (uintptr_t)scratch);
    reset(); builtin(DIF_SUBR_INET_NTOA6, 0, regs, args, 1, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        regs[0].dttr_value == 0 &&
        mstate.dtms_scratch_ptr == (uintptr_t)scratch);
    reset(); args[1].dttk_value = '/';
    builtin(DIF_SUBR_STRRCHR, 0, regs, args, 2, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        regs[0].dttr_value == 0 && regs[0].dttr_vmhdl == NULL);
    reset(); builtin(DIF_SUBR_STRLEN, 0, regs, args, 1, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        regs[0].dttr_value == 0);
    reset(); args[1].dttk_value = (uintptr_t)"/";
    builtin(DIF_SUBR_STRSTR, 0, regs, args, 2, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        regs[0].dttr_value == 0);
    reset(); args[1].dttk_value = 0; args[2].dttk_value = 3;
    builtin(DIF_SUBR_SUBSTR, 0, regs, args, 3, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        regs[0].dttr_value == 0 && regs[0].dttr_vmhdl == NULL &&
        mstate.dtms_scratch_ptr == (uintptr_t)scratch);
    reset(); builtin(DIF_SUBR_BASENAME, 0, regs, args, 1, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        regs[0].dttr_value == 0 &&
        mstate.dtms_scratch_ptr == (uintptr_t)scratch);
    reset(); builtin(DIF_SUBR_DIRNAME, 0, regs, args, 1, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        regs[0].dttr_value == 0 &&
        mstate.dtms_scratch_ptr == (uintptr_t)scratch);
    reset(); builtin(DIF_SUBR_CLEANPATH, 0, regs, args, 1, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        regs[0].dttr_value == 0 &&
        mstate.dtms_scratch_ptr == (uintptr_t)scratch);
    input_bytes(" 12345", 7); reset();
    assert(dtrace_strtoll(&pg, (char *)text_address, 10, 4) == 123 &&
        cpu_core[0].cpuc_dtrace_flags == 0);
    reset(); builtin(DIF_SUBR_STRTOLL, 0, regs, args, 1, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        regs[0].dttr_value == (uint64_t)INT64_MIN);
    reset(); args[1].dttk_value = (uintptr_t)"x";
    mstate.dtms_strtok = 123;
    mstate.dtms_strtok_limit = 124;
    mstate.dtms_strtok_vmhdl = &pg;
    builtin(DIF_SUBR_STRTOK, 0, regs, args, 2, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        regs[0].dttr_value == 0 &&
        mstate.dtms_strtok == 123 && mstate.dtms_strtok_limit == 124 &&
        mstate.dtms_strtok_vmhdl == &pg);
    pt(6)[1] = 11 * PAGE_SIZE | 1;
    /* Out-of-range values wrap modulo 2^64, as upstream. */
    input("9223372036854775808"); reset(); run(DIF_SUBR_STRTOLL, 1);
    assert(regs[0].dttr_value == (uint64_t)INT64_MIN);
    input("-9223372036854775809"); reset(); run(DIF_SUBR_STRTOLL, 1);
    assert(regs[0].dttr_value == INT64_MAX);
    input("{\"answer\":\"yes\"}"); reset(); args[1].dttk_value = (uintptr_t)"answer";
    run(DIF_SUBR_JSON, 2); assert(strcmp(result(), "yes") == 0);
    reset(); memcpy((char *)pt(7) + 128, "answer", 7);
    args[1].dttk_value = 128; args[1].dttk_vmhdl = &pg;
    run(DIF_SUBR_JSON, 2); assert(strcmp(result(), "yes") == 0);
    input("guest"); reset(); char *joined = dtrace_strjoin(&state, &mstate, &state.dts_vstate,
        &pg, NULL, text_address, (uintptr_t)"-host"); assert(strcmp(joined, "guest-host") == 0);
    input_bytes("ab\0cd", 6); reset(); args[1].dttk_value = '_'; args[2].dttk_value = 6;
    run(DIF_SUBR_MEMSTR, 3); assert(strcmp(result(), "ab_cd") == 0);
    input("copy"); reset(); args[1].dttk_value = (uintptr_t)scratch;
    args[2].dttk_value = 4; run(DIF_SUBR_BCOPY, 3);
    assert(memcmp(scratch, "copy", 4) == 0);
    reset(); args[1].dttk_value = (uintptr_t)scratch;
    args[1].dttk_vmhdl = &pg; args[2].dttk_value = 4;
    builtin(DIF_SUBR_BCOPY, 0, regs, args, 3, &mstate, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP &&
        scratch[0] == 0xa5 && user_copy_reads == 0);
    input("record"); reset(); dtrace_difo_t difo = { .dtdo_rtype.dtdt_kind = DIF_TYPE_STRING };
    for (int kind = DIF_TF_BYREF; kind <= DIF_TF_BYUREF; kind++) {
        size_t offset = 0; uint64_t value = text_address;
        dtrace_store_by_ref(&mstate, &difo, (char *)scratch, 16, &offset,
            &value, 16, 0, kind, &pg, &state);
        assert(strcmp((char *)scratch, "record") == 0 && offset == 16 && value == text_address + 7);
    }
    reset();
    size_t offset = 0; uint64_t value = text_address;
    dtrace_store_by_ref(&mstate, &difo, (char *)scratch, 16, &offset,
        &value, 16, 0, DIF_TF_BYUREF, NULL, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == 0 &&
        strcmp((char *)scratch, "record") == 0 && offset == 16);
    reset(); offset = 0; value = text_address;
    dtrace_store_by_ref(&mstate, &difo, (char *)scratch, 16, &offset,
        &value, 16, 0, DIF_TF_BYUREF, &guest_probe, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP &&
        offset == 0 && value == text_address && scratch[0] == 0xa5);
    reset(); offset = 0; value = text_address; user_mapping_allowed = 0;
    dtrace_store_by_ref(&mstate, &difo, (char *)scratch, 16, &offset,
        &value, 16, 0, DIF_TF_BYUREF, &pg, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        offset == 0 && scratch[0] == 0xa5);
    reset(); offset = 0; value = text_address; allow_proc = 0;
    dtrace_store_by_ref(&mstate, &difo, (char *)scratch, 16, &offset,
        &value, 16, 0, DIF_TF_BYUREF, &pg, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_UPRIV &&
        offset == 0 && scratch[0] == 0xa5 && user_copy_reads == 0);
    guest_probe.dtpr_vmid = 0; reset();
    offset = 0; value = (uintptr_t)"host";
    dtrace_store_by_ref(&mstate, &difo, (char *)scratch, 16, &offset,
        &value, 16, 0, DIF_TF_BYUREF, NULL, &state);
    assert(cpu_core[0].cpuc_dtrace_flags == 0 &&
        strcmp((char *)scratch, "host") == 0 && offset == 16);
    guest_probe.dtpr_vmid = 1;
    cpu_core[0].cpuc_dtrace_flags = CPU_DTRACE_NOFAULT;
    assert(dtrace_guest_load(&pg, text_address, 1) == 'r');
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_NOFAULT);
    /* An unprivileged guest pointer into an unmapped page must be denied
     * before any builtin's length scan can raise a guest address fault. */
    const struct { int op, nargs; } guarded[] = {
        {DIF_SUBR_STRSTR, 2}, {DIF_SUBR_INDEX, 2},
        {DIF_SUBR_RINDEX, 2}, {DIF_SUBR_SUBSTR, 3},
        {DIF_SUBR_JSON, 2}, {DIF_SUBR_TOUPPER, 1},
        {DIF_SUBR_TOLOWER, 1}, {DIF_SUBR_DIRNAME, 1},
        {DIF_SUBR_BASENAME, 1}, {DIF_SUBR_MEMSTR, 3},
        {DIF_SUBR_BCOPY, 3}
    };
    pt(6)[1] = 0;
    for (size_t i = 0; i < sizeof(guarded) / sizeof(guarded[0]); ++i) {
        reset(); mstate.dtms_access = 0;
        args[0].dttk_value = PAGE_SIZE;
        args[1].dttk_value = (uintptr_t)"x";
        if (guarded[i].op == DIF_SUBR_BCOPY)
            args[1].dttk_value = (uintptr_t)scratch;
        args[2].dttk_value = 6;
        builtin(guarded[i].op, 0, regs, args, guarded[i].nargs,
            &mstate, &state);
        assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_KPRIV &&
            regs[0].dttr_value == 0);
    }
    for (size_t i = 0; i < 2; ++i) {
        reset(); mstate.dtms_access = 0;
        args[0].dttk_value = (uintptr_t)"abc";
        args[0].dttk_vmhdl = NULL;
        args[1].dttk_value = PAGE_SIZE;
        args[1].dttk_vmhdl = &pg;
        builtin(i == 0 ? DIF_SUBR_STRSTR : DIF_SUBR_JSON, 0,
            regs, args, 2, &mstate, &state);
        assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_KPRIV &&
            regs[0].dttr_value == 0);
    }
    pt(6)[1] = 11 * PAGE_SIZE | 1;
    free(arena);
    puts("PASS: actual guest string/path/JSON/token builtins, record emission, mixed address spaces, scratch bounds");
    return (0);
}
