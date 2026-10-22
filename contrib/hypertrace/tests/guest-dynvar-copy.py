#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production thread-local DIF by-reference variable arms."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('\t\tcase DIF_OP_LDTS:')
end = source.index('\t\tcase DIF_OP_SRA:', start)
arms = source[start:end]
start = source.index('\t\tcase DIF_OP_STGAA:')
end = source.index('\t\tcase DIF_OP_ALLOCS:', start)
arms += source[start:end]
start = source.index('static int\ndtrace_vstage_dynvar(')
end = source.index('\n\n/*\n * Compare s1 to s2', start)
copy_helper = source[start:end]
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef unsigned int uint_t;

enum { DIF_OP_LDTS, DIF_OP_STTS, DIF_OP_STGAA, DIF_OP_STTAA };
enum { DIF_VAR_OTHER_UBASE = 0x1000, DIF_TF_BYREF = 1,
    DIF_TYPE_STRING = 2,
    DTRACE_DYNVAR_ALLOC, DTRACE_DYNVAR_NOALLOC, DTRACE_DYNVAR_DEALLOC,
    CPU_DTRACE_FAULT = 1, CPU_DTRACE_ILLOP = 2,
    CPU_DTRACE_NOSCRATCH = 4, DIF_DTR_NREGS = 4 };
#define DIF_INSTR_VAR(instr) (instr)
#define DIF_INSTR_OP(instr) (op)
#define ASSERT(c) assert(c)
#define VERIFY(c) assert(c)
#define DTRACE_TLS_THRKEY(m, value) ((value) = 1)
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define DTRACE_INSCRATCH(m, size) ((m)->dtms_scratch_size - \
    ((m)->dtms_scratch_ptr - (m)->dtms_scratch_base) >= (size))
#define bcopy(src, dst, size) memmove((dst), (src), (size))
#define bzero(dst, size) memset((dst), 0, (size))
struct dtype { unsigned dtdt_flags; size_t dtdt_size; unsigned dtdt_kind; };
typedef struct dtype dtrace_diftype_t;
struct mstate { uintptr_t dtms_scratch_base, dtms_scratch_ptr;
    size_t dtms_scratch_size; };
typedef struct mstate dtrace_mstate_t;
struct difv { struct dtype dtdv_type; };
struct statvar { struct difv dtsv_var; };
struct vstate { struct difv *dtvs_tlocals; size_t dtvs_ntlocals;
    struct statvar **dtvs_globals; size_t dtvs_nglobals; };
struct reg { uint64_t dttr_value; const void *dttr_vmhdl; };
struct key { uint64_t dttk_value, dttk_size; const void *dttk_vmhdl; };
struct dynvar { void *dtdv_data; const void *dtdv_vmhdl; };
typedef struct dynvar dtrace_dynvar_t;
typedef struct key dtrace_key_t;
static uint8_t host_buffer[24];
static struct dynvar variable = { host_buffer, NULL };
static int variable_exists = 1;
static struct { int t_predcache; } thread;
static typeof(thread) *curthread = &thread;
static int deny, fault, fail_alloc;
static unsigned type_kind;
static int dynvar_calls;
static size_t scratch_capacity = 64;
static struct { uint16_t cpuc_dtrace_flags; } cpu_core[1];
static const int curcpu = 0;
static uint16_t *active_flags;
static struct dynvar *dtrace_dynvar(void *d, int n, struct key *keys,
    size_t size, int op, void *m, struct vstate *v)
{
    (void)d; (void)n; (void)keys; (void)size; (void)m; (void)v;
    dynvar_calls++;
    if (op == DTRACE_DYNVAR_DEALLOC) { variable_exists = 0; return NULL; }
    if (op == DTRACE_DYNVAR_NOALLOC)
        return variable_exists ? &variable : NULL;
    if (fail_alloc) return NULL;
    if (!variable_exists) {
        variable_exists = 1;
        memset(host_buffer, 0, sizeof(host_buffer));
    }
    return &variable;
}
static int dtrace_vcanload(const void *h, void *p, struct dtype *type,
    size_t *lim, void *m, struct vstate *v)
{
    (void)h; (void)p; (void)type; (void)m; (void)v;
    if (deny) return 0;
    *lim = 8;
    return 1;
}
static void dtrace_vcopy(const void *h, void *src, void *dst,
    struct dtype *type, size_t lim)
{
    (void)h;
    if (fault) {
        memcpy(dst, src, 1);
        *active_flags |= CPU_DTRACE_FAULT;
        return;
    }
    if (type->dtdt_kind == DIF_TYPE_STRING) {
        for (size_t i = 0; i < lim; i++) {
            ((char *)dst)[i] = ((char *)src)[i];
            if (((char *)dst)[i] == '\0') return;
        }
        return;
    }
    memcpy(dst, src, lim);
}
COPY_HELPER
static struct reg run(int op, struct reg input, uint16_t *out_flags,
    unsigned type_flags)
{
    struct difv variable_type[] = { { { type_flags, 24, type_kind } } };
    struct statvar global = { variable_type[0] };
    struct statvar *globals[] = { &global };
    struct vstate variables_state = { variable_type, 1, globals, 1 };
    struct vstate *vstate = &variables_state;
    struct difv *v = NULL;
    struct reg regs[1] = { input };
    const int rd = 0;
    struct key tupregs[DIF_DTR_NREGS + 2] = {0};
    unsigned ttop = 0;
    unsigned id = 0;
    unsigned instr = DIF_VAR_OTHER_UBASE;
    uint8_t scratch[64];
    struct mstate scratch_state = { (uintptr_t)scratch,
        (uintptr_t)scratch, scratch_capacity };
    uint16_t *flags = &cpu_core[0].cpuc_dtrace_flags;
    struct mstate *mstate = &scratch_state;
    void *dstate = NULL;
    *flags = 0;
    active_flags = flags;
    switch (op) {
ARMS
    default: assert(0);
    }
    assert(mstate->dtms_scratch_ptr == mstate->dtms_scratch_base);
    *out_flags = *flags;
    return regs[0];
}
int main(void)
{
    const int guest = 1;
    const char guest_value[8] = "hello";
    const char fault_value[8] = "world";
    struct reg input = { (uintptr_t)guest_value, &guest };
    uint16_t flags;
    variable.dtdv_vmhdl = &guest;
    run(DIF_OP_STTS, input, &flags, DIF_TF_BYREF);
    assert(flags == 0 && variable.dtdv_vmhdl == NULL);
    assert(memcmp(host_buffer, guest_value, 8) == 0);
    struct reg result = run(DIF_OP_LDTS, (struct reg){0}, &flags,
        DIF_TF_BYREF);
    assert(result.dttr_value == (uintptr_t)host_buffer);
    assert(result.dttr_vmhdl == NULL);
    variable.dtdv_vmhdl = NULL; deny = 1;
    int calls = dynvar_calls;
    run(DIF_OP_STTS, input, &flags, DIF_TF_BYREF);
    assert(variable.dtdv_vmhdl == NULL);
    assert(memcmp(host_buffer, guest_value, 8) == 0);
    assert(dynvar_calls == calls);
    deny = 0; fault = 1;
    run(DIF_OP_STTS, (struct reg){ (uintptr_t)fault_value, &guest },
        &flags, DIF_TF_BYREF);
    assert(flags == CPU_DTRACE_FAULT && variable.dtdv_vmhdl == NULL);
    assert(memcmp(host_buffer, guest_value, 8) == 0);
    fault = 0; scratch_capacity = 0;
    run(DIF_OP_STTS, (struct reg){ (uintptr_t)fault_value, &guest },
        &flags, DIF_TF_BYREF);
    assert(flags == CPU_DTRACE_NOSCRATCH);
    assert(memcmp(host_buffer, guest_value, 8) == 0);
    scratch_capacity = 64;
    calls = dynvar_calls;
    run(DIF_OP_STTS, input, &flags, 0);
    assert(flags == CPU_DTRACE_ILLOP && dynvar_calls == calls);
    assert(variable.dtdv_vmhdl == NULL);
    run(DIF_OP_STTS, (struct reg){ 27, NULL }, &flags, 0);
    assert(flags == 0 && *(uint64_t *)host_buffer == 27);
    calls = dynvar_calls;
    run(DIF_OP_STGAA, input, &flags, 0);
    assert(flags == CPU_DTRACE_ILLOP && dynvar_calls == calls);
    run(DIF_OP_STTAA, input, &flags, 0);
    assert(flags == CPU_DTRACE_ILLOP && dynvar_calls == calls);
    run(DIF_OP_STGAA, (struct reg){ 31, NULL }, &flags, 0);
    assert(flags == 0 && *(uint64_t *)host_buffer == 31);
    run(DIF_OP_STTAA, (struct reg){ 37, NULL }, &flags, 0);
    assert(flags == 0 && *(uint64_t *)host_buffer == 37);
    run(DIF_OP_STGAA, input, &flags, DIF_TF_BYREF);
    assert(flags == 0 && memcmp(host_buffer, guest_value, 8) == 0);
    deny = 1;
    calls = dynvar_calls;
    run(DIF_OP_STGAA, (struct reg){ (uintptr_t)fault_value, &guest },
        &flags, DIF_TF_BYREF);
    run(DIF_OP_STTAA, (struct reg){ (uintptr_t)fault_value, &guest },
        &flags, DIF_TF_BYREF);
    assert(dynvar_calls == calls);
    assert(memcmp(host_buffer, guest_value, 8) == 0);
    deny = 0;
    fault = 1;
    run(DIF_OP_STTAA, (struct reg){ (uintptr_t)fault_value, &guest },
        &flags, DIF_TF_BYREF);
    assert(flags == CPU_DTRACE_FAULT);
    assert(memcmp(host_buffer, guest_value, 8) == 0);
    for (int op = DIF_OP_STTS; op <= DIF_OP_STTAA; op++) {
        if (op != DIF_OP_STTS && op != DIF_OP_STGAA && op != DIF_OP_STTAA)
            continue;
        variable_exists = 0;
        calls = dynvar_calls;
        run(op, (struct reg){ (uintptr_t)fault_value, &guest },
            &flags, DIF_TF_BYREF);
        assert(flags == CPU_DTRACE_FAULT && !variable_exists &&
            dynvar_calls == calls);
        fault = 0;
        run(op, input, &flags, DIF_TF_BYREF);
        assert(flags == 0 && variable_exists &&
            memcmp(host_buffer, guest_value, 8) == 0);
        fault = 1;
    }
    fault = 0; fail_alloc = 1;
    run(DIF_OP_STTS, input, &flags, DIF_TF_BYREF);
    assert(flags == 0 && variable_exists &&
        memcmp(host_buffer, guest_value, 8) == 0);
    fail_alloc = 0; type_kind = DIF_TYPE_STRING;
    const char string_value[8] = { 'a', '\0', 'x', 'x', 'x', 'x', 'x', 'x' };
    memset(host_buffer, 0xcc, sizeof(host_buffer));
    run(DIF_OP_STTS, (struct reg){ (uintptr_t)string_value, &guest },
        &flags, DIF_TF_BYREF);
    assert(flags == 0 && host_buffer[0] == 'a' && host_buffer[1] == 0);
    for (size_t i = 2; i < 8; i++) assert(host_buffer[i] == 0);
    puts("PASS: dynamic by-reference copy uses host-buffer provenance");
    return 0;
}
'''.replace('ARMS', arms).replace('COPY_HELPER', copy_helper)
source_file = out / 'guest-dynvar-copy.c'
source_file.write_text(fixture)
binary = out / 'guest-dynvar-copy'
subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', str(source_file), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
