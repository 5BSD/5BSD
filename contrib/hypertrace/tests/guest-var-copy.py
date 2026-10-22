#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Execute the production static DIF by-reference store/load arms."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('\t\tcase DIF_OP_LDGS:')
end = source.index('\t\tcase DIF_OP_LDTA:', start)
arms = source[start:end]
start = source.index('\t\tcase DIF_OP_LDLS:')
end = source.index('\t\tcase DIF_OP_LDTS:', start)
arms += source[start:end]
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum { DIF_OP_LDGS, DIF_OP_STGS, DIF_OP_LDLS, DIF_OP_STLS };
enum { DIF_VAR_OTHER_UBASE = 0x1000, DIF_TF_BYREF = 1,
    CPU_DTRACE_FAULT = 1, CPU_DTRACE_ILLOP = 2 };
#define DIF_INSTR_VAR(instr) (instr)
#define ASSERT(cond) assert(cond)
#define VERIFY(cond) assert(cond)
struct dtype { unsigned dtdt_flags; size_t dtdt_size; };
struct difv { struct dtype dtdv_type; };
struct statvar {
    uintptr_t dtsv_data;
    size_t dtsv_size;
    const void *dtsv_vmhdl;
    struct difv dtsv_var;
};
struct vstate { struct statvar **dtvs_globals; size_t dtvs_nglobals;
    struct statvar **dtvs_locals; size_t dtvs_nlocals; };
struct reg { uint64_t dttr_value; const void *dttr_vmhdl; };
static int deny, fault;
static uint16_t *active_flags;
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
    (void)h; (void)type;
    if (fault) {
        memcpy(dst, src, 1);
        *active_flags |= CPU_DTRACE_FAULT;
        return;
    }
    memcpy(dst, src, lim);
}
static struct reg dtrace_dif_variable(void *m, void *s, unsigned id,
    uint64_t ndx)
{
    (void)m; (void)s; (void)id; (void)ndx;
    return (struct reg){ 0, NULL };
}
static struct reg run(int op, struct statvar *var, struct reg input,
    uint16_t *out_flags)
{
    struct statvar *variables[] = { var };
    struct vstate variables_state = { variables, 1, variables, 1 };
    struct vstate *vstate = &variables_state;
    struct statvar *svar = NULL;
    struct difv *v = NULL;
    struct reg regs[1] = { input };
    const int rd = 0;
    unsigned id = 0;
    uint64_t *tmp = NULL;
    const int curcpu = 0, mp_maxid = 0;
    unsigned instr = DIF_VAR_OTHER_UBASE;
    uint16_t flags_store = 0;
    uint16_t *flags = &flags_store;
    void *mstate = NULL, *state = NULL;
    active_flags = flags;
    switch (op) {
ARMS
    default: assert(0);
    }
    *out_flags = *flags;
    return regs[0];
}
int main(void)
{
    const int guest = 1;
    uint8_t buffer[32] = { 0 };
    struct statvar var = { (uintptr_t)buffer, sizeof(buffer), &guest,
        { { DIF_TF_BYREF, 24 } } };
    const char guest_value[8] = "hello";
    struct reg input = { (uintptr_t)guest_value, &guest };
    uint16_t flags;
    run(DIF_OP_STGS, &var, input, &flags);
    assert(flags == 0 && buffer[0] == 0);
    assert(memcmp(buffer + 8, "hello", 6) == 0 && var.dtsv_vmhdl == NULL);
    struct reg result = run(DIF_OP_LDGS, &var, (struct reg){0}, &flags);
    assert(result.dttr_value == (uintptr_t)(buffer + 8));
    assert(result.dttr_vmhdl == NULL && flags == 0);
    memcpy(buffer + 8, "old", 4); var.dtsv_vmhdl = &guest;
    deny = 1;
    run(DIF_OP_STGS, &var, input, &flags);
    assert(buffer[0] == 0 && memcmp(buffer + 8, "old", 4) == 0);
    assert(var.dtsv_vmhdl == NULL);
    deny = 0; fault = 1;
    run(DIF_OP_STGS, &var, input, &flags);
    assert(flags == CPU_DTRACE_FAULT && buffer[0] == UINT8_MAX);
    result = run(DIF_OP_LDGS, &var, (struct reg){0}, &flags);
    assert(result.dttr_value == 0 && result.dttr_vmhdl == NULL);
    fault = 0;
    run(DIF_OP_STGS, &var, (struct reg){0}, &flags);
    assert(buffer[0] == UINT8_MAX && var.dtsv_vmhdl == NULL);
    memset(buffer, 0, sizeof(buffer)); var.dtsv_vmhdl = &guest;
    run(DIF_OP_STLS, &var, input, &flags);
    assert(flags == 0 && buffer[0] == 0 && var.dtsv_vmhdl == NULL);
    result = run(DIF_OP_LDLS, &var, (struct reg){0}, &flags);
    assert(result.dttr_value == (uintptr_t)(buffer + 8));
    assert(result.dttr_vmhdl == NULL && memcmp(buffer + 8, "hello", 6) == 0);
    fault = 1;
    run(DIF_OP_STLS, &var, input, &flags);
    assert(flags == CPU_DTRACE_FAULT && buffer[0] == UINT8_MAX);
    result = run(DIF_OP_LDLS, &var, (struct reg){0}, &flags);
    assert(result.dttr_value == 0 && result.dttr_vmhdl == NULL);
    uint64_t scalar = 17;
    var.dtsv_var.dtdv_type.dtdt_flags = 0;
    var.dtsv_data = scalar;
    var.dtsv_vmhdl = NULL;
    run(DIF_OP_STGS, &var, input, &flags);
    assert(flags == CPU_DTRACE_ILLOP && var.dtsv_data == scalar);
    assert(var.dtsv_vmhdl == NULL);
    result = run(DIF_OP_LDGS, &var, (struct reg){0}, &flags);
    assert(result.dttr_value == scalar && result.dttr_vmhdl == NULL);
    var.dtsv_data = (uintptr_t)&scalar;
    var.dtsv_size = sizeof(scalar);
    run(DIF_OP_STLS, &var, input, &flags);
    assert(flags == CPU_DTRACE_ILLOP && scalar == 17);
    assert(var.dtsv_vmhdl == NULL);
    run(DIF_OP_STLS, &var, (struct reg){ 23, NULL }, &flags);
    assert(flags == 0 && scalar == 23);
    puts("PASS: copied guest by-reference data is a host-owned variable");
    return 0;
}
'''.replace('ARMS', arms)
source_file = out / 'guest-var-copy.c'
source_file.write_text(fixture)
binary = out / 'guest-var-copy'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-variable',
    '-fsanitize=address,undefined', str(source_file), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
