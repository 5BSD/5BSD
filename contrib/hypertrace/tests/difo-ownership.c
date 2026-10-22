/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned int uint_t;
typedef uint32_t dif_instr_t;
typedef struct { uint64_t data[3]; } dtrace_difv_t;
typedef struct { uint64_t data[3]; } dof_relodesc_t;
typedef struct { uint64_t data; } dtrace_diftype_t;
typedef struct { int unused; } dtrace_hdl_t;
#include "difo-types.inc"
static int countdown = -1;
static size_t live;
static void *dt_alloc(dtrace_hdl_t *hdl, size_t size) {
    (void)hdl;
    if (countdown == 0) return NULL;
    if (countdown > 0) countdown--;
    void *p = malloc(size); assert(p); live++; return p;
}
static void *dt_zalloc(dtrace_hdl_t *hdl, size_t size) {
    void *p = dt_alloc(hdl, size); if (p) memset(p, 0, size); return p;
}
static void dt_free(dtrace_hdl_t *hdl, void *p) {
    (void)hdl; if (p) { assert(live); live--; free(p); }
}
#include "difo-ownership.inc"
int main(void) {
    dtrace_hdl_t hdl = {0}; int failed;
    dif_instr_t instructions[2] = {11, 22}; uint64_t integers[2] = {33, 44};
    char strings[] = "hello", symbols[] = "kernel`symbol";
    dtrace_difv_t variables[1] = {{{1, 2, 3}}};
    dof_relodesc_t relocs[1] = {{{4, 5, 6}}}; struct dt_node *nodes[1] = {NULL};
    dtrace_difo_t original = {.dtdo_buf=instructions, .dtdo_len=2,
        .dtdo_inttab=integers, .dtdo_intlen=2, .dtdo_strtab=strings, .dtdo_strlen=sizeof(strings),
        .dtdo_symtab=symbols, .dtdo_symlen=sizeof(symbols), .dtdo_vartab=variables, .dtdo_varlen=1,
        .dtdo_kreltab=relocs, .dtdo_krelen=1, .dtdo_ureltab=relocs, .dtdo_urelen=1,
        .dtdo_xlmtab=nodes, .dtdo_xlmlen=1};
    for (int fail = 0; fail < 10; fail++) {
        countdown = fail;
        dtrace_difo_t *copy = dt_difo_dup(&hdl, &original, &failed);
        if (fail < 9) { assert(!copy && failed); }
        else {
            assert(copy && !failed);
            assert(copy->dtdo_symtab != symbols && strcmp(copy->dtdo_symtab, symbols) == 0);
            copy->dtdo_symtab[0] = 'X'; assert(symbols[0] == 'k');
            assert(memcmp(copy->dtdo_buf, instructions, sizeof(instructions)) == 0);
            assert(memcmp(copy->dtdo_vartab, variables, sizeof(variables)) == 0);
            dt_difo_free(&hdl, copy);
        }
        assert(live == 0);
    }
    countdown = -1;
    assert(dt_difo_dup(&hdl, NULL, &failed) == NULL && failed == 0);
    original.dtdo_len = 0;
    assert(dt_difo_dup(&hdl, &original, &failed) == NULL && live == 0);
    dt_difo_free(&hdl, NULL);
    puts("PASS: actual DIF duplicate/free code, nine allocation failures, deep symbol ownership, null and empty input");
}
