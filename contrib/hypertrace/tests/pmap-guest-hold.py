#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Execute the unchanged production pmap_extract_and_hold body with VM models.

This isolates the guest dirty-bit side effect; it does not emulate hardware or
replace kernel compilation. Optional source allows an exact pre-fix comparison.
"""
import argparse
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[3]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('output', type=Path)
p.add_argument('--source', type=Path, default=root / 'sys/amd64/amd64/pmap.c')
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
source = a.source.read_text()
start = source.index('vm_page_t\npmap_extract_and_hold(')
end = source.index('\n}\n', start) + 3
body = source[start:end]
prelude = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint64_t pdp_entry_t, pd_entry_t, pt_entry_t, vm_offset_t;
typedef unsigned long u_long;
typedef int vm_prot_t;
struct page { int unused; } page;
typedef struct page *vm_page_t;
struct pmap { bool guest; uint64_t valid, rw, accessed, modified; };
typedef struct pmap *pmap_t;
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define PG_PS 0x80
#define PG_FRAME UINT64_C(0x000ffffffffff000)
#define PG_PS_FRAME PG_FRAME
#define PDPMASK ((UINT64_C(1) << 30) - 1)
#define PDRMASK ((UINT64_C(1) << 21) - 1)
#define PHYS_TO_VM_PAGE(pa) ((void)(pa), &page)
static pdp_entry_t pdpe;
static pd_entry_t pde;
static pt_entry_t pte;
static bool locked, wire_ok, absent;
static unsigned checks, failures;
#define CHECK(x) do { checks++; if (!(x)) { failures++; \
    fprintf(stderr, "line %d: %s\n", __LINE__, #x); } } while (0)
#define PMAP_LOCK(p) do { (void)(p); CHECK(!locked); locked = true; } while (0)
#define PMAP_UNLOCK(p) do { (void)(p); CHECK(locked); locked = false; } while (0)
static uint64_t pmap_rw_bit(pmap_t p) { return p->rw; }
static uint64_t pmap_valid_bit(pmap_t p) { return p->valid; }
static uint64_t pmap_modified_bit(pmap_t p) { return p->modified; }
static uint64_t pmap_accessed_bit(pmap_t p) { return p->accessed; }
static bool pmap_type_guest(pmap_t p) { return p->guest; }
static pdp_entry_t *pmap_pdpe(pmap_t p, vm_offset_t va)
{ (void)p; (void)va; return absent ? NULL : &pdpe; }
static pd_entry_t *pmap_pdpe_to_pde(pdp_entry_t *p, vm_offset_t va)
{ (void)p; (void)va; return &pde; }
static pt_entry_t *pmap_pde_to_pte(pd_entry_t *p, vm_offset_t va)
{ (void)p; (void)va; return &pte; }
static bool vm_page_wire_mapped(vm_page_t p)
{ CHECK(locked); CHECK(p == &page); return wire_ok; }
static void atomic_set_long(u_long *p, u_long bits)
{ CHECK(locked); *p |= bits; }
'''
fixture = r'''
int main(void) {
    struct pmap maps[] = {
        { false, 1, 2, 32, 64 }, /* ordinary x86: behavior unchanged */
        { true, 1, 2, 32, 64 }, /* RVI */
        { true, 1, 2, 256, 512 }, /* hardware EPT A/D */
        { true, 1UL << 52, 1UL << 53, 1, 2 }, /* emulated EPT */
    };
    for (unsigned kind = 0; kind < 4; kind++)
    for (unsigned level = 1; level <= 3; level++)
    for (unsigned mode = 0; mode < 5; mode++) {
        struct pmap *p = &maps[kind];
        uint64_t before, *leaf;
        vm_page_t result;
        pdpe = pde = pte = p->valid | p->rw;
        leaf = level == 3 ? &pdpe : level == 2 ? &pde : &pte;
        if (level != 1) *leaf |= PG_PS;
        if (mode == 2) *leaf &= ~p->rw;
        absent = mode == 3;
        wire_ok = mode != 4;
        before = *leaf;
        result = pmap_extract_and_hold(p, 0x123,
            mode == 0 ? VM_PROT_READ : VM_PROT_WRITE);
        CHECK(result == (mode < 2 ? &page : NULL));
        CHECK(*leaf == (before | (mode == 1 && p->guest ?
            p->accessed | p->modified : 0)));
        CHECK(!locked);
        if (level != 3) CHECK(pdpe == (p->valid | p->rw));
        if (level == 1) CHECK(pde == (p->valid | p->rw));
    }
    printf("guest pmap holds: %u checks, %u failures\n", checks, failures);
    return failures != 0;
}
'''
unit = a.output / 'pmap-hold.c'
unit.write_text(prelude + body + fixture)
exe = a.output / 'pmap-hold'
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                '-fsanitize=address,undefined', str(unit), '-o', str(exe)], check=True)
subprocess.run([str(exe)], check=True)
