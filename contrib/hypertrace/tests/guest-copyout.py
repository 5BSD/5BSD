#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run the production guest copyout helper against faulting guest hooks."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('/* Copy a validated source to guest user memory.')
helper = source[start:source.index('\n#endif', start)]
fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define ASSERT(x) assert(x)
#define MIN(a,b) ((a)<(b)?(a):(b))
#define CPU_DTRACE_ILLOP 1
#define CPU_DTRACE_BADADDR 2
#define CPU_DTRACE_NOFAULT 4
#define CPU_DTRACE_FAULT CPU_DTRACE_BADADDR
#define DTRACE_CPUFLAG_SET(bit) (*flags |= (bit))
#define DTRACE_CPUFLAG_CLEAR(bit) (*flags &= ~(bit))
typedef struct { uintptr_t dttk_value; const void *dttk_vmhdl; } dtrace_key_t;
struct guest_args { uint32_t htr_pid; };
typedef struct { const void *dtms_vmhdl;
    struct guest_args *dtms_htrargs; } dtrace_mstate_t;
static struct { uintptr_t cpuc_dtrace_illval; } cpu_core[1];
static int curcpu, guest_handle, other_handle;
static uint8_t guest[32];
static unsigned reads, writes;
static int read_error, write_error;
static int high_end_user_byte;
static int guest_read(const void *h, uint64_t a, void *d, size_t n) {
    assert(h == &guest_handle && n <= 8); reads++;
    if (read_error) return read_error;
    if (a < 0x1000 || n > sizeof(guest) || a-0x1000 > sizeof(guest)-n)
        return EFAULT;
    memcpy(d, guest+(a-0x1000), n); return 0;
}
static int guest_write(const void *h, uint64_t a, const void *s, size_t n) {
    assert(h == &guest_handle && n <= 8); writes++;
    if (write_error) return write_error;
    if (high_end_user_byte && a == UINTPTR_MAX && n == 1) {
        assert(*(const uint8_t *)s == 0);
        return 0;
    }
    if (a < 0x1000 || n > sizeof(guest) || a-0x1000 > sizeof(guest)-n)
        return EFAULT;
    memcpy(guest+(a-0x1000), s, n); return 0;
}
static int (*hypertrace_guest_copyin)(const void *, uint64_t, void *,
    size_t) = guest_read;
static int (*hypertrace_guest_user_copyout)(const void *, uint64_t,
    const void *, size_t) = guest_write;
static void dtrace_bcopy(const void *tag, const void *s, void *d, size_t n) {
    assert(tag == NULL);
    memcpy(d, s, n);
}
HELPER
static void reset(void) {
    memset(guest, 0, sizeof(guest)); reads = writes = 0;
    read_error = write_error = 0; cpu_core[0].cpuc_dtrace_illval = 0;
    high_end_user_byte = 0;
}
int main(void) {
    struct guest_args guest_args = { .htr_pid = 77 };
    dtrace_mstate_t ms = { .dtms_vmhdl = &guest_handle,
        .dtms_htrargs = &guest_args };
    dtrace_key_t dst = { .dttk_value = 0x1010 };
    const char host[] = "hello";
    dtrace_key_t src = { .dttk_value = (uintptr_t)host };
    volatile uint16_t flags = 0;
    reset();
    dtrace_guest_copyout(&ms, src, dst, sizeof(host), 0, &flags);
    assert(flags == 0 && writes == 1 && reads == 0);
    assert(memcmp(guest+16, host, sizeof(host)) == 0);
    reset(); flags = 0; guest_args.htr_pid = 0;
    dtrace_guest_copyout(&ms, src, dst, sizeof(host), 0, &flags);
    assert(flags == CPU_DTRACE_BADADDR && reads == 0 && writes == 0 &&
        cpu_core[0].cpuc_dtrace_illval == dst.dttk_value);
    guest_args.htr_pid = 77;
    reset(); flags = 0; ms.dtms_htrargs = NULL;
    dtrace_guest_copyout(&ms, src, dst, sizeof(host), 0, &flags);
    assert(flags == CPU_DTRACE_ILLOP && reads == 0 && writes == 0);
    ms.dtms_htrargs = &guest_args;
    reset(); flags = 0;
    memcpy(guest, "guest-data", 10);
    src.dttk_value = 0x1000; src.dttk_vmhdl = &guest_handle;
    dtrace_guest_copyout(&ms, src, dst, 10, 0, &flags);
    assert(flags == 0 && reads == 2 && writes == 2);
    assert(memcmp(guest+16, "guest-data", 10) == 0);
    reset(); flags = 0; src.dttk_vmhdl = &other_handle;
    dtrace_guest_copyout(&ms, src, dst, 4, 0, &flags);
    assert(flags == CPU_DTRACE_ILLOP && reads == 0 && writes == 0);
    src.dttk_vmhdl = &guest_handle;
    reset(); flags = 0; dst.dttk_vmhdl = &other_handle;
    dtrace_guest_copyout(&ms, src, dst, 4, 0, &flags);
    assert(flags == CPU_DTRACE_ILLOP && writes == 0);
    dst.dttk_vmhdl = &guest_handle;
    reset(); flags = 0; hypertrace_guest_user_copyout = NULL;
    dtrace_guest_copyout(&ms, src, dst, 4, 0, &flags);
    assert(flags == CPU_DTRACE_ILLOP && writes == 0);
    hypertrace_guest_user_copyout = guest_write;
    reset(); flags = 0; write_error = EFAULT;
    dtrace_guest_copyout(&ms, src, dst, 4, 0, &flags);
    assert(flags == CPU_DTRACE_BADADDR && writes == 1 &&
        cpu_core[0].cpuc_dtrace_illval == 0x1010);
    reset(); flags = 0; read_error = EFAULT;
    dtrace_guest_copyout(&ms, src, dst, 4, 0, &flags);
    assert(flags == CPU_DTRACE_BADADDR && writes == 0 &&
        cpu_core[0].cpuc_dtrace_illval == 0x1000);
    reset(); flags = 0;
    src.dttk_vmhdl = NULL; src.dttk_value = (uintptr_t)host;
    dtrace_guest_copyout(&ms, src, dst, sizeof(host), 1, &flags);
    assert(flags == 0 && writes == sizeof(host) &&
        memcmp(guest+16, host, sizeof(host)) == 0 && guest[22] == 0);
    reset(); flags = 0; high_end_user_byte = 1;
    const char empty[] = "";
    src.dttk_value = (uintptr_t)empty;
    dst.dttk_value = UINTPTR_MAX;
    dtrace_guest_copyout(&ms, src, dst, 4, 1, &flags);
    assert(flags == 0 && writes == 1 && reads == 0);
    reset(); flags = 0; dst.dttk_value = UINTPTR_MAX-1;
    dtrace_guest_copyout(&ms, src, dst, 4, 0, &flags);
    assert(flags == CPU_DTRACE_BADADDR && writes == 0);
    puts("PASS: guest copyout uses guest user writes and rejects faulting targets");
    return 0;
}
'''.replace('HELPER', helper)
source_file = out / 'guest-copyout.c'
source_file.write_text(fixture)
binary = out / 'guest-copyout'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', str(source_file), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
