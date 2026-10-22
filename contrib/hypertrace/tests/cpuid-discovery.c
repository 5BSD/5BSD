/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <machine/cpufunc.h>
#define do_cpuid test_do_cpuid
static unsigned mode, version, enabled;
static void do_cpuid(unsigned leaf, unsigned regs[4]);
#include "bhyve_hypercall.h"
static void
do_cpuid(unsigned leaf, unsigned regs[4])
{
    unsigned base = mode == 2 ? 0x40000100U : 0x40000000U;
    memset(regs, 0, sizeof(unsigned) * 4);
    if (mode == 0 || mode == 4) {
        /* Old feature bits or a foreign vendor must not enable hypercalls. */
        regs[0] = 1;
        if (mode == 4) {
            regs[1] = BHYVE_HYPERTRACE_SIGNATURE;
            regs[2] = BHYVE_HYPERTRACE_VERSION;
            regs[3] = 1;
        }
        return;
    }
    if (leaf == base) {
        regs[0] = base + 1;
        memcpy(regs + 1, "bhyve bhyve ", 12);
    } else if (leaf == base + 1) {
        regs[0] = 1; /* EXT_DEST_ID remains independent. */
        regs[1] = mode == 3 ? 0 : BHYVE_HYPERTRACE_SIGNATURE;
        regs[2] = version;
        regs[3] = enabled;
    } else if (mode == 2 && leaf == 0x40000000U) {
        regs[0] = 0x40000001U;
        memcpy(regs + 1, "KVMKVMKVM\0\0\0", 12);
    } else if (mode == 2 && leaf == 0x40000001U) {
        regs[0] = 0xffffffffU;
    }
}
int main(void)
{
    version = BHYVE_HYPERTRACE_VERSION;
    enabled = 1;
    for (mode = 0; mode <= 4; mode++) {
        assert(bhyve_hypercalls_enabled() == (mode == 1 || mode == 2));
        enabled = 0;
        assert(!bhyve_hypercalls_enabled());
        enabled = 1;
    }
    for (mode = 1; mode <= 2; mode++) {
        version = BHYVE_HYPERTRACE_VERSION - 1;
        assert(!bhyve_hypercalls_enabled());
        version = BHYVE_HYPERTRACE_VERSION + 1;
        assert(!bhyve_hypercalls_enabled());
    }
    return (0);
}
