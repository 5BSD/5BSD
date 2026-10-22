/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * VM_FREE_MEMSEG as agreed with the kernel owner (vmm_dev.h, 5BSD block):
 * VMM_FREE_MEMSEG_IOCNUM 200, a 16-byte request whose reserved words must be
 * zero.  The test model implements it before the kernel header defines it;
 * once the kernel does, these assertions check that the two agree.
 */
#ifndef BHYVE_COV_FREE_MEMSEG_H
#define BHYVE_COV_FREE_MEMSEG_H
#include <sys/ioctl.h>
#ifdef VM_FREE_MEMSEG
_Static_assert(sizeof(struct vm_free_memseg) == 16, "VM_FREE_MEMSEG request ABI");
_Static_assert(VMM_FREE_MEMSEG_IOCNUM == 200, "VM_FREE_MEMSEG number");
#define VMMFAKE_FREE_MEMSEG VM_FREE_MEMSEG
#define vmmfake_free_memseg vm_free_memseg
#else
struct vmmfake_free_memseg {
	int segid;
	int reserved[3];
};
#define VMMFAKE_FREE_MEMSEG _IOW('v', 200, struct vmmfake_free_memseg)
#endif
#endif
