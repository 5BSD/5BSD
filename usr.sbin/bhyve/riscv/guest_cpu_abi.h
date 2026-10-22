/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BHYVE_RISCV_GUEST_CPU_ABI_H_
#define _BHYVE_RISCV_GUEST_CPU_ABI_H_

#include <sys/param.h>
#include <stdint.h>

/* Keep checkpoint capture tied to the FDT and SBI values guests see. */
#define RISCV_GUEST_ISA_BASE "rv64imafdc"
#define RISCV_GUEST_ISA_SSTC RISCV_GUEST_ISA_BASE "_sstc"
#define RISCV_GUEST_MMU_TYPE "riscv,sv39"
#define RISCV_GUEST_SBI_VERS_MAJOR 2U
#define RISCV_GUEST_SBI_VERS_MINOR 0U
#define RISCV_GUEST_SBI_IMPL_VERSION ((uint32_t)__FreeBSD_version)

uint32_t vmexit_sbi_extension_mask(void);

#endif /* _BHYVE_RISCV_GUEST_CPU_ABI_H_ */
