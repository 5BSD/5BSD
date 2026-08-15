/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _AMD64_VMM_VMM_SNAPSHOT_X86_STATE_H_
#define	_AMD64_VMM_VMM_SNAPSHOT_X86_STATE_H_

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdbool.h>
#include <stdint.h>
#endif

#include "vmm_event_state.h"

#define	VMM_SNAPSHOT_SECTION_VCPU_X86	UINT16_C(0x1001)
#define	VMM_SNAPSHOT_SECTION_VCPU_X86_FPU	UINT16_C(0x1002)
#define	VMM_SNAPSHOT_X86_STATE_VERSION	1U
#define	VMM_SNAPSHOT_VCPU_X86_SIZE	80U

#define	VMM_SNAPSHOT_X86_F_NMI_PENDING	UINT32_C(0x00000001)
#define	VMM_SNAPSHOT_X86_F_EXTINT_PENDING	UINT32_C(0x00000002)
#define	VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING	UINT32_C(0x00000004)
#define	VMM_SNAPSHOT_X86_F_EXCEPTION_ERROR	UINT32_C(0x00000008)
#define	VMM_SNAPSHOT_X86_F_VALID	(UINT32_C(0x0000000f))

enum vmm_snapshot_x86_exception_class {
	VMM_SNAPSHOT_X86_EXCEPTION_NONE = 0,
	VMM_SNAPSHOT_X86_EXCEPTION_FAULT,
	VMM_SNAPSHOT_X86_EXCEPTION_TRAP,
	VMM_SNAPSHOT_X86_EXCEPTION_ICEBP,
	VMM_SNAPSHOT_X86_EXCEPTION_TASK_SWITCH,
	VMM_SNAPSHOT_X86_EXCEPTION_CLASS_LAST,
};

struct vmm_snapshot_vcpu_x86 {
	uint32_t	flags;
	uint32_t	x2apic_state;
	enum vmm_snapshot_x86_exception_class exception_class;
	uint64_t	exitintinfo;
	uint32_t	exception_vector;
	uint32_t	exception_error;
	uint64_t	guest_xcr0;
	uint64_t	absolute_tsc;
};

/*
 * Guest FPU/XSAVE record (section VMM_SNAPSHOT_SECTION_VCPU_X86_FPU).
 *
 * The runtime keeps the guest's complete x87/SSE/AVX/AVX-512 register file
 * in vcpu->guestfpu: restore_guest_fpustate() loads it before every guest
 * entry and save_guest_fpustate() writes it back on every exit, so while a
 * vCPU is VCPU_FROZEN the save area is the only authoritative copy of the
 * guest vector state.  Before this record existed the kernel-common STRUCT_VM
 * transaction serialized guest_xcr0 but not the save area itself, so a
 * checkpoint silently discarded the entire vector register file.
 *
 * Wire layout (fixed-width little-endian, versioned, total = 48 + area_length
 * bytes; no native pointers, size_t, or raw host structures):
 *
 *	offset	size	field
 *	0	2	version (VMM_SNAPSHOT_X86_FPU_VERSION)
 *	2	2	total record length (must equal the section length)
 *	4	4	flags (VMM_SNAPSHOT_X86_FPU_F_*)
 *	8	4	area_length
 *	12	4	reserved, must be zero
 *	16	8	xsave_bitmap
 *	24	24	reserved, must be zero
 *	48	area_length	save-area image
 *
 * The save-area image is either a bare 512-byte FXSAVE image (flags clear;
 * xsave_bitmap must be zero and area_length exactly 512) or an XSAVE
 * standard-format image (VMM_SNAPSHOT_X86_FPU_F_XSAVE; 512-byte legacy
 * region, 64-byte XSAVE header, then extended state).  XSAVE-area layout is
 * CPU-capability-dependent, so the record carries the source's requested-
 * feature bitmap (the RFBM the host used with XSAVE, i.e. xsave_mask) and
 * the exact area size.  Restore validation is capability-aware and fails
 * closed BEFORE any destination mutation: a destination whose XSAVE feature
 * set cannot represent every component named by the image's XSTATE_BV, or
 * whose save area is smaller than the image, rejects the record
 * (EOPNOTSUPP) instead of silently truncating state.  Compacted-form images
 * (XCOMP_BV != 0), nonzero header reserved bytes, MXCSR values that would
 * #GP on XRSTOR, unknown versions, and truncated or oversized records are
 * all rejected by validation with the destination left untouched.
 *
 * IA32_XSS / IA32_SPEC_CTRL decision (explicit, per the whole-machine
 * snapshot review):
 *
 *   IA32_XSS: this VMM does not virtualize supervisor XSAVE state.  CPUID
 *   leaf 0xD sub-leaf 1 exposes only XSAVEOPT (EAX masked; ECX/EDX zeroed),
 *   so XSAVES/XRSTORS and every supervisor component are hidden from the
 *   guest; MSR 0xDA0 has no case in vmx_rdmsr/vmx_wrmsr or
 *   svm_rdmsr/svm_wrmsr, so guest access is rejected as an unknown MSR and
 *   there is no kernel storage in which a guest IA32_XSS value could exist.
 *   Nothing exists to capture, therefore nothing can be silently lost.  As
 *   a guard against future drift, VMM_SNAPSHOT_X86_XSAVE_USER_MASK pins the
 *   record to user (XCR0-managed) components: if a later change starts
 *   context-switching supervisor state (PT, CET_U/S, HDC, ...) into the
 *   guest save area, capture and restore validation fail closed instead of
 *   emitting a record whose supervisor components a destination would
 *   misinterpret or drop.
 *
 *   IA32_SPEC_CTRL: likewise not virtualized.  Neither vendor MSR handler
 *   implements MSR 0x048, and the speculation-control CPUID bits are never
 *   advertised (leaf 7 EDX is masked to MD_CLEAR/AVX512-* only; AMD leaf
 *   0x80000008 EBX is masked to CLZERO/IRPERF/XSAVEERPTR).  A guest write
 *   is bounced to userspace as an unknown MSR, so no guest SPEC_CTRL policy
 *   value is ever held by the kernel and a checkpoint cannot lose one.  If
 *   SPEC_CTRL virtualization is added later it MUST come with its own
 *   versioned snapshot record; this comment is the tripwire for that
 *   review.
 */
#define	VMM_SNAPSHOT_X86_FPU_VERSION	1U
#define	VMM_SNAPSHOT_VCPU_X86_FPU_HEADER_SIZE	48U
#define	VMM_SNAPSHOT_X86_FPU_AREA_MAX	8192U
#define	VMM_SNAPSHOT_VCPU_X86_FPU_MAX_SIZE \
	(VMM_SNAPSHOT_VCPU_X86_FPU_HEADER_SIZE + VMM_SNAPSHOT_X86_FPU_AREA_MAX)

/* Image is XSAVE standard format (legacy + header + extended area). */
#define	VMM_SNAPSHOT_X86_FPU_F_XSAVE	UINT32_C(0x00000001)
#define	VMM_SNAPSHOT_X86_FPU_F_VALID	VMM_SNAPSHOT_X86_FPU_F_XSAVE

/* Bare FXSAVE image size and minimum XSAVE image size (legacy + header). */
#define	VMM_SNAPSHOT_X86_FPU_LEGACY_SIZE	512U
#define	VMM_SNAPSHOT_X86_FPU_XSTATE_MIN	576U

/*
 * User (XCR0-managed) XSAVE components: x87, SSE, AVX, MPX (2), AVX-512 (3),
 * PKRU, and AMX TILECFG/TILEDATA.  Supervisor (IA32_XSS-managed) components
 * are deliberately excluded; see the block comment above.
 */
#define	VMM_SNAPSHOT_X86_XSAVE_USER_MASK	UINT64_C(0x00000000000602ff)

struct vmm_snapshot_vcpu_x86_fpu {
	uint32_t	flags;
	uint32_t	area_length;
	uint64_t	xsave_bitmap;
	uint8_t		area[VMM_SNAPSHOT_X86_FPU_AREA_MAX];
};

int	vmm_snapshot_vcpu_x86_validate(
	    const struct vmm_snapshot_vcpu_x86 *);
int	vmm_snapshot_x86_xcr0_validate(uint64_t, uint64_t, bool);
int	vmm_snapshot_vcpu_x86_encode(const struct vmm_snapshot_vcpu_x86 *,
	    void *, size_t, size_t *);
int	vmm_snapshot_vcpu_x86_decode(const void *, size_t,
	    struct vmm_snapshot_vcpu_x86 *);
int	vmm_snapshot_vcpu_x86_event_from_runtime(
	    const struct vmm_event_state *, struct vmm_snapshot_vcpu_x86 *);
int	vmm_snapshot_vcpu_x86_event_to_runtime(
	    const struct vmm_snapshot_vcpu_x86 *, struct vmm_event_state *);
int	vmm_snapshot_vcpu_x86_fpu_validate(
	    const struct vmm_snapshot_vcpu_x86_fpu *);
int	vmm_snapshot_vcpu_x86_fpu_wire_validate(const void *, size_t);
int	vmm_snapshot_vcpu_x86_fpu_encode(
	    const struct vmm_snapshot_vcpu_x86_fpu *, void *, size_t,
	    size_t *);
int	vmm_snapshot_vcpu_x86_fpu_decode(const void *, size_t,
	    struct vmm_snapshot_vcpu_x86_fpu *);
int	vmm_snapshot_vcpu_x86_fpu_restore_validate(
	    const struct vmm_snapshot_vcpu_x86_fpu *, bool, uint64_t,
	    uint32_t);

#endif /* _AMD64_VMM_VMM_SNAPSHOT_X86_STATE_H_ */
