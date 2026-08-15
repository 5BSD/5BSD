/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _AMD64_VMM_VMM_EVENT_STATE_H_
#define	_AMD64_VMM_VMM_EVENT_STATE_H_

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdbool.h>
#include <stdint.h>
#endif

#define	VMM_EVENT_STATE_F_NMI_PENDING	UINT32_C(0x00000001)
#define	VMM_EVENT_STATE_F_EXTINT_PENDING	UINT32_C(0x00000002)
#define	VMM_EVENT_STATE_F_EXCEPTION_PENDING	UINT32_C(0x00000004)
#define	VMM_EVENT_STATE_F_EXCEPTION_ERROR	UINT32_C(0x00000008)
#define	VMM_EVENT_STATE_F_VALID	UINT32_C(0x0000000f)

/*
 * Private, architecture-adapter provenance.  Keep this value-domain separate
 * from machine/vmm.h: this object is an internal validation boundary, not a
 * public ABI or a native structure to serialize.  The kernel adapter performs
 * an explicit, exhaustive conversion in both directions.
 */
enum vmm_event_exception_class {
	VMM_EVENT_EXCEPTION_NONE = 0,
	VMM_EVENT_EXCEPTION_FAULT,
	VMM_EVENT_EXCEPTION_TRAP,
	VMM_EVENT_EXCEPTION_ICEBP,
	VMM_EVENT_EXCEPTION_TASK_SWITCH,
	VMM_EVENT_EXCEPTION_CLASS_LAST,
};

/*
 * A transient value object.  This is not a wire structure: VMS2 encoders
 * translate it into fixed-width architecture sections.
 */
struct vmm_event_state {
	uint32_t	flags;
	uint64_t	exitintinfo;
	uint32_t	exception_vector;
	uint32_t	exception_error;
	enum vmm_event_exception_class exception_class;
};

int	vmm_event_state_validate(const struct vmm_event_state *);
bool	vmm_event_state_equal(const struct vmm_event_state *,
	    const struct vmm_event_state *);
int	vmm_event_state_exception_intinfo(const struct vmm_event_state *,
	    uint64_t *);
int	vmm_event_capture_commit_validate(uint64_t, uint64_t, size_t,
	    size_t);
bool	vmm_event_range_valid(const void *, size_t);
bool	vmm_event_ranges_overlap(const void *, size_t, const void *, size_t);

#endif /* _AMD64_VMM_VMM_EVENT_STATE_H_ */
