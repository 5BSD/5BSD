/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/errno.h>
#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <string.h>
#endif

#include <dev/vmm/vmm_snapshot_envelope.h>
#include "vmm_snapshot_x86_state.h"

#define	VMM_SNAPSHOT_X86_DOUBLE_FAULT_VECTOR	8U
#define	VMM_SNAPSHOT_X86_XCR0_X87	UINT64_C(0x0000000000000001)
#define	VMM_SNAPSHOT_X86_XCR0_SSE	UINT64_C(0x0000000000000002)
#define	VMM_SNAPSHOT_X86_XCR0_YMM	UINT64_C(0x0000000000000004)
#define	VMM_SNAPSHOT_X86_XCR0_BNDREGS	UINT64_C(0x0000000000000008)
#define	VMM_SNAPSHOT_X86_XCR0_BNDCSR	UINT64_C(0x0000000000000010)
#define	VMM_SNAPSHOT_X86_XCR0_OPMASK	UINT64_C(0x0000000000000020)
#define	VMM_SNAPSHOT_X86_XCR0_ZMM_HI256	UINT64_C(0x0000000000000040)
#define	VMM_SNAPSHOT_X86_XCR0_HI16_ZMM	UINT64_C(0x0000000000000080)
#define	VMM_SNAPSHOT_X86_XCR0_AVX	(VMM_SNAPSHOT_X86_XCR0_X87 | \
	VMM_SNAPSHOT_X86_XCR0_SSE | VMM_SNAPSHOT_X86_XCR0_YMM)
#define	VMM_SNAPSHOT_X86_XCR0_MPX	(VMM_SNAPSHOT_X86_XCR0_BNDREGS | \
	VMM_SNAPSHOT_X86_XCR0_BNDCSR)
#define	VMM_SNAPSHOT_X86_XCR0_AVX512	(VMM_SNAPSHOT_X86_XCR0_OPMASK | \
	VMM_SNAPSHOT_X86_XCR0_ZMM_HI256 | VMM_SNAPSHOT_X86_XCR0_HI16_ZMM)
#define	VMM_SNAPSHOT_X86_XCR0_TILECFG	UINT64_C(0x0000000000020000)
#define	VMM_SNAPSHOT_X86_XCR0_TILEDATA	UINT64_C(0x0000000000040000)
#define	VMM_SNAPSHOT_X86_XCR0_AMX	(VMM_SNAPSHOT_X86_XCR0_TILECFG | \
	VMM_SNAPSHOT_X86_XCR0_TILEDATA)

/* Fixed offsets inside the FXSAVE legacy region and the XSAVE header. */
#define	VMM_SNAPSHOT_X86_FPU_MXCSR_OFF	24U
#define	VMM_SNAPSHOT_X86_FPU_MXCSR_MASK_OFF	28U
#define	VMM_SNAPSHOT_X86_FPU_XSTATE_BV_OFF	512U
#define	VMM_SNAPSHOT_X86_FPU_XCOMP_BV_OFF	520U
#define	VMM_SNAPSHOT_X86_FPU_HDR_RSRV_OFF	528U
#define	VMM_SNAPSHOT_X86_FPU_MXCSR_DEFAULT_MASK	UINT32_C(0x0000ffbf)

static int vmm_snapshot_exception_to_runtime(
    enum vmm_snapshot_x86_exception_class,
    enum vmm_event_exception_class *);
static int vmm_snapshot_event_to_runtime_value(
    const struct vmm_snapshot_vcpu_x86 *, struct vmm_event_state *);

static bool
vmm_snapshot_x86_exception_has_error(uint32_t vector)
{

	switch (vector) {
	case 10: /* #TS */
	case 11: /* #NP */
	case 12: /* #SS */
	case 13: /* #GP */
	case 14: /* #PF */
	case 17: /* #AC */
	case 21: /* #CP */
	case 29: /* #VC */
	case 30: /* #SX */
		return (true);
	default:
		return (false);
	}
}

/*
 * Validate the architectural XCR0 dependency graph and, when requested by a
 * restore caller, the destination's exact host-supported mask.  The value is
 * eventually loaded by load_xcr() in kernel context, so accepting an invalid
 * image here is not merely a guest-visible compatibility error: it can raise
 * #GP while the host is entering the guest.
 */
int
vmm_snapshot_x86_xcr0_validate(uint64_t value, uint64_t allowed,
    bool xsave_enabled)
{

	if ((value & VMM_SNAPSHOT_X86_XCR0_X87) == 0)
		return (EINVAL);
	if (!xsave_enabled)
		return (value == VMM_SNAPSHOT_X86_XCR0_X87 ? 0 : EINVAL);
	if ((value & ~allowed) != 0)
		return (EINVAL);
	if ((value & VMM_SNAPSHOT_X86_XCR0_YMM) != 0 &&
	    (value & VMM_SNAPSHOT_X86_XCR0_AVX) !=
	    VMM_SNAPSHOT_X86_XCR0_AVX)
		return (EINVAL);
	if ((value & VMM_SNAPSHOT_X86_XCR0_MPX) != 0 &&
	    (value & VMM_SNAPSHOT_X86_XCR0_MPX) !=
	    VMM_SNAPSHOT_X86_XCR0_MPX)
		return (EINVAL);
	if ((value & VMM_SNAPSHOT_X86_XCR0_AVX512) != 0 &&
	    (value & (VMM_SNAPSHOT_X86_XCR0_AVX |
	    VMM_SNAPSHOT_X86_XCR0_AVX512)) !=
	    (VMM_SNAPSHOT_X86_XCR0_AVX |
	    VMM_SNAPSHOT_X86_XCR0_AVX512))
		return (EINVAL);
	return (0);
}

int
vmm_snapshot_vcpu_x86_validate(const struct vmm_snapshot_vcpu_x86 *state)
{
	struct vmm_event_state event;
	bool error_valid, exception_pending;

	if (state == NULL || !vmm_snapshot_range_valid(state, sizeof(*state)) ||
	    (state->flags & ~VMM_SNAPSHOT_X86_F_VALID) != 0 ||
	    state->x2apic_state > 1 || state->exception_class <
	    VMM_SNAPSHOT_X86_EXCEPTION_NONE || state->exception_class >=
	    VMM_SNAPSHOT_X86_EXCEPTION_CLASS_LAST ||
	    vmm_snapshot_x86_xcr0_validate(state->guest_xcr0, UINT64_MAX,
	    true) != 0)
		return (EINVAL);
	exception_pending = (state->flags &
	    VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING) != 0;
	error_valid = (state->flags &
	    VMM_SNAPSHOT_X86_F_EXCEPTION_ERROR) != 0;
	if (!exception_pending && (error_valid || state->exception_class !=
	    VMM_SNAPSHOT_X86_EXCEPTION_NONE || state->exception_vector != 0 ||
	    state->exception_error != 0))
		return (EINVAL);
	if (exception_pending && (state->exception_class ==
	    VMM_SNAPSHOT_X86_EXCEPTION_NONE || state->exception_vector >= 32 ||
	    state->exception_vector == VMM_SNAPSHOT_X86_DOUBLE_FAULT_VECTOR ||
	    (error_valid && !vmm_snapshot_x86_exception_has_error(
	    state->exception_vector)) ||
	    (!error_valid && state->exception_error != 0) ||
	    ((state->exception_class == VMM_SNAPSHOT_X86_EXCEPTION_ICEBP ||
	    state->exception_class == VMM_SNAPSHOT_X86_EXCEPTION_TASK_SWITCH) &&
	    state->exception_vector != 1)))
		return (EINVAL);
	return (vmm_snapshot_event_to_runtime_value(state, &event));
}

int
vmm_snapshot_vcpu_x86_encode(const struct vmm_snapshot_vcpu_x86 *state,
    void *buffer, size_t capacity, size_t *written)
{
	uint8_t staging[VMM_SNAPSHOT_VCPU_X86_SIZE];
	int error;

	error = vmm_snapshot_vcpu_x86_validate(state);
	if (error != 0 || buffer == NULL || written == NULL ||
	    !vmm_snapshot_range_valid(state, sizeof(*state)) ||
	    !vmm_snapshot_range_valid(buffer, capacity) ||
	    !vmm_snapshot_range_valid(written, sizeof(*written)) ||
	    capacity < sizeof(staging) ||
	    vmm_snapshot_ranges_overlap(state, sizeof(*state), buffer,
	    sizeof(staging)) ||
	    vmm_snapshot_ranges_overlap(written, sizeof(*written), buffer,
	    sizeof(staging)) ||
	    vmm_snapshot_ranges_overlap(written, sizeof(*written), state,
	    sizeof(*state)))
		return (EINVAL);
	memset(staging, 0, sizeof(staging));
	le16enc(staging, VMM_SNAPSHOT_X86_STATE_VERSION);
	le16enc(staging + 2, sizeof(staging));
	le32enc(staging + 4, state->flags);
	le32enc(staging + 8, state->x2apic_state);
	le32enc(staging + 12, state->exception_class);
	le64enc(staging + 16, state->exitintinfo);
	le32enc(staging + 24, state->exception_vector);
	le32enc(staging + 28, state->exception_error);
	le64enc(staging + 32, state->guest_xcr0);
	le64enc(staging + 40, state->absolute_tsc);
	memmove(buffer, staging, sizeof(staging));
	*written = sizeof(staging);
	return (0);
}

int
vmm_snapshot_vcpu_x86_decode(const void *buffer, size_t length,
    struct vmm_snapshot_vcpu_x86 *state)
{
	struct vmm_snapshot_vcpu_x86 candidate;
	const uint8_t *wire;
	uint32_t exception_class;
	int error;

	if (buffer == NULL || state == NULL ||
	    !vmm_snapshot_range_valid(buffer, length) ||
	    !vmm_snapshot_range_valid(state, sizeof(*state)) ||
	    length != VMM_SNAPSHOT_VCPU_X86_SIZE ||
	    vmm_snapshot_ranges_overlap(buffer, length, state,
	    sizeof(*state)))
		return (EINVAL);
	wire = buffer;
	if (le16dec(wire) != VMM_SNAPSHOT_X86_STATE_VERSION ||
	    le16dec(wire + 2) != length || le64dec(wire + 48) != 0 ||
	    le64dec(wire + 56) != 0 || le64dec(wire + 64) != 0 ||
	    le64dec(wire + 72) != 0)
		return (EINVAL);
	exception_class = le32dec(wire + 12);
	if (exception_class >= VMM_SNAPSHOT_X86_EXCEPTION_CLASS_LAST)
		return (EINVAL);
	/* The fixed-width wire image has no C-structure padding. */
	memset(&candidate, 0, sizeof(candidate));
	candidate.flags = le32dec(wire + 4);
	candidate.x2apic_state = le32dec(wire + 8);
	candidate.exception_class =
	    (enum vmm_snapshot_x86_exception_class)exception_class;
	candidate.exitintinfo = le64dec(wire + 16);
	candidate.exception_vector = le32dec(wire + 24);
	candidate.exception_error = le32dec(wire + 28);
	candidate.guest_xcr0 = le64dec(wire + 32);
	candidate.absolute_tsc = le64dec(wire + 40);
	error = vmm_snapshot_vcpu_x86_validate(&candidate);
	if (error != 0)
		return (error);
	*state = candidate;
	return (0);
}

static int
vmm_snapshot_exception_from_runtime(enum vmm_event_exception_class source,
    enum vmm_snapshot_x86_exception_class *destination)
{

	switch (source) {
	case VMM_EVENT_EXCEPTION_NONE:
		*destination = VMM_SNAPSHOT_X86_EXCEPTION_NONE;
		break;
	case VMM_EVENT_EXCEPTION_FAULT:
		*destination = VMM_SNAPSHOT_X86_EXCEPTION_FAULT;
		break;
	case VMM_EVENT_EXCEPTION_TRAP:
		*destination = VMM_SNAPSHOT_X86_EXCEPTION_TRAP;
		break;
	case VMM_EVENT_EXCEPTION_ICEBP:
		*destination = VMM_SNAPSHOT_X86_EXCEPTION_ICEBP;
		break;
	case VMM_EVENT_EXCEPTION_TASK_SWITCH:
		*destination = VMM_SNAPSHOT_X86_EXCEPTION_TASK_SWITCH;
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

static int
vmm_snapshot_exception_to_runtime(
    enum vmm_snapshot_x86_exception_class source,
    enum vmm_event_exception_class *destination)
{

	switch (source) {
	case VMM_SNAPSHOT_X86_EXCEPTION_NONE:
		*destination = VMM_EVENT_EXCEPTION_NONE;
		break;
	case VMM_SNAPSHOT_X86_EXCEPTION_FAULT:
		*destination = VMM_EVENT_EXCEPTION_FAULT;
		break;
	case VMM_SNAPSHOT_X86_EXCEPTION_TRAP:
		*destination = VMM_EVENT_EXCEPTION_TRAP;
		break;
	case VMM_SNAPSHOT_X86_EXCEPTION_ICEBP:
		*destination = VMM_EVENT_EXCEPTION_ICEBP;
		break;
	case VMM_SNAPSHOT_X86_EXCEPTION_TASK_SWITCH:
		*destination = VMM_EVENT_EXCEPTION_TASK_SWITCH;
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

static int
vmm_snapshot_event_to_runtime_value(
    const struct vmm_snapshot_vcpu_x86 *state,
    struct vmm_event_state *candidate)
{
	int error;

	memset(candidate, 0, sizeof(*candidate));
	if ((state->flags & VMM_SNAPSHOT_X86_F_NMI_PENDING) != 0)
		candidate->flags |= VMM_EVENT_STATE_F_NMI_PENDING;
	if ((state->flags & VMM_SNAPSHOT_X86_F_EXTINT_PENDING) != 0)
		candidate->flags |= VMM_EVENT_STATE_F_EXTINT_PENDING;
	if ((state->flags & VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING) != 0)
		candidate->flags |= VMM_EVENT_STATE_F_EXCEPTION_PENDING;
	if ((state->flags & VMM_SNAPSHOT_X86_F_EXCEPTION_ERROR) != 0)
		candidate->flags |= VMM_EVENT_STATE_F_EXCEPTION_ERROR;
	candidate->exitintinfo = state->exitintinfo;
	candidate->exception_vector = state->exception_vector;
	candidate->exception_error = state->exception_error;
	error = vmm_snapshot_exception_to_runtime(state->exception_class,
	    &candidate->exception_class);
	if (error != 0)
		return (error);
	return (vmm_event_state_validate(candidate));
}

int
vmm_snapshot_vcpu_x86_event_from_runtime(
    const struct vmm_event_state *event,
    struct vmm_snapshot_vcpu_x86 *state)
{
	struct vmm_snapshot_vcpu_x86 candidate;
	int error;

	if (event == NULL || state == NULL ||
	    !vmm_snapshot_range_valid(event, sizeof(*event)) ||
	    !vmm_snapshot_range_valid(state, sizeof(*state)) ||
	    vmm_snapshot_ranges_overlap(event, sizeof(*event), state,
	    sizeof(*state)))
		return (EINVAL);
	error = vmm_event_state_validate(event);
	if (error != 0)
		return (error);
	candidate = *state;
	candidate.flags = 0;
	if ((event->flags & VMM_EVENT_STATE_F_NMI_PENDING) != 0)
		candidate.flags |= VMM_SNAPSHOT_X86_F_NMI_PENDING;
	if ((event->flags & VMM_EVENT_STATE_F_EXTINT_PENDING) != 0)
		candidate.flags |= VMM_SNAPSHOT_X86_F_EXTINT_PENDING;
	if ((event->flags & VMM_EVENT_STATE_F_EXCEPTION_PENDING) != 0)
		candidate.flags |= VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING;
	if ((event->flags & VMM_EVENT_STATE_F_EXCEPTION_ERROR) != 0)
		candidate.flags |= VMM_SNAPSHOT_X86_F_EXCEPTION_ERROR;
	candidate.exitintinfo = event->exitintinfo;
	candidate.exception_vector = event->exception_vector;
	candidate.exception_error = event->exception_error;
	error = vmm_snapshot_exception_from_runtime(event->exception_class,
	    &candidate.exception_class);
	if (error == 0)
		error = vmm_snapshot_vcpu_x86_validate(&candidate);
	if (error == 0)
		*state = candidate;
	return (error);
}

int
vmm_snapshot_vcpu_x86_event_to_runtime(
    const struct vmm_snapshot_vcpu_x86 *state,
    struct vmm_event_state *event)
{
	struct vmm_event_state candidate;
	int error;

	if (state == NULL || event == NULL ||
	    !vmm_snapshot_range_valid(state, sizeof(*state)) ||
	    !vmm_snapshot_range_valid(event, sizeof(*event)) ||
	    vmm_snapshot_ranges_overlap(state, sizeof(*state), event,
	    sizeof(*event)))
		return (EINVAL);
	error = vmm_snapshot_vcpu_x86_validate(state);
	if (error != 0)
		return (error);
	error = vmm_snapshot_event_to_runtime_value(state, &candidate);
	if (error == 0)
		*event = candidate;
	return (error);
}

/*
 * Shared content validation for the guest FPU/XSAVE record.  Operates
 * directly on the save-area bytes so the wire validator can run to
 * completion before a decoder mutates any destination memory, and so the
 * struct validator applies exactly the same rules.
 */
static int
vmm_snapshot_x86_fpu_area_validate(uint32_t flags, uint64_t bitmap,
    const uint8_t *area, uint32_t area_length)
{
	uint64_t xcomp_bv, xstate_bv;
	uint32_t mxcsr, mxcsr_mask;

	if ((flags & ~VMM_SNAPSHOT_X86_FPU_F_VALID) != 0 ||
	    area == NULL || !vmm_snapshot_range_valid(area, area_length) ||
	    area_length < VMM_SNAPSHOT_X86_FPU_LEGACY_SIZE)
		return (EINVAL);
	/*
	 * An MXCSR image with reserved bits set raises #GP when it is loaded
	 * back into the CPU, so reject it here rather than while entering
	 * the guest.  A zero stored mask means the FXSAVE default.
	 */
	mxcsr = le32dec(area + VMM_SNAPSHOT_X86_FPU_MXCSR_OFF);
	mxcsr_mask = le32dec(area + VMM_SNAPSHOT_X86_FPU_MXCSR_MASK_OFF);
	if (mxcsr_mask == 0)
		mxcsr_mask = VMM_SNAPSHOT_X86_FPU_MXCSR_DEFAULT_MASK;
	if ((mxcsr & ~mxcsr_mask) != 0)
		return (EINVAL);
	if ((flags & VMM_SNAPSHOT_X86_FPU_F_XSAVE) == 0) {
		if (bitmap != 0 ||
		    area_length != VMM_SNAPSHOT_X86_FPU_LEGACY_SIZE)
			return (EINVAL);
		return (0);
	}
	if (area_length < VMM_SNAPSHOT_X86_FPU_XSTATE_MIN ||
	    area_length > VMM_SNAPSHOT_X86_FPU_AREA_MAX)
		return (EINVAL);
	/*
	 * The bitmap is pinned to user (XCR0-managed) components; a
	 * supervisor (IA32_XSS-managed) bit fails closed.  See the record's
	 * block comment in vmm_snapshot_x86_state.h.
	 */
	if ((bitmap & ~VMM_SNAPSHOT_X86_XSAVE_USER_MASK) != 0 ||
	    vmm_snapshot_x86_xcr0_validate(bitmap,
	    VMM_SNAPSHOT_X86_XSAVE_USER_MASK, true) != 0)
		return (EINVAL);
	if ((bitmap & VMM_SNAPSHOT_X86_XCR0_AMX) != 0 &&
	    (bitmap & VMM_SNAPSHOT_X86_XCR0_AMX) !=
	    VMM_SNAPSHOT_X86_XCR0_AMX)
		return (EINVAL);
	xstate_bv = le64dec(area + VMM_SNAPSHOT_X86_FPU_XSTATE_BV_OFF);
	xcomp_bv = le64dec(area + VMM_SNAPSHOT_X86_FPU_XCOMP_BV_OFF);
	/* Standard format only; a compacted image is not portable. */
	if (xcomp_bv != 0 || (xstate_bv & ~bitmap) != 0)
		return (EINVAL);
	/* XRSTOR #GPs on nonzero XSAVE header reserved bytes. */
	for (uint32_t i = VMM_SNAPSHOT_X86_FPU_HDR_RSRV_OFF;
	    i < VMM_SNAPSHOT_X86_FPU_XSTATE_MIN; i++) {
		if (area[i] != 0)
			return (EINVAL);
	}
	return (0);
}

int
vmm_snapshot_vcpu_x86_fpu_validate(
    const struct vmm_snapshot_vcpu_x86_fpu *state)
{
	int error;

	if (state == NULL || !vmm_snapshot_range_valid(state, sizeof(*state)))
		return (EINVAL);
	if (state->area_length > VMM_SNAPSHOT_X86_FPU_AREA_MAX)
		return (EINVAL);
	error = vmm_snapshot_x86_fpu_area_validate(state->flags,
	    state->xsave_bitmap, state->area, state->area_length);
	if (error != 0)
		return (error);
	/* Bytes beyond the image must be canonical zero. */
	for (uint32_t i = state->area_length;
	    i < VMM_SNAPSHOT_X86_FPU_AREA_MAX; i++) {
		if (state->area[i] != 0)
			return (EINVAL);
	}
	return (0);
}

/*
 * Validate a complete wire record without producing a decoded value.  The
 * decoder and the transaction codec's first (non-publishing) pass both use
 * this so every restore-side check completes before destination mutation.
 */
int
vmm_snapshot_vcpu_x86_fpu_wire_validate(const void *buffer, size_t length)
{
	const uint8_t *wire;
	uint32_t area_length;

	if (buffer == NULL || !vmm_snapshot_range_valid(buffer, length) ||
	    length < VMM_SNAPSHOT_VCPU_X86_FPU_HEADER_SIZE ||
	    length > VMM_SNAPSHOT_VCPU_X86_FPU_MAX_SIZE)
		return (EINVAL);
	wire = buffer;
	if (le16dec(wire) != VMM_SNAPSHOT_X86_FPU_VERSION ||
	    le16dec(wire + 2) != length || le32dec(wire + 12) != 0 ||
	    le64dec(wire + 24) != 0 || le64dec(wire + 32) != 0 ||
	    le64dec(wire + 40) != 0)
		return (EINVAL);
	area_length = le32dec(wire + 8);
	if (area_length !=
	    length - VMM_SNAPSHOT_VCPU_X86_FPU_HEADER_SIZE)
		return (EINVAL);
	return (vmm_snapshot_x86_fpu_area_validate(le32dec(wire + 4),
	    le64dec(wire + 16),
	    wire + VMM_SNAPSHOT_VCPU_X86_FPU_HEADER_SIZE, area_length));
}

int
vmm_snapshot_vcpu_x86_fpu_encode(
    const struct vmm_snapshot_vcpu_x86_fpu *state, void *buffer,
    size_t capacity, size_t *written)
{
	uint8_t *wire;
	size_t total;
	int error;

	error = vmm_snapshot_vcpu_x86_fpu_validate(state);
	if (error != 0)
		return (error);
	total = VMM_SNAPSHOT_VCPU_X86_FPU_HEADER_SIZE + state->area_length;
	if (buffer == NULL || written == NULL ||
	    !vmm_snapshot_range_valid(buffer, capacity) ||
	    !vmm_snapshot_range_valid(written, sizeof(*written)) ||
	    capacity < total ||
	    vmm_snapshot_ranges_overlap(state, sizeof(*state), buffer,
	    total) ||
	    vmm_snapshot_ranges_overlap(written, sizeof(*written), buffer,
	    total) ||
	    vmm_snapshot_ranges_overlap(written, sizeof(*written), state,
	    sizeof(*state)))
		return (EINVAL);
	/*
	 * Unlike the fixed 80-byte vCPU record this image is too large for a
	 * stack staging buffer in kernel context.  All validation is
	 * complete, so writing the destination directly cannot fail partway
	 * through for a reason the staging copy would have prevented.
	 */
	wire = buffer;
	le16enc(wire, VMM_SNAPSHOT_X86_FPU_VERSION);
	le16enc(wire + 2, total);
	le32enc(wire + 4, state->flags);
	le32enc(wire + 8, state->area_length);
	le32enc(wire + 12, 0);
	le64enc(wire + 16, state->xsave_bitmap);
	le64enc(wire + 24, 0);
	le64enc(wire + 32, 0);
	le64enc(wire + 40, 0);
	memmove(wire + VMM_SNAPSHOT_VCPU_X86_FPU_HEADER_SIZE, state->area,
	    state->area_length);
	*written = total;
	return (0);
}

int
vmm_snapshot_vcpu_x86_fpu_decode(const void *buffer, size_t length,
    struct vmm_snapshot_vcpu_x86_fpu *state)
{
	const uint8_t *wire;
	int error;

	if (buffer == NULL || state == NULL ||
	    !vmm_snapshot_range_valid(buffer, length) ||
	    !vmm_snapshot_range_valid(state, sizeof(*state)) ||
	    vmm_snapshot_ranges_overlap(buffer, length, state,
	    sizeof(*state)))
		return (EINVAL);
	/*
	 * The record is too large for an on-stack candidate in kernel
	 * context, so instead of decode-then-validate the complete wire
	 * image is validated first and the destination is only written on
	 * the success path.
	 */
	error = vmm_snapshot_vcpu_x86_fpu_wire_validate(buffer, length);
	if (error != 0)
		return (error);
	wire = buffer;
	memset(state, 0, sizeof(*state));
	state->flags = le32dec(wire + 4);
	state->area_length = le32dec(wire + 8);
	state->xsave_bitmap = le64dec(wire + 16);
	memcpy(state->area, wire + VMM_SNAPSHOT_VCPU_X86_FPU_HEADER_SIZE,
	    state->area_length);
	return (0);
}

/*
 * Capability-aware restore admission.  The destination describes the save
 * area the runtime will actually reload with XRSTOR/FXRSTOR:
 * dest_xsave_enabled and dest_xsave_mask are the host's XSAVE state
 * (use_xsave / xsave_mask) and dest_area_size is the allocated guestfpu
 * extent.  Every rejection happens before the caller touches guestfpu:
 *
 *  - an XSAVE image whose XSTATE_BV names a component outside the
 *    destination's feature mask would be silently ignored by XRSTOR
 *    (state loss), so it is rejected with EOPNOTSUPP;
 *  - an image larger than the destination save area cannot be landed
 *    without truncation, so it is rejected with EOPNOTSUPP;
 *  - an XSAVE image restricted to x87/SSE may land on a non-XSAVE
 *    destination (legacy region only), and a bare FXSAVE image may land on
 *    an XSAVE destination (the caller synthesizes a standard-format header
 *    with XSTATE_BV = x87|SSE); anything else across that capability
 *    boundary is rejected;
 *  - a destination mask containing non-user (supervisor) components fails
 *    closed until the record format explicitly supports them.
 */
int
vmm_snapshot_vcpu_x86_fpu_restore_validate(
    const struct vmm_snapshot_vcpu_x86_fpu *state, bool dest_xsave_enabled,
    uint64_t dest_xsave_mask, uint32_t dest_area_size)
{
	uint64_t xstate_bv;
	int error;

	error = vmm_snapshot_vcpu_x86_fpu_validate(state);
	if (error != 0)
		return (error);
	if (dest_area_size < VMM_SNAPSHOT_X86_FPU_LEGACY_SIZE)
		return (EINVAL);
	if (dest_xsave_enabled) {
		if ((dest_xsave_mask & VMM_SNAPSHOT_X86_XCR0_X87) == 0 ||
		    (dest_xsave_mask & ~VMM_SNAPSHOT_X86_XSAVE_USER_MASK) != 0)
			return (EOPNOTSUPP);
		if (dest_area_size < VMM_SNAPSHOT_X86_FPU_XSTATE_MIN)
			return (EINVAL);
	}
	if ((state->flags & VMM_SNAPSHOT_X86_FPU_F_XSAVE) == 0)
		return (0);
	xstate_bv = le64dec(state->area +
	    VMM_SNAPSHOT_X86_FPU_XSTATE_BV_OFF);
	if (!dest_xsave_enabled) {
		if ((xstate_bv & ~(VMM_SNAPSHOT_X86_XCR0_X87 |
		    VMM_SNAPSHOT_X86_XCR0_SSE)) != 0)
			return (EOPNOTSUPP);
		return (0);
	}
	if ((xstate_bv & ~dest_xsave_mask) != 0)
		return (EOPNOTSUPP);
	if (state->area_length > dest_area_size)
		return (EOPNOTSUPP);
	return (0);
}
