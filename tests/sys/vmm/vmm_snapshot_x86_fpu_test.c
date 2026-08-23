/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Model tests for the guest FPU/XSAVE snapshot record
 * (VMM_SNAPSHOT_SECTION_VCPU_X86_FPU): round trip, truncation, version,
 * and capability-mismatch rejection, plus the kernel-common transaction's
 * fail-closed handling of checkpoints that lack the record.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/endian.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include <dev/vmm/vmm_address_range.h>
#include <dev/vmm/vmm_snapshot_envelope.h>
#include <dev/vmm/vmm_snapshot_state.h>
#include "../../../sys/amd64/vmm/vmm_event_state.h"
#include "../../../sys/amd64/vmm/vmm_snapshot_x86_state.h"
#include "../../../sys/amd64/vmm/vmm_snapshot_x86_transaction.h"

#include "../../../sys/dev/vmm/vmm_snapshot_envelope.c"
#include "../../../sys/dev/vmm/vmm_snapshot_state.c"
#include "../../../sys/amd64/vmm/vmm_intinfo.c"
#include "../../../sys/amd64/vmm/vmm_event_state.c"
#include "../../../sys/amd64/vmm/vmm_snapshot_x86_state.c"
#include "../../../sys/amd64/vmm/vmm_snapshot_x86_transaction.c"

#define	FPU_X87		UINT64_C(0x1)
#define	FPU_SSE		UINT64_C(0x2)
#define	FPU_YMM		UINT64_C(0x4)
#define	FPU_AVX_MASK	(FPU_X87 | FPU_SSE | FPU_YMM)
#define	FPU_PT		UINT64_C(0x100)		/* supervisor (IA32_XSS) */

#define	FPU_MXCSR_OFF		24U
#define	FPU_MXCSR_MASK_OFF	28U
#define	FPU_XSTATE_BV_OFF	512U
#define	FPU_XCOMP_BV_OFF	520U
#define	FPU_AVX_AREA_SIZE	832U

/* A canonical XSAVE standard-format image with dirty x87/SSE/AVX state. */
static void
fpu_xsave_init(struct vmm_snapshot_vcpu_x86_fpu *fpu)
{

	memset(fpu, 0, sizeof(*fpu));
	fpu->flags = VMM_SNAPSHOT_X86_FPU_F_XSAVE;
	fpu->area_length = FPU_AVX_AREA_SIZE;
	fpu->xsave_bitmap = FPU_AVX_MASK;
	le32enc(fpu->area + FPU_MXCSR_OFF, 0x1f80);
	le32enc(fpu->area + FPU_MXCSR_MASK_OFF, 0xffbf);
	/* Legacy x87/XMM register pattern. */
	for (unsigned i = 32; i < FPU_XSTATE_BV_OFF; i++)
		fpu->area[i] = (uint8_t)(0xb0 ^ i);
	le64enc(fpu->area + FPU_XSTATE_BV_OFF, FPU_AVX_MASK);
	/* YMM_Hi128 extended-region pattern. */
	for (unsigned i = VMM_SNAPSHOT_X86_FPU_XSTATE_MIN;
	    i < FPU_AVX_AREA_SIZE; i++)
		fpu->area[i] = (uint8_t)(0x5a ^ i);
}

/* A bare FXSAVE image from a non-XSAVE source. */
static void
fpu_fxsave_init(struct vmm_snapshot_vcpu_x86_fpu *fpu)
{

	memset(fpu, 0, sizeof(*fpu));
	fpu->area_length = VMM_SNAPSHOT_X86_FPU_LEGACY_SIZE;
	le32enc(fpu->area + FPU_MXCSR_OFF, 0x1f80);
	le32enc(fpu->area + FPU_MXCSR_MASK_OFF, 0xffbf);
	for (unsigned i = 32; i < VMM_SNAPSHOT_X86_FPU_LEGACY_SIZE; i++)
		fpu->area[i] = (uint8_t)(0xc3 ^ i);
}

/* Independent XCR0 component constants (x86 CPUID leaf 0xD spec). */
#define	XCR0_X87	UINT64_C(0x1)
#define	XCR0_SSE	UINT64_C(0x2)
#define	XCR0_YMM	UINT64_C(0x4)
#define	XCR0_BNDREGS	UINT64_C(0x8)
#define	XCR0_BNDCSR	UINT64_C(0x10)
#define	XCR0_OPMASK	UINT64_C(0x20)
#define	XCR0_ZMM_HI256	UINT64_C(0x40)
#define	XCR0_HI16_ZMM	UINT64_C(0x80)
#define	XCR0_PKRU	UINT64_C(0x200)
#define	XCR0_TILECFG	UINT64_C(0x20000)
#define	XCR0_TILEDATA	UINT64_C(0x40000)

/* A syntactically valid, minimal x86 vCPU state (x87-only XCR0, no events). */
static void
x86_state_init(struct vmm_snapshot_vcpu_x86 *s)
{

	memset(s, 0, sizeof(*s));
	s->guest_xcr0 = XCR0_X87;
	s->exception_class = VMM_SNAPSHOT_X86_EXCEPTION_NONE;
}

static void
stage_init(struct vmm_snapshot_x86_vcpu_stage *st, uint32_t instance)
{

	memset(st, 0, sizeof(*st));
	st->instance = instance;
	st->common.next_pc = UINT64_C(0x1000) + instance;
	x86_state_init(&st->x86);
	fpu_fxsave_init(&st->fpu);
}

struct env_section {
	uint16_t	type;
	uint16_t	flags;
	uint32_t	instance;
	const uint8_t	*payload;
	size_t		length;
};

static int
build_env(uint8_t *wire, size_t capacity, const struct env_section *secs,
    size_t n, size_t *length)
{
	struct vmm_snapshot_envelope_builder builder;
	int error;

	error = vmm_snapshot_envelope_builder_init(&builder, wire, capacity);
	for (size_t i = 0; error == 0 && i < n; i++)
		error = vmm_snapshot_envelope_add(&builder, secs[i].type,
		    secs[i].flags, secs[i].instance, secs[i].payload,
		    secs[i].length);
	if (error == 0)
		error = vmm_snapshot_envelope_finalize(&builder, length);
	return (error);
}

ATF_TC_WITHOUT_HEAD(fpu_round_trip);
ATF_TC_BODY(fpu_round_trip, tc)
{
	struct vmm_snapshot_vcpu_x86_fpu decoded, state;
	uint8_t wire[VMM_SNAPSHOT_VCPU_X86_FPU_MAX_SIZE];
	size_t written;

	(void)tc;
	fpu_xsave_init(&state);
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_fpu_validate(&state), 0);
	written = 0;
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_fpu_encode(&state, wire,
	    sizeof(wire), &written), 0);
	ATF_CHECK_EQ(written, VMM_SNAPSHOT_VCPU_X86_FPU_HEADER_SIZE +
	    FPU_AVX_AREA_SIZE);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_wire_validate(wire, written),
	    0);
	memset(&decoded, 0xa5, sizeof(decoded));
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_fpu_decode(wire, written,
	    &decoded), 0);
	ATF_CHECK_EQ(memcmp(&decoded, &state, sizeof(state)), 0);

	fpu_fxsave_init(&state);
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_fpu_encode(&state, wire,
	    sizeof(wire), &written), 0);
	ATF_CHECK_EQ(written, VMM_SNAPSHOT_VCPU_X86_FPU_HEADER_SIZE +
	    VMM_SNAPSHOT_X86_FPU_LEGACY_SIZE);
	memset(&decoded, 0xa5, sizeof(decoded));
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_fpu_decode(wire, written,
	    &decoded), 0);
	ATF_CHECK_EQ(memcmp(&decoded, &state, sizeof(state)), 0);

	/* Encode rejects an undersized buffer without touching it. */
	memset(wire, 0x77, sizeof(wire));
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_encode(&state, wire,
	    VMM_SNAPSHOT_VCPU_X86_FPU_HEADER_SIZE +
	    VMM_SNAPSHOT_X86_FPU_LEGACY_SIZE - 1, &written), EINVAL);
	for (unsigned i = 0; i < sizeof(wire); i++)
		ATF_REQUIRE_EQ(wire[i], 0x77);
}

ATF_TC_WITHOUT_HEAD(fpu_reject_truncation);
ATF_TC_BODY(fpu_reject_truncation, tc)
{
	struct vmm_snapshot_vcpu_x86_fpu decoded, decoded_before, state;
	uint8_t wire[VMM_SNAPSHOT_VCPU_X86_FPU_MAX_SIZE + 1];
	size_t written;

	(void)tc;
	fpu_xsave_init(&state);
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_fpu_encode(&state, wire,
	    sizeof(wire), &written), 0);
	memset(&decoded, 0xa5, sizeof(decoded));
	decoded_before = decoded;

	/* Truncated, oversized, and header-only inputs fail pre-mutation. */
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_decode(wire, written - 1,
	    &decoded), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_decode(wire, written + 1,
	    &decoded), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_decode(wire,
	    VMM_SNAPSHOT_VCPU_X86_FPU_HEADER_SIZE - 1, &decoded), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_decode(wire, 0, &decoded),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_decode(wire,
	    VMM_SNAPSHOT_VCPU_X86_FPU_MAX_SIZE + 1, &decoded), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_decode(NULL, written,
	    &decoded), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_decode(wire, written, NULL),
	    EINVAL);
	/* An in-place decode is an aliasing hazard, not a convenience. */
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_decode(wire, written,
	    (struct vmm_snapshot_vcpu_x86_fpu *)(void *)wire), EINVAL);

	/* A total-length field disagreeing with the input is rejected. */
	le16enc(wire + 2, written - 1);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_decode(wire, written,
	    &decoded), EINVAL);
	le16enc(wire + 2, written);

	/* An area_length field disagreeing with the total is rejected. */
	le32enc(wire + 8, FPU_AVX_AREA_SIZE - 1);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_decode(wire, written,
	    &decoded), EINVAL);
	le32enc(wire + 8, FPU_AVX_AREA_SIZE);

	ATF_CHECK_EQ(memcmp(&decoded, &decoded_before, sizeof(decoded)), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_fpu_decode(wire, written,
	    &decoded), 0);
	ATF_CHECK_EQ(memcmp(&decoded, &state, sizeof(state)), 0);
}

ATF_TC_WITHOUT_HEAD(fpu_reject_version);
ATF_TC_BODY(fpu_reject_version, tc)
{
	struct vmm_snapshot_vcpu_x86_fpu decoded, decoded_before, state;
	uint8_t wire[VMM_SNAPSHOT_VCPU_X86_FPU_MAX_SIZE];
	size_t written;

	(void)tc;
	fpu_xsave_init(&state);
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_fpu_encode(&state, wire,
	    sizeof(wire), &written), 0);
	memset(&decoded, 0xa5, sizeof(decoded));
	decoded_before = decoded;

	le16enc(wire, VMM_SNAPSHOT_X86_FPU_VERSION + 1);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_decode(wire, written,
	    &decoded), EINVAL);
	le16enc(wire, 0);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_decode(wire, written,
	    &decoded), EINVAL);
	le16enc(wire, VMM_SNAPSHOT_X86_FPU_VERSION);

	/* Reserved header fields must decode as zero. */
	le32enc(wire + 12, 1);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_decode(wire, written,
	    &decoded), EINVAL);
	le32enc(wire + 12, 0);
	le64enc(wire + 40, 1);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_decode(wire, written,
	    &decoded), EINVAL);
	le64enc(wire + 40, 0);

	/* Unknown flag bits are not silently ignored. */
	le32enc(wire + 4, VMM_SNAPSHOT_X86_FPU_F_XSAVE | 0x2);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_decode(wire, written,
	    &decoded), EINVAL);
	le32enc(wire + 4, VMM_SNAPSHOT_X86_FPU_F_XSAVE);

	ATF_CHECK_EQ(memcmp(&decoded, &decoded_before, sizeof(decoded)), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_fpu_decode(wire, written,
	    &decoded), 0);
}

ATF_TC_WITHOUT_HEAD(fpu_validate_edges);
ATF_TC_BODY(fpu_validate_edges, tc)
{
	struct vmm_snapshot_vcpu_x86_fpu state;

	(void)tc;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_validate(NULL), EINVAL);

	/* Supervisor (IA32_XSS) component bits fail closed. */
	fpu_xsave_init(&state);
	state.xsave_bitmap |= FPU_PT;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_validate(&state), EINVAL);

	/* XSTATE_BV must be covered by the recorded bitmap. */
	fpu_xsave_init(&state);
	le64enc(state.area + FPU_XSTATE_BV_OFF, FPU_AVX_MASK | 0x8);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_validate(&state), EINVAL);

	/* Compacted-format images are not portable. */
	fpu_xsave_init(&state);
	le64enc(state.area + FPU_XCOMP_BV_OFF, UINT64_C(1) << 63);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_validate(&state), EINVAL);

	/* Nonzero XSAVE header reserved bytes would #GP on XRSTOR. */
	fpu_xsave_init(&state);
	state.area[FPU_XCOMP_BV_OFF + 8] = 1;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_validate(&state), EINVAL);

	/* So would MXCSR reserved bits. */
	fpu_xsave_init(&state);
	le32enc(state.area + FPU_MXCSR_OFF, 0xffff0000);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_validate(&state), EINVAL);

	/* AVX requires SSE in the dependency graph. */
	fpu_xsave_init(&state);
	state.xsave_bitmap = FPU_X87 | FPU_YMM;
	le64enc(state.area + FPU_XSTATE_BV_OFF, FPU_X87);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_validate(&state), EINVAL);

	/* Bytes beyond the image must be canonical zero. */
	fpu_xsave_init(&state);
	state.area[state.area_length] = 1;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_validate(&state), EINVAL);

	/* An XSAVE image must at least hold legacy region plus header. */
	fpu_xsave_init(&state);
	state.area_length = VMM_SNAPSHOT_X86_FPU_XSTATE_MIN - 1;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_validate(&state), EINVAL);

	/* A bare FXSAVE image is exactly 512 bytes with a zero bitmap. */
	fpu_fxsave_init(&state);
	state.area_length = VMM_SNAPSHOT_X86_FPU_LEGACY_SIZE + 1;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_validate(&state), EINVAL);
	fpu_fxsave_init(&state);
	state.xsave_bitmap = FPU_X87;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_validate(&state), EINVAL);
	fpu_fxsave_init(&state);
	state.flags = 0x2;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_validate(&state), EINVAL);
}

ATF_TC_WITHOUT_HEAD(fpu_reject_capability_mismatch);
ATF_TC_BODY(fpu_reject_capability_mismatch, tc)
{
	struct vmm_snapshot_vcpu_x86_fpu state;

	(void)tc;
	fpu_xsave_init(&state);

	/* Identical destination admits the record. */
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_restore_validate(&state, true,
	    FPU_AVX_MASK, FPU_AVX_AREA_SIZE), 0);
	/* A larger destination save area is harmless. */
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_restore_validate(&state, true,
	    FPU_AVX_MASK, VMM_SNAPSHOT_X86_FPU_AREA_MAX), 0);

	/* Destination lacking a component named by XSTATE_BV: rejected. */
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_restore_validate(&state, true,
	    FPU_X87 | FPU_SSE, FPU_AVX_AREA_SIZE), EOPNOTSUPP);
	/* Destination save area smaller than the image: rejected. */
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_restore_validate(&state, true,
	    FPU_AVX_MASK, FPU_AVX_AREA_SIZE - 1), EOPNOTSUPP);
	/* Destination without XSAVE cannot represent live AVX state. */
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_restore_validate(&state, false,
	    0, VMM_SNAPSHOT_X86_FPU_LEGACY_SIZE), EOPNOTSUPP);
	/* A supervisor component in the destination mask fails closed. */
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_restore_validate(&state, true,
	    FPU_AVX_MASK | FPU_PT, FPU_AVX_AREA_SIZE), EOPNOTSUPP);

	/*
	 * An XSAVE image whose XSTATE_BV is confined to x87/SSE carries its
	 * complete state in the legacy region and may land on a non-XSAVE
	 * destination.
	 */
	fpu_xsave_init(&state);
	le64enc(state.area + FPU_XSTATE_BV_OFF, FPU_X87 | FPU_SSE);
	for (unsigned i = VMM_SNAPSHOT_X86_FPU_XSTATE_MIN;
	    i < FPU_AVX_AREA_SIZE; i++)
		state.area[i] = 0;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_restore_validate(&state, false,
	    0, VMM_SNAPSHOT_X86_FPU_LEGACY_SIZE), 0);

	/* A bare FXSAVE image lands on either destination kind. */
	fpu_fxsave_init(&state);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_restore_validate(&state, false,
	    0, VMM_SNAPSHOT_X86_FPU_LEGACY_SIZE), 0);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_restore_validate(&state, true,
	    FPU_AVX_MASK, FPU_AVX_AREA_SIZE), 0);
	/* But not on a destination area too small to hold it. */
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_restore_validate(&state, false,
	    0, VMM_SNAPSHOT_X86_FPU_LEGACY_SIZE - 1), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_restore_validate(&state, true,
	    FPU_AVX_MASK, VMM_SNAPSHOT_X86_FPU_XSTATE_MIN - 1), EINVAL);
}

ATF_TC_WITHOUT_HEAD(fpu_transaction_contract);
ATF_TC_BODY(fpu_transaction_contract, tc)
{
	struct vmm_snapshot_envelope_builder builder;
	struct vmm_snapshot_vm_common vm = { .max_vcpus = 4, .vcpu_count = 1 };
	struct vmm_snapshot_x86_transaction transaction = {
	    .vm = { .max_vcpus = 4, .vcpu_count = 1 },
	    .vcpu_count = 1,
	};
	struct vmm_snapshot_x86_vcpu_stage decoded, decoded_before, stage;
	struct vmm_snapshot_x86_transaction decoded_transaction, tx_before;
	uint8_t payload[128];
	uint8_t wire[2 * VMM_SNAPSHOT_VCPU_X86_FPU_MAX_SIZE];
	size_t capacity, fpu_payload, length, written;

	(void)tc;
	memset(&stage, 0, sizeof(stage));
	stage.instance = 2;
	stage.common.next_pc = 0x1000;
	stage.x86.guest_xcr0 = 1;
	fpu_xsave_init(&stage.fpu);

	ATF_REQUIRE_EQ(vmm_snapshot_x86_transaction_size(1, &capacity), 0);
	ATF_REQUIRE(capacity <= sizeof(wire));
	ATF_REQUIRE_EQ(vmm_snapshot_x86_transaction_encode(&transaction,
	    &stage, 1, wire, sizeof(wire), &length), 0);
	memset(&decoded, 0xa5, sizeof(decoded));
	memset(&decoded_transaction, 0x5a, sizeof(decoded_transaction));
	ATF_REQUIRE_EQ(vmm_snapshot_x86_transaction_decode(wire, length,
	    &decoded, 1, &decoded_transaction), 0);
	ATF_CHECK_EQ(memcmp(&decoded, &stage, sizeof(stage)), 0);
	ATF_CHECK_EQ(decoded_transaction.vcpu_count, 1);

	/* Truncation is rejected with the destination untouched. */
	memset(&decoded, 0xa5, sizeof(decoded));
	memset(&decoded_transaction, 0x5a, sizeof(decoded_transaction));
	decoded_before = decoded;
	tx_before = decoded_transaction;
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_decode(wire, length - 1,
	    &decoded, 1, &decoded_transaction), EINVAL);
	ATF_CHECK_EQ(memcmp(&decoded, &decoded_before, sizeof(decoded)), 0);
	ATF_CHECK_EQ(memcmp(&decoded_transaction, &tx_before,
	    sizeof(tx_before)), 0);

	/* A corrupted FPU record version inside the envelope is rejected. */
	fpu_payload = VMM_SNAPSHOT_VCPU_X86_FPU_HEADER_SIZE +
	    stage.fpu.area_length;
	le16enc(wire + length - fpu_payload,
	    VMM_SNAPSHOT_X86_FPU_VERSION + 1);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_decode(wire, length,
	    &decoded, 1, &decoded_transaction), EINVAL);
	ATF_CHECK_EQ(memcmp(&decoded, &decoded_before, sizeof(decoded)), 0);
	le16enc(wire + length - fpu_payload, VMM_SNAPSHOT_X86_FPU_VERSION);
	ATF_REQUIRE_EQ(vmm_snapshot_x86_transaction_decode(wire, length,
	    &decoded, 1, &decoded_transaction), 0);

	/*
	 * A transaction without the FPU section — the pre-record wire format
	 * that silently lost vector state — is rejected rather than
	 * restored.
	 */
	ATF_REQUIRE_EQ(vmm_snapshot_vm_common_encode(&vm, payload,
	    sizeof(payload), &written), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_builder_init(&builder, wire,
	    sizeof(wire)), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&builder,
	    VMM_SNAPSHOT_SECTION_VM_COMMON, VMM_SNAPSHOT_SECTION_F_CRITICAL,
	    0, payload, written), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_common_encode(&stage.common, payload,
	    sizeof(payload), &written), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&builder,
	    VMM_SNAPSHOT_SECTION_VCPU_COMMON, VMM_SNAPSHOT_SECTION_F_CRITICAL,
	    2, payload, written), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_encode(&stage.x86, payload,
	    sizeof(payload), &written), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&builder,
	    VMM_SNAPSHOT_SECTION_VCPU_X86, VMM_SNAPSHOT_SECTION_F_CRITICAL,
	    2, payload, written), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_finalize(&builder, &length), 0);
	memset(&decoded, 0xa5, sizeof(decoded));
	memset(&decoded_transaction, 0x5a, sizeof(decoded_transaction));
	decoded_before = decoded;
	tx_before = decoded_transaction;
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_decode(wire, length,
	    &decoded, 1, &decoded_transaction), EINVAL);
	ATF_CHECK_EQ(memcmp(&decoded, &decoded_before, sizeof(decoded)), 0);
	ATF_CHECK_EQ(memcmp(&decoded_transaction, &tx_before,
	    sizeof(tx_before)), 0);

	/* An invalid staged FPU image cannot be encoded at all. */
	stage.fpu.xsave_bitmap |= FPU_PT;
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&transaction, &stage,
	    1, wire, sizeof(wire), &length), EINVAL);
}

ATF_TC_WITHOUT_HEAD(xcr0_validate_matrix);
ATF_TC_BODY(xcr0_validate_matrix, tc)
{

	(void)tc;
	/* x87 is architecturally mandatory in XCR0. */
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(0, UINT64_MAX, true),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(XCR0_SSE, UINT64_MAX, true),
	    EINVAL);

	/* Without XSAVE the only legal value is bare x87. */
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(XCR0_X87, UINT64_MAX,
	    false), 0);
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(XCR0_X87 | XCR0_SSE,
	    UINT64_MAX, false), EINVAL);

	/* A bit outside the allowed mask is rejected. */
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(XCR0_X87 | XCR0_SSE,
	    XCR0_X87, true), EINVAL);

	/* AVX (YMM) requires SSE. */
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(XCR0_X87 | XCR0_YMM,
	    UINT64_MAX, true), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(XCR0_X87 | XCR0_SSE |
	    XCR0_YMM, UINT64_MAX, true), 0);

	/* MPX BNDREGS and BNDCSR travel together. */
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(XCR0_X87 | XCR0_BNDREGS,
	    UINT64_MAX, true), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(XCR0_X87 | XCR0_BNDREGS |
	    XCR0_BNDCSR, UINT64_MAX, true), 0);

	/* AVX-512 requires the whole AVX + AVX-512 component set. */
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(XCR0_X87 | XCR0_SSE |
	    XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM, UINT64_MAX, true),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(XCR0_X87 | XCR0_SSE |
	    XCR0_YMM | XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM,
	    UINT64_MAX, true), 0);
}

ATF_TC_WITHOUT_HEAD(x86_validate_event_matrix);
ATF_TC_BODY(x86_validate_event_matrix, tc)
{
	struct vmm_snapshot_vcpu_x86 s;

	(void)tc;
	/* NULL and the canonical minimal state. */
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(NULL), EINVAL);
	x86_state_init(&s);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), 0);

	/* Undefined flag bit. */
	x86_state_init(&s);
	s.flags = 0x10;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), EINVAL);

	/* x2apic_state is a boolean. */
	x86_state_init(&s);
	s.x2apic_state = 2;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), EINVAL);

	/* guest_xcr0 must satisfy the XCR0 dependency graph. */
	x86_state_init(&s);
	s.guest_xcr0 = 0;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), EINVAL);

	/* exception_class out of range. */
	x86_state_init(&s);
	s.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_CLASS_LAST;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), EINVAL);

	/* NMI-only and EXTINT-only pending are legal (event value paths). */
	x86_state_init(&s);
	s.flags = VMM_SNAPSHOT_X86_F_NMI_PENDING |
	    VMM_SNAPSHOT_X86_F_EXTINT_PENDING;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), 0);

	/* Not-pending but carrying exception residue is rejected. */
	x86_state_init(&s);
	s.flags = VMM_SNAPSHOT_X86_F_EXCEPTION_ERROR;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), EINVAL);
	x86_state_init(&s);
	s.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_FAULT;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), EINVAL);
	x86_state_init(&s);
	s.exception_vector = 3;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), EINVAL);
	x86_state_init(&s);
	s.exception_error = 1;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), EINVAL);

	/* Pending with class NONE is contradictory. */
	x86_state_init(&s);
	s.flags = VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), EINVAL);

	/* Pending with an out-of-range vector. */
	x86_state_init(&s);
	s.flags = VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING;
	s.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_FAULT;
	s.exception_vector = 32;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), EINVAL);

	/* #DF (vector 8) can never be injected. */
	x86_state_init(&s);
	s.flags = VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING;
	s.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_FAULT;
	s.exception_vector = 8;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), EINVAL);

	/* error_valid on a vector that has no error code (#DB, vector 1). */
	x86_state_init(&s);
	s.flags = VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING |
	    VMM_SNAPSHOT_X86_F_EXCEPTION_ERROR;
	s.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_FAULT;
	s.exception_vector = 1;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), EINVAL);

	/* No error flag but a nonzero error code. */
	x86_state_init(&s);
	s.flags = VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING;
	s.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_FAULT;
	s.exception_vector = 14;
	s.exception_error = 1;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), EINVAL);

	/* ICEBP/TASK_SWITCH are pinned to vector 1. */
	x86_state_init(&s);
	s.flags = VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING;
	s.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_ICEBP;
	s.exception_vector = 3;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), EINVAL);
	x86_state_init(&s);
	s.flags = VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING;
	s.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_TASK_SWITCH;
	s.exception_vector = 3;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), EINVAL);

	/* A well-formed #PF (vector 14) with an error code is accepted. */
	x86_state_init(&s);
	s.flags = VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING |
	    VMM_SNAPSHOT_X86_F_EXCEPTION_ERROR;
	s.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_FAULT;
	s.exception_vector = 14;
	s.exception_error = 2;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), 0);

	/* A #GP (vector 13) is also on the error-code list. */
	x86_state_init(&s);
	s.flags = VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING |
	    VMM_SNAPSHOT_X86_F_EXCEPTION_ERROR;
	s.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_FAULT;
	s.exception_vector = 13;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), 0);

	/* An ICEBP with vector 1 is accepted. */
	x86_state_init(&s);
	s.flags = VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING;
	s.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_ICEBP;
	s.exception_vector = 1;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), 0);

	/*
	 * Every architectural error-code vector (#TS, #NP, #SS, #GP, #PF, #AC,
	 * #CP, #VC, #SX) is accepted with an error code present.
	 */
	{
		static const uint32_t err_vectors[] =
		    { 10, 11, 12, 13, 14, 17, 21, 29, 30 };
		for (size_t i = 0; i < nitems(err_vectors); i++) {
			x86_state_init(&s);
			s.flags = VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING |
			    VMM_SNAPSHOT_X86_F_EXCEPTION_ERROR;
			s.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_FAULT;
			s.exception_vector = err_vectors[i];
			s.exception_error = 1;
			ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&s), 0);
		}
	}
}

ATF_TC_WITHOUT_HEAD(x86_round_trip);
ATF_TC_BODY(x86_round_trip, tc)
{
	struct vmm_snapshot_vcpu_x86 s, decoded;
	uint8_t wire[VMM_SNAPSHOT_VCPU_X86_SIZE];
	size_t written;

	(void)tc;
	x86_state_init(&s);
	s.flags = VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING |
	    VMM_SNAPSHOT_X86_F_EXCEPTION_ERROR;
	s.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_FAULT;
	s.exception_vector = 14;
	s.exception_error = 5;
	s.exitintinfo = 0;
	s.guest_xcr0 = XCR0_X87 | XCR0_SSE | XCR0_YMM;
	s.absolute_tsc = UINT64_C(0x1122334455667788);
	s.x2apic_state = 1;

	written = 0;
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_encode(&s, wire, sizeof(wire),
	    &written), 0);
	ATF_CHECK_EQ(written, VMM_SNAPSHOT_VCPU_X86_SIZE);
	/* Wire version/length are the spec constants, not echoed input. */
	ATF_CHECK_EQ(le16dec(wire), VMM_SNAPSHOT_X86_STATE_VERSION);
	ATF_CHECK_EQ(le16dec(wire + 2), VMM_SNAPSHOT_VCPU_X86_SIZE);
	memset(&decoded, 0xa5, sizeof(decoded));
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_decode(wire, sizeof(wire),
	    &decoded), 0);
	ATF_CHECK_EQ(memcmp(&decoded, &s, sizeof(s)), 0);

	/* Encode rejects a short buffer and a NULL sink. */
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_encode(&s, wire,
	    VMM_SNAPSHOT_VCPU_X86_SIZE - 1, &written), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_encode(&s, NULL, sizeof(wire),
	    &written), EINVAL);
	/* Encode of an invalid state fails without touching the buffer. */
	{
		struct vmm_snapshot_vcpu_x86 bad = s;
		bad.x2apic_state = 5;
		ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_encode(&bad, wire,
		    sizeof(wire), &written), EINVAL);
	}

	/* Decode: wrong length, NULL, and bad envelope fields. */
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_decode(wire, sizeof(wire) - 1,
	    &decoded), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_decode(NULL, sizeof(wire),
	    &decoded), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_decode(wire, sizeof(wire), NULL),
	    EINVAL);

	le16enc(wire, VMM_SNAPSHOT_X86_STATE_VERSION + 1);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_decode(wire, sizeof(wire),
	    &decoded), EINVAL);
	le16enc(wire, VMM_SNAPSHOT_X86_STATE_VERSION);

	/* Trailing reserved words must decode as zero. */
	le64enc(wire + 48, 1);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_decode(wire, sizeof(wire),
	    &decoded), EINVAL);
	le64enc(wire + 48, 0);

	/* An out-of-range exception_class is rejected before validation. */
	le32enc(wire + 12, VMM_SNAPSHOT_X86_EXCEPTION_CLASS_LAST);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_decode(wire, sizeof(wire),
	    &decoded), EINVAL);
	le32enc(wire + 12, VMM_SNAPSHOT_X86_EXCEPTION_FAULT);

	/* A structurally sound record whose value fails validation. */
	le64enc(wire + 32, 0);	/* guest_xcr0 = 0 -> no x87 */
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_decode(wire, sizeof(wire),
	    &decoded), EINVAL);
}

ATF_TC_WITHOUT_HEAD(x86_event_runtime_round_trip);
ATF_TC_BODY(x86_event_runtime_round_trip, tc)
{
	static const struct {
		uint32_t	flags;
		enum vmm_snapshot_x86_exception_class ec;
		uint32_t	vector;
		uint32_t	error;
	} cases[] = {
	    { 0, VMM_SNAPSHOT_X86_EXCEPTION_NONE, 0, 0 },
	    { VMM_SNAPSHOT_X86_F_NMI_PENDING, VMM_SNAPSHOT_X86_EXCEPTION_NONE,
	      0, 0 },
	    { VMM_SNAPSHOT_X86_F_EXTINT_PENDING,
	      VMM_SNAPSHOT_X86_EXCEPTION_NONE, 0, 0 },
	    { VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING |
	      VMM_SNAPSHOT_X86_F_EXCEPTION_ERROR,
	      VMM_SNAPSHOT_X86_EXCEPTION_FAULT, 14, 7 },
	    { VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING,
	      VMM_SNAPSHOT_X86_EXCEPTION_TRAP, 3, 0 },
	    { VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING,
	      VMM_SNAPSHOT_X86_EXCEPTION_ICEBP, 1, 0 },
	    { VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING,
	      VMM_SNAPSHOT_X86_EXCEPTION_TASK_SWITCH, 1, 0 },
	};
	struct vmm_snapshot_vcpu_x86 s, back;
	struct vmm_event_state event;

	(void)tc;
	for (size_t i = 0; i < nitems(cases); i++) {
		x86_state_init(&s);
		s.flags = cases[i].flags;
		s.exception_class = cases[i].ec;
		s.exception_vector = cases[i].vector;
		s.exception_error = cases[i].error;
		ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_validate(&s), 0);

		memset(&event, 0xa5, sizeof(event));
		ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_event_to_runtime(&s,
		    &event), 0);
		/* The four event flag bits map one-for-one. */
		ATF_CHECK_EQ((event.flags & VMM_EVENT_STATE_F_NMI_PENDING) != 0,
		    (s.flags & VMM_SNAPSHOT_X86_F_NMI_PENDING) != 0);
		ATF_CHECK_EQ((event.flags & VMM_EVENT_STATE_F_EXCEPTION_PENDING)
		    != 0, (s.flags & VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING) != 0);

		back = s;
		back.flags = 0;
		back.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_NONE;
		back.exception_vector = 0;
		back.exception_error = 0;
		ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_event_from_runtime(&event,
		    &back), 0);
		/* The non-event fields are preserved; events round-trip. */
		ATF_CHECK_EQ(memcmp(&back, &s, sizeof(s)), 0);
	}

	/* Argument guards on both directions. */
	x86_state_init(&s);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_event_to_runtime(NULL, &event),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_event_to_runtime(&s, NULL), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_event_from_runtime(NULL, &s),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_event_from_runtime(&event, NULL),
	    EINVAL);
	/* to_runtime rejects an invalid source state. */
	s.x2apic_state = 9;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_event_to_runtime(&s, &event),
	    EINVAL);

	/* from_runtime rejects an event that fails event-state validation. */
	x86_state_init(&s);
	memset(&event, 0, sizeof(event));
	event.exception_class = VMM_EVENT_EXCEPTION_CLASS_LAST;
	event.flags = VMM_EVENT_STATE_F_EXCEPTION_PENDING;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_event_from_runtime(&event, &s),
	    EINVAL);
}

ATF_TC_WITHOUT_HEAD(fpu_codec_extra_edges);
ATF_TC_BODY(fpu_codec_extra_edges, tc)
{
	struct vmm_snapshot_vcpu_x86_fpu state;
	uint8_t wire[VMM_SNAPSHOT_VCPU_X86_FPU_MAX_SIZE];
	size_t written;

	(void)tc;
	/* area_length beyond the architectural maximum. */
	fpu_xsave_init(&state);
	state.area_length = VMM_SNAPSHOT_X86_FPU_AREA_MAX + 1;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_validate(&state), EINVAL);

	/* encode() forwards a validation failure (invalid staged image). */
	fpu_xsave_init(&state);
	state.xsave_bitmap |= XCR0_TILECFG;	/* AMX without TILEDATA */
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_encode(&state, wire,
	    sizeof(wire), &written), EINVAL);

	/* A zero stored MXCSR mask means the FXSAVE default mask applies. */
	fpu_fxsave_init(&state);
	le32enc(state.area + FPU_MXCSR_MASK_OFF, 0);
	le32enc(state.area + FPU_MXCSR_OFF, 0x1f80);	/* within default */
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_validate(&state), 0);
	le32enc(state.area + FPU_MXCSR_OFF, 0x0040);	/* outside default */
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_validate(&state), EINVAL);

	/* Both AMX components together are a self-consistent bitmap. */
	fpu_xsave_init(&state);
	state.xsave_bitmap |= XCR0_TILECFG | XCR0_TILEDATA;
	le64enc(state.area + FPU_XSTATE_BV_OFF, FPU_AVX_MASK);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_validate(&state), 0);

	/* restore_validate forwards a validation failure. */
	fpu_xsave_init(&state);
	state.area_length = VMM_SNAPSHOT_X86_FPU_AREA_MAX + 1;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_fpu_restore_validate(&state, true,
	    FPU_AVX_MASK, FPU_AVX_AREA_SIZE), EINVAL);
}

ATF_TC_WITHOUT_HEAD(transaction_size_and_encode_guards);
ATF_TC_BODY(transaction_size_and_encode_guards, tc)
{
	struct vmm_snapshot_x86_transaction transaction = {
	    .vm = { .max_vcpus = 4, .vcpu_count = 1 }, .vcpu_count = 1,
	};
	struct vmm_snapshot_x86_vcpu_stage stage[2];
	uint8_t wire[4 * VMM_SNAPSHOT_VCPU_X86_FPU_MAX_SIZE];
	size_t capacity, length;

	(void)tc;
	/* size() argument guard and the spec capacity formula. */
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_size(1, NULL), EINVAL);
	ATF_REQUIRE_EQ(vmm_snapshot_x86_transaction_size(2, &capacity), 0);
	ATF_CHECK_EQ(capacity, (size_t)(VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE +
	    VMM_SNAPSHOT_SECTION_HEADER_SIZE + VMM_SNAPSHOT_VM_COMMON_SIZE) +
	    2 * (size_t)(3 * VMM_SNAPSHOT_SECTION_HEADER_SIZE +
	    VMM_SNAPSHOT_VCPU_COMMON_SIZE + VMM_SNAPSHOT_VCPU_X86_SIZE +
	    VMM_SNAPSHOT_VCPU_X86_FPU_MAX_SIZE));

	stage_init(&stage[0], 1);

	/* validate_source guards, all funneled through encode(). */
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(NULL, stage, 1, wire,
	    sizeof(wire), &length), EINVAL);
	{
		struct vmm_snapshot_x86_transaction t = transaction;
		t.vm.max_vcpus = 0;
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&t, stage, 1,
		    wire, sizeof(wire), &length), EINVAL);
		t = transaction;
		t.vm.vcpu_count = 2;	/* != vcpu_count */
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&t, stage, 1,
		    wire, sizeof(wire), &length), EINVAL);
		t = transaction;
		t.vcpu_count = 5;	/* > max_vcpus */
		t.vm.vcpu_count = 5;
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&t, stage, 1,
		    wire, sizeof(wire), &length), EINVAL);
	}
	/* count > capacity. */
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&transaction, stage,
	    0, wire, sizeof(wire), &length), EINVAL);
	/* count != 0 with a NULL stage. */
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&transaction, NULL, 1,
	    wire, sizeof(wire), &length), EINVAL);

	/* Per-stage guards. */
	stage_init(&stage[0], 9);	/* instance >= max_vcpus */
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&transaction, stage,
	    1, wire, sizeof(wire), &length), EINVAL);
	stage_init(&stage[0], 0);
	stage[0].common.flags = 0x2;	/* undefined common flag */
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&transaction, stage,
	    1, wire, sizeof(wire), &length), EINVAL);
	stage_init(&stage[0], 0);
	stage[0].x86.x2apic_state = 7;	/* invalid x86 */
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&transaction, stage,
	    1, wire, sizeof(wire), &length), EINVAL);
	stage_init(&stage[0], 0);
	stage[0].fpu.xsave_bitmap = 0x1;	/* fxsave image with a bitmap */
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&transaction, stage,
	    1, wire, sizeof(wire), &length), EINVAL);

	/* Non-monotonic instances across two stages. */
	{
		struct vmm_snapshot_x86_transaction t = transaction;
		t.vm.vcpu_count = 2;
		t.vcpu_count = 2;
		stage_init(&stage[0], 2);
		stage_init(&stage[1], 1);	/* <= previous */
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&t, stage, 2,
		    wire, sizeof(wire), &length), EINVAL);
	}

	/* buffer / written argument guards. */
	stage_init(&stage[0], 0);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&transaction, stage,
	    1, NULL, sizeof(wire), &length), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&transaction, stage,
	    1, wire, sizeof(wire), NULL), EINVAL);

	/* Output buffer overlapping the transaction is rejected. */
	{
		uint8_t big[sizeof(struct vmm_snapshot_x86_transaction) + 64];
		struct vmm_snapshot_x86_transaction *tp =
		    (struct vmm_snapshot_x86_transaction *)(void *)big;
		*tp = transaction;
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(tp, stage, 1,
		    big, sizeof(big), &length), EINVAL);
	}

	/* An output buffer too small for the exact extent: E2BIG. */
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&transaction, stage,
	    1, wire, VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE, &length), E2BIG);
}

ATF_TC_WITHOUT_HEAD(transaction_decode_guards);
ATF_TC_BODY(transaction_decode_guards, tc)
{
	struct vmm_snapshot_x86_transaction transaction = {
	    .vm = { .max_vcpus = 4, .vcpu_count = 1 }, .vcpu_count = 1,
	};
	struct vmm_snapshot_x86_vcpu_stage stage;
	struct vmm_snapshot_x86_transaction decoded_transaction;
	uint8_t wire[2 * VMM_SNAPSHOT_VCPU_X86_FPU_MAX_SIZE];
	size_t length;

	(void)tc;
	stage_init(&stage, 0);
	ATF_REQUIRE_EQ(vmm_snapshot_x86_transaction_encode(&transaction,
	    &stage, 1, wire, sizeof(wire), &length), 0);

	/* Argument guards. */
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_decode(NULL, length, &stage,
	    1, &decoded_transaction), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_decode(wire, length, &stage,
	    1, NULL), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_decode(wire, length, NULL, 1,
	    &decoded_transaction), EINVAL);
	/* capacity that would overflow the stage-array byte length. */
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_decode(wire, length, &stage,
	    SIZE_MAX, &decoded_transaction), EINVAL);
	/* A capacity whose byte extent is unrepresentable from &stage. */
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_decode(wire, length, &stage,
	    SIZE_MAX / sizeof(stage), &decoded_transaction), EINVAL);
	/* Buffer overlapping the destination transaction. */
	{
		uint8_t big[3 * VMM_SNAPSHOT_VCPU_X86_FPU_MAX_SIZE];
		struct vmm_snapshot_x86_transaction *tp =
		    (struct vmm_snapshot_x86_transaction *)(void *)
		    (big + 8);
		memcpy(big, wire, length);
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_decode(big, length,
		    &stage, 1, tp), EINVAL);
	}
}

ATF_TC_WITHOUT_HEAD(transaction_decode_envelope_negatives);
ATF_TC_BODY(transaction_decode_envelope_negatives, tc)
{
	struct vmm_snapshot_vm_common vm = { .max_vcpus = 4, .vcpu_count = 2 };
	struct vmm_snapshot_vcpu_common common = { .next_pc = 0x2000 };
	struct vmm_snapshot_vcpu_x86 x86;
	struct vmm_snapshot_vcpu_x86_fpu fpu;
	struct vmm_snapshot_x86_vcpu_stage stage[2];
	struct vmm_snapshot_x86_transaction decoded_transaction;
	uint8_t vm_pl[VMM_SNAPSHOT_VM_COMMON_SIZE];
	uint8_t com_pl[VMM_SNAPSHOT_VCPU_COMMON_SIZE];
	uint8_t x86_pl[VMM_SNAPSHOT_VCPU_X86_SIZE];
	uint8_t fpu_pl[VMM_SNAPSHOT_VCPU_X86_FPU_MAX_SIZE];
	uint8_t junk_pl[4] = { 1, 2, 3, 4 };
	uint8_t wire[4 * VMM_SNAPSHOT_VCPU_X86_FPU_MAX_SIZE];
	size_t vm_len, com_len, x86_len, fpu_len, length;
	const uint16_t CRIT = VMM_SNAPSHOT_SECTION_F_CRITICAL;

	(void)tc;
	x86_state_init(&x86);
	fpu_fxsave_init(&fpu);
	ATF_REQUIRE_EQ(vmm_snapshot_vm_common_encode(&vm, vm_pl, sizeof(vm_pl),
	    &vm_len), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_common_encode(&common, com_pl,
	    sizeof(com_pl), &com_len), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_encode(&x86, x86_pl,
	    sizeof(x86_pl), &x86_len), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_fpu_encode(&fpu, fpu_pl,
	    sizeof(fpu_pl), &fpu_len), 0);

#define	VMC	VMM_SNAPSHOT_SECTION_VM_COMMON
#define	VCC	VMM_SNAPSHOT_SECTION_VCPU_COMMON
#define	VCX	VMM_SNAPSHOT_SECTION_VCPU_X86
#define	VCF	VMM_SNAPSHOT_SECTION_VCPU_X86_FPU
#define	DECODE(cap)	vmm_snapshot_x86_transaction_decode(wire, length, \
	stage, (cap), &decoded_transaction)

	/*
	 * A valid two-vCPU transaction with a trailing unknown section (the
	 * envelope requires sections in ascending type order, and 0x7777 is
	 * larger than every known type).  Decode must skip it.
	 */
	{
		struct env_section secs[] = {
		    { VMC, CRIT, 0, vm_pl, vm_len },
		    { VCC, CRIT, 1, com_pl, com_len },
		    { VCC, CRIT, 2, com_pl, com_len },
		    { VCX, CRIT, 1, x86_pl, x86_len },
		    { VCX, CRIT, 2, x86_pl, x86_len },
		    { VCF, CRIT, 1, fpu_pl, fpu_len },
		    { VCF, CRIT, 2, fpu_pl, fpu_len },
		    { 0x7777, 0, 0, junk_pl, sizeof(junk_pl) },
		};
		ATF_REQUIRE_EQ(build_env(wire, sizeof(wire), secs,
		    nitems(secs), &length), 0);
		ATF_CHECK_EQ(DECODE(2), 0);
		ATF_CHECK_EQ(decoded_transaction.vcpu_count, 2);
	}

	/* A known section that is not marked critical. */
	{
		struct env_section secs[] = {
		    { VMC, 0, 0, vm_pl, vm_len },
		};
		ATF_REQUIRE_EQ(build_env(wire, sizeof(wire), secs,
		    nitems(secs), &length), 0);
		ATF_CHECK_EQ(DECODE(2), EINVAL);
	}

	/* VM_COMMON with a nonzero instance. */
	{
		struct env_section secs[] = {
		    { VMC, CRIT, 1, vm_pl, vm_len },
		};
		ATF_REQUIRE_EQ(build_env(wire, sizeof(wire), secs,
		    nitems(secs), &length), 0);
		ATF_CHECK_EQ(DECODE(2), EINVAL);
	}

	/* vm.vcpu_count exceeds the caller's stage capacity. */
	{
		struct env_section secs[] = {
		    { VMC, CRIT, 0, vm_pl, vm_len },
		};
		ATF_REQUIRE_EQ(build_env(wire, sizeof(wire), secs,
		    nitems(secs), &length), 0);
		ATF_CHECK_EQ(DECODE(1), E2BIG);
	}

	/* VCPU_COMMON before any VM_COMMON. */
	{
		struct env_section secs[] = {
		    { VCC, CRIT, 1, com_pl, com_len },
		};
		ATF_REQUIRE_EQ(build_env(wire, sizeof(wire), secs,
		    nitems(secs), &length), 0);
		ATF_CHECK_EQ(DECODE(2), EINVAL);
	}

	/* VCPU_COMMON instance >= max_vcpus. */
	{
		struct env_section secs[] = {
		    { VMC, CRIT, 0, vm_pl, vm_len },
		    { VCC, CRIT, 9, com_pl, com_len },
		};
		ATF_REQUIRE_EQ(build_env(wire, sizeof(wire), secs,
		    nitems(secs), &length), 0);
		ATF_CHECK_EQ(DECODE(2), EINVAL);
	}

	/* More VCPU_COMMON sections than vm.vcpu_count. */
	{
		struct env_section secs[] = {
		    { VMC, CRIT, 0, vm_pl, vm_len },
		    { VCC, CRIT, 1, com_pl, com_len },
		    { VCC, CRIT, 2, com_pl, com_len },
		    { VCC, CRIT, 3, com_pl, com_len },
		};
		ATF_REQUIRE_EQ(build_env(wire, sizeof(wire), secs,
		    nitems(secs), &length), 0);
		ATF_CHECK_EQ(DECODE(4), EINVAL);
	}

	/* A corrupt VCPU_COMMON payload. */
	{
		uint8_t bad[VMM_SNAPSHOT_VCPU_COMMON_SIZE];
		struct env_section secs[] = {
		    { VMC, CRIT, 0, vm_pl, vm_len },
		    { VCC, CRIT, 1, bad, sizeof(bad) },
		};
		memcpy(bad, com_pl, sizeof(bad));
		bad[0] ^= 0xff;	/* wreck the version word */
		ATF_REQUIRE_EQ(build_env(wire, sizeof(wire), secs,
		    nitems(secs), &length), 0);
		ATF_CHECK_EQ(DECODE(2), EINVAL);
	}

	/* VCPU_X86 with no matching VCPU_COMMON yet. */
	{
		struct env_section secs[] = {
		    { VMC, CRIT, 0, vm_pl, vm_len },
		    { VCX, CRIT, 1, x86_pl, x86_len },
		};
		ATF_REQUIRE_EQ(build_env(wire, sizeof(wire), secs,
		    nitems(secs), &length), 0);
		ATF_CHECK_EQ(DECODE(2), EINVAL);
	}

	/* VCPU_X86 whose instance does not pair with its VCPU_COMMON. */
	{
		struct env_section secs[] = {
		    { VMC, CRIT, 0, vm_pl, vm_len },
		    { VCC, CRIT, 1, com_pl, com_len },
		    { VCC, CRIT, 2, com_pl, com_len },
		    { VCX, CRIT, 1, x86_pl, x86_len },
		    { VCX, CRIT, 3, x86_pl, x86_len },
		};
		ATF_REQUIRE_EQ(build_env(wire, sizeof(wire), secs,
		    nitems(secs), &length), 0);
		ATF_CHECK_EQ(DECODE(2), EINVAL);
	}

	/* A corrupt VCPU_X86 payload. */
	{
		uint8_t bad[VMM_SNAPSHOT_VCPU_X86_SIZE];
		struct env_section secs[] = {
		    { VMC, CRIT, 0, vm_pl, vm_len },
		    { VCC, CRIT, 1, com_pl, com_len },
		    { VCX, CRIT, 1, bad, sizeof(bad) },
		};
		memcpy(bad, x86_pl, sizeof(bad));
		bad[0] ^= 0xff;	/* wreck the version word */
		ATF_REQUIRE_EQ(build_env(wire, sizeof(wire), secs,
		    nitems(secs), &length), 0);
		ATF_CHECK_EQ(DECODE(2), EINVAL);
	}

	/* VCPU_X86_FPU with no matching VCPU_COMMON yet. */
	{
		struct env_section secs[] = {
		    { VMC, CRIT, 0, vm_pl, vm_len },
		    { VCF, CRIT, 1, fpu_pl, fpu_len },
		};
		ATF_REQUIRE_EQ(build_env(wire, sizeof(wire), secs,
		    nitems(secs), &length), 0);
		ATF_CHECK_EQ(DECODE(2), EINVAL);
	}

	/* VCPU_X86_FPU whose instance does not pair with its VCPU_COMMON. */
	{
		struct env_section secs[] = {
		    { VMC, CRIT, 0, vm_pl, vm_len },
		    { VCC, CRIT, 1, com_pl, com_len },
		    { VCC, CRIT, 2, com_pl, com_len },
		    { VCX, CRIT, 1, x86_pl, x86_len },
		    { VCX, CRIT, 2, x86_pl, x86_len },
		    { VCF, CRIT, 1, fpu_pl, fpu_len },
		    { VCF, CRIT, 3, fpu_pl, fpu_len },
		};
		ATF_REQUIRE_EQ(build_env(wire, sizeof(wire), secs,
		    nitems(secs), &length), 0);
		ATF_CHECK_EQ(DECODE(2), EINVAL);
	}

	/* Fewer VCPU_X86 sections than vm.vcpu_count (final tally fails). */
	{
		struct env_section secs[] = {
		    { VMC, CRIT, 0, vm_pl, vm_len },
		    { VCC, CRIT, 1, com_pl, com_len },
		    { VCC, CRIT, 2, com_pl, com_len },
		    { VCX, CRIT, 1, x86_pl, x86_len },
		    { VCX, CRIT, 2, x86_pl, x86_len },
		    { VCF, CRIT, 1, fpu_pl, fpu_len },
		};
		ATF_REQUIRE_EQ(build_env(wire, sizeof(wire), secs,
		    nitems(secs), &length), 0);
		ATF_CHECK_EQ(DECODE(2), EINVAL);
	}

#undef	VMC
#undef	VCC
#undef	VCX
#undef	VCF
#undef	DECODE
}

ATF_TC_WITHOUT_HEAD(transaction_destination_preflight);
ATF_TC_BODY(transaction_destination_preflight, tc)
{
	struct vmm_snapshot_x86_transaction transaction = {
	    .vm = { .max_vcpus = 4, .vcpu_count = 2 }, .vcpu_count = 2,
	};
	struct vmm_snapshot_x86_vcpu_stage stage[2];
	uint32_t instances[2] = { 1, 2 };
	uint8_t modes[2];

	(void)tc;
	stage_init(&stage[0], 1);
	stage_init(&stage[1], 2);
	stage[0].x86.x2apic_state = 1;
	stage[1].x86.x2apic_state = 0;
	modes[0] = 1;
	modes[1] = 0;

	/* The happy path. */
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
	    &transaction, stage, 2, 4, instances, 2), 0);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_restore_preflight(
	    &transaction, stage, 2, 4, instances, modes, 2), 0);

	/* validate_destination argument guards. */
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(NULL,
	    stage, 2, 4, instances, 2), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
	    &transaction, stage, 2, 0, instances, 2), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
	    &transaction, stage, 2, 4, instances, (size_t)UINT32_MAX + 1),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
	    &transaction, stage, 2, 4, instances,
	    SIZE_MAX / sizeof(stage[0])), EINVAL);
	/* max_vcpus / vcpu_count / count / capacity relationships. */
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
	    &transaction, stage, 2, 8, instances, 2), EINVAL);
	{
		struct vmm_snapshot_x86_transaction t = transaction;
		t.vm.vcpu_count = 3;	/* != vcpu_count */
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
		    &t, stage, 2, 4, instances, 2), EINVAL);
	}
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
	    &transaction, stage, 2, 4, instances, 1), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
	    &transaction, stage, 1, 4, instances, 2), EINVAL);

	/* Per-vCPU guards. */
	{
		uint32_t bad_inst[2] = { 1, 9 };	/* >= max_vcpus */
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
		    &transaction, stage, 2, 4, bad_inst, 2), EINVAL);
	}
	{
		uint32_t mism[2] = { 0, 2 };	/* stage[0].instance != 0 */
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
		    &transaction, stage, 2, 4, mism, 2), EINVAL);
	}
	{
		uint32_t nonmono[2] = { 2, 1 };
		struct vmm_snapshot_x86_vcpu_stage s2[2];
		stage_init(&s2[0], 2);
		stage_init(&s2[1], 1);
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
		    &transaction, s2, 2, 4, nonmono, 2), EINVAL);
	}
	{
		struct vmm_snapshot_x86_vcpu_stage s2[2];
		stage_init(&s2[0], 1);
		stage_init(&s2[1], 2);
		s2[1].common.flags = 0x2;
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
		    &transaction, s2, 2, 4, instances, 2), EINVAL);
		stage_init(&s2[1], 2);
		s2[1].x86.x2apic_state = 4;
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
		    &transaction, s2, 2, 4, instances, 2), EINVAL);
		stage_init(&s2[1], 2);
		s2[1].fpu.xsave_bitmap = 0x1;	/* fxsave with a bitmap */
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
		    &transaction, s2, 2, 4, instances, 2), EINVAL);
	}

	/* restore_preflight-specific guards. */
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_restore_preflight(
	    &transaction, stage, 2, 4, instances, modes,
	    SIZE_MAX / sizeof(stage[0])), EINVAL);
	/* A propagated validate_destination failure. */
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_restore_preflight(
	    &transaction, stage, 2, 8, instances, modes, 2), EINVAL);
	/* An out-of-range mode byte. */
	{
		uint8_t bad_modes[2] = { 2, 0 };
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_restore_preflight(
		    &transaction, stage, 2, 4, instances, bad_modes, 2),
		    EINVAL);
	}
	/* A mode that disagrees with the staged x2apic_state. */
	{
		uint8_t bad_modes[2] = { 0, 0 };	/* stage[0] is x2apic */
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_restore_preflight(
		    &transaction, stage, 2, 4, instances, bad_modes, 2),
		    EINVAL);
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fpu_round_trip);
	ATF_TP_ADD_TC(tp, fpu_reject_truncation);
	ATF_TP_ADD_TC(tp, fpu_reject_version);
	ATF_TP_ADD_TC(tp, fpu_validate_edges);
	ATF_TP_ADD_TC(tp, fpu_reject_capability_mismatch);
	ATF_TP_ADD_TC(tp, fpu_transaction_contract);
	ATF_TP_ADD_TC(tp, xcr0_validate_matrix);
	ATF_TP_ADD_TC(tp, x86_validate_event_matrix);
	ATF_TP_ADD_TC(tp, x86_round_trip);
	ATF_TP_ADD_TC(tp, x86_event_runtime_round_trip);
	ATF_TP_ADD_TC(tp, fpu_codec_extra_edges);
	ATF_TP_ADD_TC(tp, transaction_size_and_encode_guards);
	ATF_TP_ADD_TC(tp, transaction_decode_guards);
	ATF_TP_ADD_TC(tp, transaction_decode_envelope_negatives);
	ATF_TP_ADD_TC(tp, transaction_destination_preflight);
	return (atf_no_error());
}
