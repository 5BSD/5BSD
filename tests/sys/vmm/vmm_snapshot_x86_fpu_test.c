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

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fpu_round_trip);
	ATF_TP_ADD_TC(tp, fpu_reject_truncation);
	ATF_TP_ADD_TC(tp, fpu_reject_version);
	ATF_TP_ADD_TC(tp, fpu_validate_edges);
	ATF_TP_ADD_TC(tp, fpu_reject_capability_mismatch);
	ATF_TP_ADD_TC(tp, fpu_transaction_contract);
	return (atf_no_error());
}
