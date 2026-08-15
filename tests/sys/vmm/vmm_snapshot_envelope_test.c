/*-
 * SPDX-License-Identifier: BSD-2-Clause
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

/*
 * Minimal valid guest FPU stage state: a bare FXSAVE image (all zeroes is
 * architecturally valid; a zero stored MXCSR mask means the default mask).
 */
static void
fpu_stage_init(struct vmm_snapshot_vcpu_x86_fpu *fpu)
{

	memset(fpu, 0, sizeof(*fpu));
	fpu->area_length = VMM_SNAPSHOT_X86_FPU_LEGACY_SIZE;
}

/* Encoded extent of one FXSAVE-form guest FPU section payload. */
#define	FPU_LEGACY_PAYLOAD_SIZE	(VMM_SNAPSHOT_VCPU_X86_FPU_HEADER_SIZE + \
	VMM_SNAPSHOT_X86_FPU_LEGACY_SIZE)

ATF_TC_WITHOUT_HEAD(round_trip);
ATF_TC_BODY(round_trip, tc)
{
	struct vmm_snapshot_envelope_builder builder;
	struct vmm_snapshot_envelope_reader reader;
	struct vmm_snapshot_section section;
	const uint8_t first[] = { 0x11, 0x22, 0x33 };
	uint8_t wire[256];
	size_t length;

	memset(wire, 0xa5, sizeof(wire));
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_builder_init(&builder, wire,
	    sizeof(wire)), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&builder, 1,
	    VMM_SNAPSHOT_SECTION_F_CRITICAL, 7, first, sizeof(first)), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&builder, 2, 0, UINT32_MAX,
	    NULL, 0), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_finalize(&builder, &length), 0);
	ATF_CHECK_EQ(length, VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE +
	    2 * VMM_SNAPSHOT_SECTION_HEADER_SIZE + sizeof(first));
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_reader_init(&reader, wire,
	    length), 0);
	reader.cursor = VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE +
	    VMM_SNAPSHOT_SECTION_HEADER_SIZE + sizeof(first);
	ATF_CHECK_EQ(vmm_snapshot_envelope_next(&reader, &section), EINVAL);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_reader_init(&reader, wire,
	    length), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_next(&reader, &section), 0);
	ATF_CHECK_EQ(section.type, 1);
	ATF_CHECK_EQ(section.flags, VMM_SNAPSHOT_SECTION_F_CRITICAL);
	ATF_CHECK_EQ(section.instance, 7);
	ATF_CHECK_EQ(section.payload_length, sizeof(first));
	ATF_CHECK_EQ(memcmp(section.payload, first, sizeof(first)), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_next(&reader, &section), 0);
	ATF_CHECK_EQ(section.type, 2);
	ATF_CHECK_EQ(section.instance, UINT32_MAX);
	ATF_CHECK_EQ(section.payload_length, 0);
	ATF_CHECK_EQ(vmm_snapshot_envelope_next(&reader, &section), ENOENT);
	section = (struct vmm_snapshot_section) {
		.type = 99,
	};
	ATF_CHECK_EQ(vmm_snapshot_section_skip_unknown(&section), 0);
	section.flags = VMM_SNAPSHOT_SECTION_F_CRITICAL;
	ATF_CHECK_EQ(vmm_snapshot_section_skip_unknown(&section),
	    EPROTONOSUPPORT);
	section.flags = 2;
	ATF_CHECK_EQ(vmm_snapshot_section_skip_unknown(&section), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_section_skip_unknown(NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(builder_transactionality);
ATF_TC_BODY(builder_transactionality, tc)
{
	struct vmm_snapshot_envelope_builder before, builder;
	uint8_t wire[96], wire_before[sizeof(wire)];
	uint8_t payload[64];
	size_t length;

	memset(wire, 0x5a, sizeof(wire));
	memset(payload, 0x3c, sizeof(payload));
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_builder_init(&builder, wire,
	    sizeof(wire)), 0);
	before = builder;
	memcpy(wire_before, wire, sizeof(wire));
	ATF_CHECK_EQ(vmm_snapshot_envelope_add(&builder, 0, 0, 0, payload, 1),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&builder, &before, sizeof(builder)), 0);
	ATF_CHECK_EQ(memcmp(wire, wire_before, sizeof(wire)), 0);
	ATF_CHECK_EQ(vmm_snapshot_envelope_add(&builder, 1, 2, 0, payload, 1),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&builder, &before, sizeof(builder)), 0);
	ATF_CHECK_EQ(vmm_snapshot_envelope_add(&builder, 1, 0, 0, NULL, 1),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&builder, &before, sizeof(builder)), 0);
	ATF_CHECK_EQ(vmm_snapshot_envelope_add(&builder, 1, 0, 0, payload,
	    sizeof(payload)), EINVAL);
	ATF_CHECK_EQ(memcmp(&builder, &before, sizeof(builder)), 0);
	ATF_CHECK_EQ(vmm_snapshot_envelope_add(&builder, 1, 0, 0,
	    wire + VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE, 1), EINVAL);
	ATF_CHECK_EQ(memcmp(&builder, &before, sizeof(builder)), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&builder, 1, 0, 0, payload,
	    1), 0);
	before = builder;
	memcpy(wire_before, wire, sizeof(wire));
	ATF_CHECK_EQ(vmm_snapshot_envelope_add(&builder, 1, 0, 0, payload,
	    1), EINVAL);
	ATF_CHECK_EQ(memcmp(&builder, &before, sizeof(builder)), 0);
	ATF_CHECK_EQ(memcmp(wire, wire_before, sizeof(wire)), 0);
	ATF_CHECK_EQ(vmm_snapshot_envelope_add(&builder, 1, 0, UINT32_MAX,
	    payload, 1), 0);
	before = builder;
	ATF_CHECK_EQ(vmm_snapshot_envelope_add(&builder, 1, 0,
	    UINT32_MAX - 1, payload, 1), EINVAL);
	ATF_CHECK_EQ(memcmp(&builder, &before, sizeof(builder)), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_finalize(&builder, &length), 0);
	ATF_CHECK_EQ(vmm_snapshot_envelope_finalize(&builder, &length), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_envelope_add(&builder, 2, 0, 0, NULL, 0),
	    EINVAL);
}

ATF_TC_WITHOUT_HEAD(malformed_records);
ATF_TC_BODY(malformed_records, tc)
{
	struct vmm_snapshot_envelope_builder builder;
	struct vmm_snapshot_envelope_reader reader, reader_before;
	uint8_t good[128], bad[sizeof(good)];
	size_t length;

	ATF_REQUIRE_EQ(vmm_snapshot_envelope_builder_init(&builder, good,
	    sizeof(good)), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&builder, 9, 0, 3, "x", 1),
	    0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_finalize(&builder, &length), 0);

#define CHECK_BAD(offset, value, width) do {                             \
	memcpy(bad, good, length);                                         \
	le##width##enc(bad + (offset), (value));                            \
	memset(&reader, 0x6d, sizeof(reader));                             \
	reader_before = reader;                                            \
	ATF_CHECK_EQ(vmm_snapshot_envelope_reader_init(&reader, bad,       \
	    length), EINVAL);                                              \
	ATF_CHECK_EQ(memcmp(&reader, &reader_before, sizeof(reader)), 0);  \
} while (0)
	CHECK_BAD(0, 0, 32);
	CHECK_BAD(4, 2, 16);
	CHECK_BAD(6, 31, 16);
	CHECK_BAD(8, (uint32_t)length - 1, 32);
	CHECK_BAD(12, 2, 32);
	CHECK_BAD(16, 1, 32);
	CHECK_BAD(20, 1, 32);
	CHECK_BAD(32, 0, 16);
	CHECK_BAD(34, 2, 16);
	CHECK_BAD(36, UINT32_MAX, 32);
	CHECK_BAD(44, 1, 32);
#undef CHECK_BAD
	memcpy(bad, good, length);
	/* Append a duplicate key and make the outer counts self-consistent. */
	memcpy(bad + length, good + VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE,
	    VMM_SNAPSHOT_SECTION_HEADER_SIZE + 1);
	le32enc(bad + 8,
	    (uint32_t)(length + VMM_SNAPSHOT_SECTION_HEADER_SIZE + 1));
	le32enc(bad + 12, 2);
	ATF_CHECK_EQ(vmm_snapshot_envelope_reader_init(&reader, bad,
	    length + VMM_SNAPSHOT_SECTION_HEADER_SIZE + 1), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_envelope_reader_init(&reader, good,
	    length - 1), EINVAL);
	memcpy(bad, good, length);
	le32enc(bad + 8, (uint32_t)length + 1);
	ATF_CHECK_EQ(vmm_snapshot_envelope_reader_init(&reader, bad,
	    length), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_envelope_reader_init(NULL, good, length),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_envelope_reader_init(&reader, NULL, length),
	    EINVAL);
}

ATF_TC_WITHOUT_HEAD(argument_boundaries);
ATF_TC_BODY(argument_boundaries, tc)
{
	struct vmm_snapshot_envelope_builder builder, builder_before;
	struct vmm_snapshot_envelope_reader reader, reader_before;
	struct vmm_snapshot_section section, section_before;
	const void *wrapping;
	uint8_t wire[96];
	size_t length;

	wrapping = (const void *)(uintptr_t)(UINTPTR_MAX - 15);
	/*
	 * These assertions exercise the shared VMM primitive directly.  The
	 * snapshot wrapper deliberately gives invalid inputs the public "not an
	 * overlap" result, while private alias guards must reject the same input
	 * conservatively.  Keep both contracts visible here so a future wrapper
	 * cannot accidentally redefine the common arithmetic.
	 */
	ATF_CHECK(vmm_address_range_valid(NULL, 0));
	ATF_CHECK(!vmm_address_range_valid(NULL, 1));
	ATF_CHECK(vmm_address_range_valid(wrapping, 16));
	ATF_CHECK(!vmm_address_range_valid(wrapping, 17));
	ATF_CHECK(!vmm_address_ranges_overlap(wire, 0, wire, 1));
	ATF_CHECK(vmm_address_ranges_overlap(wire, 1, wire, 1));
	ATF_CHECK(!vmm_address_ranges_overlap(wire, 1, wire + 1, 1));
	ATF_CHECK(vmm_address_ranges_overlap(wrapping, 17, wire, 1));
	ATF_CHECK(vmm_snapshot_range_valid(NULL, 0));
	ATF_CHECK(!vmm_snapshot_range_valid(NULL, 1));
	ATF_CHECK(vmm_snapshot_range_valid(
	    (const void *)(uintptr_t)(UINTPTR_MAX - 15), 16));
	ATF_CHECK(!vmm_snapshot_range_valid(
	    (const void *)(uintptr_t)(UINTPTR_MAX - 15), 17));
	ATF_CHECK(!vmm_snapshot_range_valid(wrapping, 32));
	ATF_CHECK(vmm_snapshot_ranges_overlap(wire, 1, wire, 1));
	ATF_CHECK(!vmm_snapshot_ranges_overlap(wire, 1, wire + 1, 1));
	ATF_CHECK(!vmm_snapshot_ranges_overlap(wrapping, 32, wire, 1));
	ATF_CHECK(!vmm_snapshot_ranges_overlap(wire, 1, wrapping, 32));
	ATF_CHECK_EQ(vmm_snapshot_envelope_builder_init(NULL, wire,
	    sizeof(wire)), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_envelope_builder_init(&builder, NULL,
	    sizeof(wire)), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_envelope_builder_init(&builder, wire,
	    VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE - 1), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_envelope_builder_init(&builder,
	    (void *)(uintptr_t)(UINTPTR_MAX - 15), 32), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_envelope_builder_init(
	    (struct vmm_snapshot_envelope_builder *)(void *)wire, wire,
	    sizeof(wire)), EINVAL);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_builder_init(&builder, wire,
	    sizeof(wire)), 0);
	ATF_CHECK_EQ(vmm_snapshot_envelope_add(NULL, 1, 0, 0, NULL, 0),
	    EINVAL);
	/* A damaged private builder must not overwrite the envelope header. */
	builder_before = builder;
	builder.length = VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE - 1;
	ATF_CHECK_EQ(vmm_snapshot_envelope_add(&builder, 1, 0, 0, NULL, 0),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_envelope_finalize(&builder, &length), EINVAL);
	builder = builder_before;
	builder.section_count = 1;
	ATF_CHECK_EQ(vmm_snapshot_envelope_add(&builder, 1, 0, 0, NULL, 0),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_envelope_finalize(&builder, &length), EINVAL);
	builder = builder_before;
	builder.has_last = true;
	ATF_CHECK_EQ(vmm_snapshot_envelope_add(&builder, 1, 0, 0, NULL, 0),
	    EINVAL);
	builder = builder_before;
	/*
	 * Metadata is private caller-owned state, so it cannot be trusted to
	 * describe the retained wire sections.  A forged last marker used to let
	 * add() append an out-of-order record which finalize() would publish.
	 */
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&builder, 5, 0, 0, NULL, 0),
	    0);
	builder_before = builder;
	builder.last_type = 1;
	ATF_CHECK_EQ(vmm_snapshot_envelope_add(&builder, 3, 0, 0, NULL, 0),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_envelope_finalize(&builder, &length), EINVAL);
	builder = builder_before;
	le16enc(wire + VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE, 0);
	ATF_CHECK_EQ(vmm_snapshot_envelope_add(&builder, 6, 0, 0, NULL, 0),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_envelope_finalize(&builder, &length), EINVAL);
	le16enc(wire + VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE, 5);
	/* The retained section's reserved words are part of the same contract. */
	le32enc(wire + VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE + 12, 1);
	ATF_CHECK_EQ(vmm_snapshot_envelope_add(&builder, 6, 0, 0, NULL, 0),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_envelope_finalize(&builder, &length), EINVAL);
	le32enc(wire + VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE + 12, 0);
	/* Preserve this case's subsequent empty-envelope reader assertions. */
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_builder_init(&builder, wire,
	    sizeof(wire)), 0);
	ATF_CHECK_EQ(vmm_snapshot_envelope_finalize(NULL, &length), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_envelope_finalize(&builder, NULL), EINVAL);
	builder_before = builder;
	ATF_CHECK_EQ(vmm_snapshot_envelope_finalize(&builder,
	    (size_t *)(void *)&builder), EINVAL);
	ATF_CHECK_EQ(memcmp(&builder, &builder_before, sizeof(builder)), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_finalize(&builder, &length), 0);
	ATF_CHECK_EQ(vmm_snapshot_envelope_reader_init(
	    (struct vmm_snapshot_envelope_reader *)(void *)wire, wire,
	    length), EINVAL);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_reader_init(&reader, wire,
	    length), 0);
	ATF_CHECK_EQ(vmm_snapshot_envelope_next(NULL, &section), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_envelope_next(&reader, NULL), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_envelope_next(&reader,
	    (struct vmm_snapshot_section *)(void *)wire), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_envelope_next(&reader, &section), ENOENT);
	reader.cursor = 0;
	ATF_CHECK_EQ(vmm_snapshot_envelope_next(&reader, &section), EINVAL);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_reader_init(&reader, wire,
	    length), 0);
	le32enc(wire + 12, 1);
	reader_before = reader;
	memset(&section, 0x5a, sizeof(section));
	section_before = section;
	ATF_CHECK_EQ(vmm_snapshot_envelope_next(&reader, &section), EINVAL);
	ATF_CHECK_EQ(memcmp(&reader, &reader_before, sizeof(reader)), 0);
	ATF_CHECK_EQ(memcmp(&section, &section_before, sizeof(section)), 0);

	/* Reject output that aliases the iterator before changing either cursor. */
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_builder_init(&builder, wire,
	    sizeof(wire)), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&builder, 1, 0, 0, NULL, 0),
	    0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_finalize(&builder, &length), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_reader_init(&reader, wire,
	    length), 0);
	reader_before = reader;
	ATF_CHECK_EQ(vmm_snapshot_envelope_next(&reader,
	    (struct vmm_snapshot_section *)(void *)&reader), EINVAL);
	ATF_CHECK_EQ(memcmp(&reader, &reader_before, sizeof(reader)), 0);
	ATF_CHECK_EQ(vmm_snapshot_envelope_reader_init(&reader, wrapping, 32),
	    EINVAL);
}

ATF_TC_WITHOUT_HEAD(common_state_codecs);
ATF_TC_BODY(common_state_codecs, tc)
{
	struct vmm_snapshot_vm_common vm, vm_before, vm_decoded;
	struct vmm_snapshot_vm_common expected_vm;
	struct vmm_snapshot_vcpu_common vcpu, vcpu_before, vcpu_decoded;
	struct vmm_snapshot_vcpu_common expected_vcpu;
	uint8_t wire[VMM_SNAPSHOT_VM_COMMON_SIZE];
	uint8_t before[sizeof(wire)];
	size_t written;

	vm = (struct vmm_snapshot_vm_common) {
		.max_vcpus = 257,
		.vcpu_count = 3,
	};
	memset(wire, 0xa5, sizeof(wire));
	ATF_REQUIRE_EQ(vmm_snapshot_vm_common_encode(&vm, wire, sizeof(wire),
	    &written), 0);
	ATF_CHECK_EQ(written, VMM_SNAPSHOT_VM_COMMON_SIZE);
	ATF_REQUIRE_EQ(vmm_snapshot_vm_common_decode(wire, written,
	    &vm_decoded), 0);
	memset(&expected_vm, 0, sizeof(expected_vm));
	expected_vm.max_vcpus = vm.max_vcpus;
	expected_vm.vcpu_count = vm.vcpu_count;
	ATF_CHECK_EQ(memcmp(&vm_decoded, &expected_vm, sizeof(vm_decoded)), 0);
	ATF_CHECK_EQ(vm_decoded.max_vcpus, vm.max_vcpus);
	ATF_CHECK_EQ(vm_decoded.vcpu_count, vm.vcpu_count);
	vm_before = vm_decoded;
	le32enc(wire + 16, 1);
	ATF_CHECK_EQ(vmm_snapshot_vm_common_decode(wire, written,
	    &vm_decoded), EINVAL);
	ATF_CHECK_EQ(memcmp(&vm_decoded, &vm_before, sizeof(vm_before)), 0);

	vcpu = (struct vmm_snapshot_vcpu_common) {
		.flags = VMM_SNAPSHOT_VCPU_F_STARTUP_WAIT,
		.next_pc = UINT64_C(0xfedcba9876543210),
	};
	memset(wire, 0x5a, sizeof(wire));
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_common_encode(&vcpu, wire,
	    sizeof(wire), &written), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_common_decode(wire, written,
	    &vcpu_decoded), 0);
	memset(&expected_vcpu, 0, sizeof(expected_vcpu));
	expected_vcpu.flags = vcpu.flags;
	expected_vcpu.next_pc = vcpu.next_pc;
	ATF_CHECK_EQ(memcmp(&vcpu_decoded, &expected_vcpu,
	    sizeof(vcpu_decoded)), 0);
	ATF_CHECK_EQ(vcpu_decoded.flags, vcpu.flags);
	ATF_CHECK_EQ(vcpu_decoded.next_pc, vcpu.next_pc);
	vcpu_before = vcpu_decoded;
	le32enc(wire + 4, 2);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_common_decode(wire, written,
	    &vcpu_decoded), EINVAL);
	ATF_CHECK_EQ(memcmp(&vcpu_decoded, &vcpu_before,
	    sizeof(vcpu_before)), 0);

	memset(wire, 0x7c, sizeof(wire));
	memcpy(before, wire, sizeof(wire));
	vm.max_vcpus = 0;
	written = 99;
	ATF_CHECK_EQ(vmm_snapshot_vm_common_encode(&vm, wire, sizeof(wire),
	    &written), EINVAL);
	ATF_CHECK_EQ(written, 99);
	ATF_CHECK_EQ(memcmp(wire, before, sizeof(wire)), 0);
	vm.max_vcpus = 1;
	vm.vcpu_count = 2;
	ATF_CHECK_EQ(vmm_snapshot_vm_common_encode(&vm, wire, sizeof(wire),
	    &written), EINVAL);
	vcpu.flags = 2;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_common_encode(&vcpu, wire, sizeof(wire),
	    &written), EINVAL);
	vm = (struct vmm_snapshot_vm_common) {
		.max_vcpus = 1,
		.vcpu_count = 1,
	};
	ATF_CHECK_EQ(vmm_snapshot_vm_common_encode(&vm, &vm, sizeof(wire),
	    &written), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vm_common_encode(&vm, wire, sizeof(wire),
	    (size_t *)(void *)wire), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vm_common_decode(wire, sizeof(wire),
	    (struct vmm_snapshot_vm_common *)(void *)wire), EINVAL);
	vcpu.flags = 0;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_common_encode(&vcpu, &vcpu,
	    sizeof(wire), &written), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_common_decode(wire, sizeof(wire),
	    (struct vmm_snapshot_vcpu_common *)(void *)wire), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vm_common_decode(NULL, sizeof(wire), &vm),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_common_decode(wire, sizeof(wire), NULL),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vm_common_encode(&vm,
	    (void *)(uintptr_t)(UINTPTR_MAX - 7), sizeof(wire), &written),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vm_common_decode(
	    (const void *)(uintptr_t)(UINTPTR_MAX - 7), sizeof(wire), &vm),
	    EINVAL);
}

ATF_TC_WITHOUT_HEAD(x86_state_codec);
ATF_TC_BODY(x86_state_codec, tc)
{
	struct vmm_snapshot_vcpu_x86 decoded, decoded_before, expected, state;
	uint8_t wire[VMM_SNAPSHOT_VCPU_X86_SIZE];
	size_t written;

	memset(&state, 0, sizeof(state));
	state = (struct vmm_snapshot_vcpu_x86) {
		.flags = VMM_SNAPSHOT_X86_F_NMI_PENDING |
		    VMM_SNAPSHOT_X86_F_EXTINT_PENDING |
		    VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING |
		    VMM_SNAPSHOT_X86_F_EXCEPTION_ERROR,
		.x2apic_state = 1,
		.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_FAULT,
		.exitintinfo = UINT64_C(0x8000030e),
		.exception_vector = 14,
		.exception_error = 5,
		.guest_xcr0 = 7,
		.absolute_tsc = UINT64_C(0x123456789abcdef0),
	};
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_encode(&state, wire,
	    sizeof(wire), &written), 0);
	ATF_CHECK_EQ(written, sizeof(wire));
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_decode(wire, written, &decoded),
	    0);
	memset(&expected, 0, sizeof(expected));
	expected.flags = state.flags;
	expected.x2apic_state = state.x2apic_state;
	expected.exception_class = state.exception_class;
	expected.exitintinfo = state.exitintinfo;
	expected.exception_vector = state.exception_vector;
	expected.exception_error = state.exception_error;
	expected.guest_xcr0 = state.guest_xcr0;
	expected.absolute_tsc = state.absolute_tsc;
	ATF_CHECK_EQ(memcmp(&decoded, &expected, sizeof(decoded)), 0);
	ATF_CHECK_EQ(decoded.flags, state.flags);
	ATF_CHECK_EQ(decoded.x2apic_state, state.x2apic_state);
	ATF_CHECK_EQ(decoded.exception_class, state.exception_class);
	ATF_CHECK_EQ(decoded.exitintinfo, state.exitintinfo);
	ATF_CHECK_EQ(decoded.exception_vector, state.exception_vector);
	ATF_CHECK_EQ(decoded.exception_error, state.exception_error);
	ATF_CHECK_EQ(decoded.guest_xcr0, state.guest_xcr0);
	ATF_CHECK_EQ(decoded.absolute_tsc, state.absolute_tsc);

	decoded_before = decoded;
	for (size_t offset = 48; offset != sizeof(wire); offset += 8) {
		le64enc(wire + offset, 1);
		ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_decode(wire, written,
		    &decoded), EINVAL);
		ATF_CHECK_EQ(decoded.flags, decoded_before.flags);
		ATF_CHECK_EQ(decoded.absolute_tsc, decoded_before.absolute_tsc);
		le64enc(wire + offset, 0);
	}
	le32enc(wire + 12, UINT32_MAX);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_decode(wire, written, &decoded),
	    EINVAL);
	le32enc(wire + 12, state.exception_class);
	le64enc(wire + 16, 1);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_decode(wire, written, &decoded),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&decoded, &decoded_before, sizeof(decoded)), 0);
	le64enc(wire + 16, state.exitintinfo);

	state.flags &= ~(VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING |
	    VMM_SNAPSHOT_X86_F_EXCEPTION_ERROR);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&state), EINVAL);
	state.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_NONE;
	state.exception_vector = 0;
	state.exception_error = 0;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&state), 0);
	state.flags |= VMM_SNAPSHOT_X86_F_EXCEPTION_ERROR;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&state), EINVAL);
	state.flags = VMM_SNAPSHOT_X86_F_EXCEPTION_PENDING;
	state.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_TRAP;
	state.exception_vector = 8;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&state), EINVAL);
	state.exception_vector = 32;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&state), EINVAL);
	state.exception_vector = 1;
	state.exception_class =
	    (enum vmm_snapshot_x86_exception_class)-1;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&state), EINVAL);
	state.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_CLASS_LAST;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&state), EINVAL);
	state.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_ICEBP;
	state.flags |= UINT32_C(0x80000000);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&state), EINVAL);
	state.flags &= ~UINT32_C(0x80000000);
	state.x2apic_state = 2;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&state), EINVAL);
	state.x2apic_state = 0;
	state.guest_xcr0 = 0;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&state), EINVAL);
	state.guest_xcr0 = 1;
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(1, 1, false), 0);
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(3, 3, false), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(3, 3, true), 0);
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(5, UINT64_MAX, true),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(7, UINT64_MAX, true), 0);
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(9, UINT64_MAX, true),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(25, UINT64_MAX, true), 0);
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(0x27, UINT64_MAX, true),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(0xe7, UINT64_MAX, true), 0);
	ATF_CHECK_EQ(vmm_snapshot_x86_xcr0_validate(0xe7, 0x7f, true),
	    EINVAL);
	state.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_ICEBP;
	state.exception_vector = 3;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&state), EINVAL);
	state.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_TRAP;
	state.exception_vector = 3;
	state.flags |= VMM_SNAPSHOT_X86_F_EXCEPTION_ERROR;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(&state), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_validate(NULL), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_decode(wire, sizeof(wire),
	    (struct vmm_snapshot_vcpu_x86 *)(void *)wire), EINVAL);
	memset(&state, 0, sizeof(state));
	state.guest_xcr0 = 1;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_encode(&state,
	    (void *)(uintptr_t)(UINTPTR_MAX - 7), sizeof(wire), &written),
	    EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_decode(
	    (const void *)(uintptr_t)(UINTPTR_MAX - 7), sizeof(wire), &decoded),
	    EINVAL);
}

ATF_TC_WITHOUT_HEAD(x86_event_conversion);
ATF_TC_BODY(x86_event_conversion, tc)
{
	static const struct {
		enum vmm_event_exception_class runtime_class;
		enum vmm_snapshot_x86_exception_class wire_class;
		uint32_t vector;
	} cases[] = {
		{ VMM_EVENT_EXCEPTION_FAULT, VMM_SNAPSHOT_X86_EXCEPTION_FAULT,
		    13 },
		{ VMM_EVENT_EXCEPTION_TRAP, VMM_SNAPSHOT_X86_EXCEPTION_TRAP, 3 },
		{ VMM_EVENT_EXCEPTION_ICEBP, VMM_SNAPSHOT_X86_EXCEPTION_ICEBP,
		    1 },
		{ VMM_EVENT_EXCEPTION_TASK_SWITCH,
		    VMM_SNAPSHOT_X86_EXCEPTION_TASK_SWITCH, 1 },
	};
	struct vmm_event_state event, event_before, roundtrip;
	struct vmm_snapshot_vcpu_x86 state, state_before;

	(void)tc;
	for (size_t i = 0; i < nitems(cases); i++) {
		memset(&event, 0, sizeof(event));
		event.flags = VMM_EVENT_STATE_F_NMI_PENDING |
		    VMM_EVENT_STATE_F_EXTINT_PENDING |
		    VMM_EVENT_STATE_F_EXCEPTION_PENDING;
		event.exception_vector = cases[i].vector;
		event.exception_class = cases[i].runtime_class;
		memset(&state, 0, sizeof(state));
		state.guest_xcr0 = 1;
		ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_event_from_runtime(&event,
		    &state), 0);
		ATF_CHECK_EQ(state.exception_class, cases[i].wire_class);
		ATF_CHECK((state.flags & VMM_SNAPSHOT_X86_F_NMI_PENDING) != 0);
		ATF_CHECK((state.flags & VMM_SNAPSHOT_X86_F_EXTINT_PENDING) != 0);
		ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_event_to_runtime(&state,
		    &roundtrip), 0);
		ATF_CHECK_EQ(memcmp(&roundtrip, &event, sizeof(event)), 0);
	}

	memset(&event, 0, sizeof(event));
	memset(&state, 0, sizeof(state));
	state.guest_xcr0 = 1;
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_event_from_runtime(&event, &state),
	    0);
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_event_to_runtime(&state,
	    &roundtrip), 0);
	ATF_CHECK_EQ(memcmp(&roundtrip, &event, sizeof(event)), 0);

	state_before = state;
	event.exception_class = VMM_EVENT_EXCEPTION_CLASS_LAST;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_event_from_runtime(&event, &state),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&state, &state_before, sizeof(state)), 0);
	event = roundtrip;
	event_before = event;
	state.exception_class = VMM_SNAPSHOT_X86_EXCEPTION_CLASS_LAST;
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_event_to_runtime(&state, &event),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&event, &event_before, sizeof(event)), 0);
	ATF_CHECK_EQ(vmm_snapshot_vcpu_x86_event_from_runtime(
	    (const struct vmm_event_state *)(const void *)&state, &state),
	    EINVAL);
}

ATF_TC_WITHOUT_HEAD(x86_transaction);
ATF_TC_BODY(x86_transaction, tc)
{
	struct vmm_snapshot_envelope_builder builder;
	struct vmm_snapshot_vm_common vm = { .max_vcpus = 4, .vcpu_count = 1 };
	struct vmm_snapshot_vcpu_common common = { .next_pc = 0x1000 };
	struct vmm_snapshot_vcpu_x86 x86 = { .guest_xcr0 = 1 };
	struct vmm_snapshot_vcpu_x86_fpu fpu;
	struct vmm_snapshot_x86_vcpu_stage stage, before;
	struct vmm_snapshot_x86_vcpu_stage expected_stage;
	struct vmm_snapshot_x86_transaction transaction, tx_before;
	struct vmm_snapshot_x86_transaction expected_transaction;
	uint8_t wire[1024], payload[FPU_LEGACY_PAYLOAD_SIZE + 64];
	size_t length, written;

	(void)tc;
	ATF_REQUIRE_EQ(vmm_snapshot_vm_common_encode(&vm, payload,
	    sizeof(payload), &written), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_builder_init(&builder, wire,
	    sizeof(wire)), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&builder,
	    VMM_SNAPSHOT_SECTION_VM_COMMON, VMM_SNAPSHOT_SECTION_F_CRITICAL,
	    0, payload, written), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_common_encode(&common, payload,
	    sizeof(payload), &written), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&builder,
	    VMM_SNAPSHOT_SECTION_VCPU_COMMON, VMM_SNAPSHOT_SECTION_F_CRITICAL,
	    2, payload, written), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_encode(&x86, payload,
	    sizeof(payload), &written), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&builder,
	    VMM_SNAPSHOT_SECTION_VCPU_X86, VMM_SNAPSHOT_SECTION_F_CRITICAL,
	    2, payload, written), 0);
	fpu_stage_init(&fpu);
	ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_fpu_encode(&fpu, payload,
	    sizeof(payload), &written), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&builder,
	    VMM_SNAPSHOT_SECTION_VCPU_X86_FPU, VMM_SNAPSHOT_SECTION_F_CRITICAL,
	    2, payload, written), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_finalize(&builder, &length), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_x86_transaction_decode(wire, length, &stage,
	    1, &transaction), 0);
	memset(&expected_stage, 0, sizeof(expected_stage));
	expected_stage.instance = 2;
	expected_stage.common.next_pc = 0x1000;
	expected_stage.x86.guest_xcr0 = 1;
	fpu_stage_init(&expected_stage.fpu);
	memset(&expected_transaction, 0, sizeof(expected_transaction));
	expected_transaction.vm = vm;
	expected_transaction.vcpu_count = 1;
	ATF_CHECK_EQ(memcmp(&stage, &expected_stage, sizeof(stage)), 0);
	ATF_CHECK_EQ(memcmp(&transaction, &expected_transaction,
	    sizeof(transaction)), 0);
	ATF_CHECK_EQ(transaction.vcpu_count, 1);
	ATF_CHECK_EQ(stage.instance, 2);
	ATF_CHECK_EQ(stage.common.next_pc, UINT64_C(0x1000));

	before = stage;
	tx_before = transaction;
	/* Change only the x86 section instance; pass one must reject untouched. */
	le32enc(wire + VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE +
	    VMM_SNAPSHOT_SECTION_HEADER_SIZE + VMM_SNAPSHOT_VM_COMMON_SIZE +
	    VMM_SNAPSHOT_SECTION_HEADER_SIZE + VMM_SNAPSHOT_VCPU_COMMON_SIZE + 4,
	    3);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_decode(wire, length, &stage, 1,
	    &transaction), EINVAL);
	ATF_CHECK_EQ(memcmp(&stage, &before, sizeof(stage)), 0);
	ATF_CHECK_EQ(memcmp(&transaction, &tx_before, sizeof(transaction)), 0);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_decode(wire, length,
	    (struct vmm_snapshot_x86_vcpu_stage *)(void *)wire, 1,
	    &transaction), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_decode(wire, length, &stage,
	    SIZE_MAX, &transaction), EINVAL);
}

ATF_TC_WITHOUT_HEAD(x86_transaction_multivcpu);
ATF_TC_BODY(x86_transaction_multivcpu, tc)
{
	struct vmm_snapshot_envelope_builder builder;
	struct vmm_snapshot_vm_common vm = { .max_vcpus = 8, .vcpu_count = 2 };
	struct vmm_snapshot_vcpu_common common[2] = {
	    { .next_pc = 0x1000 }, { .next_pc = 0x7000 },
	};
	struct vmm_snapshot_vcpu_x86 x86[2] = {
	    { .guest_xcr0 = 1 },
	    { .x2apic_state = 1, .guest_xcr0 = 1 },
	};
	struct vmm_snapshot_vcpu_x86_fpu fpu;
	struct vmm_snapshot_x86_vcpu_stage stage[2], before[2];
	struct vmm_snapshot_x86_transaction transaction, tx_before;
	uint8_t wire[2048], payload[FPU_LEGACY_PAYLOAD_SIZE + 64];
	size_t length, written;
	const size_t x86_second = VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE +
	    VMM_SNAPSHOT_SECTION_HEADER_SIZE + VMM_SNAPSHOT_VM_COMMON_SIZE +
	    2 * (VMM_SNAPSHOT_SECTION_HEADER_SIZE +
	    VMM_SNAPSHOT_VCPU_COMMON_SIZE) +
	    VMM_SNAPSHOT_SECTION_HEADER_SIZE + VMM_SNAPSHOT_VCPU_X86_SIZE;

	(void)tc;
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_builder_init(&builder, wire,
	    sizeof(wire)), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_vm_common_encode(&vm, payload,
	    sizeof(payload), &written), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&builder,
	    VMM_SNAPSHOT_SECTION_VM_COMMON, VMM_SNAPSHOT_SECTION_F_CRITICAL,
	    0, payload, written), 0);
	for (size_t i = 0; i < 2; i++) {
		ATF_REQUIRE_EQ(vmm_snapshot_vcpu_common_encode(&common[i], payload,
		    sizeof(payload), &written), 0);
		ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&builder,
		    VMM_SNAPSHOT_SECTION_VCPU_COMMON,
		    VMM_SNAPSHOT_SECTION_F_CRITICAL, i == 0 ? 1 : 7,
		    payload, written), 0);
	}
	for (size_t i = 0; i < 2; i++) {
		ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_encode(&x86[i], payload,
		    sizeof(payload), &written), 0);
		ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&builder,
		    VMM_SNAPSHOT_SECTION_VCPU_X86,
		    VMM_SNAPSHOT_SECTION_F_CRITICAL, i == 0 ? 1 : 7,
		    payload, written), 0);
	}
	fpu_stage_init(&fpu);
	for (size_t i = 0; i < 2; i++) {
		ATF_REQUIRE_EQ(vmm_snapshot_vcpu_x86_fpu_encode(&fpu, payload,
		    sizeof(payload), &written), 0);
		ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&builder,
		    VMM_SNAPSHOT_SECTION_VCPU_X86_FPU,
		    VMM_SNAPSHOT_SECTION_F_CRITICAL, i == 0 ? 1 : 7,
		    payload, written), 0);
	}
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_finalize(&builder, &length), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_x86_transaction_decode(wire, length, stage,
	    2, &transaction), 0);
	ATF_CHECK_EQ(transaction.vcpu_count, 2);
	ATF_CHECK_EQ(stage[0].instance, 1);
	ATF_CHECK_EQ(stage[0].common.next_pc, UINT64_C(0x1000));
	ATF_CHECK_EQ(stage[1].instance, 7);
	ATF_CHECK_EQ(stage[1].common.next_pc, UINT64_C(0x7000));
	{
		const uint32_t destination[] = { 1, 7 };
		const uint32_t missing[] = { 1 };
		const uint32_t reordered[] = { 7, 1 };
		const uint8_t lapic_modes[] = { 0, 1 };
		const uint8_t wrong_lapic_modes[] = { 0, 0 };
		const uint8_t invalid_lapic_modes[] = { 0, 2 };

		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
		    &transaction, stage, 2, 8, destination, 2), 0);
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
		    &transaction, stage, 2, 4, destination, 2), EINVAL);
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
		    &transaction, stage, 2, 8, missing, 1), EINVAL);
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
		    &transaction, stage, 2, 8, reordered, 2), EINVAL);
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
		    &transaction, stage, 1, 8, destination, 2), EINVAL);
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
		    (const struct vmm_snapshot_x86_transaction *)(const void *)
		    (UINTPTR_MAX - 3), stage, 2, 8, destination, 2), EINVAL);
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
		    &transaction,
		    (const struct vmm_snapshot_x86_vcpu_stage *)(const void *)
		    (UINTPTR_MAX - 3), 2, 8, destination, 2), EINVAL);
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
		    &transaction, stage, 2, 8,
		    (const uint32_t *)(const void *)(UINTPTR_MAX - 3), 2),
		    EINVAL);
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
		    (const struct vmm_snapshot_x86_transaction *)(const void *)stage,
		    stage, 2, 8, destination, 2), EINVAL);
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
		    &transaction, stage, 2, 8,
		    (const uint32_t *)(const void *)stage, 2), EINVAL);
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_restore_preflight(
		    &transaction, stage, 2, 8, destination, lapic_modes, 2), 0);
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_restore_preflight(
		    &transaction, stage, 2, 8, destination, wrong_lapic_modes,
		    2), EINVAL);
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_restore_preflight(
		    &transaction, stage, 2, 8, destination,
		    invalid_lapic_modes, 2), EINVAL);
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_restore_preflight(
		    &transaction, stage, 2, 8, destination, NULL, 2), EINVAL);
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_restore_preflight(
		    &transaction, stage, 2, 8, destination,
		    (const uint8_t *)(const void *)stage, 2), EINVAL);
		ATF_CHECK_EQ(vmm_snapshot_x86_transaction_restore_preflight(
		    &transaction, stage, 2, 8, destination,
		    (const uint8_t *)(const void *)UINTPTR_MAX, 2),
		    EINVAL);
	}

	memset(before, 0xa5, sizeof(before));
	memset(&tx_before, 0x5a, sizeof(tx_before));
	memcpy(stage, before, sizeof(stage));
	transaction = tx_before;
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_decode(wire, length, stage, 1,
	    &transaction), E2BIG);
	ATF_CHECK_EQ(memcmp(stage, before, sizeof(stage)), 0);
	ATF_CHECK_EQ(memcmp(&transaction, &tx_before, sizeof(transaction)), 0);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_decode(wire, length, NULL, 0,
	    &transaction), E2BIG);
	ATF_CHECK_EQ(memcmp(&transaction, &tx_before, sizeof(transaction)), 0);
	/* Make the second x86 instance differ from the common instance set. */
	le32enc(wire + x86_second + 8, 6);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_decode(wire, length, stage, 2,
	    &transaction), EINVAL);
	ATF_CHECK_EQ(memcmp(stage, before, sizeof(stage)), 0);
	ATF_CHECK_EQ(memcmp(&transaction, &tx_before, sizeof(transaction)), 0);
	/* Repeated common-instance sections are not a canonical transaction. */
	le32enc(wire + x86_second + 8, 7);
	le32enc(wire + VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE +
	    VMM_SNAPSHOT_SECTION_HEADER_SIZE + VMM_SNAPSHOT_VM_COMMON_SIZE +
	    VMM_SNAPSHOT_SECTION_HEADER_SIZE + VMM_SNAPSHOT_VCPU_COMMON_SIZE + 8,
	    1);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_decode(wire, length, stage, 2,
	    &transaction), EINVAL);
	ATF_CHECK_EQ(memcmp(stage, before, sizeof(stage)), 0);
	ATF_CHECK_EQ(memcmp(&transaction, &tx_before, sizeof(transaction)), 0);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_decode(
	    (const void *)(UINTPTR_MAX - 3), 8, stage, 2, &transaction), EINVAL);
}

ATF_TC_WITHOUT_HEAD(x86_transaction_encode);
ATF_TC_BODY(x86_transaction_encode, tc)
{
	struct vmm_snapshot_x86_transaction transaction = {
	    .vm = { .max_vcpus = 8, .vcpu_count = 2 },
	    .vcpu_count = 2,
	};
	struct vmm_snapshot_x86_vcpu_stage source[2] = {
	    {
		.instance = 1,
		.common = { .next_pc = UINT64_C(0x1000) },
		.x86 = { .guest_xcr0 = 1, .absolute_tsc = 9 },
	    },
	    {
		.instance = 7,
		.common = {
		    .flags = VMM_SNAPSHOT_VCPU_F_STARTUP_WAIT,
		    .next_pc = UINT64_C(0x7000),
		},
		.x86 = {
		    .x2apic_state = 1,
		    .guest_xcr0 = 1,
		    .absolute_tsc = 11,
		},
	    },
	};
	struct vmm_snapshot_x86_vcpu_stage decoded[2], invalid[2];
	struct vmm_snapshot_x86_transaction decoded_transaction;
	uint8_t wire[2048], wire_roundtrip[2048], before[2048];
	size_t length, roundtrip_length, sentinel;

	(void)tc;
	fpu_stage_init(&source[0].fpu);
	fpu_stage_init(&source[1].fpu);
	memset(wire, 0xa5, sizeof(wire));
	ATF_REQUIRE_EQ(vmm_snapshot_x86_transaction_encode(&transaction,
	    source, 2, wire, sizeof(wire), &length), 0);
	ATF_CHECK_EQ(length, 384 + 2 * (VMM_SNAPSHOT_SECTION_HEADER_SIZE +
	    FPU_LEGACY_PAYLOAD_SIZE));
	ATF_REQUIRE_EQ(vmm_snapshot_x86_transaction_decode(wire, length,
	    decoded, 2, &decoded_transaction), 0);
	ATF_CHECK_EQ(decoded_transaction.vm.max_vcpus,
	    transaction.vm.max_vcpus);
	ATF_CHECK_EQ(decoded_transaction.vm.vcpu_count,
	    transaction.vm.vcpu_count);
	ATF_CHECK_EQ(decoded_transaction.vcpu_count, transaction.vcpu_count);
	ATF_REQUIRE_EQ(vmm_snapshot_x86_transaction_encode(
	    &decoded_transaction, decoded, 2, wire_roundtrip,
	    sizeof(wire_roundtrip), &roundtrip_length), 0);
	ATF_CHECK_EQ(roundtrip_length, length);
	ATF_CHECK_EQ(memcmp(wire_roundtrip, wire, length), 0);

	memset(wire, 0x5a, sizeof(wire));
	memcpy(before, wire, sizeof(wire));
	sentinel = SIZE_MAX;
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&transaction, source,
	    2, wire, 383, &sentinel), E2BIG);
	ATF_CHECK_EQ(sentinel, SIZE_MAX);
	ATF_CHECK_EQ(memcmp(wire, before, sizeof(wire)), 0);
	invalid[0] = source[0];
	invalid[1] = source[1];
	invalid[1].instance = invalid[0].instance;
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&transaction, invalid,
	    2, wire, sizeof(wire), &sentinel), EINVAL);
	ATF_CHECK_EQ(memcmp(wire, before, sizeof(wire)), 0);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&transaction, source,
	    1, wire, sizeof(wire), &sentinel), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&transaction, source,
	    2, source, sizeof(source), &sentinel), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(&transaction, source,
	    2, wire, sizeof(wire), (size_t *)(void *)wire), EINVAL);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_encode(
	    (const struct vmm_snapshot_x86_transaction *)(const void *)
	    UINTPTR_MAX, source, 2, wire, sizeof(wire), &sentinel), EINVAL);
}

ATF_TC_WITHOUT_HEAD(x86_transaction_zero_vcpus);
ATF_TC_BODY(x86_transaction_zero_vcpus, tc)
{
	struct vmm_snapshot_envelope_builder builder;
	struct vmm_snapshot_vm_common vm = { .max_vcpus = 4, .vcpu_count = 0 };
	struct vmm_snapshot_x86_transaction transaction;
	uint8_t wire[128], payload[VMM_SNAPSHOT_VM_COMMON_SIZE];
	size_t length, written;

	(void)tc;
	ATF_REQUIRE_EQ(vmm_snapshot_vm_common_encode(&vm, payload,
	    sizeof(payload), &written), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_builder_init(&builder, wire,
	    sizeof(wire)), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&builder,
	    VMM_SNAPSHOT_SECTION_VM_COMMON, VMM_SNAPSHOT_SECTION_F_CRITICAL,
	    0, payload, written), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_finalize(&builder, &length), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_x86_transaction_decode(wire, length, NULL, 0,
	    &transaction), 0);
	ATF_CHECK_EQ(transaction.vcpu_count, 0);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_validate_destination(
	    &transaction, NULL, 0, 4, NULL, 0), 0);
	ATF_CHECK_EQ(vmm_snapshot_x86_transaction_restore_preflight(
	    &transaction, NULL, 0, 4, NULL, NULL, 0), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, round_trip);
	ATF_TP_ADD_TC(tp, builder_transactionality);
	ATF_TP_ADD_TC(tp, malformed_records);
	ATF_TP_ADD_TC(tp, argument_boundaries);
	ATF_TP_ADD_TC(tp, common_state_codecs);
	ATF_TP_ADD_TC(tp, x86_state_codec);
	ATF_TP_ADD_TC(tp, x86_event_conversion);
	ATF_TP_ADD_TC(tp, x86_transaction);
	ATF_TP_ADD_TC(tp, x86_transaction_multivcpu);
	ATF_TP_ADD_TC(tp, x86_transaction_encode);
	ATF_TP_ADD_TC(tp, x86_transaction_zero_vcpus);
	return (atf_no_error());
}
