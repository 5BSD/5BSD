/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_guest.h"
#include "vmx_nested_l2_state.h"
#include "vmx_nested_state_range.h"

#define	NVMXL2S_MAGIC		UINT32_C(0x3153324c)	/* "L2S1" */
#define	NVMXL2S_VERSION		2U
#define	NVMXL2S_DIGEST_OFFSET	32U
#define	NVMXL2S_FLAGS_OFFSET	40U
#define	NVMXL2S_F_MTF_PENDING	(UINT64_C(1) << 0)

struct nvmxl2s_cursor {
	uint8_t	*bytes;
	size_t	offset;
	size_t	length;
};

struct nvmxl2s_reader {
	const uint8_t	*bytes;
	size_t		offset;
	size_t		length;
};

static uint64_t
nvmxl2s_digest(const uint8_t *bytes, size_t length)
{
	uint64_t digest;

	digest = UINT64_C(14695981039346656037);
	for (size_t i = 0; i < length; i++) {
		uint8_t byte;

		byte = i >= NVMXL2S_DIGEST_OFFSET &&
		    i < NVMXL2S_DIGEST_OFFSET + sizeof(uint64_t) ?
		    0 : bytes[i];
		digest ^= byte;
		digest *= UINT64_C(1099511628211);
	}
	return (digest);
}

static int
nvmxl2s_put8(struct nvmxl2s_cursor *cursor, uint8_t value)
{

	if (cursor->offset >= cursor->length)
		return (EOVERFLOW);
	cursor->bytes[cursor->offset++] = value;
	return (0);
}

static int
nvmxl2s_put16(struct nvmxl2s_cursor *cursor, uint16_t value)
{

	if (cursor->offset > cursor->length ||
	    cursor->length - cursor->offset < sizeof(value))
		return (EOVERFLOW);
	le16enc(cursor->bytes + cursor->offset, value);
	cursor->offset += sizeof(value);
	return (0);
}

static int
nvmxl2s_put32(struct nvmxl2s_cursor *cursor, uint32_t value)
{

	if (cursor->offset > cursor->length ||
	    cursor->length - cursor->offset < sizeof(value))
		return (EOVERFLOW);
	le32enc(cursor->bytes + cursor->offset, value);
	cursor->offset += sizeof(value);
	return (0);
}

static int
nvmxl2s_put64(struct nvmxl2s_cursor *cursor, uint64_t value)
{

	if (cursor->offset > cursor->length ||
	    cursor->length - cursor->offset < sizeof(value))
		return (EOVERFLOW);
	le64enc(cursor->bytes + cursor->offset, value);
	cursor->offset += sizeof(value);
	return (0);
}

static int
nvmxl2s_get8(struct nvmxl2s_reader *reader, uint8_t *value)
{

	if (reader->offset >= reader->length)
		return (EPROTO);
	*value = reader->bytes[reader->offset++];
	return (0);
}

static int
nvmxl2s_get16(struct nvmxl2s_reader *reader, uint16_t *value)
{

	if (reader->offset > reader->length ||
	    reader->length - reader->offset < sizeof(*value))
		return (EPROTO);
	*value = le16dec(reader->bytes + reader->offset);
	reader->offset += sizeof(*value);
	return (0);
}

static int
nvmxl2s_get32(struct nvmxl2s_reader *reader, uint32_t *value)
{

	if (reader->offset > reader->length ||
	    reader->length - reader->offset < sizeof(*value))
		return (EPROTO);
	*value = le32dec(reader->bytes + reader->offset);
	reader->offset += sizeof(*value);
	return (0);
}

static int
nvmxl2s_get64(struct nvmxl2s_reader *reader, uint64_t *value)
{

	if (reader->offset > reader->length ||
	    reader->length - reader->offset < sizeof(*value))
		return (EPROTO);
	*value = le64dec(reader->bytes + reader->offset);
	reader->offset += sizeof(*value);
	return (0);
}

static int
nvmxl2s_put_bool(struct nvmxl2s_cursor *cursor, bool value)
{

	return (nvmxl2s_put8(cursor, value ? 1 : 0));
}

static int
nvmxl2s_get_bool(struct nvmxl2s_reader *reader, bool *value)
{
	uint8_t byte;
	int error;

	error = nvmxl2s_get8(reader, &byte);
	if (error != 0)
		return (error);
	if (byte > 1)
		return (EPROTO);
	*value = byte != 0;
	return (0);
}

#define	NVMXL2S_PUT(cursor, width, value) do {			\
	error = nvmxl2s_put##width((cursor), (value));		\
	if (error != 0)						\
		return (error);					\
} while (0)

#define	NVMXL2S_GET(reader, width, value) do {			\
	error = nvmxl2s_get##width((reader), (value));		\
	if (error != 0)						\
		return (error);					\
} while (0)

static int
nvmxl2s_encode_control(struct nvmxl2s_cursor *cursor,
    const struct vmx_nested_guest_control_state *state)
{
	int error;

	NVMXL2S_PUT(cursor, 64, state->cr0);
	NVMXL2S_PUT(cursor, 64, state->cr3);
	NVMXL2S_PUT(cursor, 64, state->cr4);
	NVMXL2S_PUT(cursor, 64, state->dr7);
	NVMXL2S_PUT(cursor, 32, state->sysenter_cs);
	NVMXL2S_PUT(cursor, 64, state->sysenter_esp);
	NVMXL2S_PUT(cursor, 64, state->sysenter_eip);
	NVMXL2S_PUT(cursor, 64, state->pat);
	NVMXL2S_PUT(cursor, 64, state->efer);
	return (0);
}

static int
nvmxl2s_decode_control(struct nvmxl2s_reader *reader,
    struct vmx_nested_guest_control_state *state)
{
	int error;

	NVMXL2S_GET(reader, 64, &state->cr0);
	NVMXL2S_GET(reader, 64, &state->cr3);
	NVMXL2S_GET(reader, 64, &state->cr4);
	NVMXL2S_GET(reader, 64, &state->dr7);
	NVMXL2S_GET(reader, 32, &state->sysenter_cs);
	NVMXL2S_GET(reader, 64, &state->sysenter_esp);
	NVMXL2S_GET(reader, 64, &state->sysenter_eip);
	NVMXL2S_GET(reader, 64, &state->pat);
	NVMXL2S_GET(reader, 64, &state->efer);
	return (0);
}

static int
nvmxl2s_encode_arch(struct nvmxl2s_cursor *cursor,
    const struct vmx_nested_guest_arch_state *state)
{
	int error;

	for (uint32_t i = 0; i < VMX_NESTED_GUEST_SEGMENT_COUNT; i++) {
		NVMXL2S_PUT(cursor, 16, state->segment[i].selector);
		NVMXL2S_PUT(cursor, 32, state->segment[i].limit);
		NVMXL2S_PUT(cursor, 32, state->segment[i].access);
		NVMXL2S_PUT(cursor, 64, state->segment[i].base);
	}
	NVMXL2S_PUT(cursor, 32, state->gdtr_limit);
	NVMXL2S_PUT(cursor, 32, state->idtr_limit);
	NVMXL2S_PUT(cursor, 64, state->gdtr_base);
	NVMXL2S_PUT(cursor, 64, state->idtr_base);
	NVMXL2S_PUT(cursor, 64, state->rsp);
	NVMXL2S_PUT(cursor, 64, state->rip);
	NVMXL2S_PUT(cursor, 64, state->rflags);
	NVMXL2S_PUT(cursor, 64, state->pending_debug);
	NVMXL2S_PUT(cursor, 64, state->debugctl);
	NVMXL2S_PUT(cursor, 32, state->activity);
	NVMXL2S_PUT(cursor, 32, state->interruptibility);
	error = nvmxl2s_put_bool(cursor, state->in_smm);
	return (error);
}

static int
nvmxl2s_decode_arch(struct nvmxl2s_reader *reader,
    struct vmx_nested_guest_arch_state *state)
{
	int error;

	for (uint32_t i = 0; i < VMX_NESTED_GUEST_SEGMENT_COUNT; i++) {
		NVMXL2S_GET(reader, 16, &state->segment[i].selector);
		NVMXL2S_GET(reader, 32, &state->segment[i].limit);
		NVMXL2S_GET(reader, 32, &state->segment[i].access);
		NVMXL2S_GET(reader, 64, &state->segment[i].base);
	}
	NVMXL2S_GET(reader, 32, &state->gdtr_limit);
	NVMXL2S_GET(reader, 32, &state->idtr_limit);
	NVMXL2S_GET(reader, 64, &state->gdtr_base);
	NVMXL2S_GET(reader, 64, &state->idtr_base);
	NVMXL2S_GET(reader, 64, &state->rsp);
	NVMXL2S_GET(reader, 64, &state->rip);
	NVMXL2S_GET(reader, 64, &state->rflags);
	NVMXL2S_GET(reader, 64, &state->pending_debug);
	NVMXL2S_GET(reader, 64, &state->debugctl);
	NVMXL2S_GET(reader, 32, &state->activity);
	NVMXL2S_GET(reader, 32, &state->interruptibility);
	return (nvmxl2s_get_bool(reader, &state->in_smm));
}

static int
nvmxl2s_encode_body(struct nvmxl2s_cursor *cursor,
    const struct vmx_nested_l2_portable_state *state)
{
	const struct vmx_nested_exit_information *exit;
	int error;

	NVMXL2S_PUT(cursor, 64, state->id.state_generation);
	NVMXL2S_PUT(cursor, 64, state->id.execution_epoch);
	NVMXL2S_PUT(cursor, 64, state->id.vmcs12_gpa);
	NVMXL2S_PUT(cursor, 64, state->portable_generation);
	NVMXL2S_PUT(cursor, 64, state->capability_signature);
	error = nvmxl2s_encode_control(cursor, &state->runtime.control);
	if (error != 0)
		return (error);
	error = nvmxl2s_encode_arch(cursor, &state->runtime.arch);
	if (error != 0)
		return (error);
	NVMXL2S_PUT(cursor, 64, state->software_msrs.star);
	NVMXL2S_PUT(cursor, 64, state->software_msrs.lstar);
	NVMXL2S_PUT(cursor, 64, state->software_msrs.cstar);
	NVMXL2S_PUT(cursor, 64, state->software_msrs.sfmask);
	NVMXL2S_PUT(cursor, 64, state->software_msrs.kgsbase);
	NVMXL2S_PUT(cursor, 64, state->software_msrs.tsc_aux);
	exit = &state->exit;
	NVMXL2S_PUT(cursor, 64, exit->exit_qualification);
	NVMXL2S_PUT(cursor, 64, exit->guest_linear_address);
	NVMXL2S_PUT(cursor, 64, exit->guest_physical_address);
	NVMXL2S_PUT(cursor, 32, exit->exit_reason);
	NVMXL2S_PUT(cursor, 32, exit->exit_interruption_info);
	NVMXL2S_PUT(cursor, 32, exit->exit_interruption_error);
	NVMXL2S_PUT(cursor, 32, exit->idt_vectoring_info);
	NVMXL2S_PUT(cursor, 32, exit->idt_vectoring_error);
	NVMXL2S_PUT(cursor, 32, exit->exit_instruction_length);
	NVMXL2S_PUT(cursor, 32, exit->exit_instruction_info);
	NVMXL2S_PUT(cursor, 32, exit->entry_interruption_info);
	error = nvmxl2s_put_bool(cursor, exit->launched);
	if (error != 0)
		return (error);
	for (uint32_t i = 0; i < 4; i++)
		NVMXL2S_PUT(cursor, 64, state->pdpte.value[i]);
	error = nvmxl2s_put_bool(cursor, state->pdpte.active);
	if (error != 0)
		return (error);
	NVMXL2S_PUT(cursor, 64, state->preemption_timer.deadline_ticks);
	NVMXL2S_PUT(cursor, 32, state->preemption_timer.remaining);
	error = nvmxl2s_put_bool(cursor, state->preemption_timer.armed);
	if (error != 0)
		return (error);
	error = nvmxl2s_put_bool(cursor, state->preemption_timer.expired);
	if (error != 0)
		return (error);
	NVMXL2S_PUT(cursor, 32, state->entry_intr_info);
	NVMXL2S_PUT(cursor, 32, state->entry_exception_error);
	NVMXL2S_PUT(cursor, 32, state->entry_instruction_length);
	NVMXL2S_PUT(cursor, 16, state->guest_interrupt_status);
	error = nvmxl2s_put_bool(cursor, state->exit_valid);
	if (error != 0)
		return (error);
	error = nvmxl2s_put_bool(cursor, state->preemption_timer_enabled);
	if (error != 0)
		return (error);
	return (nvmxl2s_put_bool(cursor,
	    state->guest_interrupt_status_valid));
}

static int
nvmxl2s_decode_body(struct nvmxl2s_reader *reader,
    struct vmx_nested_l2_portable_state *state)
{
	struct vmx_nested_exit_information *exit;
	int error;

	NVMXL2S_GET(reader, 64, &state->id.state_generation);
	NVMXL2S_GET(reader, 64, &state->id.execution_epoch);
	NVMXL2S_GET(reader, 64, &state->id.vmcs12_gpa);
	NVMXL2S_GET(reader, 64, &state->portable_generation);
	NVMXL2S_GET(reader, 64, &state->capability_signature);
	error = nvmxl2s_decode_control(reader, &state->runtime.control);
	if (error != 0)
		return (error);
	error = nvmxl2s_decode_arch(reader, &state->runtime.arch);
	if (error != 0)
		return (error);
	NVMXL2S_GET(reader, 64, &state->software_msrs.star);
	NVMXL2S_GET(reader, 64, &state->software_msrs.lstar);
	NVMXL2S_GET(reader, 64, &state->software_msrs.cstar);
	NVMXL2S_GET(reader, 64, &state->software_msrs.sfmask);
	NVMXL2S_GET(reader, 64, &state->software_msrs.kgsbase);
	NVMXL2S_GET(reader, 64, &state->software_msrs.tsc_aux);
	exit = &state->exit;
	NVMXL2S_GET(reader, 64, &exit->exit_qualification);
	NVMXL2S_GET(reader, 64, &exit->guest_linear_address);
	NVMXL2S_GET(reader, 64, &exit->guest_physical_address);
	NVMXL2S_GET(reader, 32, &exit->exit_reason);
	NVMXL2S_GET(reader, 32, &exit->exit_interruption_info);
	NVMXL2S_GET(reader, 32, &exit->exit_interruption_error);
	NVMXL2S_GET(reader, 32, &exit->idt_vectoring_info);
	NVMXL2S_GET(reader, 32, &exit->idt_vectoring_error);
	NVMXL2S_GET(reader, 32, &exit->exit_instruction_length);
	NVMXL2S_GET(reader, 32, &exit->exit_instruction_info);
	NVMXL2S_GET(reader, 32, &exit->entry_interruption_info);
	error = nvmxl2s_get_bool(reader, &exit->launched);
	if (error != 0)
		return (error);
	for (uint32_t i = 0; i < 4; i++)
		NVMXL2S_GET(reader, 64, &state->pdpte.value[i]);
	error = nvmxl2s_get_bool(reader, &state->pdpte.active);
	if (error != 0)
		return (error);
	NVMXL2S_GET(reader, 64, &state->preemption_timer.deadline_ticks);
	NVMXL2S_GET(reader, 32, &state->preemption_timer.remaining);
	error = nvmxl2s_get_bool(reader, &state->preemption_timer.armed);
	if (error != 0)
		return (error);
	error = nvmxl2s_get_bool(reader, &state->preemption_timer.expired);
	if (error != 0)
		return (error);
	NVMXL2S_GET(reader, 32, &state->entry_intr_info);
	NVMXL2S_GET(reader, 32, &state->entry_exception_error);
	NVMXL2S_GET(reader, 32, &state->entry_instruction_length);
	NVMXL2S_GET(reader, 16, &state->guest_interrupt_status);
	error = nvmxl2s_get_bool(reader, &state->exit_valid);
	if (error != 0)
		return (error);
	error = nvmxl2s_get_bool(reader,
	    &state->preemption_timer_enabled);
	if (error != 0)
		return (error);
	/*
	 * The runtime image's captured preemption-timer residual is
	 * derivable: a frozen timer does not run, so the capture is exactly
	 * the canonical timer state's remaining value.  Rebuild it here
	 * instead of extending the serialized ABI.
	 */
	state->runtime.preemption_timer_valid =
	    state->preemption_timer_enabled;
	state->runtime.preemption_timer_value =
	    state->preemption_timer_enabled ?
	    state->preemption_timer.remaining : 0;
	return (nvmxl2s_get_bool(reader,
	    &state->guest_interrupt_status_valid));
}

int
vmx_nested_l2_state_encode(
    const struct vmx_nested_l2_portable_state *state, void *buffer,
    size_t capacity, size_t *written)
{
	struct nvmxl2s_cursor cursor;
	uint8_t *bytes;
	int error;

	if (state == NULL || buffer == NULL || written == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(buffer, VMX_NESTED_L2_STATE_SIZE,
	    state, sizeof(*state)) ||
	    vmx_nested_state_ranges_overlap(buffer, VMX_NESTED_L2_STATE_SIZE,
	    written, sizeof(*written)) ||
	    vmx_nested_state_ranges_overlap(written, sizeof(*written),
	    state, sizeof(*state)))
		return (EINVAL);
	*written = 0;
	if (capacity < VMX_NESTED_L2_STATE_SIZE)
		return (ENOSPC);
	error = vmx_nested_l2_portable_validate(state);
	if (error != 0)
		return (error);
	bytes = buffer;
	memset(bytes, 0, VMX_NESTED_L2_STATE_SIZE);
	le32enc(bytes, NVMXL2S_MAGIC);
	le16enc(bytes + 4, NVMXL2S_VERSION);
	le16enc(bytes + 6, VMX_NESTED_L2_STATE_HEADER_SIZE);
	le32enc(bytes + 8, VMX_NESTED_L2_STATE_SIZE);
	le32enc(bytes + 12, VMX_NESTED_L2_STATE_HEADER_SIZE);
	le32enc(bytes + 16, VMX_NESTED_L2_STATE_BODY_SIZE);
	le64enc(bytes + NVMXL2S_FLAGS_OFFSET,
	    state->mtf_pending ? NVMXL2S_F_MTF_PENDING : 0);
	cursor.bytes = bytes;
	cursor.offset = VMX_NESTED_L2_STATE_HEADER_SIZE;
	cursor.length = VMX_NESTED_L2_STATE_SIZE;
	error = nvmxl2s_encode_body(&cursor, state);
	if (error != 0)
		return (error);
	if (cursor.offset != VMX_NESTED_L2_STATE_SIZE)
		return (EPROTO);
	le64enc(bytes + NVMXL2S_DIGEST_OFFSET,
	    nvmxl2s_digest(bytes, VMX_NESTED_L2_STATE_SIZE));
	*written = VMX_NESTED_L2_STATE_SIZE;
	return (0);
}

int
vmx_nested_l2_state_decode(const void *buffer, size_t length,
    struct vmx_nested_l2_portable_state *state)
{
	struct vmx_nested_l2_portable_state candidate;
	struct nvmxl2s_reader reader;
	const uint8_t *bytes;
	int error;

	if (buffer == NULL || state == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(buffer, length, state, sizeof(*state)))
		return (EINVAL);
	if (length < VMX_NESTED_L2_STATE_HEADER_SIZE)
		return (EMSGSIZE);
	if (length != VMX_NESTED_L2_STATE_SIZE)
		return (EPROTO);
	bytes = buffer;
	if (le32dec(bytes) != NVMXL2S_MAGIC ||
	    le16dec(bytes + 4) != NVMXL2S_VERSION ||
	    le16dec(bytes + 6) != VMX_NESTED_L2_STATE_HEADER_SIZE ||
	    le32dec(bytes + 8) != length ||
	    le32dec(bytes + 12) != VMX_NESTED_L2_STATE_HEADER_SIZE ||
	    le32dec(bytes + 16) != VMX_NESTED_L2_STATE_BODY_SIZE ||
	    le32dec(bytes + 20) != 0 || le64dec(bytes + 24) != 0 ||
	    (le64dec(bytes + NVMXL2S_FLAGS_OFFSET) &
	    ~NVMXL2S_F_MTF_PENDING) != 0 || le64dec(bytes + 48) != 0 ||
	    le64dec(bytes + 56) != 0 ||
	    le64dec(bytes + NVMXL2S_DIGEST_OFFSET) !=
	    nvmxl2s_digest(bytes, length))
		return (EPROTO);
	memset(&candidate, 0, sizeof(candidate));
	candidate.mtf_pending =
	    (le64dec(bytes + NVMXL2S_FLAGS_OFFSET) &
	    NVMXL2S_F_MTF_PENDING) != 0;
	reader.bytes = bytes;
	reader.offset = VMX_NESTED_L2_STATE_HEADER_SIZE;
	reader.length = length;
	error = nvmxl2s_decode_body(&reader, &candidate);
	if (error != 0)
		return (error);
	if (reader.offset != length)
		return (EPROTO);
	error = vmx_nested_l2_portable_validate(&candidate);
	if (error != 0)
		return (EPROTO);
	*state = candidate;
	return (0);
}
