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

#include "vmx_nested_l2_continuation_state.h"
#include "vmx_nested_caps.h"
#include "vmx_nested_entry_runtime.h"
#include "vmx_nested_state_range.h"

#define	NVMXL2CS_MAGIC		UINT32_C(0x3143324c)	/* "L2C1" */
#define	NVMXL2CS_VERSION	2U
#define	NVMXL2CS_DIGEST_OFFSET	40U

static uint64_t
nvmxl2cs_digest(const uint8_t *bytes, size_t length)
{
	uint64_t digest;

	digest = UINT64_C(14695981039346656037);
	for (size_t i = 0; i < length; i++) {
		uint8_t byte;

		byte = i >= NVMXL2CS_DIGEST_OFFSET &&
		    i < NVMXL2CS_DIGEST_OFFSET + sizeof(uint64_t) ?
		    0 : bytes[i];
		digest ^= byte;
		digest *= UINT64_C(1099511628211);
	}
	return (digest);
}

static bool
nvmxl2cs_id_equal(const struct vmx_nested_vmcs02_id *left,
    const struct vmx_nested_vmcs02_id *right)
{

	return (vmx_nested_vmcs02_id_equal(left, right));
}

static int
nvmxl2cs_record_validate(
    const struct vmx_nested_l0_continuation_record *record,
    const struct vmx_nested_l2_portable_state *portable)
{

	if (record == NULL || portable == NULL ||
	    vmx_nested_l2_portable_validate(portable) != 0 ||
	    !vmx_nested_vmcs02_id_valid(&record->id) ||
	    record->exit_sequence == 0 ||
	    record->portable_generation == 0 ||
	    (record->completion != VMX_NESTED_L0_COMPLETE_RESUME_L2 &&
	    record->completion != VMX_NESTED_L0_COMPLETE_REFLECT_L1) ||
	    !nvmxl2cs_id_equal(&record->id, &portable->id) ||
	    record->portable_generation != portable->portable_generation)
		return (EINVAL);
	return (0);
}

int
vmx_nested_l2_continuation_state_encode(
    const struct vmx_nested_l0_continuation *continuation,
    const struct vmx_nested_l2_portable_state *portable, void *buffer,
    size_t capacity, size_t *written)
{
	struct vmx_nested_l0_continuation_record record;
	uint8_t *bytes;
	size_t portable_written;
	int error;

	if (continuation == NULL || portable == NULL || buffer == NULL ||
	    written == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(buffer, VMX_NESTED_L2_CONT_STATE_SIZE,
	    continuation, sizeof(*continuation)) ||
	    vmx_nested_state_ranges_overlap(buffer, VMX_NESTED_L2_CONT_STATE_SIZE,
	    portable, sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(buffer, VMX_NESTED_L2_CONT_STATE_SIZE,
	    written, sizeof(*written)) ||
	    vmx_nested_state_ranges_overlap(written, sizeof(*written),
	    continuation, sizeof(*continuation)) ||
	    vmx_nested_state_ranges_overlap(written, sizeof(*written),
	    portable, sizeof(*portable)))
		return (EINVAL);
	*written = 0;
	if (capacity < VMX_NESTED_L2_CONT_STATE_SIZE)
		return (ENOSPC);
	error = vmx_nested_l0_continuation_export(continuation, &record);
	if (error != 0)
		return (error);
	error = nvmxl2cs_record_validate(&record, portable);
	if (error != 0)
		return (error);

	bytes = buffer;
	memset(bytes, 0, VMX_NESTED_L2_CONT_STATE_SIZE);
	le32enc(bytes, NVMXL2CS_MAGIC);
	le16enc(bytes + 4, NVMXL2CS_VERSION);
	le16enc(bytes + 6, VMX_NESTED_L2_CONT_STATE_HEADER_SIZE);
	le32enc(bytes + 8, VMX_NESTED_L2_CONT_STATE_SIZE);
	le32enc(bytes + 16, VMX_NESTED_L2_CONT_STATE_HEADER_SIZE);
	le32enc(bytes + 20, VMX_NESTED_L2_CONT_STATE_RECORD_SIZE);
	le32enc(bytes + 24, VMX_NESTED_L2_CONT_STATE_HEADER_SIZE +
	    VMX_NESTED_L2_CONT_STATE_RECORD_SIZE);
	le32enc(bytes + 28, VMX_NESTED_L2_STATE_SIZE);
	le64enc(bytes + 64, record.id.state_generation);
	le64enc(bytes + 72, record.id.execution_epoch);
	le64enc(bytes + 80, record.id.vmcs12_gpa);
	le64enc(bytes + 88, record.exit_sequence);
	le64enc(bytes + 96, record.portable_generation);
	le32enc(bytes + 104, record.completion);
	error = vmx_nested_l2_state_encode(portable, bytes + 108,
	    VMX_NESTED_L2_STATE_SIZE, &portable_written);
	if (error != 0 || portable_written != VMX_NESTED_L2_STATE_SIZE)
		return (error != 0 ? error : EPROTO);
	le64enc(bytes + NVMXL2CS_DIGEST_OFFSET,
	    nvmxl2cs_digest(bytes, VMX_NESTED_L2_CONT_STATE_SIZE));
	*written = VMX_NESTED_L2_CONT_STATE_SIZE;
	return (0);
}

int
vmx_nested_l2_continuation_state_decode(const void *buffer, size_t length,
    struct vmx_nested_l2_continuation_state *state)
{
	struct vmx_nested_l2_continuation_state candidate;
	const uint8_t *bytes;
	int error;

	if (buffer == NULL || state == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(buffer, length, state, sizeof(*state)))
		return (EINVAL);
	if (length < VMX_NESTED_L2_CONT_STATE_HEADER_SIZE)
		return (EMSGSIZE);
	if (length != VMX_NESTED_L2_CONT_STATE_SIZE)
		return (EPROTO);
	bytes = buffer;
	if (le32dec(bytes) != NVMXL2CS_MAGIC ||
	    le16dec(bytes + 4) != NVMXL2CS_VERSION ||
	    le16dec(bytes + 6) != VMX_NESTED_L2_CONT_STATE_HEADER_SIZE ||
	    le32dec(bytes + 8) != length || le32dec(bytes + 12) != 0 ||
	    le32dec(bytes + 16) != VMX_NESTED_L2_CONT_STATE_HEADER_SIZE ||
	    le32dec(bytes + 20) != VMX_NESTED_L2_CONT_STATE_RECORD_SIZE ||
	    le32dec(bytes + 24) != VMX_NESTED_L2_CONT_STATE_HEADER_SIZE +
	    VMX_NESTED_L2_CONT_STATE_RECORD_SIZE ||
	    le32dec(bytes + 28) != VMX_NESTED_L2_STATE_SIZE ||
	    le16dec(bytes + 108 + 4) != le16dec(bytes + 4) ||
	    le64dec(bytes + 32) != 0 ||
	    le64dec(bytes + 48) != 0 || le64dec(bytes + 56) != 0 ||
	    le64dec(bytes + NVMXL2CS_DIGEST_OFFSET) !=
	    nvmxl2cs_digest(bytes, length))
		return (EPROTO);
	memset(&candidate, 0, sizeof(candidate));
	candidate.continuation.id.state_generation = le64dec(bytes + 64);
	candidate.continuation.id.execution_epoch = le64dec(bytes + 72);
	candidate.continuation.id.vmcs12_gpa = le64dec(bytes + 80);
	candidate.continuation.exit_sequence = le64dec(bytes + 88);
	candidate.continuation.portable_generation = le64dec(bytes + 96);
	candidate.continuation.completion = le32dec(bytes + 104);
	error = vmx_nested_l2_state_decode(bytes + 108,
	    VMX_NESTED_L2_STATE_SIZE, &candidate.portable);
	if (error != 0)
		return (error);
	error = nvmxl2cs_record_validate(&candidate.continuation,
	    &candidate.portable);
	if (error != 0)
		return (EPROTO);
	*state = candidate;
	return (0);
}

int
vmx_nested_l2_continuation_state_restore_cold(
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    struct vmx_nested_l2_portable_state *portable,
    const struct vmx_nested_capabilities *capabilities, const void *buffer,
    size_t length, bool frozen)
{
	struct vmx_nested_l2_continuation_state decoded;
	struct vmx_nested_l0_continuation candidate_continuation;
	struct vmx_nested_entry_runtime candidate_runtime;
	uint64_t signature;
	int error;

	if (continuation == NULL || runtime == NULL || portable == NULL ||
	    capabilities == NULL || buffer == NULL || !frozen ||
	    vmx_nested_state_ranges_overlap(buffer, length, continuation,
	    sizeof(*continuation)) ||
	    vmx_nested_state_ranges_overlap(buffer, length, runtime,
	    sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(buffer, length, portable,
	    sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(continuation, sizeof(*continuation),
	    runtime, sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(continuation, sizeof(*continuation),
	    portable, sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(runtime, sizeof(*runtime), portable,
	    sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(continuation, sizeof(*continuation),
	    capabilities, sizeof(*capabilities)) ||
	    vmx_nested_state_ranges_overlap(runtime, sizeof(*runtime),
	    capabilities, sizeof(*capabilities)) ||
	    vmx_nested_state_ranges_overlap(portable, sizeof(*portable),
	    capabilities, sizeof(*capabilities)))
		return (EINVAL);
	if (continuation->state != VMX_NESTED_L0_CONTINUATION_IDLE ||
	    vmx_nested_l0_continuation_validate(continuation) != 0 ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_IDLE ||
	    vmx_nested_entry_runtime_validate(runtime) != 0)
		return (EBUSY);
	error = vmx_nested_capabilities_signature(capabilities, &signature);
	if (error != 0)
		return (error);
	error = vmx_nested_l2_continuation_state_decode(buffer, length,
	    &decoded);
	if (error != 0)
		return (error);
	if (decoded.portable.capability_signature != signature)
		return (ESTALE);

	candidate_continuation = *continuation;
	candidate_runtime = *runtime;
	error = vmx_nested_l0_continuation_restore(&candidate_continuation,
	    &candidate_runtime, &decoded.continuation, true);
	if (error != 0)
		return (error);
	if (vmx_nested_l0_continuation_validate(&candidate_continuation) != 0 ||
	    vmx_nested_entry_runtime_validate(&candidate_runtime) != 0)
		return (EPROTO);
	*continuation = candidate_continuation;
	*runtime = candidate_runtime;
	*portable = decoded.portable;
	return (0);
}
