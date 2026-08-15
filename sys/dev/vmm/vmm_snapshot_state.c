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

#include <dev/vmm/vmm_snapshot_state.h>
#include <dev/vmm/vmm_snapshot_envelope.h>

int
vmm_snapshot_vm_common_encode(const struct vmm_snapshot_vm_common *state,
    void *buffer, size_t capacity, size_t *written)
{
	uint8_t staging[VMM_SNAPSHOT_VM_COMMON_SIZE];

	if (state == NULL || buffer == NULL || written == NULL ||
	    !vmm_snapshot_range_valid(state, sizeof(*state)) ||
	    !vmm_snapshot_range_valid(buffer, capacity) ||
	    !vmm_snapshot_range_valid(written, sizeof(*written)) ||
	    capacity < sizeof(staging) || state->max_vcpus == 0 ||
	    state->vcpu_count > state->max_vcpus ||
	    vmm_snapshot_ranges_overlap(state, sizeof(*state), buffer,
	    sizeof(staging)) ||
	    vmm_snapshot_ranges_overlap(written, sizeof(*written), buffer,
	    sizeof(staging)) ||
	    vmm_snapshot_ranges_overlap(written, sizeof(*written), state,
	    sizeof(*state)))
		return (EINVAL);
	memset(staging, 0, sizeof(staging));
	le16enc(staging, VMM_SNAPSHOT_COMMON_STATE_VERSION);
	le16enc(staging + 2, sizeof(staging));
	le32enc(staging + 8, state->max_vcpus);
	le32enc(staging + 12, state->vcpu_count);
	memmove(buffer, staging, sizeof(staging));
	*written = sizeof(staging);
	return (0);
}

int
vmm_snapshot_vm_common_decode(const void *buffer, size_t length,
    struct vmm_snapshot_vm_common *state)
{
	struct vmm_snapshot_vm_common candidate;
	const uint8_t *wire;

	if (buffer == NULL || state == NULL ||
	    !vmm_snapshot_range_valid(buffer, length) ||
	    !vmm_snapshot_range_valid(state, sizeof(*state)) ||
	    length != VMM_SNAPSHOT_VM_COMMON_SIZE ||
		vmm_snapshot_ranges_overlap(buffer, length, state,
	    sizeof(*state)))
		return (EINVAL);
	wire = buffer;
	/*
	 * The wire format has no native padding.  Keep the private decoded
	 * representation equally deterministic so later staging or diagnostics
	 * never retain bytes from the caller's destination object.
	 */
	memset(&candidate, 0, sizeof(candidate));
	candidate.max_vcpus = le32dec(wire + 8);
	candidate.vcpu_count = le32dec(wire + 12);
	if (le16dec(wire) != VMM_SNAPSHOT_COMMON_STATE_VERSION ||
	    le16dec(wire + 2) != length || le32dec(wire + 4) != 0 ||
	    le32dec(wire + 16) != 0 || le32dec(wire + 20) != 0 ||
	    candidate.max_vcpus == 0 ||
	    candidate.vcpu_count > candidate.max_vcpus)
		return (EINVAL);
	*state = candidate;
	return (0);
}

int
vmm_snapshot_vcpu_common_encode(const struct vmm_snapshot_vcpu_common *state,
    void *buffer, size_t capacity, size_t *written)
{
	uint8_t staging[VMM_SNAPSHOT_VCPU_COMMON_SIZE];

	if (state == NULL || buffer == NULL || written == NULL ||
	    !vmm_snapshot_range_valid(state, sizeof(*state)) ||
	    !vmm_snapshot_range_valid(buffer, capacity) ||
	    !vmm_snapshot_range_valid(written, sizeof(*written)) ||
	    capacity < sizeof(staging) ||
	    (state->flags & ~VMM_SNAPSHOT_VCPU_F_VALID) != 0 ||
	    vmm_snapshot_ranges_overlap(state, sizeof(*state), buffer,
	    sizeof(staging)) ||
	    vmm_snapshot_ranges_overlap(written, sizeof(*written), buffer,
	    sizeof(staging)) ||
	    vmm_snapshot_ranges_overlap(written, sizeof(*written), state,
	    sizeof(*state)))
		return (EINVAL);
	memset(staging, 0, sizeof(staging));
	le16enc(staging, VMM_SNAPSHOT_COMMON_STATE_VERSION);
	le16enc(staging + 2, sizeof(staging));
	le32enc(staging + 4, state->flags);
	le64enc(staging + 8, state->next_pc);
	memmove(buffer, staging, sizeof(staging));
	*written = sizeof(staging);
	return (0);
}

int
vmm_snapshot_vcpu_common_decode(const void *buffer, size_t length,
    struct vmm_snapshot_vcpu_common *state)
{
	struct vmm_snapshot_vcpu_common candidate;
	const uint8_t *wire;

	if (buffer == NULL || state == NULL ||
	    !vmm_snapshot_range_valid(buffer, length) ||
	    !vmm_snapshot_range_valid(state, sizeof(*state)) ||
	    length != VMM_SNAPSHOT_VCPU_COMMON_SIZE ||
		vmm_snapshot_ranges_overlap(buffer, length, state,
	    sizeof(*state)))
		return (EINVAL);
	wire = buffer;
	/* See vmm_snapshot_vm_common_decode() for the private-value contract. */
	memset(&candidate, 0, sizeof(candidate));
	candidate.flags = le32dec(wire + 4);
	candidate.next_pc = le64dec(wire + 8);
	if (le16dec(wire) != VMM_SNAPSHOT_COMMON_STATE_VERSION ||
	    le16dec(wire + 2) != length ||
	    (candidate.flags & ~VMM_SNAPSHOT_VCPU_F_VALID) != 0 ||
	    le64dec(wire + 16) != 0)
		return (EINVAL);
	*state = candidate;
	return (0);
}
