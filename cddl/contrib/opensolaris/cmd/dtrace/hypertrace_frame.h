/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef DTRACE_HYPERTRACE_FRAME_H
#define DTRACE_HYPERTRACE_FRAME_H
#include <sys/types.h>
#include <sys/hypertrace.h>
#include <sys/hypertrace_wire.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

struct dtrace_ht_view {
	uint16_t vmid;
	uint64_t epoch;
	const unsigned char *elf;
	size_t length;
	const unsigned char *name;
	size_t name_length;
};

/* Reject legacy VM envelopes: they cannot identify a VM lifetime safely. */
static inline int
dtrace_ht_decode(const void *data, size_t length, size_t name_capacity,
    struct dtrace_ht_view *view)
{
	const unsigned char *bytes = data;
	struct hypertrace_vm_envelope envelope;
	size_t prefix = HYPERTRACE_VM_ENVELOPE_WIRE_SIZE;

	memset(view, 0, sizeof(*view));
	if (data == NULL || length < 4 || length > 64U * 1024U * 1024U)
		return (EINVAL);
	if (memcmp(bytes, "\177ELF", 4) == 0) {
		view->elf = bytes;
		view->length = length;
		return (0);
	}
	if (length < prefix)
		return (EINVAL);
	hypertrace_envelope_decode(&envelope, bytes);
	if (envelope.magic != HYPERTRACE_ENVELOPE_MAGIC ||
	    envelope.version != HYPERTRACE_ENVELOPE_VERSION ||
	    envelope.vmid == 0 || envelope.vmid >= HYPERTRACE_MAX_VMS ||
	    envelope.epoch == 0 || envelope.name_length == 0 ||
	    envelope.name_length >= name_capacity ||
	    envelope.name_length > length - prefix ||
	    length - prefix - envelope.name_length < 4)
		return (EINVAL);
	if (memchr(bytes + prefix, 0, envelope.name_length) != NULL ||
	    memcmp(bytes + prefix + envelope.name_length, "\177ELF", 4) != 0)
		return (EINVAL);
	view->vmid = envelope.vmid;
	view->epoch = envelope.epoch;
	view->name = bytes + prefix;
	view->name_length = envelope.name_length;
	view->elf = bytes + prefix + envelope.name_length;
	view->length = length - prefix - envelope.name_length;
	return (0);
}

/* An identified guest delivery must agree with the decoded VM envelope.
 * Unidentified host programs carry an entirely empty delivery identity. */
static inline int
dtrace_ht_validate_delivery(const struct dtrace_ht_view *view,
    uint64_t delivery_id, const uint8_t program_id[16],
    const uint8_t source_id[16], uint16_t vmid, uint64_t epoch)
{
	const uint8_t zero[16] = {0};
	int program_present = memcmp(program_id, zero, sizeof(zero)) != 0;
	int source_present = memcmp(source_id, zero, sizeof(zero)) != 0;
	int identified = delivery_id != 0 || program_present ||
	    source_present || vmid != 0 || epoch != 0;

	if (!identified)
		return (0);
	if (view == NULL || delivery_id == 0 || !program_present ||
	    !source_present || vmid == 0 || epoch == 0 ||
	    view->vmid != vmid || view->epoch != epoch)
		return (EPROTO);
	return (0);
}
#endif
