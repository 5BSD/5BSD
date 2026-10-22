/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _SYS_HYPERTRACE_WIRE_H_
#define _SYS_HYPERTRACE_WIRE_H_

#include <sys/hypertrace.h>

/* The version-2 envelope is 24 bytes on disk and on the daemon wire. */
#define HYPERTRACE_VM_ENVELOPE_WIRE_SIZE 24U

static inline void
hypertrace_envelope_put_le(uint8_t *bytes, uint64_t value, unsigned width)
{
	for (unsigned i = 0; i < width; ++i)
		bytes[i] = (uint8_t)(value >> (i * 8));
}

static inline uint64_t
hypertrace_envelope_get_le(const uint8_t *bytes, unsigned width)
{
	uint64_t value = 0;
	for (unsigned i = 0; i < width; ++i)
		value |= (uint64_t)bytes[i] << (i * 8);
	return (value);
}

static inline void
hypertrace_envelope_encode(
    uint8_t wire[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE],
    const struct hypertrace_vm_envelope *envelope)
{
	hypertrace_envelope_put_le(wire, envelope->magic, 4);
	hypertrace_envelope_put_le(wire + 4, envelope->version, 2);
	hypertrace_envelope_put_le(wire + 6, envelope->vmid, 2);
	hypertrace_envelope_put_le(wire + 8, envelope->epoch, 8);
	hypertrace_envelope_put_le(wire + 16, envelope->name_length, 8);
}

static inline void
hypertrace_envelope_decode(struct hypertrace_vm_envelope *envelope,
    const uint8_t wire[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE])
{
	envelope->magic = (uint32_t)hypertrace_envelope_get_le(wire, 4);
	envelope->version = (uint16_t)hypertrace_envelope_get_le(wire + 4, 2);
	envelope->vmid = (uint16_t)hypertrace_envelope_get_le(wire + 6, 2);
	envelope->epoch = hypertrace_envelope_get_le(wire + 8, 8);
	envelope->name_length = hypertrace_envelope_get_le(wire + 16, 8);
}

#endif /* _SYS_HYPERTRACE_WIRE_H_ */
