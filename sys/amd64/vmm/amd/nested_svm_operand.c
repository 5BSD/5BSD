/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>

#ifndef _KERNEL
#include <stdint.h>
#endif

#include "nested_svm_operand.h"

int
svm_nested_operand_gpa(const uint8_t *instruction, size_t length,
    uint8_t default_bits, uint8_t opcode, uint64_t rax, uint64_t *gpa)
{
	size_t i;
	bool override;
	uint8_t byte;

	if (instruction == NULL || gpa == NULL || length < 3 || length > 15 ||
	    (default_bits != 16 && default_bits != 32 && default_bits != 64) ||
	    (opcode != 0xd8 && opcode != 0xda && opcode != 0xdb))
		return (EINVAL);
	if (instruction[length - 3] != 0x0f ||
	    instruction[length - 2] != 0x01 ||
	    instruction[length - 1] != opcode)
		return (EPROTO);
	override = false;
	for (i = 0; i < length - 3; i++) {
		byte = instruction[i];
		if (byte == 0x67) {
			override = true;
			continue;
		}
		if (byte == 0x66 || byte == 0xf0 || byte == 0xf2 ||
		    byte == 0xf3 || byte == 0x26 || byte == 0x2e ||
		    byte == 0x36 || byte == 0x3e || byte == 0x64 ||
		    byte == 0x65 ||
		    (default_bits == 64 && byte >= 0x40 && byte <= 0x4f))
			continue;
		return (EPROTO);
	}
	if (default_bits == 64) {
		*gpa = override ? (uint32_t)rax : rax;
	} else if ((default_bits == 32) != override) {
		*gpa = (uint32_t)rax;
	} else {
		*gpa = (uint16_t)rax;
	}
	return (0);
}
