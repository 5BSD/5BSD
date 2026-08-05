/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _REBOOTD_STATE_H_
#define	_REBOOTD_STATE_H_

#include <stdbool.h>
#include <stdint.h>

#define	REBOOTD_STATE_MAGIC	0x52425354U	/* "RBST" */
#define	REBOOTD_STATE_VERSION	1

struct rebootd_state_record {
	uint32_t magic;
	uint16_t version;
	uint16_t size;
	uint32_t checksum;
	uint32_t active;
	uint64_t next_request_id;
	uint64_t request_id;
	uint64_t requested_at_ns;
	uint64_t execute_at_ns;
	uint32_t howto;
	uint16_t opcode;
	uint16_t requester_length;
	char requester[64];
};

_Static_assert(sizeof(struct rebootd_state_record) == 120,
    "rebootd durable state ABI");

void	rebootd_state_seal(struct rebootd_state_record *);
bool	rebootd_state_valid(const struct rebootd_state_record *);

#endif
