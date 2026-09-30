/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _AUDITCMP_PROTOCOL_H_
#define	_AUDITCMP_PROTOCOL_H_

#include <stdint.h>

#define	AUDITCMP_INTERFACE		"system.Audit"
#define	AUDITCMP_MAGIC			0x41554443U	/* "AUDC" */
#define	AUDITCMP_MAX_MESSAGE		256
#define	AUDITCMP_MAX_SUBJECT		64
#define	AUDITCMP_MAX_OPERATION		64

#define	AUDITCMP_MSG_F_MASK		0U

enum auditcmp_opcode {
	AUDITCMP_OP_SUBMIT = 1,
	AUDITCMP_OP_STATS
};

enum auditcmp_message_role {
	AUDITCMP_MESSAGE_REQUEST = 1,
	AUDITCMP_MESSAGE_REPLY,
	AUDITCMP_MESSAGE_EVENT
};

struct auditcmp_msg {
	uint32_t	magic;
	uint32_t	opcode;
	uint32_t	flags;
	int32_t		status;
};

struct auditcmp_submit_request {
	int32_t		error;
	uint16_t	subject_length;
	uint16_t	operation_length;
	uint32_t	reserved;
	char		subject[AUDITCMP_MAX_SUBJECT];
	char		operation[AUDITCMP_MAX_OPERATION];
};

struct auditcmp_stats {
	uint64_t	submitted;
	uint64_t	rejected;
	uint64_t	reserved[2];
};

_Static_assert(sizeof(struct auditcmp_msg) == 16,
    "auditcmp message header ABI");
_Static_assert(sizeof(struct auditcmp_submit_request) == 140,
    "auditcmp submit request ABI");

#endif
