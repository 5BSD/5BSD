/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _TRACECMP_PROTOCOL_H_
#define	_TRACECMP_PROTOCOL_H_

#include <stdint.h>

#define	TRACECMP_INTERFACE		"system.Trace"
#define	TRACECMP_INTERFACE_VERSION	"1.0.0"
#define	TRACECMP_MAGIC			0x54524343U	/* "TRCC" */
#define	TRACECMP_ABI_VERSION		1
#define	TRACECMP_MAX_MESSAGE		256

#define	TRACECMP_FEATURE_RAW_DTRACE_FD	0x00000001U

#define	TRACECMP_MSG_F_MASK		0U

enum tracecmp_opcode {
	TRACECMP_OP_HELLO = 1,
	TRACECMP_OP_OPEN,
	TRACECMP_OP_STATS
};

enum tracecmp_message_role {
	TRACECMP_MESSAGE_REQUEST = 1,
	TRACECMP_MESSAGE_REPLY,
	TRACECMP_MESSAGE_EVENT
};

struct tracecmp_msg {
	uint32_t	magic;
	uint16_t	version;
	uint16_t	opcode;
	uint32_t	flags;
	int32_t		status;
};

_Static_assert(sizeof(struct tracecmp_msg) == 16,
    "tracecmp message header ABI");

/*
 * A successful OPEN reply has exactly one attachment.  The channel installs
 * a new receiver-local descriptor at slot zero; the numeric fd is not part of
 * the wire payload.  This administrator-only protocol defines that slot as a
 * DTrace consumer descriptor.
 */
enum tracecmp_open_fd_slot {
	TRACECMP_OPEN_FD_DTRACE = 0,
	TRACECMP_OPEN_FD_COUNT
};

struct tracecmp_hello_reply {
	uint32_t	version;
	uint32_t	features;
	uint32_t	reserved[2];
};

struct tracecmp_stats {
	uint64_t	opened;
	uint64_t	rejected;
	uint64_t	reserved[2];
};

#endif
