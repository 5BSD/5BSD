/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _LOGCMP_PROTOCOL_H_
#define	_LOGCMP_PROTOCOL_H_

#include <stdint.h>

#define	LOGCMP_INTERFACE		"org.5bsd.log"
#define	LOGCMP_INTERFACE_VERSION	"1.0.0"
#define	LOGCMP_MAGIC			0x4c4f4743U	/* "LOGC" */
#define	LOGCMP_ABI_VERSION		1
#define	LOGCMP_MAX_MESSAGE		8192
#define	LOGCMP_MAX_RECORD		4096
#define	LOGCMP_MAX_TEXT			2048
#define	LOGCMP_MAX_FIELDS		2048
#define	LOGCMP_RING_FDS			LOGCMP_ATTACH_FD_COUNT

#define	LOGCMP_FEATURE_INLINE		0x00000001U
#define	LOGCMP_FEATURE_SHM_RING		0x00000002U
#define	LOGCMP_FEATURE_SYSLOG		0x00000004U

#define	LOGCMP_MSG_F_MASK		0U

#define	LOGCMP_RECORD_F_NONE		0x00000000U
#define	LOGCMP_RECORD_F_MASK		LOGCMP_RECORD_F_NONE

enum logcmp_opcode {
	LOGCMP_OP_HELLO = 1,
	LOGCMP_OP_ATTACH,
	LOGCMP_OP_NOTIFY,
	LOGCMP_OP_WRITE,
	LOGCMP_OP_FLUSH,
	LOGCMP_OP_STATS,
	LOGCMP_OP_DETACH
};

/*
 * ATTACH descriptor attachment slots.  The receiver gets newly installed
 * descriptor numbers; these ordered slot numbers, not sender fd numbers,
 * define their protocol meaning.
 */
enum logcmp_attach_fd_slot {
	LOGCMP_ATTACH_FD_CONFIG = 0,
	LOGCMP_ATTACH_FD_DATA,
	LOGCMP_ATTACH_FD_HEAD,
	LOGCMP_ATTACH_FD_TAIL,
	LOGCMP_ATTACH_FD_COUNT
};

enum logcmp_severity {
	LOGCMP_EMERG = 0,
	LOGCMP_ALERT,
	LOGCMP_CRIT,
	LOGCMP_ERR,
	LOGCMP_WARNING,
	LOGCMP_NOTICE,
	LOGCMP_INFO,
	LOGCMP_DEBUG
};

enum logcmp_message_role {
	LOGCMP_MESSAGE_REQUEST = 1,
	LOGCMP_MESSAGE_REPLY,
	LOGCMP_MESSAGE_EVENT
};

struct logcmp_msg {
	uint32_t	magic;
	uint16_t	version;
	uint16_t	opcode;
	uint32_t	flags;
	int32_t		status;
};

_Static_assert(sizeof(struct logcmp_msg) == 16,
    "logcmp message header ABI");

struct logcmp_hello {
	uint32_t	min_version;
	uint32_t	max_version;
	uint32_t	features;
	uint32_t	reserved;
};

struct logcmp_hello_reply {
	uint32_t	version;
	uint32_t	features;
	uint32_t	ring_size;
	uint32_t	max_record;
	uint32_t	max_text;
	uint32_t	max_fields;
};

struct logcmp_attach_request {
	uint64_t	generation;
	uint32_t	ring_size;
	uint32_t	max_record;
};

struct logcmp_record {
	uint64_t	sequence;
	uint32_t	severity;
	uint32_t	flags;
	uint32_t	message_length;
	uint32_t	fields_length;
};

struct logcmp_stats {
	uint64_t	accepted;
	uint64_t	rejected;
	uint64_t	client_dropped;
	uint64_t	last_sequence;
};

#endif
