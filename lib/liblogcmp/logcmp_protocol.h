/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _LOGCMP_PROTOCOL_H_
#define	_LOGCMP_PROTOCOL_H_

#include <stdint.h>

#define	LOGCMP_INTERFACE		"system.Log"
#define	LOGCMP_INTERFACE_VERSION	"5.0.0"
#define	LOGCMP_MAGIC			0x4c4f4743U	/* "LOGC" */
#define	LOGCMP_ABI_VERSION		5
#define	LOGCMP_MAX_MESSAGE		8192
#define	LOGCMP_MAX_RECORD		4096
#define	LOGCMP_MAX_TEXT			2048
#define	LOGCMP_MAX_FIELDS		2048
#define	LOGCMP_MAX_SUBSYSTEM		96
#define	LOGCMP_MAX_CATEGORY		64
#define	LOGCMP_MAX_EVENT_NAME		96
#define	LOGCMP_MAX_ATTRIBUTES		32
#define	LOGCMP_MAX_ATTRIBUTE_KEY	64
#define	LOGCMP_MAX_ATTRIBUTE_VALUE	512
#define	LOGCMP_RING_FDS			LOGCMP_ATTACH_FD_COUNT
#define	LOGCMP_PRIVATE_REDACTED_LENGTH	9U
#define	LOGCMP_PRIVATE_HASH_LENGTH	42U

#define	LOGCMP_FEATURE_INLINE		0x00000001U
#define	LOGCMP_FEATURE_SHM_RING		0x00000002U
#define	LOGCMP_FEATURE_SYSLOG		0x00000004U
#define	LOGCMP_FEATURE_TYPED_RECORDS	0x00000008U
#define	LOGCMP_FEATURE_PRIVACY		0x00000010U
#define	LOGCMP_FEATURE_TRACE_CONTEXT	0x00000020U
#define	LOGCMP_FEATURE_EDGE_WAKEUP	0x00000040U
#define	LOGCMP_FEATURE_SCOPED_QUERY	0x00000080U

#define	LOGCMP_MSG_F_MASK		0U

#define	LOGCMP_RECORD_F_NONE		0x00000000U
#define	LOGCMP_RECORD_F_MASK		LOGCMP_RECORD_F_NONE

/*
 * QUERY filter match modes.  When a subsystem/category filter is non-empty the
 * default is a substring match; the EXACT bit demands a full-length equality
 * instead.  A zero-length filter is "no constraint" regardless of the bit, so a
 * zeroed request keeps the pre-filter behaviour (back-compat).
 */
#define	LOGCMP_QUERY_MATCH_SUBSYSTEM_EXACT	0x00000001U
#define	LOGCMP_QUERY_MATCH_CATEGORY_EXACT	0x00000002U
#define	LOGCMP_QUERY_MATCH_MASK \
	(LOGCMP_QUERY_MATCH_SUBSYSTEM_EXACT | LOGCMP_QUERY_MATCH_CATEGORY_EXACT)

enum logcmp_opcode {
	LOGCMP_OP_HELLO = 1,
	LOGCMP_OP_ATTACH,
	LOGCMP_OP_NOTIFY,
	LOGCMP_OP_WRITE,
	LOGCMP_OP_FLUSH,
	LOGCMP_OP_STATS,
	LOGCMP_OP_DETACH,
	LOGCMP_OP_QUERY
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
	LOGCMP_ATTACH_FD_WAKE_READ,
	LOGCMP_ATTACH_FD_COUNT
};

enum logcmp_severity {
	LOGCMP_SEVERITY_TRACE = 1,
	LOGCMP_SEVERITY_DEBUG = 5,
	LOGCMP_SEVERITY_INFO = 9,
	LOGCMP_SEVERITY_WARN = 13,
	LOGCMP_SEVERITY_ERROR = 17,
	LOGCMP_SEVERITY_FATAL = 21
};

enum logcmp_record_kind {
	LOGCMP_KIND_LOG = 1,
	LOGCMP_KIND_EVENT,
	LOGCMP_KIND_SIGNPOST_BEGIN,
	LOGCMP_KIND_SIGNPOST_END,
	LOGCMP_KIND_SIGNPOST_POINT
};

enum logcmp_privacy {
	LOGCMP_PRIVACY_PUBLIC = 1,
	LOGCMP_PRIVACY_PRIVATE,
	LOGCMP_PRIVACY_PRIVATE_HASH
};

enum logcmp_attribute_type {
	LOGCMP_ATTR_STRING = 1,
	LOGCMP_ATTR_BYTES,
	LOGCMP_ATTR_INT64,
	LOGCMP_ATTR_UINT64,
	LOGCMP_ATTR_DOUBLE,
	LOGCMP_ATTR_BOOL
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
	/* Client event time, followed by provider-trusted receive clocks. */
	uint64_t	timestamp_ns;
	uint64_t	receive_timestamp_ns;
	uint64_t	receive_monotonic_ns;
	uint64_t	activity_id;
	uint64_t	signpost_id;
	uint8_t		trace_id[16];
	uint8_t		span_id[8];
	uint32_t	severity;
	uint32_t	kind;
	uint32_t	flags;
	uint32_t	message_privacy;
	uint16_t	subsystem_length;
	uint16_t	category_length;
	uint16_t	event_name_length;
	uint16_t	attribute_count;
	uint32_t	message_length;
	uint32_t	attributes_length;
};

struct logcmp_attribute_wire {
	uint16_t	key_length;
	uint8_t		type;
	uint8_t		privacy;
	uint32_t	value_length;
};

struct logcmp_stats {
	uint64_t	accepted;
	uint64_t	rejected;
	uint64_t	client_dropped;
	uint64_t	provider_filtered;
	uint64_t	provider_rate_limited;
	uint64_t	last_sequence;
	uint64_t	client_dropped_by_severity[24];
	uint64_t	provider_rate_limited_by_severity[24];
};

struct logcmp_query_cursor {
	uint64_t	generation;
	uint64_t	offset;
};

/*
 * QUERY request.  minimum_severity and the caller's own label bound the scan as
 * before; the optional filters narrow it further, still strictly within the
 * caller's label.  A zero from_ns/to_ns is "no bound", a zero-length
 * subsystem/category is "no constraint", and match_flags == 0 selects substring
 * matching -- so a zeroed request behaves exactly as the pre-filter protocol.
 * The subsystem/category fragments are fixed inline buffers so the request is a
 * flat POD; bytes past the declared length must be zero.
 */
struct logcmp_query_request {
	struct logcmp_query_cursor cursor;
	uint32_t	minimum_severity;
	uint32_t	match_flags;
	uint64_t	from_ns;
	uint64_t	to_ns;
	uint16_t	subsystem_length;
	uint16_t	category_length;
	uint32_t	reserved;
	char		subsystem[LOGCMP_MAX_SUBSYSTEM];
	char		category[LOGCMP_MAX_CATEGORY];
};

_Static_assert(sizeof(struct logcmp_query_request) == 208,
    "logcmp query request ABI");

struct logcmp_query_reply {
	struct logcmp_query_cursor cursor;
	uint32_t	result;
	uint32_t	record_length;
};

#endif
