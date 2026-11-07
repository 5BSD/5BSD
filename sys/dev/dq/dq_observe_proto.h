/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * The dq.observe mac_capability service (design 7.2, D90): the system's
 * view of every queue and object.  Metadata only; a subscription hands
 * back an observer descriptor that carries lengths, never bytes (D41).
 * Requests and replies are fixed-width, LP64, additive.
 */

#ifndef _DEV_DQ_DQ_OBSERVE_PROTO_H_
#define	_DEV_DQ_DQ_OBSERVE_PROTO_H_

#include <sys/types.h>

#define	DQ_OBSERVE_SERVICE	"dq.observe"
#define	DQ_OBSERVE_VERSION	1

enum dqo_op {
	DQO_OP_LIST_QUEUES = 1,		/* reply: dqo_queue_info[] */
	DQO_OP_LIST_OBJECTS = 2,	/* reply: dqo_object_info[] */
	DQO_OP_SUBSCRIBE = 3,		/* reply: dqo_subscribe_reply, the
					   observer installed in the caller */
};

struct dqo_request {
	uint32_t	dr_version;	/* DQ_OBSERVE_VERSION */
	uint32_t	dr_op;		/* enum dqo_op */
	uint64_t	dr_queue;	/* queue id for LIST_OBJECTS, SUBSCRIBE */
	uint64_t	dr_first;	/* first entry index (paging) */
};

struct dqo_queue_info {
	uint64_t	qi_id;		/* kernel-wide queue id */
	int32_t		qi_pid;		/* controller pid at open */
	uint32_t	qi_uid;		/* controller real uid */
	uint64_t	qi_nonce;	/* controller identity nonce */
	uint64_t	qi_objects;	/* live */
	uint64_t	qi_pending;	/* unread events */
	uint64_t	qi_inflight;	/* delivered, awaiting reply */
	uint64_t	qi_posted;
	uint64_t	qi_dropped;
	uint64_t	qi_observers;
	uint32_t	qi_flags;	/* DQO_QF_* */
	uint32_t	qi_pad0;
};
#define	DQO_QF_CLOSING		0x1
#define	DQO_OS_LIVE		1
#define	DQO_OS_REVOKED		2

struct dqo_object_info {
	uint64_t	oi_id;
	uint32_t	oi_kind;	/* enum dq_kind */
	uint32_t	oi_state;	/* DQO_OS_* */
	uint64_t	oi_dev;
	uint64_t	oi_ino;
	uint64_t	oi_size;
	uint32_t	oi_mode;
	uint32_t	oi_inflight;
	char		oi_path[256];	/* presented path, truncated */
};

/*
 * Every list reply starts with this header; entries follow.  dh_total is
 * the number of entries that exist, dh_count how many follow, so a caller
 * pages with dr_first.
 */
struct dqo_reply_hdr {
	uint32_t	dh_version;
	uint32_t	dh_count;
	uint64_t	dh_total;
};

/*
 * SUBSCRIBE installs a metadata-only observer in the caller, with the
 * rights and locked state an ioctl-minted observer has, and returns its
 * number here; the framework's reply descriptors would arrive unrestricted.
 */
struct dqo_subscribe_reply {
	struct dqo_reply_hdr sr_hdr;
	int32_t		sr_fd;
	int32_t		sr_pad0;
};

_Static_assert(sizeof(struct dqo_request) == 24, "dqo_request");
_Static_assert(sizeof(struct dqo_subscribe_reply) == 24, "dqo_subscribe_reply");
_Static_assert(sizeof(struct dqo_queue_info) == 80, "dqo_queue_info");
_Static_assert(sizeof(struct dqo_object_info) == 304, "dqo_object_info");
_Static_assert(sizeof(struct dqo_reply_hdr) == 16, "dqo_reply_hdr");

#endif /* !_DEV_DQ_DQ_OBSERVE_PROTO_H_ */
