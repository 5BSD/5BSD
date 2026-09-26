/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * mac_capability_coalition — wire protocol for coalition capability service.
 *
 * Operations may be issued synchronously with MAC_CAPABILITY_CALL or
 * asynchronously with MAC_CAPABILITY_SENDMSG.  Async replies and notifications are
 * delivered with MAC_CAPABILITY_RECVMSG, and kqueue EVFILT_READ/EVFILT_WRITE map to
 * RECVMSG/SENDMSG queue readiness.  Member fds are passed as attached fds,
 * not as integer fd numbers in the payload.
 */

#ifndef _DEV_MAC_CAPABILITY_MAC_CAPABILITY_COALITION_PROTO_H_
#define _DEV_MAC_CAPABILITY_MAC_CAPABILITY_COALITION_PROTO_H_

#include <sys/types.h>

/*
 * Operation codes — first 4 bytes of every request payload.
 */
#define	COALITION_OP_ENLIST		1
#define	COALITION_OP_TERMINATE		2
#define	COALITION_OP_STAT		3
#define	COALITION_OP_SET_SIGNAL		4
#define	COALITION_OP_GRACEFUL		5
#define	COALITION_OP_SET_DEADLINE	6
#define	COALITION_OP_SET_WATCHDOG	7
#define	COALITION_OP_HEARTBEAT		8
#define	COALITION_OP_SET_LEADER		9
#define	COALITION_OP_JOIN		10
#define	COALITION_OP_RUSAGE		11
#define	COALITION_OP_ENLIST_SET		12
#define	COALITION_OP_SET_RESPONSIBLE	13

/*
 * Common request header.
 */
struct coalition_req_hdr {
	uint32_t	op;
};

/*
 * COALITION_OP_ENLIST
 *   req:  coalition_req_hdr { .op = COALITION_OP_ENLIST }
 *   fds:  req_fds[0] = member fd
 *   reply: coalition_reply { .status }
 */

/*
 * COALITION_OP_TERMINATE
 *   req:  coalition_req_hdr { .op = COALITION_OP_TERMINATE }
 *   reply: coalition_reply { .status }
 */

/*
 * COALITION_OP_ENLIST_SET
 *   req:  coalition_req_hdr { .op = COALITION_OP_ENLIST_SET }
 *   fds:  req_fds[0..nfds-1] = member fds
 *   reply: coalition_enlist_set_reply
 *   Stops on first error; 'enlisted' reports the success count.
 */
struct coalition_enlist_set_reply {
	int32_t		status;
	uint32_t	enlisted;
};

/*
 * COALITION_OP_JOIN
 *   req:  coalition_req_hdr { .op = COALITION_OP_JOIN }
 *   reply: coalition_reply { .status }
 *   Enlists the calling process (no fd needed).
 *   CALL-only: SENDMSG runs from the service taskqueue and has no caller
 *   process context to join.
 */

/*
 * Generic reply — returned for most operations.
 *
 * Note: coalition uses raw errno values in the status field (e.g.,
 * ESRCH, EINVAL, EPERM) rather than defining its own status codes.
 * This differs from mac_capability_node which uses NODE_STATUS_* constants.
 */
struct coalition_reply {
	int32_t		status;		/* 0 = success, errno on failure */
};

/*
 * COALITION_OP_SET_SIGNAL
 *   req:  coalition_set_signal_req
 *   reply: coalition_reply
 */
struct coalition_set_signal_req {
	uint32_t	op;
	int32_t		signal;
};

/*
 * COALITION_OP_GRACEFUL
 *   req:  coalition_graceful_req
 *   reply: coalition_reply
 */
struct coalition_graceful_req {
	uint32_t	op;
	int32_t		signal;
	uint32_t	timeout_ms;
};

/*
 * COALITION_OP_SET_DEADLINE
 *   req:  coalition_set_deadline_req
 *   reply: coalition_reply
 *   timeout_ms=0 cancels the deadline.
 */
struct coalition_set_deadline_req {
	uint32_t	op;
	uint32_t	timeout_ms;
	int32_t		signal;		/* 0 = immediate SIGKILL */
	uint32_t	grace_ms;
};

/*
 * COALITION_OP_SET_WATCHDOG
 *   req:  coalition_set_watchdog_req
 *   reply: coalition_reply
 *   timeout_ms=0 disables the watchdog.
 */
struct coalition_set_watchdog_req {
	uint32_t	op;
	uint32_t	timeout_ms;
};

/*
 * COALITION_OP_SET_LEADER
 *   req:  coalition_req_hdr { .op = COALITION_OP_SET_LEADER }
 *   fds:  req_fds[0] = leader fd (omit fds to clear leader)
 *   reply: coalition_reply
 */

/*
 * COALITION_OP_STAT
 *   req:  coalition_req_hdr { .op = COALITION_OP_STAT }
 *   reply: coalition_stat_reply
 *
 * Identity fields (id and later) were appended after the first release.
 * A caller that offers only COALITION_STAT_REPLY_V1_LEN bytes receives the
 * original layout; a caller that offers the full structure receives it all.
 * Every coalition carries a permanent 64-bit id, assigned at creation and
 * never reused for the lifetime of the kernel; 0 is never a valid id.
 *
 * The responsible parent is the coalition on whose behalf this one exists
 * (see COALITION_OP_SET_RESPONSIBLE).  responsible_id is 0 until it is set.
 * A coalition responsible for itself (the root of a chain) reports its own
 * id.  responsible_leader_pid is the responsible coalition's current leader
 * pid, or 0 when it has none or is gone.
 */
struct coalition_stat_reply {
	int32_t		status;
	uint32_t	member_count;
	uint32_t	flags;		/* COF_* */
	int32_t		signal;
	uint32_t	nesting_depth;
	uint32_t	nested_count;	/* nested coalition members */
	uint32_t	mac_capability_count;	/* non-coalition DTYPE_MAC_CAPABILITY members */
	uint32_t	process_count;
	uint32_t	jail_count;
	uint32_t	other_count;
	/* --- identity extension --- */
	uint64_t	id;		/* permanent coalition id */
	uint64_t	responsible_id;	/* responsible parent id, 0 = unset */
	int32_t		leader_pid;	/* current leader pid, 0 = none */
	int32_t		responsible_leader_pid;
};
#define	COALITION_STAT_REPLY_V1_LEN	(10 * sizeof(uint32_t))

/*
 * COALITION_OP_SET_RESPONSIBLE
 *   req:  coalition_set_responsible_req
 *   fds:  req_fds[0] = the responsible parent: a coalition fd, or a process
 *         descriptor whose process is a coalition member (that coalition
 *         becomes the parent).  Omit fds and pass a COALITION_RESP_* flag
 *         instead to name the caller's own coalition or the target itself.
 *   reply: coalition_reply
 *
 * Records which coalition this one exists on behalf of.  Set once: a
 * second call fails with EALREADY.  Naming the target itself makes it the
 * root of a responsibility chain (a shared provider that answers for its
 * own existence).  A chain may not loop: ELOOP.  The edge is immutable and
 * survives the parent's termination, so an audit trail can always be
 * walked back from a process to the session or system that caused it.
 * Membership, signals, and lifetime are NOT affected: this is attribution,
 * not nesting.
 */
#define	COALITION_RESP_SELF	0x1	/* target is its own root */
#define	COALITION_RESP_CALLER	0x2	/* caller process's coalition */
struct coalition_set_responsible_req {
	uint32_t	op;
	uint32_t	flags;		/* COALITION_RESP_*, ignored with an fd */
};

/*
 * COALITION_OP_RUSAGE
 *   req:  coalition_req_hdr { .op = COALITION_OP_RUSAGE }
 *   reply: coalition_rusage_reply
 */
struct coalition_rusage_reply {
	int32_t		status;
	uint32_t	nprocs;
	uint32_t	nthreads;
	uint32_t	_pad;
	uint64_t	rss_bytes;
	uint64_t	vsz_bytes;
	uint64_t	user_usec;
	uint64_t	sys_usec;
	uint64_t	inblock;
	uint64_t	oublock;
	uint64_t	majflt;
	uint64_t	minflt;
};

/* Coalition flags (returned in stat_reply.flags) */
#define	COF_TERMINATING		0x0001
#define	COF_DEADLINE_ACTIVE	0x0002
#define	COF_DEADLINE_GRACE	0x0004
#define	COF_WATCHDOG_ACTIVE	0x0008
#define	COF_HAS_LEADER		0x0010
#define	COF_LEADER_MONITOR	0x0020	/* mac_capability leader monitor holds a ref */
#define	COF_GRACE_ACTIVE	0x0040	/* grace period — reject new members */
#define	COF_CLOSING		0x0080	/* close_internal draining; no (re)arm */
#define	COF_RESPONSIBLE		0x0100	/* responsible parent has been set */

/*
 * Asynchronous state-change notifications are delivered as MAC_CAPABILITY_RECVMSG
 * payloads.  EVFILT_READ indicates that one or more notifications are
 * pending on the coalition fd.
 */
struct coalition_event_msg {
	uint32_t	flags;		/* COALITION_NOTE_* */
};

#define	COALITION_NOTE_MEMBER_ADDED	0x0001
#define	COALITION_NOTE_MEMBER_REMOVED	0x0002
#define	COALITION_NOTE_TERMINATING	0x0004
#define	COALITION_NOTE_TERMINATED	0x0008
#define	COALITION_NOTE_LEADER_DIED	0x0010
#define	COALITION_NOTE_DEADLINE_FIRED	0x0020
#define	COALITION_NOTE_WATCHDOG_FIRED	0x0040
#define	COALITION_NOTE_GRACE_STARTED	0x0080

#define	COALITION_NOTE_ALL		0x00ff

/*
 * Maximum parent-chain nesting depth.  A root coalition has depth 0.
 * A coalition nested directly under a root has depth 1, and so on.
 * Cycles are detected and rejected at enlist time.
 */
#define	COALITION_MAX_NESTING	16

#endif /* _DEV_MAC_CAPABILITY_MAC_CAPABILITY_COALITION_PROTO_H_ */
