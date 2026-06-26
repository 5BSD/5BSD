/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * mac_capability_node — wire protocol for the process node service.
 *
 * Observe and configure a process via an attached procdesc fd.
 * If no fd is attached, the operation targets the caller (self).
 */

#ifndef _DEV_MAC_CAPABILITY_MAC_CAPABILITY_NODE_PROTO_H_
#define _DEV_MAC_CAPABILITY_MAC_CAPABILITY_NODE_PROTO_H_

/* Operations */
#define	NODE_OP_STAT		1	/* get state, name, pid, threads */
#define	NODE_OP_CRED		2	/* get uid/gid/groups/nonce/jail */
#define	NODE_OP_RUSAGE		3	/* get live resource usage */
#define	NODE_OP_GET_RLIMIT	4	/* get one resource limit */
#define	NODE_OP_SET_RLIMIT	5	/* set one resource limit */
#define	NODE_OP_GET_RACCT	6	/* get one racct counter */
#define	NODE_OP_GET_NICE	7	/* get priority */
#define	NODE_OP_SET_NICE	8	/* set priority */
#define	NODE_OP_GET_AFFINITY	9	/* get cpuset mask */
#define	NODE_OP_SET_AFFINITY	10	/* set cpuset mask */
#define	NODE_OP_GET_PROCCTL	11	/* get procctl status */
#define	NODE_OP_SET_PROCCTL	12	/* set procctl value */
#define	NODE_OP_SET_CRED	13	/* set uid/gid/groups */
#define	NODE_OP_SET_SESSION	14	/* create new session (setsid) */
#define	NODE_OP_SET_PGRP	15	/* set process group (setpgid) */
#define	NODE_OP_GET_UMASK	16	/* get file creation mask */
#define	NODE_OP_SET_UMASK	17	/* set file creation mask */
#define	NODE_OP_SET_LOGIN	18	/* set login name */
#define	NODE_OP_GET_RTPRIO	19	/* get scheduler class + priority */
#define	NODE_OP_SET_RTPRIO	20	/* set scheduler class + priority */
/* Confinement operations */
#define	NODE_OP_SET_PDEATHSIG	21	/* set parent-death signal on target */
#define	NODE_OP_GET_PDEATHSIG	22	/* get parent-death signal */
#define	NODE_OP_REAP_ACQUIRE	23	/* become reaper (self-only) */
#define	NODE_OP_REAP_RELEASE	24	/* relinquish reaper (self-only) */
#define	NODE_OP_REAP_STATUS	25	/* query reaper descendant info */
#define	NODE_OP_GET_PGRP	26	/* get process group id */
#define	NODE_OP_REAP_KILL	27	/* signal entire subtree */
#define	NODE_OP_REAP_GETPIDS	28	/* get descendant pid list */
/* 29 reserved */
#define	NODE_OP_SIGNAL		30	/* send signal to target process */

/* Status codes */
#define	NODE_STATUS_OK		0
#define	NODE_STATUS_ERR		1
#define	NODE_STATUS_DEAD	2	/* process has exited */
#define	NODE_STATUS_EPERM	3	/* permission denied */

/* Request header — all operations start with this. */
struct node_request {
	uint32_t	op;
	uint32_t	resource;	/* RLIMIT_*, RACCT_*, procctl com */
} __packed;

/* For SET_RLIMIT */
struct node_rlimit_set {
	uint32_t	op;		/* NODE_OP_SET_RLIMIT */
	uint32_t	resource;	/* RLIMIT_* */
	int64_t		rlim_cur;
	int64_t		rlim_max;
} __packed;

/* For SET_NICE */
struct node_nice_set {
	uint32_t	op;		/* NODE_OP_SET_NICE */
	uint32_t	_pad;
	int32_t		nice;
	uint32_t	_pad2;
} __packed;

/* For SET_RTPRIO — scheduler class constants match sys/rtprio.h */
#define	NODE_RTPRIO_REALTIME	2	/* RTP_PRIO_REALTIME (round-robin) */
#define	NODE_RTPRIO_NORMAL	3	/* RTP_PRIO_NORMAL (timeshare) */
#define	NODE_RTPRIO_IDLE	4	/* RTP_PRIO_IDLE */
#define	NODE_RTPRIO_FIFO	10	/* RTP_PRIO_FIFO (REALTIME | 0x8) */
#define	NODE_RTPRIO_MAX		31	/* RTP_PRIO_MAX */

struct node_rtprio_set {
	uint32_t	op;		/* NODE_OP_SET_RTPRIO */
	uint32_t	type;		/* NODE_RTPRIO_* class */
	uint32_t	prio;		/* 0-31 for RT/idle, ignored for normal */
	uint32_t	_pad;
} __packed;

/* Reply: rtprio */
struct node_rtprio_reply {
	uint32_t	status;
	uint32_t	type;		/* NODE_RTPRIO_* class */
	uint32_t	prio;		/* 0-31 within class */
	uint32_t	_pad;
} __packed;

/* For SET_AFFINITY */
#define	NODE_CPUSET_MAXSIZE	128	/* bytes, supports up to 1024 CPUs */

struct node_affinity_set {
	uint32_t	op;		/* NODE_OP_SET_AFFINITY */
	uint32_t	size;		/* actual cpuset_t size in bytes */
	uint8_t		mask[NODE_CPUSET_MAXSIZE];
} __packed;

/* For SET_PROCCTL */
struct node_procctl_set {
	uint32_t	op;		/* NODE_OP_SET_PROCCTL */
	uint32_t	com;		/* PROC_* command */
	int32_t		val;		/* command-specific value */
	uint32_t	_pad;
} __packed;

/* For SET_CRED — set uid/gid/groups on target process */
#define	NODE_CRED_MAXGROUPS	16

#define	NODE_CREDF_UID		0x01
#define	NODE_CREDF_RUID		0x02
#define	NODE_CREDF_SVUID	0x04
#define	NODE_CREDF_GID		0x08
#define	NODE_CREDF_RGID		0x10
#define	NODE_CREDF_SVGID	0x20
#define	NODE_CREDF_GROUPS	0x40

struct node_cred_set {
	uint32_t	op;		/* NODE_OP_SET_CRED */
	uint32_t	flags;		/* NODE_CREDF_* */
	uint32_t	uid;
	uint32_t	ruid;
	uint32_t	svuid;
	uint32_t	gid;
	uint32_t	rgid;
	uint32_t	svgid;
	uint32_t	ngroups;
	uint32_t	groups[NODE_CRED_MAXGROUPS];
} __packed;

/* For SET_PGRP */
struct node_pgrp_set {
	uint32_t	op;		/* NODE_OP_SET_PGRP */
	uint32_t	_pad;
	int32_t		pgid;		/* target pgid; 0 = own pid */
	uint32_t	_pad2;
} __packed;

/* For SET_UMASK */
struct node_umask_set {
	uint32_t	op;		/* NODE_OP_SET_UMASK */
	uint32_t	mask;		/* new umask (ALLPERMS bits) */
} __packed;

/* For SET_LOGIN */
#define	NODE_MAXLOGNAME	17	/* MAXLOGNAME */

struct node_login_set {
	uint32_t	op;		/* NODE_OP_SET_LOGIN */
	uint32_t	_pad;
	char		name[NODE_MAXLOGNAME];
	uint8_t		_pad2[3];	/* align to 4 bytes */
} __packed;

/* Reply: session/pgrp */
struct node_session_reply {
	uint32_t	status;
	int32_t		sid;		/* new session id (= pid for setsid) */
	int32_t		pgid;		/* new process group id */
	uint32_t	_pad;
} __packed;

/* Reply: umask */
struct node_umask_reply {
	uint32_t	status;
	uint32_t	mask;		/* current (or previous) mask */
} __packed;

/* Reply: login */
struct node_login_reply {
	uint32_t	status;
	uint32_t	_pad;
	char		name[NODE_MAXLOGNAME];
	uint8_t		_pad2[3];
} __packed;

/* Reply: stat */
struct node_stat_reply {
	uint32_t	status;
	int32_t		pid;
	uint32_t	state;		/* PRS_NEW, PRS_NORMAL, PRS_ZOMBIE */
	uint32_t	numthreads;
	uint32_t	flags;		/* P_TRACED, P_JAILED, etc. subset */
	uint32_t	_pad;
	char		name[20];	/* MAXCOMLEN+1 */
} __packed;

/* Reply: cred */
#define	NODE_MAXGROUPS	16

struct node_cred_reply {
	uint32_t	status;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	ruid;
	uint32_t	rgid;
	int32_t		prison_id;
	uint64_t	nonce;
	uint32_t	ngroups;
	uint32_t	groups[NODE_MAXGROUPS];
} __packed;

/* Reply: rusage */
struct node_rusage_reply {
	uint32_t	status;
	uint32_t	_pad;
	int64_t		utime_usec;	/* user time in microseconds */
	int64_t		stime_usec;	/* system time in microseconds */
	int64_t		maxrss;		/* max resident set size (KB) */
	int64_t		nvcsw;		/* voluntary context switches */
	int64_t		nivcsw;		/* involuntary context switches */
	int64_t		inblock;	/* block input ops */
	int64_t		oublock;	/* block output ops */
} __packed;

/* Reply: rlimit */
struct node_rlimit_reply {
	uint32_t	status;
	uint32_t	resource;
	int64_t		rlim_cur;
	int64_t		rlim_max;
} __packed;

/* Reply: racct */
struct node_racct_reply {
	uint32_t	status;
	uint32_t	resource;
	int64_t		usage;
	int64_t		limit;
	int64_t		available;
} __packed;

/* Reply: nice */
struct node_nice_reply {
	uint32_t	status;
	int32_t		nice;
} __packed;

/* Reply: affinity */
struct node_affinity_reply {
	uint32_t	status;
	uint32_t	size;		/* actual cpuset_t size in bytes */
	uint8_t		mask[NODE_CPUSET_MAXSIZE];
} __packed;

/* Reply: procctl */
struct node_procctl_reply {
	uint32_t	status;
	uint32_t	com;
	int32_t		val;
	uint32_t	_pad;
} __packed;

/* For SET_PDEATHSIG */
struct node_pdeathsig_set {
	uint32_t	op;		/* NODE_OP_SET_PDEATHSIG */
	uint32_t	signal;		/* signal number, 0 = disable */
} __packed;

/* Reply: pdeathsig */
struct node_pdeathsig_reply {
	uint32_t	status;
	uint32_t	signal;		/* current pdeathsig value */
} __packed;

/* Reply: reap_status */
struct node_reap_status_reply {
	uint32_t	status;
	uint32_t	rs_flags;	/* REAPER_STATUS_OWNED, etc. */
	uint32_t	rs_children;	/* immediate children */
	uint32_t	rs_descendants;	/* all descendants */
	int32_t		rs_reaper;	/* reaper PID */
	int32_t		rs_pid;		/* first child PID */
} __packed;

/* For REAP_KILL */
struct node_reap_kill_req {
	uint32_t	op;		/* NODE_OP_REAP_KILL */
	uint32_t	rk_sig;		/* signal to send */
	uint32_t	rk_flags;	/* REAPER_KILL_CHILDREN, etc. */
	int32_t		rk_subtree;	/* PID for REAPER_KILL_SUBTREE */
} __packed;

/* Reply: reap_kill */
struct node_reap_kill_reply {
	uint32_t	status;
	uint32_t	rk_killed;	/* processes signaled */
	int32_t		rk_fpid;	/* first failed PID, -1 if none */
	uint32_t	_pad;
} __packed;

/* Reply: simple status-only (for chroot, capmode, reap acquire/release) */
struct node_status_reply {
	uint32_t	status;
	uint32_t	_pad;
} __packed;

/* Reply: pgrp */
struct node_pgrp_reply {
	uint32_t	status;
	int32_t		pgid;
} __packed;

/* For SIGNAL */
struct node_signal_req {
	uint32_t	op;		/* NODE_OP_SIGNAL */
	uint32_t	signal;		/* signal number (1..NSIG-1) */
} __packed;

/* Reply: reap_getpids — variable length */
#define	NODE_REAP_PIDINFO_CHILD		0x0001	/* direct child of reaper */
#define	NODE_REAP_PIDINFO_DESCENDANT	0x0002	/* deeper descendant */

struct node_reap_pidentry {
	int32_t		pid;
	int32_t		subtree;	/* subtree root pid */
	uint32_t	flags;		/* NODE_REAP_PIDINFO_* */
	uint32_t	_pad;
} __packed;

/*
 * Variable-length reply: count followed by entries.
 * Maximum entries capped to what fits in MAC_CAPABILITY_MAX_MSG.
 */
#define	NODE_REAP_GETPIDS_MAX						\
    ((14336 - sizeof(uint32_t) * 2) / sizeof(struct node_reap_pidentry))

struct node_reap_getpids_reply {
	uint32_t	status;
	uint32_t	count;		/* entries returned */
	struct node_reap_pidentry entries[];
} __packed;

#endif /* _DEV_MAC_CAPABILITY_MAC_CAPABILITY_NODE_PROTO_H_ */
