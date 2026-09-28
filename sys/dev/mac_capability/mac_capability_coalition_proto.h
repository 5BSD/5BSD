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
#define	COALITION_OP_LEDGER		14
#define	COALITION_OP_BAND		15
#define	COALITION_OP_ASSERT		16
#define	COALITION_OP_SET_LIMIT		17
#define	COALITION_OP_SET_IDLE_EXIT	18
#define	COALITION_OP_ASSERTIONS		19

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
 * COALITION_OP_LEDGER
 *   req:  coalition_ledger_req
 *   reply: coalition_ledger_reply
 *
 * The coalition's resource counters, read from the container the kernel's
 * accounting framework maintains for it.  Unlike COALITION_OP_RUSAGE this
 * never walks the member list, so it is cheap enough to poll and cheap enough
 * for a policy pass to rank every coalition on the system.
 *
 * Nothing here is sampled, so nothing goes stale and age_ms is always 0; the
 * field is kept because it is part of the reply.  Address space, process count
 * and thread count are charged and discharged as they happen and are exact.
 * Resident memory is whatever the page daemon last wrote, so it can be up to
 * one of its passes old and is zero for a process too young to have been
 * looked at yet -- which is the difference COALITION_OP_RUSAGE exists to span
 * when an exact answer for right now is wanted.
 *
 * COALITION_LEDGER_REFRESH no longer refreshes anything, since there is
 * nothing to refresh.  It now means: judge the declared ceilings before
 * replying, rather than waiting for the next sweep to do it.
 */
#define	COALITION_LEDGER_REFRESH	0x1	/* judge ceilings before replying */
struct coalition_ledger_req {
	uint32_t	op;
	uint32_t	flags;		/* COALITION_LEDGER_* */
};
struct coalition_ledger_reply {
	int32_t		status;
	uint32_t	nprocs;
	uint32_t	nthreads;
	uint32_t	_pad;
	uint64_t	id;
	uint64_t	rss_bytes;
	uint64_t	vsz_bytes;
	uint64_t	age_ms;		/* always 0; kept for the reply's shape */
};

/*
 * Bands and assertions
 * --------------------
 * A coalition has a band: how much the system wants to keep it running when
 * memory or CPU runs short.  Bands are ordered; IDLE is given up first and
 * CRITICAL last.
 *
 * The band is not a number somebody writes down and then has to remember to
 * take back.  It has two parts:
 *
 *   floor      the band the coalition always has, set by its launcher from
 *              the bundle manifest.  One value, changed by whoever holds
 *              the coalition.
 *   assertions descriptors.  COALITION_OP_ASSERT on a coalition returns a
 *              NEW descriptor that asserts a band.  While that descriptor is
 *              open the coalition's band is at least the asserted one; when
 *              it is closed -- deliberately, or because the process holding
 *              it exited or crashed -- the assertion goes away with it.
 *
 * The effective band is the highest asserted band, or the floor if nothing is
 * asserted.  An assertion is an ordinary capability: it can be transferred,
 * so a client can hand a provider the right to keep the client's own work
 * alive while a request is in flight, and can be revoked like anything else.
 * Nothing has to reconcile a table of who asked for what, and a crash cannot
 * leave a coalition pinned at a high band forever.
 *
 * COALITION_OP_BAND
 *   req:  coalition_band_req { .op = COALITION_OP_BAND, flags, floor }
 *   rep:  coalition_band_reply
 *   Reads the bands.  With COALITION_BAND_SET_FLOOR, also sets the floor
 *   first.  The reply always describes the state after any change.
 *
 * COALITION_OP_ASSERT
 *   req:  coalition_band_req { .op = COALITION_OP_ASSERT, band }
 *   rep:  coalition_band_reply
 *   fds:  one, the assertion.  Close it to drop the assertion.
 *   The reply's effective band already accounts for the new assertion.
 *
 * An assertion descriptor accepts one operation of its own,
 * COALITION_OP_BAND with no flags, which reports the band it asserts and the
 * coalition's current effective band.  It carries no other authority: it
 * cannot enlist, signal, or read the membership of the coalition it holds up.
 */

/* Bands, lowest first.  Values are wire values; do not renumber. */
#define	COALITION_BAND_IDLE		0
#define	COALITION_BAND_BACKGROUND	1
#define	COALITION_BAND_STANDARD		2
#define	COALITION_BAND_INTERACTIVE	3
#define	COALITION_BAND_CRITICAL		4
#define	COALITION_BAND_COUNT		5

#define	COALITION_BAND_SET_FLOOR	0x1	/* apply .floor */

struct coalition_band_req {
	uint32_t	op;
	uint32_t	flags;		/* COALITION_BAND_* */
	uint32_t	floor;		/* with COALITION_BAND_SET_FLOOR */
	uint32_t	band;		/* band to assert (COALITION_OP_ASSERT) */
};
#define	COALITION_LIMIT_KILL	0x1	/* terminate on breach, not just notify */

#define	COALITION_IDLE_EXIT_ENABLE	0x1	/* may be put away when idle */

/*
 * Who is holding this coalition up.
 *
 * An assertion count alone answers the wrong question.  Knowing that three
 * assertions are held does not tell an operator why a coalition will not fall
 * back to its floor, or which process to go and look at; in a system where the
 * holder of a capability is the whole point, the holder is the answer.  The
 * kernel knows it, so it says so.
 *
 * The pid recorded is whoever asked for the assertion.  A descriptor can be
 * passed on afterwards, so this is where it came from rather than a claim about
 * where it is now; the process that took it is the one that decided the
 * coalition should be held, which is usually what is being looked for.
 */
struct coalition_assert_info {
	uint32_t	band;
	int32_t		pid;		/* the process that took it */
	uint64_t	age_ms;		/* how long it has been held */
};

struct coalition_assertions_reply {
	int32_t		status;
	uint32_t	live;		/* assertions held right now */
	uint32_t	returned;	/* how many fitted in this reply */
	uint32_t	_pad;
	struct coalition_assert_info	held[];
};

struct coalition_idle_req {
	uint32_t	op;
	uint32_t	flags;		/* COALITION_IDLE_EXIT_* */
	uint32_t	min_age_ms;	/* 0 = system default */
	uint32_t	_pad;
};

/*
 * Two ceilings, because the two figures can be known in different ways.
 *
 * vmem_bytes is address space, accumulated as members take it, so the ceiling
 * is exact and cannot be slipped past between one look and the next.  This is
 * the one that catches a runaway allocation.
 *
 * memory_bytes is resident memory, which moves on every page fault and is
 * therefore sampled.  Its ceiling is about what a coalition is holding when
 * somebody looks, which is the right question for a working set but is not a
 * guarantee about any instant.
 *
 * Either may be zero, meaning no ceiling of that kind.
 */
struct coalition_limit_req {
	uint32_t	op;
	uint32_t	flags;		/* COALITION_LIMIT_* */
	uint64_t	memory_bytes;	/* resident, sampled; 0 = none */
	uint64_t	vmem_bytes;	/* address space, exact; 0 = none */
	/*
	 * CPU, as a percentage of one processor measured over the interval
	 * between one look and the next, so 100 is one processor's worth and
	 * 400 is four.  It is a rate rather than a total, because a total only
	 * ever grows and a unit that has been running for a week would breach
	 * any figure worth setting.
	 *
	 * Measured for the coalition as a whole and across its whole life:
	 * time spent by a member that has since exited still counts, or a unit
	 * could spend as much as it liked in short-lived children.  0 = no
	 * ceiling.
	 */
	uint32_t	cpu_percent;
	uint32_t	_pad2;
};

/*
 * The CPU ceiling was added after the two memory ceilings.  A request that
 * carries only the older fields is still accepted and means no CPU ceiling,
 * the same way an older event reader sees only the flags.
 */
#define	COALITION_LIMIT_REQ_V1_LEN	(2 * sizeof(uint32_t) + \
					    2 * sizeof(uint64_t))

struct coalition_band_reply {
	int32_t		status;
	uint32_t	floor;
	uint32_t	effective;
	uint32_t	asserted;	/* this descriptor's band, or floor */
	uint64_t	id;
	uint32_t	nassert[COALITION_BAND_COUNT];
	uint32_t	_pad;
};

/*
 * Memory ceiling
 * --------------
 * A coalition may be given a ceiling on its own footprint: not a per-process
 * rlimit, which a unit escapes by forking, but a figure for the unit and every
 * helper it starts, taken together.
 *
 * A coalition with no ceiling is never limited, so this does nothing until
 * something declares one.  The ceiling is checked when the coalition's
 * footprint is sampled, which happens when the system is under memory pressure
 * and whenever a ledger refresh is asked for.  It is therefore a ceiling on
 * what a coalition may be holding when memory matters, not an instantaneous
 * one: a coalition that goes over and comes back before anyone looks is never
 * penalised, which is the behaviour a ceiling on a whole unit's working set
 * wants.
 *
 * A breach always notifies (COALITION_NOTE_LIMIT).  With COALITION_LIMIT_KILL
 * it also terminates the coalition, regardless of its band -- a coalition that
 * has exceeded a figure declared for it is over budget whether or not the
 * system happens to be short, and the band only says what to give up first
 * when everyone is within budget.
 *
 * A CPU ceiling is the third figure, and is a rate rather than a total: the
 * share of one processor a coalition may average between one look and the
 * next.  A total would be useless, since it only ever grows and a unit running
 * for a week breaches any figure worth setting.  What is measured is the whole
 * unit -- what its current members have spent plus what members that have
 * since left spent while they were in -- so a coalition cannot stay under a
 * ceiling by spending in short-lived children.
 *
 * COALITION_OP_SET_LIMIT
 *   req:  coalition_limit_req { .op, flags, memory_bytes, vmem_bytes,
 *         cpu_percent }
 *   rep:  coalition_reply
 *   A figure of 0 removes that ceiling; each is independent of the others.
 *   Every ceiling is judged from the coalition's container, so on a kernel
 *   booted without resource accounting (kern.racct.enable=0) this returns
 *   EOPNOTSUPP rather than accepting a figure nothing would ever act on.
 *
 * Idle exit
 * ---------
 * Some work can be put away and brought back without losing anything: an
 * on-demand unit that is started again the next time somebody asks for it.
 * Such a coalition may be stopped when nothing is using it, which is cheaper
 * for the system than keeping it resident and cheaper for the user than
 * having it killed later under pressure.
 *
 * Whether a coalition is that kind of work is not something the kernel can
 * know, so it is declared: COALITION_OP_SET_IDLE_EXIT marks the coalition
 * eligible.  A coalition is never eligible by default, and a unit that would
 * be restarted immediately should not be marked, since putting it away
 * achieves nothing.
 *
 * Eligibility says the work CAN be put away.  Assertions say whether it should
 * be right now: a coalition with any live assertion is in use and is left
 * alone.  Nothing else is consulted -- in particular the band is a separate
 * question, about what to give up first when memory is short, not about
 * whether something is idle.
 *
 * An eligible coalition with no assertions must also have been that way for
 * min_age_ms before it is put away, so work that goes quiet for a moment is
 * not taken from under its user.  Taking an assertion resets the clock.
 *
 * COALITION_OP_SET_IDLE_EXIT
 *   req:  coalition_idle_req { .op, flags, min_age_ms }
 *   rep:  coalition_reply
 *   Clearing COALITION_IDLE_EXIT_ENABLE makes the coalition ineligible again.
 *   A min_age_ms of 0 means the system default.
 *
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
/*
 * Why a coalition died.
 *
 * Every coalition death has exactly one reason, and it is reported the same way
 * everywhere: on the event a holder receives, in the log line, and in the
 * coalition-kill probe.  An operator asking "what happened to my unit" should
 * get the same answer from all three.
 *
 * The first group are lifecycle: somebody or something asked.  The second are
 * memory policy, and are the ones that happen without anybody asking, which is
 * exactly why they have to be named.
 */
#define	COALITION_KILL_NONE		0	/* handle closed, no policy */
#define	COALITION_KILL_REQUESTED	1	/* asked for, by a holder */
#define	COALITION_KILL_DEADLINE		2	/* ran past its deadline */
#define	COALITION_KILL_WATCHDOG		3	/* stopped answering */
#define	COALITION_KILL_LEADER		4	/* its leader went away */
#define	COALITION_KILL_OVER_CEILING	5	/* over its own declared figure */
#define	COALITION_KILL_SYSTEM_MEMORY	6	/* the machine ran out */
#define	COALITION_KILL_IDLE		7	/* idle, and able to come back */
#define	COALITION_KILL_OVER_CPU		8	/* over its own CPU ceiling */

/*
 * What a limit-breach figure is measured in, so an observer is not left
 * guessing whether to read it as a size or a rate.
 */
#define	COALITION_LIMIT_KIND_BYTES	0
#define	COALITION_LIMIT_KIND_CPU	1

/*
 * Event delivered to a coalition's holder.  A message longer than
 * COALITION_EVENT_V1_LEN carries a reason; older readers see only the flags,
 * and a reason of COALITION_KILL_NONE means no memory policy was involved.
 */
struct coalition_event_msg {
	uint32_t	flags;		/* COALITION_NOTE_* */
	uint32_t	reason;		/* COALITION_KILL_* */
	uint64_t	subject_id;	/* coalition concerned, 0 = this one */
};
#define	COALITION_EVENT_V1_LEN	(sizeof(uint32_t))
#define	COALITION_EVENT_V2_LEN	(2 * sizeof(uint32_t))

#define	COALITION_NOTE_MEMBER_ADDED	0x0001
#define	COALITION_NOTE_MEMBER_REMOVED	0x0002
#define	COALITION_NOTE_TERMINATING	0x0004
#define	COALITION_NOTE_TERMINATED	0x0008
#define	COALITION_NOTE_LEADER_DIED	0x0010
#define	COALITION_NOTE_DEADLINE_FIRED	0x0020
#define	COALITION_NOTE_WATCHDOG_FIRED	0x0040
#define	COALITION_NOTE_GRACE_STARTED	0x0080
/*
 * The system is short of memory.  Delivered to every coalition with a live
 * instance when the kernel fires its low-memory event, so a unit can drop
 * caches before anything is killed.  Advisory: nothing is terminated by
 * this notification, and a coalition that ignores it is not penalised.
 */
#define	COALITION_NOTE_PRESSURE		0x0100
/* The coalition is over its declared memory ceiling. */
#define	COALITION_NOTE_LIMIT		0x0200
/*
 * A coalition this one is responsible for was terminated by a policy.  The
 * party that caused work to exist is the party that can do something about it
 * having been taken away -- relaunch it, back off, or tell somebody -- so it is
 * told, with the reason and the id of the coalition concerned.
 */
#define	COALITION_NOTE_CHILD_KILLED	0x0400

#define	COALITION_NOTE_ALL		0x07ff

/*
 * Maximum parent-chain nesting depth.  A root coalition has depth 0.
 * A coalition nested directly under a root has depth 1, and so on.
 * Cycles are detected and rejected at enlist time.
 */
#define	COALITION_MAX_NESTING	16

#endif /* _DEV_MAC_CAPABILITY_MAC_CAPABILITY_COALITION_PROTO_H_ */
