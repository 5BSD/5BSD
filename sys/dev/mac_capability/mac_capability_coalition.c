/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * mac_capability_coalition — capability-based resource group management.
 *
 * A mac_capability service that groups capabilities (mac_capability instances), processes,
 * jails, sockets, and other fd-based resources.  Operations may be issued
 * synchronously with MAC_CAPABILITY_CALL or asynchronously with MAC_CAPABILITY_SENDMSG.
 * Async replies and state-change events are emitted as MAC_CAPABILITY_RECVMSG
 * messages.  kqueue EVFILT_READ/EVFILT_WRITE report RECVMSG/SENDMSG
 * readiness.  Terminating the coalition revokes all members:
 *
 *   - mac_capability members: mac_capability_instance_revoke()
 *   - processes: kern_psignal(SIGKILL)
 *   - jails: prison_remove()
 *   - sockets: soshutdown(SHUT_RDWR)
 *
 * Userspace API (via MAC_CAPABILITY_CALL or MAC_CAPABILITY_SENDMSG on coalition fd):
 *   COALITION_OP_ENLIST      — attach member fd
 *   COALITION_OP_JOIN        — self-join calling process
 *   COALITION_OP_ENLIST_SET  — attach multiple member fds
 *   COALITION_OP_TERMINATE   — kill all members
 *   COALITION_OP_STAT        — query coalition state
 *   COALITION_OP_SET_SIGNAL  — set termination signal
 *   COALITION_OP_GRACEFUL    — signal → grace → SIGKILL
 *   COALITION_OP_SET_DEADLINE — auto-terminate after timeout
 *   COALITION_OP_SET_WATCHDOG — dead-man switch
 *   COALITION_OP_HEARTBEAT   — reset watchdog
 *   COALITION_OP_SET_LEADER  — designate leader (death triggers term)
 *   COALITION_OP_RUSAGE      — aggregate resource usage
 *   COALITION_OP_SET_RESPONSIBLE — record the responsible parent (set once)
 *   COALITION_OP_LEDGER      — cached footprint sample (cheap; no walk)
 *
 * Identity: every coalition carries a permanent 64-bit id (co_id) and an
 * optional, immutable "responsible parent" edge (co_responsible): the
 * coalition on whose behalf this one exists.  The edge is attribution only —
 * it never affects membership, signals, nesting, or lifetime — and it pins
 * the parent structure (not its members) so a chain can always be walked
 * back from a live process to the session or system that caused it.
 *
 * Lock order:
 *   co_sx (sx lock, per-coalition)
 *     → child co_sx (parent before child for nested coalitions)
 *       → coalition_proc_hash_mtx / coalition_list_mtx (leaf mutexes)
 *
 * Lock-free reads: the process hash and the global coalition list are CK
 * lists whose readers are protected by safe memory reclamation (SMR), not by
 * a lock.  Both object zones share one SMR context, so anything a reader
 * reaches inside smr_enter()/smr_exit() stays allocated for the duration of
 * the section even if it is concurrently unlinked and freed.  The two write
 * sides serialize on leaf mutexes.
 *
 * This matters because coalition_proc_info() -- the kinfo_proc and audit
 * event exporter -- runs under PROC_LOCK for every process every time
 * anything enumerates processes.  A global reader/writer lock there put a
 * contended atomic on that path for all CPUs; an SMR section is a pair of
 * per-CPU sequence stores.  It also lets a future memory-pressure kill walk
 * enumerate coalitions from a context that cannot sleep.
 *
 * An SMR reader may therefore touch only fields that are immutable after
 * creation (co_id, co_responsible_id) or published with atomics; it must
 * never take co_sx, whose destruction is not deferred.
 */

#include <sys/param.h>
#include <sys/unistd.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/osd.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/ck.h>
#include <sys/smr.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/refcount.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/stat.h>
#include <sys/capsicum.h>
#include <sys/procdesc.h>
#include <sys/jail.h>
#include <sys/jaildesc.h>
#include <security/mac/mac_policy.h>
#include <sys/limits.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <sys/eventhandler.h>
#include <sys/hash.h>
#include <sys/syslog.h>
#include <sys/socketvar.h>
#include <sys/sdt.h>
#include <sys/taskqueue.h>
#include <sys/ucred.h>

#include <machine/atomic.h>
#include <vm/uma.h>
#include <sys/mman.h>
#include <sys/racct.h>
#include <sys/rctl.h>
#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_extern.h>
#include <vm/vm_pageout.h>
#include <sys/resourcevar.h>
#include <sys/user.h>

#include "mac_capability.h"
#include "mac_capability_internal.h"
#include "mac_capability_label.h"
#include "mac_capability_coalition_proto.h"

/* ----------------------------------------------------------------
 * DTrace SDT probes
 * ---------------------------------------------------------------- */
SDT_PROVIDER_DEFINE(mac_capability_coalition);
SDT_PROBE_DEFINE2(mac_capability_coalition, , , create, "uint64_t",
    "uint64_t");
SDT_PROBE_DEFINE2(mac_capability_coalition, , , enlist, "int", "int");
SDT_PROBE_DEFINE2(mac_capability_coalition, , , join, "pid_t", "int");
SDT_PROBE_DEFINE2(mac_capability_coalition, , , terminate, "u_int", "int");
SDT_PROBE_DEFINE1(mac_capability_coalition, , , close, "u_int");
SDT_PROBE_DEFINE1(mac_capability_coalition, , , member__exit, "pid_t");
SDT_PROBE_DEFINE1(mac_capability_coalition, , , leader__exit, "pid_t");
SDT_PROBE_DEFINE2(mac_capability_coalition, , , fork__inherit, "pid_t", "pid_t");
SDT_PROBE_DEFINE3(mac_capability_coalition, , , call__done,
    "uint32_t", "int", "sbintime_t");
SDT_PROBE_DEFINE3(mac_capability_coalition, , , deny,
    "const char *", "int", "pid_t");
SDT_PROBE_DEFINE2(mac_capability_coalition, , , signal__set,
    "int", "int");
SDT_PROBE_DEFINE4(mac_capability_coalition, , , deadline__set,
    "uint32_t", "int", "uint32_t", "int");
SDT_PROBE_DEFINE2(mac_capability_coalition, , , watchdog__set,
    "uint32_t", "int");
SDT_PROBE_DEFINE1(mac_capability_coalition, , , heartbeat,
    "uint32_t");
SDT_PROBE_DEFINE2(mac_capability_coalition, , , deadline__expire,
    "const char *", "int");
SDT_PROBE_DEFINE1(mac_capability_coalition, , , watchdog__expire,
    "int");
SDT_PROBE_DEFINE3(mac_capability_coalition, , , graceful,
    "int", "uint32_t", "int");
SDT_PROBE_DEFINE3(mac_capability_coalition, , , responsible__set,
    "uint64_t", "uint64_t", "int");
SDT_PROBE_DEFINE2(mac_capability_coalition, , , pressure,
    "uint32_t", "unsigned");
SDT_PROBE_DEFINE3(mac_capability_coalition, , , pressure__notify,
    "uint64_t", "u_int", "int");
/*
 * A coalition's resource sample was refreshed: its footprint in bytes and
 * the number of process members it was summed from.  This is the input a
 * pressure policy ranks on.
 */
SDT_PROBE_DEFINE3(mac_capability_coalition, , , ledger__sample,
    "uint64_t", "uint64_t", "u_int");
/*
 * Band changes.  band__floor fires when a launcher sets the floor;
 * band__assert and band__release fire when an assertion descriptor is minted
 * and when it goes away, whether it was closed, revoked, or died with its
 * holder.  Arguments are the coalition id, the band in question, and the
 * effective band after the change, so a script can answer "why is this
 * coalition still being kept alive, and who did that".
 */
/*
 * A member was deliberately NOT signalled during a teardown because it is the
 * process doing the closing: a unit that tears down its own coalition should
 * not kill itself.  Without this probe a teardown trace shows N-1 kills and no
 * reason for the survivor, and which process that is depends on who closed the
 * coalition last, so it is worth being able to see.
 */
SDT_PROBE_DEFINE2(mac_capability_coalition, , , member__spared,
    "uint64_t", "pid_t");
/*
 * A coalition was handed down: its pages were advised reclaimable because the
 * system is short of memory and this coalition is in a band it is willing to
 * give up first.  Nothing was terminated.  Arguments are the coalition, its
 * band, the footprint that got it chosen, and how many process members were
 * advised.
 */
SDT_PROBE_DEFINE4(mac_capability_coalition, , , pressure__reclaim,
    "uint64_t", "u_int", "uint64_t", "u_int");
/*
 * A coalition was terminated to reclaim its memory.  This is the report an
 * operator needs after processes disappear: which coalition, whose work it was
 * (the responsible parent), the band that made it expendable, the footprint
 * that made it the choice, and how many process members went with it.
 */
SDT_PROBE_DEFINE5(mac_capability_coalition, , , oom__kill,
    "uint64_t", "uint64_t", "u_int", "uint64_t", "u_int");
/* No coalition was eligible; the stock largest-process choice will run. */
SDT_PROBE_DEFINE1(mac_capability_coalition, , , oom__decline, "uint32_t");
/*
 * Membership of the resource container, which is where the accounting bugs
 * live.  Every process that joins must later leave or detach exactly once: a
 * join without one leaves a process pointing at a container that is about to
 * be freed, and that is a write to freed memory on the next charge rather
 * than anything that shows up as a wrong number.
 *
 * racct-drain says what a container was still holding when it was emptied.
 * CPU is expected there, because a terminated member leaves it behind on
 * purpose.  Anything reclaimable appearing here means a member left without
 * giving it back.
 */
SDT_PROBE_DEFINE2(mac_capability_coalition, , , racct__join,
    "uint64_t", "pid_t");
SDT_PROBE_DEFINE3(mac_capability_coalition, , , racct__leave,
    "uint64_t", "pid_t", "int");
SDT_PROBE_DEFINE2(mac_capability_coalition, , , racct__jail,
    "uint64_t", "pid_t");
SDT_PROBE_DEFINE3(mac_capability_coalition, , , racct__drain,
    "uint64_t", "uint64_t", "uint64_t");
/*
 * A coalition is over the ceiling declared for it.  Arguments are the
 * coalition, the party responsible for it, the footprint, the ceiling, and
 * whether it is being terminated for it (1) or only told (0).  This is the
 * probe that answers "which unit is over budget", as opposed to oom-kill,
 * which answers "what did the system give up because it ran out".
 */
/*
 * A coalition died, and why.  One probe for every death whatever caused it, so
 * "what happened to my unit" has a single answer: the coalition, the party
 * responsible for it, the reason, the footprint it was holding and the band it
 * was in.
 */
SDT_PROBE_DEFINE5(mac_capability_coalition, , , coalition__kill,
    "uint64_t", "uint64_t", "u_int", "uint64_t", "u_int");
/*
 * The figure and the ceiling are bytes for a memory ceiling and a percentage
 * of one processor for a CPU ceiling, so the last argument says which, rather
 * than leaving a script to print a percentage as kilobytes.
 */
SDT_PROBE_DEFINE6(mac_capability_coalition, , , limit__breach,
    "uint64_t", "uint64_t", "uint64_t", "uint64_t", "int", "u_int");
SDT_PROBE_DEFINE3(mac_capability_coalition, , , band__floor,
    "uint64_t", "u_int", "u_int");
SDT_PROBE_DEFINE4(mac_capability_coalition, , , band__assert,
    "uint64_t", "u_int", "u_int", "pid_t");
SDT_PROBE_DEFINE4(mac_capability_coalition, , , band__release,
    "uint64_t", "u_int", "u_int", "pid_t");
/*
 * One process member is being signalled (sig) or, with sig 0, released
 * without a signal, as the coalition tears down.  This is the probe that
 * answers "what killed my process, and on whose behalf".
 */
SDT_PROBE_DEFINE4(mac_capability_coalition, , , member__kill,
    "uint64_t", "uint64_t", "pid_t", "int");
/*
 * A membership that was only inherited (fork, pdfork, JOIN) has been moved
 * to another coalition by a holder of the process descriptor.
 */
SDT_PROBE_DEFINE3(mac_capability_coalition, , , rehome,
    "pid_t", "uint64_t", "uint64_t");

MALLOC_DEFINE(M_COALITION, "mac_capability_coalition",
    "mac_capability coalition structures");

/* ----------------------------------------------------------------
 * Data structures
 * ---------------------------------------------------------------- */

struct coalition_member {
	TAILQ_ENTRY(coalition_member)	cm_link;
	CK_LIST_ENTRY(coalition_member)	cm_hash;	/* process hash (SMR) */
	struct file		*cm_fp;		/* held reference (NULL for JOIN) */
	struct coalition	*cm_coalition;
	void			*cm_data;	/* proc ptr for process members */
	struct coalition	*cm_nested_co;	/* ref'd child coalition (nested only) */
	int			cm_dtype;
	char			cm_svc_name[MAC_CAPABILITY_MAXNAME]; /* mac_capability service name */
};

struct coalition {
	struct sx		co_sx;
	TAILQ_HEAD(, coalition_member) co_members;
	u_int			co_flags;
	u_int			co_manual_grace_count;
	int			co_signal;
	u_int			co_nesting_depth;
	volatile u_int		co_member_count;
	u_int			co_refcount;
	/* Deadline */
	struct callout		co_deadline_callout;
	struct task		co_deadline_task;
	int			co_deadline_signal;
	uint32_t		co_deadline_grace_ms;
	/* Watchdog */
	struct callout		co_watchdog_callout;
	struct task		co_watchdog_task;
	uint32_t		co_watchdog_timeout_ms;
	/* Leader */
	struct coalition_member	*co_leader;
	pid_t			co_leader_pid;
	/* Mac_capability leader monitor — polls leader liveness */
	struct callout		co_leader_callout;
	struct task		co_leader_task;
	/* Back-reference for timer tasks */
	struct mac_capability_instance	*co_instance;
	/* All live coalitions (coalition_list_mtx to write, SMR to read) */
	CK_LIST_ENTRY(coalition)	co_all_link;
	bool			co_listed;
	/*
	 * Cached footprint, published with atomics so a policy pass can rank
	 * coalitions without taking co_sx.  Taken only when something makes
	 * a victim ranking, which is the one place a maintained figure will not
	 * do: an out-of-memory choice made on a stale footprint picks the wrong
	 * coalition, and the page daemon's last pass can be a second old.
	 * Everything else -- the ceilings, the ledger, the kill report -- reads
	 * the container instead.
	 */
	volatile uint64_t	co_rss_bytes;
	/*
	 * Band: the floor set by the launcher, plus a count of live assertion
	 * descriptors per band.  Both are plain atomics with no lock, because
	 * the effective band has to be readable from the page daemon while it
	 * decides what to give up, which cannot wait on anything.
	 */
	volatile u_int		co_band_floor;
	volatile u_int		co_band_assert[COALITION_BAND_COUNT];
	volatile u_int		co_band_nassert;	/* live assertions */
	volatile sbintime_t	co_press_time;	/* last handed down, 0 = never */
	/*
	 * Declared ceilings for the whole coalition, indexed by the accounting
	 * framework's own resource numbers; 0 means no ceiling on that one.
	 *
	 * One array rather than a field per figure, because every one of them
	 * is judged the same way -- read the container, compare -- and the
	 * container already carries all of them.  Limiting a resource this
	 * module has never heard of needs no code here, only a caller willing
	 * to name it.
	 */
	volatile uint64_t	co_limits[RACCT_MAX + 1];
	/*
	 * The coalition's resource container.  A real one, alongside the user,
	 * login class and jail containers a process is already charged to, so
	 * every resource the system already accounts for is accounted for per
	 * coalition without this module counting anything itself.  CPU is not
	 * reclaimable, so a member that exits leaves its CPU behind here --
	 * which is what stops a unit spending freely in short-lived children.
	 */
	struct racct		*co_racct;
	volatile u_int		co_limit_flags;
	volatile u_int		co_limit_breached;	/* notified already */
	int			co_kill_reason;	/* COALITION_KILL_*, set once */
	/* Idle exit: declared eligibility, and how long it has been idle. */
	volatile u_int		co_idle_flags;
	volatile u_int		co_idle_min_age_ms;
	volatile sbintime_t	co_idle_since;	/* 0 = not idle */
	/*
	 * Idle exits attributed to this coalition as a responsible party.  A
	 * coalition is a fresh object every launch, so the responsible edge is
	 * the only thing that persists across a relaunch -- which makes it the
	 * right place to notice that putting this work away keeps failing to
	 * achieve anything because it comes straight back.
	 */
	volatile u_int		co_idle_exits;
	volatile sbintime_t	co_idle_window;
	/*
	 * Live assertions, so an operator can be told who is holding this
	 * coalition up rather than only how many are.  A leaf mutex of its own:
	 * minting an assertion already allocates and mints a descriptor, so an
	 * uncontended lock costs nothing next to that, and it keeps the list
	 * off co_sx.
	 */
	struct mtx		co_assert_mtx;
	LIST_HEAD(, coalition_assert)	co_asserts;
	/* Identity (I) — immutable after creation */
	uint64_t		co_id;
	/*
	 * Responsible parent (set once under coalition_nest_lock + co_sx;
	 * immutable afterwards, so readers need no lock once non-NULL).
	 * Holds a reference on the parent released only in coalition_free().
	 * NULL with COF_RESPONSIBLE set means "responsible for itself".
	 */
	struct coalition	*co_responsible;
	uint64_t		co_responsible_id;
};

/* ----------------------------------------------------------------
 * Globals
 * ---------------------------------------------------------------- */

static struct mac_capability_service *coalition_svc;
static u_int coalition_band_effective(struct coalition *);

static uma_zone_t coalition_zone;
static uma_zone_t coalition_member_zone;

static volatile u_int coalition_count;
static volatile u_int coalition_total_members;

/*
 * Global nested-operation lock.  Serializes:
 *   - Nested coalition enlistment (cycle check + insert)
 *   - coalition_revoke clearing ci_priv
 *
 * This prevents two races:
 *   1. ABBA deadlock: A←B and B←A both take parent co_sx then
 *      try to slock the other → deadlock.  The nest lock serializes
 *      all nested enlists so only one runs at a time.
 *   2. ci_priv TOCTOU: revoke clears ci_priv and frees the
 *      coalition while enlist reads it.  Both sides hold nest_lock,
 *      so the read and clear are mutually exclusive.
 */
static struct sx coalition_nest_lock;

/* Process hash for exit handler lookup */
#define	COALITION_PROC_HASH_SIZE	256
static CK_LIST_HEAD(, coalition_member)
    coalition_proc_hash[COALITION_PROC_HASH_SIZE];
static struct mtx coalition_proc_hash_mtx;

/*
 * One SMR context shared by both object zones, so a reader that finds a
 * member may follow it to its coalition and up the responsible chain without
 * any of that memory being recycled underneath it.
 */
static smr_t coalition_smr;

static inline u_int
coalition_proc_hash_idx(struct proc *p)
{
	uintptr_t key = (uintptr_t)p;

	return (hash32_buf(&key, sizeof(key), 0) &
	    (COALITION_PROC_HASH_SIZE - 1));
}

/* Jail OSD for fork inheritance */
static u_int coalition_jail_osd_slot;
/*
 * How many jails are held by a coalition right now.
 *
 * Every fork in the system reaches the jail-charging path, and the
 * overwhelming majority of them are not in any held jail.  Zero here means
 * there is nothing to look for, and the whole path costs one atomic load.
 */
static volatile u_int coalition_held_jails;

struct coalition_jail_osd {
	struct coalition	*cjo_coalition;
	struct coalition_member	*cjo_member;
	struct file		*cjo_fp;
	struct task		cjo_cleanup_task;
	bool			cjo_cleanup_queued;
};

static eventhandler_tag coalition_fork_tag;
static eventhandler_tag coalition_exit_tag;
static eventhandler_tag coalition_lowmem_tag;

/*
 * Every live coalition, for system-wide passes (memory pressure today).
 * Writers serialize on a leaf mutex; readers walk it inside an SMR section
 * and take a reference on each coalition before doing anything that sleeps.
 * Never take co_sx or the process hash under the list mutex.
 */
static struct mtx coalition_list_mtx;
static CK_LIST_HEAD(, coalition) coalition_list =
    CK_LIST_HEAD_INITIALIZER(coalition_list);
/*
 * The pressure pass gets its own taskqueue thread rather than sharing
 * taskqueue_thread with the per-coalition deadline, watchdog and leader tasks.
 * A pass walks every coalition and samples every member, which takes a while
 * on a busy system; the close path drains those per-coalition tasks and would
 * otherwise have to wait behind a system-wide walk on a single shared thread,
 * delaying a coalition's teardown for as long as the walk takes.
 */
static struct taskqueue *coalition_pressure_tq;
static struct task coalition_pressure_task;
/*
 * A periodic sweep, so a ceiling and an idle timer mean something without
 * waiting for the system to run short.  Footprint here is sampled rather than
 * accounted continuously, so a figure is only ever as fresh as the last sweep;
 * the interval is what bounds that staleness.
 */
static struct callout coalition_sweep_callout;
static struct task coalition_sweep_task;
static int coalition_sweep_enable = 1;
static u_int coalition_sweep_interval_ms = 10000;

/* Permanent coalition ids.  Never reused; 0 is never issued. */
static volatile uint64_t coalition_next_id = 1;

/*
 * Sysctl tunables — soft limits, best-effort enforcement.
 * Concurrent connect/enlist/fork can overshoot by the number
 * of racing threads.  This is acceptable for resource control;
 * hard enforcement would require a global lock on every admission.
 */
static u_int coalition_max = 1024;
static u_int coalition_max_members = 8192;
/*
 * Assertions live in file descriptors, so a holder that keeps asking for them
 * would otherwise consume the assertion service's whole instance budget and
 * leave no way for anything else to hold a coalition at a band.  Cap them per
 * coalition as well.
 */
static u_int coalition_max_assertions = 64;

/*
 * What a memory-pressure pass does about the coalitions it finds.
 *
 * It hands them down rather than killing them.  Every coalition is notified so
 * it can drop caches of its own accord, and then the ones the system is least
 * interested in keeping -- the low bands, largest first -- have their address
 * spaces advised MADV_DONTNEED, which moves their pages to the front of the
 * reclaim queue without discarding anything.  Nothing is lost and nothing is
 * terminated: a coalition handed down keeps running and faults its pages back
 * if it turns out to need them, having in the meantime given the rest of the
 * system first claim on that memory.
 *
 * That is the whole ladder for now.  Terminating a coalition to reclaim its
 * memory is a further rung that is deliberately not taken here, because
 * handing down is reversible and killing is not.
 */
static int coalition_pressure_reclaim = 1;
static u_int coalition_pressure_band_ceiling = COALITION_BAND_BACKGROUND;
static u_int coalition_pressure_max_targets = 4;
static u_int coalition_pressure_interval_ms = 10000;
static u_int coalition_pressure_min_kb = 8192;
static volatile u_int coalition_pressure_reclaims;

/*
 * Out-of-memory kills.  When the system is about to run out of memory the
 * stock choice is the single largest process, which is very often the most
 * important thing on the machine simply because it is the biggest.  This
 * policy chooses instead by what the system is willing to lose: the lowest
 * band first, and within a band the largest footprint, because that frees the
 * most for the least.  The unit is the coalition, so a unit and its helpers go
 * together rather than leaving a decapitated remainder behind.
 *
 * A coalition above the ceiling is never chosen, which is what keeps CORE
 * units safe.  If nothing is eligible the policy declines and the stock
 * largest-process choice runs unchanged, so this can only improve the decision,
 * never prevent one.
 */
static int coalition_oom_kill = 1;
static u_int coalition_oom_band_ceiling = COALITION_BAND_INTERACTIVE;
/*
 * Kills by reason.  Counted separately because they mean different things: a
 * coalition over its own figure is a unit misbehaving, one given up for system
 * memory is the machine being short, and an idle exit is neither -- it is work
 * being put away because it can be brought back.
 */
static volatile u_int coalition_oom_kills;
static volatile u_int coalition_limit_kills;
static volatile u_int coalition_idle_kills;
static volatile u_int coalition_cpu_kills;

/*
 * Idle exit.  Eligibility is per coalition and off unless declared, so these
 * only decide how a coalition that HAS been declared eligible is treated.
 */
static int coalition_idle_exit = 1;
static u_int coalition_idle_min_age_ms = 300000;
static u_int coalition_idle_max_per_min = 6;

static const char *
coalition_kill_reason_name(int reason)
{

	switch (reason) {
	case COALITION_KILL_REQUESTED:
		return ("asked for");
	case COALITION_KILL_DEADLINE:
		return ("past its deadline");
	case COALITION_KILL_WATCHDOG:
		return ("stopped answering");
	case COALITION_KILL_LEADER:
		return ("its leader went away");
	case COALITION_KILL_OVER_CEILING:
		return ("over its own ceiling");
	case COALITION_KILL_OVER_CPU:
		return ("over its own CPU ceiling");
	case COALITION_KILL_SYSTEM_MEMORY:
		return ("the system ran out of memory");
	case COALITION_KILL_IDLE:
		return ("idle, and able to come back");
	default:
		return ("handle closed");
	}
}

static void
coalition_kill_count(int reason)
{

	switch (reason) {
	case COALITION_KILL_OVER_CEILING:
		atomic_add_int(&coalition_limit_kills, 1);
		break;
	case COALITION_KILL_OVER_CPU:
		atomic_add_int(&coalition_cpu_kills, 1);
		break;
	case COALITION_KILL_SYSTEM_MEMORY:
		atomic_add_int(&coalition_oom_kills, 1);
		break;
	case COALITION_KILL_IDLE:
		atomic_add_int(&coalition_idle_kills, 1);
		break;
	default:
		break;
	}
}

SYSCTL_NODE(_kern, OID_AUTO, mac_capability_coalition,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0, "mac_capability coalition");
SYSCTL_UINT(_kern_mac_capability_coalition, OID_AUTO, count, CTLFLAG_RD,
    __DEVOLATILE(u_int *, &coalition_count), 0,
    "Number of active coalitions");
SYSCTL_UINT(_kern_mac_capability_coalition, OID_AUTO, max, CTLFLAG_RW,
    &coalition_max, 0,
    "Maximum coalitions (0 = unlimited)");
SYSCTL_UINT(_kern_mac_capability_coalition, OID_AUTO, max_members, CTLFLAG_RW,
    &coalition_max_members, 0,
    "Maximum total members (0 = unlimited)");
SYSCTL_UINT(_kern_mac_capability_coalition, OID_AUTO, members, CTLFLAG_RD,
    __DEVOLATILE(u_int *, &coalition_total_members), 0,
    "Total members across all coalitions");
SYSCTL_UINT(_kern_mac_capability_coalition, OID_AUTO, max_assertions,
    CTLFLAG_RW, &coalition_max_assertions, 0,
    "Maximum live band assertions per coalition (0 = unlimited)");
SYSCTL_INT(_kern_mac_capability_coalition, OID_AUTO, pressure_reclaim,
    CTLFLAG_RW, &coalition_pressure_reclaim, 0,
    "Under memory pressure, advise low-band coalitions' pages reclaimable");
SYSCTL_UINT(_kern_mac_capability_coalition, OID_AUTO, pressure_band_ceiling,
    CTLFLAG_RW, &coalition_pressure_band_ceiling, 0,
    "Highest band handed down under pressure (COALITION_BAND_*)");
SYSCTL_UINT(_kern_mac_capability_coalition, OID_AUTO, pressure_max_targets,
    CTLFLAG_RW, &coalition_pressure_max_targets, 0,
    "Coalitions handed down per pressure pass");
SYSCTL_UINT(_kern_mac_capability_coalition, OID_AUTO, pressure_interval_ms,
    CTLFLAG_RW, &coalition_pressure_interval_ms, 0,
    "Minimum time before the same coalition is handed down again");
SYSCTL_UINT(_kern_mac_capability_coalition, OID_AUTO, pressure_min_kb,
    CTLFLAG_RW, &coalition_pressure_min_kb, 0,
    "Ignore coalitions smaller than this when handing down");
SYSCTL_UINT(_kern_mac_capability_coalition, OID_AUTO, pressure_reclaims,
    CTLFLAG_RD, __DEVOLATILE(u_int *, &coalition_pressure_reclaims), 0,
    "Total coalitions handed down since boot");
SYSCTL_INT(_kern_mac_capability_coalition, OID_AUTO, oom_kill, CTLFLAG_RW,
    &coalition_oom_kill, 0,
    "Choose an out-of-memory victim by band and footprint, by coalition");
SYSCTL_UINT(_kern_mac_capability_coalition, OID_AUTO, oom_band_ceiling,
    CTLFLAG_RW, &coalition_oom_band_ceiling, 0,
    "Highest band an out-of-memory kill may choose (COALITION_BAND_*)");
SYSCTL_UINT(_kern_mac_capability_coalition, OID_AUTO, oom_kills, CTLFLAG_RD,
    __DEVOLATILE(u_int *, &coalition_oom_kills), 0,
    "Total coalitions terminated for memory since boot");
SYSCTL_UINT(_kern_mac_capability_coalition, OID_AUTO, limit_kills, CTLFLAG_RD,
    __DEVOLATILE(u_int *, &coalition_limit_kills), 0,
    "Total coalitions terminated for exceeding their own ceiling since boot");
SYSCTL_UINT(_kern_mac_capability_coalition, OID_AUTO, cpu_kills, CTLFLAG_RD,
    __DEVOLATILE(u_int *, &coalition_cpu_kills), 0,
    "Total coalitions terminated for exceeding their own CPU ceiling since boot");
SYSCTL_UINT(_kern_mac_capability_coalition, OID_AUTO, idle_kills, CTLFLAG_RD,
    __DEVOLATILE(u_int *, &coalition_idle_kills), 0,
    "Total coalitions put away for being idle since boot");
SYSCTL_INT(_kern_mac_capability_coalition, OID_AUTO, sweep, CTLFLAG_RW,
    &coalition_sweep_enable, 0,
    "Periodically sample footprints, enforce ceilings and put idle work away");
SYSCTL_UINT(_kern_mac_capability_coalition, OID_AUTO, sweep_interval_ms,
    CTLFLAG_RW, &coalition_sweep_interval_ms, 0,
    "How often the periodic sweep runs, and so how stale a footprint may be");
SYSCTL_INT(_kern_mac_capability_coalition, OID_AUTO, idle_exit, CTLFLAG_RW,
    &coalition_idle_exit, 0,
    "Put declared-eligible coalitions away once they have been idle");
SYSCTL_UINT(_kern_mac_capability_coalition, OID_AUTO, idle_min_age_ms,
    CTLFLAG_RW, &coalition_idle_min_age_ms, 0,
    "Default time a coalition must be idle before it is put away");
SYSCTL_UINT(_kern_mac_capability_coalition, OID_AUTO, idle_max_per_min,
    CTLFLAG_RW, &coalition_idle_max_per_min, 0,
    "Give up putting a responsible party's work away after this many a minute");

/* Forward declarations */
static void	coalition_terminate_members_locked(struct coalition *co,
		    struct thread *td, bool skip_self, int sig_override,
		    int reason);
static void	coalition_notify_responsible(struct coalition *co, int reason);
static void	coalition_racct_join(struct proc *p, struct coalition *co);
static struct coalition_member *coalition_proc_hash_lookup(struct proc *p);
static void	coalition_charge_jailed_child(struct proc *child);
static void	coalition_racct_leave(struct proc *p, struct coalition *co);
static struct coalition *coalition_responsible_or_self(struct coalition *co);
static bool	coalition_idle_exit_worthwhile(struct coalition *co,
		    sbintime_t now);
static void	coalition_collect_external_members_locked(
		    struct coalition *co, struct file ***jail_fpsp,
		    int *jail_countp,
		    struct mac_capability_instance ***mac_capability_cisp,
		    int *mac_capability_countp);
static void	coalition_terminate_external_members(struct thread *td,
		    struct file **jail_fps, int jail_count,
		    struct mac_capability_instance **mac_capability_cis,
		    int mac_capability_count);
static int	coalition_terminate(struct coalition *co);
static void	coalition_deadline_callout_fn(void *arg);
static void	coalition_deadline_task_fn(void *context, int pending);
static void	coalition_watchdog_callout_fn(void *arg);
static void	coalition_watchdog_task_fn(void *context, int pending);
static void	coalition_leader_callout_fn(void *arg);
static void	coalition_leader_task_fn(void *context, int pending);
static void	coalition_jail_cleanup_task_fn(void *context, int pending);

/* Leader monitor polling interval: 100ms */
#define	COALITION_LEADER_POLL_TICKS	(hz / 10)

/* ----------------------------------------------------------------
 * Coalition lifecycle
 * ---------------------------------------------------------------- */

static void
coalition_ref(struct coalition *co)
{

	refcount_acquire(&co->co_refcount);
}

static void	coalition_rel(struct coalition *co);
static void	coalition_rehome_inherited(struct proc *p);

static void
coalition_free(struct coalition *co)
{

	KASSERT(TAILQ_EMPTY(&co->co_members),
	    ("coalition_free: members not empty"));
	KASSERT(co->co_refcount == 0,
	    ("coalition_free: refcount %u", co->co_refcount));
	mtx_lock(&coalition_list_mtx);
	if (co->co_listed) {
		CK_LIST_REMOVE(co, co_all_link);
		co->co_listed = false;
	}
	mtx_unlock(&coalition_list_mtx);
	sx_destroy(&co->co_sx);
	mtx_destroy(&co->co_assert_mtx);
	/*
	 * Give up this coalition's own reference on the container.  It is NOT
	 * destroyed here: a member part way through exiting still points at it
	 * and still has accounting to do, so the container outlives the
	 * coalition and the last holder frees it.
	 */
	SDT_PROBE3(mac_capability_coalition, , , racct__drain, co->co_id,
	    racct_read(co->co_racct, RACCT_CPU),
	    racct_read(co->co_racct, RACCT_RSS));
	racct_release(&co->co_racct);
	/*
	 * Drop the responsible-parent pin last.  Chains are acyclic (enforced
	 * at set time), so the recursion this may cause is bounded by the
	 * chain length limit.
	 */
	if (co->co_responsible != NULL) {
		struct coalition *parent = co->co_responsible;

		co->co_responsible = NULL;
		uma_zfree_smr(coalition_zone, co);
		atomic_subtract_int(&coalition_count, 1);
		coalition_rel(parent);
		return;
	}
	uma_zfree_smr(coalition_zone, co);
	atomic_subtract_int(&coalition_count, 1);
}

static void
coalition_rel(struct coalition *co)
{

	if (refcount_release(&co->co_refcount))
		coalition_free(co);
}

static struct coalition *
coalition_alloc(void)
{
	struct coalition *co;

	co = uma_zalloc_smr(coalition_zone, M_WAITOK | M_ZERO);
	sx_init_flags(&co->co_sx, "mac_capability_coalition", SX_DUPOK);
	mtx_init(&co->co_assert_mtx, "coalition_asserts", NULL, MTX_DEF);
	LIST_INIT(&co->co_asserts);
	racct_create(&co->co_racct);
	TAILQ_INIT(&co->co_members);
	co->co_signal = SIGKILL;
	co->co_band_floor = COALITION_BAND_STANDARD;
	co->co_nesting_depth = 0;
	/*
	 * The permanent id has to be set before the coalition is published to
	 * the global list: a lock-free pass walking that list must never see a
	 * live coalition whose id is still zero.
	 */
	co->co_id = atomic_fetchadd_64(&coalition_next_id, 1);
	refcount_init(&co->co_refcount, 1);
	callout_init(&co->co_deadline_callout, 1);
	TASK_INIT(&co->co_deadline_task, 0, coalition_deadline_task_fn, co);
	callout_init(&co->co_watchdog_callout, 1);
	TASK_INIT(&co->co_watchdog_task, 0, coalition_watchdog_task_fn, co);
	callout_init(&co->co_leader_callout, 1);
	TASK_INIT(&co->co_leader_task, 0, coalition_leader_task_fn, co);
	atomic_add_int(&coalition_count, 1);
	mtx_lock(&coalition_list_mtx);
	CK_LIST_INSERT_HEAD(&coalition_list, co, co_all_link);
	co->co_listed = true;
	mtx_unlock(&coalition_list_mtx);
	return (co);
}

static void
coalition_update_grace_flag_locked(struct coalition *co)
{

	sx_assert(&co->co_sx, SA_XLOCKED);

	if ((co->co_flags & COF_TERMINATING) != 0) {
		co->co_flags &= ~COF_GRACE_ACTIVE;
		return;
	}

	if (co->co_manual_grace_count != 0 ||
	    (co->co_flags & COF_DEADLINE_GRACE) != 0)
		co->co_flags |= COF_GRACE_ACTIVE;
	else
		co->co_flags &= ~COF_GRACE_ACTIVE;
}

static int
coalition_timeout_ticks(uint32_t timeout_ms)
{
	uint32_t ticks_ms;

	if (timeout_ms == 0)
		return (0);

	ticks_ms = MSEC_2_TICKS(timeout_ms);
	if (ticks_ms > INT_MAX)
		return (INT_MAX);
	return ((int)ticks_ms);
}

static int
coalition_validate_member_rights(int dtype, const struct filecaps *fcaps)
{

	if (fcaps == NULL)
		return (0);

	switch (dtype) {
	case DTYPE_PROCDESC:
		return (cap_check(&fcaps->fc_rights, &cap_pdkill_rights));
	case DTYPE_JAILDESC:
		return (cap_check(&fcaps->fc_rights, &cap_jail_remove_rights));
	case DTYPE_SOCKET:
		return (cap_check(&fcaps->fc_rights, &cap_shutdown_rights));
	case DTYPE_SHM:
		return (cap_check(&fcaps->fc_rights, &cap_ftruncate_rights));
	default:
		return (0);
	}
}

static void
coalition_notify_event(struct coalition *co, uint32_t flags)
{
	struct coalition_event_msg ev;
	int error;

	if (co == NULL || co->co_instance == NULL || flags == 0)
		return;
	sx_assert(&co->co_sx, SA_XLOCKED);

	ev.flags = flags;
	ev.reason = (uint32_t)co->co_kill_reason;
	ev.subject_id = 0;
	error = mac_capability_notify(co->co_instance, &ev, sizeof(ev), NULL, NULL, 0);
	if (error != 0 && error != EAGAIN && error != ENOBUFS &&
	    error != ECONNRESET)
		log(LOG_NOTICE,
		    "mac_capability_coalition: event delivery failed: %d\n", error);
}

/* ----------------------------------------------------------------
 * Nested coalition detection
 * ---------------------------------------------------------------- */

static bool
coalition_is_nested(struct file *fp)
{
	struct mac_capability_instance *ci;

	if (fp == NULL || fp->f_type != DTYPE_MAC_CAPABILITY)
		return (false);
	ci = fp->f_data;
	if (ci == NULL || ci->ci_service == NULL)
		return (false);
	return (ci->ci_service == coalition_svc);
}

/* ----------------------------------------------------------------
 * Jail OSD
 * ---------------------------------------------------------------- */

static int
coalition_jail_set_atomic(struct prison *pr, struct coalition *co,
    struct file *fp)
{
	struct coalition_jail_osd *cjo, *existing;
	void **rsv;

	if (coalition_jail_osd_slot == 0)
		return (ENXIO);

	cjo = malloc(sizeof(*cjo), M_COALITION, M_WAITOK);
	cjo->cjo_coalition = co;
	cjo->cjo_member = NULL;
	cjo->cjo_cleanup_queued = false;
	if (!fhold(fp)) {
		free(cjo, M_COALITION);
		return (EBADF);
	}
	cjo->cjo_fp = fp;
	TASK_INIT(&cjo->cjo_cleanup_task, 0, coalition_jail_cleanup_task_fn, cjo);
	rsv = osd_reserve(coalition_jail_osd_slot);

	prison_lock(pr);
	existing = osd_jail_get(pr, coalition_jail_osd_slot);
	if (existing != NULL) {
		prison_unlock(pr);
		osd_free_reserved(rsv);
		fdrop(cjo->cjo_fp, NULL);
		free(cjo, M_COALITION);
		return (EBUSY);
	}
	osd_jail_set_reserved(pr, coalition_jail_osd_slot, rsv, cjo);
	prison_unlock(pr);
	return (0);
}

static void
coalition_jail_set_member(struct prison *pr, struct coalition_member *cm)
{
	struct coalition_jail_osd *cjo;

	if (coalition_jail_osd_slot == 0)
		return;
	prison_lock(pr);
	cjo = osd_jail_get(pr, coalition_jail_osd_slot);
	if (cjo != NULL)
		cjo->cjo_member = cm;
	prison_unlock(pr);
}

/*
 * The coalition that holds this prison, or the innermost one holding a prison
 * that encloses it.
 *
 * A jail may sit inside another jail, and a different coalition may hold each.
 * The innermost wins, being the more specific statement about whose work this
 * is -- the same reason an individual enlistment beats either of them.
 *
 * Returns with a reference held, or NULL.
 */
static struct coalition *
coalition_of_prison(struct prison *pr)
{
	struct coalition_jail_osd *cjo;
	struct coalition *co = NULL;

	if (coalition_jail_osd_slot == 0 ||
	    atomic_load_int(&coalition_held_jails) == 0)
		return (NULL);
	for (; pr != NULL && co == NULL; pr = pr->pr_parent) {
		prison_lock(pr);
		cjo = osd_jail_get(pr, coalition_jail_osd_slot);
		if (cjo != NULL && cjo->cjo_coalition != NULL &&
		    refcount_acquire_if_not_zero(
		    &cjo->cjo_coalition->co_refcount))
			co = cjo->cjo_coalition;
		prison_unlock(pr);
	}
	return (co);
}

/*
 * Charge a process to the coalition holding the jail it is in.
 *
 * Only a process carries a container pointer, so without this a coalition that
 * holds a jail would govern that jail's lifetime while accounting for nothing
 * inside it: the processes in there were never enlisted one at a time and have
 * no pointer of their own.
 *
 * A process enlisted in its own right is left alone.  An individual enlistment
 * is the more specific statement, and it is not overridden by a jail the
 * process merely happens to be in.  Nothing is undone when a process leaves a
 * jail or the jail stops being held: the container is reference counted, so a
 * pointer into it is always safe, and exit gives back everything reclaimable
 * and drops the reference on its own.
 */
static void
coalition_charge_jailed_proc(struct proc *p, struct prison *pr)
{
	struct coalition *co;

	/*
	 * The cheap refusals first, in the order that rejects the most for the
	 * least: no jail is held at all, or this process is not in a jail.
	 * Only then is it worth looking at the process's membership.
	 */
	if (!racct_enable || p == NULL || pr == NULL || pr == &prison0 ||
	    atomic_load_int(&coalition_held_jails) == 0)
		return;

	smr_enter(coalition_smr);
	if (coalition_proc_hash_lookup(p) != NULL) {
		smr_exit(coalition_smr);
		return;
	}
	smr_exit(coalition_smr);

	co = coalition_of_prison(pr);
	if (co == NULL)
		return;
	SDT_PROBE2(mac_capability_coalition, , , racct__jail, co->co_id,
	    p->p_pid);
	coalition_racct_join(p, co);
	coalition_rel(co);
}

/*
 * Charge everything already inside a jail that has just been enlisted.
 *
 * Walking once here is what makes a jail's existing work count; anything that
 * enters afterwards is caught when it attaches or when it forks.  Descendant
 * prisons are included, because a process in a nested jail is inside this one
 * too -- coalition_of_prison() gives each one the innermost answer.
 */
static void
coalition_jail_charge_existing(struct prison *pr)
{
	struct prison *cpr;
	struct proc *p;
	int descend;

	if (!racct_enable)
		return;

	/*
	 * allproc before allprison: that is the order the rest of the kernel
	 * takes them in, and witness has it hardcoded.  pr_proclist is the one
	 * allproc protects here; allprison is for walking pr_children.
	 */
	sx_slock(&allproc_lock);
	sx_slock(&allprison_lock);
	LIST_FOREACH(p, &pr->pr_proclist, p_jaillist)
		coalition_charge_jailed_proc(p, pr);
	FOREACH_PRISON_DESCENDANT(pr, cpr, descend) {
		LIST_FOREACH(p, &cpr->pr_proclist, p_jaillist)
			coalition_charge_jailed_proc(p, cpr);
	}
	sx_sunlock(&allprison_lock);
	sx_sunlock(&allproc_lock);
}

/*
 * A newly forked process whose parent is in no coalition of its own.  It may
 * still have been born inside a jail that a coalition holds.
 *
 * The prison comes from the child's own credential, which at this point is the
 * parent's, so this is the jail it was born into.
 */
static void
coalition_charge_jailed_child(struct proc *child)
{
	struct prison *pr;
	bool locked;

	if (!racct_enable || coalition_jail_osd_slot == 0 ||
	    atomic_load_int(&coalition_held_jails) == 0)
		return;

	/*
	 * The fork hook runs with no process lock held, but take it the way
	 * the rest of this module does rather than assuming that stays true.
	 */
	locked = PROC_LOCKED(child);
	if (!locked)
		PROC_LOCK(child);
	pr = child->p_ucred != NULL ? child->p_ucred->cr_prison : NULL;
	if (pr != NULL)
		prison_hold(pr);
	if (!locked)
		PROC_UNLOCK(child);
	if (pr == NULL)
		return;
	coalition_charge_jailed_proc(child, pr);
	prison_free(pr);
}

/*
 * A process attached to a jail.  If that jail is held by a coalition, this is
 * where the process starts being accounted for.
 */
static void
coalition_mac_prison_attached(struct ucred *cred __unused, struct prison *pr,
    struct label *prlabel __unused, struct proc *p, struct label *plabel __unused)
{

	coalition_charge_jailed_proc(p, pr);
}

static struct mac_policy_ops coalition_mac_ops = {
	.mpo_prison_attached		= coalition_mac_prison_attached,
};

MAC_POLICY_SET(&coalition_mac_ops, mac_mac_capability_coalition,
    "MAC_CAPABILITY coalition jail accounting",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);

static void
coalition_jail_cleanup_task_fn(void *context, int pending __unused)
{
	struct coalition_jail_osd *cjo = context;
	struct coalition *co;
	struct coalition_member *cm;
	bool removed;
	bool was_leader;

	if (cjo == NULL)
		return;

	co = cjo->cjo_coalition;
	cm = NULL;
	removed = false;
	was_leader = false;

	if (co != NULL) {
		sx_xlock(&co->co_sx);
		TAILQ_FOREACH(cm, &co->co_members, cm_link) {
			if (cm->cm_dtype == DTYPE_JAILDESC &&
			    cm->cm_fp == cjo->cjo_fp)
				break;
		}
		if (cm != NULL) {
			TAILQ_REMOVE(&co->co_members, cm, cm_link);
			cm->cm_link.tqe_prev = NULL;
			if ((co->co_flags & COF_HAS_LEADER) &&
			    co->co_leader == cm) {
				was_leader = true;
				co->co_leader = NULL;
				co->co_flags &= ~COF_HAS_LEADER;
			}
			coalition_notify_event(co, COALITION_NOTE_MEMBER_REMOVED);
			removed = true;
		}
		sx_xunlock(&co->co_sx);
	}

	if (was_leader) {
		SDT_PROBE1(mac_capability_coalition, , , leader__exit, 0);
		coalition_terminate(co);
	}

	if (removed) {
		atomic_subtract_int(&co->co_member_count, 1);
		atomic_subtract_int(&coalition_total_members, 1);
		if (cm->cm_fp != NULL)
			fdrop(cm->cm_fp, NULL);
		if (cm->cm_data != NULL) {
			struct prison *pr = cm->cm_data;

			cm->cm_data = NULL;
			atomic_subtract_int(&coalition_held_jails, 1);
			prison_free(pr);
		}
		uma_zfree_smr(coalition_member_zone, cm);
		coalition_rel(co);
	}

	if (cjo->cjo_fp != NULL)
		fdrop(cjo->cjo_fp, NULL);
	if (co != NULL)
		coalition_rel(co);
	free(cjo, M_COALITION);
}

static void
coalition_jail_osd_dtor(void *value)
{
	struct coalition_jail_osd *cjo = value;
	struct coalition *co;

	if (cjo == NULL)
		return;

	co = cjo->cjo_coalition;

	if (cjo->cjo_member != NULL || cjo->cjo_cleanup_queued) {
		if (!cjo->cjo_cleanup_queued) {
			cjo->cjo_cleanup_queued = true;
			taskqueue_enqueue(taskqueue_thread,
			    &cjo->cjo_cleanup_task);
		}
		return;
	}

	if (cjo->cjo_fp != NULL)
		fdrop(cjo->cjo_fp, NULL);
	if (co != NULL)
		coalition_rel(co);
	free(cjo, M_COALITION);
}

/* ----------------------------------------------------------------
 * Jail termination
 * ---------------------------------------------------------------- */

static int
coalition_jail_terminate(struct file *fp)
{
	struct jaildesc *jd;
	struct prison *pr;

	KASSERT(fp != NULL && fp->f_data != NULL,
	    ("coalition_jail_terminate: bad fp"));

	jd = fp->f_data;
	JAILDESC_LOCK(jd);
	pr = jd->jd_prison;
	if (pr == NULL || !prison_isvalid(pr)) {
		JAILDESC_UNLOCK(jd);
		return (ENOENT);
	}
	prison_hold(pr);
	JAILDESC_UNLOCK(jd);

	sx_xlock(&allprison_lock);
	mtx_lock(&pr->pr_mtx);
	if (prison_isalive(pr)) {
		/*
		 * prison_remove() releases pr_mtx and allprison_lock and
		 * consumes the reference acquired by prison_hold() above.
		 */
		prison_remove(pr);
	} else {
		mtx_unlock(&pr->pr_mtx);
		sx_xunlock(&allprison_lock);
		prison_free(pr);
	}
	return (0);
}

/* ----------------------------------------------------------------
 * Member limit checks
 * ---------------------------------------------------------------- */

static int
coalition_check_limits(void)
{
	u_int max, cur;

	max = coalition_max_members;
	if (max != 0) {
		cur = atomic_load_acq_int(&coalition_total_members);
		if (cur >= max)
			return (ENOMEM);
	}
	return (0);
}

/* ----------------------------------------------------------------
 * Process hash
 * ---------------------------------------------------------------- */

static void
coalition_proc_hash_insert(struct coalition_member *cm, struct proc *p)
{
	u_int idx;

	mtx_assert(&coalition_proc_hash_mtx, MA_OWNED);
	idx = coalition_proc_hash_idx(p);
	CK_LIST_INSERT_HEAD(&coalition_proc_hash[idx], cm, cm_hash);
}

static struct coalition_member *
coalition_proc_hash_lookup(struct proc *p)
{
	struct coalition_member *cm;
	u_int idx;

	/*
	 * Callers either hold coalition_proc_hash_mtx (writers, and readers
	 * that go on to mutate) or are inside an SMR section (coalition_
	 * proc_info).  There is no assertion that covers both.
	 */
	idx = coalition_proc_hash_idx(p);
	CK_LIST_FOREACH(cm, &coalition_proc_hash[idx], cm_hash) {
		if (cm->cm_data == p)
			return (cm);
	}
	return (NULL);
}

/* ----------------------------------------------------------------
 * Enlistment
 * ---------------------------------------------------------------- */

/*
 * Check whether 'target' appears anywhere in 'child's nested
 * coalition tree.  depth_limit bounds recursion so a malformed
 * existing graph cannot recurse indefinitely.
 *
 * Lock ordering: caller must NOT hold target->co_sx.
 * We acquire child->co_sx as reader, then recurse into
 * grandchildren (always child-before-grandchild order).
 */
static int
coalition_check_cycle(struct coalition *child, struct coalition *target,
    int depth_limit)
{
	struct coalition_member *cm;
	int error = 0;

	if (depth_limit <= 0)
		return (ELOOP);

	sx_slock(&child->co_sx);
	TAILQ_FOREACH(cm, &child->co_members, cm_link) {
		struct coalition *grandchild;

		grandchild = cm->cm_nested_co;
		if (grandchild == NULL)
			continue;

		if (grandchild == target) {
			error = ELOOP;
			break;
		}

		error = coalition_check_cycle(grandchild, target,
		    depth_limit - 1);
		if (error != 0)
			break;
	}
	sx_sunlock(&child->co_sx);
	return (error);
}

static int
coalition_validate_redepth_locked(struct coalition *co, u_int depth)
{
	struct coalition_member *cm;
	int error;

	sx_assert(&co->co_sx, SA_XLOCKED);

	if (depth >= COALITION_MAX_NESTING)
		return (ELOOP);

	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		struct coalition *child;

		child = cm->cm_nested_co;
		if (child == NULL)
			continue;

		sx_xlock(&child->co_sx);
		error = coalition_validate_redepth_locked(child, depth + 1);
		sx_xunlock(&child->co_sx);
		if (error != 0)
			return (error);
	}

	return (0);
}

static void
coalition_apply_redepth_locked(struct coalition *co, u_int depth)
{
	struct coalition_member *cm;

	sx_assert(&co->co_sx, SA_XLOCKED);
	KASSERT(depth < COALITION_MAX_NESTING,
	    ("coalition depth overflow: %u", depth));

	co->co_nesting_depth = depth;
	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		struct coalition *child;

		child = cm->cm_nested_co;
		if (child == NULL)
			continue;

		sx_xlock(&child->co_sx);
		coalition_apply_redepth_locked(child, depth + 1);
		sx_xunlock(&child->co_sx);
	}
}

/*
 * Return true if 'fp' is already enlisted in coalition 'co'.
 * Caller must hold co_sx.
 */
static bool
coalition_has_member(struct coalition *co, struct file *fp)
{
	struct coalition_member *cm;

	sx_assert(&co->co_sx, SA_LOCKED);
	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		if (cm->cm_fp == fp)
			return (true);
	}
	return (false);
}

static int
coalition_enlist(struct coalition *co, struct thread *td, struct file *fp,
    const struct filecaps *fcaps)
{
	struct coalition_member *cm;
	int dtype, error;
	bool is_nested;

	dtype = fp->f_type;
	is_nested = coalition_is_nested(fp);

	error = coalition_validate_member_rights(dtype, fcaps);
	if (error != 0)
		return (error);

	/*
	 * For nested coalitions, defer the cycle check until after
	 * we hold co_sx (in the generic path below).  This makes
	 * the check-and-insert atomic, preventing concurrent
	 * opposite enlists (A←B and B←A) from both passing.
	 */

	error = coalition_check_limits();
	if (error != 0) {
		SDT_PROBE3(mac_capability_coalition, , , deny, (uintptr_t)"enlist-limit",
		    ENOMEM, curthread->td_proc->p_pid);
		return (error);
	}

	if (!fhold(fp))
		return (EBADF);

	cm = uma_zalloc_smr(coalition_member_zone, M_WAITOK | M_ZERO);
	cm->cm_dtype = dtype;
	cm->cm_svc_name[0] = '\0';

	/*
	 * For mac_capability members, record the service name (type).
	 */
	if (dtype == DTYPE_MAC_CAPABILITY) {
		struct mac_capability_instance *ci = fp->f_data;

		if (ci != NULL && ci->ci_service != NULL)
			strlcpy(cm->cm_svc_name, ci->ci_service->csvc_name,
			    sizeof(cm->cm_svc_name));
	}

	if (dtype == DTYPE_PROCDESC) {
		struct procdesc *pd = fp->f_data;
		struct proc *p;

		sx_slock(&proctree_lock);
		p = pd->pd_proc;
		if (p == NULL) {
			sx_sunlock(&proctree_lock);
			uma_zfree_smr(coalition_member_zone, cm);
			fdrop(fp, td);
			SDT_PROBE3(mac_capability_coalition, , , deny,
			    "enlist-dead", ESRCH, td->td_proc->p_pid);
			return (ESRCH);
		}
		sx_sunlock(&proctree_lock);

		cm->cm_data = p;

		/*
		 * A membership the process merely inherited (fork, pdfork,
		 * JOIN: cm_fp == NULL) yields to an explicit enlist by a holder
		 * of its process descriptor: detach it from the old coalition
		 * first, then insert as usual.  An explicit procdesc membership
		 * (cm_fp != NULL) is pinned and fails below with EBUSY.
		 */
		coalition_rehome_inherited(p);

		/*
		 * Lock order: co_sx → hash_lock.
		 * Take co_sx first to match timer task paths.
		 */
		sx_xlock(&co->co_sx);
		if (co->co_flags & (COF_TERMINATING | COF_GRACE_ACTIVE)) {
			sx_xunlock(&co->co_sx);
			uma_zfree_smr(coalition_member_zone, cm);
			fdrop(fp, td);
			SDT_PROBE3(mac_capability_coalition, , , deny,
			    "enlist-shutdown", ESHUTDOWN, td->td_proc->p_pid);
			return (ESHUTDOWN);
		}

		mtx_lock(&coalition_proc_hash_mtx);
		if (coalition_proc_hash_lookup(p) != NULL) {
			mtx_unlock(&coalition_proc_hash_mtx);
			sx_xunlock(&co->co_sx);
			uma_zfree_smr(coalition_member_zone, cm);
			fdrop(fp, td);
			SDT_PROBE3(mac_capability_coalition, , , deny,
			    "enlist-busy", EBUSY, td->td_proc->p_pid);
			return (EBUSY);
		}

		coalition_proc_hash_insert(cm, p);
		coalition_racct_join(p, co);
		mtx_unlock(&coalition_proc_hash_mtx);

	} else if (dtype == DTYPE_JAILDESC) {
		struct jaildesc *jd = fp->f_data;
		struct prison *pr;

		JAILDESC_LOCK(jd);
		pr = jd->jd_prison;
		if (pr == NULL || !prison_isvalid(pr)) {
			JAILDESC_UNLOCK(jd);
			uma_zfree_smr(coalition_member_zone, cm);
			fdrop(fp, td);
			SDT_PROBE3(mac_capability_coalition, , , deny,
			    "enlist-invalid-jail", ENOENT,
			    td->td_proc->p_pid);
			return (ENOENT);
		}
		prison_hold(pr);
		JAILDESC_UNLOCK(jd);

		cm->cm_data = pr;

		sx_xlock(&co->co_sx);
		if (co->co_flags & (COF_TERMINATING | COF_GRACE_ACTIVE)) {
			sx_xunlock(&co->co_sx);
			prison_free(pr);
			uma_zfree_smr(coalition_member_zone, cm);
			fdrop(fp, td);
			SDT_PROBE3(mac_capability_coalition, , , deny,
			    "enlist-shutdown", ESHUTDOWN,
			    td->td_proc->p_pid);
			return (ESHUTDOWN);
		}

			/*
			 * Take the OSD-owned coalition reference before
			 * publishing the OSD entry so the destructor always
			 * drops a live reference.
			 */
			coalition_ref(co);
			error = coalition_jail_set_atomic(pr, co, fp);
			if (error != 0) {
				coalition_rel(co);
				sx_xunlock(&co->co_sx);
			prison_free(pr);
			uma_zfree_smr(coalition_member_zone, cm);
			fdrop(fp, td);
			return (error);
		}

	} else if (is_nested) {
		/*
		 * Nested coalition enlistment.
		 *
		 * Take the global nest_lock to serialize against:
		 *   - Concurrent opposite enlists (prevents ABBA deadlock
		 *     on per-coalition locks)
		 *   - Concurrent co_revoke clearing ci_priv (prevents
		 *     use-after-free on child coalition)
		 *
		 * Under nest_lock: read ci_priv, ref the child, run
		 * cycle check.  Then take co_sx for the actual insert.
		 */
		struct mac_capability_instance *ci;
		struct coalition *nested_co;

		sx_xlock(&coalition_nest_lock);

		ci = fp->f_data;
		nested_co = mac_capability_instance_get_priv(ci);
		if (nested_co == NULL) {
			sx_xunlock(&coalition_nest_lock);
			uma_zfree_smr(coalition_member_zone, cm);
			fdrop(fp, td);
			return (EBADF);
		}
		coalition_ref(nested_co);

		if (nested_co == co) {
			coalition_rel(nested_co);
			sx_xunlock(&coalition_nest_lock);
			uma_zfree_smr(coalition_member_zone, cm);
			fdrop(fp, td);
			return (EINVAL);
		}

		error = coalition_check_cycle(nested_co, co,
		    COALITION_MAX_NESTING);
		if (error != 0) {
			coalition_rel(nested_co);
			sx_xunlock(&coalition_nest_lock);
			uma_zfree_smr(coalition_member_zone, cm);
			fdrop(fp, td);
			SDT_PROBE3(mac_capability_coalition, , , deny,
			    "enlist-cycle", error, td->td_proc->p_pid);
			return (error);
		}

		/* Cycle check passed — now take co_sx for insertion */
		sx_xlock(&co->co_sx);
		if (co->co_flags & (COF_TERMINATING | COF_GRACE_ACTIVE)) {
			sx_xunlock(&co->co_sx);
			coalition_rel(nested_co);
			sx_xunlock(&coalition_nest_lock);
			uma_zfree_smr(coalition_member_zone, cm);
			fdrop(fp, td);
			SDT_PROBE3(mac_capability_coalition, , , deny,
			    "enlist-shutdown", ESHUTDOWN,
			    td->td_proc->p_pid);
			return (ESHUTDOWN);
		}

		if (coalition_has_member(co, fp)) {
			sx_xunlock(&co->co_sx);
			coalition_rel(nested_co);
			sx_xunlock(&coalition_nest_lock);
			uma_zfree_smr(coalition_member_zone, cm);
			fdrop(fp, td);
			SDT_PROBE3(mac_capability_coalition, , , deny,
			    "enlist-busy", EBUSY,
			    td->td_proc->p_pid);
			return (EBUSY);
		}

		sx_xlock(&nested_co->co_sx);
		if (nested_co->co_nesting_depth != 0) {
			sx_xunlock(&nested_co->co_sx);
			sx_xunlock(&co->co_sx);
			coalition_rel(nested_co);
			sx_xunlock(&coalition_nest_lock);
			uma_zfree_smr(coalition_member_zone, cm);
			fdrop(fp, td);
			SDT_PROBE3(mac_capability_coalition, , , deny,
			    "enlist-busy", EBUSY,
			    td->td_proc->p_pid);
			return (EBUSY);
		}

		error = coalition_validate_redepth_locked(nested_co,
		    co->co_nesting_depth + 1);
		if (error != 0) {
			sx_xunlock(&nested_co->co_sx);
			sx_xunlock(&co->co_sx);
			coalition_rel(nested_co);
			sx_xunlock(&coalition_nest_lock);
			uma_zfree_smr(coalition_member_zone, cm);
			fdrop(fp, td);
			return (error);
		}

		coalition_apply_redepth_locked(nested_co,
		    co->co_nesting_depth + 1);
		sx_xunlock(&nested_co->co_sx);

		cm->cm_nested_co = nested_co;
		/* ref transferred to cm_nested_co */
		sx_xunlock(&coalition_nest_lock);
	} else {
		/* Generic: mac_capability (non-nested), socket, shm, etc. */
		sx_xlock(&co->co_sx);
		if (co->co_flags & (COF_TERMINATING | COF_GRACE_ACTIVE)) {
			sx_xunlock(&co->co_sx);
			uma_zfree_smr(coalition_member_zone, cm);
			fdrop(fp, td);
			SDT_PROBE3(mac_capability_coalition, , , deny,
			    "enlist-shutdown", ESHUTDOWN,
			    td->td_proc->p_pid);
			return (ESHUTDOWN);
		}

		if (coalition_has_member(co, fp)) {
			sx_xunlock(&co->co_sx);
			uma_zfree_smr(coalition_member_zone, cm);
			fdrop(fp, td);
			SDT_PROBE3(mac_capability_coalition, , , deny,
			    "enlist-busy", EBUSY,
			    td->td_proc->p_pid);
			return (EBUSY);
		}
	}

	/* Common member setup */
	cm->cm_fp = fp;
	cm->cm_coalition = co;
	TAILQ_INSERT_TAIL(&co->co_members, cm, cm_link);

	if (dtype == DTYPE_JAILDESC) {
		struct prison *pr = cm->cm_data;

		/*
		 * cm_data owns the prison_hold() taken during enlist and must
		 * keep that reference until member teardown.
		 */
		coalition_jail_set_member(pr, cm);
		atomic_add_int(&coalition_held_jails, 1);
	}

	atomic_add_int(&co->co_member_count, 1);
	atomic_add_int(&coalition_total_members, 1);
	coalition_ref(co);
	coalition_notify_event(co, COALITION_NOTE_MEMBER_ADDED);
	sx_xunlock(&co->co_sx);

	/*
	 * Now that the jail is held, charge what is already running inside it.
	 * Done after co_sx is dropped: the walk takes allprison_lock and
	 * allproc_lock and then the process lock, and holding co_sx across
	 * those would put this module in the middle of two of the heaviest
	 * locks in the kernel for no reason.
	 */
	if (dtype == DTYPE_JAILDESC)
		coalition_jail_charge_existing((struct prison *)cm->cm_data);

	SDT_PROBE2(mac_capability_coalition, , , enlist, dtype, 0);
	return (0);
}

/* ----------------------------------------------------------------
 * Self-join (process joins coalition without procdesc)
 * ---------------------------------------------------------------- */

static int
coalition_join(struct coalition *co, struct thread *td)
{
	struct coalition_member *cm;
	struct proc *p;
	int error;

	error = coalition_check_limits();
	if (error != 0) {
		SDT_PROBE3(mac_capability_coalition, , , deny, (uintptr_t)"join-limit",
		    ENOMEM, td->td_proc->p_pid);
		return (error);
	}

	p = td->td_proc;
	cm = uma_zalloc_smr(coalition_member_zone, M_WAITOK | M_ZERO);

	/*
	 * Lock order: co_sx → hash_lock.
	 */
	sx_xlock(&co->co_sx);
	if (co->co_flags & (COF_TERMINATING | COF_GRACE_ACTIVE)) {
		sx_xunlock(&co->co_sx);
		uma_zfree_smr(coalition_member_zone, cm);
		SDT_PROBE3(mac_capability_coalition, , , deny,
		    "join-shutdown", ESHUTDOWN, p->p_pid);
		return (ESHUTDOWN);
	}

	mtx_lock(&coalition_proc_hash_mtx);
	if (coalition_proc_hash_lookup(p) != NULL) {
		mtx_unlock(&coalition_proc_hash_mtx);
		sx_xunlock(&co->co_sx);
		uma_zfree_smr(coalition_member_zone, cm);
		SDT_PROBE3(mac_capability_coalition, , , deny,
		    "join-busy", EBUSY, p->p_pid);
		return (EBUSY);
	}

	cm->cm_data = p;
	cm->cm_fp = NULL;
	cm->cm_coalition = co;
	cm->cm_dtype = DTYPE_PROCDESC;

	coalition_proc_hash_insert(cm, p);
	coalition_racct_join(p, co);
	mtx_unlock(&coalition_proc_hash_mtx);
	TAILQ_INSERT_TAIL(&co->co_members, cm, cm_link);

	atomic_add_int(&co->co_member_count, 1);
	atomic_add_int(&coalition_total_members, 1);
	coalition_ref(co);
	coalition_notify_event(co, COALITION_NOTE_MEMBER_ADDED);

	sx_xunlock(&co->co_sx);

	SDT_PROBE2(mac_capability_coalition, , , join, p->p_pid, 0);
	return (0);
}

/* ----------------------------------------------------------------
 * Termination
 * ---------------------------------------------------------------- */

static void
coalition_signal_processes_locked(struct coalition *co, int sig)
{
	struct coalition_member *cm;

	sx_assert(&co->co_sx, SA_XLOCKED);

	if (sig == 0)
		return;
	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		struct proc *p;

		if (cm->cm_dtype != DTYPE_PROCDESC)
			continue;

		if (cm->cm_fp != NULL) {
			struct procdesc *pd = cm->cm_fp->f_data;

			sx_slock(&proctree_lock);
			p = pd->pd_proc;
			if (p != NULL) {
				PROC_LOCK(p);
				sx_sunlock(&proctree_lock);
				kern_psignal(p, sig);
				PROC_UNLOCK(p);
			} else {
				sx_sunlock(&proctree_lock);
			}
		} else if (cm->cm_data != NULL) {
			p = (struct proc *)atomic_load_acq_ptr(
			    (uintptr_t *)&cm->cm_data);
			if (p != NULL) {
				PROC_LOCK(p);
				kern_psignal(p, sig);
				PROC_UNLOCK(p);
			}
		}
	}
}

static u_int
coalition_count_process_members_locked(struct coalition *co)
{
	struct coalition_member *cm;
	u_int count;

	sx_assert(&co->co_sx, SA_XLOCKED);

	count = 0;
	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		if (cm->cm_dtype == DTYPE_PROCDESC)
			count++;
	}
	return (count);
}

static u_int
coalition_count_live_procs_locked(struct coalition *co)
{
	struct coalition_member *cm;
	u_int count = 0;

	sx_assert(&co->co_sx, SA_XLOCKED);

	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		struct proc *p;

		if (cm->cm_dtype != DTYPE_PROCDESC)
			continue;

		if (cm->cm_fp != NULL) {
			struct procdesc *pd = cm->cm_fp->f_data;

			sx_slock(&proctree_lock);
			p = pd->pd_proc;
			if (p != NULL) {
				PROC_LOCK(p);
				if ((p->p_flag & P_WEXIT) == 0)
					count++;
				PROC_UNLOCK(p);
			}
			sx_sunlock(&proctree_lock);
		} else if (cm->cm_data != NULL) {
			p = (struct proc *)atomic_load_acq_ptr(
			    (uintptr_t *)&cm->cm_data);
			if (p != NULL) {
				PROC_LOCK(p);
				if ((p->p_flag & P_WEXIT) == 0)
					count++;
				PROC_UNLOCK(p);
			}
		}
	}
	return (count);
}

static void
coalition_collect_external_members_locked(struct coalition *co,
    struct file ***jail_fpsp, int *jail_countp,
    struct mac_capability_instance ***mac_capability_cisp, int *mac_capability_countp)
{
	struct coalition_member *cm;
	struct file **jail_fps;
	struct mac_capability_instance **mac_capability_cis;
	int jail_count, mac_capability_count, i;

	sx_assert(&co->co_sx, SA_XLOCKED);

	jail_count = 0;
	mac_capability_count = 0;
	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		if (cm->cm_dtype == DTYPE_JAILDESC && cm->cm_fp != NULL)
			jail_count++;
		else if (cm->cm_dtype == DTYPE_MAC_CAPABILITY && cm->cm_fp != NULL)
			mac_capability_count++;
	}

	jail_fps = NULL;
	if (jail_count > 0) {
		jail_fps = malloc(jail_count * sizeof(struct file *),
		    M_COALITION, M_WAITOK);
		i = 0;
		TAILQ_FOREACH(cm, &co->co_members, cm_link) {
			if (cm->cm_dtype == DTYPE_JAILDESC &&
			    cm->cm_fp != NULL && i < jail_count) {
				if (fhold(cm->cm_fp))
					jail_fps[i++] = cm->cm_fp;
			}
		}
		jail_count = i;
	}

	mac_capability_cis = NULL;
	if (mac_capability_count > 0) {
		mac_capability_cis = malloc(
		    mac_capability_count * sizeof(struct mac_capability_instance *),
		    M_COALITION, M_WAITOK);
		i = 0;
		TAILQ_FOREACH(cm, &co->co_members, cm_link) {
			if (cm->cm_dtype == DTYPE_MAC_CAPABILITY &&
			    cm->cm_fp != NULL && i < mac_capability_count) {
				struct mac_capability_instance *ci;

				ci = cm->cm_fp->f_data;
				if (ci != NULL) {
					mac_capability_instance_hold(ci);
					mac_capability_cis[i++] = ci;
				}
			}
		}
		mac_capability_count = i;
	}

	*jail_fpsp = jail_fps;
	*jail_countp = jail_count;
	*mac_capability_cisp = mac_capability_cis;
	*mac_capability_countp = mac_capability_count;
}

static void
coalition_terminate_external_members(struct thread *td, struct file **jail_fps,
    int jail_count, struct mac_capability_instance **mac_capability_cis, int mac_capability_count)
{
	int i;

	for (i = 0; i < mac_capability_count; i++) {
		mac_capability_instance_revoke(mac_capability_cis[i]);
		mac_capability_instance_rele(mac_capability_cis[i]);
	}
	if (mac_capability_cis != NULL)
		free(mac_capability_cis, M_COALITION);

	for (i = 0; i < jail_count; i++) {
		(void)coalition_jail_terminate(jail_fps[i]);
		fdrop(jail_fps[i], td);
	}
	if (jail_fps != NULL)
		free(jail_fps, M_COALITION);
}

/*
 * Must be called with co_sx held.
 * sig_override: if nonzero, use this signal instead of co_signal.
 * Used by graceful/deadline escalation to force SIGKILL.
 */
static void
coalition_terminate_members_locked(struct coalition *co, struct thread *td,
    bool skip_self, int sig_override, int reason)
{
	struct coalition_member *cm;
	struct proc *self;

	sx_assert(&co->co_sx, SA_XLOCKED);

	if (co->co_flags & COF_TERMINATING)
		return;
	co->co_flags |= COF_TERMINATING;
	/*
	 * Record why before anything is signalled, so the notification a holder
	 * receives, the probe and any later report all say the same thing.  A
	 * coalition dies once, for one reason.
	 */
	co->co_kill_reason = reason;
	SDT_PROBE5(mac_capability_coalition, , , coalition__kill, co->co_id,
	    co->co_responsible_id, (u_int)reason,
	    racct_read(co->co_racct, RACCT_RSS), coalition_band_effective(co));
	if (reason != COALITION_KILL_NONE &&
	    reason != COALITION_KILL_REQUESTED) {
		coalition_kill_count(reason);
		/*
		 * Say it out loud for anything the system decided by itself.
		 * A holder asking for a termination already knows; a unit
		 * disappearing because of a policy is the case that needs a
		 * record an operator can find afterwards.
		 */
		log(LOG_WARNING, "mac_capability_coalition: terminating "
		    "coalition %ju (responsible %ju): %s; %ju KB, band %u, "
		    "%u members\n", (uintmax_t)co->co_id,
		    (uintmax_t)co->co_responsible_id,
		    coalition_kill_reason_name(reason),
		    (uintmax_t)(racct_read(co->co_racct, RACCT_RSS) / 1024),
		    coalition_band_effective(co),
		    atomic_load_int(&co->co_member_count));
	}
	coalition_notify_event(co, COALITION_NOTE_TERMINATING);

	/* Clean up leader tracking */
	co->co_leader = NULL;
	co->co_flags &= ~COF_HAS_LEADER;
	co->co_manual_grace_count = 0;
	coalition_update_grace_flag_locked(co);

	self = (skip_self && td != NULL) ? td->td_proc : NULL;

	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		/*
		 * Skip mac_capability and jail members — both must be
		 * terminated outside the lock to avoid deadlock.
		 * mac_capability: co_revoke can re-enter coalition_close_internal.
		 * jails: OSD destructor needs co_sx.
		 */
		if (cm->cm_dtype == DTYPE_MAC_CAPABILITY)
			continue;
		if (cm->cm_dtype == DTYPE_JAILDESC)
			continue;

		/* Process members — use override or configured signal */
		if (cm->cm_dtype == DTYPE_PROCDESC) {
			struct proc *p;
			int sig = (sig_override != 0) ?
			    sig_override : co->co_signal;

			if (cm->cm_fp != NULL) {
				struct procdesc *pd = cm->cm_fp->f_data;

				sx_slock(&proctree_lock);
				p = pd->pd_proc;
				if (p != NULL) {
					PROC_LOCK(p);
					sx_sunlock(&proctree_lock);
					if (!(skip_self && p == self)) {
						SDT_PROBE4(
						    mac_capability_coalition, , ,
						    member__kill, co->co_id,
						    co->co_responsible_id,
						    p->p_pid, sig);
						if (sig != 0)
							kern_psignal(p, sig);
					} else
						SDT_PROBE2(
						    mac_capability_coalition, , ,
						    member__spared, co->co_id,
						    p->p_pid);
					PROC_UNLOCK(p);
				} else {
					sx_sunlock(&proctree_lock);
				}
			} else if (cm->cm_data != NULL) {
				p = (struct proc *)atomic_load_acq_ptr(
				    (uintptr_t *)&cm->cm_data);
				if (skip_self && p == self) {
					SDT_PROBE2(mac_capability_coalition, , ,
					    member__spared, co->co_id,
					    p->p_pid);
					continue;
				}
				if (p != NULL) {
					SDT_PROBE4(mac_capability_coalition, , ,
					    member__kill, co->co_id,
					    co->co_responsible_id, p->p_pid,
					    sig);
					if (sig != 0) {
						PROC_LOCK(p);
						kern_psignal(p, sig);
						PROC_UNLOCK(p);
					}
				}
			}
			continue;
		}

		/* Sockets */
		if (cm->cm_dtype == DTYPE_SOCKET && cm->cm_fp != NULL) {
			struct socket *so = cm->cm_fp->f_data;

			(void)soshutdown(so, SHUT_RDWR);
			continue;
		}

		/* SHM — truncate to zero */
		if (cm->cm_dtype == DTYPE_SHM && cm->cm_fp != NULL) {
			(void)fo_truncate(cm->cm_fp, 0, td->td_ucred, td);
			continue;
		}
	}
}

static int
coalition_terminate(struct coalition *co)
{
	struct thread *td = curthread;
	struct file **jail_fps;
	struct mac_capability_instance **mac_capability_cis;
	int jail_count, mac_capability_count;

	sx_xlock(&co->co_sx);

	if (co->co_flags & COF_TERMINATING) {
		sx_xunlock(&co->co_sx);
		return (ESHUTDOWN);
	}

	coalition_collect_external_members_locked(co, &jail_fps,
	    &jail_count, &mac_capability_cis, &mac_capability_count);

	/* Terminate processes, sockets, shm under lock */
	coalition_terminate_members_locked(co, td, false, 0,
	    COALITION_KILL_REQUESTED);
	sx_xunlock(&co->co_sx);

	coalition_terminate_external_members(td, jail_fps, jail_count,
	    mac_capability_cis, mac_capability_count);

	SDT_PROBE2(mac_capability_coalition, , , terminate,
	    atomic_load_acq_int(&co->co_member_count), 0);
	return (0);
}

static int
coalition_terminate_graceful(struct coalition *co, int sig, u_int timeout_ms)
{
	struct file **jail_fps;
	struct mac_capability_instance **mac_capability_cis;
	bool had_process_members;
	bool force_kill;
	int jail_count, mac_capability_count;

	u_int remaining, elapsed;

	if (sig <= 0 || sig >= NSIG)
		return (EINVAL);
	if (timeout_ms > 60000)
		timeout_ms = 60000;

	sx_xlock(&co->co_sx);
	if (co->co_flags & COF_TERMINATING) {
		sx_xunlock(&co->co_sx);
		return (ESHUTDOWN);
	}

	/* Freeze membership during grace period */
	co->co_manual_grace_count++;
	coalition_update_grace_flag_locked(co);
	had_process_members = (coalition_count_process_members_locked(co) != 0);

	coalition_signal_processes_locked(co, sig);
	SDT_PROBE3(mac_capability_coalition, , , graceful,
	    sig, timeout_ms, 0);

	elapsed = 0;
	while (elapsed < timeout_ms) {
		remaining = coalition_count_live_procs_locked(co);
		if (remaining == 0)
			break;
		sx_xunlock(&co->co_sx);
		u_int sleep_ms = (timeout_ms - elapsed);
		if (sleep_ms > 100)
			sleep_ms = 100;
		(void)pause_sbt("co_grace", SBT_1MS * sleep_ms,
		    0, C_HARDCLOCK);
		elapsed += sleep_ms;
		sx_xlock(&co->co_sx);
		if (co->co_flags & COF_TERMINATING) {
			if (co->co_manual_grace_count > 0)
				co->co_manual_grace_count--;
			coalition_update_grace_flag_locked(co);
			sx_xunlock(&co->co_sx);
			return (0);
		}
	}

	force_kill = (coalition_count_live_procs_locked(co) != 0);
	if (co->co_manual_grace_count > 0)
		co->co_manual_grace_count--;
	coalition_update_grace_flag_locked(co);

	if (force_kill || !had_process_members) {
		/*
		 * If processes are still alive after grace, escalate to
		 * SIGKILL.  If there were never any process members, degrade
		 * graceful termination into an immediate full termination for
		 * the remaining member types.
		 */
		coalition_collect_external_members_locked(co, &jail_fps,
		    &jail_count, &mac_capability_cis, &mac_capability_count);
		coalition_terminate_members_locked(co, curthread, false,
		    force_kill ? SIGKILL : 0, COALITION_KILL_REQUESTED);
		sx_xunlock(&co->co_sx);
		coalition_terminate_external_members(curthread, jail_fps,
		    jail_count, mac_capability_cis, mac_capability_count);
	} else {
		/*
		 * All processes exited during grace period —
		 * coalition stays alive for reuse.
		 */
		sx_xunlock(&co->co_sx);
	}
	return (0);
}

static bool
coalition_deadline_disarm_locked(struct coalition *co)
{
	u_int pending;
	int error;

	sx_assert(&co->co_sx, SA_XLOCKED);

	if (!(co->co_flags & COF_DEADLINE_ACTIVE))
		return (false);

	co->co_flags &= ~(COF_DEADLINE_ACTIVE | COF_DEADLINE_GRACE);
	coalition_update_grace_flag_locked(co);

	if (callout_stop(&co->co_deadline_callout))
		coalition_rel(co);

	pending = 0;
	error = taskqueue_cancel(taskqueue_thread, &co->co_deadline_task,
	    &pending);
	if (pending != 0)
		coalition_rel(co);
	return (error == EBUSY);
}

static bool
coalition_watchdog_disarm_locked(struct coalition *co)
{
	u_int pending;
	int error;

	sx_assert(&co->co_sx, SA_XLOCKED);

	if (!(co->co_flags & COF_WATCHDOG_ACTIVE))
		return (false);

	co->co_flags &= ~COF_WATCHDOG_ACTIVE;

	if (callout_stop(&co->co_watchdog_callout))
		coalition_rel(co);

	pending = 0;
	error = taskqueue_cancel(taskqueue_thread, &co->co_watchdog_task,
	    &pending);
	if (pending != 0)
		coalition_rel(co);
	return (error == EBUSY);
}

/* ----------------------------------------------------------------
 * Deadline timer
 * ---------------------------------------------------------------- */

static void
coalition_deadline_task_fn(void *context, int pending __unused)
{
	struct coalition *co = context;
	struct file **jail_fps = NULL;
	struct mac_capability_instance **mac_capability_cis = NULL;
	struct thread *td = curthread;
	int jail_count = 0, mac_capability_count = 0;
	int sig_override;

	sx_xlock(&co->co_sx);

	/*
	 * close_internal is draining us: do NOT re-arm and do NOT drop the ref.
	 * Leave COF_DEADLINE_ACTIVE and the timer ref in place so close's single
	 * flag-check release balances the arm.  (Without COF_CLOSING we fall
	 * through to the early-return below, which drops the ref -- no leak.)
	 */
	if ((co->co_flags & COF_CLOSING) &&
	    (co->co_flags & COF_DEADLINE_ACTIVE)) {
		sx_xunlock(&co->co_sx);
		return;
	}

	if ((co->co_flags & COF_TERMINATING) ||
	    !(co->co_flags & COF_DEADLINE_ACTIVE)) {
		sx_xunlock(&co->co_sx);
		coalition_rel(co);
		return;
	}

	if (co->co_flags & COF_DEADLINE_GRACE) {
		/* Grace expired — escalate to SIGKILL */
		co->co_flags &= ~(COF_DEADLINE_ACTIVE | COF_DEADLINE_GRACE);
		SDT_PROBE2(mac_capability_coalition, , , deadline__expire,
		    (uintptr_t)"grace-escalate", SIGKILL);
		coalition_notify_event(co, COALITION_NOTE_DEADLINE_FIRED);
		coalition_collect_external_members_locked(co, &jail_fps,
		    &jail_count, &mac_capability_cis, &mac_capability_count);
		coalition_terminate_members_locked(co, td, false, SIGKILL,
		    COALITION_KILL_DEADLINE);
		sx_xunlock(&co->co_sx);
		coalition_terminate_external_members(td, jail_fps, jail_count,
		    mac_capability_cis, mac_capability_count);
		coalition_rel(co);
		return;
	} else if (co->co_deadline_signal != 0 &&
	    co->co_deadline_grace_ms > 0) {
		coalition_signal_processes_locked(co, co->co_deadline_signal);
		coalition_notify_event(co,
		    COALITION_NOTE_DEADLINE_FIRED |
		    COALITION_NOTE_GRACE_STARTED);
		co->co_flags |= COF_DEADLINE_GRACE;
		SDT_PROBE2(mac_capability_coalition, , , deadline__expire,
		    (uintptr_t)"grace-start", co->co_deadline_signal);
		coalition_update_grace_flag_locked(co);
		coalition_ref(co);
		callout_reset(&co->co_deadline_callout,
		    coalition_timeout_ticks(co->co_deadline_grace_ms),
		    coalition_deadline_callout_fn, co);
	} else {
		co->co_flags &= ~COF_DEADLINE_ACTIVE;
		SDT_PROBE2(mac_capability_coalition, , , deadline__expire,
		    (uintptr_t)"immediate", co->co_deadline_signal != 0 ? co->co_deadline_signal : SIGKILL);
		coalition_notify_event(co, COALITION_NOTE_DEADLINE_FIRED);
		coalition_collect_external_members_locked(co, &jail_fps,
		    &jail_count, &mac_capability_cis, &mac_capability_count);
		sig_override = (co->co_deadline_signal != 0) ?
		    co->co_deadline_signal : SIGKILL;
		coalition_terminate_members_locked(co, td, false, sig_override,
		    COALITION_KILL_DEADLINE);
		sx_xunlock(&co->co_sx);
		coalition_terminate_external_members(td, jail_fps, jail_count,
		    mac_capability_cis, mac_capability_count);
		coalition_rel(co);
		return;
	}

	sx_xunlock(&co->co_sx);
	coalition_rel(co);
}

static void
coalition_deadline_callout_fn(void *arg)
{
	struct coalition *co = arg;

	taskqueue_enqueue(taskqueue_thread, &co->co_deadline_task);
}

/* ----------------------------------------------------------------
 * Watchdog timer
 * ---------------------------------------------------------------- */

static void
coalition_watchdog_task_fn(void *context, int pending __unused)
{
	struct coalition *co = context;
	struct file **jail_fps = NULL;
	struct mac_capability_instance **mac_capability_cis = NULL;
	int jail_count = 0, mac_capability_count = 0;

	sx_xlock(&co->co_sx);

	if ((co->co_flags & COF_TERMINATING) ||
	    !(co->co_flags & COF_WATCHDOG_ACTIVE)) {
		sx_xunlock(&co->co_sx);
		coalition_rel(co);
		return;
	}

	co->co_flags &= ~COF_WATCHDOG_ACTIVE;
	SDT_PROBE1(mac_capability_coalition, , , watchdog__expire, SIGKILL);
	coalition_notify_event(co, COALITION_NOTE_WATCHDOG_FIRED);
	coalition_collect_external_members_locked(co, &jail_fps,
	    &jail_count, &mac_capability_cis, &mac_capability_count);
	coalition_terminate_members_locked(co, curthread, false, SIGKILL,
	    COALITION_KILL_WATCHDOG);
	sx_xunlock(&co->co_sx);
	coalition_terminate_external_members(curthread, jail_fps, jail_count,
	    mac_capability_cis, mac_capability_count);
	coalition_rel(co);
}

static void
coalition_watchdog_callout_fn(void *arg)
{
	struct coalition *co = arg;

	taskqueue_enqueue(taskqueue_thread, &co->co_watchdog_task);
}

/* ----------------------------------------------------------------
 * Mac_capability leader monitor
 * ---------------------------------------------------------------- */

/*
 * Taskqueue handler: check if the mac_capability leader is still alive.
 * If dead, terminate the coalition immediately.  If still alive,
 * reschedule the monitor callout.
 */
static void
coalition_leader_task_fn(void *context, int pending __unused)
{
	struct coalition *co = context;
	struct coalition_member *leader;
	struct mac_capability_instance *ci;
	bool dead = false;

	sx_xlock(&co->co_sx);

	/*
	 * close_internal is draining us: keep COF_LEADER_MONITOR and the monitor
	 * ref in place (do not re-arm, do not drop) so close's flag-check release
	 * is the single finalizer -- same rule as the deadline task.
	 */
	if ((co->co_flags & COF_CLOSING) &&
	    (co->co_flags & COF_LEADER_MONITOR)) {
		sx_xunlock(&co->co_sx);
		return;
	}

	/* Bail if terminating or monitor was stopped */
	if ((co->co_flags & COF_TERMINATING) ||
	    !(co->co_flags & COF_LEADER_MONITOR)) {
		co->co_flags &= ~COF_LEADER_MONITOR;
		sx_xunlock(&co->co_sx);
		coalition_rel(co);	/* monitor's ref */
		return;
	}

	leader = co->co_leader;
	if (leader == NULL || leader->cm_dtype != DTYPE_MAC_CAPABILITY ||
	    leader->cm_fp == NULL) {
		co->co_flags &= ~COF_LEADER_MONITOR;
		sx_xunlock(&co->co_sx);
		coalition_rel(co);
		return;
	}

	ci = leader->cm_fp->f_data;
	if (ci != NULL) {
		mtx_lock(&ci->ci_mtx);
		if (ci->ci_flags & (MAC_CAPABILITY_SF_CLOSED | MAC_CAPABILITY_SF_REVOKED))
			dead = true;
		mtx_unlock(&ci->ci_mtx);
	}

	if (dead) {
		co->co_leader = NULL;
		co->co_flags &= ~(COF_HAS_LEADER | COF_LEADER_MONITOR);
		coalition_notify_event(co, COALITION_NOTE_LEADER_DIED);
		sx_xunlock(&co->co_sx);

		SDT_PROBE1(mac_capability_coalition, , , leader__exit, 0);
		coalition_terminate(co);
		coalition_rel(co);	/* monitor's ref */
	} else {
		/* Still alive — reschedule, keep ref */
		callout_reset(&co->co_leader_callout,
		    COALITION_LEADER_POLL_TICKS,
		    coalition_leader_callout_fn, co);
		sx_xunlock(&co->co_sx);
	}
}

static void
coalition_leader_callout_fn(void *arg)
{
	struct coalition *co = arg;

	taskqueue_enqueue(taskqueue_thread, &co->co_leader_task);
}

/*
 * Start or restart the mac_capability leader monitor.
 * Exactly one coalition reference is held while the monitor
 * is active (tracked by COF_LEADER_MONITOR flag).
 * Caller must hold co_sx.
 */
static void
coalition_leader_monitor_start_locked(struct coalition *co)
{

	sx_assert(&co->co_sx, SA_XLOCKED);
	if (!(co->co_flags & COF_LEADER_MONITOR)) {
		co->co_flags |= COF_LEADER_MONITOR;
		coalition_ref(co);
	}
	callout_reset(&co->co_leader_callout,
	    COALITION_LEADER_POLL_TICKS,
	    coalition_leader_callout_fn, co);
}

/*
 * Stop the monitor.  Clears the flag; the running task will
 * see the flag clear and release the ref.  If a task is
 * merely queued, cancel it and release the ref here.
 * Caller must hold co_sx.
 */
static bool
coalition_leader_monitor_stop_locked(struct coalition *co)
{
	u_int pending;
	int error;

	sx_assert(&co->co_sx, SA_XLOCKED);
	if (!(co->co_flags & COF_LEADER_MONITOR))
		return (false);
	co->co_flags &= ~COF_LEADER_MONITOR;
	if (callout_stop(&co->co_leader_callout))
		coalition_rel(co);
	pending = 0;
	error = taskqueue_cancel(taskqueue_thread, &co->co_leader_task,
	    &pending);
	if (pending != 0)
		coalition_rel(co);
	return (error == EBUSY);
}

/* ----------------------------------------------------------------
 * Process exit / fork eventhandlers
 * ---------------------------------------------------------------- */

static void
coalition_process_exit(void *arg __unused, struct proc *p)
{
	struct coalition_member *cm;
	struct coalition *co;
	bool was_leader = false;

	mtx_lock(&coalition_proc_hash_mtx);
	cm = coalition_proc_hash_lookup(p);
	if (cm == NULL) {
		mtx_unlock(&coalition_proc_hash_mtx);
		/*
		 * Not a member, which does not mean it is not charged
		 * anywhere: a process inside a jail that a coalition holds is
		 * accounted without ever being enlisted.
		 *
		 * The pointer is deliberately left alone.  This handler runs
		 * at the top of exit, long before the address space is torn
		 * down, and it is that teardown which gives the container back
		 * everything reclaimable; cutting the pointer here would keep
		 * the charges on the container for good.  racct_proc_exit()
		 * drops the reference and clears the pointer once the giving
		 * back is done.
		 *
		 * Detaching here used to guard against a container being freed
		 * under an exiting process.  The container is reference
		 * counted now -- a process holds one for as long as it points
		 * at one -- so that cannot happen, and a coalition torn down
		 * while this process was alive has already taken the pointer
		 * away itself.
		 */
		return;
	}

	SDT_PROBE1(mac_capability_coalition, , , member__exit, p->p_pid);

	co = cm->cm_coalition;
	coalition_ref(co);
	CK_LIST_REMOVE(cm, cm_hash);
	cm->cm_hash.cle_prev = NULL;
	mtx_unlock(&coalition_proc_hash_mtx);

	/*
	 * Re-find the member on the coalition's TAILQ under co_sx.
	 *
	 * We cannot dereference cm after dropping hash_lock because
	 * coalition_close_internal() may have already removed it from
	 * the TAILQ, freed it, and moved on — making cm a dangling
	 * pointer.  Instead, search by proc pointer (p is still alive
	 * as the exiting process, and each proc can only be in one
	 * coalition).
	 */
	cm = NULL;

	sx_xlock(&co->co_sx);
	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		if (cm->cm_data == p)
			break;
	}
	if (cm != NULL) {
		TAILQ_REMOVE(&co->co_members, cm, cm_link);
		cm->cm_link.tqe_prev = NULL;

		if ((co->co_flags & COF_HAS_LEADER) &&
		    co->co_leader == cm) {
			was_leader = true;
			co->co_leader = NULL;
			co->co_flags &= ~COF_HAS_LEADER;
		}

		atomic_subtract_int(&co->co_member_count, 1);
		atomic_subtract_int(&coalition_total_members, 1);
		coalition_notify_event(co, COALITION_NOTE_MEMBER_REMOVED);
	}
	sx_xunlock(&co->co_sx);

	if (was_leader) {
		SDT_PROBE1(mac_capability_coalition, , , leader__exit, p->p_pid);
		coalition_terminate(co);
	}

	if (cm != NULL) {
		if (cm->cm_fp != NULL)
			fdrop(cm->cm_fp, curthread);
		uma_zfree_smr(coalition_member_zone, cm);
		coalition_rel(co);	/* member's ref */
	}
	coalition_rel(co);	/* our local ref */
}

static void
coalition_process_fork(void *arg __unused, struct proc *parent,
    struct proc *child, int flags)
{
	struct coalition_member *pcm, *ccm;
	struct coalition *co;

	/*
	 * Every child of a member inherits membership, pdfork(2) children
	 * included: a unit's helpers must carry the unit's identity or the
	 * attribution chain (kinfo, audit, OES) breaks at the first helper.
	 * The launcher pattern still works: a process descriptor holder may
	 * re-home an INHERITED membership by enlisting the procdesc elsewhere
	 * (coalition_enlist), so a factory that hands a worker to a consumer's
	 * coalition just enlists it there.  Only an explicit procdesc enlist is
	 * pinned (EBUSY on a second enlist).
	 */
	smr_enter(coalition_smr);
	pcm = coalition_proc_hash_lookup(parent);
	if (pcm == NULL || (co = pcm->cm_coalition) == NULL) {
		smr_exit(coalition_smr);
		/*
		 * The parent is in no coalition of its own, but it may be
		 * inside a jail that one holds, in which case the child is
		 * too and is charged there.  It does not become a member:
		 * a jail's processes are accounted, not enlisted.
		 */
		coalition_charge_jailed_child(child);
		return;
	}
	/*
	 * The parent's coalition may already be on its way out, in which case
	 * there is no identity left to inherit.
	 */
	if (!refcount_acquire_if_not_zero(&co->co_refcount)) {
		smr_exit(coalition_smr);
		return;
	}
	smr_exit(coalition_smr);

	ccm = uma_zalloc_smr(coalition_member_zone, M_WAITOK | M_ZERO);

	/*
	 * Lock order: co_sx → hash_lock.
	 */
	sx_xlock(&co->co_sx);

	if (co->co_flags & (COF_TERMINATING | COF_GRACE_ACTIVE)) {
		sx_xunlock(&co->co_sx);
		uma_zfree_smr(coalition_member_zone, ccm);
		coalition_rel(co);
		return;
	}

	/* Enforce member limits — refuse fork inheritance if exceeded */
	if (coalition_check_limits() != 0) {
		sx_xunlock(&co->co_sx);
		uma_zfree_smr(coalition_member_zone, ccm);
		coalition_rel(co);
		SDT_PROBE3(mac_capability_coalition, , , deny, (uintptr_t)"fork-limit",
		    ENOMEM, child->p_pid);
		log(LOG_WARNING,
		    "mac_capability_coalition: fork denied by member limit\n");
		return;
	}

	ccm->cm_data = child;
	ccm->cm_fp = NULL;
	ccm->cm_coalition = co;
	ccm->cm_dtype = DTYPE_PROCDESC;

	mtx_lock(&coalition_proc_hash_mtx);
	coalition_proc_hash_insert(ccm, child);
	mtx_unlock(&coalition_proc_hash_mtx);
	TAILQ_INSERT_TAIL(&co->co_members, ccm, cm_link);

	atomic_add_int(&co->co_member_count, 1);
	atomic_add_int(&coalition_total_members, 1);
	coalition_ref(co);
	coalition_notify_event(co, COALITION_NOTE_MEMBER_ADDED);

	sx_xunlock(&co->co_sx);

	SDT_PROBE2(mac_capability_coalition, , , fork__inherit,
	    parent->p_pid, child->p_pid);
	coalition_rel(co);
}

/* ----------------------------------------------------------------
 * Close / cleanup (co_revoke)
 * ---------------------------------------------------------------- */

static void
coalition_close_internal(struct coalition *co, struct thread *td)
{
	struct coalition_member *cm, *cm_temp;
	struct coalition_member *cleanup_list, **cleanup_tailp;
	struct coalition_member *jail_list, **jail_tailp;

	if (co == NULL)
		return;

	SDT_PROBE1(mac_capability_coalition, , , close,
	    atomic_load_acq_int(&co->co_member_count));

	/*
	 * Announce the close under co_sx BEFORE draining.  callout_drain stops the
	 * CALLOUT from re-firing, but the drained TASK may legally callout_reset()
	 * and reschedule it (the deadline grace-start and leader-alive paths do
	 * exactly that), leaving a callout armed on `co` after the drain returns --
	 * a use-after-free once close drops the last ref.  COF_TERMINATING is not
	 * usable as the stop flag: it is a one-shot re-entrancy guard consumed by
	 * coalition_terminate_members_locked() below, and pre-setting it would skip
	 * member termination.  So publish COF_CLOSING here; the re-arming task fns
	 * observe it under co_sx and bail WITHOUT re-arming and WITHOUT dropping the
	 * timer ref (leaving it for close's single flag-check release), so no
	 * callout survives the drains.  co_sx serializes us against a task that
	 * re-armed just before this store -- its callout is then killed by the
	 * callout_drain below.
	 */
	sx_xlock(&co->co_sx);
	co->co_flags |= COF_CLOSING;
	sx_xunlock(&co->co_sx);

	/*
	 * Drain pending callouts/tasks before acquiring locks to
	 * avoid deadlock.  callout_drain blocks until any running
	 * handler completes; with COF_CLOSING set above, no task re-arms.
	 */
	callout_drain(&co->co_deadline_callout);
	taskqueue_drain(taskqueue_thread, &co->co_deadline_task);
	callout_drain(&co->co_watchdog_callout);
	taskqueue_drain(taskqueue_thread, &co->co_watchdog_task);
	callout_drain(&co->co_leader_callout);
	taskqueue_drain(taskqueue_thread, &co->co_leader_task);

	/*
	 * Take co_sx alone first to release timer refs and
	 * terminate members (which takes proctree_lock internally).
	 * This avoids holding hash_lock across proctree_lock.
	 */
	sx_xlock(&co->co_sx);

	/*
	 * Release refs held by active timers.  The drains above
	 * ensure nothing is running, so we can safely check flags
	 * and release refs under the lock.
	 */
	if (co->co_flags & COF_DEADLINE_ACTIVE) {
		co->co_flags &= ~(COF_DEADLINE_ACTIVE | COF_DEADLINE_GRACE);
		coalition_rel(co);
	}
	if (co->co_flags & COF_WATCHDOG_ACTIVE) {
		co->co_flags &= ~COF_WATCHDOG_ACTIVE;
		coalition_rel(co);
	}
	if (co->co_flags & COF_LEADER_MONITOR) {
		co->co_flags &= ~COF_LEADER_MONITOR;
		coalition_rel(co);
	}

	coalition_terminate_members_locked(co, td, true, co->co_signal,
	    COALITION_KILL_NONE);
	sx_xunlock(&co->co_sx);

	/*
	 * Re-acquire co_sx to collect members.
	 * COF_TERMINATING is set, so no new members will be added.
	 */
	sx_xlock(&co->co_sx);

	/*
	 * Collect members into cleanup/jail lists.
	 * Mark every member as removed (tqe_prev = NULL) so the
	 * exit handler won't double-remove/double-free.
	 * Remove procdesc members from hash (acquire/release
	 * hash_lock per-member to avoid lock order issues).
	 */
	cleanup_list = NULL;
	cleanup_tailp = &cleanup_list;
	jail_list = NULL;
	jail_tailp = &jail_list;

	TAILQ_FOREACH_SAFE(cm, &co->co_members, cm_link, cm_temp) {
		TAILQ_REMOVE(&co->co_members, cm, cm_link);
		cm->cm_link.tqe_prev = NULL;	/* sentinel for exit handler */

		if (cm->cm_dtype == DTYPE_PROCDESC) {
			/*
			 * A member that survives this -- a release, where the
			 * signal is zero -- leaves the container and takes its
			 * usage with it, as a process does when it changes uid.
			 *
			 * A member being killed only detaches.  It must stop
			 * pointing at the container, because the coalition can
			 * be freed before a terminated member has finished
			 * exiting and a later charge would then write to freed
			 * memory.  It must not give anything back, because the
			 * CPU a terminated member leaves behind is the whole
			 * point of charging it there.  What the container is
			 * still holding is emptied when it is destroyed.
			 */
			/*
			 * Every member leaves the same way, whether it is
			 * being released or killed.  Its CPU is kept.
			 */
			if (cm->cm_data != NULL)
				coalition_racct_leave((struct proc *)cm->cm_data,
				    co);
			mtx_lock(&coalition_proc_hash_mtx);
			if (cm->cm_hash.cle_prev != NULL) {
				CK_LIST_REMOVE(cm, cm_hash);
				/*
				 * Clear the sentinel as well: removing the
				 * same node twice would write through a stale
				 * back pointer and corrupt the bucket, and a
				 * reader walking it lock-free has no lock to
				 * protect it from that.
				 */
				cm->cm_hash.cle_prev = NULL;
			}
			mtx_unlock(&coalition_proc_hash_mtx);
		}

		if (cm->cm_dtype == DTYPE_JAILDESC) {
			*jail_tailp = cm;
			jail_tailp = (struct coalition_member **)
			    &cm->cm_link.tqe_next;
			continue;
		}

		*cleanup_tailp = cm;
		cleanup_tailp = (struct coalition_member **)
		    &cm->cm_link.tqe_next;
	}
	*cleanup_tailp = NULL;
	*jail_tailp = NULL;

	sx_xunlock(&co->co_sx);

	/* Clean up non-jail members (no locks held) */
	for (cm = cleanup_list; cm != NULL; ) {
		struct coalition_member *next =
		    (struct coalition_member *)cm->cm_link.tqe_next;

		atomic_subtract_int(&co->co_member_count, 1);
		atomic_subtract_int(&coalition_total_members, 1);

		/*
		 * Revoke mac_capability members before dropping our file reference so
		 * coalition close preserves terminate semantics and nested
		 * coalition members tear themselves down before the last close.
		 */
		if (cm->cm_dtype == DTYPE_MAC_CAPABILITY && cm->cm_fp != NULL) {
			struct mac_capability_instance *ci = cm->cm_fp->f_data;

			if (ci != NULL)
				mac_capability_instance_revoke(ci);
		}

		/* Release nested coalition ref */
		if (cm->cm_nested_co != NULL)
			coalition_rel(cm->cm_nested_co);

		if (cm->cm_fp != NULL)
			fdrop(cm->cm_fp, td);

		uma_zfree_smr(coalition_member_zone, cm);
		coalition_rel(co);
		cm = next;
	}

	/* Clean up jail members (no locks held) */
	for (cm = jail_list; cm != NULL; ) {
		struct coalition_member *next =
		    (struct coalition_member *)cm->cm_link.tqe_next;
		struct jaildesc *jd;
		struct prison *pr;
		struct coalition_jail_osd *cjo;

		if (cm->cm_fp != NULL && cm->cm_fp->f_data != NULL) {
			jd = cm->cm_fp->f_data;
			JAILDESC_LOCK(jd);
			pr = jd->jd_prison;
			if (pr != NULL && prison_isvalid(pr)) {
				prison_hold(pr);
				JAILDESC_UNLOCK(jd);
				prison_lock(pr);
				cjo = osd_jail_get(pr,
				    coalition_jail_osd_slot);
				if (cjo != NULL)
					cjo->cjo_member = NULL;
				prison_unlock(pr);
				prison_free(pr);
			} else {
				JAILDESC_UNLOCK(jd);
			}
		}

			if (cm->cm_fp != NULL)
				(void)coalition_jail_terminate(cm->cm_fp);

			if (cm->cm_data != NULL) {
				pr = cm->cm_data;
				cm->cm_data = NULL;
				atomic_subtract_int(&coalition_held_jails, 1);
				prison_free(pr);
			}

			atomic_subtract_int(&co->co_member_count, 1);
			atomic_subtract_int(&coalition_total_members, 1);

		if (cm->cm_fp != NULL)
			fdrop(cm->cm_fp, td);

		uma_zfree_smr(coalition_member_zone, cm);
		coalition_rel(co);
		cm = next;
	}

	coalition_rel(co);
}

/* ----------------------------------------------------------------
 * Re-homing an inherited membership
 * ---------------------------------------------------------------- */

/*
 * Detach p from a coalition it belongs to only by inheritance (fork, pdfork
 * or JOIN: no held file).  Mirrors the exit path: unhash under the hash
 * lock, then re-find the member under the old coalition's lock.  A moved
 * leader stops being the leader; it does not terminate the old coalition,
 * because the process is alive and merely changing hands.  No-op when p is
 * in no coalition or its membership is an explicit procdesc enlist.
 */
static void
coalition_rehome_inherited(struct proc *p)
{
	struct coalition_member *cm;
	struct coalition *old;

	mtx_lock(&coalition_proc_hash_mtx);
	cm = coalition_proc_hash_lookup(p);
	if (cm == NULL || cm->cm_fp != NULL) {
		mtx_unlock(&coalition_proc_hash_mtx);
		return;
	}
	old = cm->cm_coalition;
	coalition_ref(old);
	CK_LIST_REMOVE(cm, cm_hash);
	cm->cm_hash.cle_prev = NULL;
	mtx_unlock(&coalition_proc_hash_mtx);

	cm = NULL;
	sx_xlock(&old->co_sx);
	TAILQ_FOREACH(cm, &old->co_members, cm_link) {
		if (cm->cm_data == p && cm->cm_fp == NULL)
			break;
	}
	if (cm != NULL) {
		TAILQ_REMOVE(&old->co_members, cm, cm_link);
		cm->cm_link.tqe_prev = NULL;
		if ((old->co_flags & COF_HAS_LEADER) != 0 &&
		    old->co_leader == cm) {
			old->co_leader = NULL;
			old->co_flags &= ~COF_HAS_LEADER;
		}
		atomic_subtract_int(&old->co_member_count, 1);
		atomic_subtract_int(&coalition_total_members, 1);
		coalition_notify_event(old, COALITION_NOTE_MEMBER_REMOVED);
	}
	sx_xunlock(&old->co_sx);
	if (cm != NULL) {
		SDT_PROBE3(mac_capability_coalition, , , rehome, p->p_pid,
		    old->co_id, (uint64_t)0);
		uma_zfree_smr(coalition_member_zone, cm);
		coalition_rel(old);	/* the member's reference */
	}
	coalition_rel(old);
}

/* ----------------------------------------------------------------
 * Resource ledger
 * ---------------------------------------------------------------- */

/*
 * Sum the footprint of this coalition's process members and publish it.
 *
 * Walking members and reading each process is far too heavy for the page
 * daemon, so the walk happens here -- on a taskqueue under pressure, or in
 * a caller's own thread on request -- and the result is published with
 * atomics for a policy pass to read cheaply.  Nested coalitions are not
 * summed: each is ranked on its own footprint, which is what a kill walk
 * wants, since terminating a parent takes its children with it anyway.
 *
 * Caller holds co_sx (shared is enough; the published values are atomics).
 */
/* ----------------------------------------------------------------
 * Bands
 * ---------------------------------------------------------------- */

/*
 * The effective band: the highest band with a live assertion, or the floor if
 * there are none.  Lock-free and non-sleeping by construction -- a memory
 * pressure pass ranks every coalition through this function, from a context
 * where it can take nothing.
 */
static u_int
coalition_band_effective(struct coalition *co)
{
	int b;

	for (b = COALITION_BAND_COUNT - 1; b > 0; b--) {
		if (atomic_load_int(&co->co_band_assert[b]) != 0)
			break;
	}
	return (MAX((u_int)b, atomic_load_int(&co->co_band_floor)));
}

static void
coalition_band_fill_reply(struct coalition *co, struct coalition_band_reply *br,
    u_int asserted)
{
	int b;

	memset(br, 0, sizeof(*br));
	br->id = co->co_id;
	br->floor = atomic_load_int(&co->co_band_floor);
	br->effective = coalition_band_effective(co);
	br->asserted = asserted;
	for (b = 0; b < COALITION_BAND_COUNT; b++)
		br->nassert[b] = atomic_load_int(&co->co_band_assert[b]);
}

/*
 * Recompute whether the coalition counts as idle, and when it started being so.
 *
 * Idle here means two things and only two: somebody declared this work able to
 * come back, and nothing holds an assertion on it.  Taking an assertion resets
 * the clock, so work that is used again is not put away for having been quiet
 * before.  Lock-free: this runs from the assertion paths, which are themselves
 * lock-free.
 */
static void
coalition_idle_update(struct coalition *co)
{
	bool idle;

	idle = (atomic_load_int(&co->co_idle_flags) &
	    COALITION_IDLE_EXIT_ENABLE) != 0 &&
	    atomic_load_int(&co->co_band_nassert) == 0;
	if (!idle)
		atomic_store_64((volatile uint64_t *)&co->co_idle_since, 0);
	else if (atomic_load_64((volatile uint64_t *)&co->co_idle_since) == 0)
		atomic_store_64((volatile uint64_t *)&co->co_idle_since,
		    (uint64_t)getsbinuptime());
}

/*
 * Has this coalition been idle long enough to be put away?
 */
static bool
coalition_idle_expired(struct coalition *co, sbintime_t now)
{
	sbintime_t since;
	u_int age;

	if (coalition_idle_exit == 0)
		return (false);
	if ((atomic_load_int(&co->co_idle_flags) &
	    COALITION_IDLE_EXIT_ENABLE) == 0)
		return (false);
	if (atomic_load_int(&co->co_band_nassert) != 0)
		return (false);
	since = (sbintime_t)atomic_load_64(
	    (volatile uint64_t *)&co->co_idle_since);
	if (since == 0)
		return (false);
	age = atomic_load_int(&co->co_idle_min_age_ms);
	if (age == 0)
		age = coalition_idle_min_age_ms;
	return (now - since >= (sbintime_t)age * SBT_1MS);
}

/*
 * An assertion: a descriptor that holds a coalition at a band for as long as
 * it is open.  It pins the coalition structure but holds no authority over it.
 */
struct coalition_assert {
	struct coalition	*ca_co;
	u_int			ca_band;
	pid_t			ca_pid;		/* who took it */
	sbintime_t		ca_time;	/* when */
	LIST_ENTRY(coalition_assert)	ca_link;
};

static struct mac_capability_service *coalition_assert_svc;

static void
coalition_assert_drop(struct coalition_assert *ca)
{
	struct coalition *co = ca->ca_co;
	u_int eff;

	mtx_lock(&co->co_assert_mtx);
	LIST_REMOVE(ca, ca_link);
	mtx_unlock(&co->co_assert_mtx);
	atomic_subtract_int(&co->co_band_assert[ca->ca_band], 1);
	atomic_subtract_int(&co->co_band_nassert, 1);
	coalition_idle_update(co);
	eff = coalition_band_effective(co);
	SDT_PROBE4(mac_capability_coalition, , , band__release, co->co_id,
	    ca->ca_band, eff, curthread->td_proc->p_pid);
	free(ca, M_COALITION);
	coalition_rel(co);
}

/*
 * Mint an assertion on co at band.  On success the caller's reply carries the
 * new descriptor; the count is raised before the descriptor exists so the band
 * can never dip between the two.
 */
static int
coalition_band_assert(struct coalition *co, u_int band, struct file **fpp)
{
	struct coalition_assert *ca;
	struct file *fp;
	u_int max;
	int error;

	if (band >= COALITION_BAND_COUNT)
		return (EINVAL);

	/*
	 * Soft limit, like the coalition and member caps above: concurrent
	 * requests can overshoot by the number of racing threads, which is
	 * acceptable for resource control and avoids a global lock on a path
	 * that is otherwise lock-free.
	 */
	max = coalition_max_assertions;
	if (max != 0 && atomic_load_int(&co->co_band_nassert) >= max)
		return (EAGAIN);

	ca = malloc(sizeof(*ca), M_COALITION, M_WAITOK | M_ZERO);
	ca->ca_band = band;
	ca->ca_co = co;
	ca->ca_pid = curthread->td_proc->p_pid;
	ca->ca_time = getsbinuptime();
	coalition_ref(co);
	mtx_lock(&co->co_assert_mtx);
	LIST_INSERT_HEAD(&co->co_asserts, ca, ca_link);
	mtx_unlock(&co->co_assert_mtx);
	atomic_add_int(&co->co_band_assert[band], 1);
	atomic_add_int(&co->co_band_nassert, 1);
	coalition_idle_update(co);

	error = mac_capability_mint_fp(coalition_assert_svc, 0, &fp);
	if (error != 0) {
		coalition_assert_drop(ca);
		return (error);
	}
	mac_capability_instance_set_priv(fp->f_data, ca);
	SDT_PROBE4(mac_capability_coalition, , , band__assert, co->co_id, band,
	    coalition_band_effective(co), curthread->td_proc->p_pid);
	*fpp = fp;
	return (0);
}

/*
 * An assertion is not connectable: the only way to get one is to hold the
 * coalition it applies to and ask for it.
 */
static int
coalition_assert_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badgep __unused)
{

	return (EPERM);
}

static void
coalition_assert_revoke(struct mac_capability_instance *s,
    uint64_t badge __unused, enum mac_capability_revoke_reason reason __unused,
    void *arg __unused)
{
	struct coalition_assert *ca;

	ca = mac_capability_instance_get_priv(s);
	if (ca == NULL)
		return;
	mac_capability_instance_set_priv(s, NULL);
	coalition_assert_drop(ca);
}

/*
 * The only operation an assertion answers: what it asserts, and what the
 * coalition's band is now.  Deliberately no way back to the coalition's
 * membership or controls.
 */
static int
coalition_assert_call(struct mac_capability_instance *s,
    const void *req, size_t reqlen,
    struct file **fds __unused, struct filecaps *fcaps __unused,
    int nfds __unused, void *reply, size_t *replylenp,
    struct file **reply_fds __unused, int *reply_nfdsp __unused,
    void *arg __unused)
{
	const struct coalition_req_hdr *hdr;
	struct coalition_assert *ca;
	struct coalition_band_reply *br;

	ca = mac_capability_instance_get_priv(s);
	if (ca == NULL)
		return (EBADF);
	if (reqlen < sizeof(*hdr))
		return (EINVAL);
	hdr = req;
	if (hdr->op != COALITION_OP_BAND)
		return (EOPNOTSUPP);
	/*
	 * Read-only.  An assertion must refuse a request to change the band
	 * rather than quietly answer as though it had done nothing: a caller
	 * that asks an assertion to set a floor has the wrong descriptor, and
	 * silently succeeding would hide that.
	 */
	if (reqlen >= sizeof(struct coalition_band_req)) {
		const struct coalition_band_req *bq = req;

		if (bq->flags != 0)
			return (EPERM);
	}
	if (*replylenp < sizeof(*br)) {
		*replylenp = sizeof(*br);
		return (EMSGSIZE);
	}
	br = reply;
	*replylenp = sizeof(*br);
	coalition_band_fill_reply(ca->ca_co, br, ca->ca_band);
	return (0);
}

static const struct mac_capability_ops coalition_assert_ops = {
	.co_connect	= coalition_assert_connect,
	.co_call	= coalition_assert_call,
	.co_revoke	= coalition_assert_revoke,
};

static void
coalition_sample_locked(struct coalition *co)
{
	struct coalition_member *cm;
	struct proc *p;
	struct vmspace *vm;
	uint64_t rss = 0;
	u_int nprocs = 0;

	sx_assert(&co->co_sx, SA_LOCKED);

	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		if (cm->cm_dtype != DTYPE_PROCDESC)
			continue;
		p = NULL;
		if (cm->cm_fp != NULL) {
			struct procdesc *pd = cm->cm_fp->f_data;

			sx_slock(&proctree_lock);
			p = pd->pd_proc;
			if (p != NULL)
				PROC_LOCK(p);
			sx_sunlock(&proctree_lock);
		} else if (cm->cm_data != NULL) {
			p = (struct proc *)atomic_load_acq_ptr(
			    (uintptr_t *)&cm->cm_data);
			if (p != NULL)
				PROC_LOCK(p);
		}
		if (p == NULL)
			continue;
		if (p->p_state == PRS_ZOMBIE || (p->p_flag & P_WEXIT) != 0) {
			PROC_UNLOCK(p);
			continue;
		}
		/*
		 * Read the footprint straight off the address space rather
		 * than through fill_kinfo_proc(), which needs proctree_lock
		 * for the session and process-group walk and fills in a great
		 * deal we do not want.  Four numbers is all a ranking needs,
		 * and taking only the vmspace reference keeps this usable from
		 * a pressure pass that must not wait on the process tree.
		 */
		vm = vmspace_acquire_ref(p);
		PROC_UNLOCK(p);
		if (vm == NULL)
			continue;
		rss += (uint64_t)vmspace_resident_count(vm) * PAGE_SIZE;
		vmspace_free(vm);
		nprocs++;
	}

	atomic_store_64(&co->co_rss_bytes, rss);
	SDT_PROBE3(mac_capability_coalition, , , ledger__sample, co->co_id,
	    rss, nprocs);
}

/*
 * Act on a coalition's declared ceilings, if it has any.  Called with co_sx
 * held EXCLUSIVE: a breach notifies, and delivering a notification requires
 * the exclusive lock.  Every figure it judges comes from the container, so it
 * walks nothing and costs the same whatever a coalition's size.
 *
 * Returns true if the coalition should be terminated for the breach.  The
 * caller does the terminating, because that needs co_sx exclusive and this is
 * reached from paths that hold it shared.
 *
 * A coalition that comes back under the ceiling is rearmed, so a unit that
 * drifts over and recovers is told once per excursion rather than once per
 * sample.
 */
/*
 * The accounting framework's name for a resource.  rctl already keeps the
 * table an operator sees in rctl(8) rules; using it means one set of names on
 * the machine rather than a second set that can drift from the first.
 */
static const char *
coalition_resource_name(int resource)
{

#ifdef RCTL
	return (rctl_resource_name(resource));
#else
	return ("resource");
#endif
}

static int
coalition_limit_check_locked(struct coalition *co)
{
	uint64_t limit = 0, used = 0;
	u_int flags;
	int i, breached = -1;

	sx_assert(&co->co_sx, SA_XLOCKED);

	/*
	 * Every ceiling is judged the same way: read the counter the
	 * accounting framework keeps for this container and compare.  Nothing
	 * here measures anything, walks anything, or knows what a resource
	 * means -- address space is charged at the mapping path, resident
	 * memory is refreshed by the page daemon's pass, and RACCT_PCTCPU is a
	 * decaying rate the framework maintains and clamps to the number of
	 * processors.  CPU spent by members that have since left is still in
	 * there, because CPU is neither reclaimable nor decaying and so is
	 * never taken back out of a container.
	 *
	 * The first breach in resource order is the one reported: a reason has
	 * to be a single answer, and a coalition over two ceilings at once is
	 * over budget either way.
	 */
	for (i = 0; i <= RACCT_MAX; i++) {
		limit = atomic_load_64(&co->co_limits[i]);
		if (limit == 0)
			continue;
		used = racct_read(co->co_racct, i);
		if (used > limit) {
			breached = i;
			break;
		}
	}
	if (breached < 0) {
		atomic_store_int(&co->co_limit_breached, 0);
		return (COALITION_KILL_NONE);
	}
	flags = atomic_load_int(&co->co_limit_flags);
	if (atomic_load_int(&co->co_limit_breached) == 0) {
		/*
		 * Reported in the units the framework keeps the resource in,
		 * with the framework's own name for it rather than a second
		 * table of names kept here.
		 */
		bool millions = RACCT_IS_IN_MILLIONS(breached);

		atomic_store_int(&co->co_limit_breached, 1);
		SDT_PROBE6(mac_capability_coalition, , , limit__breach,
		    co->co_id, co->co_responsible_id, used, limit,
		    (flags & COALITION_LIMIT_KILL) != 0 ? 1 : 0,
		    breached == RACCT_PCTCPU ? COALITION_LIMIT_KIND_CPU :
		    COALITION_LIMIT_KIND_BYTES);
		coalition_notify_event(co, COALITION_NOTE_LIMIT);
		log(LOG_WARNING, "mac_capability_coalition: coalition %ju "
		    "(responsible %ju) is over its %s ceiling: %ju of %ju%s\n",
		    (uintmax_t)co->co_id, (uintmax_t)co->co_responsible_id,
		    coalition_resource_name(breached),
		    (uintmax_t)(millions ? used / 1000000 : used),
		    (uintmax_t)(millions ? limit / 1000000 : limit),
		    (flags & COALITION_LIMIT_KILL) != 0 ?
		    "; terminating it" : "");
	}
	if ((flags & COALITION_LIMIT_KILL) == 0)
		return (COALITION_KILL_NONE);
	return (breached == RACCT_PCTCPU ? COALITION_KILL_OVER_CPU :
	    COALITION_KILL_OVER_CEILING);
}

/* ----------------------------------------------------------------
 * Memory pressure
 * ---------------------------------------------------------------- */

/*
 * Tell every coalition that the system is short of memory, so a unit can
 * drop caches before the kernel starts killing.  Runs on a taskqueue, not
 * in the page daemon: notification takes co_sx and may sleep, and the page
 * daemon must not wait on a service's queue.
 *
 * A coalition that is terminating, closing, or has no live instance is
 * skipped.  Delivery is best effort by construction: mac_capability_notify()
 * drops the message if the instance's queue is full, which is the right
 * answer under memory pressure.
 */
/* ----------------------------------------------------------------
 * Handing a coalition down under memory pressure
 * ---------------------------------------------------------------- */

#define	COALITION_PRESS_MAX	8

struct coalition_press_target {
	struct coalition	*pt_co;		/* reference held */
	u_int			pt_band;
	uint64_t		pt_rss;
};

/*
 * Advise every process member's address space reclaimable.  MADV_DONTNEED
 * keeps dirty data -- the page is dirtied first if the pmap says it was
 * modified -- and only clears references and moves pages to the front of the
 * inactive queue, so the pager takes memory from here before anywhere else.
 * The coalition keeps running throughout and faults back whatever it still
 * needs.
 *
 * Caller holds a reference on co.  Takes co_sx shared; the map advice sleeps,
 * which is why the pressure pass has a thread of its own.
 */
static u_int
coalition_press_down(struct coalition *co)
{
	struct coalition_member *cm;
	struct proc *p;
	struct vmspace *vm;
	vm_map_t map;
	u_int pressed = 0;

	sx_slock(&co->co_sx);
	if ((co->co_flags & (COF_TERMINATING | COF_CLOSING)) != 0) {
		sx_sunlock(&co->co_sx);
		return (0);
	}
	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		if (cm->cm_dtype != DTYPE_PROCDESC)
			continue;
		p = NULL;
		if (cm->cm_fp != NULL) {
			struct procdesc *pd = cm->cm_fp->f_data;

			if (pd == NULL)
				continue;
			sx_slock(&proctree_lock);
			p = pd->pd_proc;
			if (p != NULL)
				PROC_LOCK(p);
			sx_sunlock(&proctree_lock);
		} else if (cm->cm_data != NULL) {
			p = (struct proc *)atomic_load_acq_ptr(
			    (uintptr_t *)&cm->cm_data);
			if (p != NULL)
				PROC_LOCK(p);
		}
		if (p == NULL)
			continue;
		if (p->p_state == PRS_ZOMBIE || (p->p_flag & P_WEXIT) != 0) {
			PROC_UNLOCK(p);
			continue;
		}
		vm = vmspace_acquire_ref(p);
		PROC_UNLOCK(p);
		if (vm == NULL)
			continue;
		map = &vm->vm_map;
		if (vm_map_madvise(map, vm_map_min(map), vm_map_max(map),
		    MADV_DONTNEED) == 0)
			pressed++;
		vmspace_free(vm);
	}
	sx_sunlock(&co->co_sx);
	return (pressed);
}

/*
 * Is this coalition one the system should hand down, and is it due?  Called
 * with only atomic loads, so it costs nothing to ask about every coalition.
 */
static bool
coalition_press_eligible(struct coalition *co, sbintime_t now, u_int *bandp,
    uint64_t *rssp)
{
	sbintime_t last;
	uint64_t rss;
	u_int band, interval;

	if (coalition_pressure_reclaim == 0)
		return (false);
	band = coalition_band_effective(co);
	if (band > coalition_pressure_band_ceiling)
		return (false);
	rss = atomic_load_64(&co->co_rss_bytes);
	if (rss < (uint64_t)coalition_pressure_min_kb * 1024)
		return (false);
	interval = coalition_pressure_interval_ms;
	last = (sbintime_t)atomic_load_64(
	    (volatile uint64_t *)&co->co_press_time);
	if (last != 0 && interval != 0 &&
	    now - last < (sbintime_t)interval * SBT_1MS)
		return (false);
	*bandp = band;
	*rssp = rss;
	return (true);
}

/*
 * Keep the best candidates seen so far: lowest band first, and within a band
 * the largest footprint, since that is where handing down frees the most for
 * the least disruption.  The array owns a reference on everything it holds.
 */
static void
coalition_press_offer(struct coalition_press_target *t, u_int max, u_int *nt,
    struct coalition *co, u_int band, uint64_t rss)
{
	u_int i, worst;

	if (max > COALITION_PRESS_MAX)
		max = COALITION_PRESS_MAX;
	if (max == 0)
		return;
	if (*nt < max) {
		coalition_ref(co);
		t[*nt].pt_co = co;
		t[*nt].pt_band = band;
		t[*nt].pt_rss = rss;
		(*nt)++;
		return;
	}
	/* Find the least deserving entry and displace it if we are better. */
	worst = 0;
	for (i = 1; i < *nt; i++) {
		if (t[i].pt_band > t[worst].pt_band ||
		    (t[i].pt_band == t[worst].pt_band &&
		    t[i].pt_rss < t[worst].pt_rss))
			worst = i;
	}
	if (band > t[worst].pt_band ||
	    (band == t[worst].pt_band && rss <= t[worst].pt_rss))
		return;
	coalition_rel(t[worst].pt_co);
	coalition_ref(co);
	t[worst].pt_co = co;
	t[worst].pt_band = band;
	t[worst].pt_rss = rss;
}

/*
 * The out-of-memory victim policy.  Runs in the page daemon, which may sleep,
 * so the candidates are sampled for real rather than trusted from the cache:
 * at this moment the footprint is the whole basis of the decision and a stale
 * one would pick the wrong coalition.
 *
 * Returns true if a coalition was terminated.
 */
static bool
coalition_oom_policy(int shortage __unused)
{
	struct coalition_press_target cand[COALITION_PRESS_MAX];
	struct coalition *co, *victim;
	uint64_t rss, best_rss;
	u_int band, ncand = 0, i, best, members;

	if (coalition_oom_kill == 0)
		return (false);

	/* Collect eligible coalitions, lock-free, with a reference on each. */
	smr_enter(coalition_smr);
	CK_LIST_FOREACH(co, &coalition_list, co_all_link) {
		if (ncand >= nitems(cand))
			break;
		if (coalition_band_effective(co) > coalition_oom_band_ceiling)
			continue;
		if (!refcount_acquire_if_not_zero(&co->co_refcount))
			continue;
		cand[ncand].pt_co = co;
		cand[ncand].pt_band = 0;
		cand[ncand].pt_rss = 0;
		ncand++;
	}
	smr_exit(coalition_smr);

	/* Sample each for real, then choose. */
	best = ncand;
	best_rss = 0;
	for (i = 0; i < ncand; i++) {
		co = cand[i].pt_co;
		sx_slock(&co->co_sx);
		if ((co->co_flags & (COF_TERMINATING | COF_CLOSING)) == 0)
			coalition_sample_locked(co);
		sx_sunlock(&co->co_sx);
		band = coalition_band_effective(co);
		rss = atomic_load_64(&co->co_rss_bytes);
		cand[i].pt_band = band;
		cand[i].pt_rss = rss;
		if (rss == 0 || band > coalition_oom_band_ceiling)
			continue;
		if (best == ncand || band < cand[best].pt_band ||
		    (band == cand[best].pt_band && rss > best_rss)) {
			best = i;
			best_rss = rss;
		}
	}

	victim = best < ncand ? cand[best].pt_co : NULL;
	if (victim != NULL) {
		coalition_ref(victim);
		members = atomic_load_int(&victim->co_member_count);
		SDT_PROBE5(mac_capability_coalition, , , oom__kill,
		    victim->co_id, victim->co_responsible_id,
		    cand[best].pt_band, cand[best].pt_rss, members);
		/*
		 * Say this out loud.  Processes are about to disappear and the
		 * only honest thing is to leave a record of which coalition was
		 * given up, on whose behalf it was running, and why it was the
		 * one chosen.
		 */
		log(LOG_WARNING, "mac_capability_coalition: out of memory: "
		    "terminating coalition %ju (responsible %ju, band %u, "
		    "%ju KB, %u members)\n", (uintmax_t)victim->co_id,
		    (uintmax_t)victim->co_responsible_id, cand[best].pt_band,
		    (uintmax_t)(cand[best].pt_rss / 1024), members);
	} else
		SDT_PROBE1(mac_capability_coalition, , , oom__decline,
		    (uint32_t)atomic_load_int(&coalition_count));

	for (i = 0; i < ncand; i++)
		coalition_rel(cand[i].pt_co);

	if (victim == NULL)
		return (false);

	/*
	 * Terminate with SIGKILL regardless of the coalition's configured
	 * signal: the system needs the memory now, and a coalition that was
	 * set up to be released without a signal must still be reclaimable.
	 */
	sx_xlock(&victim->co_sx);
	coalition_terminate_members_locked(victim, curthread, false, SIGKILL,
	    COALITION_KILL_SYSTEM_MEMORY);
	sx_xunlock(&victim->co_sx);
	coalition_notify_responsible(victim, COALITION_KILL_SYSTEM_MEMORY);
	coalition_rel(victim);
	return (true);
}

/*
 * The periodic sweep.  Samples every coalition, acts on any that is over the
 * ceiling declared for it, and puts away any that has been idle long enough.
 *
 * Deliberately does not notify and does not hand anything down: those belong to
 * memory pressure, which is a different question.  This is about promises a
 * coalition made about itself being kept whether or not the machine is busy.
 */
/*
 * The coalition that answers for this one: its responsible parent, or itself.
 */
static struct coalition *
coalition_responsible_or_self(struct coalition *co)
{

	return (co->co_responsible != NULL ? co->co_responsible : co);
}

/*
 * Would putting this coalition away be worth doing?
 *
 * Idle exit is only a good deal if the work stays away until somebody wants it.
 * A unit the launcher restarts immediately comes straight back, so putting it
 * away costs two context switches and achieves nothing, and doing that in a
 * loop is worse than leaving it resident.  Eligibility is declared precisely so
 * that such units are not marked, but a wrong declaration should degrade rather
 * than spin, so the same work coming back repeatedly stops being taken.
 *
 * "The same work" across relaunches is the responsible party: the coalition is
 * a new object every launch, the party that caused it is not.
 */
static bool
coalition_idle_exit_worthwhile(struct coalition *co, sbintime_t now)
{
	struct coalition *owner = coalition_responsible_or_self(co);
	sbintime_t window;
	u_int max, n;

	max = coalition_idle_max_per_min;
	if (max == 0)
		return (true);
	window = (sbintime_t)atomic_load_64(
	    (volatile uint64_t *)&owner->co_idle_window);
	if (window == 0 || now - window >= 60 * SBT_1S) {
		atomic_store_64((volatile uint64_t *)&owner->co_idle_window,
		    (uint64_t)now);
		atomic_store_int(&owner->co_idle_exits, 0);
		return (true);
	}
	n = atomic_load_int(&owner->co_idle_exits);
	if (n < max)
		return (true);
	if (n == max) {
		/* Say it once, when the decision changes. */
		atomic_add_int(&owner->co_idle_exits, 1);
		log(LOG_NOTICE, "mac_capability_coalition: no longer putting "
		    "coalition %ju's work away: %u came back within a minute\n",
		    (uintmax_t)owner->co_id, n);
	}
	return (false);
}

/*
 * Tell the party responsible for a coalition that it was terminated by a
 * policy, so it can relaunch, back off, or report.  Called with no coalition
 * lock held: the lock order is parent before child, and the caller has just
 * finished with the child.
 */
static void
coalition_notify_responsible(struct coalition *co, int reason)
{
	struct coalition_event_msg ev;
	struct coalition *owner;
	uint64_t child_id = co->co_id;

	if (co->co_responsible == NULL)
		return;
	owner = co->co_responsible;
	if (!refcount_acquire_if_not_zero(&owner->co_refcount))
		return;
	sx_xlock(&owner->co_sx);
	if (owner->co_instance != NULL) {
		ev.flags = COALITION_NOTE_CHILD_KILLED;
		ev.reason = (uint32_t)reason;
		ev.subject_id = child_id;
		(void)mac_capability_notify(owner->co_instance, &ev,
		    sizeof(ev), NULL, NULL, 0);
	}
	sx_xunlock(&owner->co_sx);
	coalition_rel(owner);
}

/*
 * Put a process into, or take it out of, the coalition's resource container.
 *
 * Everything it has already accounted for moves with it, which is what the
 * framework does when a process changes uid or jail, and is the right answer
 * for the same reason: the container answers what this coalition is using, and
 * memory a process brings with it is memory the coalition is using.
 *
 * The process lock is what the framework wants here, and the caller may or may
 * not already hold it, so this takes it when needed.
 */
/*
 * Take a process out of its coalition's container.
 *
 * Leaving always gives everything back, whatever the reason.  The alternative
 * -- detaching and letting the container keep the charges -- looked cheaper and
 * was wrong: a process exits long before the accounting framework tears its
 * container down, so a coalition can be freed while an exiting member still
 * points at it, and that member's own accounting then writes to a container
 * that has gone.  Subtracting on the way out makes the container hold only what
 * its current members hold, which is an invariant that cannot race.
 *
 * "Everything" is the framework's definition of it, and that definition is
 * what makes a departed member's CPU stay behind with no help from here: CPU
 * is neither reclaimable nor decaying, so racct_sub_racct() does not touch it.
 * Keeping a second tally of departed CPU, as this once did, counted it twice.
 */
static void
coalition_racct_leave(struct proc *p, struct coalition *co)
{

	if (p == NULL || co == NULL)
		return;
	SDT_PROBE3(mac_capability_coalition, , , racct__leave, co->co_id,
	    p->p_pid, (int)racct_read(p->p_racct, RACCT_CPU));
	coalition_racct_join(p, NULL);
}

static void
coalition_racct_join(struct proc *p, struct coalition *co)
{
	bool locked;

	if (p == NULL)
		return;
	locked = PROC_LOCKED(p);
	if (!locked)
		PROC_LOCK(p);
	if (co != NULL) {
		SDT_PROBE2(mac_capability_coalition, , , racct__join,
		    co->co_id, p->p_pid);
	}
	racct_proc_join_coalition(p, co != NULL ? co->co_racct : NULL);
	if (!locked)
		PROC_UNLOCK(p);
}

static void
coalition_sweep_task_fn(void *ctx __unused, int pending __unused)
{
	struct coalition *co, *next;
	sbintime_t now = getsbinuptime();
	unsigned overlimit = 0, idled = 0;
	int reason;

	smr_enter(coalition_smr);
	CK_LIST_FOREACH(co, &coalition_list, co_all_link) {
		if (refcount_acquire_if_not_zero(&co->co_refcount))
			break;
	}
	smr_exit(coalition_smr);

	while (co != NULL) {
		reason = COALITION_KILL_NONE;
		sx_xlock(&co->co_sx);
		if ((co->co_flags & (COF_TERMINATING | COF_CLOSING)) == 0) {
			/*
			 * The sweep is the one regular cadence this module
			 * has, so it is what drives the decaying CPU rate the
			 * accounting framework keeps.  Refreshing here and
			 * reading everywhere else leaves the rate with a
			 * single owner and a single interval.
			 */
			racct_updatepcpu(co->co_racct);
			reason = coalition_limit_check_locked(co);
			if (reason == COALITION_KILL_NONE &&
			    coalition_idle_expired(co, now) &&
			    coalition_idle_exit_worthwhile(co, now))
				reason = COALITION_KILL_IDLE;
			if (reason != COALITION_KILL_NONE)
				coalition_terminate_members_locked(co,
				    curthread, false, SIGKILL, reason);
		}
		sx_xunlock(&co->co_sx);
		if (reason == COALITION_KILL_OVER_CEILING ||
		    reason == COALITION_KILL_OVER_CPU)
			overlimit++;
		else if (reason == COALITION_KILL_IDLE) {
			struct coalition *owner =
			    coalition_responsible_or_self(co);

			atomic_add_int(&owner->co_idle_exits, 1);
			idled++;
		}
		/*
		 * Told after the child's lock is dropped: the lock order is
		 * parent before child, so the parent cannot be notified while
		 * the child is still held.
		 */
		if (reason != COALITION_KILL_NONE)
			coalition_notify_responsible(co, reason);

		smr_enter(coalition_smr);
		for (next = CK_LIST_NEXT(co, co_all_link); next != NULL;
		    next = CK_LIST_NEXT(next, co_all_link)) {
			if (refcount_acquire_if_not_zero(&next->co_refcount))
				break;
		}
		smr_exit(coalition_smr);
		coalition_rel(co);
		co = next;
	}

	if (overlimit != 0 || idled != 0)
		log(LOG_INFO, "mac_capability_coalition: sweep: %u over "
		    "ceiling, %u put away idle\n", overlimit, idled);
}

static void
coalition_sweep_callout_fn(void *ctx __unused)
{
	u_int interval;

	if (coalition_sweep_enable != 0)
		taskqueue_enqueue(coalition_pressure_tq,
		    &coalition_sweep_task);
	interval = coalition_sweep_interval_ms;
	if (interval < 1000)
		interval = 1000;
	callout_reset_sbt(&coalition_sweep_callout,
	    (sbintime_t)interval * SBT_1MS, SBT_1S, coalition_sweep_callout_fn,
	    NULL, C_PREL(1));
}

static void
coalition_pressure_task_fn(void *ctx __unused, int pending __unused)
{
	struct coalition_press_target targets[COALITION_PRESS_MAX];
	struct coalition *co, *next;
	sbintime_t now = getsbinuptime();
	unsigned notified = 0, handed = 0, limited = 0;
	u_int band, ntargets = 0, i;
	uint64_t rss;
	int overreason;

	/*
	 * Enumerate lock-free.  A reference is taken on each coalition inside
	 * the SMR section and held across the sleeping work, so the successor
	 * link can be re-read afterwards even if this coalition has since
	 * been unlinked: SMR keeps the memory, the reference keeps the object.
	 * A coalition whose refcount already reached zero is skipped -- it is
	 * on its way out and has nothing to free on our behalf.
	 */
	smr_enter(coalition_smr);
	CK_LIST_FOREACH(co, &coalition_list, co_all_link) {
		if (refcount_acquire_if_not_zero(&co->co_refcount))
			break;
	}
	smr_exit(coalition_smr);

	while (co != NULL) {
		sx_xlock(&co->co_sx);
		if ((co->co_flags & (COF_TERMINATING | COF_CLOSING)) == 0) {
			/*
			 * Refresh the ranking input while we are here: this
			 * is exactly when a policy needs it, and this pass
			 * already holds the right locks in the right thread.
			 */
			coalition_sample_locked(co);
		}
		if ((co->co_flags & (COF_TERMINATING | COF_CLOSING)) == 0 &&
		    co->co_instance != NULL) {
			coalition_notify_event(co, COALITION_NOTE_PRESSURE);
			notified++;
			SDT_PROBE3(mac_capability_coalition, , ,
			    pressure__notify, co->co_id,
			    atomic_load_int(&co->co_member_count), 0);
		} else
			SDT_PROBE3(mac_capability_coalition, , ,
			    pressure__notify, co->co_id, 0U, ESHUTDOWN);
		overreason = coalition_limit_check_locked(co);
		sx_xunlock(&co->co_sx);

		/*
		 * A coalition over the ceiling declared for it is terminated
		 * here whatever its band: it is over budget, and the band only
		 * decides what to give up first among coalitions that are not.
		 */
		if (overreason != COALITION_KILL_NONE) {
			sx_xlock(&co->co_sx);
			coalition_terminate_members_locked(co, curthread,
			    false, SIGKILL, overreason);
			sx_xunlock(&co->co_sx);
			limited++;
		}

		/*
		 * The sample is fresh now, so decide whether this is one of the
		 * coalitions to hand down.  The choice is made across the whole
		 * walk rather than greedily, so a big background coalition
		 * found late still wins over a small one found early.
		 */
		if (coalition_press_eligible(co, now, &band, &rss))
			coalition_press_offer(targets,
			    coalition_pressure_max_targets, &ntargets, co,
			    band, rss);

		smr_enter(coalition_smr);
		for (next = CK_LIST_NEXT(co, co_all_link); next != NULL;
		    next = CK_LIST_NEXT(next, co_all_link)) {
			if (refcount_acquire_if_not_zero(&next->co_refcount))
				break;
		}
		smr_exit(coalition_smr);

		/*
		 * Release outside the section: the last reference frees the
		 * coalition, and a deferred free must not be issued from
		 * inside a read section of its own SMR context.
		 */
		coalition_rel(co);
		co = next;
	}

	/*
	 * Hand the chosen ones down, outside the enumeration: advising an
	 * address space takes the map lock and sleeps, and doing it here keeps
	 * that off the walk entirely.
	 */
	for (i = 0; i < ntargets; i++) {
		u_int pressed = coalition_press_down(targets[i].pt_co);

		if (pressed != 0) {
			atomic_store_64((volatile uint64_t *)
			    &targets[i].pt_co->co_press_time, (uint64_t)now);
			atomic_add_int(&coalition_pressure_reclaims, 1);
			handed++;
			SDT_PROBE4(mac_capability_coalition, , ,
			    pressure__reclaim, targets[i].pt_co->co_id,
			    targets[i].pt_band, targets[i].pt_rss, pressed);
		}
		coalition_rel(targets[i].pt_co);
	}

	SDT_PROBE2(mac_capability_coalition, , , pressure,
	    (uint32_t)atomic_load_int(&coalition_count), notified);
	if (handed != 0 || limited != 0)
		log(LOG_INFO, "mac_capability_coalition: memory pressure: "
		    "handed down %u coalition%s, terminated %u over ceiling\n",
		    handed, handed == 1 ? "" : "s", limited);
}

/*
 * The kernel's low-memory event.  Runs in the page daemon (or whoever
 * triggered the reclaim), so it does nothing but schedule the pass.
 */
static void
coalition_lowmem(void *arg __unused, int flags __unused)
{

	taskqueue_enqueue(coalition_pressure_tq, &coalition_pressure_task);
}

/* ----------------------------------------------------------------
 * Identity and responsible parent
 * ---------------------------------------------------------------- */

#define	COALITION_RESP_CHAIN_MAX	64

/*
 * Leader pid of the coalition this one is responsible to.  Unlocked read of
 * a plain int on a pinned structure: the parent may be terminated, in which
 * case COF_HAS_LEADER is clear and 0 is returned.
 */
static pid_t
coalition_responsible_leader_pid(struct coalition *co)
{
	struct coalition *parent;

	if ((co->co_flags & COF_RESPONSIBLE) == 0)
		return (0);
	parent = co->co_responsible != NULL ? co->co_responsible : co;
	if ((atomic_load_int(&parent->co_flags) & COF_HAS_LEADER) == 0)
		return (0);
	return (parent->co_leader_pid);
}

/*
 * Coalition of a process, referenced.  ESRCH if it belongs to none.
 */
static int
coalition_of_proc_ref(struct proc *p, struct coalition **cop)
{
	struct coalition_member *cm;

	smr_enter(coalition_smr);
	cm = coalition_proc_hash_lookup(p);
	if (cm == NULL || cm->cm_coalition == NULL) {
		smr_exit(coalition_smr);
		return (ESRCH);
	}
	*cop = cm->cm_coalition;
	if (!refcount_acquire_if_not_zero(&(*cop)->co_refcount)) {
		smr_exit(coalition_smr);
		return (ESRCH);
	}
	smr_exit(coalition_smr);
	return (0);
}

/*
 * Resolve the attached fd of SET_RESPONSIBLE to a referenced coalition:
 * a coalition instance fd names that coalition; a process descriptor names
 * the coalition its process is a member of.  Caller holds
 * coalition_nest_lock, which pins instance -> coalition.
 */
static int
coalition_resolve_responsible_fd(struct file *fp, struct coalition **cop)
{
	struct mac_capability_instance *ci;
	struct coalition *target;
	struct procdesc *pd;
	struct proc *p;
	int error;

	sx_assert(&coalition_nest_lock, SA_XLOCKED);

	if (coalition_is_nested(fp)) {
		ci = fp->f_data;
		target = mac_capability_instance_get_priv(ci);
		if (target == NULL)
			return (EBADF);
		coalition_ref(target);
		*cop = target;
		return (0);
	}
	if (fp->f_type == DTYPE_PROCDESC) {
		pd = fp->f_data;
		sx_slock(&proctree_lock);
		p = pd->pd_proc;
		if (p == NULL) {
			sx_sunlock(&proctree_lock);
			return (ESRCH);
		}
		error = coalition_of_proc_ref(p, cop);
		sx_sunlock(&proctree_lock);
		return (error);
	}
	return (EBADF);
}

/*
 * Make 'target' the responsible parent of 'co'.  Set once (EALREADY).
 * 'target == co' records a self-root.  Cycles are refused (ELOOP) by
 * walking the immutable edges from target upward; the walk is bounded so
 * a hostile chain cannot spin the kernel.  On success the edge holds its
 * own reference on target (nothing when self).
 */
static int
coalition_set_responsible_locked(struct coalition *co,
    struct coalition *target)
{
	struct coalition *t;
	int depth, error;

	sx_assert(&coalition_nest_lock, SA_XLOCKED);

	for (t = target, depth = 0; t != NULL; t = t->co_responsible) {
		if (t == co && t != target)
			return (ELOOP);
		if (++depth > COALITION_RESP_CHAIN_MAX)
			return (ELOOP);
	}

	sx_xlock(&co->co_sx);
	if ((co->co_flags & COF_RESPONSIBLE) != 0)
		error = EALREADY;
	else {
		if (target != co) {
			coalition_ref(target);
			co->co_responsible = target;
		}
		co->co_responsible_id = target->co_id;
		co->co_flags |= COF_RESPONSIBLE;
		error = 0;
	}
	sx_xunlock(&co->co_sx);
	return (error);
}

/*
 * Provider for mac_capability_proc_coalition(): identity of the coalition a
 * process belongs to.  May run with the process lock held, so only the
 * hash rwlock (non-sleepable) is taken.
 */
static bool
coalition_proc_info(struct proc *p, struct mac_capability_proc_coalition *out)
{
	struct coalition_member *cm;
	struct coalition *co;

	/*
	 * Lock-free.  This runs under PROC_LOCK for every process on every
	 * kinfo_proc fill and every audit event, so it takes no lock at all:
	 * the SMR section keeps the member, its coalition, and the responsible
	 * chain allocated while we copy out of them.  Everything read here is
	 * either immutable after creation or published with an atomic store,
	 * and nothing here sleeps or takes co_sx.
	 *
	 * A coalition that is being torn down concurrently may still be
	 * reported for one more sample.  That is what a snapshot means; the
	 * ids are permanent, so a stale id is never a wrong id.
	 */
	smr_enter(coalition_smr);
	cm = coalition_proc_hash_lookup(p);
	if (cm == NULL) {
		smr_exit(coalition_smr);
		return (false);
	}
	co = cm->cm_coalition;
	if (co == NULL) {
		smr_exit(coalition_smr);
		return (false);
	}
	out->id = co->co_id;
	out->responsible_id = co->co_responsible_id;
	out->leader_pid = (atomic_load_int(&co->co_flags) & COF_HAS_LEADER) != 0 ?
	    co->co_leader_pid : 0;
	out->responsible_leader_pid = coalition_responsible_leader_pid(co);
	out->band = coalition_band_effective(co);
	smr_exit(coalition_smr);
	return (true);
}

/* ----------------------------------------------------------------
 * mac_capability service callbacks
 * ---------------------------------------------------------------- */

static volatile uint64_t coalition_next_badge = 1;

static int
coalition_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{
	u_int max, cur;

	max = coalition_max;
	if (max != 0) {
		cur = atomic_load_acq_int(&coalition_count);
		if (cur >= max)
			return (ENOMEM);
	}

	return (MAC_CAPABILITY_CONNECT_BADGE(coalition_next_badge, badge_out));
}

static int
coalition_init(struct mac_capability_instance *s, void *arg __unused)
{
	struct coalition *co;

	co = coalition_alloc();
	co->co_instance = s;
	mac_capability_instance_set_priv(s, co);

	SDT_PROBE2(mac_capability_coalition, , , create,
	    co->co_id, mac_capability_instance_get_badge(s));
	return (0);
}

static int
coalition_call(struct mac_capability_instance *s,
    const void *req, size_t reqlen,
    struct file **fds, struct filecaps *fcaps, int nfds,
    void *reply, size_t *replylenp,
    struct file **reply_fds, int *reply_nfdsp,
    void *arg __unused)
{
	struct coalition *co;
	const struct coalition_req_hdr *hdr;
	struct coalition_reply *rpl;
	sbintime_t start __unused;
	uint32_t op __unused;
	int error;
	size_t reply_avail;

	start = getsbinuptime();
	op = 0;
	error = 0;
	co = mac_capability_instance_get_priv(s);
	if (co == NULL) {
		error = EBADF;
		goto out;
	}

	if (reqlen < sizeof(struct coalition_req_hdr)) {
		error = EINVAL;
		goto out;
	}
	hdr = req;
	op = hdr->op;

	/* All replies are at least coalition_reply sized */
	if (*replylenp < sizeof(struct coalition_reply)) {
		error = EMSGSIZE;
		goto out;
	}

	reply_avail = *replylenp;
	rpl = reply;
	rpl->status = 0;
	*replylenp = sizeof(struct coalition_reply);

	switch (hdr->op) {
	case COALITION_OP_ENLIST:
		if (nfds < 1) {
			rpl->status = EINVAL;
			break;
		}
		rpl->status = coalition_enlist(co, curthread, fds[0],
		    fcaps != NULL ? &fcaps[0] : NULL);
		break;

	case COALITION_OP_ENLIST_SET:
	{
		struct coalition_enlist_set_reply *esr;
		int i;

		if (reply_avail < sizeof(*esr)) {
			*replylenp = sizeof(*esr);
			error = EMSGSIZE;
			goto out;
		}
		esr = reply;
		esr->status = 0;
		esr->enlisted = 0;
		*replylenp = sizeof(*esr);

		for (i = 0; i < nfds; i++) {
			esr->status = coalition_enlist(co, curthread, fds[i],
			    fcaps != NULL ? &fcaps[i] : NULL);
			if (esr->status != 0)
				break;
			esr->enlisted++;
		}
		break;
	}

	case COALITION_OP_JOIN:
		rpl->status = coalition_join(co, curthread);
		break;

	case COALITION_OP_TERMINATE:
		rpl->status = coalition_terminate(co);
		break;

	case COALITION_OP_STAT:
	{
		struct coalition_stat_reply *sr;
		struct coalition_member *cm;
		bool full;

		/*
		 * Callers built before the identity extension offer only the
		 * original layout; serve them that.  Anything shorter is an
		 * error, as before.
		 */
		if (reply_avail < COALITION_STAT_REPLY_V1_LEN) {
			*replylenp = sizeof(*sr);
			error = EMSGSIZE;
			goto out;
		}
		full = reply_avail >= sizeof(*sr);
		sr = reply;
		*replylenp = full ? sizeof(*sr) : COALITION_STAT_REPLY_V1_LEN;

		sx_slock(&co->co_sx);
		if (full) {
			sr->id = co->co_id;
			sr->responsible_id = co->co_responsible_id;
			sr->leader_pid = (co->co_flags & COF_HAS_LEADER) != 0 ?
			    co->co_leader_pid : 0;
			sr->responsible_leader_pid =
			    coalition_responsible_leader_pid(co);
		}
		sr->status = 0;
		sr->member_count = co->co_member_count;
		sr->flags = co->co_flags;
		sr->signal = co->co_signal;
		sr->nesting_depth = co->co_nesting_depth;
		sr->nested_count = 0;
		sr->mac_capability_count = 0;
		sr->process_count = 0;
		sr->jail_count = 0;
		sr->other_count = 0;

		TAILQ_FOREACH(cm, &co->co_members, cm_link) {
			if (cm->cm_dtype == DTYPE_PROCDESC)
				sr->process_count++;
			else if (cm->cm_dtype == DTYPE_JAILDESC)
				sr->jail_count++;
			else if (cm->cm_nested_co != NULL)
				sr->nested_count++;
			else if (cm->cm_dtype == DTYPE_MAC_CAPABILITY)
				sr->mac_capability_count++;
			else
				sr->other_count++;
		}
		sx_sunlock(&co->co_sx);
		break;
	}

	case COALITION_OP_SET_SIGNAL:
	{
		const struct coalition_set_signal_req *ssr;

		if (reqlen < sizeof(*ssr)) {
			rpl->status = EINVAL;
			break;
		}
		ssr = req;
		/*
		 * Signal 0 means "release": when the coalition ends, process
		 * members are dropped from it but not signalled.  Attribution
		 * coalitions (login sessions) use this so ending the session
		 * record never kills a detached process that outlived it.
		 */
		if (ssr->signal < 0 || ssr->signal >= NSIG) {
			rpl->status = EINVAL;
			break;
		}
		sx_xlock(&co->co_sx);
		if (co->co_flags & COF_TERMINATING) {
			sx_xunlock(&co->co_sx);
			rpl->status = ESHUTDOWN;
			break;
		}
		co->co_signal = ssr->signal;
		SDT_PROBE2(mac_capability_coalition, , , signal__set,
		    ssr->signal, 0);
		sx_xunlock(&co->co_sx);
		rpl->status = 0;
		break;
	}

	case COALITION_OP_GRACEFUL:
	{
		const struct coalition_graceful_req *gr;

		if (reqlen < sizeof(*gr)) {
			rpl->status = EINVAL;
			break;
		}
		gr = req;
		rpl->status = coalition_terminate_graceful(co,
		    gr->signal, gr->timeout_ms);
		break;
	}

	case COALITION_OP_SET_DEADLINE:
	{
		const struct coalition_set_deadline_req *dr;
		bool need_drain = false;

		if (reqlen < sizeof(*dr)) {
			rpl->status = EINVAL;
			break;
		}
		dr = req;
		if (dr->timeout_ms != 0 && dr->signal != 0 &&
		    (dr->signal < 0 || dr->signal >= NSIG)) {
			rpl->status = EINVAL;
			break;
		}

		sx_xlock(&co->co_sx);
		if (co->co_flags & COF_TERMINATING) {
			sx_xunlock(&co->co_sx);
			rpl->status = ESHUTDOWN;
			break;
		}

		/* Cancel existing deadline */
		if (co->co_flags & COF_DEADLINE_ACTIVE)
			need_drain = coalition_deadline_disarm_locked(co);
		if (need_drain) {
			sx_xunlock(&co->co_sx);
			taskqueue_drain(taskqueue_thread,
			    &co->co_deadline_task);
			sx_xlock(&co->co_sx);
			if (co->co_flags & COF_TERMINATING) {
				sx_xunlock(&co->co_sx);
				rpl->status = ESHUTDOWN;
				break;
			}
		}

			if (dr->timeout_ms == 0) {
				sx_xunlock(&co->co_sx);
				rpl->status = 0;
				break;
			}

			co->co_deadline_signal = dr->signal;
			co->co_deadline_grace_ms = dr->grace_ms;
			co->co_flags |= COF_DEADLINE_ACTIVE;
			co->co_flags &= ~COF_DEADLINE_GRACE;
			coalition_ref(co);
		callout_reset(&co->co_deadline_callout,
		    coalition_timeout_ticks(dr->timeout_ms),
		    coalition_deadline_callout_fn, co);
		SDT_PROBE4(mac_capability_coalition, , , deadline__set,
		    dr->timeout_ms, dr->signal, dr->grace_ms, 0);
		sx_xunlock(&co->co_sx);
		rpl->status = 0;
		break;
	}

	case COALITION_OP_SET_WATCHDOG:
	{
		const struct coalition_set_watchdog_req *wr;
		bool need_drain = false;

		if (reqlen < sizeof(*wr)) {
			rpl->status = EINVAL;
			break;
		}
		wr = req;

		sx_xlock(&co->co_sx);
		if (co->co_flags & COF_TERMINATING) {
			sx_xunlock(&co->co_sx);
			rpl->status = ESHUTDOWN;
			break;
		}

		if (co->co_flags & COF_WATCHDOG_ACTIVE)
			need_drain = coalition_watchdog_disarm_locked(co);
		if (need_drain) {
			sx_xunlock(&co->co_sx);
			taskqueue_drain(taskqueue_thread,
			    &co->co_watchdog_task);
			sx_xlock(&co->co_sx);
			if (co->co_flags & COF_TERMINATING) {
				sx_xunlock(&co->co_sx);
				rpl->status = ESHUTDOWN;
				break;
			}
		}

		if (wr->timeout_ms == 0) {
			sx_xunlock(&co->co_sx);
			rpl->status = 0;
			break;
		}

		co->co_watchdog_timeout_ms = wr->timeout_ms;
		co->co_flags |= COF_WATCHDOG_ACTIVE;
		coalition_ref(co);
		callout_reset(&co->co_watchdog_callout,
		    coalition_timeout_ticks(wr->timeout_ms),
		    coalition_watchdog_callout_fn, co);
		SDT_PROBE2(mac_capability_coalition, , , watchdog__set,
		    wr->timeout_ms, 0);
		sx_xunlock(&co->co_sx);
		rpl->status = 0;
		break;
	}

	case COALITION_OP_HEARTBEAT:
	{
		bool need_drain = false;

		sx_xlock(&co->co_sx);
		if (co->co_flags & COF_TERMINATING) {
			sx_xunlock(&co->co_sx);
			rpl->status = ESHUTDOWN;
			break;
		}
		if (!(co->co_flags & COF_WATCHDOG_ACTIVE)) {
			sx_xunlock(&co->co_sx);
			rpl->status = EINVAL;
			break;
		}
		need_drain = coalition_watchdog_disarm_locked(co);
		if (need_drain) {
			sx_xunlock(&co->co_sx);
			taskqueue_drain(taskqueue_thread,
			    &co->co_watchdog_task);
			sx_xlock(&co->co_sx);
			if (co->co_flags & COF_TERMINATING) {
				sx_xunlock(&co->co_sx);
				rpl->status = ESHUTDOWN;
				break;
			}
		}
		co->co_flags |= COF_WATCHDOG_ACTIVE;
		coalition_ref(co);
		callout_reset(&co->co_watchdog_callout,
		    coalition_timeout_ticks(co->co_watchdog_timeout_ms),
		    coalition_watchdog_callout_fn, co);
		SDT_PROBE1(mac_capability_coalition, , , heartbeat,
		    co->co_watchdog_timeout_ms);
		sx_xunlock(&co->co_sx);
		rpl->status = 0;
			break;
	}

	case COALITION_OP_SET_LEADER:
	{
		struct coalition_member *cm;
		bool had_mac_capability_leader = false;
		bool need_drain = false;
		bool new_mac_capability_leader = false;

		sx_xlock(&co->co_sx);
		if (co->co_flags & COF_TERMINATING) {
			sx_xunlock(&co->co_sx);
			rpl->status = ESHUTDOWN;
			break;
		}

		/* Check if old leader has a monitor */
		if ((co->co_flags & COF_HAS_LEADER) &&
		    co->co_leader != NULL &&
		    co->co_leader->cm_dtype == DTYPE_MAC_CAPABILITY)
			had_mac_capability_leader = true;

		/* Clear leader if no fd passed */
		if (nfds == 0) {
			if (had_mac_capability_leader)
				(void)coalition_leader_monitor_stop_locked(co);
			co->co_leader = NULL;
			co->co_leader_pid = 0;
			co->co_flags &= ~COF_HAS_LEADER;
			sx_xunlock(&co->co_sx);
			rpl->status = 0;
			break;
		}

		/* Find the fd in member list */
		TAILQ_FOREACH(cm, &co->co_members, cm_link) {
			if (cm->cm_fp == fds[0])
				break;
		}
		if (cm == NULL) {
			/* Old monitor untouched on failure */
			sx_xunlock(&co->co_sx);
			rpl->status = ESRCH;
			break;
		}

		/* Extract leader tracking info */
		if (cm->cm_dtype == DTYPE_PROCDESC) {
			struct procdesc *pd;
			struct proc *p;

			pd = cm->cm_fp->f_data;
			sx_slock(&proctree_lock);
			p = pd->pd_proc;
			if (p == NULL) {
				sx_sunlock(&proctree_lock);
				sx_xunlock(&co->co_sx);
				rpl->status = ESRCH;
				break;
			}
			PROC_LOCK(p);
			if ((p->p_flag & P_WEXIT) != 0) {
				PROC_UNLOCK(p);
				sx_sunlock(&proctree_lock);
				sx_xunlock(&co->co_sx);
				rpl->status = ESRCH;
				break;
			}
			co->co_leader_pid = p->p_pid;
			PROC_UNLOCK(p);
			sx_sunlock(&proctree_lock);
		} else if (cm->cm_dtype == DTYPE_JAILDESC) {
			co->co_leader_pid = 0;
		} else if (cm->cm_dtype == DTYPE_MAC_CAPABILITY) {
			co->co_leader_pid = 0;
			new_mac_capability_leader = true;
		} else {
			sx_xunlock(&co->co_sx);
			rpl->status = EINVAL;
			break;
		}

		/* Validation passed — stop old monitor, set new leader */
		if (had_mac_capability_leader)
			need_drain = coalition_leader_monitor_stop_locked(co);
		if (need_drain && new_mac_capability_leader) {
			sx_xunlock(&co->co_sx);
			taskqueue_drain(taskqueue_thread,
			    &co->co_leader_task);
			sx_xlock(&co->co_sx);
			if (co->co_flags & COF_TERMINATING) {
				sx_xunlock(&co->co_sx);
				rpl->status = ESHUTDOWN;
				break;
			}
			/*
			 * The validated member may have been removed while
			 * we waited for the old monitor task to finish.
			 */
			if (cm->cm_coalition != co || cm->cm_link.tqe_prev == NULL) {
				sx_xunlock(&co->co_sx);
				rpl->status = ESRCH;
				break;
			}
		}

		co->co_leader = cm;
		co->co_flags |= COF_HAS_LEADER;

		if (new_mac_capability_leader)
			coalition_leader_monitor_start_locked(co);

		sx_xunlock(&co->co_sx);
		rpl->status = 0;
		break;
	}

	case COALITION_OP_SET_RESPONSIBLE:
	{
		const struct coalition_set_responsible_req *rr;
		struct coalition *target;
		uint32_t flags;

		if (reqlen < sizeof(*rr)) {
			rpl->status = EINVAL;
			break;
		}
		rr = req;
		flags = rr->flags;
		if (nfds > 1 || (nfds == 0 &&
		    (flags & ~(COALITION_RESP_SELF | COALITION_RESP_CALLER)) != 0)) {
			rpl->status = EINVAL;
			break;
		}
		if (nfds == 0 && (flags == 0 ||
		    (flags & (COALITION_RESP_SELF | COALITION_RESP_CALLER)) ==
		    (COALITION_RESP_SELF | COALITION_RESP_CALLER))) {
			rpl->status = EINVAL;
			break;
		}

		/*
		 * coalition_nest_lock serialises every responsible-edge
		 * mutation and pins the target's instance -> coalition link
		 * (same idiom as nested enlist), so the cycle walk below sees
		 * a stable graph.  Lock order: nest_lock -> hash_lock, and
		 * nest_lock -> co_sx, both already established.
		 */
		sx_xlock(&coalition_nest_lock);
		if (nfds == 1)
			rpl->status = coalition_resolve_responsible_fd(fds[0],
			    &target);
		else if ((flags & COALITION_RESP_CALLER) != 0)
			rpl->status = coalition_of_proc_ref(curproc, &target);
		else {
			target = co;
			coalition_ref(target);
			rpl->status = 0;
		}
		if (rpl->status != 0) {
			sx_xunlock(&coalition_nest_lock);
			SDT_PROBE3(mac_capability_coalition, , , responsible__set,
			    co->co_id, 0, rpl->status);
			break;
		}
		rpl->status = coalition_set_responsible_locked(co, target);
		sx_xunlock(&coalition_nest_lock);
		SDT_PROBE3(mac_capability_coalition, , , responsible__set,
		    co->co_id, target->co_id, rpl->status);
		/* The edge, when made, took its own reference. */
		coalition_rel(target);
		break;
	}

	case COALITION_OP_SET_LIMIT:
	{
		const struct coalition_limit_req *lq;
		uint32_t cpu_pct;

		if (reqlen < COALITION_LIMIT_REQ_V1_LEN) {
			rpl->status = EINVAL;
			break;
		}
		lq = req;
		/*
		 * Every ceiling is judged from the coalition's container, so on
		 * a kernel booted without resource accounting there is nothing
		 * to judge and nothing would ever enforce a figure set here.
		 * Say so rather than accept one and silently never act on it.
		 * kern.racct.enable is read-only after boot, so this answer
		 * cannot go stale.
		 */
		if (!racct_enable) {
			rpl->status = EOPNOTSUPP;
			break;
		}
		/* An older caller offers no CPU ceiling, which means none. */
		cpu_pct = reqlen >= sizeof(*lq) ? lq->cpu_percent : 0;
		if ((lq->flags & ~COALITION_LIMIT_KILL) != 0) {
			rpl->status = EINVAL;
			break;
		}
		/*
		 * Published with atomics, and the breach flag is rearmed, so a
		 * ceiling raised above the current footprint takes effect at
		 * once rather than leaving the coalition marked over.
		 */
		atomic_store_int(&co->co_limit_flags, lq->flags);
		/*
		 * The three figures the wire carries today, placed in the
		 * framework's own resource slots.  A CPU percentage becomes
		 * RACCT_PCTCPU, which is kept in millionths like every other
		 * IN_MILLIONS resource.
		 */
		atomic_store_64(&co->co_limits[RACCT_RSS], lq->memory_bytes);
		atomic_store_64(&co->co_limits[RACCT_VMEM], lq->vmem_bytes);
		atomic_store_64(&co->co_limits[RACCT_PCTCPU],
		    (uint64_t)cpu_pct * 1000000);
		atomic_store_int(&co->co_limit_breached, 0);
		break;
	}

	case COALITION_OP_ASSERTIONS:
	{
		struct coalition_assertions_reply *ar;
		struct coalition_assert *ca;
		sbintime_t now = getsbinuptime();
		size_t room;
		u_int n = 0;

		if (reply_avail < sizeof(*ar)) {
			*replylenp = sizeof(*ar);
			error = EMSGSIZE;
			goto out;
		}
		ar = reply;
		memset(ar, 0, sizeof(*ar));
		room = (reply_avail - sizeof(*ar)) / sizeof(ar->held[0]);
		mtx_lock(&co->co_assert_mtx);
		LIST_FOREACH(ca, &co->co_asserts, ca_link) {
			ar->live++;
			if (n >= room)
				continue;
			ar->held[n].band = ca->ca_band;
			ar->held[n].pid = ca->ca_pid;
			ar->held[n].age_ms = now > ca->ca_time ?
			    (uint64_t)((now - ca->ca_time) / SBT_1MS) : 0;
			n++;
		}
		mtx_unlock(&co->co_assert_mtx);
		ar->returned = n;
		/*
		 * live is the true count whether or not they all fitted, so a
		 * caller with a small buffer still learns that it is being
		 * shown only part of the answer.
		 */
		*replylenp = sizeof(*ar) + n * sizeof(ar->held[0]);
		break;
	}

	case COALITION_OP_SET_IDLE_EXIT:
	{
		const struct coalition_idle_req *iq;

		if (reqlen < sizeof(*iq)) {
			rpl->status = EINVAL;
			break;
		}
		iq = req;
		if ((iq->flags & ~COALITION_IDLE_EXIT_ENABLE) != 0) {
			rpl->status = EINVAL;
			break;
		}
		atomic_store_int(&co->co_idle_min_age_ms, iq->min_age_ms);
		atomic_store_int(&co->co_idle_flags, iq->flags);
		/* Start or stop the clock to match what was just declared. */
		coalition_idle_update(co);
		break;
	}

	case COALITION_OP_BAND:
	{
		const struct coalition_band_req *bq;
		struct coalition_band_reply *br;

		if (reqlen < sizeof(*bq)) {
			rpl->status = EINVAL;
			break;
		}
		bq = req;
		if ((bq->flags & ~COALITION_BAND_SET_FLOOR) != 0) {
			rpl->status = EINVAL;
			break;
		}
		if (reply_avail < sizeof(*br)) {
			*replylenp = sizeof(*br);
			error = EMSGSIZE;
			goto out;
		}
		if ((bq->flags & COALITION_BAND_SET_FLOOR) != 0) {
			if (bq->floor >= COALITION_BAND_COUNT) {
				rpl->status = EINVAL;
				break;
			}
			atomic_store_int(&co->co_band_floor, bq->floor);
			SDT_PROBE3(mac_capability_coalition, , , band__floor,
			    co->co_id, bq->floor,
			    coalition_band_effective(co));
		}
		br = reply;
		*replylenp = sizeof(*br);
		coalition_band_fill_reply(co, br,
		    atomic_load_int(&co->co_band_floor));
		break;
	}

	case COALITION_OP_ASSERT:
	{
		const struct coalition_band_req *bq;
		struct coalition_band_reply *br;
		struct file *afp;

		if (reqlen < sizeof(*bq)) {
			rpl->status = EINVAL;
			break;
		}
		bq = req;
		if (bq->flags != 0 || bq->band >= COALITION_BAND_COUNT) {
			rpl->status = EINVAL;
			break;
		}
		if (reply_avail < sizeof(*br)) {
			*replylenp = sizeof(*br);
			error = EMSGSIZE;
			goto out;
		}
		if (reply_nfdsp == NULL || *reply_nfdsp < 1) {
			rpl->status = EINVAL;
			break;
		}
		rpl->status = coalition_band_assert(co, bq->band, &afp);
		if (rpl->status != 0)
			break;
		br = reply;
		*replylenp = sizeof(*br);
		coalition_band_fill_reply(co, br, bq->band);
		reply_fds[0] = afp;
		*reply_nfdsp = 1;
		break;
	}

	case COALITION_OP_LEDGER:
	{
		struct coalition_ledger_reply *lr;
		const struct coalition_ledger_req *lq;

		if (reqlen < sizeof(*lq)) {
			rpl->status = EINVAL;
			break;
		}
		lq = req;
		if ((lq->flags & ~COALITION_LEDGER_REFRESH) != 0) {
			rpl->status = EINVAL;
			break;
		}
		if (reply_avail < sizeof(*lr)) {
			*replylenp = sizeof(*lr);
			error = EMSGSIZE;
			goto out;
		}
		lr = reply;
		*replylenp = sizeof(*lr);
		memset(lr, 0, sizeof(*lr));

		if ((lq->flags & COALITION_LEDGER_REFRESH) != 0) {
			int over;

			/*
			 * Nothing to refresh any more -- the figures are
			 * maintained by the accounting framework -- so what
			 * this asks for now is that the ceilings be judged at
			 * once rather than at the next sweep.  Exclusive, not
			 * shared: a breach notifies, and that needs the
			 * exclusive lock.
			 */
			sx_xlock(&co->co_sx);
			over = coalition_limit_check_locked(co);
			sx_xunlock(&co->co_sx);
			if (over != COALITION_KILL_NONE) {
				sx_xlock(&co->co_sx);
				coalition_terminate_members_locked(co,
				    curthread, false, SIGKILL, over);
				sx_xunlock(&co->co_sx);
				/*
				 * Same event, same reason, so the party
				 * responsible hears about it whichever code
				 * noticed the breach.  Told after the lock is
				 * dropped: the order is parent before child.
				 */
				coalition_notify_responsible(co, over);
			}
		}
		/*
		 * Every figure comes from the container.  There is no walk of
		 * the member list and nothing to go stale, so age_ms is zero:
		 * the field is kept because it is part of the reply, and zero
		 * is the truthful answer for a figure that is maintained
		 * rather than sampled.
		 */
		lr->id = co->co_id;
		lr->rss_bytes = racct_read(co->co_racct, RACCT_RSS);
		lr->vsz_bytes = racct_read(co->co_racct, RACCT_VMEM);
		lr->nprocs = (uint32_t)racct_read(co->co_racct, RACCT_NPROC);
		lr->nthreads = (uint32_t)racct_read(co->co_racct, RACCT_NTHR);
		lr->age_ms = 0;
		break;
	}

	case COALITION_OP_RUSAGE:
	{
		struct coalition_rusage_reply *rr;
		struct coalition_member *cm;
		struct proc *p;
		struct kinfo_proc kp;

		if (reply_avail < sizeof(*rr)) {
			*replylenp = sizeof(*rr);
			return (EMSGSIZE);
		}
		rr = reply;
		*replylenp = sizeof(*rr);
		memset(rr, 0, sizeof(*rr));

		sx_slock(&co->co_sx);
		TAILQ_FOREACH(cm, &co->co_members, cm_link) {
			if (cm->cm_dtype != DTYPE_PROCDESC)
				continue;

			p = NULL;
			if (cm->cm_fp != NULL) {
				struct procdesc *pd = cm->cm_fp->f_data;

				if (pd != NULL) {
					sx_slock(&proctree_lock);
					p = pd->pd_proc;
					if (p != NULL)
						PROC_LOCK(p);
					if (p == NULL) {
						sx_sunlock(&proctree_lock);
					}
				}
			} else if (cm->cm_data != NULL) {
				sx_slock(&proctree_lock);
				p = (struct proc *)atomic_load_acq_ptr(
				    (uintptr_t *)&cm->cm_data);
				if (p != NULL)
					PROC_LOCK(p);
				if (p == NULL)
					sx_sunlock(&proctree_lock);
			}
			if (p == NULL)
				continue;

			if (p->p_state == PRS_ZOMBIE ||
			    (p->p_flag & P_WEXIT)) {
				PROC_UNLOCK(p);
				sx_sunlock(&proctree_lock);
				continue;
			}
			fill_kinfo_proc(p, &kp);
			PROC_UNLOCK(p);
			sx_sunlock(&proctree_lock);

			rr->nprocs++;
			rr->nthreads += kp.ki_numthreads;
			rr->rss_bytes +=
			    (uint64_t)kp.ki_rssize * PAGE_SIZE;
			rr->vsz_bytes += kp.ki_size;
			rr->user_usec +=
			    (uint64_t)kp.ki_rusage.ru_utime.tv_sec *
			    1000000 + kp.ki_rusage.ru_utime.tv_usec;
			rr->sys_usec +=
			    (uint64_t)kp.ki_rusage.ru_stime.tv_sec *
			    1000000 + kp.ki_rusage.ru_stime.tv_usec;
			rr->inblock += kp.ki_rusage.ru_inblock;
			rr->oublock += kp.ki_rusage.ru_oublock;
			rr->majflt += kp.ki_rusage.ru_majflt;
			rr->minflt += kp.ki_rusage.ru_minflt;
		}
		sx_sunlock(&co->co_sx);
		break;
	}

	default:
		rpl->status = EINVAL;
		break;
	}

out:
	SDT_PROBE3(mac_capability_coalition, , , call__done, op, error,
	    getsbinuptime() - start);
	return (error);
}

static int
coalition_handler(struct mac_capability_instance *s, const struct mac_capability_msg *msg,
    void *arg)
{
	union {
		struct coalition_reply cr;
		struct coalition_enlist_set_reply cesr;
		struct coalition_stat_reply csr;
		struct coalition_rusage_reply crr;
		struct coalition_ledger_reply clr;
	} reply;
	const struct coalition_req_hdr *hdr;
	const void *req;
	size_t reqlen, replylen;
	int error;

	req = mac_capability_msg_data(msg);
	reqlen = mac_capability_msg_datalen(msg);
	memset(&reply, 0, sizeof(reply));
	replylen = sizeof(reply);

	if (reqlen < sizeof(*hdr)) {
		reply.cr.status = EINVAL;
		replylen = sizeof(reply.cr);
		goto out;
	}

	hdr = req;
	if (hdr->op == COALITION_OP_JOIN) {
		reply.cr.status = EOPNOTSUPP;
		replylen = sizeof(reply.cr);
		goto out;
	}

	error = coalition_call(s, req, reqlen, mac_capability_msg_fds(msg),
	    mac_capability_msg_fcaps(msg), mac_capability_msg_nfds(msg), &reply, &replylen,
	    NULL, NULL, arg);
	if (error != 0) {
		memset(&reply, 0, sizeof(reply.cr));
		reply.cr.status = error;
		replylen = sizeof(reply.cr);
	}

out:
	return (mac_capability_reply(s, mac_capability_msg_token(msg), &reply, replylen,
	    NULL, NULL, 0));
}

static void
coalition_revoke(struct mac_capability_instance *s, uint64_t badge __unused,
    enum mac_capability_revoke_reason reason __unused, void *arg __unused)
{
	struct coalition *co;

	/*
	 * Clear priv under nest_lock so that concurrent nested
	 * enlist reads of ci_priv are serialized against us.
	 * A nested enlist that reads ci_priv before our clear
	 * will see a valid pointer and ref the coalition before
	 * we free it.  One that reads after will see NULL.
	 */
	sx_xlock(&coalition_nest_lock);
	co = mac_capability_instance_get_priv(s);
	if (co == NULL) {
		sx_xunlock(&coalition_nest_lock);
		return;
	}
	sx_xlock(&co->co_sx);
	coalition_notify_event(co, COALITION_NOTE_TERMINATED);
	co->co_instance = NULL;
	sx_xunlock(&co->co_sx);
	mac_capability_instance_set_priv(s, NULL);
	sx_xunlock(&coalition_nest_lock);

	coalition_close_internal(co, curthread);
}

/* ----------------------------------------------------------------
 * Module init / fini
 * ---------------------------------------------------------------- */

static const struct mac_capability_ops coalition_ops = {
	.co_connect	= coalition_connect,
	.co_init	= coalition_init,
	.co_handler	= coalition_handler,
	.co_call	= coalition_call,
	.co_revoke	= coalition_revoke,
};

static int
coalition_mod_init(void)
{
	struct mac_capability_service_params p;
	int error, i;

	coalition_zone = uma_zcreate("mac_capability_coalition",
	    sizeof(struct coalition), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);
	coalition_member_zone = uma_zcreate("mac_capability_co_member",
	    sizeof(struct coalition_member), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);

	/*
	 * Both zones share one SMR context: a reader holding a member may
	 * follow cm_coalition and the responsible chain, so all of that
	 * memory has to stay valid for the same read section.
	 */
	coalition_smr = smr_create("mac_capability_coalition", 0, 0);
	uma_zone_set_smr(coalition_zone, coalition_smr);
	uma_zone_set_smr(coalition_member_zone, coalition_smr);

	mtx_init(&coalition_proc_hash_mtx, "coalition_proc_hash", NULL,
	    MTX_DEF);
	mtx_init(&coalition_list_mtx, "coalition_list", NULL, MTX_DEF);
	sx_init(&coalition_nest_lock, "coalition_nest");
	TASK_INIT(&coalition_pressure_task, 0, coalition_pressure_task_fn,
	    NULL);
	coalition_pressure_tq = taskqueue_create("coalition_pressure",
	    M_WAITOK, taskqueue_thread_enqueue, &coalition_pressure_tq);
	(void)taskqueue_start_threads(&coalition_pressure_tq, 1, PWAIT,
	    "coalition pressure");
	TASK_INIT(&coalition_sweep_task, 0, coalition_sweep_task_fn, NULL);
	callout_init(&coalition_sweep_callout, 1);
	coalition_sweep_callout_fn(NULL);
	for (i = 0; i < COALITION_PROC_HASH_SIZE; i++)
		CK_LIST_INIT(&coalition_proc_hash[i]);

	coalition_jail_osd_slot = osd_jail_register(
	    coalition_jail_osd_dtor, NULL);
	if (coalition_jail_osd_slot == 0) {
		error = ENOMEM;
		goto fail_osd;
	}

	coalition_fork_tag = EVENTHANDLER_REGISTER(process_fork,
	    coalition_process_fork, NULL, EVENTHANDLER_PRI_ANY);
	if (coalition_fork_tag == NULL) {
		error = ENOMEM;
		goto fail_fork;
	}

	coalition_exit_tag = EVENTHANDLER_REGISTER(process_exit,
	    coalition_process_exit, NULL, EVENTHANDLER_PRI_ANY);
	if (coalition_exit_tag == NULL) {
		error = ENOMEM;
		goto fail_exit;
	}

	/*
	 * Memory pressure: tell units to shrink before the kernel kills
	 * anything.  Advisory, so a registration failure is not fatal.
	 */
	coalition_lowmem_tag = EVENTHANDLER_REGISTER(vm_lowmem,
	    coalition_lowmem, NULL, EVENTHANDLER_PRI_ANY);
	if (coalition_lowmem_tag == NULL)
		log(LOG_NOTICE, "mac_capability_coalition: no low-memory "
		    "notification\n");

	memset(&p, 0, sizeof(p));
	p.name = "coalition";
	p.ops = &coalition_ops;
	p.flags = MAC_CAPABILITY_SVC_NOTIFY | MAC_CAPABILITY_SVC_MINTABLE |
	    MAC_CAPABILITY_SVC_REFATTACH;

	error = mac_capability_service_create(&p, &coalition_svc);
	if (error != 0)
		goto fail_svc;

	/*
	 * Assertions are a separate service so that an assertion descriptor
	 * is a different kind of object from a coalition descriptor and can
	 * never be mistaken for one.  Mintable, but not connectable: the only
	 * way to obtain one is to already hold the coalition.
	 */
	memset(&p, 0, sizeof(p));
	p.name = "coalition_assert";
	p.ops = &coalition_assert_ops;
	p.flags = MAC_CAPABILITY_SVC_MINTABLE;
	/*
	 * Assertions are meant to be ordinary: a client handing a provider the
	 * right to keep its work alive for the duration of a call takes one
	 * every time.  The default instance budget is sized for services with a
	 * handful of endpoints and would run out across a few dozen coalitions,
	 * so give this one room.  The per-coalition cap above is what stops a
	 * single holder from taking it all.
	 */
	p.instance_limit = 4096;
	error = mac_capability_service_create(&p, &coalition_assert_svc);
	if (error != 0) {
		mac_capability_service_destroy(coalition_svc);
		goto fail_svc;
	}

	mac_capability_proc_coalition_hook_set(coalition_proc_info);
	vm_pageout_oom_policy_set(coalition_oom_policy);
	log(LOG_INFO, "mac_capability_coalition: loaded\n");
	return (0);

fail_svc:
	EVENTHANDLER_DEREGISTER(process_exit, coalition_exit_tag);
fail_exit:
	EVENTHANDLER_DEREGISTER(process_fork, coalition_fork_tag);
fail_fork:
	osd_jail_deregister(coalition_jail_osd_slot);
fail_osd:
	if (coalition_pressure_tq != NULL) {
		taskqueue_free(coalition_pressure_tq);
		coalition_pressure_tq = NULL;
	}
	sx_destroy(&coalition_nest_lock);
	mtx_destroy(&coalition_list_mtx);
	mtx_destroy(&coalition_proc_hash_mtx);
	uma_zdestroy(coalition_member_zone);
	uma_zdestroy(coalition_zone);
	smr_destroy(coalition_smr);
	return (error);
}

static int
coalition_modevent(module_t mod __unused, int type, void *arg __unused)
{

	switch (type) {
	case MOD_LOAD:
		return (coalition_mod_init());

	case MOD_UNLOAD:
		if (atomic_load_acq_int(&coalition_count) != 0) {
			log(LOG_WARNING,
			    "mac_capability_coalition: cannot unload, "
			    "%u active coalitions\n",
			    atomic_load_acq_int(&coalition_count));
			return (EBUSY);
		}

		vm_pageout_oom_policy_set(NULL);
		mac_capability_proc_coalition_hook_set(NULL);
		if (coalition_lowmem_tag != NULL)
			EVENTHANDLER_DEREGISTER(vm_lowmem,
			    coalition_lowmem_tag);
		callout_drain(&coalition_sweep_callout);
		taskqueue_drain(coalition_pressure_tq, &coalition_sweep_task);
		taskqueue_drain(coalition_pressure_tq, &coalition_pressure_task);
		taskqueue_free(coalition_pressure_tq);
		coalition_pressure_tq = NULL;
		mac_capability_service_destroy(coalition_assert_svc);
		mac_capability_service_destroy(coalition_svc);
		EVENTHANDLER_DEREGISTER(process_exit, coalition_exit_tag);
		EVENTHANDLER_DEREGISTER(process_fork, coalition_fork_tag);
		osd_jail_deregister(coalition_jail_osd_slot);
		sx_destroy(&coalition_nest_lock);
		mtx_destroy(&coalition_proc_hash_mtx);
		mtx_destroy(&coalition_list_mtx);
		uma_zdestroy(coalition_member_zone);
		uma_zdestroy(coalition_zone);
		smr_destroy(coalition_smr);

		log(LOG_INFO, "mac_capability_coalition: unloaded\n");
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t mac_capability_coalition_mod = {
	"mac_capability_coalition",
	coalition_modevent,
	NULL,
};

DECLARE_MODULE(mac_capability_coalition, mac_capability_coalition_mod,
    SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(mac_capability_coalition, 1);
MODULE_DEPEND(mac_capability_coalition, mac_capability, 1, 1, 1);
