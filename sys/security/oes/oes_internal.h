/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * Open Endpoint Security (OES) - Kernel Internal Header
 */

#ifndef _SECURITY_OES_INTERNAL_H_
#define _SECURITY_OES_INTERNAL_H_

#ifdef _KERNEL

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/queue.h>
#include <sys/taskqueue.h>
#include <sys/selinfo.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>

#include <security/oes/oes.h>

/*
 * Forward declarations
 */
struct oes_client;
struct oes_pending;
struct oes_auth_group;
struct oes_cache_entry;

/*
 * Global state
 */
struct oes_softc {
	struct mtx		sc_mtx;		/* Protects client list */
	LIST_HEAD(, oes_client)	sc_clients;	/* All active clients */
	uint32_t		sc_nclients;	/* Number of clients */
	uint64_t		sc_next_msg_id;	/* Next message ID */
	uint64_t		sc_next_client_id; /* Next client ID */
	struct cdev		*sc_cdev;	/* Character device */
	bool			sc_active;	/* Module is active */
	uint64_t		sc_nosleep_drops; /* NOSLEEP notifies dropped */
	uint64_t		sc_alloc_failures; /* Allocation failures */

	/*
	 * Deferred NOSLEEP notify delivery.  NOSLEEP MAC hooks run with VFS
	 * locks held and cannot take the blocking client locks, so events are
	 * handed to sc_defer_task, which delivers them later with normal locks
	 * (no trylock drops).  sc_defer_mtx is a spin lock so it is safe to
	 * take from the NOSLEEP context.
	 */
	struct mtx		sc_defer_mtx;	/* SPIN: guards sc_defer */
	TAILQ_HEAD(, oes_pending) sc_defer;	/* Deferred NOSLEEP events */
	uint32_t		sc_defer_count;	/* Deferred queue depth */
	struct task		sc_defer_task;	/* Deferred delivery task */
	struct taskqueue	*sc_defer_tq;	/* Dedicated delivery thread */
};

/* Bound on the deferred queue so a burst cannot exhaust memory. */
#define	OES_DEFER_MAX		16384

extern struct oes_softc oes_softc;

#define OES_LOCK()		mtx_lock(&oes_softc.sc_mtx)
#define OES_UNLOCK()		mtx_unlock(&oes_softc.sc_mtx)
#define OES_LOCK_ASSERT()	mtx_assert(&oes_softc.sc_mtx, MA_OWNED)

struct oes_mute_path_entry;
LIST_HEAD(oes_mute_path_list, oes_mute_path_entry);

/*
 * Forward declarations for UID/GID mute lists
 */
struct oes_mute_uid_entry;
struct oes_mute_gid_entry;
LIST_HEAD(oes_mute_uid_list, oes_mute_uid_entry);
LIST_HEAD(oes_mute_gid_list, oes_mute_gid_entry);

/*
 * Process mute hash table
 */
#define OES_MUTE_PROC_BUCKETS	64

struct oes_mute_entry;
LIST_HEAD(oes_mute_bucket, oes_mute_entry);

/*
 * Decision cache entry
 */
#define OES_CACHE_BUCKETS	64

struct oes_cache_entry {
	LIST_ENTRY(oes_cache_entry) ece_link;
	TAILQ_ENTRY(oes_cache_entry) ece_lru;
	oes_cache_key_t	ece_key;
	oes_auth_result_t ece_result;
	struct timespec	ece_expires;
};

LIST_HEAD(oes_cache_bucket, oes_cache_entry);
TAILQ_HEAD(oes_cache_lru, oes_cache_entry);

/*
 * Per-client state (one per open())
 *
 * Each open() creates a new client with independent subscriptions,
 * event queue, and configuration.
 */
struct oes_client {
	LIST_ENTRY(oes_client)	ec_link;	/* Link in global list */
	struct mtx		ec_mtx;		/* Protects this client */
	uint64_t		ec_id;		/* Unique client ID */
	pid_t			ec_owner_pid;	/* Owner pid (open()) */
	uint64_t		ec_owner_genid;	/* Owner generation */
	uint64_t		ec_scope_marker;	/* Inherited descendants marker */
	uint32_t		ec_scope;	/* OES_SCOPE_* visibility */
	uint32_t		ec_mode;	/* OES_MODE_* */
	uint32_t		ec_default_deadline_ms; /* Default AUTH deadline */
	uint32_t		ec_deadline_miss_mode; /* OES_DEADLINE_MISS_* */
	uint32_t		ec_deadline_min_ms[128]; /* Per-AUTH-event floor */
	uint32_t		ec_deadline_max_ms[128]; /* Per-AUTH-event cap; 0=default */
	uint64_t		ec_subscriptions[4]; /* [0,1]=AUTH (128b), [2,3]=NOTIFY (128b) */
	uint32_t		ec_flags;	/* EC_FLAG_* */
	uint32_t		ec_mute_invert;	/* OES_MUTE_INVERT_* */

	/* Event queue */
	TAILQ_HEAD(, oes_pending) ec_pending;	/* Pending events */
	TAILQ_HEAD(, oes_pending) ec_delivered;	/* Delivered AUTH events */
	uint32_t		ec_queue_count;	/* Current queue depth */
	uint32_t		ec_queue_max;	/* Max queue size */
	uint32_t		ec_queue_bytes;	/* Current queued bytes */
	uint32_t		ec_queue_highwater; /* Peak queue depth */
	uint64_t		ec_global_seq_num; /* Includes attempted deliveries */
	uint64_t		ec_event_seq[2][128]; /* AUTH/NOTIFY by event index */
	struct selinfo		ec_selinfo;	/* For poll/select/kqueue */

	/* Process muting (hash table by pid) */
	struct oes_mute_bucket ec_muted[OES_MUTE_PROC_BUCKETS];
	struct oes_mute_path_list ec_muted_paths;	/* Muted paths */
	struct oes_mute_path_list ec_muted_targets;	/* Muted target paths */
	uint32_t		ec_muted_proc_count;	/* Muted process count */
	uint32_t		ec_muted_path_count;	/* Muted path count */
	uint32_t		ec_muted_target_count;	/* Muted target count */

	/* Decision cache */
	struct oes_cache_bucket ec_cache[OES_CACHE_BUCKETS];
	struct oes_cache_lru	ec_cache_lru;
	uint32_t		ec_cache_entries;
	uint32_t		ec_cache_max;

	/* UID/GID muting */
	struct oes_mute_uid_list ec_muted_uids;
	struct oes_mute_gid_list ec_muted_gids;
	uint32_t		ec_muted_uid_count;
	uint32_t		ec_muted_gid_count;

	/* Statistics */
	uint64_t		ec_events_received;
	uint64_t		ec_events_dropped;
	uint64_t		ec_auth_timeouts;
	uint64_t		ec_auth_allowed;
	uint64_t		ec_auth_denied;
	uint64_t		ec_cache_hits;
	uint64_t		ec_cache_misses;
	uint64_t		ec_cache_evictions;
	uint64_t		ec_cache_expired;
};

/* Client flags */
#define EC_FLAG_CLOSING		0x0001	/* Client is closing */
#define EC_FLAG_MUTED_SELF	0x0002	/* Self-muted */
#define EC_FLAG_MODE_SET	0x0004	/* Mode has been explicitly set */
#define EC_FLAG_SCOPE_SETTING	0x0008	/* Scope credential update in flight */

/* Mute inversion flags */
#define EC_MUTE_INVERT_PROCESS	0x0001	/* Process mute inversion */
#define EC_MUTE_INVERT_PATH	0x0002	/* Path mute inversion */
#define EC_MUTE_INVERT_TARGET	0x0004	/* Target path mute inversion */

#define EC_LOCK(ec)		mtx_lock(&(ec)->ec_mtx)
#define EC_UNLOCK(ec)		mtx_unlock(&(ec)->ec_mtx)
#define EC_LOCK_ASSERT(ec)	mtx_assert(&(ec)->ec_mtx, MA_OWNED)

/*
 * String table builder for variable-length message construction.
 *
 * Strings are appended after sizeof(oes_message_t) in the same
 * allocation as oes_pending.  Offsets are relative to the start
 * of oes_message_t.
 */
struct oes_strtab {
	uint32_t	st_off;		/* Next write offset (from msg start) */
	uint32_t	st_max;		/* Max message size */
};

/* Nested scope markers inherited through credential labels. */
#define OES_SCOPE_MARKERS_MAX	64

/*
 * Pending event (in client queue)
 *
 * Variable-size: the allocation extends past ep_msg to hold the
 * string table.  ep_msg.em_size records the total message size.
 * ep_msg MUST be the last field.
 */
struct oes_pending {
	TAILQ_ENTRY(oes_pending) ep_link;	/* Link in client queue */
	uint32_t		ep_flags;	/* EP_FLAG_* */
	int			ep_refcount;	/* Reference count */
	uint64_t		ep_client_id;	/* AUTH client ID */
	uint32_t		ep_deadline_miss_mode; /* OES_DEADLINE_MISS_* */

	/* For AUTH events: response handling */
	struct mtx		ep_mtx;		/* Protects response state */
	struct cv		ep_cv;		/* Wait for response */
	bool			ep_responded;	/* Response received */
	oes_auth_result_t	ep_result;	/* Response value */
	uint32_t		ep_allowed_flags; /* Flags-based: allowed flags */
	uint32_t		ep_denied_flags;  /* Flags-based: denied flags */
	bool			ep_has_flag_response; /* Explicit flags mask supplied */
	struct timespec		ep_deadline;	/* Absolute deadline */
	struct oes_auth_group	*ep_group;	/* AUTH arbitration group */
	uint64_t		ep_scope_markers[OES_SCOPE_MARKERS_MAX];
	uint8_t			ep_scope_count;	/* Valid inherited markers */

	/* Variable-length message - MUST be last */
	oes_message_t		ep_msg;
};

/* Pending event flags */
#define EP_FLAG_AUTH		0x0001	/* This is an AUTH event */
#define EP_FLAG_DELIVERED	0x0002	/* Delivered to userspace */
#define EP_FLAG_EXPIRED		0x0004	/* Deadline expired */

/*
 * Muted process entry
 *
 * If all em_events[] are 0, all events are muted.
 * Otherwise, only events with bits set in em_events are muted.
 * Layout: [0,1]=AUTH (128 bits), [2,3]=NOTIFY (128 bits)
 */
struct oes_mute_entry {
	LIST_ENTRY(oes_mute_entry) em_link;
	pid_t			em_pid;		/* Muted PID */
	uint64_t		em_genid;	/* Generation to detect reuse */
	uint64_t		em_events[4];	/* [0,1]=AUTH, [2,3]=NOTIFY */
};

/*
 * Muted path entry
 *
 * If all emp_events[] are 0, all events are muted.
 * Otherwise, only events with bits set in emp_events are muted.
 * Layout: [0,1]=AUTH (128 bits), [2,3]=NOTIFY (128 bits)
 */
struct oes_mute_path_entry {
	LIST_ENTRY(oes_mute_path_entry) emp_link;
	char			emp_path[MAXPATHLEN];
	size_t			emp_len;
	uint32_t		emp_type;	/* OES_MUTE_PATH_* */
	uint64_t		emp_events[4];	/* [0,1]=AUTH, [2,3]=NOTIFY */
	/* Token for matching when path resolution fails */
	uint64_t		emp_ino;	/* Inode number */
	uint64_t		emp_dev;	/* Device number */
	bool			emp_has_token;	/* Token is valid */
};

/*
 * Muted UID entry (dynamically allocated)
 */
struct oes_mute_uid_entry {
	LIST_ENTRY(oes_mute_uid_entry) emu_link;
	uid_t			emu_uid;
};

/*
 * Muted GID entry (dynamically allocated)
 */
struct oes_mute_gid_entry {
	LIST_ENTRY(oes_mute_gid_entry) emg_link;
	gid_t			emg_gid;
};

/*
 * Process mute hash helper
 */
static __inline uint32_t
oes_mute_proc_bucket(pid_t pid)
{

	return ((uint32_t)pid & (OES_MUTE_PROC_BUCKETS - 1));
}

/*
 * Subscription bitmap helpers
 *
 * AUTH events use ec_subscriptions[0,1], NOTIFY uses ec_subscriptions[2,3]
 * Each category has 128 bits (2 x 64-bit words).
 */
static __inline bool
oes_client_subscribed(struct oes_client *ec, oes_event_type_t event)
{
	int base = OES_EVENT_IS_NOTIFY(event) ? 2 : 0;
	int bit = event & 0x0FFF;
	int word = bit / 64;
	int shift = bit % 64;

	if (bit >= 128)
		return (false);
	return ((ec->ec_subscriptions[base + word] & (1ULL << shift)) != 0);
}

static __inline void
oes_client_subscribe(struct oes_client *ec, oes_event_type_t event)
{
	int base = OES_EVENT_IS_NOTIFY(event) ? 2 : 0;
	int bit = event & 0x0FFF;
	int word = bit / 64;
	int shift = bit % 64;

	if (bit < 128)
		ec->ec_subscriptions[base + word] |= (1ULL << shift);
}

static __inline void
oes_client_unsubscribe(struct oes_client *ec, oes_event_type_t event)
{
	int base = OES_EVENT_IS_NOTIFY(event) ? 2 : 0;
	int bit = event & 0x0FFF;
	int word = bit / 64;
	int shift = bit % 64;

	if (bit < 128)
		ec->ec_subscriptions[base + word] &= ~(1ULL << shift);
}

static __inline void
oes_client_unsubscribe_all(struct oes_client *ec)
{
	ec->ec_subscriptions[0] = 0;
	ec->ec_subscriptions[1] = 0;
	ec->ec_subscriptions[2] = 0;
	ec->ec_subscriptions[3] = 0;
}

/*
 * Validate that an event type is a defined enum value.
 * Defined in oes_event.c to avoid duplicating 100+ lines per TU.
 */
bool	oes_event_is_valid(oes_event_type_t ev);

/*
 * Valid event bitmaps.
 *
 * These define which bits correspond to real enum values.
 * Used to mask bitmap subscribe inputs, expand "mute all" correctly,
 * and validate cache keys.
 *
 * AUTH: bits 1-34 (EXEC..RELABEL), 41-42 (SWAPON, SWAPOFF)
 * NOTIFY: bits 1-4,6-9,11,13-63 (low), 64-66 (high)
 *   Gaps at bits 0, 5, 10, 12 (no NOTIFY events defined there)
 */
#define OES_VALID_AUTH_LO	OES_AUTH_EVENT_MASK_LO
#define OES_VALID_AUTH_HI	OES_AUTH_EVENT_MASK_HI
#define OES_VALID_NOTIFY_LO	OES_NOTIFY_EVENT_MASK_LO
#define OES_VALID_NOTIFY_HI	OES_NOTIFY_EVENT_MASK_HI

/*
 * Map AUTH event type to its NOTIFY counterpart.
 * Defined in oes_event.c.
 */
oes_event_type_t oes_auth_to_notify(oes_event_type_t auth_event);

/* Deferred NOSLEEP notify delivery task handler (oes_mac.c). */
void	oes_defer_task_fn(void *arg, int pending);

/*
 * Convert vnode type to EF_TYPE_*
 */
static __inline uint8_t
oes_vtype_to_eftype(int vt)
{
	switch (vt) {
	case VREG:	return (EF_TYPE_REG);
	case VDIR:	return (EF_TYPE_DIR);
	case VLNK:	return (EF_TYPE_LNK);
	case VCHR:	return (EF_TYPE_CHR);
	case VBLK:	return (EF_TYPE_BLK);
	case VFIFO:	return (EF_TYPE_FIFO);
	case VSOCK:	return (EF_TYPE_SOCK);
	default:	return (EF_TYPE_UNKNOWN);
	}
}

/*
 * Function prototypes - oes_dev.c
 */
int	oes_dev_init(void);
void	oes_dev_uninit(void);

/*
 * Function prototypes - oes_client.c
 */
struct oes_client *oes_client_alloc(void);
void	oes_client_free(struct oes_client *ec);
int	oes_client_subscribe_events(struct oes_client *ec,
	    oes_event_type_t *events, size_t count, uint32_t flags);
int	oes_client_subscribe_bitmap(struct oes_client *ec,
	    const uint64_t auth_bitmap[2], const uint64_t notify_bitmap[2],
	    uint32_t flags);
void	oes_client_get_subscriptions(struct oes_client *ec,
	    uint64_t auth_bitmap[2], uint64_t notify_bitmap[2]);
int	oes_client_set_scope(struct oes_client *ec, uint32_t scope);
void	oes_client_get_scope(struct oes_client *ec, uint32_t *scope);
bool	oes_client_observes_token(const struct oes_client *ec,
	    const oes_proc_token_t *token);
int	oes_client_set_mode(struct oes_client *ec, uint32_t mode,
	    uint32_t default_deadline_ms, uint32_t queue_size);
void	oes_client_get_mode(struct oes_client *ec, uint32_t *mode,
	    uint32_t *default_deadline_ms, uint32_t *queue_size);
int	oes_client_set_deadline_bound(struct oes_client *ec,
	    oes_event_type_t event, uint32_t milliseconds, bool minimum);
int	oes_client_get_deadline_bound(struct oes_client *ec,
	    oes_event_type_t event, uint32_t *milliseconds, bool minimum);
uint32_t oes_client_effective_deadline_locked(struct oes_client *ec,
	    oes_event_type_t event);
bool	oes_client_is_muted(struct oes_client *ec, struct proc *p,
	    oes_event_type_t event);
bool	oes_client_is_muted_by_token(struct oes_client *ec,
	    const oes_proc_token_t *token, oes_event_type_t event);
bool	oes_client_is_path_muted(struct oes_client *ec, const char *path,
	    bool target, oes_event_type_t event);
bool	oes_client_is_token_muted(struct oes_client *ec, uint64_t ino,
	    uint64_t dev, bool target, oes_event_type_t event);
int	oes_client_mute(struct oes_client *ec, oes_proc_token_t *token,
	    uint32_t flags);
int	oes_client_unmute(struct oes_client *ec, oes_proc_token_t *token);
int	oes_client_mute_path(struct oes_client *ec, const char *path,
	    uint32_t type, bool target);
int	oes_client_unmute_path(struct oes_client *ec, const char *path,
	    uint32_t type, bool target);
int	oes_client_set_mute_invert(struct oes_client *ec, uint32_t type,
	    bool invert);
int	oes_client_get_mute_invert(struct oes_client *ec, uint32_t type,
	    uint32_t *invert);
int	oes_client_set_deadline_miss_mode(struct oes_client *ec, uint32_t mode);
int	oes_client_get_deadline_miss_mode(struct oes_client *ec, uint32_t *mode);
void	oes_client_get_stats(struct oes_client *ec, struct oes_stats *stats);

/* Per-event-type muting */
int	oes_client_mute_events(struct oes_client *ec, oes_proc_token_t *token,
	    uint32_t flags, const oes_event_type_t *events, size_t count);
int	oes_client_unmute_events(struct oes_client *ec, oes_proc_token_t *token,
	    uint32_t flags, const oes_event_type_t *events, size_t count);
int	oes_client_mute_path_events(struct oes_client *ec, const char *path,
	    uint32_t type, bool target, const oes_event_type_t *events,
	    size_t count);
int	oes_client_unmute_path_events(struct oes_client *ec, const char *path,
	    uint32_t type, bool target, const oes_event_type_t *events,
	    size_t count);

/* Query muted lists */
int	oes_client_get_muted_processes(struct oes_client *ec,
	    struct oes_muted_process_entry *entries, size_t count,
	    size_t *actual);
int	oes_client_get_muted_paths(struct oes_client *ec,
	    struct oes_muted_path_entry *entries, size_t count,
	    size_t *actual, bool target);

/* Unmute all */
void	oes_client_unmute_all_processes(struct oes_client *ec);
void	oes_client_unmute_all_paths(struct oes_client *ec, bool target);

/* UID/GID muting */
int	oes_client_mute_uid(struct oes_client *ec, uid_t uid);
int	oes_client_unmute_uid(struct oes_client *ec, uid_t uid);
int	oes_client_mute_gid(struct oes_client *ec, gid_t gid);
int	oes_client_unmute_gid(struct oes_client *ec, gid_t gid);
void	oes_client_unmute_all_uids(struct oes_client *ec);
void	oes_client_unmute_all_gids(struct oes_client *ec);
bool	oes_client_is_uid_muted(struct oes_client *ec, uid_t uid);
bool	oes_client_is_gid_muted(struct oes_client *ec, gid_t gid);

/*
 * Function prototypes - oes_cache.c
 */
void	oes_cache_init(struct oes_client *ec);
void	oes_cache_destroy(struct oes_client *ec);
int	oes_client_cache_add(struct oes_client *ec,
	    const oes_cache_entry_t *entry);
int	oes_client_cache_remove(struct oes_client *ec,
	    const oes_cache_key_t *key);
void	oes_client_cache_clear(struct oes_client *ec);
void	oes_cache_invalidate_token(const oes_file_token_t *token);
void	oes_cache_invalidate_all(void);
bool	oes_client_cache_lookup(struct oes_client *ec,
	    const struct oes_pending *ep, oes_auth_result_t *result);

/*
 * Function prototypes - oes_event.c
 */
struct oes_pending *oes_pending_alloc(oes_event_type_t event, struct proc *p);
void	oes_pending_free(struct oes_pending *ep);
void	oes_pending_hold(struct oes_pending *ep);
void	oes_pending_rele(struct oes_pending *ep);
int	oes_event_enqueue(struct oes_client *ec, struct oes_pending *ep);
void	oes_event_note_drop(struct oes_client *ec, oes_event_type_t event);
struct oes_pending *oes_event_dequeue(struct oes_client *ec);
int	oes_event_respond(struct oes_client *ec, uint64_t msg_id,
	    oes_auth_result_t result);
int	oes_event_respond_flags(struct oes_client *ec, uint64_t msg_id,
	    oes_auth_result_t result, uint32_t allowed_flags,
	    uint32_t denied_flags);
void	oes_event_handle_timeout(struct oes_pending *ep);
struct oes_pending *oes_pending_clone(const struct oes_pending *src, int mflags);

struct oes_auth_group *oes_auth_group_alloc(int mflags);
void	oes_auth_group_hold(struct oes_auth_group *ag);
void	oes_auth_group_rele(struct oes_auth_group *ag);
void	oes_auth_group_add_pending(struct oes_auth_group *ag);
void	oes_auth_group_cancel_pending(struct oes_auth_group *ag);
void	oes_auth_group_mark_response(struct oes_auth_group *ag,
	    oes_auth_result_t result);
int	oes_auth_group_wait(struct oes_auth_group *ag,
	    struct oes_pending **eps, size_t count);
void	oes_set_auth_deadline(struct oes_pending *ep, uint32_t deadline_ms);

/*
 * Function prototypes - oes_mac.c (MAC policy integration)
 */
int	oes_mac_init(void);
uint64_t oes_proc_get_exec_id(struct proc *p);
const char *oes_proc_get_exec_path(struct proc *p, uint32_t *meta_flags);

/*
 * String table helpers
 */
void	oes_strtab_init(struct oes_strtab *st);
uint32_t oes_strtab_add(struct oes_strtab *st, void *msg_base,
	    const char *str);
uint32_t oes_strtab_add_buf(struct oes_strtab *st, void *msg_base,
	    const void *data, size_t len);

/*
 * Helpers to fill process/file info.
 * strtab is used to append path strings to the message's string table.
 */
void	oes_fill_process(oes_process_t *ep, struct proc *p,
	    struct ucred *cred, struct oes_strtab *st, void *msg_base);
void	oes_fill_file(oes_file_t *ef, struct vnode *vp, struct ucred *cred,
	    struct oes_strtab *st, void *msg_base);
int	oes_scope_mark_current(pid_t owner_pid, uint64_t *markerp);
void	oes_scope_snapshot(struct oes_pending *ep);

/*
 * Sysctl variables
 */
SYSCTL_DECL(_security_oes);

extern int oes_debug;
extern int oes_default_deadline;
extern int oes_default_deadline_miss_mode;
extern int oes_auth_fail_closed;
extern int oes_require_auth_clients;
extern int oes_default_queue_size;
extern int oes_max_clients;
extern int oes_cache_max_entries;
extern char oes_default_muted_paths[];
extern char oes_default_muted_paths_literal[];
extern int oes_default_self_mute;

/*
 * Debug macros
 */
#define OES_DEBUG(fmt, ...)	do {				\
	if (oes_debug)						\
		printf("oes: " fmt "\n", ##__VA_ARGS__);	\
} while (0)

#define OES_WARN(fmt, ...)	\
	printf("oes: WARNING: " fmt "\n", ##__VA_ARGS__)

#define OES_ERR(fmt, ...)	\
	printf("oes: ERROR: " fmt "\n", ##__VA_ARGS__)

#endif /* _KERNEL */

#endif /* !_SECURITY_OES_INTERNAL_H_ */
