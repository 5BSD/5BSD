/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * Open Endpoint Security (OES) - Character Device
 *
 * This file implements /dev/oes, the userspace interface to the
 * endpoint security framework.
 */

#include "opt_dq.h"
#include "opt_mac_capability.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/conf.h>
#include <sys/counter.h>
#include <sys/event.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/filio.h>
#include <sys/jail.h>
#include <sys/resourcevar.h>
#include <sys/rmlock.h>
#include <sys/poll.h>
#include <sys/selinfo.h>
#include <sys/smp.h>
#include <sys/capsicum.h>
#include <sys/priv.h>
#include <sys/sysctl.h>

#include <vm/vm.h>
#include <vm/vm_kern.h>

#include <security/mac/mac_policy.h>	/* MAC_VERSION */
#include <security/oes/oes.h>
#include <security/oes/oes_internal.h>

MALLOC_DEFINE(M_OES, "oes", "Endpoint Security Capabilities");

/*
 * Global state
 */
struct oes_softc oes_softc;

/*
 * Sysctl variables
 */
SYSCTL_NODE(_security, OID_AUTO, oes, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Endpoint Security Capabilities");

int oes_debug = 0;
SYSCTL_INT(_security_oes, OID_AUTO, debug, CTLFLAG_RW,
    &oes_debug, 0, "Enable debug output");

int oes_default_deadline = OES_DEFAULT_DEADLINE_MS;
SYSCTL_INT(_security_oes, OID_AUTO, default_deadline_ms, CTLFLAG_RW,
    &oes_default_deadline, 0, "Default AUTH deadline in milliseconds");

/*
 * The strict settings decide whether an AUTH operation nobody answers is
 * denied, so they decide whether AUTH hooks run with nobody listening: a
 * write goes through oes_gate_set_strict(), which makes the hooks live
 * before a value that needs them is visible.  Values are not validated, as
 * before.
 */
static int
oes_sysctl_strict(SYSCTL_HANDLER_ARGS)
{
	int error, value;

	value = *(int *)arg1;
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	oes_gate_set_strict(arg1, value);
	return (0);
}

int oes_default_deadline_miss_mode = OES_DEADLINE_MISS_FAIL_OPEN;
SYSCTL_PROC(_security_oes, OID_AUTO, default_deadline_miss_mode,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
    &oes_default_deadline_miss_mode, 0, oes_sysctl_strict, "I",
    "Default AUTH deadline miss mode (0=fail open, 1=fail closed)");

int oes_auth_fail_closed = 0;
SYSCTL_PROC(_security_oes, OID_AUTO, auth_fail_closed,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
    &oes_auth_fail_closed, 0, oes_sysctl_strict, "I",
    "Deny AUTH operations when OES cannot allocate or deliver required state");

int oes_require_auth_clients = 0;
SYSCTL_PROC(_security_oes, OID_AUTO, require_auth_clients,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
    &oes_require_auth_clients, 0, oes_sysctl_strict, "I",
    "Deny AUTH operations when no AUTH client is consulted");

int oes_default_queue_size = OES_DEFAULT_QUEUE_SIZE;
SYSCTL_INT(_security_oes, OID_AUTO, default_queue_size, CTLFLAG_RW,
    &oes_default_queue_size, 0, "Default event queue size per client");

int oes_max_clients = 64;
SYSCTL_INT(_security_oes, OID_AUTO, max_clients, CTLFLAG_RW,
    &oes_max_clients, 0, "Maximum number of concurrent clients");

/*
 * Values that tell whether, and how, OES is being watched: as private as
 * the device (PRIV_DRIVER, as oes_open()).  priv_check() refuses a jailed
 * caller as well.
 */
static int
oes_sysctl_private(struct sysctl_req *req)
{

	return (priv_check(req->td, PRIV_DRIVER));
}

/* The number of clients open now. */
static int
oes_sysctl_clients(SYSCTL_HANDLER_ARGS)
{
	u_int n;
	int error;

	error = oes_sysctl_private(req);
	if (error != 0)
		return (error);
	n = atomic_load_int(&oes_softc.sc_nclients);
	return (sysctl_handle_int(oidp, &n, 0, req));
}
SYSCTL_PROC(_security_oes, OID_AUTO, clients,
    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0, oes_sysctl_clients,
    "IU", "Clients open now (PRIV_DRIVER)");

/*
 * The deferred-delivery queue's byte bound (oes_mac.c oes_defer_admits()).
 *
 * The queue is kernel memory that unprivileged producers fill and one
 * thread drains, as pipe buffers are; its default follows the kernel's
 * rule for those (kern.ipc.maxpipekva, subr_param.c): 1/64 of physical
 * memory.  maxpipekva is capped at 1/64 of the kernel address space it
 * maps; the queue is malloc(9) memory, so the malloc arena takes that
 * place: min(physical memory, vm_kmem_size) / 64.  The floor lets a uid
 * alone (which gets half the bound) queue one maximum-size entry per CPU,
 * 2 * mp_ncpus * defer_entry_max, where defer_entry_max is what malloc(9)
 * gives a maximum-size event, measured once here.  A value is raised to
 * the floor and lowered to vm_kmem_size (no larger bound can be
 * allocated, and the admission sum then cannot wrap); 0 restores the
 * default.  Lowering the bound below what is queued only refuses new
 * entries until the queue drains.
 */
static u_long
oes_defer_bound_clamp(u_long v)
{

	if (v == 0)
		v = oes_softc.sc_defer_max_default;
	if (v < oes_softc.sc_defer_floor)
		v = oes_softc.sc_defer_floor;
	if (v > vm_kmem_size)
		v = vm_kmem_size;
	return (v);
}

static void
oes_defer_bound_init(void)
{
	void *probe;
	u_long def, v;

	probe = malloc(offsetof(struct oes_pending, ep_msg) +
	    OES_MSG_MAX_SIZE, M_OES, M_WAITOK);
	oes_softc.sc_defer_entry_max = malloc_usable_size(probe);
	free(probe, M_OES);
	oes_softc.sc_defer_floor = 2 * (u_long)mp_ncpus *
	    oes_softc.sc_defer_entry_max;
	def = MIN(ptoa((u_long)physmem), vm_kmem_size) / 64;
	oes_softc.sc_defer_max_default = oes_defer_bound_clamp(def);
	v = 0;
	TUNABLE_ULONG_FETCH("security.oes.defer_max_bytes", &v);
	oes_softc.sc_defer_max_bytes = oes_defer_bound_clamp(v);
}

static int
oes_sysctl_defer_max_bytes(SYSCTL_HANDLER_ARGS)
{
	u_long v;
	int error;

	v = atomic_load_long(&oes_softc.sc_defer_max_bytes);
	error = sysctl_handle_long(oidp, &v, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	atomic_store_long(&oes_softc.sc_defer_max_bytes,
	    oes_defer_bound_clamp(v));
	return (0);
}
SYSCTL_PROC(_security_oes, OID_AUTO, defer_max_bytes,
    CTLTYPE_ULONG | CTLFLAG_RWTUN | CTLFLAG_NOFETCH | CTLFLAG_MPSAFE, NULL, 0,
    oes_sysctl_defer_max_bytes, "LU",
    "Bytes the deferred-delivery queue holds before it discards "
    "(es_nosleep_drops); 0 restores the default, "
    "min(physical memory, vm.kmem_size) / 64");

SYSCTL_ULONG(_security_oes, OID_AUTO, defer_entry_max, CTLFLAG_RD,
    &oes_softc.sc_defer_entry_max, 0,
    "Bytes a maximum-size deferred event holds");

/* What is queued now: as private as the device, like clients. */
static int
oes_sysctl_defer_bytes(SYSCTL_HANDLER_ARGS)
{
	u_long v;
	int error;

	error = oes_sysctl_private(req);
	if (error != 0)
		return (error);
	v = atomic_load_long(&oes_softc.sc_defer_bytes);
	return (sysctl_handle_long(oidp, &v, 0, req));
}
SYSCTL_PROC(_security_oes, OID_AUTO, defer_bytes,
    CTLTYPE_ULONG | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    oes_sysctl_defer_bytes, "LU",
    "Bytes the deferred-delivery queue holds now (PRIV_DRIVER)");

static int
oes_sysctl_defer_depth(SYSCTL_HANDLER_ARGS)
{
	u_int n;
	int error;

	error = oes_sysctl_private(req);
	if (error != 0)
		return (error);
	mtx_lock_spin(&oes_softc.sc_defer_mtx);
	n = oes_softc.sc_defer_count;
	mtx_unlock_spin(&oes_softc.sc_defer_mtx);
	return (sysctl_handle_int(oidp, &n, 0, req));
}
SYSCTL_PROC(_security_oes, OID_AUTO, defer_depth,
    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    oes_sysctl_defer_depth, "IU",
    "Events the deferred-delivery queue holds now (PRIV_DRIVER)");

int oes_cache_max_entries = 1024;
SYSCTL_INT(_security_oes, OID_AUTO, cache_max_entries, CTLFLAG_RW,
    &oes_cache_max_entries, 0, "Maximum decision cache entries per client");

/*
 * Events dropped before anything was allocated for them, because every open
 * client is jail-scoped and none covers the subject (oes_event_unobserved()).
 * The counters exist only once oes_dev_state_init() has run.
 */
static int
oes_sysctl_jail_counter(SYSCTL_HANDLER_ARGS)
{
	counter_u64_t *cp = arg1;
	uint64_t value;

	value = *cp != NULL ? counter_u64_fetch(*cp) : 0;
	return (sysctl_handle_64(oidp, &value, 0, req));
}

SYSCTL_PROC(_security_oes, OID_AUTO, jail_filtered,
    CTLTYPE_U64 | CTLFLAG_RD | CTLFLAG_MPSAFE,
    &oes_softc.sc_jail_filtered, 0, oes_sysctl_jail_counter, "QU",
    "Events dropped before allocation: only jail-scoped clients are open "
    "and none covers the subject");
SYSCTL_PROC(_security_oes, OID_AUTO, jail_filtered_auth,
    CTLTYPE_U64 | CTLFLAG_RD | CTLFLAG_MPSAFE,
    &oes_softc.sc_jail_filtered_auth, 0, oes_sysctl_jail_counter, "QU",
    "AUTH events among security.oes.jail_filtered");
/*
 * Base-exclusion counters: they move only while a client is open, so they
 * are as private as the client count (oes_sysctl_private()).
 */
static int
oes_sysctl_private_counter(SYSCTL_HANDLER_ARGS)
{
	int error;

	error = oes_sysctl_private(req);
	if (error != 0)
		return (error);
	return (oes_sysctl_jail_counter(oidp, arg1, arg2, req));
}

SYSCTL_PROC(_security_oes, OID_AUTO, excluded_skipped,
    CTLTYPE_U64 | CTLFLAG_RD | CTLFLAG_MPSAFE,
    &oes_softc.sc_excluded_skipped, 0, oes_sysctl_private_counter, "QU",
    "Events not produced because the acting process is excluded "
    "(cap_process(2) BASE EXCLUSION)");
SYSCTL_PROC(_security_oes, OID_AUTO, excluded_invalidations,
    CTLTYPE_U64 | CTLFLAG_RD | CTLFLAG_MPSAFE,
    &oes_softc.sc_excluded_invalidations, 0, oes_sysctl_private_counter, "QU",
    "Decision-cache invalidations by excluded processes, without an event");
SYSCTL_PROC(_security_oes, OID_AUTO, exec_fail_open,
    CTLTYPE_U64 | CTLFLAG_RD | CTLFLAG_MPSAFE,
    &oes_softc.sc_exec_fail_open, 0, oes_sysctl_private_counter, "QU",
    "Exec events of programs started by excluded processes, delivered "
    "without strict denial");

/*
 * Default muting configuration
 *
 * These sysctls define paths that are automatically muted for new clients.
 * Paths are colon-separated (e.g., "/var/log:/tmp:/dev").
 * Applied when client calls OES_IOC_SET_MODE.
 */
char oes_default_muted_paths[1024] = "";
SYSCTL_STRING(_security_oes, OID_AUTO, default_muted_paths, CTLFLAG_RW,
    oes_default_muted_paths, sizeof(oes_default_muted_paths),
    "Colon-separated paths to mute by default (prefix match)");

char oes_default_muted_paths_literal[1024] = "";
SYSCTL_STRING(_security_oes, OID_AUTO, default_muted_paths_literal, CTLFLAG_RW,
    oes_default_muted_paths_literal, sizeof(oes_default_muted_paths_literal),
    "Colon-separated paths to mute by default (literal match)");

/*
 * Device operations
 */
static d_open_t		oes_open;
static d_close_t	oes_close;
static d_read_t		oes_read;
static d_write_t	oes_write;
static d_ioctl_t	oes_ioctl;
static d_poll_t		oes_poll;
static d_kqfilter_t	oes_kqfilter;

static bool
oes_thread_is_ilp32(struct thread *td)
{

	return (td != NULL && td->td_proc != NULL &&
	    (td->td_proc->p_sysent->sv_flags & SV_ILP32) != 0);
}

static int	oes_ioctl_subscribe(struct oes_client *ec,
		    struct oes_subscribe_args *args);
static int	oes_ioctl_subscribe_bitmap(struct oes_client *ec,
		    struct oes_subscribe_bitmap_args *args);
static int	oes_ioctl_get_subscriptions(struct oes_client *ec,
		    struct oes_subscribe_bitmap_args *args);
static int	oes_ioctl_set_scope(struct oes_client *ec,
		    struct oes_scope_args *args);
static int	oes_ioctl_get_scope(struct oes_client *ec,
		    struct oes_scope_args *args);
static int	oes_ioctl_set_jail_scope(struct oes_client *ec,
		    struct thread *td, struct oes_jail_scope_args *args);
static int	oes_ioctl_get_jail_scope(struct oes_client *ec,
		    struct thread *td, struct oes_jail_scope_args *args);
static int	oes_ioctl_set_mode(struct oes_client *ec,
		    struct oes_mode_args *args);
static int	oes_ioctl_get_mode(struct oes_client *ec,
		    struct oes_mode_args *args);
static int	oes_ioctl_set_deadline_bound(struct oes_client *ec,
		    struct oes_event_deadline_args *args, bool minimum);
static int	oes_ioctl_get_deadline_bound(struct oes_client *ec,
		    struct oes_event_deadline_args *args, bool minimum);
static int	oes_ioctl_mute_process(struct oes_client *ec,
		    struct oes_mute_args *args);
static int	oes_ioctl_unmute_process(struct oes_client *ec,
		    struct oes_mute_args *args);
static int	oes_ioctl_mute_path(struct oes_client *ec,
		    struct oes_mute_path_args *args);
static int	oes_ioctl_unmute_path(struct oes_client *ec,
		    struct oes_mute_path_args *args);
static int	oes_ioctl_set_mute_invert(struct oes_client *ec,
		    struct oes_mute_invert_args *args);
static int	oes_ioctl_get_mute_invert(struct oes_client *ec,
		    struct oes_mute_invert_args *args);
static int	oes_ioctl_set_deadline_miss_mode(struct oes_client *ec,
		    struct oes_deadline_miss_mode_args *args);
static int	oes_ioctl_get_deadline_miss_mode(struct oes_client *ec,
		    struct oes_deadline_miss_mode_args *args);
static int	oes_ioctl_cache_add(struct oes_client *ec,
		    oes_cache_entry_t *entry);
static int	oes_ioctl_cache_remove(struct oes_client *ec,
		    oes_cache_key_t *key);
static int	oes_ioctl_cache_clear(struct oes_client *ec);
static int	oes_ioctl_get_stats(struct oes_client *ec,
		    struct oes_stats *stats);
static int	oes_ioctl_mute_process_events(struct oes_client *ec,
		    struct oes_mute_process_events_args *args);
static int	oes_ioctl_unmute_process_events(struct oes_client *ec,
		    struct oes_mute_process_events_args *args);
static int	oes_ioctl_mute_path_events(struct oes_client *ec,
		    struct oes_mute_path_events_args *args);
static int	oes_ioctl_unmute_path_events(struct oes_client *ec,
		    struct oes_mute_path_events_args *args);
static int	oes_ioctl_get_muted_processes(struct oes_client *ec,
		    struct oes_get_muted_processes_args *args);
static int	oes_ioctl_get_muted_paths(struct oes_client *ec,
		    struct oes_get_muted_paths_args *args);
static int	oes_ioctl_unmute_all_processes(struct oes_client *ec);
static int	oes_ioctl_unmute_all_paths(struct oes_client *ec, bool target);

/* Forward declaration for cdevpriv dtor */
static void	oes_client_dtor(void *data);

static struct cdevsw oes_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	oes_open,
	.d_close =	oes_close,
	.d_read =	oes_read,
	.d_write =	oes_write,
	.d_ioctl =	oes_ioctl,
	.d_poll =	oes_poll,
	.d_kqfilter =	oes_kqfilter,
	.d_name =	"oes",
};

/*
 * Kqueue filter operations
 */
static void	oes_kqdetach(struct knote *kn);
static int	oes_kqread(struct knote *kn, long hint);

static struct filterops oes_rfiltops = {
	.f_isfd =	1,
	.f_detach =	oes_kqdetach,
	.f_event =	oes_kqread,
};

/*
 * oes_open - Create new client on each open()
 *
 * Each open() creates an independent client with its own subscriptions,
 * event queue, and configuration.
 */
static int
oes_open(struct cdev *dev __unused, int oflags, int devtype __unused,
    struct thread *td)
{
	struct oes_client *ec;
	int error;

	if (oes_thread_is_ilp32(td))
		return (EOPNOTSUPP);

	/* Check privilege to open the device */
	error = priv_check(td, PRIV_DRIVER);
	if (error)
		return (error);

	/* Reject opens until initialization has completed. */
	OES_LOCK();
	if (!oes_softc.sc_active) {
		OES_UNLOCK();
		return (ENXIO);
	}

	/* Enforce max clients */
	if (oes_max_clients <= 0 ||
	    oes_softc.sc_nclients >= (uint32_t)oes_max_clients) {
		OES_UNLOCK();
		return (EAGAIN);
	}
	/* A new client is not jail-scoped; see oes_event_unobserved(). */
	atomic_add_int(&oes_softc.sc_nwide, 1);
	atomic_add_int(&oes_softc.sc_nclients, 1);
	OES_UNLOCK();

	/* Allocate outside OES/process locks, before publishing this client. */
	oes_signal_reserve_prepare();

	/* Allocate client state */
	ec = oes_client_alloc();
	if (ec == NULL) {
		OES_LOCK();
		atomic_subtract_int(&oes_softc.sc_nclients, 1);
		atomic_subtract_int(&oes_softc.sc_nwide, 1);
		OES_UNLOCK();
		return (ENOMEM);
	}

	OES_LOCK();
	ec->ec_id = oes_softc.sc_next_client_id++;
	OES_UNLOCK();

	/* The opener's identity anchors OES_SCOPE_DESCENDANTS. */
	ec->ec_owner_pid = td->td_proc->p_pid;
	ec->ec_owner_genid = oes_proc_genid_unlocked(td->td_proc);

	/* Store client in cdevpriv for later retrieval */
	error = devfs_set_cdevpriv(ec, oes_client_dtor);
	if (error) {
		oes_client_free(ec);
		OES_LOCK();
		atomic_subtract_int(&oes_softc.sc_nclients, 1);
		atomic_subtract_int(&oes_softc.sc_nwide, 1);
		OES_UNLOCK();
		return (error);
	}

	/*
	 * The opener acts as the client: it is its first reader, before the
	 * client can receive anything (oes(4), "A client's own processes").
	 */
	/*
	 * The descriptor is not installed yet, so its rights cannot be read;
	 * a fresh open carries every right, and FWRITE decides.
	 */
	oes_client_join(ec, td, NULL, (oflags & FWRITE) != 0 ?
	    OES_JOIN_ANSWER : OES_JOIN_READ);

	/* Add to global client list */
	OES_LOCK();
	LIST_INSERT_HEAD(&oes_softc.sc_clients, ec, ec_link);
	OES_UNLOCK();

	OES_DEBUG("client %p opened by pid %d", ec, td->td_proc->p_pid);

	return (0);
}

/*
 * oes_client_dtor - Called when file descriptor is closed
 */
static void
oes_client_dtor(void *data)
{
	struct oes_client *ec = data;
	struct prison *pr, *setter_pr;

	if (ec == NULL)
		return;

	OES_DEBUG("client %p closing", ec);

	/* Mark as closing to reject new events */
	EC_LOCK(ec);
	ec->ec_flags |= EC_FLAG_CLOSING;
	EC_UNLOCK(ec);

	/*
	 * Remove from global list.  A jail scope that has not ended gives up
	 * its jail here; one that ended already did so in the delivery task.
	 */
	pr = NULL;
	OES_LOCK();
	LIST_REMOVE(ec, ec_link);
	EC_LOCK(ec);
	if (ec->ec_scope == OES_SCOPE_JAIL) {
		if (ec->ec_jail_pr != NULL)
			pr = oes_client_jail_detach_locked(ec);
	} else
		atomic_subtract_int(&oes_softc.sc_nwide, 1);
	/* Kept past the end of the scope: GET still answers then. */
	setter_pr = ec->ec_jail_setter_pr;
	ec->ec_jail_setter_pr = NULL;
	if (setter_pr != NULL)
		atomic_subtract_int(&oes_softc.sc_jail_setters, 1);
	EC_UNLOCK(ec);
	atomic_subtract_int(&oes_softc.sc_nclients, 1);
	OES_UNLOCK();
	/* Hooks only this client needed go idle; nothing waits for them. */
	oes_gate_client_update(ec, true);
	if (pr != NULL)
		prison_free(pr);
	if (setter_pr != NULL)
		prison_free(setter_pr);

	/* Wake any waiters and clean up */
	oes_client_free(ec);
}

/*
 * oes_close - Close handler (actual cleanup in dtor)
 */
static int
oes_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	/* Cleanup happens in oes_client_dtor via devfs_clear_cdevpriv */
	return (0);
}

/*
 * Return ec's OES_EVENT_NOTIFY_LOST marker (oes(4) "Lost events") and
 * clear the counts it reports.  Called with ec locked and a count
 * pending; returns with it unlocked.  The marker is built from the counts,
 * never queued, so no full queue or failed allocation can lose it: if the
 * copy out fails the counts are restored for the next read.
 */
static int
oes_read_lost(struct oes_client *ec, struct uio *uio)
{
	oes_message_t *msg;
	struct timespec now, wall_now;
	uint64_t queue, deferred;
	int error;

	EC_LOCK_ASSERT(ec);
	queue = ec->ec_lost_queue;
	deferred = ec->ec_lost_deferred;
	ec->ec_lost_queue = 0;
	ec->ec_lost_deferred = 0;
	EC_UNLOCK(ec);

	msg = malloc(sizeof(*msg), M_OES, M_WAITOK | M_ZERO);
	msg->em_version = OES_MESSAGE_VERSION;
	msg->em_size = sizeof(*msg);
	msg->em_struct_size = sizeof(*msg);
	msg->em_event = OES_EVENT_NOTIFY_LOST;
	msg->em_action = OES_ACTION_NOTIFY;
	nanouptime(&now);
	nanotime(&wall_now);
	msg->em_time.tv_sec = now.tv_sec;
	msg->em_time.tv_nsec = now.tv_nsec;
	msg->em_wall_time.tv_sec = wall_now.tv_sec;
	msg->em_wall_time.tv_nsec = wall_now.tv_nsec;
	msg->em_event_data.lost.el_count = queue + deferred;
	msg->em_event_data.lost.el_deferred = deferred;
	msg->em_event_data.lost.el_queue = queue;
	error = uiomove(msg, msg->em_size, uio);
	free(msg, M_OES);
	if (error != 0) {
		EC_LOCK(ec);
		ec->ec_lost_queue += queue;
		ec->ec_lost_deferred += deferred;
		EC_UNLOCK(ec);
	}
	return (error);
}

/*
 * oes_read - Read events from client queue
 *
 * Returns one or more events per read.  AUTH events are always returned
 * alone (each needs an individual response).  NOTIFY events are batched:
 * as many as fit in the user buffer are packed contiguously, stopping at
 * the first AUTH event or when the buffer is full.
 *
 * Each message is self-describing via em_size.  Userspace iterates:
 *   off = 0;
 *   while (off < bytes_read) {
 *       msg = buf + off;
 *       off += msg->em_size;
 *   }
 *
 * A client that lost events since its last read gets an
 * OES_EVENT_NOTIFY_LOST marker first, alone in its read (oes_read_lost()).
 *
 * Blocks if queue is empty (unless O_NONBLOCK).
 */
static int
oes_read(struct cdev *dev __unused, struct uio *uio, int ioflag)
{
	struct oes_client *ec;
	struct oes_pending *ep;
	int error;

	if (oes_thread_is_ilp32(curthread))
		return (EOPNOTSUPP);
	error = devfs_get_cdevpriv((void **)&ec);
	if (error)
		return (error);

	if (uio->uio_resid < sizeof(oes_message_t))
		return (EINVAL);
	oes_client_join(ec, curthread, curthread->td_fpop, OES_JOIN_READ);

	EC_LOCK(ec);

	for (;;) {
		/*
		 * Wait for events if queue is empty.  Every wakeup re-tests
		 * the queue: the end of a jail scope wakes readers with
		 * nothing queued, and an expired AUTH event can be unlinked
		 * between an enqueue's wakeup and this thread running.
		 */
		while (TAILQ_EMPTY(&ec->ec_pending) &&
		    !oes_client_lost_pending(ec)) {
			if (ec->ec_flags & EC_FLAG_CLOSING) {
				EC_UNLOCK(ec);
				return (ENXIO);
			}
			/*
			 * The client's jail is gone and everything queued
			 * for it has been read: end of file.
			 */
			if ((ec->ec_jail_flags & OES_JAIL_SCOPE_DEAD) != 0) {
				EC_UNLOCK(ec);
				return (0);
			}
			if (ioflag & O_NONBLOCK) {
				EC_UNLOCK(ec);
				return (EAGAIN);
			}
			error = msleep(&ec->ec_pending, &ec->ec_mtx, PCATCH,
			    "oesrd", 0);
			if (error) {
				EC_UNLOCK(ec);
				return (error);
			}
		}

		/* A loss is reported first, before what is still queued. */
		if (oes_client_lost_pending(ec))
			return (oes_read_lost(ec, uio));

		ep = oes_event_dequeue(ec);
		KASSERT(ep != NULL, ("oes_read: dequeue returned NULL"));

		/* Skip expired AUTH events at head of queue */
		if (!OES_EVENT_IS_AUTH(ep->ep_msg.em_event) ||
		    (ep->ep_flags & EP_FLAG_EXPIRED) == 0)
			break;
		EC_UNLOCK(ec);
		oes_pending_rele(ep);
		EC_LOCK(ec);
	}

	/*
	 * AUTH event: return alone (needs individual response).
	 */
	if (OES_EVENT_IS_AUTH(ep->ep_msg.em_event)) {
		TAILQ_INSERT_TAIL(&ec->ec_delivered, ep, ep_link);
		EC_UNLOCK(ec);

		if (uio->uio_resid < ep->ep_msg.em_size) {
			EC_LOCK(ec);
			TAILQ_REMOVE(&ec->ec_delivered, ep, ep_link);
			ep->ep_flags &= ~EP_FLAG_DELIVERED;
			TAILQ_INSERT_HEAD(&ec->ec_pending, ep, ep_link);
			ec->ec_queue_count++;
			ec->ec_queue_bytes += ep->ep_msg.em_size;
			selwakeup(&ec->ec_selinfo);
			KNOTE_LOCKED(&ec->ec_selinfo.si_note, 0);
			wakeup(&ec->ec_pending);
			EC_UNLOCK(ec);
			return (ENOBUFS);
		}

		error = uiomove(&ep->ep_msg, ep->ep_msg.em_size, uio);
		if (error != 0) {
			EC_LOCK(ec);
			TAILQ_REMOVE(&ec->ec_delivered, ep, ep_link);
			ep->ep_flags &= ~EP_FLAG_DELIVERED;
			TAILQ_INSERT_HEAD(&ec->ec_pending, ep, ep_link);
			ec->ec_queue_count++;
			ec->ec_queue_bytes += ep->ep_msg.em_size;
			selwakeup(&ec->ec_selinfo);
			KNOTE_LOCKED(&ec->ec_selinfo.si_note, 0);
			wakeup(&ec->ec_pending);
			EC_UNLOCK(ec);
		}
		return (error);
	}

	/*
	 * NOTIFY event: batch as many as fit in the user buffer.
	 * Pack contiguously, stopping at the first AUTH event or
	 * when buffer space runs out.
	 */
	EC_UNLOCK(ec);

	{
	bool copied_any = false;

	for (;;) {
		/* Check buffer space */
		if (uio->uio_resid < ep->ep_msg.em_size) {
			/* No room - requeue and wake so next read sees it */
			EC_LOCK(ec);
			ep->ep_flags &= ~EP_FLAG_DELIVERED;
			TAILQ_INSERT_HEAD(&ec->ec_pending, ep, ep_link);
			ec->ec_queue_count++;
			ec->ec_queue_bytes += ep->ep_msg.em_size;
			selwakeup(&ec->ec_selinfo);
			KNOTE_LOCKED(&ec->ec_selinfo.si_note, 0);
			wakeup(&ec->ec_pending);
			EC_UNLOCK(ec);
			/*
			 * If nothing was copied yet, the buffer is too
			 * small for even one event.  Return ENOBUFS so
			 * the caller doesn't see a zero-byte "success".
			 */
			if (!copied_any)
				return (ENOBUFS);
			break;
		}

		error = uiomove(&ep->ep_msg, ep->ep_msg.em_size, uio);
		oes_pending_rele(ep);
		if (error != 0)
			return (error);
		copied_any = true;

		/* Try to dequeue more NOTIFY events */
		EC_LOCK(ec);
		ep = TAILQ_FIRST(&ec->ec_pending);
		if (ep == NULL || OES_EVENT_IS_AUTH(ep->ep_msg.em_event) ||
		    (ep->ep_flags & EP_FLAG_EXPIRED)) {
			EC_UNLOCK(ec);
			break;
		}
		ep = oes_event_dequeue(ec);
		EC_UNLOCK(ec);
	}
	}

	return (0);
}

/*
 * oes_write - Write AUTH responses
 *
 * Clients write responses to AUTH events. Two formats are supported:
 * - oes_response_t: Basic allow/deny response
 * - oes_response_flags_t: Response with flags for partial authorization
 *
 * The write size determines which format is used.
 */
static int
oes_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct oes_client *ec;
	int error;

	if (oes_thread_is_ilp32(curthread))
		return (EOPNOTSUPP);
	error = devfs_get_cdevpriv((void **)&ec);
	if (error)
		return (error);
	oes_client_join(ec, curthread, curthread->td_fpop, OES_JOIN_ANSWER);

	if (uio->uio_resid == sizeof(oes_response_t)) {
		/* Basic response */
		oes_response_t resp;

		error = uiomove(&resp, sizeof(resp), uio);
		if (error)
			return (error);

		/* Validate response */
		if (resp.er_result != OES_AUTH_ALLOW &&
		    resp.er_result != OES_AUTH_DENY)
			return (EINVAL);
		if (resp.er_flags != 0)
			return (EINVAL);

		error = oes_event_respond(ec, resp.er_id, resp.er_result);

	} else if (uio->uio_resid == sizeof(oes_response_flags_t)) {
		/* Flags-based response */
		oes_response_flags_t resp;

		error = uiomove(&resp, sizeof(resp), uio);
		if (error)
			return (error);

		/* Validate response */
		if (resp.erf_result != OES_AUTH_ALLOW &&
		    resp.erf_result != OES_AUTH_DENY)
			return (EINVAL);
		if (resp.erf_reserved != 0)
			return (EINVAL);

		error = oes_event_respond_flags(ec, resp.erf_id,
		    resp.erf_result, resp.erf_allowed_flags,
		    resp.erf_denied_flags);

	} else {
		/* Invalid size */
		return (EINVAL);
	}

	return (error);
}

static int
oes_ioctl_subscribe(struct oes_client *ec, struct oes_subscribe_args *args)
{
	oes_event_type_t *events;
	size_t count;
	int error;

	if (args == NULL)
		return (EINVAL);
	if (args->esa_reserved != 0)
		return (EINVAL);

	count = args->esa_count;
	if (count == 0 || count > 64)
		return (EINVAL);

	events = malloc(count * sizeof(*events), M_OES, M_WAITOK);
	error = copyin(args->esa_events, events, count * sizeof(*events));
	if (error) {
		free(events, M_OES);
		return (error);
	}

	error = oes_client_subscribe_events(ec, events, count, args->esa_flags);
	free(events, M_OES);
	return (error);
}

static int
oes_ioctl_subscribe_bitmap(struct oes_client *ec,
    struct oes_subscribe_bitmap_args *args)
{
	if (args == NULL)
		return (EINVAL);
	if (args->esba_reserved != 0)
		return (EINVAL);

	return (oes_client_subscribe_bitmap(ec, args->esba_auth,
	    args->esba_notify, args->esba_flags));
}

static int
oes_ioctl_get_subscriptions(struct oes_client *ec,
    struct oes_subscribe_bitmap_args *args)
{
	if (args == NULL)
		return (EINVAL);
	oes_client_get_subscriptions(ec, args->esba_auth, args->esba_notify);
	args->esba_flags = 0;
	args->esba_reserved = 0;
	return (0);
}

static int
oes_ioctl_set_scope(struct oes_client *ec, struct oes_scope_args *args)
{

	if (args == NULL || args->esa_reserved != 0)
		return (EINVAL);
	return (oes_client_set_scope(ec, args->esa_scope));
}

static int
oes_ioctl_get_scope(struct oes_client *ec, struct oes_scope_args *args)
{

	if (args == NULL)
		return (EINVAL);
	oes_client_get_scope(ec, &args->esa_scope);
	args->esa_reserved = 0;
	return (0);
}

static int
oes_ioctl_set_jail_scope(struct oes_client *ec, struct thread *td,
    struct oes_jail_scope_args *args)
{

	if (args == NULL)
		return (EINVAL);
	return (oes_client_set_jail_scope(ec, td, args));
}

static int
oes_ioctl_get_jail_scope(struct oes_client *ec, struct thread *td,
    struct oes_jail_scope_args *args)
{

	if (args == NULL)
		return (EINVAL);
	return (oes_client_get_jail_scope(ec, td, args));
}

static int
oes_ioctl_set_mode(struct oes_client *ec, struct oes_mode_args *args)
{
	if (args == NULL || args->ema_flags != 0)
		return (EINVAL);

	/*
	 * Access to this ioctl is controlled via cap_ioctls_limit().
	 * Third-party clients won't have this ioctl in their allowed set.
	 */
	return (oes_client_set_mode(ec, args->ema_mode,
	    args->ema_default_deadline_ms, args->ema_queue_size));
}

static int
oes_ioctl_get_mode(struct oes_client *ec, struct oes_mode_args *args)
{
	if (args == NULL)
		return (EINVAL);

	oes_client_get_mode(ec, &args->ema_mode, &args->ema_default_deadline_ms,
	    &args->ema_queue_size);
	args->ema_flags = 0;
	return (0);
}

static int
oes_ioctl_set_deadline_bound(struct oes_client *ec,
    struct oes_event_deadline_args *args, bool minimum)
{

	if (args == NULL || args->oeda_reserved[0] != 0 ||
	    args->oeda_reserved[1] != 0)
		return (EINVAL);
	return (oes_client_set_deadline_bound(ec,
	    (oes_event_type_t)args->oeda_event, args->oeda_milliseconds,
	    minimum));
}

static int
oes_ioctl_get_deadline_bound(struct oes_client *ec,
    struct oes_event_deadline_args *args, bool minimum)
{
	int error;

	if (args == NULL || args->oeda_reserved[0] != 0 ||
	    args->oeda_reserved[1] != 0)
		return (EINVAL);
	error = oes_client_get_deadline_bound(ec,
	    (oes_event_type_t)args->oeda_event, &args->oeda_milliseconds,
	    minimum);
	if (error == 0) {
		args->oeda_reserved[0] = 0;
		args->oeda_reserved[1] = 0;
	}
	return (error);
}

static int
oes_ioctl_mute_process(struct oes_client *ec, struct oes_mute_args *args)
{
	if (args == NULL || (args->emu_flags & ~OES_MUTE_SELF) != 0)
		return (EINVAL);

	return (oes_client_mute(ec, &args->emu_token, args->emu_flags));
}

static int
oes_ioctl_unmute_process(struct oes_client *ec, struct oes_mute_args *args)
{
	if (args == NULL || (args->emu_flags & ~OES_MUTE_SELF) != 0)
		return (EINVAL);

	/*
	 * A client never receives its own processes' events; there is no
	 * self-mute to lift (oes(4)).
	 */
	if (args->emu_flags & OES_MUTE_SELF)
		return (EINVAL);

	return (oes_client_unmute(ec, &args->emu_token));
}

static int
oes_ioctl_mute_path(struct oes_client *ec, struct oes_mute_path_args *args)
{
	bool target;

	if (args == NULL ||
	    (args->emp_flags & ~OES_MUTE_PATH_FLAG_TARGET) != 0)
		return (EINVAL);

	target = (args->emp_flags & OES_MUTE_PATH_FLAG_TARGET) != 0;
	return (oes_client_mute_path(ec, args->emp_path, args->emp_type,
	    target));
}

static int
oes_ioctl_unmute_path(struct oes_client *ec, struct oes_mute_path_args *args)
{
	bool target;

	if (args == NULL ||
	    (args->emp_flags & ~OES_MUTE_PATH_FLAG_TARGET) != 0)
		return (EINVAL);

	target = (args->emp_flags & OES_MUTE_PATH_FLAG_TARGET) != 0;
	return (oes_client_unmute_path(ec, args->emp_path, args->emp_type,
	    target));
}

static int
oes_ioctl_set_mute_invert(struct oes_client *ec,
    struct oes_mute_invert_args *args)
{
	if (args == NULL || args->emi_invert > 1)
		return (EINVAL);

	return (oes_client_set_mute_invert(ec, args->emi_type,
	    args->emi_invert != 0));
}

static int
oes_ioctl_get_mute_invert(struct oes_client *ec,
    struct oes_mute_invert_args *args)
{
	if (args == NULL)
		return (EINVAL);

	return (oes_client_get_mute_invert(ec, args->emi_type,
	    &args->emi_invert));
}

static int
oes_ioctl_set_deadline_miss_mode(struct oes_client *ec,
    struct oes_deadline_miss_mode_args *args)
{
	if (args == NULL || args->edma_reserved != 0)
		return (EINVAL);

	return (oes_client_set_deadline_miss_mode(ec, args->edma_mode));
}

static int
oes_ioctl_get_deadline_miss_mode(struct oes_client *ec,
    struct oes_deadline_miss_mode_args *args)
{
	if (args == NULL || args->edma_reserved != 0)
		return (EINVAL);

	args->edma_reserved = 0;
	return (oes_client_get_deadline_miss_mode(ec, &args->edma_mode));
}

static int
oes_ioctl_cache_add(struct oes_client *ec, oes_cache_entry_t *entry)
{
	if (entry == NULL)
		return (EINVAL);

	return (oes_client_cache_add(ec, entry));
}

static int
oes_ioctl_cache_remove(struct oes_client *ec, oes_cache_key_t *key)
{
	if (key == NULL)
		return (EINVAL);

	return (oes_client_cache_remove(ec, key));
}

static int
oes_ioctl_cache_clear(struct oes_client *ec)
{
	oes_client_cache_clear(ec);
	return (0);
}

static int
oes_ioctl_get_stats(struct oes_client *ec, struct oes_stats *stats)
{
	oes_client_get_stats(ec, stats);
	return (0);
}

static int
oes_ioctl_mute_process_events(struct oes_client *ec,
    struct oes_mute_process_events_args *args)
{
	if (args == NULL || (args->empe_flags & ~OES_MUTE_SELF) != 0)
		return (EINVAL);

	if (args->empe_count > OES_MAX_MUTE_EVENTS)
		return (EINVAL);

	return (oes_client_mute_events(ec, &args->empe_token, args->empe_flags,
	    args->empe_events, args->empe_count));
}

static int
oes_ioctl_unmute_process_events(struct oes_client *ec,
    struct oes_mute_process_events_args *args)
{
	if (args == NULL || (args->empe_flags & ~OES_MUTE_SELF) != 0)
		return (EINVAL);

	if (args->empe_count > OES_MAX_MUTE_EVENTS)
		return (EINVAL);

	return (oes_client_unmute_events(ec, &args->empe_token, args->empe_flags,
	    args->empe_events, args->empe_count));
}

static int
oes_ioctl_mute_path_events(struct oes_client *ec,
    struct oes_mute_path_events_args *args)
{
	bool target;

	if (args == NULL ||
	    (args->empae_flags & ~OES_MUTE_PATH_FLAG_TARGET) != 0)
		return (EINVAL);

	if (args->empae_count > OES_MAX_MUTE_EVENTS)
		return (EINVAL);

	target = (args->empae_flags & OES_MUTE_PATH_FLAG_TARGET) != 0;
	return (oes_client_mute_path_events(ec, args->empae_path,
	    args->empae_type, target, args->empae_events, args->empae_count));
}

static int
oes_ioctl_unmute_path_events(struct oes_client *ec,
    struct oes_mute_path_events_args *args)
{
	bool target;

	if (args == NULL ||
	    (args->empae_flags & ~OES_MUTE_PATH_FLAG_TARGET) != 0)
		return (EINVAL);

	if (args->empae_count > OES_MAX_MUTE_EVENTS)
		return (EINVAL);

	target = (args->empae_flags & OES_MUTE_PATH_FLAG_TARGET) != 0;
	return (oes_client_unmute_path_events(ec, args->empae_path,
	    args->empae_type, target, args->empae_events, args->empae_count));
}

static int
oes_ioctl_get_muted_processes(struct oes_client *ec,
    struct oes_get_muted_processes_args *args)
{
	struct oes_muted_process_entry *kbuf = NULL;
	size_t count, actual;
	int error;

	if (args == NULL)
		return (EINVAL);

	count = args->egmp_count;
	if (count > OES_MAX_MUTED_ENTRIES)
		count = OES_MAX_MUTED_ENTRIES;

	/* Allocate kernel buffer for results */
	if (count > 0 && args->egmp_entries != NULL)
		kbuf = malloc(count * sizeof(*kbuf), M_OES, M_WAITOK | M_ZERO);

	/* Fill kernel buffer */
	error = oes_client_get_muted_processes(ec, kbuf, count, &actual);
	if (error != 0) {
		if (kbuf != NULL)
			free(kbuf, M_OES);
		return (error);
	}

	/* Copy results to userspace */
	if (kbuf != NULL && actual > 0) {
		size_t tocopy = (actual < count) ? actual : count;
		error = copyout(kbuf, args->egmp_entries,
		    tocopy * sizeof(*kbuf));
	}

	if (kbuf != NULL)
		free(kbuf, M_OES);

	args->egmp_actual = actual;
	return (error);
}

static int
oes_ioctl_get_muted_paths(struct oes_client *ec,
    struct oes_get_muted_paths_args *args)
{
	struct oes_muted_path_entry *kbuf = NULL;
	size_t count, actual;
	bool target;
	int error;

	if (args == NULL)
		return (EINVAL);
	if (args->egmpa_reserved != 0 ||
	    (args->egmpa_flags & ~OES_MUTE_PATH_FLAG_TARGET) != 0)
		return (EINVAL);

	target = (args->egmpa_flags & OES_MUTE_PATH_FLAG_TARGET) != 0;
	count = args->egmpa_count;
	if (count > OES_MAX_MUTED_ENTRIES)
		count = OES_MAX_MUTED_ENTRIES;

	/* Allocate kernel buffer for results */
	if (count > 0 && args->egmpa_entries != NULL)
		kbuf = malloc(count * sizeof(*kbuf), M_OES, M_WAITOK | M_ZERO);

	/* Fill kernel buffer */
	error = oes_client_get_muted_paths(ec, kbuf, count, &actual, target);
	if (error != 0) {
		if (kbuf != NULL)
			free(kbuf, M_OES);
		return (error);
	}

	/* Copy results to userspace */
	if (kbuf != NULL && actual > 0) {
		size_t tocopy = (actual < count) ? actual : count;
		error = copyout(kbuf, args->egmpa_entries,
		    tocopy * sizeof(*kbuf));
	}

	if (kbuf != NULL)
		free(kbuf, M_OES);

	args->egmpa_actual = actual;
	return (error);
}

static int
oes_ioctl_unmute_all_processes(struct oes_client *ec)
{
	oes_client_unmute_all_processes(ec);
	return (0);
}

static int
oes_ioctl_unmute_all_paths(struct oes_client *ec, bool target)
{
	oes_client_unmute_all_paths(ec, target);
	return (0);
}

/*
 * oes_ioctl - Handle control operations
 */
static int
oes_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	struct oes_client *ec;
	int error;

	if (oes_thread_is_ilp32(td))
		return (EOPNOTSUPP);
	error = devfs_get_cdevpriv((void **)&ec);
	if (error)
		return (error);

	switch (cmd) {
	case OES_IOC_SUBSCRIBE: {
		return (oes_ioctl_subscribe(ec,
		    (struct oes_subscribe_args *)data));
	}

	case OES_IOC_SUBSCRIBE_BITMAP: {
		return (oes_ioctl_subscribe_bitmap(ec,
		    (struct oes_subscribe_bitmap_args *)data));
	}

	case OES_IOC_GET_SUBSCRIPTIONS: {
		return (oes_ioctl_get_subscriptions(ec,
		    (struct oes_subscribe_bitmap_args *)data));
	}
	case OES_IOC_SET_SCOPE:
		return (oes_ioctl_set_scope(ec, (struct oes_scope_args *)data));
	case OES_IOC_GET_SCOPE:
		return (oes_ioctl_get_scope(ec, (struct oes_scope_args *)data));
	case OES_IOC_SET_JAIL_SCOPE:
		return (oes_ioctl_set_jail_scope(ec, td,
		    (struct oes_jail_scope_args *)data));
	case OES_IOC_GET_JAIL_SCOPE:
		return (oes_ioctl_get_jail_scope(ec, td,
		    (struct oes_jail_scope_args *)data));

	case OES_IOC_SET_MODE: {
		return (oes_ioctl_set_mode(ec, (struct oes_mode_args *)data));
	}

	case OES_IOC_GET_MODE: {
		return (oes_ioctl_get_mode(ec, (struct oes_mode_args *)data));
	}

	case OES_IOC_SET_DEADLINE_MAX:
		return (oes_ioctl_set_deadline_bound(ec,
		    (struct oes_event_deadline_args *)data, false));
	case OES_IOC_GET_DEADLINE_MAX:
		return (oes_ioctl_get_deadline_bound(ec,
		    (struct oes_event_deadline_args *)data, false));
	case OES_IOC_SET_DEADLINE_MIN:
		return (oes_ioctl_set_deadline_bound(ec,
		    (struct oes_event_deadline_args *)data, true));
	case OES_IOC_GET_DEADLINE_MIN:
		return (oes_ioctl_get_deadline_bound(ec,
		    (struct oes_event_deadline_args *)data, true));

	case OES_IOC_MUTE_PROCESS: {
		return (oes_ioctl_mute_process(ec, (struct oes_mute_args *)data));
	}

	case OES_IOC_UNMUTE_PROCESS: {
		return (oes_ioctl_unmute_process(ec, (struct oes_mute_args *)data));
	}

	case OES_IOC_MUTE_PATH: {
		return (oes_ioctl_mute_path(ec,
		    (struct oes_mute_path_args *)data));
	}

	case OES_IOC_UNMUTE_PATH: {
		return (oes_ioctl_unmute_path(ec,
		    (struct oes_mute_path_args *)data));
	}

	case OES_IOC_JOIN:
		oes_client_join(ec, td, td->td_fpop, OES_JOIN_CHECK);
		return (0);

#ifdef MAC_CAPABILITY_TEST_PERMISSIVE
	case OES_IOC_TEST_READER_ENTRIES:
		return (oes_client_test_reader_entries(ec,
		    (struct oes_test_reader_entries *)data));
#endif

	case OES_IOC_SET_MUTE_INVERT: {
		return (oes_ioctl_set_mute_invert(ec,
		    (struct oes_mute_invert_args *)data));
	}

	case OES_IOC_GET_MUTE_INVERT: {
		return (oes_ioctl_get_mute_invert(ec,
		    (struct oes_mute_invert_args *)data));
	}

	case OES_IOC_SET_DEADLINE_MISS_MODE: {
		return (oes_ioctl_set_deadline_miss_mode(ec,
		    (struct oes_deadline_miss_mode_args *)data));
	}

	case OES_IOC_GET_DEADLINE_MISS_MODE: {
		return (oes_ioctl_get_deadline_miss_mode(ec,
		    (struct oes_deadline_miss_mode_args *)data));
	}

	case OES_IOC_CACHE_ADD: {
		return (oes_ioctl_cache_add(ec, (oes_cache_entry_t *)data));
	}

	case OES_IOC_CACHE_REMOVE: {
		return (oes_ioctl_cache_remove(ec, (oes_cache_key_t *)data));
	}

	case OES_IOC_CACHE_CLEAR:
		return (oes_ioctl_cache_clear(ec));

	case OES_IOC_GET_STATS: {
		return (oes_ioctl_get_stats(ec, (struct oes_stats *)data));
	}

	case OES_IOC_MUTE_PROCESS_EVENTS: {
		return (oes_ioctl_mute_process_events(ec,
		    (struct oes_mute_process_events_args *)data));
	}

	case OES_IOC_UNMUTE_PROCESS_EVENTS: {
		return (oes_ioctl_unmute_process_events(ec,
		    (struct oes_mute_process_events_args *)data));
	}

	case OES_IOC_MUTE_PATH_EVENTS: {
		return (oes_ioctl_mute_path_events(ec,
		    (struct oes_mute_path_events_args *)data));
	}

	case OES_IOC_UNMUTE_PATH_EVENTS: {
		return (oes_ioctl_unmute_path_events(ec,
		    (struct oes_mute_path_events_args *)data));
	}

	case OES_IOC_GET_MUTED_PROCESSES: {
		return (oes_ioctl_get_muted_processes(ec,
		    (struct oes_get_muted_processes_args *)data));
	}

	case OES_IOC_GET_MUTED_PATHS: {
		return (oes_ioctl_get_muted_paths(ec,
		    (struct oes_get_muted_paths_args *)data));
	}

	case OES_IOC_UNMUTE_ALL_PROCESSES:
		return (oes_ioctl_unmute_all_processes(ec));

	case OES_IOC_UNMUTE_ALL_PATHS:
		return (oes_ioctl_unmute_all_paths(ec, false));

	case OES_IOC_UNMUTE_ALL_TARGET_PATHS:
		return (oes_ioctl_unmute_all_paths(ec, true));

	case OES_IOC_MUTE_UID: {
		struct oes_mute_uid_args *args =
		    (struct oes_mute_uid_args *)data;
		return (oes_client_mute_uid(ec, args->emu_uid));
	}

	case OES_IOC_UNMUTE_UID: {
		struct oes_mute_uid_args *args =
		    (struct oes_mute_uid_args *)data;
		return (oes_client_unmute_uid(ec, args->emu_uid));
	}

	case OES_IOC_MUTE_GID: {
		struct oes_mute_gid_args *args =
		    (struct oes_mute_gid_args *)data;
		return (oes_client_mute_gid(ec, args->emg_gid));
	}

	case OES_IOC_UNMUTE_GID: {
		struct oes_mute_gid_args *args =
		    (struct oes_mute_gid_args *)data;
		return (oes_client_unmute_gid(ec, args->emg_gid));
	}

	case OES_IOC_UNMUTE_ALL_UIDS:
		oes_client_unmute_all_uids(ec);
		return (0);

	case OES_IOC_UNMUTE_ALL_GIDS:
		oes_client_unmute_all_gids(ec);
		return (0);

	case FIONBIO:
	case FIOASYNC:
		/* Handled by upper layers */
		return (0);

	case FIONREAD: {
		int *nread = (int *)data;

		EC_LOCK(ec);
		*nread = ec->ec_queue_bytes;
		EC_UNLOCK(ec);
		return (0);
	}

	default:
		return (ENOTTY);
	}
}

/*
 * oes_poll - Poll for events
 */
static int
oes_poll(struct cdev *dev, int events, struct thread *td)
{
	struct oes_client *ec;
	int revents = 0;
	int error;

	if (oes_thread_is_ilp32(td))
		return (POLLERR);
	error = devfs_get_cdevpriv((void **)&ec);
	if (error)
		return (POLLNVAL);
	oes_client_join(ec, td, td->td_fpop, OES_JOIN_READ);

	EC_LOCK(ec);

	if (events & (POLLIN | POLLRDNORM)) {
		if (!TAILQ_EMPTY(&ec->ec_pending) ||
		    oes_client_lost_pending(ec))
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(td, &ec->ec_selinfo);
	}

	/* Always writable (responses don't block) */
	if (events & (POLLOUT | POLLWRNORM))
		revents |= events & (POLLOUT | POLLWRNORM);

	if (ec->ec_flags & EC_FLAG_CLOSING)
		revents |= POLLHUP;
	/* The jail of a jail-scoped client is gone; see oes_read(). */
	if ((ec->ec_jail_flags & OES_JAIL_SCOPE_DEAD) != 0)
		revents |= POLLHUP;

	EC_UNLOCK(ec);

	return (revents);
}

/*
 * oes_kqfilter - Kqueue filter attachment
 */
static int
oes_kqfilter(struct cdev *dev, struct knote *kn)
{
	struct oes_client *ec;
	int error;

	if (oes_thread_is_ilp32(curthread))
		return (EOPNOTSUPP);
	error = devfs_get_cdevpriv((void **)&ec);
	if (error)
		return (error);

	switch (kn->kn_filter) {
	case EVFILT_READ:
		/* Registering for events makes a reader, as reading does. */
		oes_client_join(ec, curthread, curthread->td_fpop,
		    OES_JOIN_READ);
		kn->kn_fop = &oes_rfiltops;
		kn->kn_hook = ec;
		EC_LOCK(ec);
		knlist_add(&ec->ec_selinfo.si_note, kn, 1);
		EC_UNLOCK(ec);
		return (0);

	default:
		return (EINVAL);
	}
}

static void
oes_kqdetach(struct knote *kn)
{
	struct oes_client *ec = kn->kn_hook;

	/*
	 * f_detach is called from knote_drop WITHOUT the knlist lock.
	 * Use islocked=0 so knlist_remove acquires ec_mtx internally.
	 */
	knlist_remove(&ec->ec_selinfo.si_note, kn, 0);
}

static int
oes_kqread(struct knote *kn, long hint)
{
	struct oes_client *ec = kn->kn_hook;

	/*
	 * Called from KNOTE_LOCKED / kqueue_scan with ec_mtx already held
	 * (registered via knlist_init_mtx). Must NOT reacquire.
	 */
	EC_LOCK_ASSERT(ec);
	kn->kn_data = ec->ec_queue_bytes;
	if ((ec->ec_jail_flags & OES_JAIL_SCOPE_DEAD) != 0) {
		kn->kn_flags |= EV_EOF;
		return (1);
	}
	if (oes_client_lost_pending(ec)) {
		/* The marker is read first, alone. */
		kn->kn_data = sizeof(oes_message_t);
		return (1);
	}
	return (!TAILQ_EMPTY(&ec->ec_pending));
}

/*
 * OES starts in two steps.  At SI_SUB_MAC_POLICY, before the framework's
 * late boundary, oes_policy_sysinit() builds every piece of state a hook can
 * reach and registers the MAC policy, which then sits on the framework's
 * static list like any policy present at boot: its walks take no lock and
 * do not pin the calling thread.  The hooks start idle (no client can
 * exist yet) and inert (sc_active is false).  At SI_SUB_DRIVERS the module
 * handler starts what needs the system further up: the delivery thread,
 * the device, the jail methods and the event handlers, and only then makes
 * OES active.  OES never unloads.
 */
static bool oes_policy_registered;

/* The state the hooks reach: everything but the thread and the device. */
static void
oes_dev_state_init(void)
{
	bzero(&oes_softc, sizeof(oes_softc));

	mtx_init(&oes_softc.sc_mtx, "oes", NULL, MTX_DEF);
	LIST_INIT(&oes_softc.sc_clients);
	oes_softc.sc_next_msg_id = 1;
	oes_softc.sc_next_client_id = 1;

	/* Jail-scoped clients. */
	rm_init(&oes_softc.sc_jail_lock, "oes_jail");
	LIST_INIT(&oes_softc.sc_jail_clients);
	oes_softc.sc_jail_filtered = counter_u64_alloc(M_WAITOK);
	oes_softc.sc_jail_filtered_auth = counter_u64_alloc(M_WAITOK);
	oes_softc.sc_excluded_skipped = counter_u64_alloc(M_WAITOK);
	oes_softc.sc_excluded_invalidations = counter_u64_alloc(M_WAITOK);
	oes_softc.sc_exec_fail_open = counter_u64_alloc(M_WAITOK);

	/* Idle gating; oes_mac_policy_init() computes the first liveness. */
	sx_init(&oes_softc.sc_gate_sx, "oes gate");
	oes_softc.sc_gate_passes = counter_u64_alloc(M_WAITOK);

	/* Deferred NOSLEEP notify delivery; its thread starts in attach. */
	mtx_init(&oes_softc.sc_defer_mtx, "oes_defer", NULL, MTX_SPIN);
	TAILQ_INIT(&oes_softc.sc_defer);
	oes_softc.sc_defer_count = 0;
	oes_defer_bound_init();
	TASK_INIT(&oes_softc.sc_defer_task, 0, oes_defer_task_fn, NULL);
}

static void
oes_policy_sysinit(void *arg __unused)
{

	/* A load after boot is refused by oes_modevent(). */
	if (!cold)
		return;
	oes_dev_state_init();
	if (oes_mac_policy_init() == 0)
		oes_policy_registered = true;
}
SYSINIT(oes_policy, SI_SUB_MAC_POLICY, SI_ORDER_MIDDLE, oes_policy_sysinit,
    NULL);

/* The delivery thread and the device; then OES is active. */
int
oes_dev_attach(void)
{

	/*
	 * Dedicated worker thread for deferred NOSLEEP event delivery.  A
	 * private taskqueue keeps delivery latency low and bounded: notify
	 * events queued from non-sleepable contexts are drained promptly by a
	 * dedicated thread rather than contending with unrelated work on the
	 * shared taskqueue_thread, which was observed to stall deferred delivery
	 * long enough for observers to miss events under load.
	 *
	 * User threads produce the events and set their volume, so the thread
	 * is a timeshare thread starting at PUSER, the priority every user
	 * thread starts from, not above its producers.  Woken, it does not
	 * preempt a producer on that producer's CPU, and oes_defer_task_fn()
	 * moves it to the timeshare priority the scheduler computes for it
	 * whenever the scheduler ends its slice.  Under a storm the queue
	 * then fills and events beyond its byte bound (defer_max_bytes) are
	 * discarded and counted in es_nosleep_drops (oes(4)).
	 */
	oes_softc.sc_defer_tq = taskqueue_create("oes_deferq", M_WAITOK,
	    taskqueue_thread_enqueue, &oes_softc.sc_defer_tq);
	taskqueue_start_threads(&oes_softc.sc_defer_tq, 1, PUSER,
	    "oes_deferq");

	oes_softc.sc_cdev = make_dev(&oes_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "oes");
	if (oes_softc.sc_cdev == NULL) {
		/* Cold and inactive: nothing has queued to the thread. */
		taskqueue_free(oes_softc.sc_defer_tq);
		oes_softc.sc_defer_tq = NULL;
		return (ENXIO);
	}

	oes_softc.sc_active = true;

	printf("oes: Endpoint Security Capabilities device created\n");

	return (0);
}

/*
 * Module event handler
 */
static int
oes_modevent(module_t mod, int type, void *data)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		if (!cold) {
			printf("oes: cannot be loaded after boot\n");
			error = EBUSY;
			break;
		}
		if (!oes_policy_registered) {
			/* oes_mac_policy_init() said why. */
			error = ENXIO;
			break;
		}
		/*
		 * On failure the policy stays registered, idle and inert: a
		 * static policy is never unregistered, and with sc_active
		 * false its hooks do nothing.
		 */
		error = oes_dev_attach();
		if (error == 0)
			error = oes_mac_attach();
		break;

	case MOD_UNLOAD:
		/*
		 * OES never unloads (owner decision 2026-11-15).  Hooks, tables
		 * and locks are permanent; oes_gate_reconcile() relies on it.
		 */
		error = EBUSY;
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

static moduledata_t oes_mod = {
	"oes",
	oes_modevent,
	NULL
};

DECLARE_MODULE(oes, oes_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(oes, 1);
/*
 * Depend on the exact MAC framework ABI this policy was built against.  The
 * framework registers kernel_mac_support at MODULE_VERSION == MAC_VERSION, so
 * pinning to MAC_VERSION both fixes loading (it was hardcoded to a stale 6; the
 * framework is now at 9) and forces a rebuild/re-review if the MAC ABI changes.
 */
MODULE_DEPEND(oes, kernel_mac_support, MAC_VERSION, MAC_VERSION, MAC_VERSION);
#ifdef DEV_DQ
/*
 * oes_fill_file_presented() calls dq_file_ident(); a kernel configured
 * without the dq device compiles the call out and takes no dependency.
 */
MODULE_DEPEND(oes, dq, 1, 1, 1);
#endif
