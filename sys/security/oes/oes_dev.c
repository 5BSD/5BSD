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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/filio.h>
#include <sys/resourcevar.h>
#include <sys/poll.h>
#include <sys/selinfo.h>
#include <sys/capsicum.h>
#include <sys/priv.h>
#include <sys/sysctl.h>

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

int oes_default_deadline_miss_mode = OES_DEADLINE_MISS_FAIL_OPEN;
SYSCTL_INT(_security_oes, OID_AUTO, default_deadline_miss_mode, CTLFLAG_RW,
    &oes_default_deadline_miss_mode, 0,
    "Default AUTH deadline miss mode (0=fail open, 1=fail closed)");

int oes_auth_fail_closed = 0;
SYSCTL_INT(_security_oes, OID_AUTO, auth_fail_closed, CTLFLAG_RW,
    &oes_auth_fail_closed, 0,
    "Deny AUTH operations when OES cannot allocate or deliver required state");

int oes_require_auth_clients = 0;
SYSCTL_INT(_security_oes, OID_AUTO, require_auth_clients, CTLFLAG_RW,
    &oes_require_auth_clients, 0,
    "Deny AUTH operations when no AUTH client is consulted");

int oes_default_queue_size = OES_DEFAULT_QUEUE_SIZE;
SYSCTL_INT(_security_oes, OID_AUTO, default_queue_size, CTLFLAG_RW,
    &oes_default_queue_size, 0, "Default event queue size per client");

int oes_max_clients = 64;
SYSCTL_INT(_security_oes, OID_AUTO, max_clients, CTLFLAG_RW,
    &oes_max_clients, 0, "Maximum number of concurrent clients");

int oes_cache_max_entries = 1024;
SYSCTL_INT(_security_oes, OID_AUTO, cache_max_entries, CTLFLAG_RW,
    &oes_cache_max_entries, 0, "Maximum decision cache entries per client");

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

int oes_default_self_mute = 1;
SYSCTL_INT(_security_oes, OID_AUTO, default_self_mute, CTLFLAG_RW,
    &oes_default_self_mute, 0, "Automatically self-mute new clients (1=yes)");

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
oes_open(struct cdev *dev __unused, int oflags __unused, int devtype __unused,
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
	oes_softc.sc_nclients++;
	OES_UNLOCK();

	/* Allocate client state */
	ec = oes_client_alloc();
	if (ec == NULL) {
		OES_LOCK();
		oes_softc.sc_nclients--;
		OES_UNLOCK();
		return (ENOMEM);
	}

	OES_LOCK();
	ec->ec_id = oes_softc.sc_next_client_id++;
	OES_UNLOCK();

	/* Record owner identity for self-mute */
	PROC_LOCK(td->td_proc);
	ec->ec_owner_pid = td->td_proc->p_pid;
	if (td->td_proc->p_stats != NULL) {
		/* Must match oes_proc_genid() formula: sec*1000000 + usec */
		ec->ec_owner_genid =
		    (uint64_t)td->td_proc->p_stats->p_start.tv_sec * 1000000ULL +
		    (uint64_t)td->td_proc->p_stats->p_start.tv_usec;
	}
	PROC_UNLOCK(td->td_proc);

	/* Store client in cdevpriv for later retrieval */
	error = devfs_set_cdevpriv(ec, oes_client_dtor);
	if (error) {
		oes_client_free(ec);
		OES_LOCK();
		oes_softc.sc_nclients--;
		OES_UNLOCK();
		return (error);
	}

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

	if (ec == NULL)
		return;

	OES_DEBUG("client %p closing", ec);

	/* Mark as closing to reject new events */
	EC_LOCK(ec);
	ec->ec_flags |= EC_FLAG_CLOSING;
	EC_UNLOCK(ec);

	/* Remove from global list */
	OES_LOCK();
	LIST_REMOVE(ec, ec_link);
	oes_softc.sc_nclients--;
	OES_UNLOCK();

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

	EC_LOCK(ec);

	/* Wait for events if queue is empty */
	while (TAILQ_EMPTY(&ec->ec_pending)) {
		if (ec->ec_flags & EC_FLAG_CLOSING) {
			EC_UNLOCK(ec);
			return (ENXIO);
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

	/* Skip expired AUTH events at head of queue */
	for (;;) {
		ep = oes_event_dequeue(ec);
		KASSERT(ep != NULL, ("oes_read: dequeue returned NULL"));

		if (OES_EVENT_IS_AUTH(ep->ep_msg.em_event) &&
		    (ep->ep_flags & EP_FLAG_EXPIRED)) {
			EC_UNLOCK(ec);
			oes_pending_rele(ep);
			EC_LOCK(ec);

			if (TAILQ_EMPTY(&ec->ec_pending)) {
				if (ec->ec_flags & EC_FLAG_CLOSING) {
					EC_UNLOCK(ec);
					return (ENXIO);
				}
				if (ioflag & O_NONBLOCK) {
					EC_UNLOCK(ec);
					return (EAGAIN);
				}
				error = msleep(&ec->ec_pending, &ec->ec_mtx,
				    PCATCH, "oesrd", 0);
				if (error) {
					EC_UNLOCK(ec);
					return (error);
				}
			}
			continue;
		}
		break;
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
	struct oes_mute_entry *em, *em_tmp;
	pid_t mypid;

	if (args == NULL || (args->emu_flags & ~OES_MUTE_SELF) != 0)
		return (EINVAL);

	/* Self-unmute: clear the self-mute flag AND remove list entry */
	if (args->emu_flags & OES_MUTE_SELF) {
		/*
		 * Use ec_owner_pid, not curproc->p_pid, because the fd may
		 * have been passed to another process.  Self-mute is about
		 * the original opener, not the current caller.
		 */
		EC_LOCK(ec);
		mypid = ec->ec_owner_pid;
		ec->ec_flags &= ~EC_FLAG_MUTED_SELF;

		/* Also remove the list entry for self */
		LIST_FOREACH_SAFE(em, &ec->ec_muted[oes_mute_proc_bucket(mypid)],
		    em_link, em_tmp) {
			if (em->em_pid == mypid) {
				LIST_REMOVE(em, em_link);
				free(em, M_OES);
				ec->ec_muted_proc_count--;
				break;
			}
		}

		EC_UNLOCK(ec);
		return (0);
	}

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

	EC_LOCK(ec);

	if (events & (POLLIN | POLLRDNORM)) {
		if (!TAILQ_EMPTY(&ec->ec_pending))
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(td, &ec->ec_selinfo);
	}

	/* Always writable (responses don't block) */
	if (events & (POLLOUT | POLLWRNORM))
		revents |= events & (POLLOUT | POLLWRNORM);

	if (ec->ec_flags & EC_FLAG_CLOSING)
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
	return (!TAILQ_EMPTY(&ec->ec_pending));
}

/*
 * Device initialization
 */
int
oes_dev_init(void)
{
	bzero(&oes_softc, sizeof(oes_softc));

	mtx_init(&oes_softc.sc_mtx, "oes", NULL, MTX_DEF);
	LIST_INIT(&oes_softc.sc_clients);
	oes_softc.sc_next_msg_id = 1;
	oes_softc.sc_next_client_id = 1;

	/* Deferred NOSLEEP notify delivery. */
	mtx_init(&oes_softc.sc_defer_mtx, "oes_defer", NULL, MTX_SPIN);
	TAILQ_INIT(&oes_softc.sc_defer);
	oes_softc.sc_defer_count = 0;
	TASK_INIT(&oes_softc.sc_defer_task, 0, oes_defer_task_fn, NULL);

	/*
	 * Dedicated worker thread for deferred NOSLEEP event delivery.  A
	 * private taskqueue keeps delivery latency low and bounded: notify
	 * events queued from non-sleepable contexts are drained promptly by a
	 * dedicated thread rather than contending with unrelated work on the
	 * shared taskqueue_thread, which was observed to stall deferred delivery
	 * long enough for observers to miss events under load.
	 */
	oes_softc.sc_defer_tq = taskqueue_create("oes_deferq", M_WAITOK,
	    taskqueue_thread_enqueue, &oes_softc.sc_defer_tq);
	taskqueue_start_threads(&oes_softc.sc_defer_tq, 1, PI_SOFT,
	    "oes_deferq");

	oes_softc.sc_cdev = make_dev(&oes_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "oes");
	if (oes_softc.sc_cdev == NULL) {
		taskqueue_free(oes_softc.sc_defer_tq);
		mtx_destroy(&oes_softc.sc_defer_mtx);
		mtx_destroy(&oes_softc.sc_mtx);
		return (ENXIO);
	}

	oes_softc.sc_active = true;

	printf("oes: Endpoint Security Capabilities device created\n");

	return (0);
}

void
oes_dev_uninit(void)
{
	struct oes_client *ec, *ec_tmp;
	int wait_count = 0;

	if (!oes_softc.sc_active && oes_softc.sc_cdev == NULL)
		return;

	oes_softc.sc_active = false;

	/* Wake all clients and mark them as closing */
	OES_LOCK();
	LIST_FOREACH_SAFE(ec, &oes_softc.sc_clients, ec_link, ec_tmp) {
		EC_LOCK(ec);
		ec->ec_flags |= EC_FLAG_CLOSING;
		/* Wake all waiters: msleep, poll/select, and kqueue */
		wakeup(&ec->ec_pending);
		selwakeup(&ec->ec_selinfo);
		KNOTE_LOCKED(&ec->ec_selinfo.si_note, 0);
		EC_UNLOCK(ec);
	}

	/*
	 * Wait for clients to drain. Clients are removed from the list
	 * in oes_client_dtor when their fd is closed. We must wait before
	 * destroying the cdev or mutex to avoid use-after-free.
	 */
	while (oes_softc.sc_nclients > 0 && wait_count < 50) {
		OES_UNLOCK();
		pause("oesdrn", hz / 10);  /* 100ms */
		wait_count++;
		OES_LOCK();
	}

	if (oes_softc.sc_nclients > 0) {
		printf("oes: warning: %u clients still open after 5s\n",
		    oes_softc.sc_nclients);
	}
	OES_UNLOCK();

	if (oes_softc.sc_cdev != NULL) {
		destroy_dev(oes_softc.sc_cdev);
		oes_softc.sc_cdev = NULL;
	}

	printf("oes: device destroyed\n");

	/*
	 * Deferred delivery: sc_active is false so no new events are queued.
	 * Drain the task, then release anything still on the deferred list.
	 */
	taskqueue_drain(oes_softc.sc_defer_tq, &oes_softc.sc_defer_task);
	taskqueue_free(oes_softc.sc_defer_tq);
	{
		struct oes_pending *ep;

		mtx_lock_spin(&oes_softc.sc_defer_mtx);
		while ((ep = TAILQ_FIRST(&oes_softc.sc_defer)) != NULL) {
			TAILQ_REMOVE(&oes_softc.sc_defer, ep, ep_link);
			oes_softc.sc_defer_count--;
			mtx_unlock_spin(&oes_softc.sc_defer_mtx);
			oes_pending_rele(ep);
			mtx_lock_spin(&oes_softc.sc_defer_mtx);
		}
		mtx_unlock_spin(&oes_softc.sc_defer_mtx);
	}
	mtx_destroy(&oes_softc.sc_defer_mtx);

	mtx_destroy(&oes_softc.sc_mtx);
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
		error = oes_dev_init();
		if (error != 0)
			break;
		error = oes_mac_init();
		if (error != 0) {
			oes_dev_uninit();
			break;
		}
		break;

	case MOD_UNLOAD:
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
