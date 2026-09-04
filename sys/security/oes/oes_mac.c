/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * Open Endpoint Security (OES) - MAC Policy Integration
 *
 * This file hooks into the FreeBSD MAC framework to generate
 * security events for subscribed clients.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/refcount.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/namei.h>
#include <sys/imgact.h>
#include <sys/sysctl.h>
#include <sys/random.h>
#include <sys/fcntl.h>
#include <sys/eventhandler.h>
#include <sys/acl.h>
#include <sys/dirent.h>
#include <sys/extattr.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/sdt.h>
#include <sys/pipe.h>
#include <sys/priv.h>
#include <netinet/in.h>
#include <sys/un.h>

#include <security/mac/mac_policy.h>
#include <security/audit/audit.h>

#include <security/oes/oes.h>
#include <security/oes/oes_internal.h>

/* DTrace probes defined in oes_event.c */
SDT_PROBE_DECLARE(oes, , , auth__allow);
SDT_PROBE_DECLARE(oes, , , auth__deny);

MALLOC_DECLARE(M_OES);

/*
 * Per-credential label: stores execution identity and immutable path metadata.
 *
 * The exec_id is a 64-bit random value that:
 * - Stays the same across fork() (inherited by child via cred_copy_label)
 * - Changes on exec() (new random value in vnode_execve_relabel)
 *
 * This allows tracking process lineage and detecting when
 * the actual executable code changes.
 */
struct oes_exec_meta {
	u_int		eem_refcount;
	uint32_t	eem_flags;
	char		eem_path[];
};

#define OES_EXEC_META_PATH_TRUNCATED	0x00000001

struct oes_scope_meta {
	u_int		esm_refcount;
	uint8_t		esm_count;
	uint64_t	esm_markers[OES_SCOPE_MARKERS_MAX];
};

struct oes_cred_label {
	uint64_t	ecl_exec_id;	/* Execution ID */
	struct oes_exec_meta *ecl_exec_meta; /* Shared across credential copies */
	struct oes_scope_meta *ecl_scope_meta; /* Immutable inherited scopes */
};

struct oes_pipe_label {
	uint64_t	epl_id;		/* Opaque identifier; never a kernel address */
};

static int oes_slot;		/* MAC label slot for our data */
static bool oes_mac_registered;	/* Track if MAC policy is registered */
static struct mtx oes_rename_mtx;

static void
oes_scope_meta_hold(struct oes_scope_meta *meta)
{
	if (meta != NULL)
		atomic_add_int(&meta->esm_refcount, 1);
}

static void
oes_scope_meta_rele(struct oes_scope_meta *meta)
{
	if (meta != NULL && atomic_fetchadd_int(&meta->esm_refcount, -1) == 1)
		free(meta, M_OES);
}

struct oes_rename_ctx {
	LIST_ENTRY(oes_rename_ctx) er_link;
	lwpid_t			er_tid;
	pid_t			er_pid;
	time_t			er_time;	/* creation time for gc */
	oes_file_t		er_src_dir;
	oes_file_t		er_src_file;
	char			er_src_dir_path[MAXPATHLEN];
	char			er_src_file_path[MAXPATHLEN];
	char			er_src_name[MAXNAMLEN + 1];
};

/* Entries older than this (in seconds) are garbage collected */
#define OES_RENAME_CACHE_MAX_AGE	60

static LIST_HEAD(, oes_rename_ctx) oes_rename_list =
    LIST_HEAD_INITIALIZER(oes_rename_list);

#define SLOT(l)	((struct oes_cred_label *)mac_label_get((l), oes_slot))
#define SLOT_SET(l, v) mac_label_set((l), oes_slot, (uintptr_t)(v))
#define PIPE_SLOT(l) \
	((struct oes_pipe_label *)mac_label_get((l), oes_slot))

/* Forward declarations for socket helpers */
static void oes_fill_sockaddr(oes_sockaddr_t *esa, const struct sockaddr *sa);
static void oes_fill_socket_info(oes_socket_t *es, struct socket *so);

static __inline uint64_t
oes_generate_exec_id(void)
{
	uint64_t id;

	arc4random_buf(&id, sizeof(id));
	return (id);
}

static struct oes_exec_meta *
oes_exec_meta_alloc(const char *path)
{
	struct oes_exec_meta *meta;
	size_t len, alloc_size;
	bool truncated;

	if (path == NULL || path[0] == '\0')
		return (NULL);
	len = strnlen(path, MAXPATHLEN);
	truncated = len == MAXPATHLEN;
	if (truncated)
		len = MAXPATHLEN - 1;
	alloc_size = offsetof(struct oes_exec_meta, eem_path) + len + 1;
	meta = malloc(alloc_size, M_OES, M_NOWAIT | M_ZERO);
	if (meta == NULL)
		return (NULL);
	refcount_init(&meta->eem_refcount, 1);
	if (truncated)
		meta->eem_flags |= OES_EXEC_META_PATH_TRUNCATED;
	memcpy(meta->eem_path, path, len);
	meta->eem_path[len] = '\0';
	return (meta);
}

static void
oes_exec_meta_hold(struct oes_exec_meta *meta)
{

	if (meta != NULL)
		refcount_acquire(&meta->eem_refcount);
}

static void
oes_exec_meta_rele(struct oes_exec_meta *meta)
{

	if (meta != NULL && refcount_release(&meta->eem_refcount))
		free(meta, M_OES);
}

static void
oes_mac_pipe_init_label(struct label *label)
{
	struct oes_pipe_label *epl;

	epl = malloc(sizeof(*epl), M_OES, M_NOWAIT | M_ZERO);
	if (epl != NULL) {
		do {
			arc4random_buf(&epl->epl_id, sizeof(epl->epl_id));
		} while (epl->epl_id == 0);
	}
	SLOT_SET(label, epl);
}

static void
oes_mac_pipe_destroy_label(struct label *label)
{
	struct oes_pipe_label *epl;

	epl = PIPE_SLOT(label);
	if (epl != NULL) {
		free(epl, M_OES);
		SLOT_SET(label, NULL);
	}
}

static void
oes_mac_pipe_copy_label(struct label *src, struct label *dst)
{
	struct oes_pipe_label *src_epl, *dst_epl;

	src_epl = PIPE_SLOT(src);
	dst_epl = PIPE_SLOT(dst);
	if (src_epl != NULL && dst_epl != NULL)
		dst_epl->epl_id = src_epl->epl_id;
}

uint64_t
oes_proc_get_exec_id(struct proc *p)
{
	struct ucred *cred;
	struct oes_cred_label *ecl;

	PROC_LOCK_ASSERT(p, MA_OWNED);

	cred = p->p_ucred;
	if (cred == NULL || cred->cr_label == NULL)
		return (0);

	ecl = SLOT(cred->cr_label);
	if (ecl == NULL)
		return (0);

	return (ecl->ecl_exec_id);
}

const char *
oes_proc_get_exec_path(struct proc *p, uint32_t *meta_flags)
{
	struct oes_cred_label *ecl;
	struct oes_exec_meta *meta;
	struct ucred *cred;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	if (meta_flags != NULL)
		*meta_flags = 0;
	cred = p->p_ucred;
	if (cred == NULL || cred->cr_label == NULL)
		return (NULL);
	ecl = SLOT(cred->cr_label);
	if (ecl == NULL || ecl->ecl_exec_meta == NULL)
		return (NULL);
	meta = ecl->ecl_exec_meta;
	if (meta_flags != NULL &&
	    (meta->eem_flags & OES_EXEC_META_PATH_TRUNCATED) != 0)
		*meta_flags |= OES_PROC_META_PATH_TRUNCATED;
	return (meta->eem_path);
}

/* MAC hook: allocate label for new credential */
static void
oes_mac_cred_init_label(struct label *label)
{
	struct oes_cred_label *ecl;

	if (label == NULL)
		return;

	if (!oes_mac_registered) {
		SLOT_SET(label, NULL);
		return;
	}

	ecl = malloc(sizeof(*ecl), M_OES, M_NOWAIT | M_ZERO);
	if (ecl != NULL)
		ecl->ecl_exec_id = oes_generate_exec_id();
	SLOT_SET(label, ecl);
}

/* MAC hook: free label from credential */
static void
oes_mac_cred_destroy_label(struct label *label)
{
	struct oes_cred_label *ecl;

	if (label == NULL)
		return;

	ecl = SLOT(label);
	if (ecl != NULL) {
		oes_exec_meta_rele(ecl->ecl_exec_meta);
		oes_scope_meta_rele(ecl->ecl_scope_meta);
		free(ecl, M_OES);
		SLOT_SET(label, NULL);
	}
}

/* MAC hook: copy label (preserves exec_id across fork) */
static void
oes_mac_cred_copy_label(struct label *src, struct label *dst)
{
	struct oes_cred_label *src_ecl, *dst_ecl;

	if (src == NULL || dst == NULL)
		return;

	src_ecl = SLOT(src);
	dst_ecl = SLOT(dst);

	if (src_ecl != NULL && dst_ecl != NULL) {
		oes_exec_meta_hold(src_ecl->ecl_exec_meta);
		oes_exec_meta_rele(dst_ecl->ecl_exec_meta);
		dst_ecl->ecl_exec_id = src_ecl->ecl_exec_id;
		dst_ecl->ecl_exec_meta = src_ecl->ecl_exec_meta;
		oes_scope_meta_hold(src_ecl->ecl_scope_meta);
		oes_scope_meta_rele(dst_ecl->ecl_scope_meta);
		dst_ecl->ecl_scope_meta = src_ecl->ecl_scope_meta;
	}
}

/*
 * Anchor a descendants client in a private copy of the caller's credential.
 * Fork and exec credential-label copying then propagate this opaque marker
 * without walking the process tree from arbitrary MAC hook lock contexts.
 */
int
oes_scope_mark_current(pid_t owner_pid, uint64_t *markerp)
{
	struct oes_cred_label *ecl;
	struct oes_scope_meta *meta, *oldmeta;
	struct ucred *newcred, *oldcred;
	struct proc *p;
	uint64_t marker;

	p = curthread->td_proc;
	if (p == NULL || p->p_pid != owner_pid || markerp == NULL)
		return (EPERM);
	newcred = crget();
	meta = malloc(sizeof(*meta), M_OES, M_WAITOK | M_ZERO);
	meta->esm_refcount = 1;
	PROC_LOCK(p);
	oldcred = crcopysafe(p, newcred);
	ecl = SLOT(newcred->cr_label);
	oldmeta = ecl != NULL ? ecl->ecl_scope_meta : NULL;
	if (ecl == NULL || (oldmeta != NULL &&
	    oldmeta->esm_count == OES_SCOPE_MARKERS_MAX)) {
		PROC_UNLOCK(p);
		crfree(newcred);
		oes_scope_meta_rele(meta);
		return (ecl == NULL ? ENOMEM : ENOSPC);
	}
	do {
		arc4random_buf(&marker, sizeof(marker));
	} while (marker == 0);
	if (oldmeta != NULL) {
		meta->esm_count = oldmeta->esm_count;
		memcpy(meta->esm_markers, oldmeta->esm_markers,
		    sizeof(meta->esm_markers));
	}
	meta->esm_markers[meta->esm_count++] = marker;
	ecl->ecl_scope_meta = meta;
	oes_scope_meta_rele(oldmeta);
	proc_set_cred(p, newcred);
	PROC_UNLOCK(p);
	crfree(oldcred);
	*markerp = marker;
	return (0);
}

void
oes_scope_snapshot(struct oes_pending *ep)
{
	struct oes_cred_label *ecl;
	struct oes_scope_meta *meta;
	struct ucred *cred;

	if (curthread == NULL || curthread->td_ucred == NULL)
		return;
	cred = curthread->td_ucred;
	if (cred->cr_label == NULL)
		return;
	ecl = SLOT(cred->cr_label);
	if (ecl == NULL || ecl->ecl_scope_meta == NULL)
		return;
	meta = ecl->ecl_scope_meta;
	ep->ep_scope_count = meta->esm_count;
	memcpy(ep->ep_scope_markers, meta->esm_markers,
	    sizeof(ep->ep_scope_markers));
}

/* Refresh the OES identity on every successful exec, including non-setid. */
static int
oes_mac_vnode_execve_will_relabel(struct ucred *old, struct vnode *vp,
    struct label *vplabel, struct label *interpvplabel,
    struct image_params *imgp, struct label *execlabel)
{

	(void)old;
	(void)vp;
	(void)vplabel;
	(void)interpvplabel;
	(void)imgp;
	(void)execlabel;
	return (1);
}

static void
oes_mac_vnode_execve_relabel(struct ucred *old, struct ucred *new,
    struct vnode *vp, struct label *vplabel, struct label *interpvplabel,
    struct image_params *imgp, struct label *execlabel)
{
	struct oes_cred_label *ecl;
	struct oes_exec_meta *new_meta, *old_meta;
	struct label *label;

	(void)old;
	(void)vp;
	(void)vplabel;
	(void)interpvplabel;
	(void)execlabel;
	label = new->cr_label;
	if (label == NULL)
		return;

	ecl = SLOT(label);
	if (ecl != NULL) {
		new_meta = oes_exec_meta_alloc(imgp != NULL ? imgp->execpath : NULL);
		old_meta = ecl->ecl_exec_meta;
		ecl->ecl_exec_meta = new_meta;
		ecl->ecl_exec_id = oes_generate_exec_id();
		oes_exec_meta_rele(old_meta);
		OES_DEBUG("exec: new exec_id %llu for pid %d",
		    (unsigned long long)ecl->ecl_exec_id, curproc->p_pid);
	}
}

struct oes_vnode_event_info {
	struct ucred		*cred;
	struct vnode		*vp;
	struct vnode		*dvp;
	struct componentname	*cnp;
	struct vattr		*vap;
	struct proc		*target_proc;
	struct oes_rename_ctx	*rename_ctx;
	struct socket		*socket;
	struct sockaddr		*sockaddr;
	accmode_t		accmode;
	int			prot;
	int			mmap_flags;
	int			attrnamespace;
	const char		*attrname;
	acl_type_t		acl_type;
	int			signum;
	uid_t			uid;
	gid_t			gid;
	mode_t			mode;
	uid_t			owner_uid;
	gid_t			owner_gid;
	u_long			fflags;
	struct timespec		atime;
	struct timespec		mtime;
	int			reboot_howto;
	const char		*sysctl_name;
	int			sysctl_op;
	const char		*kenv_name;
	int			kenv_op;
	int			socket_domain;
	int			socket_type;
	int			socket_protocol;
	struct pipepair		*pipepair;
	uint64_t		pipe_id;
	unsigned long		ioctl_cmd;
	struct mount		*mp;
	int			priv;
	bool			nosleep;	/* Use non-blocking delivery */
};

#define OES_VNODE_INFO_INIT(_cred) \
	((struct oes_vnode_event_info){ .cred = (_cred) })


static void
oes_copy_component(char *dst, size_t dstlen, const struct componentname *cnp)
{
	size_t len;

	if (dstlen == 0) {
		return;
	}
	dst[0] = '\0';

	if (cnp == NULL || cnp->cn_nameptr == NULL || cnp->cn_namelen == 0)
		return;

	len = cnp->cn_namelen;
	if (len >= dstlen)
		len = dstlen - 1;

	memcpy(dst, cnp->cn_nameptr, len);
	dst[len] = '\0';
}

static void
oes_copy_component_path(char *dst, size_t dstlen, const struct componentname *cnp)
{

	if (dstlen == 0)
		return;
	dst[0] = '\0';

	if (cnp == NULL || cnp->cn_pnbuf == NULL || cnp->cn_pnbuf[0] == '\0')
		return;

	strlcpy(dst, cnp->cn_pnbuf, dstlen);
}

static void
oes_build_path(char *dst, size_t dstlen, const char *dir, const char *name)
{
	size_t dlen;

	if (dstlen == 0)
		return;

	dst[0] = '\0';
	if (dir == NULL || dir[0] == '\0') {
		if (name != NULL)
			strlcpy(dst, name, dstlen);
		return;
	}
	if (name == NULL || name[0] == '\0') {
		strlcpy(dst, dir, dstlen);
		return;
	}

	dlen = strlen(dir);
	if (dir[dlen - 1] == '/')
		snprintf(dst, dstlen, "%s%s", dir, name);
	else
		snprintf(dst, dstlen, "%s/%s", dir, name);
}

static void
oes_file_set_resolved_path_off(oes_file_t *file, uint32_t path_off)
{

	file->ef_path_off = path_off;
	if (path_off != 0) {
		file->ef_meta_flags &= ~OES_FILE_META_PATH_UNAVAILABLE;
		file->ef_meta_flags &= ~OES_FILE_META_PATH_REQUESTED;
	}
}

static void
oes_file_set_requested_path_off(oes_file_t *file, uint32_t path_off)
{

	file->ef_path_off = path_off;
	if (path_off != 0) {
		file->ef_meta_flags &= ~OES_FILE_META_PATH_UNAVAILABLE;
		oes_file_mark_path_requested(file);
	}
}

static struct oes_pending *
oes_pending_alloc_notify_from_template(const struct oes_pending *src,
    oes_event_type_t notify_event, oes_auth_result_t result)
{
	struct oes_pending *ep;
	size_t src_msg_size, alloc_size;

	/*
	 * Clone the source message including its string table rather than
	 * allocating a fresh pending (which would only have the process
	 * strings).  The event data contains _off fields that point into
	 * the source's string table, so we must preserve the whole thing.
	 */
	src_msg_size = src->ep_msg.em_size;
	if (src_msg_size < sizeof(oes_message_t))
		src_msg_size = sizeof(oes_message_t);
	alloc_size = offsetof(struct oes_pending, ep_msg) + src_msg_size;

	ep = malloc(alloc_size, M_OES, M_NOWAIT | M_ZERO);
	if (ep == NULL)
		return (NULL);

	ep->ep_refcount = 1;
	ep->ep_scope_count = src->ep_scope_count;
	memcpy(ep->ep_scope_markers, src->ep_scope_markers,
	    sizeof(ep->ep_scope_markers));
	bcopy(&src->ep_msg, &ep->ep_msg, src_msg_size);

	/* Override event type and action for the notify copy */
	ep->ep_msg.em_event = notify_event;
	ep->ep_msg.em_action = OES_ACTION_NOTIFY;
	ep->ep_msg.em_result = result;
	ep->ep_msg.em_flags |= OES_MSG_FLAG_AUTH_RESULT;
	ep->ep_msg.em_id = atomic_fetchadd_64(&oes_softc.sc_next_msg_id, 1);
	ep->ep_msg.em_deadline = (oes_timespec_t){ 0 };

	return (ep);
}

static bool
oes_pending_visible_to_client(const struct oes_pending *ep,
	const struct oes_client *ec)
{
	uint8_t i;

	if (ec->ec_scope == OES_SCOPE_GLOBAL)
		return (true);
	if (ec->ec_scope != OES_SCOPE_DESCENDANTS)
		return (false);
	for (i = 0; i < ep->ep_scope_count; i++) {
		if (ep->ep_scope_markers[i] == ec->ec_scope_marker)
			return (true);
	}
	return (false);
}

/* Forward declaration for per-event path muting */
static bool oes_event_is_path_muted(struct oes_client *ec,
    const struct oes_pending *ep, oes_event_type_t mute_event);

/*
 * Deliver the NOTIFY counterpart only after the combined AUTH decision is
 * known.  This guarantees that em_result is the decision OES actually
 * applied, rather than exposing a pre-decision attempt without an outcome.
 */
static void
oes_dispatch_auth_notification(const struct oes_pending *ep, struct proc *p,
    struct ucred *cred, oes_event_type_t notify_event,
    oes_auth_result_t result)
{
	struct oes_client *ec;
	struct oes_pending *ep_notify;
	oes_event_type_t auth_event;
	oes_event_type_t mute_event;
	bool subscribed;

	if (notify_event == 0)
		return;

	auth_event = ep->ep_msg.em_event;
	OES_LOCK();
	LIST_FOREACH(ec, &oes_softc.sc_clients, ec_link) {
		if (!oes_pending_visible_to_client(ep, ec))
			continue;
		EC_LOCK(ec);
		if (ec->ec_flags & EC_FLAG_CLOSING) {
			EC_UNLOCK(ec);
			continue;
		}

		if (ec->ec_mode == OES_MODE_PASSIVE) {
			subscribed = oes_client_subscribed(ec, auth_event);
			mute_event = auth_event;
		} else if (ec->ec_mode == OES_MODE_NOTIFY ||
		    ec->ec_mode == OES_MODE_AUTH) {
			subscribed = oes_client_subscribed(ec, notify_event);
			mute_event = notify_event;
		} else {
			EC_UNLOCK(ec);
			continue;
		}
		if (!subscribed || oes_client_is_muted(ec, p, mute_event) ||
		    oes_event_is_path_muted(ec, ep, mute_event) ||
		    (cred != NULL &&
		    (oes_client_is_uid_muted(ec, cred->cr_uid) ||
		    oes_client_is_gid_muted(ec, cred->cr_gid)))) {
			EC_UNLOCK(ec);
			continue;
		}

		ep_notify = oes_pending_alloc_notify_from_template(ep,
		    notify_event, result);
		if (ep_notify != NULL) {
			(void)oes_event_enqueue(ec, ep_notify);
			oes_pending_rele(ep_notify);
		} else {
			oes_event_note_drop(ec, notify_event);
			atomic_add_64(&oes_softc.sc_alloc_failures, 1);
		}
		EC_UNLOCK(ec);
	}
	OES_UNLOCK();
}

static int
oes_dispatch_event(struct oes_pending *ep, struct proc *p, struct ucred *cred,
    oes_event_type_t notify_event)
{
	struct oes_client *ec;
	struct oes_pending *ep_client;
	struct oes_auth_group *ag = NULL;
	struct oes_pending **auth_eps = NULL;
	struct oes_pending **auth_clones = NULL;
	size_t auth_count = 0;
	size_t auth_max = 0;
	size_t clone_idx = 0;
	bool auth_consulted = false;
	bool auth_delivery_failed = false;
	bool auth_delivery_fail_closed = false;
	bool is_auth;
	bool cached_denied = false;
	int error = 0;
	oes_event_type_t event;

	event = ep->ep_msg.em_event;
	is_auth = OES_EVENT_IS_AUTH(event);

	if (is_auth) {
		/*
		 * AUTH events can sleep (NOSLEEP hooks are NOTIFY-only).
		 *
		 * Pre-allocate everything with M_WAITOK BEFORE taking any
		 * locks.  This avoids both M_WAITOK-under-mutex warnings
		 * and the silent fail-open when M_NOWAIT fails.
		 *
		 * Size the clone pool to currently subscribed AUTH clients,
		 * then re-check all eligibility while dispatching.  This keeps
		 * memory use bounded by consulted clients instead of every open
		 * fd.  If subscriptions grow between the estimate and dispatch,
		 * the new clients can be served by the next event.
		 */
		for (;;) {
			size_t need, i = 0;

			OES_LOCK();
			need = 0;
			LIST_FOREACH(ec, &oes_softc.sc_clients, ec_link) {
				if (!oes_pending_visible_to_client(ep, ec))
					continue;
				EC_LOCK(ec);
				if ((ec->ec_flags & EC_FLAG_CLOSING) == 0 &&
				    ec->ec_mode == OES_MODE_AUTH &&
				    oes_client_subscribed(ec, event))
					need++;
				EC_UNLOCK(ec);
			}
			if (need == 0) {
				/* No AUTH clients to consult, nothing to pre-allocate */
				break;
			}
			if (need <= auth_max)
				break;
			OES_UNLOCK();

			/* Free old pools if retrying */
			if (auth_eps != NULL)
				free(auth_eps, M_OES);
			if (auth_clones != NULL) {
				for (i = 0; i < auth_max; i++) {
					if (auth_clones[i] != NULL)
						oes_pending_rele(auth_clones[i]);
				}
				free(auth_clones, M_OES);
			}
			if (ag != NULL) {
				oes_auth_group_rele(ag);
				ag = NULL;
			}

			auth_eps = malloc(sizeof(*auth_eps) * need, M_OES,
			    M_WAITOK | M_ZERO);
			auth_clones = malloc(sizeof(*auth_clones) * need, M_OES,
			    M_WAITOK | M_ZERO);
			if (auth_eps != NULL && auth_clones != NULL) {
				for (i = 0; i < need; i++) {
					auth_clones[i] = oes_pending_clone(ep,
					    M_WAITOK);
					if (auth_clones[i] == NULL)
						break;
				}
			}
			ag = oes_auth_group_alloc(M_WAITOK);
			if (auth_eps == NULL || auth_clones == NULL || ag == NULL ||
			    i != need) {
				/*
				 * Do not dereference partially allocated AUTH state.
				 * In fail-closed mode this condition must deny the
				 * authorization rather than silently skipping a client.
				 */
				if (auth_clones != NULL) {
					for (i = 0; i < need; i++) {
						if (auth_clones[i] != NULL)
							oes_pending_rele(auth_clones[i]);
					}
					free(auth_clones, M_OES);
				}
				if (auth_eps != NULL)
					free(auth_eps, M_OES);
				if (ag != NULL)
					oes_auth_group_rele(ag);
				auth_clones = NULL;
				auth_eps = NULL;
				ag = NULL;
				auth_delivery_failed = true;
				OES_LOCK();
				break;
			}
			auth_max = need;
		}
	} else {
		OES_LOCK();
	}

	/* Snapshot the portable equivalent of es_process_t.is_es_client. */
	LIST_FOREACH(ec, &oes_softc.sc_clients, ec_link) {
		if (ec->ec_owner_pid != ep->ep_msg.em_process.ep_pid ||
		    (ec->ec_owner_genid != 0 &&
		    ec->ec_owner_genid !=
		    ep->ep_msg.em_process.ep_token.ept_genid))
			continue;
		ep->ep_msg.em_process.ep_flags |= EP_FLAG_OES_CLIENT;
		if (auth_clones != NULL) {
			for (size_t i = 0; i < auth_max; i++) {
				if (auth_clones[i] != NULL)
					auth_clones[i]->ep_msg.em_process.ep_flags |=
					    EP_FLAG_OES_CLIENT;
			}
		}
		break;
	}

	LIST_FOREACH(ec, &oes_softc.sc_clients, ec_link) {
		oes_event_type_t mute_event;

		if (!oes_pending_visible_to_client(ep, ec))
			continue;
		EC_LOCK(ec);

		if (ec->ec_flags & EC_FLAG_CLOSING) {
			EC_UNLOCK(ec);
			continue;
		}

		/* AUTH clients never authorize their own operations. */
		if (is_auth && ec->ec_mode == OES_MODE_AUTH &&
		    oes_client_subscribed(ec, event) &&
		    ep->ep_msg.em_process.ep_pid == ec->ec_owner_pid &&
		    (ec->ec_owner_genid == 0 ||
		    ep->ep_msg.em_process.ep_token.ept_genid ==
		    ec->ec_owner_genid)) {
			auth_consulted = true; /* Implicit allow, as part of the policy. */
			EC_UNLOCK(ec);
			continue;
		}

		/* NOTIFY clients mute by NOTIFY event type, others by AUTH */
		mute_event = (is_auth && ec->ec_mode == OES_MODE_NOTIFY &&
		    notify_event != 0) ? notify_event : event;

		if (oes_client_is_muted(ec, p, mute_event)) {
			EC_UNLOCK(ec);
			continue;
		}
		if (oes_event_is_path_muted(ec, ep, mute_event)) {
			EC_UNLOCK(ec);
			continue;
		}

		/* Check UID/GID muting */
		if (cred != NULL) {
			if (oes_client_is_uid_muted(ec, cred->cr_uid) ||
			    oes_client_is_gid_muted(ec, cred->cr_gid)) {
				EC_UNLOCK(ec);
				continue;
			}
		}

		if (is_auth) {
			if (ec->ec_mode == OES_MODE_AUTH) {
				uint32_t deadline_ms;
				uint32_t miss_mode = ec->ec_deadline_miss_mode;
				oes_auth_result_t cache_result;

				if (!oes_client_subscribed(ec, event)) {
					EC_UNLOCK(ec);
					continue;
				}
				deadline_ms = oes_client_effective_deadline_locked(ec,
				    event);

				if (oes_client_cache_lookup(ec, ep,
				    &cache_result)) {
					auth_consulted = true;
					if (cache_result == OES_AUTH_DENY)
						cached_denied = true;
					if (cache_result == OES_AUTH_ALLOW)
						ec->ec_auth_allowed++;
					else
						ec->ec_auth_denied++;
					EC_UNLOCK(ec);
					continue;
				}

				/*
				 * Take a pre-allocated clone from the pool.
				 * The pool was sized to the eligible-client estimate, so
				 * this should succeed while the global client lock is held.
				 */
				ep_client = NULL;
				if (clone_idx < auth_max)
					ep_client = auth_clones[clone_idx];
				if (ep_client == NULL) {
					oes_event_note_drop(ec, event);
					auth_delivery_failed = true;
					if (miss_mode == OES_DEADLINE_MISS_FAIL_CLOSED)
						auth_delivery_fail_closed = true;
					EC_UNLOCK(ec);
					continue;
				}
				auth_clones[clone_idx] = NULL; /* taken */
				clone_idx++;

				ep_client->ep_client_id = ec->ec_id;
				ep_client->ep_deadline_miss_mode = miss_mode;
				oes_set_auth_deadline(ep_client, deadline_ms);

				oes_auth_group_hold(ag);
				ep_client->ep_group = ag;
				oes_auth_group_add_pending(ag);

				if (oes_event_enqueue(ec, ep_client) == 0) {
					if (auth_eps != NULL &&
					    auth_count < auth_max)
						auth_eps[auth_count++] = ep_client;
				} else {
					oes_auth_group_cancel_pending(ag);
					oes_pending_rele(ep_client);
					auth_delivery_failed = true;
					if (miss_mode == OES_DEADLINE_MISS_FAIL_CLOSED)
						auth_delivery_fail_closed = true;
				}
				EC_UNLOCK(ec);
				continue;
			}

			EC_UNLOCK(ec);
			continue;
		}

		if (!oes_client_subscribed(ec, event)) {
			EC_UNLOCK(ec);
			continue;
		}

		ep_client = oes_pending_clone(ep, M_NOWAIT);
		if (ep_client != NULL) {
			oes_event_enqueue(ec, ep_client);
			oes_pending_rele(ep_client);
		} else {
			oes_event_note_drop(ec, event);
		}
		EC_UNLOCK(ec);
	}

	OES_UNLOCK();

	/*
	 * Wait for AUTH responses. All AUTH events can sleep
	 * (NOSLEEP hooks are NOTIFY-only now).
	 *
	 * If no AUTH-mode clients were consulted (all skipped due to
	 * allocation failure, muting, or no subscriptions), the event
	 * is implicitly allowed. Log this for observability.
	 */
	if (is_auth && auth_count == 0 && !auth_consulted && !cached_denied) {
		OES_DEBUG("AUTH event 0x%x: no clients consulted, fail-open",
		    event);
		if (oes_require_auth_clients || oes_auth_fail_closed)
			error = EACCES;
	}
	if (is_auth && auth_count > 0 && ag != NULL)
		error = oes_auth_group_wait(ag, auth_eps, auth_count);
	if (is_auth && cached_denied)
		error = EACCES;
	if (is_auth && auth_delivery_failed &&
	    (oes_auth_fail_closed || auth_delivery_fail_closed))
		error = EACCES;

	/*
	 * Check flags-based responses for events that support partial
	 * authorization (OPEN, MMAP, MPROTECT). If a client allowed with
	 * restricted flags, deny if the requested flags exceed what's allowed.
	 */
	if (error == 0 && is_auth && auth_count > 0) {
		uint32_t requested_flags = 0;
		size_t i;

		/* Get requested flags based on event type */
		switch (event) {
		case OES_EVENT_AUTH_OPEN:
			requested_flags = ep->ep_msg.em_event_data.open.access;
			break;
		case OES_EVENT_AUTH_MMAP:
			requested_flags = ep->ep_msg.em_event_data.mmap.prot;
			break;
		case OES_EVENT_AUTH_MPROTECT:
			requested_flags = ep->ep_msg.em_event_data.mprotect.prot;
			break;
		default:
			break;
		}

		/* Check each client's flags-based response */
		for (i = 0; i < auth_count && error == 0; i++) {
			struct oes_pending *ep_auth = auth_eps[i];
			uint32_t allowed, denied;
			bool has_flags;

			if (ep_auth == NULL)
				continue;

			mtx_lock(&ep_auth->ep_mtx);
			allowed = ep_auth->ep_allowed_flags;
			denied = ep_auth->ep_denied_flags;
			has_flags = ep_auth->ep_has_flag_response;
			mtx_unlock(&ep_auth->ep_mtx);
			if (!has_flags)
				continue;

			/*
			 * If client set denied_flags and requested has any
			 * of those flags, deny the operation.
			 */
			if (denied != 0 && (requested_flags & denied) != 0) {
				error = EACCES;
				break;
			}

			/*
			 * If client set allowed_flags (partial allow) and
			 * requested has flags not in allowed set, deny.
			 */
			if (allowed != 0 && (requested_flags & ~allowed) != 0) {
				error = EACCES;
				break;
			}
		}
	}

	/*
	 * Record OES denials in audit records when audit is active.
	 * This adds context to the syscall's audit record indicating
	 * that OES denied the operation.
	 */
	if (error == EACCES) {
		AUDIT_ARG_TEXT("OES: authorization denied");
		SDT_PROBE3(oes, , , auth__deny,
		    ep->ep_msg.em_event,
		    ep->ep_msg.em_process.ep_pid,
		    oes_msg_string(&ep->ep_msg,
		    ep->ep_msg.em_process.ep_path_off));
	}

	if (is_auth)
		oes_dispatch_auth_notification(ep, p, cred, notify_event,
		    error == 0 ? OES_AUTH_ALLOW : OES_AUTH_DENY);

	if (auth_eps != NULL) {
		size_t i;

		for (i = 0; i < auth_count; i++)
			oes_pending_rele(auth_eps[i]);
		free(auth_eps, M_OES);
	}

	/* Free unused pre-allocated clones */
	if (auth_clones != NULL) {
		size_t i;

		for (i = 0; i < auth_max; i++) {
			if (auth_clones[i] != NULL)
				oes_pending_rele(auth_clones[i]);
		}
		free(auth_clones, M_OES);
	}

	if (ag != NULL)
		oes_auth_group_rele(ag);

	return (error);
}

static void
oes_rename_cache_init(void)
{
	mtx_init(&oes_rename_mtx, "oes_rename", NULL, MTX_DEF);
	LIST_INIT(&oes_rename_list);
}

static void
oes_rename_cache_store(struct thread *td,
    const struct oes_vnode_event_info *info)
{
	struct oes_rename_ctx *ctx, *cur, *tmp;
	time_t now;
	bool found_self = false;

	if (info == NULL)
		return;

	ctx = malloc(sizeof(*ctx), M_OES, M_NOWAIT | M_ZERO);
	if (ctx == NULL)
		return;

	now = time_second;
	ctx->er_tid = td->td_tid;
	ctx->er_pid = td->td_proc->p_pid;
	ctx->er_time = now;
	ctx->er_src_dir_path[0] = '\0';
	ctx->er_src_file_path[0] = '\0';
	oes_copy_component_path(ctx->er_src_file_path,
	    sizeof(ctx->er_src_file_path), info->cnp);
	if (ctx->er_src_file_path[0] != '\0')
		oes_file_mark_path_requested(&ctx->er_src_file);
	if (info->dvp != NULL) {
		oes_fill_file(&ctx->er_src_dir, info->dvp, info->cred,
		    NULL, NULL);
		/*
		 * Resolve dir path into context's own buffer.
		 * Guard with VOP_ISLOCKED to avoid deadlock - MAC rename
		 * hooks are called with vnodes locked.
		 */
		if (VOP_ISLOCKED(info->dvp) == 0) {
			char *fp = NULL, *free_fp = NULL;
			if (vn_fullpath(info->dvp, &fp, &free_fp) == 0 &&
			    fp != NULL)
				strlcpy(ctx->er_src_dir_path, fp,
				    sizeof(ctx->er_src_dir_path));
			if (free_fp != NULL)
				free(free_fp, M_TEMP);
		}
	}
	if (info->vp != NULL) {
		oes_fill_file(&ctx->er_src_file, info->vp, info->cred,
		    NULL, NULL);
		if (VOP_ISLOCKED(info->vp) == 0) {
			char *fp = NULL, *free_fp = NULL;
			if (vn_fullpath(info->vp, &fp, &free_fp) == 0 &&
			    fp != NULL) {
				strlcpy(ctx->er_src_file_path, fp,
				    sizeof(ctx->er_src_file_path));
				ctx->er_src_file.ef_meta_flags &=
				    ~OES_FILE_META_PATH_REQUESTED;
			}
			if (free_fp != NULL)
				free(free_fp, M_TEMP);
		}
	}
	oes_copy_component(ctx->er_src_name, sizeof(ctx->er_src_name),
	    info->cnp);
	if (ctx->er_src_file_path[0] == '\0' &&
	    ctx->er_src_dir_path[0] != '\0' &&
	    ctx->er_src_name[0] != '\0') {
		oes_build_path(ctx->er_src_file_path,
		    sizeof(ctx->er_src_file_path),
		    ctx->er_src_dir_path,
		    ctx->er_src_name);
	}

	mtx_lock(&oes_rename_mtx);
	LIST_FOREACH_SAFE(cur, &oes_rename_list, er_link, tmp) {
		/* Replace existing entry for this tid/pid */
		if (!found_self &&
		    cur->er_tid == td->td_tid &&
		    cur->er_pid == td->td_proc->p_pid) {
			LIST_REMOVE(cur, er_link);
			free(cur, M_OES);
			found_self = true;
			continue;
		}
		/* Garbage collect stale entries (failed/aborted renames) */
		if (now - cur->er_time > OES_RENAME_CACHE_MAX_AGE) {
			LIST_REMOVE(cur, er_link);
			free(cur, M_OES);
		}
	}
	LIST_INSERT_HEAD(&oes_rename_list, ctx, er_link);
	mtx_unlock(&oes_rename_mtx);
}

static struct oes_rename_ctx *
oes_rename_cache_take(struct thread *td)
{
	struct oes_rename_ctx *ctx;


	mtx_lock(&oes_rename_mtx);
	LIST_FOREACH(ctx, &oes_rename_list, er_link) {
		if (ctx->er_tid == td->td_tid &&
		    ctx->er_pid == td->td_proc->p_pid) {
			LIST_REMOVE(ctx, er_link);
			mtx_unlock(&oes_rename_mtx);
			return (ctx);
		}
	}
	mtx_unlock(&oes_rename_mtx);

	return (NULL);
}

static void
oes_rename_cache_purge_pid(pid_t pid)
{
	struct oes_rename_ctx *ctx, *tmp;

	if (pid <= 0)
		return;

	mtx_lock(&oes_rename_mtx);
	LIST_FOREACH_SAFE(ctx, &oes_rename_list, er_link, tmp) {
		if (ctx->er_pid != pid)
			continue;
		LIST_REMOVE(ctx, er_link);
		free(ctx, M_OES);
	}
	mtx_unlock(&oes_rename_mtx);
}

static void
oes_fill_file_from_vap(oes_file_t *ef, struct vattr *vap)
{
	bzero(ef, sizeof(*ef));
	if (vap == NULL)
		return;

	ef->ef_type = oes_vtype_to_eftype(vap->va_type);
	ef->ef_mode = vap->va_mode;
	ef->ef_uid = vap->va_uid;
	ef->ef_gid = vap->va_gid;
	ef->ef_vaflags = vap->va_vaflags;
	ef->ef_meta_flags |= OES_FILE_META_PROPOSED_ATTRS;
}

static const char *
oes_event_primary_path(const struct oes_pending *ep)
{
	const oes_message_t *msg = &ep->ep_msg;
	const char *s;

	switch (msg->em_event) {
	case OES_EVENT_AUTH_EXEC:
	case OES_EVENT_NOTIFY_EXEC:
		return (oes_msg_string(msg, msg->em_event_data.exec.executable.ef_path_off));
	case OES_EVENT_AUTH_OPEN:
	case OES_EVENT_NOTIFY_OPEN:
		return (oes_msg_string(msg, msg->em_event_data.open.file.ef_path_off));
	case OES_EVENT_AUTH_ACCESS:
	case OES_EVENT_NOTIFY_ACCESS:
		return (oes_msg_string(msg, msg->em_event_data.access.file.ef_path_off));
	case OES_EVENT_AUTH_READ:
	case OES_EVENT_NOTIFY_READ:
	case OES_EVENT_AUTH_WRITE:
	case OES_EVENT_NOTIFY_WRITE:
		return (oes_msg_string(msg, msg->em_event_data.rw.file.ef_path_off));
	case OES_EVENT_AUTH_STAT:
	case OES_EVENT_NOTIFY_STAT:
		return (oes_msg_string(msg, msg->em_event_data.stat.file.ef_path_off));
	case OES_EVENT_AUTH_POLL:
	case OES_EVENT_NOTIFY_POLL:
		return (oes_msg_string(msg, msg->em_event_data.poll.file.ef_path_off));
	case OES_EVENT_AUTH_REVOKE:
	case OES_EVENT_NOTIFY_REVOKE:
		return (oes_msg_string(msg, msg->em_event_data.revoke.file.ef_path_off));
	case OES_EVENT_AUTH_READLINK:
	case OES_EVENT_NOTIFY_READLINK:
		return (oes_msg_string(msg, msg->em_event_data.readlink.file.ef_path_off));
	case OES_EVENT_AUTH_READDIR:
	case OES_EVENT_NOTIFY_READDIR:
		return (oes_msg_string(msg, msg->em_event_data.readdir.dir.ef_path_off));
	case OES_EVENT_AUTH_LOOKUP:
	case OES_EVENT_NOTIFY_LOOKUP:
		s = oes_msg_string(msg, msg->em_event_data.lookup.name_off);
		if (s[0] != '\0')
			return (s);
		return (oes_msg_string(msg, msg->em_event_data.lookup.dir.ef_path_off));
	case OES_EVENT_AUTH_CREATE:
	case OES_EVENT_NOTIFY_CREATE:
		s = oes_msg_string(msg, msg->em_event_data.create.file.ef_path_off);
		if (s[0] != '\0')
			return (s);
		return (oes_msg_string(msg, msg->em_event_data.create.dir.ef_path_off));
	case OES_EVENT_AUTH_UNLINK:
	case OES_EVENT_NOTIFY_UNLINK:
		s = oes_msg_string(msg, msg->em_event_data.unlink.file.ef_path_off);
		if (s[0] != '\0')
			return (s);
		return (oes_msg_string(msg, msg->em_event_data.unlink.dir.ef_path_off));
	case OES_EVENT_AUTH_RENAME:
	case OES_EVENT_NOTIFY_RENAME:
		s = oes_msg_string(msg, msg->em_event_data.rename.src_file.ef_path_off);
		if (s[0] != '\0')
			return (s);
		return (oes_msg_string(msg, msg->em_event_data.rename.src_dir.ef_path_off));
	case OES_EVENT_AUTH_LINK:
	case OES_EVENT_NOTIFY_LINK:
		return (oes_msg_string(msg, msg->em_event_data.link.target.ef_path_off));
	case OES_EVENT_AUTH_KLDLOAD:
	case OES_EVENT_NOTIFY_KLDLOAD:
		return (oes_msg_string(msg, msg->em_event_data.kldload.file.ef_path_off));
	case OES_EVENT_AUTH_MMAP:
	case OES_EVENT_NOTIFY_MMAP:
		return (oes_msg_string(msg, msg->em_event_data.mmap.file.ef_path_off));
	case OES_EVENT_AUTH_MPROTECT:
	case OES_EVENT_NOTIFY_MPROTECT:
		return (oes_msg_string(msg, msg->em_event_data.mprotect.file.ef_path_off));
	case OES_EVENT_AUTH_SETMODE:
	case OES_EVENT_NOTIFY_SETMODE:
		return (oes_msg_string(msg, msg->em_event_data.setmode.file.ef_path_off));
	case OES_EVENT_AUTH_SETOWNER:
	case OES_EVENT_NOTIFY_SETOWNER:
		return (oes_msg_string(msg, msg->em_event_data.setowner.file.ef_path_off));
	case OES_EVENT_AUTH_SETFLAGS:
	case OES_EVENT_NOTIFY_SETFLAGS:
		return (oes_msg_string(msg, msg->em_event_data.setflags.file.ef_path_off));
	case OES_EVENT_AUTH_SETUTIMES:
	case OES_EVENT_NOTIFY_SETUTIMES:
		return (oes_msg_string(msg, msg->em_event_data.setutimes.file.ef_path_off));
	case OES_EVENT_AUTH_CHDIR:
	case OES_EVENT_NOTIFY_CHDIR:
		return (oes_msg_string(msg, msg->em_event_data.chdir.dir.ef_path_off));
	case OES_EVENT_AUTH_CHROOT:
	case OES_EVENT_NOTIFY_CHROOT:
		return (oes_msg_string(msg, msg->em_event_data.chroot.dir.ef_path_off));
	case OES_EVENT_AUTH_SETEXTATTR:
	case OES_EVENT_NOTIFY_SETEXTATTR:
		return (oes_msg_string(msg, msg->em_event_data.setextattr.file.ef_path_off));
	case OES_EVENT_AUTH_GETEXTATTR:
	case OES_EVENT_NOTIFY_GETEXTATTR:
		return (oes_msg_string(msg, msg->em_event_data.getextattr.file.ef_path_off));
	case OES_EVENT_AUTH_DELETEEXTATTR:
	case OES_EVENT_NOTIFY_DELETEEXTATTR:
		return (oes_msg_string(msg, msg->em_event_data.deleteextattr.file.ef_path_off));
	case OES_EVENT_AUTH_LISTEXTATTR:
	case OES_EVENT_NOTIFY_LISTEXTATTR:
		return (oes_msg_string(msg, msg->em_event_data.listextattr.file.ef_path_off));
	case OES_EVENT_AUTH_GETACL:
	case OES_EVENT_NOTIFY_GETACL:
		return (oes_msg_string(msg, msg->em_event_data.getacl.file.ef_path_off));
	case OES_EVENT_AUTH_SETACL:
	case OES_EVENT_NOTIFY_SETACL:
		return (oes_msg_string(msg, msg->em_event_data.setacl.file.ef_path_off));
	case OES_EVENT_AUTH_DELETEACL:
	case OES_EVENT_NOTIFY_DELETEACL:
		return (oes_msg_string(msg, msg->em_event_data.deleteacl.file.ef_path_off));
	case OES_EVENT_AUTH_RELABEL:
	case OES_EVENT_NOTIFY_RELABEL:
		return (oes_msg_string(msg, msg->em_event_data.relabel.file.ef_path_off));
	case OES_EVENT_AUTH_MOUNT:
	case OES_EVENT_NOTIFY_MOUNT:
		return (oes_msg_string(msg, msg->em_event_data.mount.mountpoint.ef_path_off));
	case OES_EVENT_NOTIFY_UNMOUNT:
		return (oes_msg_string(msg, msg->em_event_data.unmount.mountpoint.ef_path_off));
	case OES_EVENT_AUTH_SWAPON:
	case OES_EVENT_NOTIFY_SWAPON:
		return (oes_msg_string(msg, msg->em_event_data.swapon.file.ef_path_off));
	case OES_EVENT_AUTH_SWAPOFF:
	case OES_EVENT_NOTIFY_SWAPOFF:
		return (oes_msg_string(msg, msg->em_event_data.swapoff.file.ef_path_off));
	case OES_EVENT_NOTIFY_MOUNT_STAT:
		return (oes_msg_string(msg, msg->em_event_data.mount_stat.fspath_off));
	default:
		return (NULL);
	}
}

/*
 * Return pointer to the primary file structure for an event.
 * Used for token-based path muting when path resolution fails.
 */
static const oes_file_t *
oes_event_primary_file(const struct oes_pending *ep)
{
	const oes_message_t *msg = &ep->ep_msg;

	switch (msg->em_event) {
	case OES_EVENT_AUTH_EXEC:
	case OES_EVENT_NOTIFY_EXEC:
		return (&msg->em_event_data.exec.executable);
	case OES_EVENT_AUTH_OPEN:
	case OES_EVENT_NOTIFY_OPEN:
		return (&msg->em_event_data.open.file);
	case OES_EVENT_AUTH_ACCESS:
	case OES_EVENT_NOTIFY_ACCESS:
		return (&msg->em_event_data.access.file);
	case OES_EVENT_AUTH_READ:
	case OES_EVENT_NOTIFY_READ:
	case OES_EVENT_AUTH_WRITE:
	case OES_EVENT_NOTIFY_WRITE:
		return (&msg->em_event_data.rw.file);
	case OES_EVENT_AUTH_STAT:
	case OES_EVENT_NOTIFY_STAT:
		return (&msg->em_event_data.stat.file);
	case OES_EVENT_AUTH_POLL:
	case OES_EVENT_NOTIFY_POLL:
		return (&msg->em_event_data.poll.file);
	case OES_EVENT_AUTH_REVOKE:
	case OES_EVENT_NOTIFY_REVOKE:
		return (&msg->em_event_data.revoke.file);
	case OES_EVENT_AUTH_READLINK:
	case OES_EVENT_NOTIFY_READLINK:
		return (&msg->em_event_data.readlink.file);
	case OES_EVENT_AUTH_READDIR:
	case OES_EVENT_NOTIFY_READDIR:
		return (&msg->em_event_data.readdir.dir);
	case OES_EVENT_AUTH_SETMODE:
	case OES_EVENT_NOTIFY_SETMODE:
		return (&msg->em_event_data.setmode.file);
	case OES_EVENT_AUTH_SETOWNER:
	case OES_EVENT_NOTIFY_SETOWNER:
		return (&msg->em_event_data.setowner.file);
	case OES_EVENT_AUTH_SETFLAGS:
	case OES_EVENT_NOTIFY_SETFLAGS:
		return (&msg->em_event_data.setflags.file);
	case OES_EVENT_AUTH_SETUTIMES:
	case OES_EVENT_NOTIFY_SETUTIMES:
		return (&msg->em_event_data.setutimes.file);
	case OES_EVENT_AUTH_CHDIR:
	case OES_EVENT_NOTIFY_CHDIR:
		return (&msg->em_event_data.chdir.dir);
	case OES_EVENT_AUTH_CHROOT:
	case OES_EVENT_NOTIFY_CHROOT:
		return (&msg->em_event_data.chroot.dir);
	case OES_EVENT_AUTH_SETEXTATTR:
	case OES_EVENT_NOTIFY_SETEXTATTR:
		return (&msg->em_event_data.setextattr.file);
	case OES_EVENT_AUTH_GETEXTATTR:
	case OES_EVENT_NOTIFY_GETEXTATTR:
		return (&msg->em_event_data.getextattr.file);
	case OES_EVENT_AUTH_DELETEEXTATTR:
	case OES_EVENT_NOTIFY_DELETEEXTATTR:
		return (&msg->em_event_data.deleteextattr.file);
	case OES_EVENT_AUTH_LISTEXTATTR:
	case OES_EVENT_NOTIFY_LISTEXTATTR:
		return (&msg->em_event_data.listextattr.file);
	case OES_EVENT_AUTH_GETACL:
	case OES_EVENT_NOTIFY_GETACL:
		return (&msg->em_event_data.getacl.file);
	case OES_EVENT_AUTH_SETACL:
	case OES_EVENT_NOTIFY_SETACL:
		return (&msg->em_event_data.setacl.file);
	case OES_EVENT_AUTH_DELETEACL:
	case OES_EVENT_NOTIFY_DELETEACL:
		return (&msg->em_event_data.deleteacl.file);
	case OES_EVENT_AUTH_RELABEL:
	case OES_EVENT_NOTIFY_RELABEL:
		return (&msg->em_event_data.relabel.file);
	case OES_EVENT_AUTH_MMAP:
	case OES_EVENT_NOTIFY_MMAP:
		return (&msg->em_event_data.mmap.file);
	case OES_EVENT_AUTH_MPROTECT:
	case OES_EVENT_NOTIFY_MPROTECT:
		return (&msg->em_event_data.mprotect.file);
	case OES_EVENT_AUTH_KLDLOAD:
	case OES_EVENT_NOTIFY_KLDLOAD:
		return (&msg->em_event_data.kldload.file);
	case OES_EVENT_AUTH_MOUNT:
	case OES_EVENT_NOTIFY_MOUNT:
		return (&msg->em_event_data.mount.mountpoint);
	case OES_EVENT_NOTIFY_UNMOUNT:
		return (&msg->em_event_data.unmount.mountpoint);
	case OES_EVENT_AUTH_SWAPON:
	case OES_EVENT_NOTIFY_SWAPON:
		return (&msg->em_event_data.swapon.file);
	case OES_EVENT_AUTH_SWAPOFF:
	case OES_EVENT_NOTIFY_SWAPOFF:
		return (&msg->em_event_data.swapoff.file);
	default:
		return (NULL);
	}
}

static const char *
oes_event_target_path(const struct oes_pending *ep)
{
	const oes_message_t *msg = &ep->ep_msg;

	switch (msg->em_event) {
	case OES_EVENT_AUTH_RENAME:
	case OES_EVENT_NOTIFY_RENAME:
		return (oes_msg_string(msg, msg->em_event_data.rename.dst_name_off));
	case OES_EVENT_AUTH_LINK:
	case OES_EVENT_NOTIFY_LINK:
		return (oes_msg_string(msg, msg->em_event_data.link.name_off));
	default:
		return (NULL);
	}
}

static bool
oes_event_path_muted_join(struct oes_client *ec, const char *dir,
    const char *name, bool target, bool require_basename, oes_event_type_t event)
{
	char fullpath[MAXPATHLEN];

	if (dir == NULL || name == NULL)
		return (oes_client_is_path_muted(ec, "", target, event));
	if (dir[0] == '\0' || name[0] == '\0')
		return (oes_client_is_path_muted(ec, "", target, event));
	if (require_basename && strchr(name, '/') != NULL)
		return (oes_client_is_path_muted(ec, "", target, event));

	oes_build_path(fullpath, sizeof(fullpath), dir, name);
	return (oes_client_is_path_muted(ec, fullpath, target, event));
}

/*
 * Check if an event's path is muted.
 *
 * mute_event specifies the event type to use for per-event path muting.
 * This allows NOTIFY mode clients to check NOTIFY event types even when
 * the pending event contains an AUTH event type.  If mute_event is 0,
 * the event type from the pending structure is used.
 */
static bool
oes_event_is_path_muted(struct oes_client *ec, const struct oes_pending *ep,
    oes_event_type_t mute_event)
{
	const oes_message_t *msg;
	const oes_file_t *file;
	const char *path;
	const char *target_path;
	oes_event_type_t event;

	EC_LOCK_ASSERT(ec);

	msg = &ep->ep_msg;
	event = (mute_event != 0) ? mute_event : msg->em_event;
	path = oes_event_primary_path(ep);
	file = oes_event_primary_file(ep);

	if (event == OES_EVENT_AUTH_EXEC) {
		if (path != NULL && path[0] != '\0' &&
		    oes_client_is_path_muted(ec, path, false, event))
			return (true);
	} else if (event != OES_EVENT_AUTH_LOOKUP &&
	    event != OES_EVENT_NOTIFY_LOOKUP) {
		if (path != NULL && path[0] != '\0' &&
		    oes_client_is_path_muted(ec, path, false, event))
			return (true);
		/*
		 * Token-based fallback: if path is empty (e.g., vnode locked
		 * during MAC hook), try matching by inode/device.
		 */
		if ((path == NULL || path[0] == '\0') && file != NULL &&
		    oes_client_is_token_muted(ec, file->ef_ino, file->ef_dev,
		    false, event))
			return (true);
	}

	/*
	 * Event-specific path mute checks.  LOOKUP events need special
	 * handling because oes_event_primary_path returns just the component
	 * name, not the full path.  We must join dir+name to check properly.
	 */
	switch (event) {
	case OES_EVENT_AUTH_LOOKUP:
	case OES_EVENT_NOTIFY_LOOKUP:
		if (oes_event_path_muted_join(ec,
		    oes_msg_string(msg, msg->em_event_data.lookup.dir.ef_path_off),
		    oes_msg_string(msg, msg->em_event_data.lookup.name_off),
		    false, false, event))
			return (true);
		break;
	case OES_EVENT_AUTH_CREATE:
	case OES_EVENT_NOTIFY_CREATE:
		if (oes_event_path_muted_join(ec,
		    oes_msg_string(msg, msg->em_event_data.create.dir.ef_path_off),
		    oes_msg_string(msg, msg->em_event_data.create.file.ef_path_off),
		    false, true, event))
			return (true);
		break;
	case OES_EVENT_AUTH_UNLINK:
	case OES_EVENT_NOTIFY_UNLINK:
		if (oes_event_path_muted_join(ec,
		    oes_msg_string(msg, msg->em_event_data.unlink.dir.ef_path_off),
		    oes_msg_string(msg, msg->em_event_data.unlink.file.ef_path_off),
		    false, true, event))
			return (true);
		break;
	case OES_EVENT_AUTH_RENAME:
	case OES_EVENT_NOTIFY_RENAME:
		if (oes_event_path_muted_join(ec,
		    oes_msg_string(msg, msg->em_event_data.rename.src_dir.ef_path_off),
		    oes_msg_string(msg, msg->em_event_data.rename.src_file.ef_path_off),
		    false, true, event))
			return (true);
		break;
	default:
		break;
	}

	/*
	 * Target path mute check.  For RENAME and LINK events,
	 * oes_event_target_path returns just the basename (dst_name or
	 * link.name), not a full path.  Use join-based checking for those.
	 */
	switch (event) {
	case OES_EVENT_AUTH_RENAME:
	case OES_EVENT_NOTIFY_RENAME:
		if (oes_event_path_muted_join(ec,
		    oes_msg_string(msg, msg->em_event_data.rename.dst_dir.ef_path_off),
		    oes_msg_string(msg, msg->em_event_data.rename.dst_name_off),
		    true, false, event))
			return (true);
		break;
	case OES_EVENT_AUTH_LINK:
	case OES_EVENT_NOTIFY_LINK: {
		const char *link_name = oes_msg_string(msg,
		    msg->em_event_data.link.name_off);

		/* Check full path first (dir + name) */
		if (oes_event_path_muted_join(ec,
		    oes_msg_string(msg, msg->em_event_data.link.dir.ef_path_off),
		    link_name, true, false, event))
			return (true);
		/* Also check just the link name (basename) for convenience */
		if (link_name[0] != '\0' &&
		    oes_client_is_path_muted(ec, link_name, true, event))
			return (true);
		break;
	}
	default:
		/* Other events: target_path is a full path, check directly */
		target_path = oes_event_target_path(ep);
		if (target_path != NULL && target_path[0] != '\0' &&
		    oes_client_is_path_muted(ec, target_path, true, event))
			return (true);
		break;
	}

	return (false);
}

static int
oes_accmode_to_open_flags(accmode_t accmode)
{
	int flags = 0;

	if ((accmode & (VREAD | VWRITE)) == (VREAD | VWRITE))
		flags = O_RDWR;
	else if (accmode & VWRITE)
		flags = O_WRONLY;
	else if (accmode & VREAD)
		flags = O_RDONLY;

	if (accmode & VEXEC)
		flags |= O_EXEC;

	return (flags);
}

static uint32_t
oes_accmode_to_access(accmode_t accmode)
{
	uint32_t access = 0;

	if (accmode & VREAD)
		access |= OES_ACCESS_READ;
	if (accmode & VWRITE)
		access |= OES_ACCESS_WRITE;
	if (accmode & VEXEC)
		access |= OES_ACCESS_EXEC;
	return (access);
}


/*
 * Deliver a self-contained NOTIFY event to all subscribed clients using the
 * normal blocking client locks.  Runs from the deferred task (or any context
 * with no VFS locks held), so it never has to trylock-and-drop.  The pending
 * event still carries the AUTH event type it was generated with; NOTIFY
 * clients subscribe to (and mute by) the NOTIFY variant, so convert before
 * matching and stamp each delivered clone with it.
 */
static void
oes_deliver_notify_locked(struct oes_pending *ep)
{
	struct oes_client *ec;
	struct oes_pending *ep_clone;
	oes_event_type_t notify_event;

	notify_event = OES_EVENT_IS_AUTH(ep->ep_msg.em_event) ?
	    oes_auth_to_notify(ep->ep_msg.em_event) : ep->ep_msg.em_event;
	if (notify_event == 0)
		notify_event = ep->ep_msg.em_event;

	OES_LOCK();
	LIST_FOREACH(ec, &oes_softc.sc_clients, ec_link) {
		if (!oes_pending_visible_to_client(ep, ec))
			continue;
		EC_LOCK(ec);
		if (ec->ec_flags & EC_FLAG_CLOSING) {
			EC_UNLOCK(ec);
			continue;
		}
		if (!oes_client_subscribed(ec, notify_event)) {
			EC_UNLOCK(ec);
			continue;
		}
		/* Token-based mute check: token captured at event creation. */
		if (oes_client_is_muted_by_token(ec,
		    &ep->ep_msg.em_process.ep_token, notify_event)) {
			EC_UNLOCK(ec);
			continue;
		}
		if (oes_event_is_path_muted(ec, ep, 0)) {
			EC_UNLOCK(ec);
			continue;
		}
		if (oes_client_is_uid_muted(ec, ep->ep_msg.em_process.ep_uid) ||
		    oes_client_is_gid_muted(ec, ep->ep_msg.em_process.ep_gid)) {
			EC_UNLOCK(ec);
			continue;
		}

		/* M_NOWAIT: still under EC_LOCK, as in the sleep-path dispatch. */
		ep_clone = oes_pending_clone(ep, M_NOWAIT);
		if (ep_clone == NULL) {
			oes_event_note_drop(ec, notify_event);
			atomic_add_64(&oes_softc.sc_alloc_failures, 1);
			EC_UNLOCK(ec);
			continue;
		}
		/* Deliver as the NOTIFY event type the client subscribed to. */
		ep_clone->ep_msg.em_event = notify_event;

		if (oes_event_enqueue(ec, ep_clone) != 0)
			oes_pending_free(ep_clone);
		else
			oes_pending_rele(ep_clone);
		EC_UNLOCK(ec);
	}
	OES_UNLOCK();
}

/*
 * Deferred-delivery task: drain the deferred queue, delivering each event with
 * the blocking path above.  Runs on the system taskqueue thread, so it may
 * sleep/block on the client locks.
 */
void
oes_defer_task_fn(void *arg __unused, int pending __unused)
{
	struct oes_pending *ep;

	for (;;) {
		mtx_lock_spin(&oes_softc.sc_defer_mtx);
		ep = TAILQ_FIRST(&oes_softc.sc_defer);
		if (ep == NULL) {
			mtx_unlock_spin(&oes_softc.sc_defer_mtx);
			break;
		}
		TAILQ_REMOVE(&oes_softc.sc_defer, ep, ep_link);
		oes_softc.sc_defer_count--;
		mtx_unlock_spin(&oes_softc.sc_defer_mtx);

		oes_deliver_notify_locked(ep);
		oes_pending_rele(ep);
	}
}

/*
 * NOSLEEP MAC hooks run with VFS locks held, so taking the blocking client
 * locks here risks a lock-order deadlock -- the reason the old path used
 * trylock and dropped events (sc_nosleep_drops) under contention.  Instead,
 * hand the already-built, self-contained event to the deferred task, which
 * delivers it later with normal locks and no contention drops.  Only a truly
 * overloaded deferred queue (bounded by OES_DEFER_MAX) drops, keeping memory
 * bounded.  The event's ep_link is free here (only clones enter client queues).
 */
static void
oes_deliver_notify_nosleep(struct oes_pending *ep, struct proc *p __unused)
{

	mtx_lock_spin(&oes_softc.sc_defer_mtx);
	if (oes_softc.sc_defer_count >= OES_DEFER_MAX) {
		mtx_unlock_spin(&oes_softc.sc_defer_mtx);
		atomic_add_64(&oes_softc.sc_nosleep_drops, 1);
		return;
	}
	oes_pending_hold(ep);
	TAILQ_INSERT_TAIL(&oes_softc.sc_defer, ep, ep_link);
	oes_softc.sc_defer_count++;
	mtx_unlock_spin(&oes_softc.sc_defer_mtx);

	taskqueue_enqueue(oes_softc.sc_defer_tq, &oes_softc.sc_defer_task);
}

static void
oes_proc_event_fork(void *arg __unused, struct proc *p1,
    struct proc *p2, int flags __unused)
{
	struct oes_pending *ep;

	if (!oes_softc.sc_active)
		return;

	ep = oes_pending_alloc(OES_EVENT_NOTIFY_FORK, p1);
	if (ep == NULL)
		return;

	{
		struct oes_strtab st;
		bool owned = mtx_owned(&p2->p_mtx);

		oes_strtab_init(&st);
		st.st_off = ep->ep_msg.em_size;

		if (!owned)
			PROC_LOCK(p2);
		oes_fill_process(&ep->ep_msg.em_event_data.fork.child,
		    p2, p2->p_ucred, &st, &ep->ep_msg);
		if (!owned)
			PROC_UNLOCK(p2);

		ep->ep_msg.em_size = OES_MSG_ALIGNED(st.st_off);
	}

	oes_deliver_notify_nosleep(ep, p1);
	oes_pending_rele(ep);
}

static void
oes_proc_event_exit(void *arg __unused, struct proc *p)
{
	struct oes_pending *ep;
	int xexit;

	if (!oes_softc.sc_active)
		return;

	oes_rename_cache_purge_pid(p->p_pid);

	PROC_LOCK(p);
	xexit = p->p_xexit;
	PROC_UNLOCK(p);

	ep = oes_pending_alloc(OES_EVENT_NOTIFY_EXIT, p);
	if (ep == NULL)
		return;

	ep->ep_msg.em_event_data.exit.status = xexit;

	oes_deliver_notify_nosleep(ep, p);
	oes_pending_rele(ep);
}

/*
 * Eventhandler: vfs_mounted - called when a filesystem is mounted
 */
static void
oes_vfs_event_mounted(void *arg __unused, struct mount *mp,
    struct vnode *vp, struct thread *td)
{
	struct oes_pending *ep;
	struct ucred *cred;
	struct proc *p;
	struct statfs *sp;

	if (!oes_softc.sc_active)
		return;
	if (td == NULL || td->td_proc == NULL)
		return;

	p = td->td_proc;
	PROC_LOCK(p);
	cred = crhold(p->p_ucred);
	PROC_UNLOCK(p);

	ep = oes_pending_alloc(OES_EVENT_NOTIFY_MOUNT, p);
	if (ep == NULL) {
		crfree(cred);
		return;
	}

	/* Fill mount event data from mount structure */
	sp = &mp->mnt_stat;
	{
		struct oes_strtab st;

		oes_strtab_init(&st);
		st.st_off = ep->ep_msg.em_size;

		if (vp != NULL)
			oes_fill_file(&ep->ep_msg.em_event_data.mount.mountpoint,
			    vp, cred, &st, &ep->ep_msg);
		/* Fallback: use f_mntonname if vnode path resolution failed */
		if (ep->ep_msg.em_event_data.mount.mountpoint.ef_path_off == 0)
			ep->ep_msg.em_event_data.mount.mountpoint.ef_path_off =
			    oes_strtab_add(&st, &ep->ep_msg, sp->f_mntonname);
		strlcpy(ep->ep_msg.em_event_data.mount.fstype, sp->f_fstypename,
		    sizeof(ep->ep_msg.em_event_data.mount.fstype));
		ep->ep_msg.em_event_data.mount.source_off =
		    oes_strtab_add(&st, &ep->ep_msg, sp->f_mntfromname);
		ep->ep_msg.em_event_data.mount.flags = mp->mnt_flag;

		ep->ep_msg.em_size = OES_MSG_ALIGNED(st.st_off);
	}

	oes_deliver_notify_nosleep(ep, p);
	oes_pending_rele(ep);
	crfree(cred);
}

/*
 * Eventhandler: vfs_unmounted - called when a filesystem is unmounted
 */
static void
oes_vfs_event_unmounted(void *arg __unused, struct mount *mp,
    struct thread *td)
{
	struct oes_pending *ep;
	struct ucred *cred;
	struct proc *p;
	struct statfs *sp;

	if (!oes_softc.sc_active)
		return;
	if (td == NULL || td->td_proc == NULL)
		return;

	p = td->td_proc;
	PROC_LOCK(p);
	cred = crhold(p->p_ucred);
	PROC_UNLOCK(p);

	ep = oes_pending_alloc(OES_EVENT_NOTIFY_UNMOUNT, p);
	if (ep == NULL) {
		crfree(cred);
		return;
	}

	/* Fill unmount event data from mount structure */
	sp = &mp->mnt_stat;
	{
		struct oes_strtab st;

		oes_strtab_init(&st);
		st.st_off = ep->ep_msg.em_size;

		oes_fill_file(&ep->ep_msg.em_event_data.unmount.mountpoint,
		    mp->mnt_vnodecovered, cred, &st, &ep->ep_msg);
		/* Fallback: use f_mntonname if vnode path resolution failed */
		if (ep->ep_msg.em_event_data.unmount.mountpoint.ef_path_off == 0)
			ep->ep_msg.em_event_data.unmount.mountpoint.ef_path_off =
			    oes_strtab_add(&st, &ep->ep_msg, sp->f_mntonname);
		strlcpy(ep->ep_msg.em_event_data.unmount.fstype, sp->f_fstypename,
		    sizeof(ep->ep_msg.em_event_data.unmount.fstype));
		ep->ep_msg.em_event_data.unmount.source_off =
		    oes_strtab_add(&st, &ep->ep_msg, sp->f_mntfromname);
		ep->ep_msg.em_event_data.unmount.flags = mp->mnt_flag;

		ep->ep_msg.em_size = OES_MSG_ALIGNED(st.st_off);
	}

	oes_deliver_notify_nosleep(ep, p);
	oes_pending_rele(ep);
	crfree(cred);
}

/*
 * Eventhandler: kld_unload - called when a kernel module is unloaded
 */
static void
oes_kld_event_unload(void *arg __unused, const char *name, caddr_t addr __unused,
    size_t size __unused)
{
	struct oes_pending *ep;
	struct ucred *cred;
	struct proc *p;

	if (!oes_softc.sc_active)
		return;

	p = curthread->td_proc;

	PROC_LOCK(p);
	cred = crhold(p->p_ucred);
	PROC_UNLOCK(p);

	ep = oes_pending_alloc(OES_EVENT_NOTIFY_KLDUNLOAD, p);
	if (ep == NULL) {
		crfree(cred);
		return;
	}

	/* Fill kldunload event data - no file vnode available at unload time */
	memset(&ep->ep_msg.em_event_data.kldunload.file, 0,
	    sizeof(ep->ep_msg.em_event_data.kldunload.file));
	if (name != NULL)
		strlcpy(ep->ep_msg.em_event_data.kldunload.name, name,
		    sizeof(ep->ep_msg.em_event_data.kldunload.name));

	oes_deliver_notify_nosleep(ep, p);
	oes_pending_rele(ep);
	crfree(cred);
}

static void
oes_fill_event_file(oes_file_t *file, struct vnode *vp, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	if (vp != NULL)
		oes_fill_file(file, vp, cred, st, msg_base);
}

/*
 * Join a directory path and a component name into a full path, adding
 * the result to the string table.  Returns the string table offset.
 * If either part is empty, returns 0 (empty).
 */
static uint32_t
oes_strtab_join_path(struct oes_strtab *st, void *msg_base,
    const char *dir, const char *name)
{
	char fullpath[MAXPATHLEN];

	if (dir == NULL || name == NULL)
		return (0);
	if (dir[0] == '\0' || name[0] == '\0')
		return (0);

	oes_build_path(fullpath, sizeof(fullpath), dir, name);
	return (oes_strtab_add(st, msg_base, fullpath));
}

static uint32_t
oes_strtab_component_path(struct oes_strtab *st, void *msg_base,
    const struct componentname *cnp)
{
	char pathbuf[MAXPATHLEN];

	oes_copy_component_path(pathbuf, sizeof(pathbuf), cnp);
	if (pathbuf[0] == '\0')
		return (0);
	return (oes_strtab_add(st, msg_base, pathbuf));
}

static void
oes_fill_event_open(struct oes_pending *ep, struct vnode *vp,
    accmode_t accmode, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.open.file, vp, cred,
	    st, msg_base);
	ep->ep_msg.em_event_data.open.flags =
	    oes_accmode_to_open_flags(accmode);
	ep->ep_msg.em_event_data.open.access = oes_accmode_to_access(accmode);
}

static void
oes_fill_event_access(struct oes_pending *ep, struct vnode *vp,
    accmode_t accmode, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.access.file, vp, cred,
	    st, msg_base);
	ep->ep_msg.em_event_data.access.accmode = accmode;
}

static void
oes_fill_event_rw(struct oes_pending *ep, struct vnode *vp, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.rw.file, vp, cred,
	    st, msg_base);
}

static void
oes_fill_event_stat(struct oes_pending *ep, struct vnode *vp,
    struct ucred *cred, struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.stat.file, vp, cred,
	    st, msg_base);
}

static void
oes_fill_event_poll(struct oes_pending *ep, struct vnode *vp,
    struct ucred *cred, struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.poll.file, vp, cred,
	    st, msg_base);
}

static void
oes_fill_event_revoke(struct oes_pending *ep, struct vnode *vp,
    struct ucred *cred, struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.revoke.file, vp, cred,
	    st, msg_base);
}

static void
oes_fill_event_readlink(struct oes_pending *ep, struct vnode *vp,
    struct ucred *cred, struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.readlink.file, vp, cred,
	    st, msg_base);
}

static void
oes_fill_event_readdir(struct oes_pending *ep, struct vnode *dvp,
    struct ucred *cred, struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.readdir.dir, dvp, cred,
	    st, msg_base);
}

static void
oes_fill_event_lookup(struct oes_pending *ep, struct vnode *dvp,
    struct componentname *cnp, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	char namebuf[MAXNAMLEN + 1];

	oes_fill_event_file(&ep->ep_msg.em_event_data.lookup.dir, dvp, cred,
	    st, msg_base);
	oes_copy_component(namebuf, sizeof(namebuf), cnp);
	ep->ep_msg.em_event_data.lookup.name_off =
	    oes_strtab_add(st, msg_base, namebuf);
}

static void
oes_fill_event_create(struct oes_pending *ep, struct vnode *dvp,
    struct vattr *vap, struct componentname *cnp, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	char namebuf[MAXNAMLEN + 1];
	const char *dir_path;
	uint32_t file_path_off;
	bool requested_path;
	bool basename_only;

	oes_fill_event_file(&ep->ep_msg.em_event_data.create.dir, dvp, cred,
	    st, msg_base);
	oes_fill_file_from_vap(&ep->ep_msg.em_event_data.create.file, vap);

	/* Build file path from dir + component name */
	oes_copy_component(namebuf, sizeof(namebuf), cnp);
	dir_path = oes_msg_string(&ep->ep_msg,
	    ep->ep_msg.em_event_data.create.dir.ef_path_off);
	file_path_off = oes_strtab_join_path(st, msg_base, dir_path, namebuf);
	requested_path = false;
	basename_only = false;
	if (file_path_off == 0) {
		file_path_off = oes_strtab_component_path(st, msg_base, cnp);
		requested_path = (file_path_off != 0);
	}
	if (file_path_off == 0 && namebuf[0] != '\0') {
		file_path_off = oes_strtab_add(st, msg_base, namebuf);
		basename_only = (file_path_off != 0);
	}
	if (basename_only) {
		ep->ep_msg.em_event_data.create.file.ef_path_off = file_path_off;
		oes_file_mark_path_unavailable(&ep->ep_msg,
		    &ep->ep_msg.em_event_data.create.file);
	} else if (file_path_off == 0) {
		oes_file_mark_path_unavailable(&ep->ep_msg,
		    &ep->ep_msg.em_event_data.create.file);
	} else if (requested_path) {
		oes_file_set_requested_path_off(
		    &ep->ep_msg.em_event_data.create.file, file_path_off);
	} else {
		oes_file_set_resolved_path_off(
		    &ep->ep_msg.em_event_data.create.file, file_path_off);
	}

	if (vap != NULL)
		ep->ep_msg.em_event_data.create.mode = vap->va_mode;
}

static void
oes_fill_event_unlink(struct oes_pending *ep, struct vnode *dvp,
    struct vnode *vp, struct componentname *cnp, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	char namebuf[MAXNAMLEN + 1];
	const char *dir_path;
	uint32_t file_path_off;
	bool requested_path;

	oes_fill_event_file(&ep->ep_msg.em_event_data.unlink.dir, dvp, cred,
	    st, msg_base);
	oes_fill_event_file(&ep->ep_msg.em_event_data.unlink.file, vp, cred,
	    st, msg_base);

	/* Build file path from dir + component name */
	oes_copy_component(namebuf, sizeof(namebuf), cnp);
	dir_path = oes_msg_string(&ep->ep_msg,
	    ep->ep_msg.em_event_data.unlink.dir.ef_path_off);
	file_path_off = oes_strtab_join_path(st, msg_base, dir_path, namebuf);
	requested_path = false;
	if (file_path_off == 0) {
		file_path_off = oes_strtab_component_path(st, msg_base, cnp);
		requested_path = (file_path_off != 0);
	}
	if (file_path_off != 0) {
		if (requested_path) {
			oes_file_set_requested_path_off(
			    &ep->ep_msg.em_event_data.unlink.file,
			    file_path_off);
		} else {
			oes_file_set_resolved_path_off(
			    &ep->ep_msg.em_event_data.unlink.file,
			    file_path_off);
		}
	} else {
		oes_file_mark_path_unavailable(&ep->ep_msg,
		    &ep->ep_msg.em_event_data.unlink.file);
	}
}

static void
oes_fill_event_rename(struct oes_pending *ep,
    const struct oes_rename_ctx *rename_ctx, struct vnode *dvp,
    struct componentname *cnp, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	char namebuf[MAXNAMLEN + 1];

	if (rename_ctx != NULL) {
		ep->ep_msg.em_event_data.rename.src_dir =
		    rename_ctx->er_src_dir;
		ep->ep_msg.em_event_data.rename.src_file =
		    rename_ctx->er_src_file;
		/* Add paths from context's own buffers to this message's strtab */
		oes_file_set_resolved_path_off(&ep->ep_msg.em_event_data.rename.src_dir,
		    oes_strtab_add(st, msg_base, rename_ctx->er_src_dir_path));
		if ((rename_ctx->er_src_file.ef_meta_flags &
		    OES_FILE_META_PATH_REQUESTED) != 0) {
			oes_file_set_requested_path_off(
			    &ep->ep_msg.em_event_data.rename.src_file,
			    oes_strtab_add(st, msg_base,
			    rename_ctx->er_src_file_path));
		} else {
			oes_file_set_resolved_path_off(
			    &ep->ep_msg.em_event_data.rename.src_file,
			    oes_strtab_add(st, msg_base,
			    rename_ctx->er_src_file_path));
		}
		if (rename_ctx->er_src_dir_path[0] == '\0' ||
		    ep->ep_msg.em_event_data.rename.src_dir.ef_path_off == 0) {
			oes_file_mark_path_unavailable(&ep->ep_msg,
			    &ep->ep_msg.em_event_data.rename.src_dir);
		}
		if (rename_ctx->er_src_file_path[0] == '\0' ||
		    ep->ep_msg.em_event_data.rename.src_file.ef_path_off == 0) {
			oes_file_mark_path_unavailable(&ep->ep_msg,
			    &ep->ep_msg.em_event_data.rename.src_file);
		}
	}
	oes_fill_event_file(&ep->ep_msg.em_event_data.rename.dst_dir, dvp, cred,
	    st, msg_base);
	oes_copy_component(namebuf, sizeof(namebuf), cnp);
	ep->ep_msg.em_event_data.rename.dst_name_off =
	    oes_strtab_add(st, msg_base, namebuf);
}

static void
oes_fill_event_link(struct oes_pending *ep, struct vnode *vp,
    struct vnode *dvp, struct componentname *cnp, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	char namebuf[MAXNAMLEN + 1];

	oes_fill_event_file(&ep->ep_msg.em_event_data.link.target, vp, cred,
	    st, msg_base);
	oes_fill_event_file(&ep->ep_msg.em_event_data.link.dir, dvp, cred,
	    st, msg_base);
	oes_copy_component(namebuf, sizeof(namebuf), cnp);
	ep->ep_msg.em_event_data.link.name_off =
	    oes_strtab_add(st, msg_base, namebuf);
}

static void
oes_fill_event_kldload(struct oes_pending *ep, struct vnode *vp,
    struct ucred *cred, struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.kldload.file, vp, cred,
	    st, msg_base);
}

static void
oes_fill_event_mmap(struct oes_pending *ep, struct vnode *vp, int prot,
    int mmap_flags, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.mmap.file, vp, cred,
	    st, msg_base);
	ep->ep_msg.em_event_data.mmap.prot = prot;
	ep->ep_msg.em_event_data.mmap.flags = mmap_flags;
}

static void
oes_fill_event_mprotect(struct oes_pending *ep, struct vnode *vp, int prot,
    struct ucred *cred, struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.mprotect.file, vp, cred,
	    st, msg_base);
	ep->ep_msg.em_event_data.mprotect.prot = prot;
}

static void
oes_fill_event_setmode(struct oes_pending *ep, struct vnode *vp, mode_t mode,
    struct ucred *cred, struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.setmode.file, vp, cred,
	    st, msg_base);
	ep->ep_msg.em_event_data.setmode.mode = mode;
}

static void
oes_fill_event_setowner(struct oes_pending *ep, struct vnode *vp, uid_t uid,
    gid_t gid, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.setowner.file, vp, cred,
	    st, msg_base);
	ep->ep_msg.em_event_data.setowner.uid = uid;
	ep->ep_msg.em_event_data.setowner.gid = gid;
}

static void
oes_fill_event_setflags(struct oes_pending *ep, struct vnode *vp,
    u_long flags, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.setflags.file, vp, cred,
	    st, msg_base);
	ep->ep_msg.em_event_data.setflags.flags = flags;
}

static void
oes_fill_event_setutimes(struct oes_pending *ep, struct vnode *vp,
    struct timespec atime, struct timespec mtime, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.setutimes.file, vp, cred,
	    st, msg_base);
	ep->ep_msg.em_event_data.setutimes.atime.tv_sec = atime.tv_sec;
	ep->ep_msg.em_event_data.setutimes.atime.tv_nsec = atime.tv_nsec;
	ep->ep_msg.em_event_data.setutimes.mtime.tv_sec = mtime.tv_sec;
	ep->ep_msg.em_event_data.setutimes.mtime.tv_nsec = mtime.tv_nsec;
}

static void
oes_fill_event_chdir(struct oes_pending *ep, struct vnode *dvp,
    struct ucred *cred, struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.chdir.dir, dvp, cred,
	    st, msg_base);
}

static void
oes_fill_event_chroot(struct oes_pending *ep, struct vnode *dvp,
    struct ucred *cred, struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.chroot.dir, dvp, cred,
	    st, msg_base);
}

static void
oes_fill_event_setextattr(struct oes_pending *ep, struct vnode *vp,
    int attrnamespace, const char *attrname, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.setextattr.file, vp, cred,
	    st, msg_base);
	ep->ep_msg.em_event_data.setextattr.attrnamespace = attrnamespace;
	if (attrname != NULL)
		ep->ep_msg.em_event_data.setextattr.name_off =
		    oes_strtab_add(st, msg_base, attrname);
}

static void
oes_fill_event_getextattr(struct oes_pending *ep, struct vnode *vp,
    int attrnamespace, const char *attrname, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.getextattr.file, vp, cred,
	    st, msg_base);
	ep->ep_msg.em_event_data.getextattr.attrnamespace = attrnamespace;
	if (attrname != NULL)
		ep->ep_msg.em_event_data.getextattr.name_off =
		    oes_strtab_add(st, msg_base, attrname);
}

static void
oes_fill_event_deleteextattr(struct oes_pending *ep, struct vnode *vp,
    int attrnamespace, const char *attrname, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.deleteextattr.file, vp,
	    cred, st, msg_base);
	ep->ep_msg.em_event_data.deleteextattr.attrnamespace = attrnamespace;
	if (attrname != NULL)
		ep->ep_msg.em_event_data.deleteextattr.name_off =
		    oes_strtab_add(st, msg_base, attrname);
}

static void
oes_fill_event_listextattr(struct oes_pending *ep, struct vnode *vp,
    int attrnamespace, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.listextattr.file, vp,
	    cred, st, msg_base);
	ep->ep_msg.em_event_data.listextattr.attrnamespace = attrnamespace;
	/* name_off stays 0 (empty) for list operations */
}

static void
oes_fill_event_acl(oes_event_acl_t *acl, struct vnode *vp, acl_type_t type,
    struct ucred *cred, struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&acl->file, vp, cred, st, msg_base);
	acl->type = (int)type;
}

static void
oes_fill_event_getacl(struct oes_pending *ep, struct vnode *vp,
    acl_type_t type, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_acl(&ep->ep_msg.em_event_data.getacl, vp, type, cred,
	    st, msg_base);
}

static void
oes_fill_event_setacl(struct oes_pending *ep, struct vnode *vp,
    acl_type_t type, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_acl(&ep->ep_msg.em_event_data.setacl, vp, type, cred,
	    st, msg_base);
}

static void
oes_fill_event_deleteacl(struct oes_pending *ep, struct vnode *vp,
    acl_type_t type, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_acl(&ep->ep_msg.em_event_data.deleteacl, vp, type, cred,
	    st, msg_base);
}

static void
oes_fill_event_relabel(struct oes_pending *ep, struct vnode *vp,
    struct ucred *cred, struct oes_strtab *st, void *msg_base)
{
	oes_fill_event_file(&ep->ep_msg.em_event_data.relabel.file, vp, cred,
	    st, msg_base);
}

static void
oes_fill_event_signal(struct oes_pending *ep, struct proc *target_proc,
    int signum, struct oes_strtab *st, void *msg_base)
{
	if (target_proc != NULL) {
		bool owned = mtx_owned(&target_proc->p_mtx);

		if (!owned)
			PROC_LOCK(target_proc);
		oes_fill_process(&ep->ep_msg.em_event_data.signal.target,
		    target_proc, NULL, st, msg_base);
		if (!owned)
			PROC_UNLOCK(target_proc);
	}
	ep->ep_msg.em_event_data.signal.signum = signum;
}

static void
oes_fill_event_setuid(struct oes_pending *ep, uid_t uid)
{
	ep->ep_msg.em_event_data.setuid.uid = uid;
}

static void
oes_fill_event_setgid(struct oes_pending *ep, gid_t gid)
{
	ep->ep_msg.em_event_data.setgid.gid = gid;
}

static bool
oes_event_invalidates_namespace(oes_event_type_t event)
{
	switch (event) {
	case OES_EVENT_AUTH_CREATE:
	case OES_EVENT_AUTH_UNLINK:
	case OES_EVENT_AUTH_RENAME:
	case OES_EVENT_AUTH_LINK:
	case OES_EVENT_AUTH_MOUNT:
		return (true);
	default:
		return (false);
	}
}

static bool
oes_event_invalidates_file(oes_event_type_t event)
{
	switch (event) {
	case OES_EVENT_AUTH_WRITE:
	case OES_EVENT_AUTH_SETMODE:
	case OES_EVENT_AUTH_SETOWNER:
	case OES_EVENT_AUTH_SETFLAGS:
	case OES_EVENT_AUTH_SETUTIMES:
	case OES_EVENT_AUTH_SETEXTATTR:
	case OES_EVENT_AUTH_DELETEEXTATTR:
	case OES_EVENT_AUTH_SETACL:
	case OES_EVENT_AUTH_DELETEACL:
	case OES_EVENT_AUTH_RELABEL:
		return (true);
	default:
		return (false);
	}
}

/*
 * Helper: Generate an event and optionally wait for AUTH response.
 * NOSLEEP hooks (info.nosleep=true) use cache-only authorization.
 */
static int
oes_generate_vnode_event(oes_event_type_t event,
    const struct oes_vnode_event_info *info)
{
	struct proc *p = curthread->td_proc;
	struct oes_pending *ep;
	oes_event_type_t notify_event;
	int error = 0;
	struct ucred *cred = info->cred;
	struct vnode *vp = info->vp;
	struct vnode *dvp = info->dvp;
	struct componentname *cnp = info->cnp;
	struct vattr *vap = info->vap;
	struct proc *target_proc = info->target_proc;
	struct oes_rename_ctx *rename_ctx = info->rename_ctx;
	accmode_t accmode = info->accmode;
	int prot = info->prot;
	int mmap_flags = info->mmap_flags;
	int attrnamespace = info->attrnamespace;
	const char *attrname = info->attrname;
	acl_type_t acl_type = info->acl_type;
	int signum = info->signum;
	uid_t uid = info->uid;
	gid_t gid = info->gid;
	mode_t mode = info->mode;
	uid_t owner_uid = info->owner_uid;
	gid_t owner_gid = info->owner_gid;
	u_long fflags = info->fflags;
	struct timespec atime = info->atime;
	struct timespec mtime = info->mtime;
	struct socket *so = info->socket;
	struct sockaddr *sa = info->sockaddr;
	int reboot_howto = info->reboot_howto;
	const char *sysctl_name = info->sysctl_name;
	int sysctl_op = info->sysctl_op;
	const char *kenv_name = info->kenv_name;
	int kenv_op = info->kenv_op;

	if (!oes_softc.sc_active || p == NULL)
		return (0);

	notify_event = OES_EVENT_IS_AUTH(event) ? oes_auth_to_notify(event) : event;

	/* Allocate pending event */
	ep = oes_pending_alloc(event, p);
	if (ep == NULL) {
		atomic_add_64(&oes_softc.sc_alloc_failures, 1);
		if (OES_EVENT_IS_AUTH(event))
			return (oes_require_auth_clients || oes_auth_fail_closed ||
			    oes_default_deadline_miss_mode ==
			    OES_DEADLINE_MISS_FAIL_CLOSED ? EACCES : 0);
		return (0);
	}

	/*
	 * Fill event-specific data based on event type.
	 * Continue appending to the string table where oes_pending_alloc
	 * left off (after em_process strings).
	 */
	{
		struct oes_strtab st;

		oes_strtab_init(&st);
		st.st_off = ep->ep_msg.em_size;

		switch (event) {
		case OES_EVENT_AUTH_OPEN:
		case OES_EVENT_NOTIFY_OPEN:
			oes_fill_event_open(ep, vp, accmode, cred, &st,
			    &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_ACCESS:
		case OES_EVENT_NOTIFY_ACCESS:
			oes_fill_event_access(ep, vp, accmode, cred, &st,
			    &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_READ:
		case OES_EVENT_NOTIFY_READ:
		case OES_EVENT_AUTH_WRITE:
		case OES_EVENT_NOTIFY_WRITE:
			oes_fill_event_rw(ep, vp, cred, &st, &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_STAT:
		case OES_EVENT_NOTIFY_STAT:
			oes_fill_event_stat(ep, vp, cred, &st, &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_POLL:
		case OES_EVENT_NOTIFY_POLL:
			oes_fill_event_poll(ep, vp, cred, &st, &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_REVOKE:
		case OES_EVENT_NOTIFY_REVOKE:
			oes_fill_event_revoke(ep, vp, cred, &st, &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_READLINK:
		case OES_EVENT_NOTIFY_READLINK:
			oes_fill_event_readlink(ep, vp, cred, &st,
			    &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_READDIR:
		case OES_EVENT_NOTIFY_READDIR:
			oes_fill_event_readdir(ep, dvp, cred, &st,
			    &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_LOOKUP:
		case OES_EVENT_NOTIFY_LOOKUP:
			oes_fill_event_lookup(ep, dvp, cnp, cred, &st,
			    &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_CREATE:
		case OES_EVENT_NOTIFY_CREATE:
			oes_fill_event_create(ep, dvp, vap, cnp, cred, &st,
			    &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_UNLINK:
		case OES_EVENT_NOTIFY_UNLINK:
			oes_fill_event_unlink(ep, dvp, vp, cnp, cred, &st,
			    &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_RENAME:
		case OES_EVENT_NOTIFY_RENAME:
			oes_fill_event_rename(ep, rename_ctx, dvp, cnp, cred,
			    &st, &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_LINK:
			oes_fill_event_link(ep, vp, dvp, cnp, cred, &st,
			    &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_KLDLOAD:
		case OES_EVENT_NOTIFY_KLDLOAD:
			oes_fill_event_kldload(ep, vp, cred, &st,
			    &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_MMAP:
			oes_fill_event_mmap(ep, vp, prot, mmap_flags, cred,
			    &st, &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_MPROTECT:
			oes_fill_event_mprotect(ep, vp, prot, cred, &st,
			    &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_SETMODE:
		case OES_EVENT_NOTIFY_SETMODE:
			oes_fill_event_setmode(ep, vp, mode, cred, &st,
			    &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_SETOWNER:
		case OES_EVENT_NOTIFY_SETOWNER:
			oes_fill_event_setowner(ep, vp, owner_uid, owner_gid,
			    cred, &st, &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_SETFLAGS:
		case OES_EVENT_NOTIFY_SETFLAGS:
			oes_fill_event_setflags(ep, vp, fflags, cred, &st,
			    &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_SETUTIMES:
		case OES_EVENT_NOTIFY_SETUTIMES:
			oes_fill_event_setutimes(ep, vp, atime, mtime, cred,
			    &st, &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_CHDIR:
			oes_fill_event_chdir(ep, dvp, cred, &st, &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_CHROOT:
			oes_fill_event_chroot(ep, dvp, cred, &st,
			    &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_SETEXTATTR:
			oes_fill_event_setextattr(ep, vp, attrnamespace,
			    attrname, cred, &st, &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_GETEXTATTR:
		case OES_EVENT_NOTIFY_GETEXTATTR:
			oes_fill_event_getextattr(ep, vp, attrnamespace,
			    attrname, cred, &st, &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_DELETEEXTATTR:
		case OES_EVENT_NOTIFY_DELETEEXTATTR:
			oes_fill_event_deleteextattr(ep, vp, attrnamespace,
			    attrname, cred, &st, &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_LISTEXTATTR:
		case OES_EVENT_NOTIFY_LISTEXTATTR:
			oes_fill_event_listextattr(ep, vp, attrnamespace, cred,
			    &st, &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_GETACL:
		case OES_EVENT_NOTIFY_GETACL:
			oes_fill_event_getacl(ep, vp, acl_type, cred, &st,
			    &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_SETACL:
		case OES_EVENT_NOTIFY_SETACL:
			oes_fill_event_setacl(ep, vp, acl_type, cred, &st,
			    &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_DELETEACL:
		case OES_EVENT_NOTIFY_DELETEACL:
			oes_fill_event_deleteacl(ep, vp, acl_type, cred, &st,
			    &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_RELABEL:
		case OES_EVENT_NOTIFY_RELABEL:
			oes_fill_event_relabel(ep, vp, cred, &st,
			    &ep->ep_msg);
			break;
		case OES_EVENT_NOTIFY_SIGNAL:
			oes_fill_event_signal(ep, target_proc, signum, &st,
			    &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_PTRACE:
		case OES_EVENT_NOTIFY_PTRACE:
			if (target_proc != NULL) {
				bool tp_owned = mtx_owned(&target_proc->p_mtx);

				if (!tp_owned)
					PROC_LOCK(target_proc);
				oes_fill_process(
				    &ep->ep_msg.em_event_data.ptrace.target,
				    target_proc, NULL, &st, &ep->ep_msg);
				if (!tp_owned)
					PROC_UNLOCK(target_proc);
			}
			break;
		case OES_EVENT_NOTIFY_SETUID:
			oes_fill_event_setuid(ep, uid);
			break;
		case OES_EVENT_NOTIFY_SETGID:
			oes_fill_event_setgid(ep, gid);
			break;
		case OES_EVENT_NOTIFY_SOCKET_CONNECT:
			oes_fill_socket_info(
			    &ep->ep_msg.em_event_data.socket_connect.socket, so);
			oes_fill_sockaddr(
			    &ep->ep_msg.em_event_data.socket_connect.address, sa);
			break;
		case OES_EVENT_NOTIFY_SOCKET_BIND:
			oes_fill_socket_info(
			    &ep->ep_msg.em_event_data.socket_bind.socket, so);
			oes_fill_sockaddr(
			    &ep->ep_msg.em_event_data.socket_bind.address, sa);
			break;
		case OES_EVENT_NOTIFY_SOCKET_LISTEN:
			oes_fill_socket_info(
			    &ep->ep_msg.em_event_data.socket_listen.socket, so);
			break;
		case OES_EVENT_NOTIFY_SOCKET_CREATE:
			ep->ep_msg.em_event_data.socket_create.domain =
			    info->socket_domain;
			ep->ep_msg.em_event_data.socket_create.type =
			    info->socket_type;
			ep->ep_msg.em_event_data.socket_create.protocol =
			    info->socket_protocol;
			break;
		case OES_EVENT_NOTIFY_SOCKET_ACCEPT:
			oes_fill_socket_info(
			    &ep->ep_msg.em_event_data.socket_accept.socket, so);
			break;
		case OES_EVENT_NOTIFY_SOCKET_SEND:
			oes_fill_socket_info(
			    &ep->ep_msg.em_event_data.socket_send.socket, so);
			break;
		case OES_EVENT_NOTIFY_SOCKET_RECEIVE:
			oes_fill_socket_info(
			    &ep->ep_msg.em_event_data.socket_receive.socket, so);
			break;
		case OES_EVENT_NOTIFY_SOCKET_STAT:
			oes_fill_socket_info(
			    &ep->ep_msg.em_event_data.socket_stat.socket, so);
			break;
		case OES_EVENT_NOTIFY_SOCKET_POLL:
			oes_fill_socket_info(
			    &ep->ep_msg.em_event_data.socket_poll.socket, so);
			break;
		case OES_EVENT_NOTIFY_PIPE_READ:
		case OES_EVENT_NOTIFY_PIPE_WRITE:
		case OES_EVENT_NOTIFY_PIPE_STAT:
		case OES_EVENT_NOTIFY_PIPE_POLL:
			ep->ep_msg.em_event_data.pipe.pipe_id =
			    info->pipe_id;
			break;
		case OES_EVENT_NOTIFY_PIPE_IOCTL:
			ep->ep_msg.em_event_data.pipe.pipe_id =
			    info->pipe_id;
			ep->ep_msg.em_event_data.pipe.ioctl_cmd =
			    info->ioctl_cmd;
			break;
		case OES_EVENT_NOTIFY_MOUNT_STAT:
			if (info->mp != NULL) {
				if (info->mp->mnt_vfc != NULL)
					strlcpy(ep->ep_msg.em_event_data.mount_stat.fstype,
					    info->mp->mnt_vfc->vfc_name,
					    sizeof(ep->ep_msg.em_event_data.mount_stat.fstype));
				ep->ep_msg.em_event_data.mount_stat.fspath_off =
				    oes_strtab_add(&st, &ep->ep_msg,
				    info->mp->mnt_stat.f_mntonname);
			}
			break;
		case OES_EVENT_NOTIFY_PRIV_CHECK:
			ep->ep_msg.em_event_data.priv.priv = info->priv;
			break;
		case OES_EVENT_NOTIFY_PROC_SCHED:
			if (info->target_proc != NULL) {
				if (info->nosleep) {
					/*
					 * NOSLEEP context: fill minimal info
					 * without PROC_LOCK. The scheduler holds
					 * a reference so pid/comm are stable.
					 * Cannot safely access p_stats for genid.
					 */
					oes_process_t *tp =
					    &ep->ep_msg.em_event_data.proc_sched.target;
					tp->ep_pid = info->target_proc->p_pid;
					tp->ep_token.ept_id = info->target_proc->p_pid;
					tp->ep_token.ept_genid = 0;
					strlcpy(tp->ep_comm,
					    info->target_proc->p_comm,
					    sizeof(tp->ep_comm));
				} else {
					bool tp_owned =
					    mtx_owned(&info->target_proc->p_mtx);

					if (!tp_owned)
						PROC_LOCK(info->target_proc);
					oes_fill_process(
					    &ep->ep_msg.em_event_data.proc_sched.target,
					    info->target_proc, NULL, &st,
					    &ep->ep_msg);
					if (!tp_owned)
						PROC_UNLOCK(info->target_proc);
				}
			}
			break;
		case OES_EVENT_NOTIFY_REBOOT:
			ep->ep_msg.em_event_data.reboot.howto = reboot_howto;
			break;
		case OES_EVENT_NOTIFY_SYSCTL:
			if (sysctl_name != NULL)
				ep->ep_msg.em_event_data.sysctl.name_off =
				    oes_strtab_add(&st, &ep->ep_msg,
				    sysctl_name);
			ep->ep_msg.em_event_data.sysctl.op = sysctl_op;
			break;
		case OES_EVENT_NOTIFY_KENV:
			if (kenv_name != NULL)
				ep->ep_msg.em_event_data.kenv.name_off =
				    oes_strtab_add(&st, &ep->ep_msg,
				    kenv_name);
			ep->ep_msg.em_event_data.kenv.op = kenv_op;
			break;
		case OES_EVENT_AUTH_SWAPON:
		case OES_EVENT_NOTIFY_SWAPON:
			if (vp != NULL)
				oes_fill_file(&ep->ep_msg.em_event_data.swapon.file,
				    vp, cred, &st, &ep->ep_msg);
			break;
		case OES_EVENT_AUTH_SWAPOFF:
		case OES_EVENT_NOTIFY_SWAPOFF:
			if (vp != NULL)
				oes_fill_file(&ep->ep_msg.em_event_data.swapoff.file,
				    vp, cred, &st, &ep->ep_msg);
			break;
		default:
			break;
		}

		ep->ep_msg.em_size = OES_MSG_ALIGNED(st.st_off);
	}

	/*
	 * Invalidate before consulting the cache.  Namespace changes are rare
	 * and can affect path-based decisions beyond a single inode, so use the
	 * conservative global operation for those.  Content/metadata mutations
	 * invalidate every client entry that references the affected file.
	 */
	if (oes_event_invalidates_namespace(event)) {
		oes_cache_invalidate_all();
	} else if (oes_event_invalidates_file(event) ||
	    (event == OES_EVENT_AUTH_MMAP &&
	    (ep->ep_msg.em_event_data.mmap.prot & PROT_WRITE) != 0) ||
	    (event == OES_EVENT_AUTH_MPROTECT &&
	    (ep->ep_msg.em_event_data.mprotect.prot & PROT_WRITE) != 0)) {
		const oes_file_t *file = oes_event_primary_file(ep);

		if (file != NULL)
			oes_cache_invalidate_token(&file->ef_token);
	}

	/* Use non-blocking delivery for NOSLEEP hooks */
	if (info->nosleep) {
		oes_deliver_notify_nosleep(ep, p);
		oes_pending_rele(ep);
		return (0);
	}

	error = oes_dispatch_event(ep, p, cred, notify_event);
	oes_pending_rele(ep);
	return (error);
}

/*
 * Generate exec event with arguments
 *
 * Captures argv from imgp->args for exec events.
 */
static int
oes_generate_exec_event(struct ucred *cred, struct vnode *vp,
    struct image_params *imgp)
{
	struct proc *p = curthread->td_proc;
	struct oes_pending *ep;
	oes_event_type_t event = OES_EVENT_AUTH_EXEC;
	oes_event_type_t notify_event;
	int error = 0;

	if (!oes_softc.sc_active || p == NULL)
		return (0);

	/*
	 * Skip duplicate exec events when execpath is NULL.
	 * The MAC hook is called twice: once with the path during initial
	 * exec processing, and again during rtld/interpreter handling with
	 * NULL path. We only want to generate one event with the actual path.
	 */
	if (imgp == NULL || imgp->execpath == NULL)
		return (0);

	notify_event = oes_auth_to_notify(event);

	ep = oes_pending_alloc(event, p);
	if (ep == NULL) {
		atomic_add_64(&oes_softc.sc_alloc_failures, 1);
		if (OES_EVENT_IS_AUTH(event))
			return (oes_require_auth_clients ||
			    oes_auth_fail_closed ||
			    oes_default_deadline_miss_mode ==
			    OES_DEADLINE_MISS_FAIL_CLOSED ? EACCES : 0);
		return (0);
	}

	{
		struct oes_strtab st;
		uint32_t exec_path_off;

		oes_strtab_init(&st);
		st.st_off = ep->ep_msg.em_size;

		if (vp != NULL)
			oes_fill_file(&ep->ep_msg.em_event_data.exec.executable,
			    vp, cred, &st, &ep->ep_msg);

		/* Pre-exec snapshot */
		PROC_LOCK(p);
		oes_fill_process(&ep->ep_msg.em_event_data.exec.target, p, NULL,
		    &st, &ep->ep_msg);
		PROC_UNLOCK(p);

		if (imgp != NULL && imgp->execpath != NULL) {
			exec_path_off = oes_strtab_add(&st, &ep->ep_msg,
			    imgp->execpath);
			ep->ep_msg.em_event_data.exec.executable.ef_path_off =
			    exec_path_off;
			ep->ep_msg.em_event_data.exec.target.ep_path_off =
			    exec_path_off;
			ep->ep_msg.em_event_data.exec.target.ep_meta_flags &=
			    ~(OES_PROC_META_PATH_UNAVAILABLE |
			    OES_PROC_META_PATH_TRUNCATED);
			ep->ep_msg.em_event_data.exec.executable.ef_meta_flags &=
			    ~(OES_FILE_META_PATH_UNAVAILABLE |
			    OES_FILE_META_PATH_TRUNCATED |
			    OES_FILE_META_PATH_REQUESTED);
			if (exec_path_off == 0) {
				oes_file_mark_path_unavailable(&ep->ep_msg,
				    &ep->ep_msg.em_event_data.exec.executable);
				oes_process_mark_path_unavailable(&ep->ep_msg,
				    &ep->ep_msg.em_event_data.exec.target);
			}
		}

		if (imgp != NULL && imgp->args != NULL) {
			struct image_args *args = imgp->args;
			oes_event_exec_t *exec = &ep->ep_msg.em_event_data.exec;
			size_t argv_len, envp_len, total_len;
			size_t copy_argv, copy_envp;
			char *envv_start;

			exec->argc = args->argc;
			exec->envc = args->envc;
			exec->argv_off = 0;
			exec->argv_len = 0;
			exec->envp_off = 0;
			exec->envp_len = 0;
			exec->flags = 0;

			/* Calculate argv length (from begin_argv to begin_envv) */
			argv_len = 0;
			envp_len = 0;
			envv_start = NULL;
			if (args->begin_argv != NULL) {
				envv_start = exec_args_get_begin_envv(args);
				if (envv_start != NULL &&
				    envv_start > args->begin_argv) {
					argv_len = envv_start - args->begin_argv;
				} else if (args->endp != NULL &&
				    args->endp > args->begin_argv) {
					argv_len = args->endp - args->begin_argv;
					envv_start = NULL;
				}

				/* Calculate envp length */
				if (envv_start != NULL && args->endp != NULL &&
				    args->endp > envv_start) {
					envp_len = args->endp - envv_start;
				}
			}

			/* Copy argv (truncate if necessary) */
			copy_argv = argv_len;
			if (copy_argv > OES_EXEC_ARGS_MAX) {
				copy_argv = OES_EXEC_ARGS_MAX;
				exec->flags |= EE_FLAG_ARGV_TRUNCATED;
			}
			if (copy_argv > 0 && args->begin_argv != NULL) {
				exec->argv_off = oes_strtab_add_buf(&st,
				    &ep->ep_msg, args->begin_argv, copy_argv);
				exec->argv_len = copy_argv;
			}

			/* Copy envp if there's room */
			total_len = copy_argv + envp_len;
			if (total_len > OES_EXEC_ARGS_MAX) {
				copy_envp = OES_EXEC_ARGS_MAX - copy_argv;
				if (envp_len > 0)
					exec->flags |= EE_FLAG_ENVP_TRUNCATED;
			} else {
				copy_envp = envp_len;
			}
			if (copy_envp > 0 && envv_start != NULL) {
				exec->envp_off = oes_strtab_add_buf(&st,
				    &ep->ep_msg, envv_start, copy_envp);
				exec->envp_len = copy_envp;
			}
		}

		ep->ep_msg.em_size = OES_MSG_ALIGNED(st.st_off);
	}

	error = oes_dispatch_event(ep, p, cred, notify_event);
	oes_pending_rele(ep);
	return (error);
}

/*
 * MAC hook: vnode_check_exec
 *
 * Called when a process attempts to execute a file.
 * This is sleepable - can block for AUTH response.
 */
static int
oes_mac_vnode_check_exec(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct image_params *imgp,
    struct label *execlabel)
{
	return (oes_generate_exec_event(cred, vp, imgp));
}

/*
 * MAC hook: vnode_check_open
 */
static int
oes_mac_vnode_check_open(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.accmode = accmode;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_OPEN, &info));
}

/*
 * File close.  Uses the mac_vnode_check_close hook added to the MAC framework
 * for this purpose.  Close cannot be denied, so this is a NOTIFY-only event.
 */
static int
oes_mac_vnode_check_close(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;

	return (oes_generate_vnode_event(OES_EVENT_NOTIFY_CLOSE, &info));
}

/*
 * MAC hook: vnode_check_create
 */
static int
oes_mac_vnode_check_create(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp, struct vattr *vap)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.dvp = dvp;
	info.cnp = cnp;
	info.vap = vap;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_CREATE, &info));
}

/*
 * MAC hook: vnode_check_unlink
 */
static int
oes_mac_vnode_check_unlink(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.dvp = dvp;
	info.cnp = cnp;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_UNLINK, &info));
}

/*
 * MAC hook: vnode_check_rename_from
 */
static int
oes_mac_vnode_check_rename_from(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.dvp = dvp;
	info.cnp = cnp;


	oes_rename_cache_store(curthread, &info);
	return (0);
}

/*
 * MAC hook: vnode_check_rename_to
 */
static int
oes_mac_vnode_check_rename_to(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    int samedir, struct componentname *cnp)
{
	int error;
	struct oes_rename_ctx *ctx;
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.dvp = dvp;
	info.cnp = cnp;


	(void)samedir;
	ctx = oes_rename_cache_take(curthread);
	info.rename_ctx = ctx;
	if (ctx == NULL)
		return (0);

	error = oes_generate_vnode_event(OES_EVENT_AUTH_RENAME, &info);
	free(ctx, M_OES);
	return (error);
}

/*
 * MAC hook: vnode_check_link
 */
static int
oes_mac_vnode_check_link(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.dvp = dvp;
	info.cnp = cnp;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_LINK, &info));
}

/*
 * MAC hook: vnode_check_access
 */
static int
oes_mac_vnode_check_access(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.accmode = accmode;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_ACCESS, &info));
}

/*
 * MAC hook: vnode_check_read
 */
static int
oes_mac_vnode_check_read(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(active_cred);

	info.vp = vp;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_READ, &info));
}

/*
 * MAC hook: vnode_check_write
 */
static int
oes_mac_vnode_check_write(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(active_cred);

	info.vp = vp;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_WRITE, &info));
}

/* Truncate event delivery is pending, but cache invalidation is mandatory. */
static int
oes_mac_vnode_check_truncate(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	oes_file_token_t token = { 0 };
	struct vattr va;

	(void)vplabel;
	if (!oes_softc.sc_active)
		return (0);
	if (VOP_GETATTR(vp, &va, cred) == 0) {
		token.eft_id = va.va_fileid;
		token.eft_dev = va.va_fsid;
		oes_cache_invalidate_token(&token);
	} else {
		/* An unresolved mutation must not leave stale allow decisions. */
		oes_cache_invalidate_all();
	}
	return (0);
}

/*
 * MAC hook: vnode_check_stat
 */
static int
oes_mac_vnode_check_stat(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(active_cred);

	info.vp = vp;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_STAT, &info));
}

/*
 * MAC hook: vnode_check_poll
 */
static int
oes_mac_vnode_check_poll(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(active_cred);

	info.vp = vp;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_POLL, &info));
}

/*
 * MAC hook: vnode_check_readdir
 */
static int
oes_mac_vnode_check_readdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.dvp = dvp;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_READDIR, &info));
}

/*
 * MAC hook: vnode_check_readlink
 */
static int
oes_mac_vnode_check_readlink(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_READLINK, &info));
}

/*
 * MAC hook: vnode_check_revoke
 */
static int
oes_mac_vnode_check_revoke(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_REVOKE, &info));
}

/*
 * MAC hook: vnode_check_lookup
 */
static int
oes_mac_vnode_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.dvp = dvp;
	info.cnp = cnp;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_LOOKUP, &info));
}

/*
 * MAC hook: vnode_check_setmode
 */
static int
oes_mac_vnode_check_setmode(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, mode_t mode)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.mode = mode;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_SETMODE, &info));
}

/*
 * MAC hook: vnode_check_setowner
 */
static int
oes_mac_vnode_check_setowner(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, uid_t uid, gid_t gid)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.owner_uid = uid;
	info.owner_gid = gid;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_SETOWNER, &info));
}

/*
 * MAC hook: vnode_check_setflags
 */
static int
oes_mac_vnode_check_setflags(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, u_long flags)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.fflags = flags;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_SETFLAGS, &info));
}

/*
 * MAC hook: vnode_check_setutimes
 */
static int
oes_mac_vnode_check_setutimes(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct timespec atime, struct timespec mtime)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.atime = atime;
	info.mtime = mtime;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_SETUTIMES, &info));
}

/*
 * MAC hook: vnode_check_chdir
 */
static int
oes_mac_vnode_check_chdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.dvp = dvp;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_CHDIR, &info));
}

/*
 * MAC hook: vnode_check_chroot
 */
static int
oes_mac_vnode_check_chroot(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.dvp = dvp;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_CHROOT, &info));
}

/*
 * MAC hook: vnode_check_mmap
 */
static int
oes_mac_vnode_check_mmap(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot, int flags)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.prot = prot;
	info.mmap_flags = flags;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_MMAP, &info));
}

/*
 * MAC hook: vnode_check_mprotect
 */
static int
oes_mac_vnode_check_mprotect(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.prot = prot;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_MPROTECT, &info));
}

/*
 * MAC hook: vnode_check_setextattr
 */
static int
oes_mac_vnode_check_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.attrnamespace = attrnamespace;
	info.attrname = name;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_SETEXTATTR, &info));
}

/*
 * MAC hook: vnode_check_getextattr
 */
static int
oes_mac_vnode_check_getextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.attrnamespace = attrnamespace;
	info.attrname = name;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_GETEXTATTR, &info));
}

/*
 * MAC hook: vnode_check_deleteextattr
 */
static int
oes_mac_vnode_check_deleteextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.attrnamespace = attrnamespace;
	info.attrname = name;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_DELETEEXTATTR, &info));
}

/*
 * MAC hook: vnode_check_listextattr
 */
static int
oes_mac_vnode_check_listextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.attrnamespace = attrnamespace;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_LISTEXTATTR, &info));
}

/*
 * MAC hook: vnode_check_getacl
 */
static int
oes_mac_vnode_check_getacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.acl_type = type;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_GETACL, &info));
}

/*
 * MAC hook: vnode_check_setacl
 */
static int
oes_mac_vnode_check_setacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type, struct acl *acl)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.acl_type = type;


	(void)acl;
	return (oes_generate_vnode_event(OES_EVENT_AUTH_SETACL, &info));
}

/*
 * MAC hook: vnode_check_deleteacl
 */
static int
oes_mac_vnode_check_deleteacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.acl_type = type;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_DELETEACL, &info));
}

/*
 * MAC hook: vnode_check_relabel
 */
static int
oes_mac_vnode_check_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;


	(void)newlabel;
	return (oes_generate_vnode_event(OES_EVENT_AUTH_RELABEL, &info));
}

/*
 * MAC hook: kld_check_load
 */
static int
oes_mac_kld_check_load(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_KLDLOAD, &info));
}

/*
 * MAC hook: proc_check_signal
 */
static int
oes_mac_proc_check_signal(struct ucred *cred, struct proc *p, int signum)
{
	struct oes_pending *ep;
	struct proc *curp = curthread->td_proc;

	if (!oes_softc.sc_active)
		return (0);

	ep = oes_pending_alloc(OES_EVENT_NOTIFY_SIGNAL, curp);
	if (ep == NULL)
		return (0);

	{
		struct oes_strtab st;
		bool owned = mtx_owned(&p->p_mtx);

		oes_strtab_init(&st);
		st.st_off = ep->ep_msg.em_size;

		if (!owned)
			PROC_LOCK(p);
		oes_fill_process(&ep->ep_msg.em_event_data.signal.target, p, NULL,
		    &st, &ep->ep_msg);
		if (!owned)
			PROC_UNLOCK(p);

		ep->ep_msg.em_event_data.signal.signum = signum;
		ep->ep_msg.em_size = OES_MSG_ALIGNED(st.st_off);
	}

	oes_deliver_notify_nosleep(ep, curp);
	oes_pending_rele(ep);
	return (0);
}

/*
 * MAC hook: cred_check_setuid
 */
static int
oes_mac_cred_check_setuid(struct ucred *cred, uid_t uid)
{
	struct oes_pending *ep;
	struct proc *curp = curthread->td_proc;

	if (!oes_softc.sc_active)
		return (0);

	ep = oes_pending_alloc(OES_EVENT_NOTIFY_SETUID, curp);
	if (ep == NULL)
		return (0);

	ep->ep_msg.em_event_data.setuid.uid = uid;
	oes_deliver_notify_nosleep(ep, curp);
	oes_pending_rele(ep);
	return (0);
}

/*
 * MAC hook: cred_check_setgid
 */
static int
oes_mac_cred_check_setgid(struct ucred *cred, gid_t gid)
{
	struct oes_pending *ep;
	struct proc *curp = curthread->td_proc;

	if (!oes_softc.sc_active)
		return (0);

	ep = oes_pending_alloc(OES_EVENT_NOTIFY_SETGID, curp);
	if (ep == NULL)
		return (0);

	ep->ep_msg.em_event_data.setgid.gid = gid;
	oes_deliver_notify_nosleep(ep, curp);
	oes_pending_rele(ep);
	return (0);
}

/*
 * MAC hook: proc_check_debug (for ptrace)
 *
 * Called from p_candebug() with PROC_LOCK held (MA_OWNED assert).
 * Cannot sleep or take OES_LOCK -- must use NOSLEEP notify path.
 * AUTH_PTRACE is not possible because we cannot block under PROC_LOCK.
 */
static int
oes_mac_proc_check_debug(struct ucred *cred, struct proc *p)
{
	struct oes_pending *ep;
	struct proc *curp = curthread->td_proc;

	if (!oes_softc.sc_active)
		return (0);

	ep = oes_pending_alloc(OES_EVENT_NOTIFY_PTRACE, curp);
	if (ep == NULL)
		return (0);

	/* p is already locked by caller (p_candebug) */
	{
		struct oes_strtab st;

		oes_strtab_init(&st);
		st.st_off = ep->ep_msg.em_size;
		oes_fill_process(&ep->ep_msg.em_event_data.ptrace.target, p, NULL,
		    &st, &ep->ep_msg);
		ep->ep_msg.em_size = OES_MSG_ALIGNED(st.st_off);
	}

	oes_deliver_notify_nosleep(ep, curp);
	oes_pending_rele(ep);
	return (0);
}

static void
oes_fill_sockaddr(oes_sockaddr_t *esa, const struct sockaddr *sa)
{
	memset(esa, 0, sizeof(*esa));

	if (sa == NULL)
		return;

	esa->esa_family = sa->sa_family;

	switch (sa->sa_family) {
	case AF_INET:
		{
			const struct sockaddr_in *sin =
			    (const struct sockaddr_in *)sa;
			if (sa->sa_len < sizeof(struct sockaddr_in))
				break;  /* malformed, leave zeroed */
			esa->esa_port = sin->sin_port;
			esa->esa_addr.v4 = sin->sin_addr.s_addr;
		}
		break;

	case AF_INET6:
		{
			const struct sockaddr_in6 *sin6 =
			    (const struct sockaddr_in6 *)sa;
			if (sa->sa_len < sizeof(struct sockaddr_in6))
				break;  /* malformed, leave zeroed */
			esa->esa_port = sin6->sin6_port;
			memcpy(esa->esa_addr.v6, &sin6->sin6_addr, 16);
		}
		break;

	case AF_UNIX:
		{
			const struct sockaddr_un *sun =
			    (const struct sockaddr_un *)sa;
			size_t maxlen;

			/*
			 * AF_UNIX paths may not be NUL-terminated if the
			 * path fills the entire sun_path buffer.  Use sun_len
			 * to bound the copy and avoid reading past the struct.
			 */
			if (sun->sun_len > offsetof(struct sockaddr_un, sun_path))
				maxlen = sun->sun_len -
				    offsetof(struct sockaddr_un, sun_path);
			else
				maxlen = 0;
			if (maxlen > sizeof(sun->sun_path))
				maxlen = sizeof(sun->sun_path);
			if (maxlen > sizeof(esa->esa_addr.path) - 1)
				maxlen = sizeof(esa->esa_addr.path) - 1;
			memcpy(esa->esa_addr.path, sun->sun_path, maxlen);
			esa->esa_addr.path[maxlen] = '\0';
		}
		break;
	}
}

static void
oes_fill_socket_info(oes_socket_t *es, struct socket *so)
{
	memset(es, 0, sizeof(*es));

	if (so == NULL)
		return;

	/*
	 * Sockets should always have so_proto set, but check defensively
	 * in case we see a partially initialized socket.
	 */
	if (so->so_proto == NULL)
		return;

	if (so->so_proto->pr_domain != NULL)
		es->es_domain = so->so_proto->pr_domain->dom_family;
	es->es_type = so->so_type;
	es->es_protocol = so->so_proto->pr_protocol;
}

/*
 * MAC hook: socket_check_connect
 */
static int
oes_mac_socket_check_connect(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);
	(void)solabel;

	info.socket = so;
	info.sockaddr = sa;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_SOCKET_CONNECT, &info);
	return (0);
}

/*
 * MAC hook: socket_check_bind
 */
static int
oes_mac_socket_check_bind(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);
	(void)solabel;

	info.socket = so;
	info.sockaddr = sa;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_SOCKET_BIND, &info);
	return (0);
}

/*
 * MAC hook: socket_check_listen
 */
static int
oes_mac_socket_check_listen(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);
	(void)solabel;

	info.socket = so;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_SOCKET_LISTEN, &info);
	return (0);
}

/*
 * MAC hook: socket_check_create
 */
static int
oes_mac_socket_check_create(struct ucred *cred, int domain, int type,
    int protocol)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.socket_domain = domain;
	info.socket_type = type;
	info.socket_protocol = protocol;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_SOCKET_CREATE, &info);
	return (0);
}

/*
 * MAC hook: socket_check_accept
 */
static int
oes_mac_socket_check_accept(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);
	(void)solabel;

	info.socket = so;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_SOCKET_ACCEPT, &info);
	return (0);
}

/*
 * MAC hook: socket_check_send
 */
static int
oes_mac_socket_check_send(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);
	(void)solabel;

	info.socket = so;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_SOCKET_SEND, &info);
	return (0);
}

/*
 * MAC hook: socket_check_receive
 */
static int
oes_mac_socket_check_receive(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);
	(void)solabel;

	info.socket = so;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_SOCKET_RECEIVE, &info);
	return (0);
}

/*
 * MAC hook: socket_check_stat
 */
static int
oes_mac_socket_check_stat(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);
	(void)solabel;

	info.socket = so;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_SOCKET_STAT, &info);
	return (0);
}

/*
 * MAC hook: socket_check_poll
 */
static int
oes_mac_socket_check_poll(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);
	(void)solabel;

	info.socket = so;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_SOCKET_POLL, &info);
	return (0);
}

/*
 * MAC hook: system_check_reboot
 */
static int
oes_mac_system_check_reboot(struct ucred *cred, int howto)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.reboot_howto = howto;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_REBOOT, &info);
	return (0);
}

/*
 * MAC hook: system_check_sysctl
 */
static int
oes_mac_system_check_sysctl(struct ucred *cred, struct sysctl_oid *oidp,
    void *arg1, int arg2, struct sysctl_req *req)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);
	char name[256];

	/* Build the sysctl name from OID path */
	if (oidp != NULL && oidp->oid_name != NULL) {
		struct sysctl_oid *p;
		char *buf = name;
		size_t buflen = sizeof(name);
		size_t len;

		/* Walk up the tree to build full name */
		name[0] = '\0';
		for (p = oidp; p != NULL && p->oid_name != NULL;
		    p = SYSCTL_PARENT(p)) {
			if (name[0] != '\0') {
				len = strlen(p->oid_name);
				if (len + 1 + strlen(name) < buflen) {
					memmove(buf + len + 1, name,
					    strlen(name) + 1);
					memcpy(buf, p->oid_name, len);
					buf[len] = '.';
				}
			} else {
				strlcpy(name, p->oid_name, buflen);
			}
		}
		info.sysctl_name = name;
	}
	info.sysctl_op = (req != NULL && req->newptr != NULL) ? 1 : 0;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_SYSCTL, &info);
	return (0);
}

/*
 * MAC hook: kenv_check_set
 */
static int
oes_mac_kenv_check_set(struct ucred *cred, char *name, char *value)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	(void)value;
	info.kenv_name = name;
	info.kenv_op = 1;  /* set */
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_KENV, &info);
	return (0);
}

/*
 * MAC hook: kenv_check_unset
 */
static int
oes_mac_kenv_check_unset(struct ucred *cred, char *name)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.kenv_name = name;
	info.kenv_op = 2;  /* unset */
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_KENV, &info);
	return (0);
}

/*
 * MAC hook: pipe_check_read
 */
static int
oes_mac_pipe_check_read(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);
	struct oes_pipe_label *epl =
	    pplabel != NULL ? PIPE_SLOT(pplabel) : NULL;

	info.pipepair = pp;
	info.pipe_id = epl != NULL ? epl->epl_id : 0;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_PIPE_READ, &info);
	return (0);
}

/*
 * MAC hook: pipe_check_write
 */
static int
oes_mac_pipe_check_write(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);
	struct oes_pipe_label *epl =
	    pplabel != NULL ? PIPE_SLOT(pplabel) : NULL;

	info.pipepair = pp;
	info.pipe_id = epl != NULL ? epl->epl_id : 0;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_PIPE_WRITE, &info);
	return (0);
}

/*
 * MAC hook: pipe_check_stat
 */
static int
oes_mac_pipe_check_stat(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);
	struct oes_pipe_label *epl =
	    pplabel != NULL ? PIPE_SLOT(pplabel) : NULL;

	info.pipepair = pp;
	info.pipe_id = epl != NULL ? epl->epl_id : 0;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_PIPE_STAT, &info);
	return (0);
}

/*
 * MAC hook: pipe_check_poll
 */
static int
oes_mac_pipe_check_poll(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);
	struct oes_pipe_label *epl =
	    pplabel != NULL ? PIPE_SLOT(pplabel) : NULL;

	info.pipepair = pp;
	info.pipe_id = epl != NULL ? epl->epl_id : 0;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_PIPE_POLL, &info);
	return (0);
}

/*
 * MAC hook: pipe_check_ioctl
 */
static int
oes_mac_pipe_check_ioctl(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel, unsigned long cmd, void *data)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);
	struct oes_pipe_label *epl =
	    pplabel != NULL ? PIPE_SLOT(pplabel) : NULL;
	(void)data;

	info.pipepair = pp;
	info.pipe_id = epl != NULL ? epl->epl_id : 0;
	info.ioctl_cmd = cmd;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_PIPE_IOCTL, &info);
	return (0);
}

/*
 * MAC hook: mount_check_stat
 */
static int
oes_mac_mount_check_stat(struct ucred *cred, struct mount *mp,
    struct label *mplabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);
	(void)mplabel;

	info.mp = mp;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_MOUNT_STAT, &info);
	return (0);
}

/*
 * MAC hook: priv_check
 */
static int
oes_mac_priv_check(struct ucred *cred, int priv)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.priv = priv;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_PRIV_CHECK, &info);
	return (0);
}

/*
 * MAC hook: proc_check_sched
 */
static int
oes_mac_proc_check_sched(struct ucred *cred, struct proc *p)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.target_proc = p;
	info.nosleep = true;

	(void)oes_generate_vnode_event(OES_EVENT_NOTIFY_PROC_SCHED, &info);
	return (0);
}

/*
 * MAC hook: system_check_swapon
 *
 * Called when enabling swap on a device/file.
 */
static int
oes_mac_system_check_swapon(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_SWAPON, &info));
}

/*
 * MAC hook: system_check_swapoff
 *
 * Called when disabling swap on a device/file.
 */
static int
oes_mac_system_check_swapoff(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct oes_vnode_event_info info = OES_VNODE_INFO_INIT(cred);

	info.vp = vp;

	return (oes_generate_vnode_event(OES_EVENT_AUTH_SWAPOFF, &info));
}

/*
 * MAC policy operations structure
 */
static struct mac_policy_ops oes_mac_ops = {
	/* Credential label management */
	.mpo_cred_init_label = oes_mac_cred_init_label,
	.mpo_cred_destroy_label = oes_mac_cred_destroy_label,
	.mpo_cred_copy_label = oes_mac_cred_copy_label,
	.mpo_cred_check_setuid = oes_mac_cred_check_setuid,
	.mpo_cred_check_setgid = oes_mac_cred_check_setgid,

	/* Every successful exec refreshes the path and execution identity. */
	.mpo_vnode_execve_will_relabel = oes_mac_vnode_execve_will_relabel,
	.mpo_vnode_execve_relabel = oes_mac_vnode_execve_relabel,

	/* Sleepable VFS checks - can block for AUTH */
	.mpo_vnode_check_exec = oes_mac_vnode_check_exec,
	.mpo_vnode_check_access = oes_mac_vnode_check_access,
	.mpo_vnode_check_lookup = oes_mac_vnode_check_lookup,
	.mpo_vnode_check_read = oes_mac_vnode_check_read,
	.mpo_vnode_check_write = oes_mac_vnode_check_write,
	.mpo_vnode_check_truncate = oes_mac_vnode_check_truncate,
	.mpo_vnode_check_stat = oes_mac_vnode_check_stat,
	.mpo_vnode_check_poll = oes_mac_vnode_check_poll,
	.mpo_vnode_check_readdir = oes_mac_vnode_check_readdir,
	.mpo_vnode_check_readlink = oes_mac_vnode_check_readlink,
	.mpo_vnode_check_revoke = oes_mac_vnode_check_revoke,
	.mpo_vnode_check_open = oes_mac_vnode_check_open,
	.mpo_vnode_check_close = oes_mac_vnode_check_close,
	.mpo_vnode_check_create = oes_mac_vnode_check_create,
	.mpo_vnode_check_unlink = oes_mac_vnode_check_unlink,
	.mpo_vnode_check_rename_from = oes_mac_vnode_check_rename_from,
	.mpo_vnode_check_rename_to = oes_mac_vnode_check_rename_to,
	.mpo_vnode_check_link = oes_mac_vnode_check_link,
	.mpo_vnode_check_chdir = oes_mac_vnode_check_chdir,
	.mpo_vnode_check_chroot = oes_mac_vnode_check_chroot,
	.mpo_vnode_check_mmap = oes_mac_vnode_check_mmap,
	.mpo_vnode_check_mprotect = oes_mac_vnode_check_mprotect,
	.mpo_vnode_check_setextattr = oes_mac_vnode_check_setextattr,
	.mpo_vnode_check_getextattr = oes_mac_vnode_check_getextattr,
	.mpo_vnode_check_deleteextattr = oes_mac_vnode_check_deleteextattr,
	.mpo_vnode_check_listextattr = oes_mac_vnode_check_listextattr,
	.mpo_vnode_check_getacl = oes_mac_vnode_check_getacl,
	.mpo_vnode_check_setacl = oes_mac_vnode_check_setacl,
	.mpo_vnode_check_deleteacl = oes_mac_vnode_check_deleteacl,
	.mpo_vnode_check_relabel = oes_mac_vnode_check_relabel,
	.mpo_vnode_check_setmode = oes_mac_vnode_check_setmode,
	.mpo_vnode_check_setowner = oes_mac_vnode_check_setowner,
	.mpo_vnode_check_setflags = oes_mac_vnode_check_setflags,
	.mpo_vnode_check_setutimes = oes_mac_vnode_check_setutimes,

	/* KLD check - sleepable (can block for AUTH response) */
	.mpo_kld_check_load = oes_mac_kld_check_load,

	/* Process checks - NOSLEEP (cannot block for AUTH response) */
	.mpo_proc_check_debug = oes_mac_proc_check_debug,
	.mpo_proc_check_signal = oes_mac_proc_check_signal,

	/* Socket checks - NOSLEEP (cannot block for AUTH response) */
	.mpo_socket_check_connect = oes_mac_socket_check_connect,
	.mpo_socket_check_bind = oes_mac_socket_check_bind,
	.mpo_socket_check_listen = oes_mac_socket_check_listen,
	.mpo_socket_check_create = oes_mac_socket_check_create,
	.mpo_socket_check_accept = oes_mac_socket_check_accept,
	.mpo_socket_check_send = oes_mac_socket_check_send,
	.mpo_socket_check_receive = oes_mac_socket_check_receive,
	.mpo_socket_check_stat = oes_mac_socket_check_stat,
	.mpo_socket_check_poll = oes_mac_socket_check_poll,

	/* Pipe checks - NOSLEEP (cannot block for AUTH response) */
	.mpo_pipe_check_read = oes_mac_pipe_check_read,
	.mpo_pipe_check_write = oes_mac_pipe_check_write,
	.mpo_pipe_check_stat = oes_mac_pipe_check_stat,
	.mpo_pipe_check_poll = oes_mac_pipe_check_poll,
	.mpo_pipe_check_ioctl = oes_mac_pipe_check_ioctl,
	.mpo_pipe_init_label = oes_mac_pipe_init_label,
	.mpo_pipe_destroy_label = oes_mac_pipe_destroy_label,
	.mpo_pipe_copy_label = oes_mac_pipe_copy_label,

	/* Mount check - NOSLEEP */
	.mpo_mount_check_stat = oes_mac_mount_check_stat,

	/* Privilege check - NOSLEEP */
	.mpo_priv_check = oes_mac_priv_check,

	/* Process scheduling check - NOSLEEP */
	.mpo_proc_check_sched = oes_mac_proc_check_sched,

	/*
	 * System checks - mixed sleep semantics:
	 *   reboot, sysctl: NOSLEEP (cannot block for AUTH response)
	 *   swapon, swapoff: sleepable (can block for AUTH response)
	 */
	.mpo_system_check_reboot = oes_mac_system_check_reboot,
	.mpo_system_check_sysctl = oes_mac_system_check_sysctl,
	.mpo_system_check_swapon = oes_mac_system_check_swapon,
	.mpo_system_check_swapoff = oes_mac_system_check_swapoff,

	/* Kenv checks - NOSLEEP (cannot block for AUTH response) */
	.mpo_kenv_check_set = oes_mac_kenv_check_set,
	.mpo_kenv_check_unset = oes_mac_kenv_check_unset,
};

/*
 * MAC policy configuration - registered manually, not via MAC_POLICY_SET
 * because we're part of the oes module, not a standalone MAC policy module.
 * The outer module handler enforces boot-only loading because OES initializes
 * in SI_SUB_DRIVERS, after the MAC framework's late-load boundary.  Omitting
 * UNLOADOK makes the policy non-unloadable as an additional safeguard.
 */
static struct mac_policy_conf oes_mac_policy_conf = {
	.mpc_name = "oes",
	.mpc_fullname = "Endpoint Security Capabilities",
	.mpc_ops = &oes_mac_ops,
	.mpc_loadtime_flags = 0,
	.mpc_field_off = &oes_slot,
	.mpc_runtime_flags = 0,
};

/*
 * Initialize MAC policy
 *
 * Called from oes module load. Registers with MAC framework.
 */
int
oes_mac_init(void)
{
	int error;

	error = mac_policy_modevent(NULL, MOD_LOAD, &oes_mac_policy_conf);
	if (error != 0) {
		OES_ERR("failed to register MAC policy: %d", error);
		return (error);
	}

	oes_mac_registered = true;
	OES_DEBUG("MAC policy registered");

	oes_rename_cache_init();

	EVENTHANDLER_REGISTER(process_fork,
	    oes_proc_event_fork, NULL, EVENTHANDLER_PRI_LAST);
	EVENTHANDLER_REGISTER(process_exit,
	    oes_proc_event_exit, NULL, EVENTHANDLER_PRI_LAST);
	EVENTHANDLER_REGISTER(vfs_mounted,
	    oes_vfs_event_mounted, NULL, EVENTHANDLER_PRI_LAST);
	EVENTHANDLER_REGISTER(vfs_unmounted,
	    oes_vfs_event_unmounted, NULL, EVENTHANDLER_PRI_LAST);
	EVENTHANDLER_REGISTER(kld_unload,
	    oes_kld_event_unload, NULL, EVENTHANDLER_PRI_LAST);

	return (0);
}
