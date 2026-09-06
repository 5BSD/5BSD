/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * tzfsd(8) request loop.  tzfsd is a socket-free service_provider: it exposes
 * system.Filesystem and serves each client on its own mac_capability worker
 * channel.  Every handle is derived/created/cloned/destroyed from the retained
 * parent handles in capability mode, and the granted handle rides back to the
 * client as the reply's single SCM fd.
 *
 * Dataset keys are opaque, single-level names derived by the trusted bundle
 * parser.  tzfsd never accepts a user-facing role or path.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/capsicum.h>

#include <dev/hid/vhid.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sha256.h>

#include <channel.h>
#include <libservice.h>
#include <trustedzfs.h>

#include "tzfsd.h"
#include "tzfsd_probes.h"

/*
 * Per-connection worker context: the retained-handle state (a private COW copy)
 * plus the connecting client's unforgeable label, which namespaces every leaf
 * this client can name.
 */
struct tzfs_conn {
	struct tzfsd_state	*st;
	char			client[64];	/* == service_identity.client_label */
	/*
	 * A DELIVER_MOUNTED grant anchors its anonymous mount on the leaf
	 * handle: the mount lives only while that handle stays open (closing it
	 * force-unmounts, dooming the consumer's delivered directory fd).  Retain
	 * the handle here for the connection's lifetime so the delivered store
	 * stays mounted as long as the client holds its storage lease; the worker
	 * closes it on teardown, which unmounts.  -1 == none held.
	 */
	int			mount_anchor_fd;
};

/* A claim name must be a single, safe path component. */
static bool
valid_dataset(const char *name)
{

	if (memchr(name, '\0', TZFSD_NAME_MAX) == NULL)
		return (false);
	if (name[0] == '\0' || strcmp(name, ".") == 0 ||
	    strcmp(name, "..") == 0)
		return (false);
	if (strchr(name, '/') != NULL)
		return (false);
	return (true);
}

static bool
all_zero(const void *buf, size_t len)
{
	const unsigned char *p = buf;
	size_t i;

	for (i = 0; i < len; i++)
		if (p[i] != 0)
			return (false);
	return (true);
}

/*
 * Reject any literal ".." path component (a ".." sitting between slashes),
 * while allowing legitimate names that merely embed ".." such as
 * /dev/foo..bar.  The path is already known to be NUL-terminated and to start
 * with '/'.  Component-wise, this mirrors config.c's absolute_path_valid().
 */
static bool
has_dotdot_component(const char *path)
{
	const char *component = path + 1, *slash;
	size_t n;

	for (;;) {
		slash = strchr(component, '/');
		n = slash == NULL ? strlen(component) : (size_t)(slash - component);
		if (n == 2 && component[0] == '.' && component[1] == '.')
			return (true);
		if (slash == NULL)
			return (false);
		component = slash + 1;
	}
}

/* Reject malformed and ambiguous protocol messages before dispatch. */
static bool
valid_request(const struct tzfsd_request *rq)
{

	if (!all_zero(rq->_reserved, sizeof(rq->_reserved)) ||
	    rq->deliver > TZFSD_DELIVER_MOUNTED ||
	    memchr(rq->dataset, '\0', sizeof(rq->dataset)) == NULL ||
	    memchr(rq->session, '\0', sizeof(rq->session)) == NULL)
		return (false);
	switch (rq->op) {
	case TZFSD_OP_REQUEST:
		/*
		 * quota (0=default, else validated in grant) may be nonzero.
		 * DELIVER_MOUNTED is only meaningful for a claim that was granted
		 * ZH_MOUNT — tzfsd mounts it server-side and returns the dir fd.
		 */
		if (rq->deliver == TZFSD_DELIVER_MOUNTED &&
		    (rq->rights & ZH_MOUNT) == 0)
			return (false);
		return (rq->session[0] == '\0');
	case TZFSD_OP_RELEASE:
		return (rq->deliver == 0 && rq->flags == 0 && rq->rights == 0 &&
		    rq->lifetime == 0 && rq->quota == 0 && rq->session[0] == '\0');
	case TZFSD_OP_DESTROY:
		/*
		 * Identifies a claim exactly as REQUEST does (dataset + lifetime),
		 * but carries no rights/flags/quota/session and no fd/path.
		 */
		return (rq->deliver == 0 && rq->flags == 0 && rq->rights == 0 &&
		    rq->quota == 0 && rq->session[0] == '\0');
	case TZFSD_OP_PING:
		return (rq->deliver == 0 && rq->flags == 0 && rq->rights == 0 &&
		    rq->lifetime == 0 && rq->quota == 0 && rq->dataset[0] == '\0' &&
		    rq->session[0] == '\0');
	case TZFSD_OP_BEGIN_SESSION:
		return (rq->deliver == 0 && rq->flags == 0 && rq->rights == 0 &&
		    rq->lifetime == 0 && rq->quota == 0 && rq->dataset[0] == '\0' &&
		    rq->session[0] != '\0');
	default:
		return (rq->deliver == 0 && rq->flags == 0 && rq->rights == 0 &&
		    rq->lifetime == 0 && rq->quota == 0 && rq->dataset[0] == '\0' &&
		    rq->session[0] == '\0');
	}
}

/*
 * Derive a client's per-service namespace: a single dataset component named by
 * a hash of the connecting service's (unforgeable) label — set by serviced when
 * it brokered the channel, never by the client.  Every claim a client makes is
 * a child dataset under this namespace, so a client can only ever create or open
 * storage inside its own subtree.  It cannot name another service's storage:
 * authority is the held channel's identity, not a wire argument.
 */
static bool
derive_ns(const char *client, char *out, size_t outsz)
{
	SHA256_CTX ctx;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	char hex[25];
	unsigned i;

	if (client == NULL || client[0] == '\0')
		return (false);
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, client, strlen(client));
	SHA256_Final(digest, &ctx);
	for (i = 0; i < 12; i++)
		(void)snprintf(hex + i * 2, 3, "%02x", digest[i]);
	hex[24] = '\0';
	if ((size_t)snprintf(out, outsz, "u%s", hex) >= outsz)
		return (false);
	return (true);
}

/*
 * Produce a rights-limited handle for a REQUEST from the client identified by
 * `client`.  Returns the granted fd (>=0) and fills dataset[]/dsz for audit, or
 * -1 with errno set.
 */
static int
grant(struct tzfsd_state *st, const char *client,
    const struct tzfsd_request *rq, char *dataset, size_t dsz, int *keep_fd)
{
	struct tzfsd_config *cfg = &st->cfg;
	int parent_fd, ns_fd, leaf_fd, granted;
	const char *parent_name, *claim;
	char parent_buf[TZFSD_MAXPATH];
	char ns[TZFSD_NAME_MAX];

	/*
	 * On a DELIVER_MOUNTED grant this returns the leaf handle that anchors
	 * the delivered mount; the caller must keep it open for the mount's
	 * lifetime.  -1 for every other outcome (nothing to retain).
	 */
	*keep_fd = -1;

	if (rq->lifetime > TZFSD_LEASE) {
		errno = EINVAL;
		return (-1);
	}
	if ((rq->rights & ~ZH_ALL_RIGHTS) != 0 || rq->rights == 0 ||
	    (rq->flags & ~ZHF_SUBTREE) != 0) {
		errno = EINVAL;
		return (-1);
	}
	/* A per-request quota override must be either the default (0) or sane. */
	if (rq->quota != 0 && rq->quota < TZFSD_MIN_REFQUOTA) {
		errno = EINVAL;
		return (-1);
	}
	if (!valid_dataset(rq->dataset) ||
	    !derive_ns(client, ns, sizeof(ns))) {
		errno = EINVAL;
		return (-1);
	}
	claim = rq->dataset;

	if (rq->lifetime == TZFSD_BOOT) {
		parent_fd = st->boot_fd;
		(void)snprintf(parent_buf, sizeof(parent_buf), "%s/%s",
		    cfg->ephemeral, st->boot_name);
		parent_name = parent_buf;
	} else if (rq->lifetime == TZFSD_LEASE) {
		if (st->lease_fd == -1) {
			errno = ENXIO;
			return (-1);
		}
		parent_fd = st->lease_fd;
		(void)snprintf(parent_buf, sizeof(parent_buf), "%s/%s",
		    cfg->ephemeral, st->lease_name);
		parent_name = parent_buf;
	} else {
		parent_fd = st->persistent_fd;
		parent_name = cfg->persistent;
	}

	/*
	 * Open-or-create the service's namespace subtree, then the claim child
	 * under it.  The client can only ever reach children of its own ns.
	 */
	ns_fd = tzfsd_ensure_path(parent_fd, ns, ZH_ALL_RIGHTS);
	if (ns_fd == -1)
		return (-1);
	leaf_fd = tzfsd_ensure_path(ns_fd, claim, ZH_ALL_RIGHTS);
	if (leaf_fd == -1) {
		int saved = errno;

		(void)close(ns_fd);
		errno = saved;
		return (-1);
	}

	/*
	 * Apply the per-claim space ceiling so no single claim can fill the pool
	 * and starve every other tenant.  refquota is a byte-count property
	 * (uint64), 0 == none; set on the full-rights leaf before the ioctl
	 * ceiling is applied to the delivered handle.  A nonzero rq->quota is this
	 * claim's explicit ceiling (already floor-checked above) and overrides the
	 * configured default; quota == 0 falls back to cfg->default_refquota (0 ==
	 * no ceiling).  Best-effort: a pre-existing persistent claim already over
	 * the (possibly lowered) ceiling must not be made undeliverable — the
	 * ceiling still blocks further growth.
	 */
	{
		uint64_t refquota = rq->quota != 0 ? rq->quota :
		    cfg->default_refquota;

		if (refquota != 0 &&
		    tzfs_set_prop_uint64(leaf_fd, "refquota", refquota) == -1)
			syslog(LOG_WARNING, "set refquota=%ju on claim %s: %m",
			    (uintmax_t)refquota, claim);
	}

	/*
	 * DELIVER_MOUNTED: the consumer is born in capability mode and cannot
	 * perform the ZFS mount itself, so tzfsd (privileged) mounts the claim ONCE
	 * here and returns the mounted store directory in the handle's place.  The
	 * objset stays mounted for the claim's lifetime (RELEASE/DESTROY reclaim
	 * it); doing the mount once — rather than the provisioning mount+unmount
	 * below followed by a second consumer mount — avoids the double-mount that
	 * otherwise fails EINVAL.  The delivered directory carries full rights; the
	 * consumer narrows it (e.g. logd's cap_rights_limit on its store dir).
	 */
	if (rq->deliver == TZFSD_DELIVER_MOUNTED) {
		int dfd = tzfs_mount(leaf_fd, false);
		int saved;

		if (dfd == -1 || (rq->owner_uid != 0 &&
		    fchown(dfd, rq->owner_uid, rq->owner_gid) == -1)) {
			saved = errno;
			if (dfd != -1) {
				(void)close(dfd);
				(void)tzfs_unmount(leaf_fd);
			}
			(void)close(leaf_fd);
			(void)close(ns_fd);
			errno = saved;
			return (-1);
		}
		/*
		 * Retain leaf_fd (do NOT close it): it anchors the anonymous
		 * mount whose root we just handed back in dfd.  Closing it here
		 * would force-unmount and doom the consumer's delivered
		 * directory.  The caller holds it for the connection's lifetime.
		 */
		*keep_fd = leaf_fd;
		(void)close(ns_fd);
		(void)snprintf(dataset, dsz, "%s/%s/%s", parent_name, ns, claim);
		return (dfd);
	}

	/*
	 * Set the dataset root's owner to the requesting service so it can write
	 * its own storage once it mounts the handle lazily.  This runs on the
	 * full-rights leaf (before the ioctl ceiling is applied to the delivered
	 * handle): a rights-limited handle would be denied ZFD_UNMOUNT, stranding
	 * the transient mount and making the consumer's later mount fail EINVAL.
	 * The ownership persists in the dataset.  Failure is fatal to the mint —
	 * unwritable storage must not be delivered as if it were usable.
	 */
	if (rq->owner_uid != 0 && (rq->rights & ZH_MOUNT) != 0) {
		int dfd = tzfs_mount(leaf_fd, false);

		if (dfd == -1 ||
		    fchown(dfd, rq->owner_uid, rq->owner_gid) == -1) {
			int saved = errno;

			if (dfd != -1)
				(void)close(dfd);
			(void)tzfs_unmount(leaf_fd);
			(void)close(leaf_fd);
			(void)close(ns_fd);
			errno = saved;
			return (-1);
		}
		(void)close(dfd);
		(void)tzfs_unmount(leaf_fd);
	}

	/*
	 * Re-open the claim from its retained namespace parent so both rights and
	 * subtree scope are exactly those requested.  The provisioning leaf is
	 * always subtree-capable and deriving it would accidentally preserve that
	 * authority.
	 */
	(void)close(leaf_fd);
	granted = tzfs_openat(ns_fd, claim, rq->rights, rq->flags);
	(void)close(ns_fd);
	if (granted == -1)
		return (-1);
	/* Add a monotonic Capsicum ioctl ceiling before SCM_RIGHTS transfer. */
	if (tzfs_limit_dataset_ioctls_by_rights(granted, rq->rights,
	    rq->flags) == -1) {
		int saved = errno;

		(void)close(granted);
		errno = saved;
		return (-1);
	}

	(void)snprintf(dataset, dsz, "%s/%s/%s", parent_name, ns, claim);
	return (granted);
}

/*
 * Open an isolated path descriptor for a TZFSD_OP_OPEN request from `client`.
 * Default-deny: the client's unforgeable label and the exact path must match a
 * configured policy entry that covers the requested rights.  The open is done
 * relative to the retained root fd (capsicum-legal in capability mode) and the
 * delivered fd is capped to exactly the requested rights.  Returns the fd, or
 * -1 with errno (EACCES when the policy does not grant it).
 */
static int
grant_open(struct tzfsd_state *st, const char *client,
    const struct tzfsd_open_request *rq)
{
	const struct tzfsd_config *cfg = &st->cfg;
	cap_rights_t rights;
	unsigned i;
	int flags, fd, saved;

	if (rq->rights == 0 || (rq->rights & ~TZFSD_OPEN_RIGHTS_ALL) != 0) {
		errno = EINVAL;
		return (-1);
	}
	/*
	 * Message hygiene, symmetric with the storage path's valid_request():
	 * reserved bytes must be zero and is_dir must be a canonical 0/1.
	 */
	if (!all_zero(rq->_reserved, sizeof(rq->_reserved)) || rq->is_dir > 1) {
		errno = EINVAL;
		return (-1);
	}
	/* Absolute, NUL-terminated, no ".." traversal component. */
	if (rq->path[0] != '/' ||
	    memchr(rq->path, '\0', sizeof(rq->path)) == NULL ||
	    has_dotdot_component(rq->path)) {
		errno = EINVAL;
		return (-1);
	}
	if (st->root_fd == -1) {
		errno = ENXIO;
		return (-1);
	}

	/* Default-deny: a policy entry for this label must cover path + rights. */
	for (i = 0; i < cfg->nopen_policy; i++) {
		const struct tzfsd_open_policy *pol = &cfg->open_policy[i];

		if (strcmp(pol->label, client) != 0 ||
		    (rq->rights & ~pol->rights) != 0)
			continue;
		if (pol->prefix) {
			size_t plen = strlen(pol->path);
			const char *suffix;

			if (strncmp(pol->path, rq->path, plen) != 0)
				continue;
			/*
			 * The remainder must be the exact path itself or a single
			 * trailing component (a device unit: /dev/vhid -> vhidN),
			 * never a subdirectory — no '/' in the suffix.
			 */
			suffix = rq->path + plen;
			if (suffix[0] != '\0' && strchr(suffix, '/') != NULL)
				continue;
		} else if (strcmp(pol->path, rq->path) != 0) {
			continue;
		}
		break;
	}
	if (i == cfg->nopen_policy) {
		errno = EACCES;
		return (-1);
	}

	if ((rq->rights & (TZFSD_OPEN_READ | TZFSD_OPEN_WRITE)) ==
	    (TZFSD_OPEN_READ | TZFSD_OPEN_WRITE))
		flags = O_RDWR;
	else if (rq->rights & TZFSD_OPEN_WRITE)
		flags = O_WRONLY;
	else
		flags = O_RDONLY;	/* read/exec/lookup all open read-only */
	flags |= O_CLOEXEC | O_NOCTTY;
	if (rq->is_dir)
		flags |= O_DIRECTORY;
	/*
	 * The proto promises symlink safety (tzfsd_proto.h): O_NOFOLLOW refuses a
	 * symlink at the granted leaf itself, and O_RESOLVE_BENEATH refuses any
	 * intermediate symlink, absolute path, or ".." that would resolve outside
	 * the retained root fd.  Capmode already blocks absolute/".." escapes, but
	 * not an in-tree symlink pointed at a different node/type than the policy
	 * author intended; these flags close that.  Both are compatible with the
	 * capmode openat here — path+1 is strictly relative to root_fd with no
	 * ".." (validated above), so resolution always stays beneath it.
	 */
	flags |= O_NOFOLLOW | O_RESOLVE_BENEATH;

	/* Relative to the retained root fd: legal in capability mode. */
	fd = openat(st->root_fd, rq->path + 1, flags);
	if (fd == -1)
		return (-1);

	cap_rights_init(&rights, 0);
	if (rq->rights & TZFSD_OPEN_READ)
		cap_rights_set(&rights, CAP_READ, CAP_SEEK, CAP_FSTAT);
	if (rq->rights & TZFSD_OPEN_WRITE)
		cap_rights_set(&rights, CAP_WRITE, CAP_SEEK, CAP_FSYNC);
	if (rq->rights & TZFSD_OPEN_EXEC)
		cap_rights_set(&rights, CAP_FEXECVE);
	if (rq->rights & TZFSD_OPEN_LOOKUP)
		cap_rights_set(&rights, CAP_LOOKUP, CAP_FSTATAT);
	if (rq->rights & TZFSD_OPEN_IOCTL)
		cap_rights_set(&rights, CAP_IOCTL, CAP_EVENT);
	if (cap_rights_limit(fd, &rights) == -1) {
		saved = errno;
		(void)close(fd);
		errno = saved;
		return (-1);
	}
	/*
	 * A delivered CAP_IOCTL descriptor must not be able to issue every ioctl
	 * the node supports.  The only ioctl consumer of an OP_OPEN device grant
	 * is blued <-> /dev/vhid{,N}: VHID_CREATE on the control node, VHID_ATTACH
	 * on a created unit, VHID_DESTROY to tear one down.  Cap the delivered fd
	 * to exactly that set (blued narrows further per-node on its own side).
	 */
	if (rq->rights & TZFSD_OPEN_IOCTL) {
		static const unsigned long vhid_ioctls[] = {
			VHID_CREATE, VHID_ATTACH, VHID_DESTROY,
		};

		if (cap_ioctls_limit(fd, vhid_ioctls, nitems(vhid_ioctls)) == -1) {
			saved = errno;
			(void)close(fd);
			errno = saved;
			return (-1);
		}
	}
	return (fd);
}

/* Deterministic claim ordering so pagination windows are stable across calls. */
static int
claim_name_cmp(const void *ap, const void *bp)
{

	return (strcmp(*(const char *const *)ap, *(const char *const *)bp));
}

/*
 * Enumerate the caller's own persistent/cache claims into *rp for an
 * TZFSD_OP_LIST request.  Owner-scoping is the hard invariant: the walk is
 * rooted at the caller's OWN namespace — derive_ns(client), the connecting
 * channel's unforgeable label — opened under the retained persistent parent, so
 * it can only ever see children of u<hash(client)> and never another label's
 * claims.  There is no wire argument that could redirect it.  Fills the page
 * [cursor, cursor+TZFSD_LIST_MAX) of the claim set (sorted for a stable window)
 * and sets rp->next_cursor nonzero when more remain.  Per-claim usage/refquota
 * are folded in best-effort from the same walk.  Returns 0 (rp->status left 0),
 * or -1 with errno set.  A caller with no namespace lists empty, not an error.
 */
static int
grant_list(struct tzfsd_state *st, const char *client,
    const struct tzfsd_list_request *rq, struct tzfsd_list_reply *rp)
{
	struct zfd_info_args info;
	char ns[TZFSD_NAME_MAX];
	void *buf;
	char **names, **claims;
	size_t len, prefix_len, nnames, nclaims, i, idx;
	int ns_fd, saved;

	/* Additive fields must be zero (message hygiene, symmetric with the rest). */
	if (rq->flags != 0 || rq->_reserved != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (!derive_ns(client, ns, sizeof(ns))) {
		errno = EINVAL;
		return (-1);
	}
	if (st->persistent_fd == -1) {
		errno = ENXIO;
		return (-1);
	}

	/*
	 * Open the caller's OWN namespace under the persistent parent.  This — and
	 * only this — is what the walk enumerates; it is never a wire-named parent.
	 * An absent namespace means the caller has made no persistent claims yet:
	 * an empty list, not an error.
	 */
	ns_fd = tzfs_openat(st->persistent_fd, ns, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	if (ns_fd == -1) {
		if (errno == ENOENT)
			return (0);	/* rp->count / next_cursor already 0 */
		return (-1);
	}
	memset(&info, 0, sizeof(info));
	if (tzfs_info(ns_fd, &info) == -1 ||
	    tzfs_list_children(ns_fd, &buf, &len) == -1) {
		saved = errno;
		(void)close(ns_fd);
		errno = saved;
		return (-1);
	}
	if (tzfsd_nvl_names(buf, len, &names, &nnames) == -1) {
		saved = errno;
		free(buf);
		(void)close(ns_fd);
		errno = saved;
		return (-1);
	}
	free(buf);

	/*
	 * Reduce the returned full dataset names to the immediate claim components
	 * under this namespace (a single trailing path element — deeper descendants
	 * of a claim are not themselves claims and are skipped).  Every retained
	 * name must lie under info.zi_name; anything else is a kernel protocol
	 * violation and fails closed rather than being interpreted.
	 */
	prefix_len = strlen(info.zi_name);
	claims = calloc(nnames == 0 ? 1 : nnames, sizeof(*claims));
	if (claims == NULL) {
		saved = errno;
		tzfsd_nvl_names_free(names, nnames);
		(void)close(ns_fd);
		errno = saved;
		return (-1);
	}
	nclaims = 0;
	for (i = 0; i < nnames; i++) {
		const char *name = names[i], *rel;

		if (strncmp(name, info.zi_name, prefix_len) != 0 ||
		    name[prefix_len] != '/') {
			free(claims);
			tzfsd_nvl_names_free(names, nnames);
			(void)close(ns_fd);
			errno = EPROTO;
			return (-1);
		}
		rel = name + prefix_len + 1;
		if (strchr(rel, '/') != NULL)
			continue;	/* a child of a claim, not a claim itself */
		claims[nclaims++] = (char *)(uintptr_t)rel;
	}
	qsort(claims, nclaims, sizeof(*claims), claim_name_cmp);

	/*
	 * Emit the requested page.  cursor is an index into the sorted claim set;
	 * a stable sort makes the window reproducible across paged calls.  For each
	 * claim, open a read-only handle under the retained namespace fd (never a
	 * client-named parent) and fold in usage + refquota best-effort.
	 */
	rp->count = 0;
	rp->next_cursor = 0;
	for (idx = rq->cursor; idx < nclaims && rp->count < TZFSD_LIST_MAX;
	    idx++) {
		struct tzfsd_claim_entry *e = &rp->entries[rp->count];
		const char *claim = claims[idx];
		struct zfd_stat_args stt;
		uint64_t refquota = 0;
		int cfd, is_string = 0;
		uint32_t src = 0;

		if (strlcpy(e->name, claim, sizeof(e->name)) >= sizeof(e->name))
			continue;	/* claim keys are < TZFSD_NAME_MAX by construction */
		cfd = tzfs_openat(ns_fd, claim, ZH_PROPS_READ, 0);
		if (cfd != -1) {
			memset(&stt, 0, sizeof(stt));
			if (tzfs_stat(cfd, &stt) == 0)
				e->used = stt.zs_referenced;
			if (tzfs_get_one_prop(cfd, "refquota", NULL, 0, &refquota,
			    &is_string, &src) == 0 && !is_string)
				e->refquota = refquota;
			(void)close(cfd);
		}
		rp->count++;
	}
	if (idx < nclaims)
		rp->next_cursor = (uint32_t)idx;

	free(claims);
	tzfsd_nvl_names_free(names, nnames);
	(void)close(ns_fd);
	return (0);
}

/*
 * Reclaim a retired consumer label's ENTIRE persistent namespace in one
 * operation.  This is the seam behind the capability-cleanup reclaim callback:
 * it derives the label's namespace component (u<hash(label)>) and destroys that
 * whole subtree — every claim the label ever made, deepest dataset first, then
 * the namespace dataset itself — under the daemon's retained persistent parent,
 * reusing exactly the destroy primitive OP_DESTROY/OP_RELEASE use
 * (tzfsd_destroy_tree).  On success *ns is left holding the namespace that was
 * targeted (for the caller's probe/audit and for the test seam to assert
 * owner-scoping).  Returns 0 (destroyed, or already absent — tzfsd_destroy_tree
 * maps ENOENT to success, so this is idempotent), or -1 with errno set.
 *
 * Owner-scoping is inherent and total: the destroy target is ALWAYS and ONLY
 * derive_ns(label) under st->persistent_fd.  There is no wire argument, and the
 * namespace is a pure hash of the retired label, so reclaiming label A can never
 * reach label B's namespace u<hash(B)>; derive_ns yields a single '/'-free
 * component, and tzfsd_destroy_tree refuses any relname bearing a '/'.
 */
static int
reclaim_namespace(struct tzfsd_state *st, const char *label, char *ns,
    size_t nsz)
{

	if (st == NULL || !derive_ns(label, ns, nsz)) {
		errno = EINVAL;
		return (-1);
	}
	if (st->persistent_fd == -1) {
		/* No pool retained: nothing to reclaim.  Fail-safe (no touch). */
		errno = ENXIO;
		return (-1);
	}
	/*
	 * Cache claims live under the persistent tree (see OP_DESTROY), so this
	 * single persistent-namespace destroy reclaims them too; there is no
	 * separate cache root to sweep.  Ephemeral lease storage is boot- and
	 * connection-scoped (reaped at startup and on channel teardown), not
	 * per-label bundle state, so it is intentionally out of scope here.
	 */
	return (tzfsd_destroy_tree(st->persistent_fd, ns));
}

/*
 * Capability-cleanup reclaim handler (docs/capability-lifecycle-cleanup.md,
 * docs/capability-plane-vision.md) — the tier-1 bulk reclaim.  When a consumer
 * bundle is uninstalled its label is retired and its per-label storage can never
 * again be reclaimed by a live consumer.  serviced detects the uninstall and
 * pushes SVC_OP_RECLAIM_LABEL over the control channel; libservice's dispatcher
 * — pumped by tzfsd's main process, the same path that delivers quiesce — invokes
 * this callback while the daemon is serving.  ctx is the tzfsd_state carrying the
 * retained persistent_fd.  We destroy the retired label's whole namespace in one
 * operation (see reclaim_namespace).  Idempotent and fail-safe: push and a future
 * pull sweep may both fire for one label, and a re-reclaim of an already-gone
 * namespace is a no-op success; any failure is logged, never fatal to serving.
 *
 * RECONCILE GAP (push-only by construction): tzfsd keys namespaces by
 * hash(label) and cannot reverse u<hash> back to a label, so it CANNOT run the
 * service_label_is_live() pull sweep over the namespaces it holds — it has no way
 * to recover a label to query from a stored namespace.  This handler is therefore
 * push-only, which is primary and sufficient here: serviced pushes a reclaim for
 * every uninstalled bundle.  A serviced-driven live-namespace sweep (serviced
 * enumerating live labels and pushing a reclaim for every namespace not among
 * them) is a possible future backstop; tzfsd cannot self-drive one.  We do NOT
 * fake a reconcile.
 */
void
tzfsd_reclaim_label(const char *label, void *ctx)
{
	struct tzfsd_state *st = ctx;
	char ns[TZFSD_NAME_MAX];
	int status;

	if (reclaim_namespace(st, label, ns, sizeof(ns)) == -1) {
		status = errno;
		/*
		 * A missing pool/namespace or an unnamespaceable label leaves
		 * nothing to reclaim; a real ZFS failure is logged for the
		 * operator but must not stop the serve loop.
		 */
		if (status != ENXIO && status != EINVAL)
			syslog(LOG_WARNING, "reclaim label %s: %s",
			    label != NULL ? label : "(null)",
			    strerror(status));
	} else {
		status = 0;
		syslog(LOG_INFO, "reclaim label %s -> namespace %s destroyed",
		    label, ns);
	}
	/*
	 * The dtrace(1)-generated probe stub takes a non-const char *; cast away
	 * const safely (the probe only reads the string) to satisfy -Wcast-qual.
	 */
	TZFSD_PROBE_RECLAIM(__DECONST(char *, label != NULL ? label : ""),
	    status);
}

/*
 * Per-client channel request handler.  arg is this worker's tzfsd_state (its
 * own copy of the retained handles, plus per-connection lease state).  The
 * reply is a fixed tzfsd_reply; a granted handle rides back as its single fd.
 */
static void
tzfs_request(struct channel *ch __unused, struct channel_message *m, void *arg)
{
	struct tzfs_conn *conn = arg;
	struct tzfsd_state *st = conn->st;
	const struct tzfsd_request *rq;
	struct tzfsd_reply rp;
	struct channel_outgoing out;
	int handle = -1;

	memset(&rp, 0, sizeof(rp));

	TZFSD_PROBE_MSG((uint64_t)channel_message_length(m),
	    channel_message_fd_count(m));

	if (channel_message_fd_count(m) != 0) {
		rp.status = EPROTO;
		goto reply;
	}

	/*
	 * TZFSD_OP_OPEN carries its own, larger request struct; dispatch it by
	 * its distinct length before the storage-shaped requests.
	 */
	if (channel_message_length(m) == sizeof(struct tzfsd_open_request)) {
		const struct tzfsd_open_request *orq = channel_message_data(m);

		if (orq->op == TZFSD_OP_OPEN) {
			handle = grant_open(st, conn->client, orq);
			if (handle == -1) {
				rp.status = errno;
				syslog(LOG_INFO, "OPEN rights=%#x -> %s",
				    orq->rights, strerror(rp.status));
			} else {
				syslog(LOG_INFO, "OPEN %s rights=%#x -> granted",
				    orq->path, orq->rights);
			}
			goto reply;
		}
	}

	/*
	 * TZFSD_OP_LIST carries its own small request struct and a distinctly
	 * sized, fd-free reply (the caller's own claim page).  Dispatch it by its
	 * length here — like OPEN — and send its dedicated reply inline, before the
	 * storage-shaped request path.
	 */
	if (channel_message_length(m) == sizeof(struct tzfsd_list_request)) {
		const struct tzfsd_list_request *lrq = channel_message_data(m);

		if (lrq->op == TZFSD_OP_LIST) {
			struct tzfsd_list_reply lrp;
			struct channel_outgoing lout;

			memset(&lrp, 0, sizeof(lrp));
			if (grant_list(st, conn->client, lrq, &lrp) == -1) {
				lrp.status = errno;
				lrp.count = 0;
				lrp.next_cursor = 0;
				syslog(LOG_INFO, "LIST cursor=%u -> %s",
				    lrq->cursor, strerror(lrp.status));
			} else {
				syslog(LOG_INFO, "LIST cursor=%u -> %u claim(s)%s",
				    lrq->cursor, lrp.count,
				    lrp.next_cursor != 0 ? " (more)" : "");
			}
			TZFSD_PROBE_REPLY(0, lrp.status, -1);
			memset(&lout, 0, sizeof(lout));
			lout.size = sizeof(lout);
			lout.data = &lrp;
			lout.length = sizeof(lrp);
			(void)channel_send_reply(m, &lout);
			channel_message_free(m);
			return;
		}
	}

	if (channel_message_length(m) != sizeof(*rq)) {
		rp.status = EPROTO;
		goto reply;
	}
	rq = channel_message_data(m);
	{
		int ok = valid_request(rq);

		TZFSD_PROBE_VALIDATE(rq->op, rq->deliver, rq->rights,
		    rq->lifetime, ok);
		if (!ok) {
			rp.status = EINVAL;
			goto reply;
		}
	}

	switch (rq->op) {
	case TZFSD_OP_REQUEST: {
		int keep_fd = -1;

		handle = grant(st, conn->client, rq, rp.dataset,
		    sizeof(rp.dataset), &keep_fd);
		TZFSD_PROBE_GRANT(rq->op, rq->deliver, handle,
		    handle == -1 ? errno : 0);
		/*
		 * A DELIVER_MOUNTED grant hands back the leaf handle anchoring
		 * the delivered mount; retain it for the connection's lifetime so
		 * the store stays mounted while the client holds its lease.  One
		 * live mount per connection: if a prior lease is replaced, drop
		 * its anchor (which unmounts the old store).
		 */
		if (keep_fd != -1) {
			if (conn->mount_anchor_fd != -1)
				(void)close(conn->mount_anchor_fd);
			conn->mount_anchor_fd = keep_fd;
		}
		if (handle == -1) {
			rp.status = errno;
			rp.dataset[0] = '\0';
			syslog(LOG_INFO, "REQUEST claim=%s life=%u -> %s",
			    rq->dataset, rq->lifetime, strerror(rp.status));
		} else {
			/*
			 * grant() returns the mounted store directory for a
			 * DELIVER_MOUNTED request (it performed the mount) or the
			 * dataset handle otherwise; either way we deliver it below.
			 */
			syslog(LOG_INFO, "REQUEST %s life=%u -> granted%s",
			    rp.dataset, rq->lifetime,
			    rq->deliver == TZFSD_DELIVER_MOUNTED ? " (mounted)" :
			    "");
		}
		break;
	}
	case TZFSD_OP_RELEASE: {
		/* Destroy the caller's own claim under its lease namespace. */
		char ns[TZFSD_NAME_MAX];
		int ns_fd;

		if (!valid_dataset(rq->dataset) ||
		    !derive_ns(conn->client, ns, sizeof(ns))) {
			rp.status = EINVAL;
			break;
		}
		if (st->lease_fd == -1) {
			rp.status = ENXIO;
			break;
		}
		ns_fd = tzfs_openat(st->lease_fd, ns, ZH_ALL_RIGHTS, ZHF_SUBTREE);
		if (ns_fd == -1) {
			/* No namespace => nothing to release (idempotent). */
			if (errno != ENOENT)
				rp.status = errno;
			break;
		}
		if (tzfsd_destroy_tree(ns_fd, rq->dataset) == -1 &&
		    errno != ENOENT)
			rp.status = errno;
		else
			syslog(LOG_INFO, "RELEASE %s/%s -> ok", ns, rq->dataset);
		(void)close(ns_fd);
		break;
	}
	case TZFSD_OP_DESTROY: {
		/*
		 * Reclaim the caller's own persistent/cache claim.  The claim is
		 * resolved under the CALLER's namespace (derive_ns of the connecting
		 * label), so a caller can only ever name — and destroy — its own
		 * storage; the persistent tree covers both PERSISTENT and CACHE.
		 * Unlike RELEASE, an absent claim replies ENOENT rather than
		 * idempotent success, so a caller can distinguish a real reclaim.
		 */
		char ns[TZFSD_NAME_MAX];
		int ns_fd, probe;

		if (rq->lifetime > TZFSD_CACHE || !valid_dataset(rq->dataset) ||
		    !derive_ns(conn->client, ns, sizeof(ns))) {
			rp.status = EINVAL;
			break;
		}
		if (st->persistent_fd == -1) {
			rp.status = ENXIO;
			break;
		}
		ns_fd = tzfs_openat(st->persistent_fd, ns, ZH_ALL_RIGHTS,
		    ZHF_SUBTREE);
		if (ns_fd == -1) {
			/* No namespace => the claim cannot exist. */
			rp.status = errno;
			break;
		}
		/*
		 * Probe for the claim so absence is reported as ENOENT rather than
		 * the idempotent success tzfsd_destroy_tree() would return.
		 */
		probe = tzfs_openat(ns_fd, rq->dataset, ZH_PROPS_READ, 0);
		if (probe == -1) {
			rp.status = errno;
			(void)close(ns_fd);
			break;
		}
		(void)close(probe);
		if (tzfsd_destroy_tree(ns_fd, rq->dataset) == -1)
			rp.status = errno;
		else
			syslog(LOG_INFO, "DESTROY %s/%s -> ok", ns, rq->dataset);
		(void)close(ns_fd);
		break;
	}
	case TZFSD_OP_PING:
		rp.status = 0;
		break;
	case TZFSD_OP_BEGIN_SESSION:
		if (tzfsd_session_begin(st, rq->session) == -1)
			rp.status = errno;
		break;
	default:
		rp.status = EOPNOTSUPP;
		break;
	}

reply:
	TZFSD_PROBE_REPLY(0, rp.status, handle);
	memset(&out, 0, sizeof(out));
	out.size = sizeof(out);
	out.data = &rp;
	out.length = sizeof(rp);
	if (handle != -1 && rp.status == 0) {
		out.fds = &handle;
		out.nfds = 1;
	}
	(void)channel_send_reply(m, &out);
	if (handle != -1)
		(void)close(handle);
	channel_message_free(m);
}

/*
 * Serve one client on its own worker channel until the channel closes.  Runs in
 * a pdfork'd worker with its own copy of st (so its lease state is private).
 */
static int
tzfs_worker(struct tzfsd_state *st, int fd, const char *client)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct channel *channel = NULL;
	struct tzfs_conn conn;
	int ready, wants_write;

	conn.st = st;
	conn.mount_anchor_fd = -1;
	(void)strlcpy(conn.client, client, sizeof(conn.client));

	if (channel_create(fd, &options, &channel) == -1)
		return (1);
	if (channel_set_request_handler(channel, tzfs_request, &conn) == -1) {
		channel_destroy(channel);
		return (1);
	}
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1 ||
		    (ready = channel_wait(channel, wants_write, -1)) == -1 ||
		    ((ready & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(channel) == -1) ||
		    ((ready & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(channel) == -1))
			break;
	}
	channel_destroy(channel);
	/*
	 * Drop any retained mount anchor: closing the leaf handle unmounts the
	 * delivered store now that the client's connection is gone.  (Process
	 * exit would do this too; explicit is clearer and lets a worker that is
	 * reused across errors not strand a mount.)
	 */
	if (conn.mount_anchor_fd != -1)
		(void)close(conn.mount_anchor_fd);
	return (0);
}

/*
 * Expose system.Filesystem and dispatch each accepted client on its own pdfork'd
 * worker.  Enters capability mode before serving; returns -1 only on setup
 * failure (never on success).
 */
int
tzfsd_serve(struct tzfsd_state *st)
{
	struct service_identity id;
	struct service_listener *listener;
	struct service_provider *provider;
	int fd;

	/*
	 * Register the capability-cleanup reclaim handler before serving.  It
	 * fires on the control-dispatch path this main process already pumps, so
	 * a retired label's namespace is reclaimed while tzfsd keeps serving; ctx
	 * is the state carrying the retained persistent_fd.  Registering it up
	 * front means no early SVC_OP_RECLAIM_LABEL push is missed.
	 */
	service_set_reclaim_handler(tzfsd_reclaim_label, st);

	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_expose(provider, TZFSD_SERVICE_NAME, &listener) ==
	    -1 ||
	    service_provider_enter_privileged(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		return (-1);

	for (;;) {
		pid_t pid;
		int pd;

		memset(&id, 0, sizeof(id));
		id.size = sizeof(id);
		if (service_listener_accept(listener, &id, &fd) == -1)
			return (-1);
		pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
		if (pid == -1) {
			syslog(LOG_ERR, "pdfork: %m");
			(void)close(fd);
			continue;
		}
		if (pid == 0)
			_exit(tzfs_worker(st, fd, id.client_label));
		(void)close(fd);
		(void)close(pd);
	}
}

#ifdef TZFSD_TESTING
/*
 * Test-only accessors.  These expose the file-private pure-logic functions and a
 * single-channel serve entrypoint so the ATF suite can exercise the tenant-
 * isolation and request-validation logic directly.  They add no code to the
 * production build (the whole block is compiled out unless TZFSD_TESTING is
 * defined) and change no runtime behavior.
 */
bool
tzfsd_test_derive_ns(const char *client, char *out, size_t outsz)
{

	return (derive_ns(client, out, outsz));
}

bool
tzfsd_test_valid_dataset(const char *name)
{

	return (valid_dataset(name));
}

bool
tzfsd_test_has_dotdot_component(const char *path)
{

	return (has_dotdot_component(path));
}

bool
tzfsd_test_valid_request(const struct tzfsd_request *rq)
{

	return (valid_request(rq));
}

/*
 * Drive grant_open() so tests can assert the OPEN request's message hygiene
 * (_reserved must be zero, is_dir must be a canonical 0/1) and the default-deny
 * policy outcome without reaching any ZFS machinery.
 */
int
tzfsd_test_grant_open(struct tzfsd_state *st, const char *client,
    const struct tzfsd_open_request *rq)
{

	return (grant_open(st, client, rq));
}

/*
 * Drive grant() so tests can assert the storage-request argument validation
 * (quota floor, rights/flags/lifetime bounds) that fails EINVAL before any ZFS
 * handle is touched, without an imported pool.
 */
int
tzfsd_test_grant(struct tzfsd_state *st, const char *client,
    const struct tzfsd_request *rq, char *dataset, size_t dsz)
{
	int keep_fd = -1;
	int handle;

	handle = grant(st, client, rq, dataset, dsz, &keep_fd);
	/* The test path validates argument handling; don't leak a retained mount. */
	if (keep_fd != -1)
		(void)close(keep_fd);
	return (handle);
}

/*
 * Serve a single client channel to completion on the caller's own fd (no
 * pdfork, no accept loop).  This is the plane entrypoint the provider test uses
 * to assert fail-closed framing/validation over a real mac_capability channel.
 */
int
tzfsd_test_worker(struct tzfsd_state *st, int fd, const char *client)
{

	return (tzfs_worker(st, fd, client));
}

/*
 * Drive grant_list() so tests can assert the LIST request's message hygiene
 * (flags/_reserved must be zero) and the fail-closed no-pool outcome (ENXIO)
 * without an imported pool.  The owner-scoping itself is guarded at the
 * derivation layer (derive_ns) that grant_list roots the walk at.
 */
int
tzfsd_test_grant_list(struct tzfsd_state *st, const char *client,
    const struct tzfsd_list_request *rq, struct tzfsd_list_reply *rp)
{

	return (grant_list(st, client, rq, rp));
}

/*
 * Drive the reclaim seam so tests can assert the crown-jewel owner-scoping
 * invariant — a reclaim ALWAYS targets exactly derive_ns(label) and never
 * another label's namespace — and the fail-safe no-pool/bad-label outcomes,
 * without an imported pool.  On return *ns holds the namespace the reclaim
 * targeted (whenever the label was namespaceable), so a test can assert reclaim
 * of label A computes u<hash(A)> and never label B's u<hash(B)>.  The return
 * value / errno are reclaim_namespace()'s (0 destroyed-or-absent; -1 with EINVAL
 * for an unnamespaceable label, ENXIO for no retained pool).
 */
int
tzfsd_test_reclaim(struct tzfsd_state *st, const char *label, char *ns,
    size_t nsz)
{

	return (reclaim_namespace(st, label, ns, nsz));
}
#endif /* TZFSD_TESTING */
