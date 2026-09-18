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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>


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
	char			client[64];	/* resource owner (ephemeral key) */
	char			label[64];	/* canonical policy identity */
	char			container[128];	/* "<bundle>/<unit>" durable container,
						 * "" if the client has no bundle */
	char			groups[4][64];	/* group containers the bundle may
						 * claim (Data/Shared/<group>/) */
	/* Stamped sender credentials: the only ownership a store can take. */
	uid_t			uid;
	gid_t			gid;
	/*
	 * A DELIVER_MOUNTED grant anchors its anonymous mount on the leaf
	 * handle: the mount lives while at least one anchoring handle stays open
	 * (the kernel shares one mount per dataset across handles and unmounts
	 * on the last close).  Retain one anchor PER CLAIM for the connection's
	 * lifetime so every store the client holds stays mounted -- a unit
	 * claims its persistent store and its cache, or several shared stores,
	 * over the one connection its library keeps.  A claim's anchor is
	 * dropped when the claim is DESTROYed/RELEASEd (a mounted dataset cannot
	 * be destroyed) and all are closed on teardown.
	 */
	struct tzfs_anchor {
		char	dataset[TZFSD_MAXPATH];	/* full dataset name */
		int	fd;			/* leaf handle, -1 == free */
	}			anchors[TZFSD_CONN_MAX_CLAIMS];
};

/*
 * Retain `fd` as the anchor of `dataset`.  A re-claim of a dataset already
 * anchored replaces the old anchor AFTER the new one is stored, so the mount
 * (shared by both handles) never drops to zero anchors in between.  Returns
 * -1 with EMFILE when the connection already holds the maximum number of
 * live claims; the caller then closes `fd` (unmounting the store only if this
 * was its sole anchor).
 */
static int
conn_anchor_add(struct tzfs_conn *conn, const char *dataset, int fd)
{
	size_t i, slot = SIZE_MAX;
	int old = -1;

	for (i = 0; i < nitems(conn->anchors); i++) {
		if (conn->anchors[i].fd != -1 &&
		    strcmp(conn->anchors[i].dataset, dataset) == 0) {
			old = conn->anchors[i].fd;
			conn->anchors[i].fd = fd;
			(void)close(old);
			return (0);
		}
		if (conn->anchors[i].fd == -1 && slot == SIZE_MAX)
			slot = i;
	}
	if (slot == SIZE_MAX) {
		errno = EMFILE;
		return (-1);
	}
	(void)strlcpy(conn->anchors[slot].dataset, dataset,
	    sizeof(conn->anchors[slot].dataset));
	conn->anchors[slot].fd = fd;
	return (0);
}

/*
 * Drop the anchor of exactly the named dataset (the full name grant()
 * recorded), if this connection holds one.  Exact: a suffix match would
 * conflate a boot-scoped and a lease-scoped claim of the same name.
 */
static void
conn_anchor_drop(struct tzfs_conn *conn, const char *dataset)
{
	size_t i;

	for (i = 0; i < nitems(conn->anchors); i++) {
		if (conn->anchors[i].fd != -1 &&
		    strcmp(conn->anchors[i].dataset, dataset) == 0) {
			(void)close(conn->anchors[i].fd);
			conn->anchors[i].fd = -1;
		}
	}
}

static void
conn_anchors_init(struct tzfs_conn *conn)
{
	size_t i;

	for (i = 0; i < nitems(conn->anchors); i++)
		conn->anchors[i].fd = -1;
}

static void
conn_anchors_close(struct tzfs_conn *conn)
{
	size_t i;

	for (i = 0; i < nitems(conn->anchors); i++) {
		if (conn->anchors[i].fd != -1)
			(void)close(conn->anchors[i].fd);
		conn->anchors[i].fd = -1;
	}
}

/* A claim name must be a single, safe path component. */
static bool
valid_dataset_n(const char *name, size_t capacity)
{
	size_t i, len;

	/*
	 * A claim or namespace component is a positive charset, not merely
	 * "no slash": ZFS gives a leading '@', '#' or '%' a meaning of its own
	 * (a snapshot, a bookmark, a receive placeholder -- of the PARENT, one
	 * level above the claim), and a leading '.' or '-' is a hazard to
	 * every tool that later names the dataset.  Everything else that ZFS
	 * accepts in a component is fine.
	 */
	len = strnlen(name, capacity);
	if (len == 0 || len >= capacity)
		return (false);
	if (name[0] == '.' || name[0] == '-' || name[0] == '@' ||
	    name[0] == '#' || name[0] == '%')
		return (false);
	for (i = 0; i < len; i++) {
		char c = name[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '.' || c == '_' ||
		    c == '-' || c == ':'))
			return (false);
	}
	return (true);
}

static bool
valid_dataset(const char *name)
{

	return (valid_dataset_n(name, TZFSD_NAME_MAX));
}

/* Case-insensitive equality for reserved-name checks (ZFS names are
 * case-sensitive; operators and packagers are not). */
static bool
name_is(const char *a, const char *b)
{
	for (; *a != '\0' && *b != '\0'; a++, b++)
		if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
			return (false);
	return (*a == '\0' && *b == '\0');
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
	    rq->deliver > TZFSD_DELIVER_MOUNTED_RO ||
	    memchr(rq->dataset, '\0', sizeof(rq->dataset)) == NULL ||
	    memchr(rq->session, '\0', sizeof(rq->session)) == NULL ||
	    memchr(rq->group, '\0', sizeof(rq->group)) == NULL ||
	    rq->scope > TZFSD_SCOPE_GROUP)
		return (false);
	/*
	 * Scope names a durable container shape: only REQUEST and DESTROY take
	 * one, only for persistent/cache claims, and `group` is present exactly
	 * when the scope is GROUP (and is then a safe single component).
	 */
	if (rq->op != TZFSD_OP_REQUEST && rq->op != TZFSD_OP_DESTROY) {
		if (rq->scope != TZFSD_SCOPE_UNIT || rq->group[0] != '\0')
			return (false);
	} else {
		if (rq->scope != TZFSD_SCOPE_UNIT && rq->lifetime > TZFSD_CACHE)
			return (false);
		if ((rq->scope == TZFSD_SCOPE_GROUP) != (rq->group[0] != '\0'))
			return (false);
		if (rq->group[0] != '\0' && !valid_dataset(rq->group))
			return (false);
	}
	switch (rq->op) {
	case TZFSD_OP_REQUEST:
		/*
		 * quota (0=default, else validated in grant) may be nonzero.
		 * DELIVER_MOUNTED is only meaningful for a claim that was granted
		 * ZH_MOUNT — tzfsd mounts it server-side and returns the dir fd.
		 */
		if (rq->deliver != TZFSD_DELIVER_HANDLE &&
		    (rq->rights & ZH_MOUNT) == 0)
			return (false);
		/*
		 * A read-only view never sizes the store; ownership fields are
		 * tolerated (the library always sends the caller's own uid/gid)
		 * but ignored -- a read-only claim never chowns (see grant()).
		 */
		if (rq->deliver == TZFSD_DELIVER_MOUNTED_RO && rq->quota != 0)
			return (false);
		return (rq->session[0] == '\0');
	case TZFSD_OP_RELEASE:
		return (rq->deliver == 0 && rq->flags == 0 && rq->rights == 0 &&
		    rq->lifetime == 0 && rq->quota == 0 && rq->owner_uid == 0 &&
		    rq->owner_gid == 0 && rq->session[0] == '\0');
	case TZFSD_OP_DESTROY:
		/*
		 * Identifies a claim exactly as REQUEST does (dataset + lifetime),
		 * but carries no rights/flags/quota/session and no fd/path.
		 */
		return (rq->deliver == 0 && rq->flags == 0 && rq->rights == 0 &&
		    rq->quota == 0 && rq->owner_uid == 0 && rq->owner_gid == 0 &&
		    rq->session[0] == '\0');
	case TZFSD_OP_PING:
		return (rq->deliver == 0 && rq->flags == 0 && rq->rights == 0 &&
		    rq->lifetime == 0 && rq->quota == 0 && rq->owner_uid == 0 &&
		    rq->owner_gid == 0 && rq->dataset[0] == '\0' &&
		    rq->session[0] == '\0');
	case TZFSD_OP_BEGIN_SESSION:
		return (rq->deliver == 0 && rq->flags == 0 && rq->rights == 0 &&
		    rq->lifetime == 0 && rq->quota == 0 && rq->owner_uid == 0 &&
		    rq->owner_gid == 0 && rq->dataset[0] == '\0' &&
		    rq->session[0] != '\0');
	default:
		return (rq->deliver == 0 && rq->flags == 0 && rq->rights == 0 &&
		    rq->lifetime == 0 && rq->quota == 0 && rq->owner_uid == 0 &&
		    rq->owner_gid == 0 && rq->dataset[0] == '\0' &&
		    rq->session[0] == '\0');
	}
}

/*
 * Derive a client's EPHEMERAL namespace: a single dataset component named
 * directly by the connecting service's resource owner — the flat, unforgeable
 * "cap.<hex>" key switchboard stamps on the brokered channel, never a wire
 * argument.  This roots the client's boot- and lease-scoped storage (reaped on
 * disconnect or reboot).  Durable storage is not keyed this way — it lives in
 * the per-bundle container (see container_ns).  The owner is already a safe
 * fixed-width component, so this only rejects an empty key, a bare "."/".." , or
 * one bearing a path separator, so a caller can never escape its own subtree.
 */
static bool
derive_ns(const char *client, char *out, size_t outsz)
{
	if (client == NULL || client[0] == '\0' ||
	    strchr(client, '/') != NULL ||
	    strcmp(client, ".") == 0 || strcmp(client, "..") == 0)
		return (false);
	if ((size_t)snprintf(out, outsz, "%s", client) >= outsz)
		return (false);
	return (true);
}

/*
 * A container path is exactly "<bundle>/<unit>" — two safe single components,
 * the unit's place in the Data layout.  Reject anything else so a caller can
 * never escape its container into another bundle's data or the Data root.
 */
static bool
valid_container(const char *c)
{
	const char *slash;
	char comp[TZFSD_NAME_MAX];
	size_t n;

	if (c == NULL || (slash = strchr(c, '/')) == NULL || slash == c ||
	    slash[1] == '\0' || strchr(slash + 1, '/') != NULL)
		return (false);
	n = (size_t)(slash - c);
	if (n >= sizeof(comp))
		return (false);
	memcpy(comp, c, n);
	comp[n] = '\0';
	if (!valid_dataset_n(comp, sizeof(comp)) ||
	    !valid_dataset_n(slash + 1, TZFSD_NAME_MAX))
		return (false);
	/*
	 * Reserved: a bundle named "Shared" would alias Data/Shared/ -- the
	 * GROUP container root -- so its unit-scope claims would land in group
	 * containers with no membership check and be reaped by the group
	 * reconcile; a unit named "shared" would alias its bundle's SHARED
	 * scope.  Neither may exist as a container.
	 */
	if (name_is(comp, TZFSD_SHARED_DIR) || name_is(slash + 1, "shared"))
		return (false);
	return (true);
}

/*
 * The caller's DURABLE namespace under the Data root: its per-bundle container's
 * persistent or cache subdir, Data/<bundle>/<unit>/{persistent,cache}
 * (docs/capability-container-model.md).  Fails when the caller has no valid
 * container (no bundle), so a bundleless client holds no durable storage.
 */
static bool
container_ns(const char *container, uint32_t lifetime, char *out, size_t outsz)
{
	const char *sub = lifetime == TZFSD_CACHE ? "cache" : "persistent";

	if (!valid_container(container))
		return (false);
	return ((size_t)snprintf(out, outsz, "%s/%s", container, sub) < outsz);
}

/*
 * The caller's durable namespace for a claim's scope
 * (docs/capability-container-model.md "Storage and delivery"):
 *   UNIT    Data/<bundle>/<unit>/{persistent,cache}   (container_ns)
 *   SHARED  Data/<bundle>/shared/{persistent,cache}   any unit of the bundle
 *   GROUP   Data/Shared/<group>/{persistent,cache}    only if the bundle
 *           declares membership in <group> (stamped on the identity)
 * A bundleless client has none.  The group name is validated as a single safe
 * component even though it was already matched against the stamped list.
 */
static bool
scoped_ns(const char *container, const char (*groups)[64], uint8_t scope,
    const char *group, uint32_t lifetime, char *out, size_t outsz)
{
	const char *sub = lifetime == TZFSD_CACHE ? "cache" : "persistent";
	const char *slash;
	size_t blen;
	unsigned i;

	if (!valid_container(container))
		return (false);
	switch (scope) {
	case TZFSD_SCOPE_UNIT:
		return (container_ns(container, lifetime, out, outsz));
	case TZFSD_SCOPE_SHARED:
		slash = strchr(container, '/');
		blen = (size_t)(slash - container);
		return ((size_t)snprintf(out, outsz, "%.*s/shared/%s", (int)blen,
		    container, sub) < outsz);
	case TZFSD_SCOPE_GROUP:
		if (group == NULL || group[0] == '\0' || groups == NULL ||
		    !valid_dataset(group))
			return (false);
		for (i = 0; i < 4; i++)
			if (groups[i][0] != '\0' && strcmp(groups[i], group) == 0)
				break;
		if (i == 4)
			return (false);			/* not a member */
		return ((size_t)snprintf(out, outsz, "Shared/%s/%s", group, sub) <
		    outsz);
	default:
		return (false);
	}
}

/*
 * Open an existing multi-component subtree under parent_fd, one component at a
 * time (never create).  Returns the leaf handle, or -1 with errno (ENOENT if any
 * component is absent), mirroring tzfsd_ensure_path's walk without the create.
 */
static int
open_ns_path(int parent_fd, const char *relpath, uint64_t rights, uint32_t flags)
{
	char comp[TZFSD_MAXPATH];
	const char *p = relpath, *slash;
	int cur = -1, next;

	for (;;) {
		size_t n;

		slash = strchr(p, '/');
		n = slash != NULL ? (size_t)(slash - p) : strlen(p);
		if (n == 0 || n >= sizeof(comp)) {
			if (cur != -1)
				(void)close(cur);
			errno = EINVAL;
			return (-1);
		}
		memcpy(comp, p, n);
		comp[n] = '\0';
		next = tzfs_openat(cur == -1 ? parent_fd : cur, comp,
		    slash != NULL ? ZH_ALL_RIGHTS : rights,
		    slash != NULL ? ZHF_SUBTREE : flags);
		if (cur != -1)
			(void)close(cur);
		if (next == -1)
			return (-1);
		cur = next;
		if (slash == NULL)
			return (cur);
		p = slash + 1;
	}
}

/*
 * Produce a rights-limited handle for a REQUEST.  `owner` roots ephemeral
 * (boot/lease) storage; `container` roots durable (persistent/cache) storage in
 * the caller's per-bundle container.  Returns the granted fd (>=0) and fills
 * dataset[]/dsz for audit, or -1 with errno set.
 */
/*
 * Narrow a delivered store directory to a read-only view: lookup, read, stat,
 * read-only mmap, seek, fcntl, pathconf, and event registration -- no write,
 * create, unlink, rename, chmod/chown, utimes, or flags.  Capsicum rights are
 * monotonic and inherited by every descriptor derived from this one.
 */
int
tzfsd_limit_readonly_dir(int dfd)
{
	cap_rights_t rights;

	cap_rights_init(&rights, CAP_READ, CAP_LOOKUP, CAP_FSTAT, CAP_FSTATAT,
	    CAP_FSTATFS, CAP_SEEK, CAP_MMAP_R, CAP_FCNTL, CAP_FPATHCONF,
	    CAP_EVENT, CAP_KQUEUE_EVENT);
	return (cap_rights_limit(dfd, &rights));
}

static int
grant(struct tzfsd_state *st, const struct tzfs_conn *conn,
    const struct tzfsd_request *rq, char *dataset, size_t dsz, int *keep_fd)
{
	struct tzfsd_config *cfg = &st->cfg;
	const char *owner = conn->client, *container = conn->container;
	const char (*groups)[64] = (const char (*)[64])conn->groups;
	const bool ro = rq->deliver == TZFSD_DELIVER_MOUNTED_RO;
	int parent_fd, ns_fd, leaf_fd, granted;
	const char *parent_name, *claim;
	char parent_buf[TZFSD_MAXPATH];
	char ns[TZFSD_MAXPATH];

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
	if (!valid_dataset(rq->dataset)) {
		errno = EINVAL;
		return (-1);
	}
	/*
	 * Ownership comes from the STAMPED credentials, never the wire: a
	 * client may ask for its own uid/gid (what libservice sends) or 0 (skip),
	 * nothing else.  Otherwise any unit of a bundle could take over a shared
	 * store by chowning it to itself.
	 */
	if ((rq->owner_uid != 0 && rq->owner_uid != conn->uid) ||
	    (rq->owner_gid != 0 && rq->owner_gid != conn->gid)) {
		errno = EPERM;
		return (-1);
	}
	claim = rq->dataset;

	/*
	 * Ephemeral (boot/lease) storage is keyed by the flat owner under the
	 * ephemeral parent; durable (persistent/cache) storage lives in the
	 * caller's per-bundle container under the Data root.  The pool check
	 * precedes the container check so an unavailable backend reports ENXIO,
	 * not a bundleless client's EPERM.
	 */
	if (rq->lifetime == TZFSD_BOOT) {
		parent_fd = st->boot_fd;
		(void)snprintf(parent_buf, sizeof(parent_buf), "%s/%s",
		    cfg->ephemeral, st->boot_name);
		parent_name = parent_buf;
		if (!derive_ns(owner, ns, sizeof(ns))) {
			errno = EINVAL;
			return (-1);
		}
	} else if (rq->lifetime == TZFSD_LEASE) {
		if (st->lease_fd == -1) {
			errno = ENXIO;
			return (-1);
		}
		parent_fd = st->lease_fd;
		(void)snprintf(parent_buf, sizeof(parent_buf), "%s/%s",
		    cfg->ephemeral, st->lease_name);
		parent_name = parent_buf;
		if (!derive_ns(owner, ns, sizeof(ns))) {
			errno = EINVAL;
			return (-1);
		}
	} else {
		parent_fd = st->persistent_fd;
		parent_name = cfg->persistent;
		if (parent_fd == -1) {
			errno = ENXIO;
			return (-1);
		}
		if (!scoped_ns(container, groups, rq->scope, rq->group,
		    rq->lifetime, ns, sizeof(ns))) {
			errno = EPERM;	/* no bundle, or not a member of the group */
			return (-1);
		}
	}
	/*
	 * Installer/live media deliberately has no ZFS pool yet.  Report that
	 * state as ENXIO before passing the sentinel descriptor to TrustedZFS;
	 * leaking -1 down to openat/ioctl turns an expected unavailable backend
	 * into the misleading EBADF seen in the system log.
	 */
	if (parent_fd == -1) {
		errno = ENXIO;
		return (-1);
	}

	/*
	 * Open-or-create the service's namespace subtree, then the claim child
	 * under it.  The client can only ever reach children of its own ns.
	 */
	if (ro) {
		/*
		 * A read-only view never creates anything: the namespace and
		 * the claim must already exist (ENOENT otherwise), and no quota
		 * or ownership is applied.
		 */
		ns_fd = open_ns_path(parent_fd, ns, ZH_ALL_RIGHTS, ZHF_SUBTREE);
		if (ns_fd == -1)
			return (-1);
		leaf_fd = tzfs_openat(ns_fd, claim, ZH_ALL_RIGHTS, ZHF_SUBTREE);
		if (leaf_fd == -1) {
			int saved = errno;

			(void)close(ns_fd);
			errno = saved;
			return (-1);
		}
		goto mounted;
	}
	ns_fd = tzfsd_ensure_path(parent_fd, ns, ZH_ALL_RIGHTS);
	if (ns_fd == -1)
		return (-1);
	/*
	 * Bound the datasets one namespace may hold: every distinct claim name
	 * is a dataset (pool metadata, a reaper walk, a mount), so an unbounded
	 * client could fill the pool with empty ones.  Existing claims reopen
	 * freely; only a NEW claim counts against the limit.
	 */
	leaf_fd = tzfs_openat(ns_fd, claim, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	if (leaf_fd == -1 && errno == ENOENT) {
		if (tzfsd_count_children(ns_fd) >= TZFSD_NS_MAX_CLAIMS) {
			(void)close(ns_fd);
			errno = EDQUOT;
			return (-1);
		}
		leaf_fd = tzfsd_ensure_path(ns_fd, claim, ZH_ALL_RIGHTS);
	}
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
mounted:
	if (rq->deliver == TZFSD_DELIVER_MOUNTED ||
	    rq->deliver == TZFSD_DELIVER_MOUNTED_RO) {
		int dfd, saved, tries;

		/*
		 * The kernel shares one anonymous mount per dataset and refuses
		 * (EBUSY) a claim that races the last anchor's teardown or a
		 * concurrent first mount -- the shape of a unit relaunching
		 * right after its previous instance let go of the store.  That
		 * window is short; wait it out rather than fail the claim.
		 */
		for (tries = 0;; tries++) {
			dfd = tzfs_mount(leaf_fd, false);
			if (dfd != -1 || errno != EBUSY ||
			    tries >= TZFSD_MOUNT_BUSY_RETRIES)
				break;
			(void)usleep(TZFSD_MOUNT_BUSY_WAIT_US);
		}
		if (tries > 0)
			syslog(LOG_INFO, "mount of claim %s %s after %d busy "
			    "retr%s", claim, dfd != -1 ? "succeeded" : "failed",
			    tries, tries == 1 ? "y" : "ies");

		/*
		 * A read-only claim never chowns: the store belongs to its
		 * writer, and this caller only gets a narrowed view of it.  The
		 * narrowing is Capsicum rights on the delivered directory, so
		 * every descriptor opened beneath it is read-only as well; the
		 * mount itself stays read-write and shared with the writers.
		 */
		if (dfd == -1 || (!ro && rq->owner_uid != 0 &&
		    fchown(dfd, conn->uid, conn->gid) == -1) ||
		    (ro && tzfsd_limit_readonly_dir(dfd) == -1)) {
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
		(void)close(ns_fd);
		if (snprintf(dataset, dsz, "%s/%s/%s", parent_name, ns, claim) >=
		    (int)dsz) {
			(void)close(dfd);
			(void)close(leaf_fd);	/* drops the mount anchor */
			errno = ENAMETOOLONG;
			return (-1);
		}
		*keep_fd = leaf_fd;
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
		    fchown(dfd, conn->uid, conn->gid) == -1) {
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

	if (snprintf(dataset, dsz, "%s/%s/%s", parent_name, ns, claim) >=
	    (int)dsz) {
		(void)close(granted);
		errno = ENAMETOOLONG;
		return (-1);
	}
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
 * TZFSD_OP_LIST request.  Container-scoping is the hard invariant: the walk is
 * rooted at the caller's OWN container — its per-bundle Data/<bundle>/<unit>/
 * persistent, from the container switchboard stamped on the channel — so it can
 * only ever see children of its own container and never another label's claims.
 * There is no wire argument that could redirect it.  Fills the page
 * [cursor, cursor+TZFSD_LIST_MAX) of the claim set (sorted for a stable window)
 * and sets rp->next_cursor nonzero when more remain.  Per-claim usage/refquota
 * are folded in best-effort from the same walk.  Returns 0 (rp->status left 0),
 * or -1 with errno set.  A caller with no namespace lists empty, not an error.
 */
static int
grant_list(struct tzfsd_state *st, const char *container,
    const struct tzfsd_list_request *rq, struct tzfsd_list_reply *rp)
{
	struct zfd_info_args info;
	char ns[TZFSD_MAXPATH];
	void *buf;
	char **names, **claims;
	size_t len, prefix_len, nnames, nclaims, i, idx;
	int ns_fd, saved;

	/* Additive fields must be zero (message hygiene, symmetric with the rest). */
	if (rq->flags != 0 || rq->_reserved != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (st->persistent_fd == -1) {
		errno = ENXIO;
		return (-1);
	}
	/*
	 * A caller with no container (no bundle) holds no durable claims: an empty
	 * list, not an error.
	 */
	if (!container_ns(container, TZFSD_PERSISTENT, ns, sizeof(ns)))
		return (0);	/* rp->count / next_cursor already 0 */

	/*
	 * Open the caller's OWN container-persistent namespace under the Data
	 * root.  This — and only this — is what the walk enumerates; it is never a
	 * wire-named parent.  An absent namespace means the caller has made no
	 * persistent claims yet: an empty list, not an error.
	 */
	ns_fd = open_ns_path(st->persistent_fd, ns, ZH_ALL_RIGHTS, ZHF_SUBTREE);
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
			handle = grant_open(st, conn->label, orq);
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
			if (grant_list(st, conn->container, lrq, &lrp) == -1) {
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
		/*
		 * The sender's credentials are stamped by the kernel on every
		 * message; they are the only ownership a store may take.
		 */
		const struct channel_sender *sender = channel_message_sender(m);

		conn->uid = sender != NULL ? sender->uid : 0;
		conn->gid = sender != NULL ? sender->gid : 0;
	}
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

		handle = grant(st, conn, rq, rp.dataset, sizeof(rp.dataset),
		    &keep_fd);
		TZFSD_PROBE_GRANT(rq->op, rq->deliver, handle,
		    handle == -1 ? errno : 0);
		/*
		 * A mounted grant hands back the leaf handle anchoring the
		 * delivered mount; retain it (one anchor per claim) so the store
		 * stays mounted while the client holds its lease.
		 */
		if (keep_fd != -1 &&
		    conn_anchor_add(conn, rp.dataset, keep_fd) == -1) {
			int saved = errno;

			(void)close(handle);
			(void)close(keep_fd);
			handle = -1;
			errno = saved;
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
			    rq->deliver == TZFSD_DELIVER_MOUNTED_RO ?
			    " (mounted, read-only view)" : "");
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
		{
			char full[TZFSD_MAXPATH];

			/*
			 * Our own anchor would make the destroy EBUSY, so drop it
			 * first.  If the destroy still fails (another holder), the
			 * store stays mounted by the other anchors -- including the
			 * consumer's own delivered descriptor -- and is unmounted
			 * when the last of those goes, rather than at this
			 * connection's end.
			 */
			(void)snprintf(full, sizeof(full), "%s/%s/%s/%s",
			    st->cfg.ephemeral, st->lease_name, ns, rq->dataset);
			conn_anchor_drop(conn, full);
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
		 * resolved under the CALLER's per-bundle container (from its own
		 * unforgeable identity), so a caller can only ever name — and destroy
		 * — its own storage.  Unlike RELEASE, an absent claim replies ENOENT
		 * rather than idempotent success, so a caller can distinguish a real
		 * reclaim.
		 */
		char ns[TZFSD_MAXPATH];
		int ns_fd, probe;

		if (rq->lifetime > TZFSD_CACHE || !valid_dataset(rq->dataset) ||
		    !scoped_ns(conn->container, (const char (*)[64])conn->groups,
		    rq->scope, rq->group, rq->lifetime, ns, sizeof(ns))) {
			rp.status = EINVAL;
			break;
		}
		if (st->persistent_fd == -1) {
			rp.status = ENXIO;
			break;
		}
		ns_fd = open_ns_path(st->persistent_fd, ns, ZH_ALL_RIGHTS,
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
		{
			char full[TZFSD_MAXPATH];

			/* Our own anchor would make the destroy EBUSY (see RELEASE). */
			(void)snprintf(full, sizeof(full), "%s/%s/%s",
			    st->cfg.persistent, ns, rq->dataset);
			conn_anchor_drop(conn, full);
		}
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
tzfs_worker(struct tzfsd_state *st, int fd, const char *client,
    const char *owner, const char *container, const char (*groups)[64])
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct channel *channel = NULL;
	struct tzfs_conn conn;
	int ready, wants_write;

	/* Discard parent authority before serving the worker channel. */
	service_worker_drop_inherited_authority();

	conn.st = st;
	conn.uid = 0;		/* stamped per message, see tzfs_request */
	conn.gid = 0;
	conn_anchors_init(&conn);
	(void)strlcpy(conn.client, owner, sizeof(conn.client));
	(void)strlcpy(conn.label, client, sizeof(conn.label));
	(void)strlcpy(conn.container, container, sizeof(conn.container));
	memset(conn.groups, 0, sizeof(conn.groups));
	if (groups != NULL) {
		unsigned gi;

		for (gi = 0; gi < 4; gi++)
			(void)strlcpy(conn.groups[gi], groups[gi],
			    sizeof(conn.groups[gi]));
	}

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
	conn_anchors_close(&conn);
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

	/* Cleanup is the container-model reconcile: the forked reaper started at
	 * boot (see tzfsd_start_reaper). */
	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_expose(provider, TZFSD_SERVICE_NAME, &listener) ==
	    -1 ||
	    service_provider_enter_privileged(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		return (-1);

	for (;;) {
		pid_t pid;

		memset(&id, 0, sizeof(id));
		id.size = sizeof(id);
		if (service_listener_accept(listener, &id, &fd) == -1)
			return (-1);
		pid = fork();
		if (pid == -1) {
			syslog(LOG_ERR, "fork: %m");
			(void)close(fd);
			continue;
		}
		if (pid == 0) {
			/* Protect before dropping the inherited bootstrap authority. */
			if (service_worker_protect(SERVICE_PROTECT_EXTERNAL) == -1) {
				syslog(LOG_ERR, "worker protection: %m");
				_exit(1);
			}
			_exit(tzfs_worker(st, fd, id.client_label,
			    id.resource_owner, id.container,
			    (const char (*)[64])id.groups));
		}
		(void)close(fd);
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

/*
 * Anchor bookkeeping seams: a bare connection whose anchors are the only
 * state, driven with ordinary descriptors (no ZFS).  "live" counts the
 * anchors held.
 */
struct tzfs_conn *
tzfsd_test_conn_new(void)
{
	struct tzfs_conn *conn = calloc(1, sizeof(*conn));

	if (conn != NULL)
		conn_anchors_init(conn);
	return (conn);
}

int
tzfsd_test_anchor_add(struct tzfs_conn *conn, const char *dataset, int fd)
{

	return (conn_anchor_add(conn, dataset, fd));
}

void
tzfsd_test_anchor_drop(struct tzfs_conn *conn, const char *dataset)
{

	conn_anchor_drop(conn, dataset);
}

bool
tzfsd_test_valid_container(const char *c)
{

	return (valid_container(c));
}

unsigned
tzfsd_test_anchor_live(const struct tzfs_conn *conn)
{
	unsigned n = 0;
	size_t i;

	for (i = 0; i < nitems(conn->anchors); i++)
		if (conn->anchors[i].fd != -1)
			n++;
	return (n);
}

void
tzfsd_test_conn_free(struct tzfs_conn *conn)
{

	conn_anchors_close(conn);
	free(conn);
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
bool
tzfsd_test_scoped_ns(const char *container, const char (*groups)[64],
    uint8_t scope, const char *group, uint32_t lifetime, char *out,
    size_t outsz)
{
	return (scoped_ns(container, groups, scope, group, lifetime, out, outsz));
}

int
tzfsd_test_grant(struct tzfsd_state *st, const char *client,
    const struct tzfsd_request *rq, char *dataset, size_t dsz)
{
	struct tzfs_conn conn;
	int keep_fd = -1;
	int handle;

	memset(&conn, 0, sizeof(conn));
	(void)strlcpy(conn.client, client, sizeof(conn.client));
	(void)strlcpy(conn.label, client, sizeof(conn.label));
	conn_anchors_init(&conn);
	handle = grant(st, &conn, rq, dataset, dsz, &keep_fd);
	conn_anchors_close(&conn);
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

	return (tzfs_worker(st, fd, client, client, "", NULL));
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

	return (grant_list(st, client, rq, rp));	/* client == container in the seam */
}
#endif /* TZFSD_TESTING */
