/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsdfilesystem(8) request loop.  bsdfilesystem is a socket-free service_provider: it exposes
 * system.Filesystem and serves each client on its own mac_capability worker
 * channel.  Every handle is derived/created/cloned/destroyed from the retained
 * parent handles in capability mode, and the granted handle rides back to the
 * client as the reply's single SCM fd.
 *
 * Dataset keys are opaque, single-level names derived by the trusted bundle
 * parser.  bsdfilesystem never accepts a user-facing role or path.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/wait.h>

#include <dev/hid/vhid.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>


#include <channel.h>
#include <libservice.h>
#include <trustedzfs.h>

#include "bsdfilesystem.h"
#include "bsdfilesystem_probes.h"

/*
 * Per-connection worker context: the retained-handle state (a private COW copy)
 * plus the connecting client's unforgeable label, which namespaces every leaf
 * this client can name.
 */
struct tzfs_conn {
	struct bsdfilesystem_state	*st;
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
		char	dataset[BSDFILESYSTEM_MAXPATH];	/* full dataset name */
		int	fd;			/* leaf handle, -1 == free */
		bool	ephemeral;		/* destroy the dataset on teardown */
	}			anchors[BSDFILESYSTEM_CONN_MAX_CLAIMS];
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
conn_anchor_add(struct tzfs_conn *conn, const char *dataset, int fd,
    bool ephemeral)
{
	size_t i, slot = SIZE_MAX;
	int old = -1;

	for (i = 0; i < nitems(conn->anchors); i++) {
		if (conn->anchors[i].fd != -1 &&
		    strcmp(conn->anchors[i].dataset, dataset) == 0) {
			old = conn->anchors[i].fd;
			conn->anchors[i].fd = fd;
			conn->anchors[i].ephemeral = ephemeral;
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
	conn->anchors[slot].ephemeral = ephemeral;
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

/*
 * Leaf-name prefix the broker reserves for its own transient staging clones
 * during a TXN_COMMIT swap (see the TXN_COMMIT handler's `del-<version>`).  A
 * caller-supplied claim must never occupy it: otherwise a pre-created
 * `del-<version>` claim would EEXIST-collide with the swap's rename and wedge
 * the commit.  Versions themselves use the unpredictable `v<hex>` shape keyed
 * to the caller's own container, so they need no reservation here.
 *
 * BSDFILESYSTEM_STAGING_PREFIX and BSDFILESYSTEM_TXN_BASE_PROP are defined in
 * bsdfilesystem.h: the boot-scoped staging sweep in layout.c reaps by both.
 *
 * The v<hex> version-id shape is ALSO reserved: it names the broker's TXN
 * staging clones, and letting a caller take a claim (or a writable handle) by
 * that name would let it (a) rewrite a staging clone's bsdfilesystem:txnbase
 * property to redirect a commit onto a different claim, and (b) name a claim
 * that the reaper's name-shape guard would then mistake for an orphan and
 * destroy.  A real claim never needs this shape.
 */
static bool
valid_dataset(const char *name)
{

	if (strncmp(name, BSDFILESYSTEM_STAGING_PREFIX,
	    sizeof(BSDFILESYSTEM_STAGING_PREFIX) - 1) == 0)
		return (false);
	if (bsdfilesystem_is_version_id_name(name))
		return (false);
	return (valid_dataset_n(name, BSDFILESYSTEM_NAME_MAX));
}

/*
 * A version identifier a caller supplies (TXN_COMMIT/ABORT, ROLLBACK,
 * OPEN_VERSION) must be exactly the v<hex> shape the broker mints -- never a
 * claim name and never the reserved del-<id> transient.  Screening with
 * valid_dataset_n alone (charset only) would let a caller pass version="del-X"
 * (destroying the broker's mid-swap transient) or version=<some claim> (naming
 * a different dataset in its own namespace) into destroy_tree/promote paths.
 */
static bool
valid_version(const char *version, size_t capacity)
{

	return (valid_dataset_n(version, capacity) &&
	    bsdfilesystem_is_version_id_name(version));
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
valid_request(const struct bsdfilesystem_request *rq)
{

	if (!all_zero(rq->_reserved, sizeof(rq->_reserved)) ||
	    rq->deliver > BSDFILESYSTEM_DELIVER_MOUNTED_RO ||
	    memchr(rq->dataset, '\0', sizeof(rq->dataset)) == NULL ||
	    memchr(rq->session, '\0', sizeof(rq->session)) == NULL ||
	    memchr(rq->group, '\0', sizeof(rq->group)) == NULL ||
	    rq->scope > BSDFILESYSTEM_SCOPE_GROUP)
		return (false);
	/*
	 * Scope names a durable container shape: only REQUEST and DESTROY take
	 * one, only for persistent/cache claims, and `group` is present exactly
	 * when the scope is GROUP (and is then a safe single component).
	 */
	if (rq->op != BSDFILESYSTEM_OP_REQUEST && rq->op != BSDFILESYSTEM_OP_DESTROY &&
	    rq->op != BSDFILESYSTEM_OP_STAT_CLAIM &&
	    rq->op != BSDFILESYSTEM_OP_SET_QUOTA) {
		if (rq->scope != BSDFILESYSTEM_SCOPE_UNIT || rq->group[0] != '\0')
			return (false);
	} else {
		if (rq->scope != BSDFILESYSTEM_SCOPE_UNIT && rq->lifetime > BSDFILESYSTEM_CACHE)
			return (false);
		if ((rq->scope == BSDFILESYSTEM_SCOPE_GROUP) != (rq->group[0] != '\0'))
			return (false);
		if (rq->group[0] != '\0' && !valid_dataset(rq->group))
			return (false);
	}
	switch (rq->op) {
	case BSDFILESYSTEM_OP_REQUEST:
		/*
		 * quota (0=default, else validated in grant) may be nonzero.
		 * DELIVER_MOUNTED is only meaningful for a claim that was granted
		 * ZH_MOUNT — bsdfilesystem mounts it server-side and returns the dir fd.
		 */
		if (rq->deliver != BSDFILESYSTEM_DELIVER_HANDLE &&
		    (rq->rights & ZH_MOUNT) == 0)
			return (false);
		/*
		 * A read-only view never sizes the store; ownership fields are
		 * tolerated (the library always sends the caller's own uid/gid)
		 * but ignored -- a read-only claim never chowns (see grant()).
		 */
		if (rq->deliver == BSDFILESYSTEM_DELIVER_MOUNTED_RO && rq->quota != 0)
			return (false);
		return (rq->session[0] == '\0');
	case BSDFILESYSTEM_OP_RELEASE:
		return (rq->deliver == 0 && rq->flags == 0 && rq->rights == 0 &&
		    rq->lifetime == 0 && rq->quota == 0 && rq->owner_uid == 0 &&
		    rq->owner_gid == 0 && rq->session[0] == '\0');
	case BSDFILESYSTEM_OP_DESTROY:
		/*
		 * Identifies a claim exactly as REQUEST does (dataset + lifetime),
		 * but carries no rights/flags/quota/session and no fd/path.
		 */
		return (rq->deliver == 0 && rq->flags == 0 && rq->rights == 0 &&
		    rq->quota == 0 && rq->owner_uid == 0 && rq->owner_gid == 0 &&
		    rq->session[0] == '\0');
	case BSDFILESYSTEM_OP_STAT_CLAIM:
		/* Names a claim (dataset + lifetime + scope), reads only. */
		return (rq->deliver == 0 && rq->flags == 0 && rq->rights == 0 &&
		    rq->quota == 0 && rq->owner_uid == 0 && rq->owner_gid == 0 &&
		    rq->lifetime <= BSDFILESYSTEM_CACHE && rq->session[0] == '\0');
	case BSDFILESYSTEM_OP_SET_QUOTA:
		/* Names a claim + carries the new refquota (quota may be 0). */
		return (rq->deliver == 0 && rq->flags == 0 && rq->rights == 0 &&
		    rq->owner_uid == 0 && rq->owner_gid == 0 &&
		    rq->lifetime <= BSDFILESYSTEM_CACHE && rq->session[0] == '\0');
	case BSDFILESYSTEM_OP_PING:
		return (rq->deliver == 0 && rq->flags == 0 && rq->rights == 0 &&
		    rq->lifetime == 0 && rq->quota == 0 && rq->owner_uid == 0 &&
		    rq->owner_gid == 0 && rq->dataset[0] == '\0' &&
		    rq->session[0] == '\0');
	case BSDFILESYSTEM_OP_BEGIN_SESSION:
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
	char comp[BSDFILESYSTEM_NAME_MAX];
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
	    !valid_dataset_n(slash + 1, BSDFILESYSTEM_NAME_MAX))
		return (false);
	/*
	 * Reserved: a bundle named "Shared" would alias Data/Shared/ -- the
	 * GROUP container root -- so its unit-scope claims would land in group
	 * containers with no membership check and be reaped by the group
	 * reconcile; a unit named "shared" would alias its bundle's SHARED
	 * scope.  Neither may exist as a container.
	 */
	if (name_is(comp, BSDFILESYSTEM_SHARED_DIR) || name_is(slash + 1, "shared"))
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
	const char *sub = lifetime == BSDFILESYSTEM_CACHE ? "cache" : "persistent";

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
	const char *sub = lifetime == BSDFILESYSTEM_CACHE ? "cache" : "persistent";
	const char *slash;
	size_t blen;
	unsigned i;

	if (!valid_container(container))
		return (false);
	switch (scope) {
	case BSDFILESYSTEM_SCOPE_UNIT:
		return (container_ns(container, lifetime, out, outsz));
	case BSDFILESYSTEM_SCOPE_SHARED:
		slash = strchr(container, '/');
		blen = (size_t)(slash - container);
		return ((size_t)snprintf(out, outsz, "%.*s/shared/%s", (int)blen,
		    container, sub) < outsz);
	case BSDFILESYSTEM_SCOPE_GROUP:
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
 * component is absent), mirroring bsdfilesystem_ensure_path's walk without the create.
 */
static int
open_ns_path(int parent_fd, const char *relpath, uint64_t rights, uint32_t flags)
{
	char comp[BSDFILESYSTEM_MAXPATH];
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
bsdfilesystem_limit_readonly_dir(int dfd)
{
	cap_rights_t rights;

	cap_rights_init(&rights, CAP_READ, CAP_LOOKUP, CAP_FSTAT, CAP_FSTATAT,
	    CAP_FSTATFS, CAP_SEEK, CAP_MMAP_R, CAP_FCNTL, CAP_FPATHCONF,
	    CAP_EVENT, CAP_KQUEUE_EVENT);
	return (cap_rights_limit(dfd, &rights));
}

static int
grant(struct bsdfilesystem_state *st, const struct tzfs_conn *conn,
    const struct bsdfilesystem_request *rq, char *dataset, size_t dsz, int *keep_fd)
{
	struct bsdfilesystem_config *cfg = &st->cfg;
	const char *owner = conn->client, *container = conn->container;
	const char (*groups)[64] = (const char (*)[64])conn->groups;
	const bool ro = rq->deliver == BSDFILESYSTEM_DELIVER_MOUNTED_RO;
	int parent_fd, ns_fd, leaf_fd, granted;
	const char *parent_name, *claim;
	char parent_buf[BSDFILESYSTEM_MAXPATH];
	char ns[BSDFILESYSTEM_MAXPATH];

	/*
	 * On a DELIVER_MOUNTED grant this returns the leaf handle that anchors
	 * the delivered mount; the caller must keep it open for the mount's
	 * lifetime.  -1 for every other outcome (nothing to retain).
	 */
	*keep_fd = -1;

	if (rq->lifetime > BSDFILESYSTEM_LEASE) {
		errno = EINVAL;
		return (-1);
	}
	if ((rq->rights & ~ZH_ALL_RIGHTS) != 0 || rq->rights == 0 ||
	    (rq->flags & ~ZHF_SUBTREE) != 0) {
		errno = EINVAL;
		return (-1);
	}
	/* A per-request quota override must be either the default (0) or sane. */
	if (rq->quota != 0 && rq->quota < BSDFILESYSTEM_MIN_REFQUOTA) {
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
	if (rq->lifetime == BSDFILESYSTEM_BOOT) {
		parent_fd = st->boot_fd;
		(void)snprintf(parent_buf, sizeof(parent_buf), "%s/%s",
		    cfg->ephemeral, st->boot_name);
		parent_name = parent_buf;
		if (!derive_ns(owner, ns, sizeof(ns))) {
			errno = EINVAL;
			return (-1);
		}
	} else if (rq->lifetime == BSDFILESYSTEM_LEASE) {
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
	ns_fd = bsdfilesystem_ensure_path(parent_fd, ns, ZH_ALL_RIGHTS);
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
		if (bsdfilesystem_count_children(ns_fd) >= BSDFILESYSTEM_NS_MAX_CLAIMS) {
			(void)close(ns_fd);
			errno = EDQUOT;
			return (-1);
		}
		leaf_fd = bsdfilesystem_ensure_path(ns_fd, claim, ZH_ALL_RIGHTS);
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
	 * perform the ZFS mount itself, so bsdfilesystem (privileged) mounts the claim ONCE
	 * here and returns the mounted store directory in the handle's place.  The
	 * objset stays mounted for the claim's lifetime (RELEASE/DESTROY reclaim
	 * it); doing the mount once — rather than the provisioning mount+unmount
	 * below followed by a second consumer mount — avoids the double-mount that
	 * otherwise fails EINVAL.  The delivered directory carries full rights; the
	 * consumer narrows it (e.g. bsdlog's cap_rights_limit on its store dir).
	 */
mounted:
	if (rq->deliver == BSDFILESYSTEM_DELIVER_MOUNTED ||
	    rq->deliver == BSDFILESYSTEM_DELIVER_MOUNTED_RO) {
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
			    tries >= BSDFILESYSTEM_MOUNT_BUSY_RETRIES)
				break;
			(void)usleep(BSDFILESYSTEM_MOUNT_BUSY_WAIT_US);
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
		    (ro && bsdfilesystem_limit_readonly_dir(dfd) == -1)) {
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
 * Open an isolated path descriptor for a BSDFILESYSTEM_OP_OPEN request from `client`.
 * Default-deny: the client's unforgeable label and the exact path must match a
 * configured policy entry that covers the requested rights.  The open is done
 * relative to the retained root fd (capsicum-legal in capability mode) and the
 * delivered fd is capped to exactly the requested rights.  Returns the fd, or
 * -1 with errno (EACCES when the policy does not grant it).
 */
static int
grant_open(struct bsdfilesystem_state *st, const char *client,
    const struct bsdfilesystem_open_request *rq)
{
	const struct bsdfilesystem_config *cfg = &st->cfg;
	cap_rights_t rights;
	unsigned i;
	int flags, fd, saved;

	if (rq->rights == 0 || (rq->rights & ~BSDFILESYSTEM_OPEN_RIGHTS_ALL) != 0) {
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
		const struct bsdfilesystem_open_policy *pol = &cfg->open_policy[i];

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

	if ((rq->rights & (BSDFILESYSTEM_OPEN_READ | BSDFILESYSTEM_OPEN_WRITE)) ==
	    (BSDFILESYSTEM_OPEN_READ | BSDFILESYSTEM_OPEN_WRITE))
		flags = O_RDWR;
	else if (rq->rights & BSDFILESYSTEM_OPEN_WRITE)
		flags = O_WRONLY;
	else
		flags = O_RDONLY;	/* read/exec/lookup all open read-only */
	flags |= O_CLOEXEC | O_NOCTTY;
	if (rq->is_dir)
		flags |= O_DIRECTORY;
	/*
	 * The proto promises symlink safety (bsdfilesystem_proto.h): O_NOFOLLOW refuses a
	 * symlink at the granted leaf itself, and O_RESOLVE_BENEATH refuses any
	 * intermediate symlink, absolute path, or ".." that would resolve outside
	 * the retained root fd.  O_RESOLVE_BENEATH relative to that root fd is what
	 * blocks absolute/".." escapes (bsdfilesystem is ambient, NOT in capability mode, so
	 * capsicum is not the boundary here); O_NOFOLLOW additionally refuses an
	 * in-tree symlink pointed at a different node/type than the policy author
	 * intended.  Both are compatible with the
	 * capmode openat here — path+1 is strictly relative to root_fd with no
	 * ".." (validated above), so resolution always stays beneath it.
	 */
	flags |= O_NOFOLLOW | O_RESOLVE_BENEATH;

	/* Relative to the retained root fd: legal in capability mode. */
	fd = openat(st->root_fd, rq->path + 1, flags);
	if (fd == -1)
		return (-1);

	cap_rights_init(&rights, 0);
	if (rq->rights & BSDFILESYSTEM_OPEN_READ)
		cap_rights_set(&rights, CAP_READ, CAP_SEEK, CAP_FSTAT);
	if (rq->rights & BSDFILESYSTEM_OPEN_WRITE)
		cap_rights_set(&rights, CAP_WRITE, CAP_SEEK, CAP_FSYNC);
	if (rq->rights & BSDFILESYSTEM_OPEN_EXEC)
		cap_rights_set(&rights, CAP_FEXECVE);
	if (rq->rights & BSDFILESYSTEM_OPEN_LOOKUP)
		cap_rights_set(&rights, CAP_LOOKUP, CAP_FSTATAT);
	if (rq->rights & BSDFILESYSTEM_OPEN_IOCTL)
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
	if (rq->rights & BSDFILESYSTEM_OPEN_IOCTL) {
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

/*
 * One collected claim in the combined LIST set: its opaque key and the lifetime
 * (persistent/cache) of the namespace it was found under.  The name is a copy so
 * the per-namespace nvlist buffers can be released as soon as each namespace is
 * walked, leaving only the two namespace fds open for the usage lookup.
 */
struct list_claim {
	char		name[BSDFILESYSTEM_NAME_MAX];
	uint8_t		lifetime;
};

/*
 * Deterministic claim ordering so pagination windows are stable across calls.
 * The merged set spans two namespaces, so a claim key may appear under both
 * (a persistent and a cache claim of the same name are distinct datasets); order
 * by name, then by lifetime, so the combined window is fully reproducible and
 * the two same-named claims keep a fixed relative position.
 */
static int
list_claim_cmp(const void *ap, const void *bp)
{
	const struct list_claim *a = ap, *b = bp;
	int c = strcmp(a->name, b->name);

	if (c != 0)
		return (c);
	return ((int)a->lifetime - (int)b->lifetime);
}

/*
 * Collect the immediate claim components of ONE durable namespace (persistent or
 * cache) rooted under parent_fd into the growing *claimsp array, tagging each
 * with `lifetime`.  On success the opened namespace fd is returned via *ns_fdp
 * (so the caller can open each claim for usage under the same retained fd) and is
 * -1 when the namespace does not exist yet (an absent namespace contributes no
 * claims, not an error).  Returns 0, or -1 with errno; on failure nothing is
 * left open and the caller frees *claimsp.
 */
static int
list_collect_ns(int parent_fd, const char *ns, uint8_t lifetime, int *ns_fdp,
    struct list_claim **claimsp, size_t *nclaimsp, size_t *capp)
{
	struct zfd_info_args info;
	void *buf;
	char **names;
	size_t len, prefix_len, nnames, i;
	int ns_fd, saved;

	*ns_fdp = -1;
	/*
	 * Open the caller's OWN container namespace under the Data root.  This —
	 * and only this — is what the walk enumerates; it is never a wire-named
	 * parent.  An absent namespace means the caller has made no claims of this
	 * lifetime yet: contribute nothing rather than fail.
	 */
	ns_fd = open_ns_path(parent_fd, ns, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	if (ns_fd == -1)
		return (errno == ENOENT ? 0 : -1);
	memset(&info, 0, sizeof(info));
	if (tzfs_info(ns_fd, &info) == -1 ||
	    tzfs_list_children(ns_fd, &buf, &len) == -1) {
		saved = errno;
		(void)close(ns_fd);
		errno = saved;
		return (-1);
	}
	if (bsdfilesystem_nvl_names(buf, len, &names, &nnames) == -1) {
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
	for (i = 0; i < nnames; i++) {
		const char *name = names[i], *rel;
		struct list_claim *nc;

		if (strncmp(name, info.zi_name, prefix_len) != 0 ||
		    name[prefix_len] != '/') {
			bsdfilesystem_nvl_names_free(names, nnames);
			(void)close(ns_fd);
			errno = EPROTO;
			return (-1);
		}
		rel = name + prefix_len + 1;
		if (strchr(rel, '/') != NULL)
			continue;	/* a child of a claim, not a claim itself */
		if (strlen(rel) >= BSDFILESYSTEM_NAME_MAX)
			continue;	/* claim keys are < BSDFILESYSTEM_NAME_MAX by construction */
		if (*nclaimsp == *capp) {
			size_t ncap = *capp == 0 ? 64 : *capp * 2;
			struct list_claim *tmp;

			tmp = reallocarray(*claimsp, ncap, sizeof(*tmp));
			if (tmp == NULL) {
				saved = errno;
				bsdfilesystem_nvl_names_free(names, nnames);
				(void)close(ns_fd);
				errno = saved;
				return (-1);
			}
			*claimsp = tmp;
			*capp = ncap;
		}
		nc = &(*claimsp)[(*nclaimsp)++];
		(void)strlcpy(nc->name, rel, sizeof(nc->name));
		nc->lifetime = lifetime;
	}
	bsdfilesystem_nvl_names_free(names, nnames);
	*ns_fdp = ns_fd;
	return (0);
}

/*
 * Enumerate the caller's own persistent AND cache claims into *rp for an
 * BSDFILESYSTEM_OP_LIST request.  Container-scoping is the hard invariant: both
 * walks are rooted at the caller's OWN container — its per-bundle
 * Data/<bundle>/<unit>/{persistent,cache}, from the container switchboard stamped
 * on the channel — so they can only ever see children of the caller's own
 * container and never another label's claims.  There is no wire argument that
 * could redirect them.  The two namespaces are merged into one set, sorted (by
 * name then lifetime) for a stable window, and the page
 * [cursor, cursor+BSDFILESYSTEM_LIST_MAX) is emitted; rp->next_cursor is set
 * nonzero when more remain.  Each entry carries its lifetime (so the consumer can
 * DESTROY it under the right namespace) plus best-effort usage/refquota folded in
 * from the claim's own namespace fd.  Returns 0 (rp->status left 0), or -1 with
 * errno set.  A caller with neither namespace lists empty, not an error.
 */
static int
grant_list(struct bsdfilesystem_state *st, const char *container,
    const char (*groups)[64], const struct bsdfilesystem_list_request *rq,
    struct bsdfilesystem_list_reply *rp)
{
	char ns[BSDFILESYSTEM_MAXPATH];
	struct list_claim *claims = NULL;
	size_t nclaims = 0, cap = 0, idx;
	int ns_fd_pers = -1, ns_fd_cache = -1, saved;

	/* Additive fields must be zero (message hygiene, symmetric with the rest). */
	if (rq->flags != 0 || !all_zero(rq->_reserved, sizeof(rq->_reserved))) {
		errno = EINVAL;
		return (-1);
	}
	/*
	 * Scope selects which of the caller's namespaces to enumerate; `group`
	 * accompanies GROUP scope only.  A malformed shape (bad scope, or a group
	 * on a non-GROUP request, or an empty group on a GROUP request) is EINVAL.
	 */
	if (rq->scope > BSDFILESYSTEM_SCOPE_GROUP ||
	    (rq->scope != BSDFILESYSTEM_SCOPE_GROUP && rq->group[0] != '\0') ||
	    (rq->scope == BSDFILESYSTEM_SCOPE_GROUP && rq->group[0] == '\0')) {
		errno = EINVAL;
		return (-1);
	}
	if (st->persistent_fd == -1) {
		errno = ENXIO;
		return (-1);
	}
	/*
	 * A caller with no container (no bundle), or a GROUP it is not a member
	 * of, holds no claims in this scope: an empty list, not an error (never a
	 * leak).  Both durable namespaces derive from the same scope, so if the
	 * persistent name will not build neither will cache.
	 */
	if (!scoped_ns(container, groups, rq->scope, rq->group,
	    BSDFILESYSTEM_PERSISTENT, ns, sizeof(ns)))
		return (0);	/* rp->count / next_cursor already 0 */
	if (list_collect_ns(st->persistent_fd, ns, BSDFILESYSTEM_PERSISTENT,
	    &ns_fd_pers, &claims, &nclaims, &cap) == -1) {
		saved = errno;
		free(claims);
		errno = saved;
		return (-1);
	}
	if (scoped_ns(container, groups, rq->scope, rq->group,
	    BSDFILESYSTEM_CACHE, ns, sizeof(ns)) &&
	    list_collect_ns(st->persistent_fd, ns, BSDFILESYSTEM_CACHE,
	    &ns_fd_cache, &claims, &nclaims, &cap) == -1) {
		saved = errno;
		free(claims);
		if (ns_fd_pers != -1)
			(void)close(ns_fd_pers);
		errno = saved;
		return (-1);
	}
	qsort(claims, nclaims, sizeof(*claims), list_claim_cmp);

	/*
	 * Emit the requested page.  cursor is an index into the merged, sorted
	 * claim set; a stable sort makes the window reproducible across paged
	 * calls.  For each claim, open a read-only handle under the retained
	 * namespace fd for that claim's lifetime (never a client-named parent) and
	 * fold in usage + refquota best-effort.
	 */
	rp->count = 0;
	rp->next_cursor = 0;
	for (idx = rq->cursor; idx < nclaims && rp->count < BSDFILESYSTEM_LIST_MAX;
	    idx++) {
		struct bsdfilesystem_claim_entry *e = &rp->entries[rp->count];
		const struct list_claim *lc = &claims[idx];
		int ns_fd = lc->lifetime == BSDFILESYSTEM_CACHE ? ns_fd_cache :
		    ns_fd_pers;
		struct zfd_stat_args stt;
		uint64_t refquota = 0;
		int cfd, is_string = 0;
		uint32_t src = 0;

		(void)strlcpy(e->name, lc->name, sizeof(e->name));
		e->lifetime = lc->lifetime;
		if (ns_fd != -1 &&
		    (cfd = tzfs_openat(ns_fd, lc->name, ZH_PROPS_READ, 0)) != -1) {
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
	if (ns_fd_pers != -1)
		(void)close(ns_fd_pers);
	if (ns_fd_cache != -1)
		(void)close(ns_fd_cache);
	return (0);
}


/* Generate a unique, lexically-sortable version id for a new snapshot. */
static void
gen_version_id(char *out, size_t sz)
{
	static uint32_t counter;
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
		ts.tv_sec = (time_t)counter;
		ts.tv_nsec = 0;
	}
	/*
	 * Each connection is its own fork(), so `counter` resets to 0 per worker
	 * and the nanosecond clock can repeat: two workers acting on the same
	 * SHARED claim in the same nanosecond would otherwise mint an identical
	 * id and collide (EEXIST).  Salt with the pid, as OPEN_VERSION's clone
	 * name already does, so distinct workers never produce the same id.
	 */
	(void)snprintf(out, sz, "v%016jx%08x%08x",
	    (uintmax_t)ts.tv_sec * 1000000000u + (uintmax_t)ts.tv_nsec,
	    (uint32_t)getpid(), counter++);
}

/*
 * Open one of the caller's OWN persistent/cache claims, resolved under its
 * unforgeable container exactly as DESTROY/STAT_CLAIM do, with the given rights.
 * Returns the claim handle fd, or -1 with errno (EINVAL bad name / EPERM no
 * container / ENXIO no pool / ENOENT absent claim).
 */
static int
open_own_claim(struct bsdfilesystem_state *st, struct tzfs_conn *conn,
    uint8_t lifetime, uint8_t scope, const char *group, const char *dataset,
    uint64_t rights, uint32_t flags)
{
	char ns[BSDFILESYSTEM_MAXPATH];
	int ns_fd, cfd;

	if (lifetime > BSDFILESYSTEM_CACHE || !valid_dataset(dataset)) {
		errno = EINVAL;
		return (-1);
	}
	if (!scoped_ns(conn->container, (const char (*)[64])conn->groups, scope,
	    group, lifetime, ns, sizeof(ns))) {
		errno = EPERM;
		return (-1);
	}
	if (st->persistent_fd == -1) {
		errno = ENXIO;
		return (-1);
	}
	ns_fd = open_ns_path(st->persistent_fd, ns, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	if (ns_fd == -1)
		return (-1);
	cfd = tzfs_openat(ns_fd, dataset, rights, flags);
	(void)close(ns_fd);
	return (cfd);
}

/*
 * Open the full-rights namespace fd that holds one of the caller's own
 * persistent/cache claims (its parent), for ops that create/rename siblings of
 * the claim (transactions).  Fills ns[] with the namespace path.  Returns the
 * ns fd, or -1 with errno.
 */
static int
open_own_ns(struct bsdfilesystem_state *st, struct tzfs_conn *conn,
    uint8_t lifetime, uint8_t scope, const char *group, char *ns, size_t nssz)
{

	if (lifetime > BSDFILESYSTEM_CACHE) {
		errno = EINVAL;
		return (-1);
	}
	if (!scoped_ns(conn->container, (const char (*)[64])conn->groups, scope,
	    group, lifetime, ns, nssz)) {
		errno = EPERM;
		return (-1);
	}
	if (st->persistent_fd == -1) {
		errno = ENXIO;
		return (-1);
	}
	return (open_ns_path(st->persistent_fd, ns, ZH_ALL_RIGHTS, ZHF_SUBTREE));
}

/*
 * Serve the snapshot/time-travel ops (BSDFILESYSTEM_OP_SNAPSHOT / _LIST_VERSIONS /
 * _ROLLBACK / _OPEN_VERSION), each carrying a bsdfilesystem_version_request and a
 * distinctly-sized reply.  Every op resolves the claim under the CALLER's own
 * container, so a caller can only ever version its own storage.  Sends its reply
 * inline and returns; never falls through to the shared bsdfilesystem_reply path.
 */
static void
bsdfilesystem_serve_version(struct bsdfilesystem_state *st, struct tzfs_conn *conn,
    const struct bsdfilesystem_version_request *vrq, struct channel_message *m)
{
	struct channel_outgoing out;
	int cfd;

	if (!all_zero(vrq->_reserved, sizeof(vrq->_reserved)) ||
	    vrq->_reserved2 != 0 || vrq->scope > BSDFILESYSTEM_SCOPE_GROUP ||
	    memchr(vrq->dataset, '\0', sizeof(vrq->dataset)) == NULL ||
	    memchr(vrq->group, '\0', sizeof(vrq->group)) == NULL ||
	    memchr(vrq->version, '\0', sizeof(vrq->version)) == NULL)
		goto einval;

	switch (vrq->op) {
	case BSDFILESYSTEM_OP_SNAPSHOT: {
		struct bsdfilesystem_version_reply vrp;

		memset(&vrp, 0, sizeof(vrp));
		if (vrq->version[0] != '\0' || vrq->cursor != 0)
			vrp.status = EINVAL;
		else if ((cfd = open_own_claim(st, conn, vrq->lifetime, vrq->scope,
		    vrq->group, vrq->dataset, ZH_SNAPSHOT | ZH_PROPS_READ,
		    ZHF_SUBTREE)) == -1)
			vrp.status = errno;
		else {
			/*
			 * Bound the snapshots one claim may hold.  refquota caps
			 * only the claim's LIVE referenced data, not the space its
			 * snapshots pin, and there is no per-snapshot destroy verb,
			 * so an unbounded caller could otherwise retain unbounded
			 * snapshot space (defeating "no single claim fills the
			 * pool").  Each snapshot's unique data is bounded by
			 * refquota, so capping the COUNT bounds total snapshot
			 * space.  A count failure is best-effort (allow).
			 */
			if (bsdfilesystem_count_snapshots(cfd) >=
			    BSDFILESYSTEM_MAX_SNAPSHOTS) {
				vrp.status = EDQUOT;
				(void)close(cfd);
			} else {
				gen_version_id(vrp.version, sizeof(vrp.version));
				if (tzfs_snapshot(cfd, vrp.version) == -1) {
					vrp.status = errno;
					vrp.version[0] = '\0';
				}
				(void)close(cfd);
			}
			syslog(LOG_INFO, "SNAPSHOT %s -> %s", vrq->dataset,
			    vrp.status == 0 ? vrp.version : strerror(vrp.status));
		}
		memset(&out, 0, sizeof(out));
		out.size = sizeof(out);
		out.data = &vrp;
		out.length = sizeof(vrp);
		(void)channel_send_reply(m, &out);
		channel_message_free(m);
		return;
	}
	case BSDFILESYSTEM_OP_LIST_VERSIONS: {
		struct bsdfilesystem_versions_reply vrp;

		memset(&vrp, 0, sizeof(vrp));
		if (vrq->version[0] != '\0')
			vrp.status = EINVAL;
		else if ((cfd = open_own_claim(st, conn, vrq->lifetime, vrq->scope,
		    vrq->group, vrq->dataset, ZH_PROPS_READ, ZHF_SUBTREE)) == -1)
			vrp.status = errno;
		else {
			void *buf;
			char **names;
			size_t len, nnames, idx;

			if (tzfs_list_snapshots(cfd, &buf, &len) == -1)
				vrp.status = errno;
			else if (bsdfilesystem_nvl_names(buf, len, &names,
			    &nnames) == -1) {
				vrp.status = errno;
				free(buf);
			} else {
				free(buf);
				/* Names are "pool/.../claim@version"; page the
				 * bare version ids after the '@'. */
				for (idx = vrq->cursor; idx < nnames &&
				    vrp.count < BSDFILESYSTEM_VERSIONS_MAX; idx++) {
					const char *at = strchr(names[idx], '@');

					if (at == NULL || at[1] == '\0')
						continue;
					(void)strlcpy(vrp.versions[vrp.count],
					    at + 1, BSDFILESYSTEM_NAME_MAX);
					vrp.count++;
				}
				if (idx < nnames)
					vrp.next_cursor = (uint32_t)idx;
				bsdfilesystem_nvl_names_free(names, nnames);
			}
			(void)close(cfd);
			syslog(LOG_INFO, "LIST_VERSIONS %s -> %s", vrq->dataset,
			    vrp.status == 0 ? "ok" : strerror(vrp.status));
		}
		memset(&out, 0, sizeof(out));
		out.size = sizeof(out);
		out.data = &vrp;
		out.length = sizeof(vrp);
		(void)channel_send_reply(m, &out);
		channel_message_free(m);
		return;
	}
	case BSDFILESYSTEM_OP_ROLLBACK: {
		struct bsdfilesystem_reply rp;

		memset(&rp, 0, sizeof(rp));
		if (!valid_version(vrq->version, sizeof(vrq->version)) ||
		    vrq->cursor != 0)
			rp.status = EINVAL;
		else if ((cfd = open_own_claim(st, conn, vrq->lifetime, vrq->scope,
		    vrq->group, vrq->dataset,
		    ZH_ROLLBACK | ZH_SNAP_DESTROY, ZHF_SUBTREE)) == -1)
			rp.status = errno;
		else {
			if (tzfs_rollback(cfd, vrq->version) == -1)
				rp.status = errno;
			else
				syslog(LOG_INFO, "ROLLBACK %s -> %s",
				    vrq->dataset, vrq->version);
			(void)close(cfd);
		}
		memset(&out, 0, sizeof(out));
		out.size = sizeof(out);
		out.data = &rp;
		out.length = sizeof(rp);
		(void)channel_send_reply(m, &out);
		channel_message_free(m);
		return;
	}
	case BSDFILESYSTEM_OP_OPEN_VERSION: {
		/*
		 * Non-destructive time-travel: clone the snapshot into an
		 * ephemeral lease dataset, mount it read-only, and deliver the
		 * directory fd.  The clone lives under the caller's lease
		 * namespace and is reaped with the lease at the next boot; the
		 * connection anchors the mount for its lifetime.
		 */
		static uint32_t clone_ctr;
		struct bsdfilesystem_reply rp;
		char lns[BSDFILESYSTEM_MAXPATH], clonm[BSDFILESYSTEM_NAME_MAX];
		char full[BSDFILESYSTEM_MAXPATH];
		int lns_fd = -1, clone_fd = -1, dfd = -1;
		bool cloned = false;

		memset(&rp, 0, sizeof(rp));
		if (!valid_version(vrq->version, sizeof(vrq->version)) ||
		    vrq->cursor != 0) {
			rp.status = EINVAL;
			goto ov_reply;
		}
		if (st->lease_fd == -1) {
			rp.status = ENXIO;	/* no session: BEGIN_SESSION first */
			goto ov_reply;
		}
		cfd = open_own_claim(st, conn, vrq->lifetime, vrq->scope,
		    vrq->group, vrq->dataset, ZH_CLONE_SRC | ZH_PROPS_READ,
		    ZHF_SUBTREE);
		if (cfd == -1) {
			rp.status = errno;
			goto ov_reply;
		}
		if (!derive_ns(conn->client, lns, sizeof(lns))) {
			rp.status = EINVAL;
			(void)close(cfd);
			goto ov_reply;
		}
		lns_fd = bsdfilesystem_ensure_path(st->lease_fd, lns, ZH_ALL_RIGHTS);
		if (lns_fd == -1) {
			rp.status = errno;
			(void)close(cfd);
			goto ov_reply;
		}
		(void)snprintf(clonm, sizeof(clonm), "ver-%x-%x",
		    (unsigned)getpid(), clone_ctr++);
		if (tzfs_clone(lns_fd, cfd, vrq->version, clonm) == -1)
			rp.status = errno;
		else
			cloned = true;
		(void)close(cfd);
		if (rp.status == 0) {
			clone_fd = tzfs_openat(lns_fd, clonm,
			    ZH_MOUNT | ZH_PROPS_READ, ZHF_SUBTREE);
			if (clone_fd == -1)
				rp.status = errno;
		}
		if (rp.status == 0) {
			dfd = tzfs_mount(clone_fd, true);
			if (dfd == -1 || bsdfilesystem_limit_readonly_dir(dfd) == -1) {
				rp.status = errno;
				if (dfd != -1) {
					(void)close(dfd);
					(void)tzfs_unmount(clone_fd);
					dfd = -1;
				}
				(void)close(clone_fd);
				clone_fd = -1;
			}
		}
		if (rp.status == 0) {
			/* Anchor the mount on the connection (like a claim). */
			(void)snprintf(full, sizeof(full), "%s/%s/%s/%s",
			    st->cfg.ephemeral, st->lease_name, lns, clonm);
			/* Ephemeral: destroyed when the connection closes. */
			if (conn_anchor_add(conn, full, clone_fd, true) == -1) {
				rp.status = errno;
				(void)close(dfd);
				dfd = -1;
				(void)tzfs_unmount(clone_fd);
				(void)close(clone_fd);
				clone_fd = -1;
			}
		}
		/*
		 * On any failure AFTER the clone was created, it is an orphan in
		 * the lease namespace -- nothing reaps it before the session is
		 * reclaimed -- so destroy it here.  (lns_fd is still open.)
		 */
		if (rp.status != 0 && cloned)
			(void)bsdfilesystem_destroy_tree(lns_fd, clonm);
		(void)close(lns_fd);
		syslog(LOG_INFO, "OPEN_VERSION %s@%s -> %s", vrq->dataset,
		    vrq->version, rp.status == 0 ? "granted (ro)" :
		    strerror(rp.status));
ov_reply:
		memset(&out, 0, sizeof(out));
		out.size = sizeof(out);
		out.data = &rp;
		out.length = sizeof(rp);
		if (rp.status == 0 && dfd != -1) {
			/*
			 * Fail CLOSED if the delivered version fd cannot be made
			 * non-re-delegable: a read-only view must not leak as a
			 * re-sendable descriptor.  The anchored clone is left in
			 * place (reaped with the lease); only this delivery fails.
			 */
			if (service_harden_fd(dfd, SERVICE_HARDEN_XFER_ONCE |
			    SERVICE_HARDEN_CLOFORK_ONCE) == -1) {
				rp.status = EPERM;
				out.length = sizeof(rp);
			} else {
				out.fds = &dfd;
				out.nfds = 1;
			}
		}
		(void)channel_send_reply(m, &out);
		if (dfd != -1)
			(void)close(dfd);
		channel_message_free(m);
		return;
	}
	case BSDFILESYSTEM_OP_TXN_BEGIN: {
		/*
		 * Snapshot the claim and clone it read-write as a sibling in the
		 * caller's own namespace; the caller edits the staging clone and
		 * later COMMITs (atomic swap) or ABORTs it.
		 */
		struct bsdfilesystem_version_reply vrp;
		char ns[BSDFILESYSTEM_MAXPATH], full[BSDFILESYSTEM_MAXPATH];
		int ns_fd = -1, claim_fd = -1, clone_fd = -1, dfd = -1;

		memset(&vrp, 0, sizeof(vrp));
		if (vrq->version[0] != '\0' || vrq->cursor != 0) {
			vrp.status = EINVAL;
			goto tb_reply;
		}
		if (!valid_dataset(vrq->dataset)) {
			vrp.status = EINVAL;
			goto tb_reply;
		}
		ns_fd = open_own_ns(st, conn, vrq->lifetime, vrq->scope,
		    vrq->group, ns, sizeof(ns));
		if (ns_fd == -1) {
			vrp.status = errno;
			goto tb_reply;
		}
		/*
		 * Bound the datasets one namespace may hold: a staging clone is a
		 * persistent-tree sibling of the caller's claims and survives a
		 * disconnect until COMMIT/ABORT or the idle reap, so without this
		 * cap a caller could TXN_BEGIN in a loop and fill the pool with
		 * abandoned clones (and starve its own legitimate claims).  grant()
		 * caps new claims the same way; the two share the NS_MAX_CLAIMS
		 * budget (tb_reply closes ns_fd).
		 */
		if (bsdfilesystem_count_children(ns_fd) >=
		    BSDFILESYSTEM_NS_MAX_CLAIMS) {
			vrp.status = EDQUOT;
			goto tb_reply;
		}
		claim_fd = tzfs_openat(ns_fd, vrq->dataset,
		    ZH_SNAPSHOT | ZH_CLONE_SRC, ZHF_SUBTREE);
		if (claim_fd == -1) {
			vrp.status = errno;
			goto tb_reply;
		}
		gen_version_id(vrp.version, sizeof(vrp.version));
		if (tzfs_snapshot(claim_fd, vrp.version) == -1) {
			vrp.status = errno;
			(void)close(claim_fd);
			vrp.version[0] = '\0';
			goto tb_reply;	/* nothing created */
		}
#ifdef BSDFILESYSTEM_FAULT_INJECTION
		/*
		 * Test-only fault point (compiled out of production): the snapshot
		 * has been taken; simulate the clone failing (as ENOSPC would) to
		 * exercise the tb_cleanup snapshot-drop path deterministically.
		 */
		if (getenv("BSDFILESYSTEM_FAULT_TXN_CLONE") != NULL) {
			(void)close(claim_fd);
			vrp.status = ENOSPC;
			errno = ENOSPC;
			goto tb_cleanup;
		}
#endif
		if (tzfs_clone(ns_fd, claim_fd, vrp.version, vrp.version) == -1) {
			/*
			 * The snapshot was taken but the clone failed (e.g. ENOSPC
			 * on the clone allocation): with no clone the boot staging
			 * sweep would never find the snapshot, and the caller got no
			 * id back so it cannot ABORT it.  Route through tb_cleanup,
			 * which destroys the (absent) clone and drops the snapshot.
			 */
			vrp.status = errno;
			(void)close(claim_fd);
			goto tb_cleanup;
		}
		(void)close(claim_fd);
		clone_fd = tzfs_openat(ns_fd, vrp.version,
		    ZH_MOUNT | ZH_ALL_RIGHTS, ZHF_SUBTREE);
		if (clone_fd == -1) {
			vrp.status = errno;
			goto tb_cleanup;	/* clone made, must be reaped */
		}
		/* Record the base claim so TXN_COMMIT can bind to its origin. */
		if (tzfs_set_prop_string(clone_fd, BSDFILESYSTEM_TXN_BASE_PROP,
		    vrq->dataset) == -1) {
			vrp.status = errno;
			(void)close(clone_fd);
			clone_fd = -1;
			goto tb_cleanup;
		}
		dfd = tzfs_mount(clone_fd, false);
		if (dfd == -1 || (conn->uid != 0 &&
		    fchown(dfd, conn->uid, conn->gid) == -1)) {
			vrp.status = errno;
			if (dfd != -1) {
				(void)close(dfd);
				(void)tzfs_unmount(clone_fd);
				dfd = -1;
			}
			(void)close(clone_fd);
			clone_fd = -1;
			goto tb_cleanup;
		}
		(void)snprintf(full, sizeof(full), "%s/%s/%s", st->cfg.persistent,
		    ns, vrp.version);
		/* Not ephemeral: reaped explicitly by TXN_COMMIT/TXN_ABORT. */
		if (conn_anchor_add(conn, full, clone_fd, false) == -1) {
			vrp.status = errno;
			(void)close(dfd);
			dfd = -1;
			(void)tzfs_unmount(clone_fd);
			(void)close(clone_fd);
			clone_fd = -1;
			goto tb_cleanup;
		}
		syslog(LOG_INFO, "TXN_BEGIN %s -> %s", vrq->dataset,
		    vrp.version);
		goto tb_reply;
tb_cleanup:
		/*
		 * A post-clone failure: the staging clone + its base snapshot are
		 * created in the PERSISTENT namespace (never reaped automatically)
		 * and the caller got no txn id back, so it cannot ABORT them.
		 * Destroy both here so a repeated failure cannot grow the tree.
		 */
		(void)bsdfilesystem_destroy_tree(ns_fd, vrp.version);
		{
			int c = tzfs_openat(ns_fd, vrq->dataset, ZH_SNAP_DESTROY,
			    ZHF_SUBTREE);

			if (c != -1) {
				(void)tzfs_snap_destroy(c, vrp.version);
				(void)close(c);
			}
		}
		vrp.version[0] = '\0';
tb_reply:
		if (ns_fd != -1)
			(void)close(ns_fd);
		memset(&out, 0, sizeof(out));
		out.size = sizeof(out);
		out.data = &vrp;
		out.length = sizeof(vrp);
		if (vrp.status == 0 && dfd != -1) {
			(void)service_harden_fd(dfd, SERVICE_HARDEN_XFER_ONCE |
			    SERVICE_HARDEN_CLOFORK_ONCE);
			out.fds = &dfd;
			out.nfds = 1;
		}
		(void)channel_send_reply(m, &out);
		if (dfd != -1)
			(void)close(dfd);
		channel_message_free(m);
		return;
	}
	case BSDFILESYSTEM_OP_TXN_COMMIT: {
		/*
		 * Atomic swap: promote the staging clone, then rename it over the
		 * claim (claim -> del-<id>, txn -> claim, destroy del-<id>).  Fails
		 * EBUSY if the claim is still mounted/held elsewhere.
		 */
		struct bsdfilesystem_reply rp;
		char ns[BSDFILESYSTEM_MAXPATH], del[BSDFILESYSTEM_NAME_MAX], full[BSDFILESYSTEM_MAXPATH];
		int ns_fd, clone_fd;

		memset(&rp, 0, sizeof(rp));
		if (!valid_version(vrq->version, sizeof(vrq->version)) ||
		    !valid_dataset(vrq->dataset) || vrq->cursor != 0) {
			rp.status = EINVAL;
			goto tc_reply;
		}
		ns_fd = open_own_ns(st, conn, vrq->lifetime, vrq->scope,
		    vrq->group, ns, sizeof(ns));
		if (ns_fd == -1) {
			rp.status = errno;
			goto tc_reply;
		}
		clone_fd = tzfs_openat(ns_fd, vrq->version, ZH_ALL_RIGHTS,
		    ZHF_SUBTREE);
		if (clone_fd == -1)
			rp.status = errno;
		else {
			char base[BSDFILESYSTEM_NAME_MAX];
			uint64_t iv = 0;
			int is_str = 0;
			uint32_t src = 0;

			/*
			 * Bind the txn to its ORIGIN claim BEFORE any side effect:
			 * the base-claim name TXN_BEGIN stamped on the staging clone
			 * must equal the dataset being committed.  Without this a
			 * caller could TXN_BEGIN on claim A (id V) and then
			 * TXN_COMMIT{dataset=B, version=V} to swap A's clone over a
			 * DIFFERENT claim B in the same container -- destroying B.
			 * The check must precede the anchor drops below so a REJECTED
			 * commit leaves both the target claim and the clone mounted
			 * and otherwise untouched (no observable side effect).
			 */
			base[0] = '\0';
			if (tzfs_get_one_prop(clone_fd, BSDFILESYSTEM_TXN_BASE_PROP,
			    base, sizeof(base), &iv, &is_str, &src) != 0 ||
			    !is_str || strcmp(base, vrq->dataset) != 0) {
				syslog(LOG_WARNING, "TXN_COMMIT rejected: txn %s "
				    "was begun on claim '%s', not '%s'",
				    vrq->version, is_str ? base : "?",
				    vrq->dataset);
				rp.status = EINVAL;	/* not this claim's txn */
				goto tc_close;
			}
			/*
			 * Origin verified -- commit is going to proceed.  Clear the
			 * txn stamp on the clone NOW, before the anchor drop below
			 * unmounts it.  The idle staging reap relies on "a live txn
			 * clone is mounted (so its destroy fails EBUSY)"; that guard
			 * does NOT hold in the swap window, where the clone is
			 * unmounted but not yet renamed.  An unmounted, aged, still-
			 * STAMPED v<hex> clone in that window would be a valid
			 * idle-reap target -- the reaper could destroy a live commit's
			 * clone out from under it (promote then fails ENXIO and the
			 * committed work is lost).  With the stamp gone first, the
			 * idle reap (which requires the stamp) skips it; and if the
			 * worker crashes before the swap completes, the boot sweep
			 * still reaps the leftover by its reserved v<hex> NAME alone
			 * (valid_dataset forbids a real claim that shape).
			 */
			(void)tzfs_set_prop_string(clone_fd,
			    BSDFILESYSTEM_TXN_BASE_PROP, "");
			/*
			 * Neither the staging clone NOR the base claim may be mounted
			 * for the rename swap below (a mounted dataset cannot be
			 * renamed -- EBUSY).  Drop this connection's anchor on BOTH:
			 * the clone
			 * (always mounted by TXN_BEGIN) and the base (mounted by
			 * REQUEST if the caller opened it; a plain RELEASE by name may
			 * not have run, or a ROLLBACK re-established the mount).  A
			 * base still held by ANOTHER connection correctly leaves the
			 * swap to fail EBUSY.
			 */
			(void)snprintf(full, sizeof(full), "%s/%s/%s",
			    st->cfg.persistent, ns, vrq->version);
			conn_anchor_drop(conn, full);
			(void)snprintf(full, sizeof(full), "%s/%s/%s",
			    st->cfg.persistent, ns, vrq->dataset);
			conn_anchor_drop(conn, full);
			(void)snprintf(del, sizeof(del),
			    BSDFILESYSTEM_STAGING_PREFIX "%s", vrq->version);
			if (tzfs_promote(clone_fd) == -1)
				rp.status = errno;	/* nothing changed yet */
			else if (tzfs_rename(ns_fd, vrq->dataset, del) == -1) {
				int pc;

				rp.status = errno;
				/*
				 * The promote already inverted the origin: the
				 * base snapshot <claim>@<version> migrated onto the
				 * staging clone and the live claim became a clone of
				 * it.  Leaving it so would strand the transaction --
				 * the migrated snapshot is pinned by the live claim,
				 * so TXN_ABORT and the boot staging sweep both fail
				 * EEXIST on the clone forever.  Undo the promote by
				 * re-promoting the claim, restoring the original
				 * relationship so the staging clone stays abortable
				 * and reapable.
				 */
				pc = tzfs_openat(ns_fd, vrq->dataset,
				    ZH_ALL_RIGHTS, ZHF_SUBTREE);
				if (pc == -1 || tzfs_promote(pc) == -1)
					syslog(LOG_ERR, "TXN_COMMIT %s: rename "
					    "failed and promote-undo failed; "
					    "staging clone %s is stranded (%m)",
					    vrq->dataset, vrq->version);
				if (pc != -1)
					(void)close(pc);
			} else if (tzfs_rename(ns_fd, vrq->version,
			    vrq->dataset) == -1) {
				int pc;

				rp.status = errno;
				/*
				 * Undo the first rename to restore the claim, THEN
				 * undo the promote (re-promote the restored claim).
				 * Both are needed and in this order: the promote
				 * left the claim a clone of <version>@<version>, so
				 * without the re-promote the staging clone stays the
				 * pinned origin and TXN_ABORT / the sweep hit EEXIST
				 * on it forever -- the same asymmetry the first-rename
				 * failure branch above avoids.
				 */
				if (tzfs_rename(ns_fd, del, vrq->dataset) == -1)
					syslog(LOG_ERR, "TXN_COMMIT %s: swap "
					    "failed and undo failed; original "
					    "claim is stranded as %s (%m)",
					    vrq->dataset, del);
				else {
					pc = tzfs_openat(ns_fd, vrq->dataset,
					    ZH_ALL_RIGHTS, ZHF_SUBTREE);
					if (pc == -1 || tzfs_promote(pc) == -1)
						syslog(LOG_ERR, "TXN_COMMIT %s: "
						    "swap failed and promote-undo "
						    "failed; staging clone %s is "
						    "stranded (%m)", vrq->dataset,
						    vrq->version);
					if (pc != -1)
						(void)close(pc);
				}
			} else {
				int nfd;

				/*
				 * `zfs promote` migrated the origin snapshot
				 * (<dataset>@<version>) onto the promoted clone,
				 * which is now the live claim, and made the OLD base
				 * (now del-<version>) a clone of that snapshot.
				 * Destroy del- FIRST -- it depends on the snapshot,
				 * so destroying the snapshot before it fails "clone
				 * depends on it" and leaks the snapshot.  Then drop
				 * the now-unreferenced snapshot, which otherwise
				 * accumulates one per commit (pinning space and
				 * surfacing in LIST_VERSIONS as a version the caller
				 * never took).  Both best-effort.
				 */
				(void)bsdfilesystem_destroy_tree(ns_fd, del);
				nfd = tzfs_openat(ns_fd, vrq->dataset,
				    ZH_SNAP_DESTROY, ZHF_SUBTREE);
				if (nfd != -1) {
					(void)tzfs_snap_destroy(nfd,
					    vrq->version);
					(void)close(nfd);
				}
				/* The txnbase stamp was already cleared before
				 * the swap (see above), so the now-live claim
				 * carries no transaction marker. */
				syslog(LOG_INFO, "TXN_COMMIT %s <- %s",
				    vrq->dataset, vrq->version);
			}
tc_close:
			(void)close(clone_fd);
		}
		(void)close(ns_fd);
tc_reply:
		memset(&out, 0, sizeof(out));
		out.size = sizeof(out);
		out.data = &rp;
		out.length = sizeof(rp);
		(void)channel_send_reply(m, &out);
		channel_message_free(m);
		return;
	}
	case BSDFILESYSTEM_OP_TXN_ABORT: {
		/* Discard the staging clone and its base snapshot. */
		struct bsdfilesystem_reply rp;
		char ns[BSDFILESYSTEM_MAXPATH], full[BSDFILESYSTEM_MAXPATH];
		int ns_fd, claim_fd;

		memset(&rp, 0, sizeof(rp));
		if (!valid_version(vrq->version, sizeof(vrq->version)) ||
		    !valid_dataset(vrq->dataset) || vrq->cursor != 0) {
			rp.status = EINVAL;
			goto ta_reply;
		}
		ns_fd = open_own_ns(st, conn, vrq->lifetime, vrq->scope,
		    vrq->group, ns, sizeof(ns));
		if (ns_fd == -1) {
			rp.status = errno;
			goto ta_reply;
		}
		(void)snprintf(full, sizeof(full), "%s/%s/%s", st->cfg.persistent,
		    ns, vrq->version);
		conn_anchor_drop(conn, full);	/* unmount the clone */
		if (bsdfilesystem_destroy_tree(ns_fd, vrq->version) == -1 &&
		    errno != ENOENT)
			rp.status = errno;
		else if ((claim_fd = tzfs_openat(ns_fd, vrq->dataset,
		    ZH_SNAP_DESTROY, ZHF_SUBTREE)) != -1) {
			/* Best-effort: drop the base snapshot too. */
			(void)tzfs_snap_destroy(claim_fd, vrq->version);
			(void)close(claim_fd);
		}
		if (rp.status == 0)
			syslog(LOG_INFO, "TXN_ABORT %s (%s)", vrq->dataset,
			    vrq->version);
		(void)close(ns_fd);
ta_reply:
		memset(&out, 0, sizeof(out));
		out.size = sizeof(out);
		out.data = &rp;
		out.length = sizeof(rp);
		(void)channel_send_reply(m, &out);
		channel_message_free(m);
		return;
	}
	default:
		break;
	}
einval:
	{
		struct bsdfilesystem_reply rp;

		memset(&rp, 0, sizeof(rp));
		rp.status = EINVAL;
		memset(&out, 0, sizeof(out));
		out.size = sizeof(out);
		out.data = &rp;
		out.length = sizeof(rp);
		(void)channel_send_reply(m, &out);
		channel_message_free(m);
	}
}

/*
 * Per-client channel request handler.  arg is this worker's bsdfilesystem_state (its
 * own copy of the retained handles, plus per-connection lease state).  The
 * reply is a fixed bsdfilesystem_reply; a granted handle rides back as its single fd.
 */
static void
tzfs_request(struct channel *ch __unused, struct channel_message *m, void *arg)
{
	struct tzfs_conn *conn = arg;
	struct bsdfilesystem_state *st = conn->st;
	const struct bsdfilesystem_request *rq;
	struct bsdfilesystem_reply rp;
	struct channel_outgoing out;
	int handle = -1;

	memset(&rp, 0, sizeof(rp));

	BSDFILESYSTEM_PROBE_MSG((uint64_t)channel_message_length(m),
	    channel_message_fd_count(m));

	if (channel_message_fd_count(m) != 0) {
		rp.status = EPROTO;
		goto reply;
	}

	/*
	 * Stamp the sender's kernel credentials before ANY dispatch: they are the
	 * only ownership a store may take, and the length-based dispatches below
	 * (notably TXN_BEGIN, which fchowns its staging clone to conn->uid) run
	 * before the storage-request path, so stamping there would leave them a
	 * stale/zero uid.
	 */
	{
		const struct channel_sender *sender = channel_message_sender(m);

		conn->uid = sender != NULL ? sender->uid : 0;
		conn->gid = sender != NULL ? sender->gid : 0;
	}

	/*
	 * BSDFILESYSTEM_OP_OPEN carries its own, larger request struct; dispatch it by
	 * its distinct length before the storage-shaped requests.
	 */
	if (channel_message_length(m) == sizeof(struct bsdfilesystem_open_request)) {
		const struct bsdfilesystem_open_request *orq = channel_message_data(m);

		if (orq->op == BSDFILESYSTEM_OP_OPEN) {
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
	 * BSDFILESYSTEM_OP_LIST carries its own small request struct and a distinctly
	 * sized, fd-free reply (the caller's own claim page).  Dispatch it by its
	 * length here — like OPEN — and send its dedicated reply inline, before the
	 * storage-shaped request path.
	 */
	if (channel_message_length(m) == sizeof(struct bsdfilesystem_list_request)) {
		const struct bsdfilesystem_list_request *lrq = channel_message_data(m);

		if (lrq->op == BSDFILESYSTEM_OP_LIST) {
			struct bsdfilesystem_list_reply lrp;
			struct channel_outgoing lout;

			memset(&lrp, 0, sizeof(lrp));
			if (grant_list(st, conn->container,
			    (const char (*)[64])conn->groups, lrq, &lrp) == -1) {
				lrp.status = errno;
				lrp.count = 0;
				lrp.next_cursor = 0;
				syslog(LOG_INFO, "LIST scope=%u cursor=%u -> %s",
				    lrq->scope, lrq->cursor, strerror(lrp.status));
			} else {
				syslog(LOG_INFO, "LIST scope=%u cursor=%u -> %u "
				    "claim(s)%s", lrq->scope, lrq->cursor, lrp.count,
				    lrp.next_cursor != 0 ? " (more)" : "");
			}
			BSDFILESYSTEM_PROBE_REPLY(0, lrp.status, -1);
			memset(&lout, 0, sizeof(lout));
			lout.size = sizeof(lout);
			lout.data = &lrp;
			lout.length = sizeof(lrp);
			(void)channel_send_reply(m, &lout);
			channel_message_free(m);
			return;
		}
	}

	/*
	 * The snapshot/time-travel ops carry their own bsdfilesystem_version_request
	 * and distinctly-sized replies; dispatch them by length before the
	 * storage-shaped request path.  bsdfilesystem_serve_version() sends its reply
	 * inline and does not return here.
	 */
	if (channel_message_length(m) == sizeof(struct bsdfilesystem_version_request)) {
		const struct bsdfilesystem_version_request *vrq = channel_message_data(m);

		if (vrq->op == BSDFILESYSTEM_OP_SNAPSHOT ||
		    vrq->op == BSDFILESYSTEM_OP_LIST_VERSIONS ||
		    vrq->op == BSDFILESYSTEM_OP_ROLLBACK ||
		    vrq->op == BSDFILESYSTEM_OP_OPEN_VERSION ||
		    vrq->op == BSDFILESYSTEM_OP_TXN_BEGIN ||
		    vrq->op == BSDFILESYSTEM_OP_TXN_COMMIT ||
		    vrq->op == BSDFILESYSTEM_OP_TXN_ABORT) {
			bsdfilesystem_serve_version(st, conn, vrq, m);
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

		BSDFILESYSTEM_PROBE_VALIDATE(rq->op, rq->deliver, rq->rights,
		    rq->lifetime, ok);
		if (!ok) {
			rp.status = EINVAL;
			goto reply;
		}
	}

	switch (rq->op) {
	case BSDFILESYSTEM_OP_REQUEST: {
		int keep_fd = -1;

		handle = grant(st, conn, rq, rp.dataset, sizeof(rp.dataset),
		    &keep_fd);
		BSDFILESYSTEM_PROBE_GRANT(rq->op, rq->deliver, handle,
		    handle == -1 ? errno : 0);
		/*
		 * A mounted grant hands back the leaf handle anchoring the
		 * delivered mount; retain it (one anchor per claim) so the store
		 * stays mounted while the client holds its lease.
		 */
		if (keep_fd != -1 &&
		    conn_anchor_add(conn, rp.dataset, keep_fd, false) == -1) {
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
			    rq->deliver == BSDFILESYSTEM_DELIVER_MOUNTED ? " (mounted)" :
			    rq->deliver == BSDFILESYSTEM_DELIVER_MOUNTED_RO ?
			    " (mounted, read-only view)" : "");
		}
		break;
	}
	case BSDFILESYSTEM_OP_RELEASE: {
		/* Destroy the caller's own claim under its lease namespace. */
		char ns[BSDFILESYSTEM_NAME_MAX];
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
			char full[BSDFILESYSTEM_MAXPATH];

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
		if (bsdfilesystem_destroy_tree(ns_fd, rq->dataset) == -1 &&
		    errno != ENOENT)
			rp.status = errno;
		else
			syslog(LOG_INFO, "RELEASE %s/%s -> ok", ns, rq->dataset);
		(void)close(ns_fd);
		break;
	}
	case BSDFILESYSTEM_OP_DESTROY: {
		/*
		 * Reclaim the caller's own persistent/cache claim.  The claim is
		 * resolved under the CALLER's per-bundle container (from its own
		 * unforgeable identity), so a caller can only ever name — and destroy
		 * — its own storage.  Unlike RELEASE, an absent claim replies ENOENT
		 * rather than idempotent success, so a caller can distinguish a real
		 * reclaim.
		 */
		char ns[BSDFILESYSTEM_MAXPATH];
		int ns_fd, probe;

		if (rq->lifetime > BSDFILESYSTEM_CACHE || !valid_dataset(rq->dataset) ||
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
		 * the idempotent success bsdfilesystem_destroy_tree() would return.
		 */
		probe = tzfs_openat(ns_fd, rq->dataset, ZH_PROPS_READ, 0);
		if (probe == -1) {
			rp.status = errno;
			(void)close(ns_fd);
			break;
		}
		(void)close(probe);
		{
			char full[BSDFILESYSTEM_MAXPATH];

			/* Our own anchor would make the destroy EBUSY (see RELEASE). */
			(void)snprintf(full, sizeof(full), "%s/%s/%s",
			    st->cfg.persistent, ns, rq->dataset);
			conn_anchor_drop(conn, full);
		}
		if (bsdfilesystem_destroy_tree(ns_fd, rq->dataset) == -1)
			rp.status = errno;
		else
			syslog(LOG_INFO, "DESTROY %s/%s -> ok", ns, rq->dataset);
		(void)close(ns_fd);
		break;
	}
	case BSDFILESYSTEM_OP_UNMOUNT: {
		/*
		 * Drop THIS connection's mount anchor on the caller's own claim
		 * without destroying it, so the caller can then TXN_COMMIT or
		 * ROLLBACK it (a mounted dataset cannot be renamed/rolled back --
		 * EBUSY).  Resolved under the caller's unforgeable container exactly
		 * as DESTROY does.  Idempotent: dropping a claim not anchored by
		 * this connection is success (the claim, and any other holder's
		 * anchor, is untouched).  The claim's data is never modified.
		 */
		char ns[BSDFILESYSTEM_MAXPATH], full[BSDFILESYSTEM_MAXPATH];

		if (rq->lifetime > BSDFILESYSTEM_CACHE ||
		    !valid_dataset(rq->dataset) ||
		    !scoped_ns(conn->container, (const char (*)[64])conn->groups,
		    rq->scope, rq->group, rq->lifetime, ns, sizeof(ns))) {
			rp.status = EINVAL;
			break;
		}
		(void)snprintf(full, sizeof(full), "%s/%s/%s",
		    st->cfg.persistent, ns, rq->dataset);
		conn_anchor_drop(conn, full);
		syslog(LOG_INFO, "UNMOUNT %s/%s -> ok", ns, rq->dataset);
		break;
	}
	case BSDFILESYSTEM_OP_STAT_CLAIM: {
		/*
		 * One claim's live usage, resolved under the CALLER's own container
		 * (unforgeable identity) exactly as DESTROY does.  Data-only reply
		 * (bsdfilesystem_stat_reply), so it is sent inline here rather than
		 * through the shared bsdfilesystem_reply path below.
		 */
		char ns[BSDFILESYSTEM_MAXPATH];
		struct bsdfilesystem_stat_reply srp;
		struct channel_outgoing sout;
		int ns_fd, cfd;

		memset(&srp, 0, sizeof(srp));
		if (!valid_dataset(rq->dataset) ||
		    !scoped_ns(conn->container, (const char (*)[64])conn->groups,
		    rq->scope, rq->group, rq->lifetime, ns, sizeof(ns)))
			srp.status = EINVAL;
		else if (st->persistent_fd == -1)
			srp.status = ENXIO;
		else if ((ns_fd = open_ns_path(st->persistent_fd, ns,
		    ZH_PROPS_READ, ZHF_SUBTREE)) == -1)
			srp.status = errno;
		else {
			cfd = tzfs_openat(ns_fd, rq->dataset, ZH_PROPS_READ, 0);
			if (cfd == -1)
				srp.status = errno;	/* ENOENT if absent */
			else {
				struct zfd_stat_args stt;
				uint64_t refquota = 0;
				int is_string = 0;
				uint32_t src = 0;

				memset(&stt, 0, sizeof(stt));
				if (tzfs_get_one_prop(cfd, "refquota", NULL, 0,
				    &refquota, &is_string, &src) == 0 && !is_string)
					srp.refquota = refquota;
				if (tzfs_stat(cfd, &stt) == 0) {
					srp.used = stt.zs_referenced;
					/*
					 * Report THIS claim's own headroom.  For an
					 * unquota'd dataset ZFS's `available` is the
					 * whole pool's free space -- disclosing global
					 * capacity to a tenant -- so when a refquota is
					 * set, cap available to the quota headroom
					 * (which is also the accurate limit on what the
					 * claim can still write).
					 */
					srp.available = stt.zs_available;
					if (srp.refquota != 0)
						srp.available =
						    srp.refquota > srp.used ?
						    srp.refquota - srp.used : 0;
				}
				(void)close(cfd);
			}
			(void)close(ns_fd);
		}
		syslog(LOG_INFO, "STAT_CLAIM %s -> %s", rq->dataset,
		    srp.status == 0 ? "ok" : strerror(srp.status));
		BSDFILESYSTEM_PROBE_REPLY(0, srp.status, -1);
		memset(&sout, 0, sizeof(sout));
		sout.size = sizeof(sout);
		sout.data = &srp;
		sout.length = sizeof(srp);
		(void)channel_send_reply(m, &sout);
		channel_message_free(m);
		return;
	}
	case BSDFILESYSTEM_OP_SET_QUOTA: {
		/*
		 * Raise/lower one of the caller's own claims' refquota, resolved
		 * under the caller's container.  Same floor as REQUEST; quota 0
		 * clears the ceiling.  Status-only reply (shared path below).
		 */
		char ns[BSDFILESYSTEM_MAXPATH];
		int ns_fd, cfd;

		if (!valid_dataset(rq->dataset) ||
		    (rq->quota != 0 && rq->quota < BSDFILESYSTEM_MIN_REFQUOTA) ||
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
			rp.status = errno;
			break;
		}
		cfd = tzfs_openat(ns_fd, rq->dataset,
		    ZH_PROPS_READ | ZH_PROPS_WRITE, 0);
		if (cfd == -1)
			rp.status = errno;	/* ENOENT if the claim is absent */
		else {
			if (tzfs_set_prop_uint64(cfd, "refquota", rq->quota) == -1)
				rp.status = errno;
			else
				syslog(LOG_INFO, "SET_QUOTA %s -> %ju bytes",
				    rq->dataset, (uintmax_t)rq->quota);
			(void)close(cfd);
		}
		(void)close(ns_fd);
		break;
	}
	case BSDFILESYSTEM_OP_PING:
		rp.status = 0;
		break;
	case BSDFILESYSTEM_OP_BEGIN_SESSION:
		if (bsdfilesystem_session_begin(st, rq->session) == -1)
			rp.status = errno;
		break;
	default:
		rp.status = EOPNOTSUPP;
		break;
	}

reply:
	BSDFILESYSTEM_PROBE_REPLY(0, rp.status, handle);
	memset(&out, 0, sizeof(out));
	out.size = sizeof(out);
	out.data = &rp;
	out.length = sizeof(rp);
	if (handle != -1 && rp.status == 0) {
		/*
		 * Harden every delivered descriptor (dataset handle, mounted store
		 * dirfd, or isolated-open fd) as a single-hop capability: this SCM
		 * send is the one-and-only delegation (CAP_XFER_ONCE -> the client's
		 * copy lands at CAP_XFER_NONE, non-re-delegable), close-on-fork, and
		 * close-on-exec.  Without this a client could re-send its label-scoped
		 * storage/device handle to an unrelated component, bypassing the
		 * per-label/per-container policy the broker exists to enforce (and the
		 * libservice client contract already assumes this limit was applied).
		 */
		(void)service_harden_fd(handle, SERVICE_HARDEN_XFER_ONCE |
		    SERVICE_HARDEN_CLOFORK_ONCE);
		out.fds = &handle;
		out.nfds = 1;
	}
	(void)channel_send_reply(m, &out);
	if (handle != -1)
		(void)close(handle);
	channel_message_free(m);
}

/*
 * Destroy every ephemeral clone this connection anchored (OPEN_VERSION lease
 * clones), then leave the rest to conn_anchors_close.  Without this the clones
 * survive disconnect -- unreapable by name and pinning the base snapshot they
 * were cloned from, which then blocks the claim's ROLLBACK/DESTROY until the
 * whole lease generation is reclaimed at the next session/boot.  Each anchor's
 * full name is <ephemeral>/<lease_name>/<lns>/<clonm>; close the mount handle
 * (unmount) before destroying, since a mounted dataset cannot be destroyed.
 */
static void
conn_reap_ephemeral(struct bsdfilesystem_state *st, struct tzfs_conn *conn)
{
	char prefix[BSDFILESYSTEM_MAXPATH];
	size_t plen, i;

	if (st->lease_fd == -1)
		return;
	if ((size_t)snprintf(prefix, sizeof(prefix), "%s/%s/",
	    st->cfg.ephemeral, st->lease_name) >= sizeof(prefix))
		return;
	plen = strlen(prefix);
	for (i = 0; i < nitems(conn->anchors); i++) {
		const char *rel, *slash;
		char lns[BSDFILESYSTEM_MAXPATH];
		size_t nlen;
		int lns_fd;

		if (conn->anchors[i].fd == -1 || !conn->anchors[i].ephemeral)
			continue;
		if (strncmp(conn->anchors[i].dataset, prefix, plen) != 0)
			continue;
		rel = conn->anchors[i].dataset + plen;	/* <lns>/<clonm> */
		slash = strrchr(rel, '/');
		if (slash == NULL || (nlen = (size_t)(slash - rel)) >= sizeof(lns))
			continue;
		memcpy(lns, rel, nlen);
		lns[nlen] = '\0';
		(void)close(conn->anchors[i].fd);	/* unmount first */
		conn->anchors[i].fd = -1;
		lns_fd = open_ns_path(st->lease_fd, lns, ZH_ALL_RIGHTS,
		    ZHF_SUBTREE);
		if (lns_fd != -1) {
			(void)bsdfilesystem_destroy_tree(lns_fd, slash + 1);
			(void)close(lns_fd);
		}
	}
}

/*
 * Serve one client on its own worker channel until the channel closes.  Runs in
 * a pdfork'd worker with its own copy of st (so its lease state is private).
 */
static int
tzfs_worker(struct bsdfilesystem_state *st, int fd, const char *client,
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
	 * Reap ephemeral clones (OPEN_VERSION) first -- destroy the dataset, not
	 * just unmount it -- then drop any remaining mount anchor: closing the
	 * leaf handle unmounts the delivered store now that the client's
	 * connection is gone.  (Process exit would unmount too; explicit is
	 * clearer and lets a worker that is reused across errors not strand a
	 * mount.)
	 */
	conn_reap_ephemeral(st, &conn);
	conn_anchors_close(&conn);
	return (0);
}

/*
 * Bound concurrent per-client workers so a client churning connections cannot
 * fork-bomb the storage TCB (PID/table exhaustion cascades to every daemon that
 * reads through it).  Workers are pdfork'd (NOT plain fork()) and tracked by
 * process descriptor in a kqueue, so this coexists with the daemon's
 * SIGCHLD=SIG_IGN (which still auto-reaps the boot-time reconcile reaper, a plain
 * fork that this loop never sees): a pdfork worker never raises SIGCHLD and is
 * reaped through its descriptor.  Mirrors the BSDNetwork/BSDCrypto/BSDDevice/BSDVM
 * worker-cap discipline.
 */
#define	BSDFILESYSTEM_MAX_WORKERS	4096

struct fs_worker {
	struct fs_worker	*next;
	int			 pd;	/* process descriptor for the worker */
};

/*
 * Reap an EXITED worker: remove it from the list, drain its zombie through the
 * descriptor, close it, and drop the count.  Used only on the NOTE_EXIT path,
 * where the worker has already exited.
 */
static void
fs_worker_remove(struct fs_worker **head, struct fs_worker *w, size_t *count)
{
	struct fs_worker **cursor;
	int status;

	for (cursor = head; *cursor != NULL && *cursor != w;
	    cursor = &(*cursor)->next)
		;
	if (*cursor == w)
		*cursor = w->next;
	(void)pdwait(w->pd, &status, WEXITED | WNOHANG, NULL, NULL);
	(void)close(w->pd);
	free(w);
	if (*count != 0)
		(*count)--;
}

/*
 * Expose system.Filesystem and dispatch each accepted client on its own pdfork'd
 * worker.  SELF-CONFINES before serving: the privileged bootstrap (kldload zfs,
 * zpool import, opening /dev/zfs and the root-pool handles by name) has already
 * run in main(), so the daemon now cap_enter()s and serves every request from
 * its retained, cap_ioctls-limited handles.  It cannot be BORN in capability mode
 * like the other providers (its bootstrap needs the global namespace and classic
 * privilege, so switchboard launches it ambient), but the SERVING window -- where
 * untrusted client requests are handled -- runs sandboxed: every op is an ioctl
 * on a held TrustedZFS handle (ZFD_OPENAT/MOUNT/CREATE/... , not mount(2)) or an
 * openat(2) beneath the retained root fd, all capsicum-legal.  Returns -1 only on
 * setup failure (never on success).
 */
int
bsdfilesystem_serve(struct bsdfilesystem_state *st)
{
	struct service_identity id;
	struct service_listener *listener;
	struct service_provider *provider;
	int fd;

	/* Cleanup is the container-model reconcile: the forked reaper started at
	 * boot (see bsdfilesystem_start_reaper), before this cap_enter, so it keeps
	 * the ambient path access it needs to read switchboard's live directory. */
	struct fs_worker *workers = NULL, *w;
	size_t nworkers = 0;
	struct kevent event, change;
	int kq;

	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_expose(provider, BSDFILESYSTEM_SERVICE_NAME, &listener) ==
	    -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		return (-1);

	/*
	 * Boot-scoped cleanup, moved here from main() so it runs AFTER
	 * provider-ready (above) -- on-demand waiters on system.Filesystem get
	 * their channel without blocking on this slow cold-start work -- but
	 * BEFORE the accept loop below dispatches any client request, so the
	 * "no connection served yet, so every lease/clone is a prior-boot
	 * orphan" invariant that makes this GC safe still holds.  All three are
	 * non-fatal: a cleanup failure must never stop the provider from serving.
	 *   - reap_leases:  ephemeral leases orphaned by a prior boot.
	 *   - reap_staging: TXN staging clones abandoned by a prior boot.
	 *   - start_reaper: the persistent-namespace reconcile child (kept last,
	 *     as in the original ordering: forked only after the one-shot reaps).
	 */
	if (st->storage_available) {
		if (bsdfilesystem_reap_leases(st) == -1)
			syslog(LOG_WARNING, "reap orphan leases: %m");
		if (bsdfilesystem_reap_staging(st) == -1)
			syslog(LOG_WARNING, "reap abandoned txn staging: %m");
		bsdfilesystem_start_reaper(st);
	}

	kq = kqueuex(KQUEUE_CLOEXEC);
	if (kq == -1)
		return (-1);
	EV_SET(&change, service_listener_fd(listener), EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, listener);
	if (kevent(kq, &change, 1, NULL, 0, NULL) == -1) {
		(void)close(kq);
		return (-1);
	}

	for (;;) {
		pid_t pid;
		int error;

		if (kevent(kq, NULL, 0, &event, 1, NULL) == -1) {
			if (errno == EINTR)
				continue;
			(void)close(kq);
			return (-1);
		}
		if (event.filter == EVFILT_PROCDESC) {
			/* A worker exited: reap it and free its slot. */
			fs_worker_remove(&workers, event.udata, &nworkers);
			continue;
		}
		/* The listener is readable: accept the pending client. */
		memset(&id, 0, sizeof(id));
		id.size = sizeof(id);
		if (service_listener_accept(listener, &id, &fd) == -1) {
			error = errno;
			/* A clean quiesce is the only reason to leave the loop. */
			if (service_provider_quiescing(provider) == 1) {
				int qst = service_provider_quiesce_complete(
				    provider, 0);
				(void)close(kq);
				return (qst == 0 ? 0 : 1);
			}
			/*
			 * Otherwise NEVER take the storage TCB down on a transient
			 * accept error: every daemon that reads through it would
			 * cascade.  Log and keep serving; back off briefly on fd
			 * exhaustion so the loop does not spin.
			 */
			if (error == EMFILE || error == ENFILE)
				(void)nanosleep(&(struct timespec){
				    .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000},
				    NULL);
			if (error != EINTR)
				syslog(LOG_ERR, "accept: %s", strerror(error));
			continue;
		}
		if (nworkers >= BSDFILESYSTEM_MAX_WORKERS) {
			syslog(LOG_WARNING, "worker limit reached; dropping %s",
			    id.client_label);
			(void)close(fd);
			continue;
		}
		w = calloc(1, sizeof(*w));
		if (w == NULL) {
			syslog(LOG_ERR, "worker alloc: %m");
			(void)close(fd);
			continue;
		}
		pid = pdfork(&w->pd, PD_CLOEXEC | PD_DAEMON);
		if (pid == -1) {
			syslog(LOG_ERR, "pdfork: %m");
			free(w);
			(void)close(fd);
			continue;
		}
		if (pid == 0) {
			(void)close(kq);
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
		EV_SET(&change, w->pd, EVFILT_PROCDESC, EV_ADD | EV_ENABLE,
		    NOTE_EXIT, 0, w);
		if (kevent(kq, &change, 1, NULL, 0, NULL) == -1) {
			int status;

			/*
			 * Cannot watch it.  The child runs under a PD_DAEMON
			 * descriptor, so close(pd) alone would NOT kill it -- it
			 * would keep serving as an unwatched, unreapable orphan.
			 * KILL, reap, then drop our handle.  It is not on the list
			 * yet and was never counted, so leave nworkers untouched.
			 */
			syslog(LOG_WARNING, "procdesc watch %s: %m",
			    id.client_label);
			(void)pdkill(w->pd, SIGKILL);
			(void)pdwait(w->pd, &status, WEXITED, NULL, NULL);
			(void)close(w->pd);
			free(w);
			continue;
		}
		w->next = workers;
		workers = w;
		nworkers++;
	}
}

#ifdef BSDFILESYSTEM_TESTING
/*
 * Test-only accessors.  These expose the file-private pure-logic functions and a
 * single-channel serve entrypoint so the ATF suite can exercise the tenant-
 * isolation and request-validation logic directly.  They add no code to the
 * production build (the whole block is compiled out unless BSDFILESYSTEM_TESTING is
 * defined) and change no runtime behavior.
 */
bool
bsdfilesystem_test_derive_ns(const char *client, char *out, size_t outsz)
{

	return (derive_ns(client, out, outsz));
}

/*
 * Anchor bookkeeping seams: a bare connection whose anchors are the only
 * state, driven with ordinary descriptors (no ZFS).  "live" counts the
 * anchors held.
 */
struct tzfs_conn *
bsdfilesystem_test_conn_new(void)
{
	struct tzfs_conn *conn = calloc(1, sizeof(*conn));

	if (conn != NULL)
		conn_anchors_init(conn);
	return (conn);
}

int
bsdfilesystem_test_anchor_add(struct tzfs_conn *conn, const char *dataset, int fd)
{

	return (conn_anchor_add(conn, dataset, fd, false));
}

void
bsdfilesystem_test_anchor_drop(struct tzfs_conn *conn, const char *dataset)
{

	conn_anchor_drop(conn, dataset);
}

bool
bsdfilesystem_test_valid_container(const char *c)
{

	return (valid_container(c));
}

unsigned
bsdfilesystem_test_anchor_live(const struct tzfs_conn *conn)
{
	unsigned n = 0;
	size_t i;

	for (i = 0; i < nitems(conn->anchors); i++)
		if (conn->anchors[i].fd != -1)
			n++;
	return (n);
}

void
bsdfilesystem_test_conn_free(struct tzfs_conn *conn)
{

	conn_anchors_close(conn);
	free(conn);
}

bool
bsdfilesystem_test_valid_dataset(const char *name)
{

	return (valid_dataset(name));
}

bool
bsdfilesystem_test_has_dotdot_component(const char *path)
{

	return (has_dotdot_component(path));
}

bool
bsdfilesystem_test_valid_request(const struct bsdfilesystem_request *rq)
{

	return (valid_request(rq));
}

/*
 * Drive grant_open() so tests can assert the OPEN request's message hygiene
 * (_reserved must be zero, is_dir must be a canonical 0/1) and the default-deny
 * policy outcome without reaching any ZFS machinery.
 */
int
bsdfilesystem_test_grant_open(struct bsdfilesystem_state *st, const char *client,
    const struct bsdfilesystem_open_request *rq)
{

	return (grant_open(st, client, rq));
}

/*
 * Drive grant() so tests can assert the storage-request argument validation
 * (quota floor, rights/flags/lifetime bounds) that fails EINVAL before any ZFS
 * handle is touched, without an imported pool.
 */
bool
bsdfilesystem_test_scoped_ns(const char *container, const char (*groups)[64],
    uint8_t scope, const char *group, uint32_t lifetime, char *out,
    size_t outsz)
{
	return (scoped_ns(container, groups, scope, group, lifetime, out, outsz));
}

int
bsdfilesystem_test_grant(struct bsdfilesystem_state *st, const char *client,
    const struct bsdfilesystem_request *rq, char *dataset, size_t dsz)
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
bsdfilesystem_test_worker(struct bsdfilesystem_state *st, int fd, const char *client)
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
bsdfilesystem_test_grant_list(struct bsdfilesystem_state *st, const char *client,
    const struct bsdfilesystem_list_request *rq, struct bsdfilesystem_list_reply *rp)
{

	/* client == container in the seam; NULL groups (UNIT/SHARED scopes only). */
	return (grant_list(st, client, NULL, rq, rp));
}
#endif /* BSDFILESYSTEM_TESTING */
