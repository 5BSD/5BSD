/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * cap_rt_mount — capability-based filesystem mounting.
 *
 * Allows a Capsicum-sandboxed init daemon to mount filesystems within
 * its jail via CAP_RT_CALL.  The co_call runs in the caller's thread,
 * so mounts are scoped to the caller's jail/chroot namespace and
 * subject to normal jail mount permissions (allow.mount.*).
 *
 * Whitelisted filesystem types:
 *   tmpfs, devfs, fdescfs, nullfs, procfs
 *
 * This is a sync-only (co_call) service.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>

#include "cap_rt.h"
#include "cap_rt_mount_proto.h"

/*
 * Allowed filesystem types.  Only these can be mounted through the
 * service.  The jail's allow.mount.* parameters provide a second
 * layer of enforcement.
 */
static const char *mount_allowed_fstypes[] = {
	"tmpfs",
	"devfs",
	"fdescfs",
	"nullfs",
	"procfs",
	"linprocfs",
	"linsysfs",
	NULL
};

static bool
mount_fstype_allowed(const char *fstype)
{
	const char **p;

	for (p = mount_allowed_fstypes; *p != NULL; p++) {
		if (strcmp(fstype, *p) == 0)
			return (true);
	}
	return (false);
}

/*
 * Validate a path from untrusted input.
 * Must be absolute, null-terminated within the buffer, and contain
 * no ".." components.
 */
static bool
mount_path_valid(const char *path, size_t maxlen)
{
	const char *p;
	size_t len;

	/* Must be null-terminated within the buffer. */
	for (len = 0; len < maxlen; len++) {
		if (path[len] == '\0')
			break;
	}
	if (len == 0 || len >= maxlen)
		return (false);

	/* Must be absolute. */
	if (path[0] != '/')
		return (false);

	/*
	 * Reject ".." as a path component.  Only match when ".." is
	 * bounded by '/' or string boundaries — not when it appears
	 * as part of a directory name like "..hidden".
	 */
	for (p = path; *p != '\0'; p++) {
		if (p[0] == '.' && p[1] == '.' &&
		    (p == path || p[-1] == '/') &&
		    (p[2] == '/' || p[2] == '\0'))
			return (false);
	}

	return (true);
}

/*
 * Map MOUNT_F_* flags to MNT_* flags.
 */
static uint64_t
mount_map_flags(uint32_t flags)
{
	uint64_t mnt_flags = 0;

	if (flags & MOUNT_F_RDONLY)
		mnt_flags |= MNT_RDONLY;
	if (flags & MOUNT_F_NOEXEC)
		mnt_flags |= MNT_NOEXEC;
	if (flags & MOUNT_F_NOSUID)
		mnt_flags |= MNT_NOSUID;
	if (flags & MOUNT_F_NOATIME)
		mnt_flags |= MNT_NOATIME;
	if (flags & MOUNT_F_NOSYMFOLLOW)
		mnt_flags |= MNT_NOSYMFOLLOW;
	if (flags & MOUNT_F_NOCOVER)
		mnt_flags |= MNT_NOCOVER;
	if (flags & MOUNT_F_EMPTYDIR)
		mnt_flags |= MNT_EMPTYDIR;

	return (mnt_flags);
}

static uint32_t
mount_error_status(int error)
{

	switch (error) {
	case 0:
		return (MOUNT_STATUS_OK);
	case EPERM:
	case EACCES:
		return (MOUNT_STATUS_EPERM);
	case ENOENT:
	case ENOTDIR:
		return (MOUNT_STATUS_ENOENT);
	case EBUSY:
		return (MOUNT_STATUS_EBUSY);
	default:
		return (MOUNT_STATUS_ERR);
	}
}

/* ----------------------------------------------------------------
 * Mount operation
 * ---------------------------------------------------------------- */

static int
mount_op_mount(const void *req, size_t reqlen,
    void *reply, size_t *replylenp)
{
	const struct mount_request *mr = req;
	struct mount_reply *rp = reply;
	struct mntarg *ma;
	char fstype[MOUNT_MAXFSTYPE];
	char fspath[MOUNT_MAXPATH];
	char from[MOUNT_MAXFROM];
	char fsopts[MOUNT_MAXOPTS];
	uint64_t mnt_flags;
	int error;

	if (reqlen < sizeof(*mr) || *replylenp < sizeof(*rp))
		return (EINVAL);
	*replylenp = sizeof(*rp);

	/*
	 * Copy and null-terminate strings from the wire.
	 */
	memcpy(fstype, mr->fstype, sizeof(fstype));
	fstype[sizeof(fstype) - 1] = '\0';
	memcpy(fspath, mr->fspath, sizeof(fspath));
	fspath[sizeof(fspath) - 1] = '\0';
	memcpy(from, mr->from, sizeof(from));
	from[sizeof(from) - 1] = '\0';
	memcpy(fsopts, mr->fsopts, sizeof(fsopts));
	fsopts[sizeof(fsopts) - 1] = '\0';

	memset(rp, 0, sizeof(*rp));

	/* Validate filesystem type. */
	if (!mount_fstype_allowed(fstype)) {
		rp->status = MOUNT_STATUS_EPERM;
		return (0);
	}

	/* Validate mount path. */
	if (!mount_path_valid(fspath, sizeof(fspath))) {
		rp->status = MOUNT_STATUS_ERR;
		return (0);
	}

	/* Reject unknown flags. */
	if (mr->flags & ~(MOUNT_F_RDONLY | MOUNT_F_NOEXEC |
	    MOUNT_F_NOSUID | MOUNT_F_NOATIME | MOUNT_F_NOSYMFOLLOW |
	    MOUNT_F_NOCOVER | MOUNT_F_EMPTYDIR)) {
		rp->status = MOUNT_STATUS_ERR;
		return (0);
	}

	/* nullfs needs a valid source path. */
	if (strcmp(fstype, "nullfs") == 0 &&
	    !mount_path_valid(from, sizeof(from))) {
		rp->status = MOUNT_STATUS_ERR;
		return (0);
	}

	/*
	 * Validate fs-specific options before building mntarg.
	 * Reject keys that match framework-set arguments to prevent
	 * callers from overriding the validated fstype, fspath, or from.
	 */
	if (fsopts[0] != '\0') {
		static const char *reserved_keys[] = {
			"fstype", "fspath", "from", "errmsg", "update", NULL
		};
		char check[MOUNT_MAXOPTS];
		char *opts, *opt, *eq;
		const char **rk;

		memcpy(check, fsopts, sizeof(check));
		opts = check;
		while ((opt = strsep(&opts, ",")) != NULL) {
			if (*opt == '\0')
				continue;
			/* Isolate key by truncating at '='. */
			eq = strchr(opt, '=');
			if (eq != NULL)
				*eq = '\0';
			for (rk = reserved_keys; *rk != NULL; rk++) {
				if (strcmp(opt, *rk) == 0) {
					rp->status = MOUNT_STATUS_ERR;
					return (0);
				}
			}
		}
	}

	mnt_flags = mount_map_flags(mr->flags);

	/*
	 * Always force MNT_NOSYMFOLLOW to prevent symlink TOCTOU
	 * between our textual path validation and kernel VFS
	 * resolution.
	 */
	mnt_flags |= MNT_NOSYMFOLLOW;

	/*
	 * Build the mount argument list using kernel_mount(9).
	 * kernel_mount runs in curthread context, so the mount
	 * is scoped to the caller's jail and subject to the
	 * jail's allow.mount.* permissions.
	 * kernel_mount always frees ma, even on error.
	 */
	ma = NULL;
	ma = mount_arg(ma, "fstype", fstype, -1);
	ma = mount_arg(ma, "fspath", fspath, -1);
	if (strcmp(fstype, "nullfs") == 0)
		ma = mount_arg(ma, "from", from, -1);

	/*
	 * Parse fs-specific options.  Format: comma-separated
	 * key=value pairs (e.g., "size=128M,mode=1777").
	 * Boolean options have no "=" (e.g., "linrdlnk").
	 * Each option becomes a mount_arg call.
	 */
	if (fsopts[0] != '\0') {
		char *opts, *opt, *key, *val;

		opts = fsopts;
		while ((opt = strsep(&opts, ",")) != NULL) {
			if (*opt == '\0')
				continue;
			key = opt;
			val = strchr(opt, '=');
			if (val != NULL) {
				*val = '\0';
				val++;
				ma = mount_arg(ma, key, val, -1);
			} else {
				/* Boolean option — pass empty value. */
				ma = mount_arg(ma, key, NULL, 0);
			}
		}
	}

	error = kernel_mount(ma, mnt_flags);

	memset(rp, 0, sizeof(*rp));
	rp->status = mount_error_status(error);
	return (0);
}

/* ----------------------------------------------------------------
 * Unmount operation
 * ---------------------------------------------------------------- */

static int
mount_op_unmount(const void *req, size_t reqlen,
    void *reply, size_t *replylenp)
{
	const struct unmount_request *ur = req;
	struct mount_reply *rp = reply;
	char fspath[MOUNT_MAXPATH];
	uint64_t flags;
	int error;

	if (reqlen < sizeof(*ur) || *replylenp < sizeof(*rp))
		return (EINVAL);
	*replylenp = sizeof(*rp);

	memcpy(fspath, ur->fspath, sizeof(fspath));
	fspath[sizeof(fspath) - 1] = '\0';

	if (!mount_path_valid(fspath, sizeof(fspath))) {
		memset(rp, 0, sizeof(*rp));
		rp->status = MOUNT_STATUS_ERR;
		return (0);
	}

	/* Reject unknown unmount flags. */
	if (ur->flags & ~MOUNT_F_FORCE) {
		memset(rp, 0, sizeof(*rp));
		rp->status = MOUNT_STATUS_ERR;
		return (0);
	}

	flags = 0;
	if (ur->flags & MOUNT_F_FORCE)
		flags |= MNT_FORCE;

	error = kern_unmount(curthread, fspath, flags);

	memset(rp, 0, sizeof(*rp));
	rp->status = mount_error_status(error);
	return (0);
}

/* ----------------------------------------------------------------
 * co_call handler
 * ---------------------------------------------------------------- */

static int
mount_call(struct cap_rt_instance *s __unused,
    const void *req, size_t reqlen,
    struct file **fds __unused, struct filecaps *fcaps __unused,
    int nfds __unused,
    void *reply, size_t *replylenp,
    struct file **reply_fds __unused, int *reply_nfdsp __unused,
    void *arg __unused)
{
	uint32_t op;

	if (reqlen < sizeof(uint32_t))
		return (EINVAL);

	op = *(const uint32_t *)req;

	switch (op) {
	case MOUNT_OP_MOUNT:
		return (mount_op_mount(req, reqlen, reply, replylenp));
	case MOUNT_OP_UNMOUNT:
		return (mount_op_unmount(req, reqlen, reply, replylenp));
	default:
		return (EINVAL);
	}
}

/* ----------------------------------------------------------------
 * Service registration
 * ---------------------------------------------------------------- */

static struct cap_rt_ops mount_ops = {
	.co_call = mount_call,
};

static struct cap_rt_service *mount_svc;

static int
cap_rt_mount_modevent(module_t mod __unused, int type, void *data __unused)
{
	struct cap_rt_service_params params;
	int error;

	switch (type) {
	case MOD_LOAD:
		memset(&params, 0, sizeof(params));
		params.name = "mount";
		params.ops = &mount_ops;
		error = cap_rt_service_create(&params, &mount_svc);
		if (error != 0)
			printf("cap_rt_mount: create failed: %d\n", error);
		return (error);
	case MOD_UNLOAD:
		return (EBUSY);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t cap_rt_mount_mod = {
	"cap_rt_mount",
	cap_rt_mount_modevent,
	NULL,
};

DECLARE_MODULE(cap_rt_mount, cap_rt_mount_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_DEPEND(cap_rt_mount, cap_rt, 1, 1, 1);
