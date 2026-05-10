/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * cap_rt_mount — wire protocol for the mount service.
 *
 * Capability-based filesystem mounting for sandboxed init daemons.
 * The service runs in the caller's thread context, so mounts are
 * scoped to the caller's jail/chroot namespace.
 */

#ifndef _DEV_CAP_RT_CAP_RT_MOUNT_PROTO_H_
#define _DEV_CAP_RT_CAP_RT_MOUNT_PROTO_H_

#define	MOUNT_OP_MOUNT		1	/* mount filesystem */
#define	MOUNT_OP_UNMOUNT	2	/* unmount filesystem */

/* Status codes */
#define	MOUNT_STATUS_OK		0
#define	MOUNT_STATUS_ERR	1
#define	MOUNT_STATUS_EPERM	2
#define	MOUNT_STATUS_ENOENT	3	/* mountpoint not found */
#define	MOUNT_STATUS_EBUSY	4	/* already mounted / busy */

/* Maximum path and fstype lengths */
#define	MOUNT_MAXPATH		256
#define	MOUNT_MAXFSTYPE		16
#define	MOUNT_MAXFROM		256	/* source path for nullfs */
#define	MOUNT_MAXOPTS		256	/* fs-specific options string */

/* Safe mount flags (subset of MNT_*) */
#define	MOUNT_F_RDONLY		0x0001	/* MNT_RDONLY */
#define	MOUNT_F_NOEXEC		0x0002	/* MNT_NOEXEC */
#define	MOUNT_F_NOSUID		0x0004	/* MNT_NOSUID */
#define	MOUNT_F_NOATIME		0x0008	/* MNT_NOATIME */
#define	MOUNT_F_NOSYMFOLLOW	0x0010	/* MNT_NOSYMFOLLOW */
#define	MOUNT_F_NOCOVER		0x0020	/* MNT_NOCOVER — don't cover existing mount */
#define	MOUNT_F_EMPTYDIR	0x0040	/* MNT_EMPTYDIR — only mount on empty dir */

/*
 * Request: mount
 *
 * cap_rt_mount is a capability-mediated mount gateway, not a full
 * mount policy engine.  It constrains the broad shape of requests:
 * approved fstypes, approved generic flags, and safe paths.
 *
 * Whitelisted fstypes: tmpfs, devfs, fdescfs, nullfs, procfs,
 *   linprocfs, linsysfs, fusefs.
 *
 * fsopts is a comma-separated string of fs-specific options
 * passed through to the filesystem's mount handler:
 *   tmpfs:      "size=128M,mode=1777"
 *   devfs:      "ruleset=4"
 *   fdescfs:    "linrdlnk"
 *   nullfs:     (use from field for source path)
 *   linprocfs:  (no special options)
 *   linsysfs:   (no special options)
 *
 * The mount runs in the caller's thread context, so normal jail
 * policy still applies.  The jail's allow.mount.* settings decide
 * whether the filesystem may be mounted in that jail at all, and
 * invalid fs-specific options are rejected by the filesystem itself.
 *
 * Example:
 *   fstype="tmpfs", fspath="/var/run",
 *   fsopts="size=64M,mode=1777"
 *   - cap_rt_mount checks request shape, allowed fstype, flags, and path
 *   - the jail checks allow.mount.* for tmpfs
 *   - tmpfs validates size/mode
 *
 * Empty string = no fs-specific options.
 */
struct mount_request {
	uint32_t	op;		/* MOUNT_OP_MOUNT */
	uint32_t	flags;		/* MOUNT_F_* */
	char		fstype[MOUNT_MAXFSTYPE];
	char		fspath[MOUNT_MAXPATH];
	char		from[MOUNT_MAXFROM];	/* source for nullfs; empty otherwise */
	char		fsopts[MOUNT_MAXOPTS];	/* fs-specific options */
} __packed;

/* Request: unmount */
struct unmount_request {
	uint32_t	op;		/* MOUNT_OP_UNMOUNT */
	uint32_t	flags;		/* 0 or MOUNT_F_FORCE */
	char		fspath[MOUNT_MAXPATH];
} __packed;

#define	MOUNT_F_FORCE		0x8000	/* force unmount */

/* Reply (shared) */
struct mount_reply {
	uint32_t	status;
	uint32_t	_pad;
} __packed;

#endif /* _DEV_CAP_RT_CAP_RT_MOUNT_PROTO_H_ */
