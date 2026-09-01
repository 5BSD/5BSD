/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libtzfsd — client library for the tzfsd(8) storage daemon.
 *
 * A consumer asks tzfsd for storage of a given lifetime and
 * receives a rights-limited TrustedZFS dataset handle, which it then drives
 * with the libtrustedzfs verb API (tzfs_*).  This library only *obtains* the
 * handle; it deliberately does not duplicate the verb surface.
 *
 * Function prefix is tzfsd_ (not tzfs_) so a program may link both this
 * library and libtrustedzfs without symbol collision.
 */

#ifndef LIBTZFSD_H
#define LIBTZFSD_H

#include <sys/types.h>
#include <stdint.h>

#include "tzfsd_proto.h"

/*
 * Storage request for a bare dataset claim.  rights is the ZH_* mask to grant;
 * lifetime is one of the TZFSD_* lifecycle constants.
 */
struct tzfsd_req {
	char		dataset[TZFSD_NAME_MAX];
	uint64_t	rights;
	uint32_t	flags;			/* ZHF_* (0 for the common case) */
	uint8_t		lifetime;
	uint32_t	owner_uid;		/* chown dataset root at mint; 0=skip */
	uint32_t	owner_gid;
};

struct tzfsd_grant {
	int		handle_fd;		/* the granted zfd (caller closes) */
	char		dataset[TZFSD_DATASET_MAX];	/* resolved name, for audit */
};

__BEGIN_DECLS

/*
 * Connect the well-known tzfsd socket.  Returns a channel fd (caller closes)
 * or -1 with errno set.  Sandboxed callers that were handed a pre-connected
 * channel at bootstrap skip this and pass that fd to the calls below.
 */
int	tzfsd_connect(void);

/*
 * Request a storage handle.  On success returns 0 and fills *out (out->handle_fd
 * is the granted descriptor, which the caller owns and must close).  On failure
 * returns -1 with errno set to the daemon-reported error.
 */
int	tzfsd_request(int chan, const struct tzfsd_req *req,
	    struct tzfsd_grant *out);

/*
 * Release (destroy) a lease claim previously granted under this dataset key.
 * Idempotent: a missing claim is success.  Returns 0 or -1/errno.
 */
int	tzfsd_release(int chan, const char *dataset);

/* Liveness check.  Returns 0 if tzfsd answered, -1/errno otherwise. */
int	tzfsd_ping(int chan);

/* Begin or resume one service-manager lease generation. */
int	tzfsd_begin_session(int chan, const char *session);

/*
 * Convenience: mount a granted handle and return a directory fd for its root
 * (rdonly selects a read-only mount).  Thin wrapper over libtrustedzfs
 * tzfs_mount(); requires the handle to carry ZH_MOUNT.  Returns a dirfd or -1.
 */
int	tzfsd_mount_dir(int handle_fd, int rdonly);

__END_DECLS

#endif /* LIBTZFSD_H */
