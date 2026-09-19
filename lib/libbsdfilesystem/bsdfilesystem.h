/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libbsdfilesystem — client library for the bsdfilesystem(8) storage daemon.
 *
 * A consumer asks bsdfilesystem for storage of a given lifetime and
 * receives a rights-limited TrustedZFS dataset handle, which it then drives
 * with the libtrustedzfs verb API (tzfs_*).  This library only *obtains* the
 * handle; it deliberately does not duplicate the verb surface.
 *
 * Function prefix is bsdfilesystem_ (not tzfs_) so a program may link both this
 * library and libtrustedzfs without symbol collision.
 */

#ifndef LIBBSDFILESYSTEM_H
#define LIBBSDFILESYSTEM_H

#include <sys/types.h>
#include <stdint.h>

#include "bsdfilesystem_proto.h"

/*
 * Storage request for a bare dataset claim.  rights is the ZH_* mask to grant;
 * lifetime is one of the BSDFILESYSTEM_* lifecycle constants.
 */
struct bsdfilesystem_req {
	char		dataset[BSDFILESYSTEM_NAME_MAX];
	uint64_t	rights;
	uint32_t	flags;			/* ZHF_* (0 for the common case) */
	uint8_t		lifetime;
	uint32_t	owner_uid;		/* chown dataset root at mint; 0=skip */
	uint32_t	owner_gid;
};

struct bsdfilesystem_grant {
	int		handle_fd;		/* the granted zfd (caller closes) */
	char		dataset[BSDFILESYSTEM_DATASET_MAX];	/* resolved name, for audit */
};

/*
 * Opaque client handle wrapping a held mac_capability channel to bsdfilesystem.  bsdfilesystem
 * is a socket-free service_provider (system.Filesystem); there is no socket to
 * connect and no fd to pass around — the handle owns the channel session.
 */
struct bsdfilesystem_client;

__BEGIN_DECLS

/*
 * Open a channel to bsdfilesystem by name (service_open(system.Filesystem)).  Returns a
 * client handle the caller owns and must bsdfilesystem_close(), or NULL with errno set.
 * A caller handed a pre-scoped storage channel at bootstrap uses
 * bsdfilesystem_adopt() instead.
 */
struct bsdfilesystem_client	*bsdfilesystem_connect(void);

/*
 * Wrap an already-held storage channel fd (e.g. one switchboard delivered,
 * pre-scoped to a claim) as a client handle.  Consumes fd on success.  Returns
 * a handle or NULL with errno set.
 */
struct bsdfilesystem_client	*bsdfilesystem_adopt(int channel_fd);

/* Release the client handle and its channel. */
void	bsdfilesystem_close(struct bsdfilesystem_client *c);

/*
 * Request a storage handle.  On success returns 0 and fills *out (out->handle_fd
 * is the granted descriptor, which the caller owns and must close).  On failure
 * returns -1 with errno set to the daemon-reported error.
 */
int	bsdfilesystem_request(struct bsdfilesystem_client *c, const struct bsdfilesystem_req *req,
	    struct bsdfilesystem_grant *out);

/*
 * As bsdfilesystem_request(), but with an explicit per-claim refquota ceiling in bytes
 * (0 selects the daemon default; a value below the daemon's floor is rejected
 * with EINVAL by the daemon).  bsdfilesystem_request() is exactly this with quota == 0.
 */
int	bsdfilesystem_request_quota(struct bsdfilesystem_client *c, const struct bsdfilesystem_req *req,
	    uint64_t quota, struct bsdfilesystem_grant *out);

/*
 * Release (destroy) a lease claim previously granted under this dataset key.
 * Idempotent: a missing claim is success.  Returns 0 or -1/errno.
 */
int	bsdfilesystem_release(struct bsdfilesystem_client *c, const char *dataset);

/*
 * Reclaim a persistent (BSDFILESYSTEM_PERSISTENT) or cache (BSDFILESYSTEM_CACHE) claim
 * previously granted under this dataset key, freeing its pool space.  Unlike
 * bsdfilesystem_release() this is NOT idempotent: an absent claim returns -1/ENOENT so
 * a caller can distinguish a real reclaim from a no-op.  lifetime must be
 * BSDFILESYSTEM_PERSISTENT or BSDFILESYSTEM_CACHE.  The claim is resolved under the caller's own
 * namespace (the channel's unforgeable label), so no other label's claim can be
 * named.  Returns 0 or -1/errno.
 */
int	bsdfilesystem_destroy(struct bsdfilesystem_client *c, const char *dataset,
	    uint32_t lifetime);

/* Liveness check.  Returns 0 if bsdfilesystem answered, -1/errno otherwise. */
int	bsdfilesystem_ping(struct bsdfilesystem_client *c);

/* Begin or resume one service-manager lease generation. */
int	bsdfilesystem_begin_session(struct bsdfilesystem_client *c, const char *session);

/*
 * Convenience: mount a granted handle and return a directory fd for its root
 * (rdonly selects a read-only mount).  Thin wrapper over libtrustedzfs
 * tzfs_mount(); requires the handle to carry ZH_MOUNT.  Returns a dirfd or -1.
 */
int	bsdfilesystem_mount_dir(int handle_fd, int rdonly);

__END_DECLS

#endif /* LIBBSDFILESYSTEM_H */
