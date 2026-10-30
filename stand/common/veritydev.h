/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LOADER_VERITYDEV_H_
#define _LOADER_VERITYDEV_H_
#include <geom/verity/g_verity_verify.h>
struct devsw;
extern struct devsw verity_dev;
/*
 * Internal boot integration API, not a loader command. Caller authenticates the
 * root first. Success transfers ownership of fd and returns a fresh device unit;
 * failure leaves fd/output with the caller. Budget covers requested heap bytes.
 * No unit is reused in this loader session. No root admission follows merely
 * from constructing this device. Descriptor authentication/selection is separate.
 */
int verity_dev_attach(int, const struct g_verity_root *, size_t, size_t, int *);
/*
 * Authenticate/decode descriptor_fd through the existing loader manifest policy,
 * compare its private bytes to the required 32-byte expected SHA-256 from boot
 * policy, then attach backing_fd. Caller retains descriptor_fd. On success, descriptor
 * receives G_VERITY_ROOT_BYTES for handoff without reopening mutable storage.
 * On failure, both descriptors and both outputs remain owned by the caller.
 */
int verity_dev_attach_verified(int, int, const char *, const unsigned char *,
    size_t, size_t, int *,
    unsigned char *);
/* A close error is reported after retirement; the unit must not be retried. */
int verity_dev_detach(int);
#endif
