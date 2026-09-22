/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * enospcprobe: drives the TXN_BEGIN clone-failure cleanup path.  Paired with a
 * fault-injection build of bsdfilesystem (BSDFILESYSTEM_FAULT_TXN_CLONE in the
 * unit environment), every TXN_BEGIN takes its base snapshot and then fails the
 * clone as ENOSPC would.  The fixed handler must destroy that orphan snapshot
 * (it has no clone, so no later sweep would find it, and the caller gets no id
 * to ABORT).  The probe TXN_BEGINs once on a dedicated claim, expects the
 * failure, and records it; the driver then asserts the claim has no leftover
 * snapshot.
 */
#include <sys/capsicum.h>

#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libservice.h>

int
main(void)
{
	struct service_context *ctx = NULL;
	char txn[SERVICE_STORAGE_VERSION_MAX];
	int dirfd = -1, tfd = -1, r, f;

	openlog("enospcprobe", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	if (cap_enter() == -1)
		syslog(LOG_ERR, "enospcprobe: cap_enter: %m");
	if (service_acquire(&ctx) == -1) {
		syslog(LOG_ERR, "enospcprobe: service_acquire: %m");
		for (;;)
			(void)pause();
	}
	/* Materialise the claim (create-on-open), then release the handle. */
	if (service_storage_open(ctx, "faultclaim", &dirfd) == 0)
		(void)close(dirfd);
	/* The fault daemon fails this after the snapshot; expect -1. */
	r = service_storage_txn_begin(ctx, "faultclaim", txn, sizeof(txn), &tfd);
	if (r == 0) {
		(void)close(tfd);
		syslog(LOG_ERR, "enospcprobe: txn_begin UNEXPECTEDLY succeeded");
	}
	/* Record the outcome into the (still intact) claim for the driver. */
	if (service_storage_open(ctx, "faultclaim", &dirfd) == 0) {
		f = openat(dirfd, r == -1 ? "txn-failed" : "txn-unexpected-ok",
		    O_CREAT | O_WRONLY | O_TRUNC, 0600);
		if (f >= 0)
			(void)close(f);
		(void)close(dirfd);
	}
	for (;;)
		(void)pause();
	return (0);
}
