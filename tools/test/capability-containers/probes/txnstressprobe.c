/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * txnstressprobe: hammer the transaction machinery of one unit's claim in a
 * tight loop -- begin, write, and commit or abort; periodically snapshot, list
 * versions, open a version read-only, and roll back.  Several of these units run
 * concurrently (the driver stages many), so the storage daemon services the full
 * TXN path -- snapshot / clone / promote / rename / destroy, plus its reconcile
 * reaper's idle staging sweep -- under parallel load across the pool.
 *
 * Each iteration it records a running counter and the last errno into its own
 * observable "state" claim so the driver can confirm forward progress and that
 * no operation returned an unexpected error.  It never exits; the driver bounds
 * the run and then checks daemon liveness and that no staging clones leaked.
 */
#include <sys/capsicum.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libservice.h>

int
main(void)
{
	struct service_context *ctx = NULL;
	int dirfd = -1;
	unsigned long iter = 0, commits = 0, aborts = 0, snaps = 0, rolls = 0,
	    errs = 0;
	int last_errno = 0;

	openlog("txnstressprobe", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	if (cap_enter() == -1)
		syslog(LOG_ERR, "txnstressprobe: cap_enter: %m");
	while (service_acquire(&ctx) == -1)
		sleep(1);
	while (service_storage_open(ctx, "state", &dirfd) == -1)
		sleep(1);

	for (;;) {
		char txn[SERVICE_STORAGE_VERSION_MAX];
		char ver[SERVICE_STORAGE_VERSION_MAX];
		int tfd = -1, wfd, tally;

		iter++;
		/* Core churn: begin -> write -> commit or abort. */
		if (service_storage_txn_begin(ctx, "state", txn, sizeof(txn),
		    &tfd) == 0) {
			wfd = openat(tfd, "d", O_CREAT | O_WRONLY | O_APPEND, 0600);
			if (wfd >= 0) {
				(void)write(wfd, "x", 1);
				(void)close(wfd);
			}
			(void)close(tfd);
			/*
			 * Commit is a heavy promote+rename+destroy swap; abort is
			 * lighter.  Commit only occasionally so the loop makes
			 * visible progress even under a WITNESS/INVARIANTS kernel
			 * where each commit costs tens of seconds, while still
			 * exercising the commit path.
			 */
			if (iter % 8 == 0) {
				if (service_storage_txn_commit(ctx, "state",
				    txn) == 0)
					commits++;
				else {
					errs++;
					last_errno = errno;
				}
			} else {
				if (service_storage_txn_abort(ctx, "state",
				    txn) == 0)
					aborts++;
				else {
					errs++;
					last_errno = errno;
				}
			}
		} else {
			errs++;
			last_errno = errno;
		}

		/* Occasionally exercise the version verbs too (also heavy). */
		if (iter % 20 == 0) {
			if (service_storage_snapshot(ctx, "state", ver,
			    sizeof(ver)) == 0) {
				int vfd = -1;
				size_t nv = 0;
				uint32_t cur = 0;
				char list[8][SERVICE_STORAGE_VERSION_MAX];

				snaps++;
				(void)service_storage_list_versions(ctx, "state",
				    list, 8, &nv, &cur);
				if (service_storage_open_version(ctx, "state",
				    ver, &vfd) == 0)
					(void)close(vfd);
				if (service_storage_rollback(ctx, "state",
				    ver) == 0)
					rolls++;
			} else {
				errs++;
				last_errno = errno;
			}
		}

		/* Publish progress into the observable claim (truncate each time). */
		tally = openat(dirfd, "tally", O_CREAT | O_WRONLY | O_TRUNC, 0600);
		if (tally >= 0) {
			char line[160];
			int n = snprintf(line, sizeof(line),
			    "iter=%lu commits=%lu aborts=%lu snaps=%lu rolls=%lu "
			    "errs=%lu last_errno=%d\n", iter, commits, aborts,
			    snaps, rolls, errs, last_errno);

			if (n > 0)
				(void)write(tally, line, (size_t)n);
			(void)close(tally);
		}
	}
	return (0);
}
