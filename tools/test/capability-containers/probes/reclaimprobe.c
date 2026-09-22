/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * reclaimprobe: a throwaway capability unit for the container-model lifecycle
 * test.  It enters capability mode (switchboard's readiness boundary), claims
 * persistent storage from system.Filesystem -- which materialises its per-bundle
 * container Data/<bundle>/<unit>/persistent -- writes a marker, then idles.
 * Removing its bundle must make bsdfilesystem's reconcile reap that container.
 */
#include <sys/capsicum.h>

#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libservice.h>

int
main(void)
{
	struct service_context *ctx = NULL;
	int dirfd = -1, cachefd = -1, fd;

	openlog("reclaimprobe", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	/*
	 * Enter capability mode first: switchboard observes capmode entry as the
	 * readiness boundary (a boot unit that never enters it is killed on the
	 * readiness timeout).  The storage claim below rides inherited descriptors
	 * (the bootstrap envfd + the brokered channel) and openat under the
	 * delivered claim dir, so it needs no path opens and works in capmode.
	 */
	if (cap_enter() == -1)
		syslog(LOG_ERR, "reclaimprobe: cap_enter: %m");
	if (service_acquire(&ctx) == -1)
		syslog(LOG_ERR, "reclaimprobe: service_acquire: %m");
	else if (service_storage_open(ctx, "state", &dirfd) == -1)
		syslog(LOG_ERR, "reclaimprobe: service_storage_open: %m");
	else {
		/* One line per launch: a reinstalled bundle that inherited its
		 * container shows more than one; a fresh container shows one. */
		fd = openat(dirfd, "marker", O_CREAT | O_WRONLY | O_APPEND, 0600);
		if (fd >= 0) {
			(void)write(fd, "launch\n", 7);
			(void)close(fd);
			syslog(LOG_NOTICE,
			    "reclaimprobe: claimed persistent storage");
			/*
			 * Exercise the post-mint quota + single-claim stat API
			 * (system.Filesystem STAT_CLAIM/SET_QUOTA): raise the
			 * claim's refquota and read it back.  The STAT line proves
			 * the round-trip returns the ceiling we just set.
			 */
			{
				struct service_storage_stat_result ss;
				char ver[SERVICE_STORAGE_VERSION_MAX];
				char vers[4][SERVICE_STORAGE_VERSION_MAX];
				size_t nv = 0;
				uint32_t cur = 0;

				if (service_storage_set_quota(ctx, "state",
				    8u << 20) == -1)
					syslog(LOG_ERR,
					    "reclaimprobe: set_quota: %m");
				else if (service_storage_stat(ctx, "state",
				    &ss) == -1)
					syslog(LOG_ERR, "reclaimprobe: stat: %m");
				else
					syslog(LOG_NOTICE,
					    "reclaimprobe: STAT used=%ju "
					    "refquota=%ju avail=%ju",
					    (uintmax_t)ss.used,
					    (uintmax_t)ss.refquota,
					    (uintmax_t)ss.available);
				/*
				 * Time-travel round-trip (system.Filesystem #2):
				 * snapshot the claim, then list its versions and
				 * confirm the new id is present.
				 */
				if (service_storage_snapshot(ctx, "state", ver,
				    sizeof(ver)) == -1)
					syslog(LOG_ERR,
					    "reclaimprobe: snapshot: %m");
				else if (service_storage_list_versions(ctx,
				    "state", vers, 4, &nv, &cur) == -1)
					syslog(LOG_ERR,
					    "reclaimprobe: list_versions: %m");
				else {
					int found = 0;
					size_t k;

					for (k = 0; k < nv; k++)
						if (strcmp(vers[k], ver) == 0)
							found = 1;
					syslog(LOG_NOTICE, "reclaimprobe: "
					    "SNAPSHOT id=%s versions=%zu %s",
					    ver, nv, found ? "PRESENT" :
					    "MISSING");
				}
				/*
				 * Atomic transaction round-trip (#3): stage a
				 * writable clone, write to it, and abort (discard).
				 */
				{
					char txn[SERVICE_STORAGE_VERSION_MAX];
					int tfd = -1, wfd;

					if (service_storage_txn_begin(ctx, "state",
					    txn, sizeof(txn), &tfd) == -1)
						syslog(LOG_ERR,
						    "reclaimprobe: txn_begin: %m");
					else {
						wfd = openat(tfd, "staged.txt",
						    O_CREAT | O_WRONLY, 0600);
						if (wfd >= 0) {
							(void)write(wfd, "x", 1);
							(void)close(wfd);
						}
						(void)close(tfd);
						if (service_storage_txn_abort(ctx,
						    "state", txn) == -1)
							syslog(LOG_ERR,
							    "reclaimprobe: txn_abort: %m");
						else
							syslog(LOG_NOTICE,
							    "reclaimprobe: TXN "
							    "begin+write+abort ok "
							    "(%s)", txn);
					}
				}
				/* OPEN_VERSION (#2): mount the snapshot read-only. */
				if (ver[0] != '\0') {
					int vfd = -1;

					if (service_storage_open_version(ctx,
					    "state", ver, &vfd) == -1)
						syslog(LOG_ERR, "reclaimprobe: "
						    "open_version: %m");
					else {
						syslog(LOG_NOTICE, "reclaimprobe: "
						    "OPEN_VERSION %s ok", ver);
						(void)close(vfd);
					}
				}
				/* OP_LIST (UNIT scope): "state" must appear. */
				{
					struct service_storage_claim cl[8];
					size_t nc = 0, k;
					uint32_t lc = 0;
					int seen = 0;

					if (service_storage_list(ctx, cl, 8, &nc,
					    &lc) == -1)
						syslog(LOG_ERR, "reclaimprobe: "
						    "list: %m");
					else {
						for (k = 0; k < nc; k++)
							if (strcmp(cl[k].name,
							    "state") == 0)
								seen = 1;
						syslog(LOG_NOTICE, "reclaimprobe: "
						    "LIST unit=%zu state=%s", nc,
						    seen ? "PRESENT" : "MISSING");
					}
				}
				/*
				 * ROLLBACK + release + atomic COMMIT (#2/#3) on a
				 * DEDICATED claim, so the destructive swap never
				 * disturbs "state" (still exercised below).  Open it,
				 * snapshot it, drop its mount, roll it back, then
				 * commit a staged clone over it -- the full lifecycle
				 * a snapshot+abort alone never reaches.
				 */
				{
					int lfd = -1, t2 = -1, w2;
					char lver[SERVICE_STORAGE_VERSION_MAX];
					char txn2[SERVICE_STORAGE_VERSION_MAX];

					if (service_storage_open(ctx, "lifecycle",
					    &lfd) == -1)
						syslog(LOG_ERR, "reclaimprobe: "
						    "open lifecycle: %m");
					else if (service_storage_snapshot(ctx,
					    "lifecycle", lver, sizeof(lver)) == -1) {
						syslog(LOG_ERR, "reclaimprobe: "
						    "snapshot lifecycle: %m");
						(void)close(lfd);
					} else {
						(void)close(lfd);
						/* Drop the mount so it can be swapped. */
						if (service_storage_release(ctx,
						    "lifecycle") == -1)
							syslog(LOG_ERR,
							    "reclaimprobe: "
							    "release: %m");
						if (service_storage_rollback(ctx,
						    "lifecycle", lver) == -1)
							syslog(LOG_ERR,
							    "reclaimprobe: "
							    "rollback: %m");
						else
							syslog(LOG_NOTICE,
							    "reclaimprobe: "
							    "ROLLBACK %s ok", lver);
						if (service_storage_txn_begin(ctx,
						    "lifecycle", txn2,
						    sizeof(txn2), &t2) == -1)
							syslog(LOG_ERR,
							    "reclaimprobe: "
							    "txn_begin(commit): %m");
						else {
							w2 = openat(t2,
							    "committed.txt",
							    O_CREAT | O_WRONLY,
							    0600);
							if (w2 >= 0) {
								(void)write(w2,
								    "c", 1);
								(void)close(w2);
							}
							(void)close(t2);
							if (service_storage_txn_commit(
							    ctx, "lifecycle",
							    txn2) == -1)
								syslog(LOG_ERR,
								    "reclaimprobe:"
								    " txn_commit: %m");
							else
								syslog(LOG_NOTICE,
								    "reclaimprobe:"
								    " TXN COMMIT ok"
								    " (%s)", txn2);
						}
						/* Tidy the scratch claim. */
						(void)service_storage_destroy(ctx,
						    "lifecycle");
					}
				}
			}
		} else
			syslog(LOG_ERR, "reclaimprobe: openat marker: %m");
		/* And a cache sub-container, reaped with the unit. */
		if (service_storage_open_cache(ctx, "scratch", &cachefd) == -1)
			syslog(LOG_ERR, "reclaimprobe: open_cache: %m");
		else {
			fd = openat(cachefd, "scratch.bin", O_CREAT | O_WRONLY, 0600);
			if (fd >= 0)
				(void)close(fd);
			/*
			 * The persistent store must still be mounted AFTER the
			 * cache claim (one anchor per claim, not per connection):
			 * write a second file through the first claim's dirfd.
			 */
			fd = openat(dirfd, "after-cache", O_CREAT | O_WRONLY, 0600);
			if (fd >= 0) {
				(void)close(fd);
				syslog(LOG_NOTICE,
				    "reclaimprobe: persistent still mounted after cache claim");
			} else
				syslog(LOG_ERR,
				    "reclaimprobe: persistent LOST after cache claim: %m");
		}
	}
	for (;;)
		(void)pause();
	return (0);
}
