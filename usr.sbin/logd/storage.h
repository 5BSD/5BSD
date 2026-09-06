/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _LOGCMP_STORAGE_H_
#define	_LOGCMP_STORAGE_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <shmring.h>

struct logcmp_record;
struct logcmp_store_cursor;
struct logcmp_query_filter;

#define	LOGCMP_STORAGE_TIMEOUT_MS	5000U
#define	LOGCMP_STORAGE_RING_SIZE		(1U << 20)

struct logcmp_storage_session {
	int			 control_fd;
	struct shmring_fds	 producer_fds;
	struct shmring		*ring;
	char			 label[64];
	bool			 multiplex;
};

/* Factory API.  start returns owned control and process descriptors. */
int	logcmp_storage_start(int, uint64_t, uint32_t, uint64_t, uint64_t,
	    int *, int *);
int	logcmp_storage_attach(int, const char *,
	    struct logcmp_storage_session *);
int	logcmp_storage_attach_pool(int, struct logcmp_storage_session *);
int	logcmp_storage_session_prepare_fork(struct logcmp_storage_session *);

/*
 * Capability-cleanup reclaim (docs/capability-lifecycle-cleanup.md).  Sent over
 * the storage manager's attach-control channel -- the same channel retention is
 * driven behind and never a per-session channel -- so the manager, which owns
 * the store, prunes the retired label.  Idempotent on the store side.
 */
int	logcmp_storage_reclaim(int, const char *);

/* Per-session worker API. */
int	logcmp_storage_session_activate(struct logcmp_storage_session *);
void	logcmp_storage_session_close(struct logcmp_storage_session *);
int	logcmp_storage_append(struct logcmp_storage_session *,
	    const struct logcmp_record *, size_t);
int	logcmp_storage_append_for(struct logcmp_storage_session *, const char *,
	    const struct logcmp_record *, size_t);
int	logcmp_storage_flush(struct logcmp_storage_session *, uint32_t);
int	logcmp_storage_count(struct logcmp_storage_session *, const char *,
	    size_t, uint64_t *);
int	logcmp_storage_query_next(struct logcmp_storage_session *, uint32_t,
	    struct logcmp_store_cursor *, void *, size_t, size_t *, uint32_t);
int	logcmp_storage_query_next_for(struct logcmp_storage_session *,
	    const char *, uint32_t, struct logcmp_store_cursor *, void *, size_t,
	    size_t *, uint32_t);
int	logcmp_storage_query_next_filtered_for(struct logcmp_storage_session *,
	    const char *, uint32_t, const struct logcmp_query_filter *,
	    struct logcmp_store_cursor *, void *, size_t, size_t *, uint32_t);

/* Test seam: run the same writer without kernel sandbox activation. */
int	logcmp_storage_manager_run(int, int, uint64_t, uint32_t, uint64_t,
	    uint64_t, bool);
int	logcmp_storage_test_start(int, uint64_t, uint32_t, uint64_t, uint64_t,
	    int *, pid_t *);

#endif
