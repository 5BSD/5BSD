/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _LOGCMP_STORE_H_
#define	_LOGCMP_STORE_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct logcmp_record;
struct logcmp_store;

struct logcmp_store_cursor {
	uint64_t generation;
	uint64_t offset;
};

/*
 * Server-side QUERY filter.  All fields are optional and combine as AND: a
 * zero from_ns/to_ns is "no bound", a zero-length subsystem/category is "no
 * constraint".  match_flags carries the LOGCMP_QUERY_MATCH_*_EXACT bits; a
 * clear bit means substring matching for that field.  The filter never widens
 * the caller's own-label scope -- it only narrows within it.
 */
struct logcmp_query_filter {
	uint64_t	from_ns;
	uint64_t	to_ns;
	const char	*subsystem;
	const char	*category;
	uint16_t	subsystem_length;
	uint16_t	category_length;
	uint32_t	match_flags;
};

/* Retention prune reasons, reported through the retention__prune probe. */
#define	LOGCMP_STORE_RETENTION_AGE	1
#define	LOGCMP_STORE_RETENTION_SIZE	2

#define	LOGCMP_STORE_SEGMENT_MIN	(64U * 1024)
#define	LOGCMP_STORE_SEGMENT_MAX	(UINT64_C(4) * 1024 * 1024 * 1024)
#define	LOGCMP_STORE_SEGMENTS_DEFAULT	64U
#define	LOGCMP_STORE_SEGMENTS_MIN	1U
#define	LOGCMP_STORE_SEGMENTS_MAX	1024U
#define	LOGCMP_STORE_RECLAIMED_MAX	128U

/* Internal query results.  CONTINUE yields the storage event loop fairly. */
#define	LOGCMP_STORE_QUERY_EOF		0
#define	LOGCMP_STORE_QUERY_RECORD	1
#define	LOGCMP_STORE_QUERY_CONTINUE	2
#define	LOGCMP_STORE_QUERY_RECORD_BUDGET	128U
#define	LOGCMP_STORE_QUERY_BYTE_BUDGET	(1024U * 1024)
#define	LOGCMP_STORE_QUERY_SEGMENT_BUDGET 32U
#define	LOGCMP_STORE_PRIVACY_KEY_SIZE	32U

/*
 * The directory descriptor is borrowed.  The store owns every file it opens.
 * Recovery truncates only an incomplete final record.  Any corruption inside
 * a complete record fails with EILSEQ and must be quarantined by the owner:
 * on EILSEQ the owner calls logcmp_store_quarantine() to move the bad active
 * segment aside, then reopens (which starts a fresh segment), so a single
 * corrupt record left by an unclean shutdown cannot brick the logging plane.
 */
int	logcmp_store_open(int, uint64_t, uint32_t, struct logcmp_store **);
int	logcmp_store_quarantine(int);
int	logcmp_store_append(struct logcmp_store *, const char *,
	    const struct logcmp_record *, size_t, bool);
int	logcmp_store_flush(struct logcmp_store *);
int	logcmp_store_query_next(struct logcmp_store *, const char *, uint32_t,
	    struct logcmp_store_cursor *, void *, size_t, size_t *);
int	logcmp_store_query_next_filtered(struct logcmp_store *, const char *,
	    uint32_t, const struct logcmp_query_filter *,
	    struct logcmp_store_cursor *, void *, size_t, size_t *);
uint64_t logcmp_store_generation(const struct logcmp_store *);
uint64_t logcmp_store_label_count(const struct logcmp_store *, const char *);
off_t	logcmp_store_offset(const struct logcmp_store *);
void	logcmp_store_close(struct logcmp_store *);

/*
 * Retention policy.  max_age_s prunes completed segments older than that many
 * seconds; max_bytes prunes oldest completed segments while the whole store
 * (active segment included in the accounting) exceeds that many bytes.  Either
 * 0 disables that dimension; 0/0 is keep-all (today's behaviour).  Enforcement
 * only ever removes whole completed (rotated) segments -- never the active
 * segment and never a partial record.
 */
void	logcmp_store_set_retention(struct logcmp_store *, uint64_t, uint64_t);
int	logcmp_store_enforce_retention(struct logcmp_store *);

/*
 * Involuntary capability cleanup (docs/capability-lifecycle-cleanup.md).  When a
 * consumer bundle's label is retired, drop that label's records from the store.
 *
 * Mechanism: this is a *logical* prune.  The label is recorded in a bounded
 * reclaimed-labels set that the query path and the per-label count treat as
 * empty, so the label's records become invisible immediately.  It is
 * owner-scoped (only the named label is affected, exactly like the QUERY
 * own-label scoping), idempotent (a repeated reclaim, or one for a label that
 * never wrote, is a no-op success), and never rewrites, corrupts, or drops any
 * other label's records or the active segment.  A per-label physical excision
 * from the shared segment files would have to rewrite live segments and risk
 * corrupting other labels' records, so it is deliberately not done here: the
 * reclaimed records' bytes are released physically as their whole segments age
 * out through the existing retention path (logcmp_store_enforce_retention).
 *
 * Returns 0 on success (including the idempotent no-op), or -1 with errno set to
 * EINVAL for a malformed label or ENOSPC if the reclaimed set is full.
 */
int	logcmp_store_reclaim_label(struct logcmp_store *, const char *);
uint64_t logcmp_store_pruned_segments(const struct logcmp_store *);
uint64_t logcmp_store_pruned_records(const struct logcmp_store *);

/* Produce a record which contains no private source values. */
int	logcmp_record_redact(const struct logcmp_record *, size_t,
	    const uint8_t [LOGCMP_STORE_PRIVACY_KEY_SIZE], void *, size_t,
	    size_t *);

#endif
