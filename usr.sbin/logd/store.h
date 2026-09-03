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

#define	LOGCMP_STORE_SEGMENT_MIN	(64U * 1024)
#define	LOGCMP_STORE_SEGMENT_MAX	(UINT64_C(4) * 1024 * 1024 * 1024)
#define	LOGCMP_STORE_SEGMENTS_DEFAULT	64U
#define	LOGCMP_STORE_SEGMENTS_MIN	1U
#define	LOGCMP_STORE_SEGMENTS_MAX	1024U

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
uint64_t logcmp_store_generation(const struct logcmp_store *);
uint64_t logcmp_store_label_count(const struct logcmp_store *, const char *);
off_t	logcmp_store_offset(const struct logcmp_store *);
void	logcmp_store_close(struct logcmp_store *);

/* Produce a record which contains no private source values. */
int	logcmp_record_redact(const struct logcmp_record *, size_t,
	    const uint8_t [LOGCMP_STORE_PRIVACY_KEY_SIZE], void *, size_t,
	    size_t *);

#endif
