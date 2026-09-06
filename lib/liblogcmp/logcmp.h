/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _LOGCMP_H_
#define	_LOGCMP_H_

#include <sys/types.h>

#include <stdarg.h>
#include <stddef.h>

#include "logcmp_protocol.h"

struct logcmp_client;
struct logcmp_logger;

struct logcmp_attribute {
	size_t		size;
	const char	*key;
	uint8_t		type;
	uint8_t		privacy;
	uint16_t	reserved;
	const void	*value;
	size_t		value_length;
};

struct logcmp_emit_options {
	size_t		size;
	uint32_t	severity;
	uint32_t	kind;
	uint32_t	message_privacy;
	uint32_t	flags;
	const char	*event_name;
	const char	*message;
	const struct logcmp_attribute *attributes;
	size_t		nattributes;
	uint64_t	timestamp_ns;
	uint64_t	activity_id;
	uint64_t	signpost_id;
	uint8_t		trace_id[16];
	uint8_t		span_id[8];
};

__BEGIN_DECLS

int	logcmp_client_open(struct logcmp_client **);
void	logcmp_client_close(struct logcmp_client *);
int	logcmp_logger_create(struct logcmp_client *, const char *,
	    const char *, struct logcmp_logger **);
void	logcmp_logger_destroy(struct logcmp_logger *);
int	logcmp_emit(struct logcmp_logger *,
	    const struct logcmp_emit_options *);
int	logcmp_flush(struct logcmp_client *);

/*
 * Capability-mode-safe syslog(3) replacement.  Emits to system.Log through a
 * process-lifetime logger opened lazily on first use (component name =
 * getprogname(), category "log"), and falls back to syslog(3) whenever
 * system.Log is unreachable -- before the plane is up, in a pre-capmode launch,
 * or if logd is down.  Fail-soft: never blocks, never fails the caller, and
 * preserves errno so a trailing "%m" still reports the caller's error.  This is
 * the one sink every capability daemon should use after cap_enter(2), replacing
 * a bare syslog(3) whose /var/run/log socket is unreachable in capability mode.
 */
void	logcmp_log(int priority, const char *fmt, ...) __printflike(2, 3);
void	logcmp_vlog(int priority, const char *fmt, va_list ap);
int	logcmp_stats(struct logcmp_client *, struct logcmp_stats *);
int	logcmp_query_next(struct logcmp_client *, uint32_t,
	    struct logcmp_query_cursor *, void *, size_t, size_t *);

__END_DECLS

#endif
