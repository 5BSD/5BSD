/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _LOGCMP_SESSION_H_
#define	_LOGCMP_SESSION_H_

#include <stdint.h>

#include <logcmp.h>
#include <shmring.h>

struct logcmp_session {
	struct shmring		*ring;
	struct logcmp_stats	stats;
	uint32_t		max_record;
};

typedef int (*logcmp_sink_fn)(void *, const struct logcmp_record *,
    const char *, const char *);

void	logcmp_session_init(struct logcmp_session *, uint32_t);
void	logcmp_session_destroy(struct logcmp_session *);
int	logcmp_session_attach(struct logcmp_session *,
	    const struct logcmp_attach_request *, const struct shmring_fds *);
int	logcmp_session_detach(struct logcmp_session *);
int	logcmp_session_submit(struct logcmp_session *,
	    const struct logcmp_record *, size_t, logcmp_sink_fn, void *);
int	logcmp_session_drain(struct logcmp_session *, logcmp_sink_fn, void *);

#endif
