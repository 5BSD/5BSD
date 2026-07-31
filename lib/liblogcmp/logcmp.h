/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _LOGCMP_H_
#define	_LOGCMP_H_

#include <sys/types.h>

#include <stddef.h>

#include "logcmp_protocol.h"

struct logcmp_client;

__BEGIN_DECLS

int	logcmp_client_open(struct logcmp_client **);
void	logcmp_client_close(struct logcmp_client *);
int	logcmp_log(struct logcmp_client *, uint32_t, const char *,
	    const char *);
int	logcmp_flush(struct logcmp_client *);
int	logcmp_stats(struct logcmp_client *, struct logcmp_stats *);

int	logcmp_validate_message(const struct logcmp_msg *, size_t,
	    enum logcmp_message_role);
int	logcmp_message_init(struct logcmp_msg *, uint16_t, uint32_t);
int	logcmp_message_init_reply(struct logcmp_msg *,
	    const struct logcmp_msg *, int);
int	logcmp_validate_record(const struct logcmp_record *, size_t);
int	logcmp_validate_fds(const struct logcmp_msg *, size_t,
	    enum logcmp_message_role);

__END_DECLS

#endif
