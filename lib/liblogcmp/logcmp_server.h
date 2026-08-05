/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LOGCMP_SERVER_H_
#define	_LOGCMP_SERVER_H_
#include <sys/types.h>
#include <stddef.h>
#include "logcmp_protocol.h"
__BEGIN_DECLS
int logcmp_validate_message(const struct logcmp_msg *, size_t,
    enum logcmp_message_role);
int logcmp_message_init(struct logcmp_msg *, uint16_t, uint32_t);
int logcmp_message_init_reply(struct logcmp_msg *, const struct logcmp_msg *,
    int);
int logcmp_validate_record(const struct logcmp_record *, size_t);
int logcmp_validate_fds(const struct logcmp_msg *, size_t,
    enum logcmp_message_role);
__END_DECLS
#endif
