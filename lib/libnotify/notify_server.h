/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _NOTIFY_SERVER_H_
#define	_NOTIFY_SERVER_H_
#include <sys/types.h>
#include <stddef.h>
#include "notify_protocol.h"
__BEGIN_DECLS
int notify_validate_topic(const char *, size_t);
int notify_validate_message(const struct notify_msg *, size_t,
    enum notify_message_role);
int notify_message_init(struct notify_msg *, uint16_t, uint32_t);
int notify_message_init_reply(struct notify_msg *,
    const struct notify_msg *, int);
__END_DECLS
#endif
