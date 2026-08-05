/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _NOTIFYCMP_SERVER_H_
#define	_NOTIFYCMP_SERVER_H_
#include <sys/types.h>
#include <stddef.h>
#include "notifycmp_protocol.h"
__BEGIN_DECLS
int notifycmp_validate_topic(const char *, size_t);
int notifycmp_validate_message(const struct notifycmp_msg *, size_t,
    enum notifycmp_message_role);
int notifycmp_message_init(struct notifycmp_msg *, uint16_t, uint32_t);
int notifycmp_message_init_reply(struct notifycmp_msg *,
    const struct notifycmp_msg *, int);
__END_DECLS
#endif
