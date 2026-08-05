/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _AUDITCMP_SERVER_H_
#define	_AUDITCMP_SERVER_H_
#include <sys/types.h>
#include <stddef.h>
#include "auditcmp_protocol.h"
struct auditcmp_client;
__BEGIN_DECLS
int auditcmp_client_prepare(int *);
int auditcmp_client_adopt(int, struct auditcmp_client **);
int auditcmp_message_init(struct auditcmp_msg *, uint16_t, uint32_t);
int auditcmp_message_init_reply(struct auditcmp_msg *,
    const struct auditcmp_msg *, int);
int auditcmp_validate_message(const struct auditcmp_msg *, size_t,
    enum auditcmp_message_role);
int auditcmp_validate_fds(const struct auditcmp_msg *, size_t,
    enum auditcmp_message_role);
__END_DECLS
#endif
