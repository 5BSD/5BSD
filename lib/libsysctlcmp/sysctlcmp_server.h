/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _SYSCTLCMP_SERVER_H_
#define	_SYSCTLCMP_SERVER_H_
#include <sys/types.h>
#include <stddef.h>
#include "sysctlcmp_protocol.h"
__BEGIN_DECLS
int	sysctlcmp_message_init(struct sysctlcmp_msg *, uint16_t, uint32_t);
int	sysctlcmp_message_init_reply(struct sysctlcmp_msg *,
	    const struct sysctlcmp_msg *, int);
int	sysctlcmp_validate_message(const struct sysctlcmp_msg *, size_t,
	    enum sysctlcmp_message_role);
__END_DECLS
#endif
