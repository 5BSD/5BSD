/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _REBOOTCTL_SERVER_H_
#define	_REBOOTCTL_SERVER_H_
#include <sys/types.h>
#include <stddef.h>
#include "rebootctl_protocol.h"
__BEGIN_DECLS
int rebootctl_validate_request(const struct rebootctl_msg *, size_t);
int rebootctl_validate_reply(const struct rebootctl_msg *, size_t);
__END_DECLS
#endif
