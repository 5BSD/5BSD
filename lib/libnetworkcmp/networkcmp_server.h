/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _NETWORKCMP_SERVER_H_
#define	_NETWORKCMP_SERVER_H_

#include <sys/types.h>

#include <stddef.h>

#include "networkcmp_protocol.h"

__BEGIN_DECLS
int	networkcmp_validate_message(const struct networkcmp_msg *, size_t,
	    enum networkcmp_message_role);
int	networkcmp_message_init(struct networkcmp_msg *, uint16_t, uint32_t);
int	networkcmp_message_init_reply(struct networkcmp_msg *,
	    const struct networkcmp_msg *, int);
int	networkcmp_validate_fds(const struct networkcmp_msg *, size_t,
	    enum networkcmp_message_role);
__END_DECLS

#endif /* !_NETWORKCMP_SERVER_H_ */
