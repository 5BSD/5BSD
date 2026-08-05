/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _FILESYSTEMCMP_SERVER_H_
#define	_FILESYSTEMCMP_SERVER_H_

#include <sys/types.h>

#include <stddef.h>

#include "filesystemcmp_protocol.h"

__BEGIN_DECLS
int	filesystemcmp_validate_message(const struct filesystemcmp_msg *,
	    size_t, enum filesystemcmp_message_role);
int	filesystemcmp_message_init(struct filesystemcmp_msg *, uint16_t,
	    uint32_t);
int	filesystemcmp_message_init_reply(struct filesystemcmp_msg *,
	    const struct filesystemcmp_msg *, int);
int	filesystemcmp_validate_fds(const struct filesystemcmp_msg *, size_t,
	    enum filesystemcmp_message_role);
__END_DECLS

#endif /* !_FILESYSTEMCMP_SERVER_H_ */
