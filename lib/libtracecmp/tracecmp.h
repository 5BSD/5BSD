/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _TRACECMP_H_
#define	_TRACECMP_H_

#include <sys/types.h>

#include <stddef.h>

#include "tracecmp_protocol.h"

__BEGIN_DECLS
int	tracecmp_open(int *);
int	tracecmp_validate_message(const struct tracecmp_msg *, size_t,
	    enum tracecmp_message_role);
int	tracecmp_message_init(struct tracecmp_msg *, uint16_t, uint32_t);
int	tracecmp_message_init_reply(struct tracecmp_msg *,
	    const struct tracecmp_msg *, int);
int	tracecmp_validate_fds(const struct tracecmp_msg *, size_t,
	    enum tracecmp_message_role);
__END_DECLS

#endif
