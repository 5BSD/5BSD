/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NETWORKCMP_IO_H_
#define	_NETWORKCMP_IO_H_

#include <networkcmp_protocol.h>

struct networkcmp_session;

int	networkcmp_io_send(struct networkcmp_session *,
	    const struct networkcmp_inline_request *,
	    struct networkcmp_inline_reply *);
int	networkcmp_io_recv(struct networkcmp_session *,
	    const struct networkcmp_inline_request *,
	    struct networkcmp_inline_reply *, void *);

#endif
