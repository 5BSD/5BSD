/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NOTIFY_TRANSPORT_H_
#define	_NOTIFY_TRANSPORT_H_

#include <sys/types.h>

#include <stddef.h>

int	internal_send(int, const void *, size_t,
	    enum notify_message_role);
ssize_t	internal_receive(int, void *, size_t,
	    enum notify_message_role);
#endif
