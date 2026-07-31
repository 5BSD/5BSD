/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NOTIFYCMP_TRANSPORT_H_
#define	_NOTIFYCMP_TRANSPORT_H_

#include <sys/types.h>

#include <stddef.h>

int	internal_send(int, const void *, size_t,
	    enum notifycmp_message_role);
ssize_t	internal_receive(int, void *, size_t,
	    enum notifycmp_message_role);
int	internal_send_fd(int, const void *, size_t, int);
ssize_t	internal_receive_fd(int, void *, size_t, int *);

#endif
