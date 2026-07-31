/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * libservice implementation-test hooks.  This header is not installed.
 */

#ifndef _LIBSERVICE_PRIVATE_H_
#define	_LIBSERVICE_PRIVATE_H_

struct service_context;

int	service_private_control_fd(struct service_context *);

#endif
