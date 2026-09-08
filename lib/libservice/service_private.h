/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * libservice implementation-test hooks.  This header is not installed.
 */

#ifndef _LIBSERVICE_PRIVATE_H_
#define	_LIBSERVICE_PRIVATE_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct service_context;

bool	service_provider_status_valid(int32_t);
bool	service_provider_all_zero(const void *, size_t);
bool	service_provider_component_valid(const char *, size_t);

int	service_private_control_fd(struct service_context *);

#endif
