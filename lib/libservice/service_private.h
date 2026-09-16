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

/*
 * Fill the anointment set of a switchboard mint request (libservice.c);
 * shared by the bootstrap-channel and raw-fd mint paths.  `names` is an
 * array of SERVICE_ANOINT_NAME_MAX (== SVC_ANOINT_NAME_MAX == 64) byte
 * NUL-terminated strings.
 */
struct svc_mint_domain_req;
int	service_mint_req_anoint(struct svc_mint_domain_req *,
	    const char (*)[64], unsigned, bool, bool);

#endif
