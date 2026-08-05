/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _AUDITCMP_H_
#define	_AUDITCMP_H_

#include <sys/types.h>

#include <stddef.h>

#include "auditcmp_protocol.h"

struct auditcmp_client;

__BEGIN_DECLS
int	auditcmp_client_open(struct auditcmp_client **);
void	auditcmp_client_close(struct auditcmp_client *);
int	auditcmp_submit(struct auditcmp_client *, const char *, const char *,
	    int);
int	auditcmp_stats(struct auditcmp_client *, struct auditcmp_stats *);

__END_DECLS

#endif
