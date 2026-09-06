/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _TRACECMP_H_
#define	_TRACECMP_H_

#include <sys/types.h>

#include <stddef.h>
#include <dtrace.h>

#include "tracecmp_protocol.h"

__BEGIN_DECLS
int	tracecmp_open(int *);
int	tracecmp_stats(struct tracecmp_stats *);
dtrace_hdl_t *tracecmp_dtrace_open(int, int *);
__END_DECLS

#endif
