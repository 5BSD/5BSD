/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _DEVICECMP_H_
#define _DEVICECMP_H_

#include <sys/cdefs.h>
#include <stdint.h>

#include "devicecmp_protocol.h"

struct service_context;

__BEGIN_DECLS
/*
 * Open a named /dev leaf through system.Device and receive a rights-limited,
 * non-forwardable descriptor.  `name` is a single /dev component (no '/', no
 * leading '.', no ".."); `want_rights` is a DEVICECMP_RIGHT_* mask.  On success
 * returns 0, *fdp holds the delivered descriptor (caller closes it) and, when
 * non-NULL, *granted_rights holds the rights the provider actually granted
 * (want_rights intersected with the per-label policy maximum).  On failure
 * returns -1 with errno set and *fdp left as -1.  Fails closed.
 *
 * `ctx` is the process serviced context (may be NULL for a standalone caller);
 * the provider session is opened by name once and cached for the process.
 */
int	devicecmp_open(struct service_context *ctx, const char *name,
	    uint32_t want_rights, uint32_t *granted_rights, int *fdp);

/*
 * Liveness probe: exchange a HELLO with the provider.  Returns 0 on a valid
 * reply, -1 with errno otherwise.
 */
int	devicecmp_hello(struct service_context *ctx);
__END_DECLS

#endif /* !_DEVICECMP_H_ */
