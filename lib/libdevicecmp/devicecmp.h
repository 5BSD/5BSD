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
 * Enumerate the devices the caller's label is permitted to open through
 * system.Device, so a consumer can discover its openable set without blind
 * trial-and-error.  `cursor` is 0 for the first page or a prior call's
 * *next_cursor; up to `max` entries (capped at DEVICECMP_LIST_MAX per call) are
 * written to `entries`, with *countp set to the number filled and *next_cursor
 * set to the cursor to re-issue for the next page (0 == final page).  The result
 * is owner-scoped by the provider to the caller's own label; a label with no
 * policy lists empty (returns 0, *countp == 0).  On failure returns -1 with
 * errno set.  Fails closed.
 */
int	devicecmp_list(struct service_context *ctx, uint32_t cursor,
	    struct devicecmp_list_entry *entries, uint32_t max,
	    uint32_t *countp, uint32_t *next_cursor);

/*
 * Liveness probe: exchange a HELLO with the provider.  Returns 0 on a valid
 * reply, -1 with errno otherwise.
 */
int	devicecmp_hello(struct service_context *ctx);
__END_DECLS

#endif /* !_DEVICECMP_H_ */
