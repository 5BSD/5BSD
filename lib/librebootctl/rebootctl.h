/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _REBOOTCTL_H_
#define	_REBOOTCTL_H_

#include <sys/types.h>
#include <stdbool.h>
#include <stddef.h>
#include "rebootctl_protocol.h"

struct rebootctl_client;

__BEGIN_DECLS
int	rebootctl_client_open(struct rebootctl_client **);
void	rebootctl_client_close(struct rebootctl_client *);
int	rebootctl_reboot(struct rebootctl_client *, uint32_t);
int	rebootctl_shutdown(struct rebootctl_client *);
int	rebootctl_reboot_after(struct rebootctl_client *, uint32_t, uint32_t);
int	rebootctl_shutdown_after(struct rebootctl_client *, uint32_t);
int	rebootctl_cancel(struct rebootctl_client *);
int	rebootctl_status(struct rebootctl_client *, bool *);
int	rebootctl_status_detailed(struct rebootctl_client *,
	    struct rebootctl_status_reply *);
int	rebootctl_notification_decode(const char *, const void *, size_t,
	    struct rebootctl_notification *);
__END_DECLS

#endif
