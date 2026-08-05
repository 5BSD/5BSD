/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _KLDMGR_H_
#define	_KLDMGR_H_

#include <sys/types.h>
#include <stddef.h>
#include "kldmgr_protocol.h"

struct kldmgr_client;

__BEGIN_DECLS
int	kldmgr_client_open(struct kldmgr_client **);
void	kldmgr_client_close(struct kldmgr_client *);
int	kldmgr_load(struct kldmgr_client *, const char *, int *);
int	kldmgr_unload(struct kldmgr_client *, const char *, int *);
int	kldmgr_list(struct kldmgr_client *, struct kldmgr_list_entry *,
	    size_t, size_t *);
__END_DECLS

#endif
