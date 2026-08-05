/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _KLDMGR_SERVER_H_
#define	_KLDMGR_SERVER_H_
#include <sys/types.h>
#include <stddef.h>
#include "kldmgr_protocol.h"
__BEGIN_DECLS
int kldmgr_validate_request(const struct kldmgr_msg *, size_t);
int kldmgr_validate_reply(const struct kldmgr_msg *, size_t);
__END_DECLS
#endif
