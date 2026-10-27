/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_NSS_EXCHANGE_H
#define SWITCHBOARD_NSS_EXCHANGE_H
#include "nss-helper/nss_protocol.h"
/* diagnostic must refer to harmless storage, never an authority-bearing fd.
 * timeout_ms covers setup, reply and child exit. On failure out is zeroed.
 * A timed-out child is killed through its process descriptor; last close
 * delegates eventual reaping to the kernel rather than waiting indefinitely. */
int sb_nss_exchange(const char *, int diagnostic, const struct sb_nss_request *,
    uid_t owner, int timeout_ms, struct sb_nss_reply *out);
#endif
