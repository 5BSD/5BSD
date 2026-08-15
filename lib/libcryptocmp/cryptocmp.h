/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _CRYPTOCMP_H_
#define _CRYPTOCMP_H_
#include "cryptocmp_protocol.h"
__BEGIN_DECLS
struct cryptocmp_client;
int cryptocmp_open(struct cryptocmp_client **);
void cryptocmp_close(struct cryptocmp_client *);
int cryptocmp_generate(struct cryptocmp_client *, const struct cryptocmp_generate *, int *);
int cryptocmp_generate_key(struct cryptocmp_client *,
    const struct cryptocmp_key_generate *, uint8_t public_key[32], int *);
__END_DECLS
#endif
