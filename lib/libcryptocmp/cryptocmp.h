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
int cryptocmp_digest(struct cryptocmp_client *, uint32_t alg, uint32_t ttl,
    uint32_t flags, int *);
int cryptocmp_random(struct cryptocmp_client *, void *, size_t);
int cryptocmp_named_create(struct cryptocmp_client *, const char *,
    const struct cryptocmp_generate *, uint64_t *);
int cryptocmp_named_lease(struct cryptocmp_client *, const char *, uint32_t,
    uint32_t, uint64_t *, int *);
int cryptocmp_named_rotate(struct cryptocmp_client *, const char *, uint64_t *);
int cryptocmp_named_delete(struct cryptocmp_client *, const char *, uint64_t *);
__END_DECLS
#endif
