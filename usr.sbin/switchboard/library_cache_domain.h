/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_LIBRARY_CACHE_DOMAIN_H
#define SWITCHBOARD_LIBRARY_CACHE_DOMAIN_H
#include <stdbool.h>
struct svc_cache_domain {
	int control_fd;
	int backing_fd;
};
int svc_cache_domain_create(int, int, const char *, const char *, struct svc_cache_domain *);
int svc_cache_domain_bind(int, const struct svc_cache_domain *, int, bool);
int svc_cache_domain_publish(int, const struct svc_cache_domain *);
void svc_cache_domain_close(struct svc_cache_domain *);
#endif
