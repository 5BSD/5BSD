/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_MANAGEMENT_POLICY_H
#define SWITCHBOARD_MANAGEMENT_POLICY_H

#include <sys/types.h>
#include <stdbool.h>
#include <stddef.h>

struct svc_runtime;

/* Boot-selected opt-in. Never derived from a requesting process's environment. */
void svc_management_policy_init(void);
int svc_management_authorize(const struct svc_runtime *, const char *, uid_t,
    bool);
/* Pure evaluator: caller supplies authenticated identity and resolved target. */
int svc_management_policy_fd(int, uid_t, const char *, const char *,
    const char *, char *, size_t);
#endif
