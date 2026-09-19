/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _TRACECMP_POLICY_H_
#define	_TRACECMP_POLICY_H_

#include <sys/types.h>

#include <stdbool.h>

#define	TRACECMP_POLICY_MAX_LABELS	256
#define	TRACECMP_POLICY_LABEL_SIZE	64
#define	TRACECMP_POLICY_FILE_MAX	(64 * 1024)
#define	TRACECMP_POLICY_PATH		"/etc/traced.allow"

struct tracecmp_policy {
	char	labels[TRACECMP_POLICY_MAX_LABELS][TRACECMP_POLICY_LABEL_SIZE];
	size_t	count;
};

int	tracecmp_policy_load(const char *, struct tracecmp_policy *);
int	tracecmp_policy_load_fd(int, struct tracecmp_policy *);
bool	tracecmp_policy_allows(const struct tracecmp_policy *, const char *);

#endif
