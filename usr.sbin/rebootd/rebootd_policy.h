/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _REBOOTD_POLICY_H_
#define	_REBOOTD_POLICY_H_

#include <sys/types.h>

#include <stdbool.h>

#define	REBOOTD_POLICY_MAX_LABELS	256
#define	REBOOTD_POLICY_LABEL_SIZE	64
#define	REBOOTD_POLICY_FILE_MAX		(64 * 1024)
#define	REBOOTD_POLICY_PATH		"/etc/rebootd.allow"

struct rebootd_policy {
	char	labels[REBOOTD_POLICY_MAX_LABELS][REBOOTD_POLICY_LABEL_SIZE];
	size_t	count;
};

int	rebootd_policy_load(const char *, struct rebootd_policy *);
bool	rebootd_policy_allows(const struct rebootd_policy *, const char *);

#endif
