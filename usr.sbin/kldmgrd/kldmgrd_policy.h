/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _KLDMGRD_POLICY_H_
#define	_KLDMGRD_POLICY_H_

#include <sys/types.h>

#include <stdbool.h>

#define	KLDMGRD_POLICY_MAX_LABELS	256
#define	KLDMGRD_POLICY_LABEL_SIZE	64
#define	KLDMGRD_POLICY_FILE_MAX		(64 * 1024)
#define	KLDMGRD_POLICY_PATH		"/etc/kldmgrd.allow"

struct kldmgrd_policy {
	char	labels[KLDMGRD_POLICY_MAX_LABELS][KLDMGRD_POLICY_LABEL_SIZE];
	size_t	count;
};

int	kldmgrd_policy_load(const char *, struct kldmgrd_policy *);
bool	kldmgrd_policy_allows(const struct kldmgrd_policy *, const char *);

#endif
