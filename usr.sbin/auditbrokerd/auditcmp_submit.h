/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _AUDITCMP_SUBMIT_H_
#define	_AUDITCMP_SUBMIT_H_

#include <stdbool.h>

struct auditcmp_submit_request;

struct auditcmp_backend {
	int	(*submit)(int, int, const char *, const char *, const char *,
	    void *);
	void	*context;
};

int	auditcmp_submit_record(const char *, int,
	    const struct auditcmp_submit_request *, bool,
	    const struct auditcmp_backend *);

#endif /* !_AUDITCMP_SUBMIT_H_ */
