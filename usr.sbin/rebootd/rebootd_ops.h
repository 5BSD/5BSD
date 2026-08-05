/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _REBOOTD_OPS_H_
#define	_REBOOTD_OPS_H_

#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>

struct rebootctl_request;

struct rebootd_backend {
	int	(*reboot)(int, void *);
	void	*context;
};

int	rebootd_validate(uint16_t, const struct rebootctl_request *, bool,
	    int *);
int	rebootd_execute(uint16_t, const struct rebootctl_request *, bool,
	    _Atomic bool *, const struct rebootd_backend *);

#endif /* !_REBOOTD_OPS_H_ */
