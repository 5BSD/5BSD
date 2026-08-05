/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/reboot.h>

#include <errno.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>

#include <rebootctl.h>

#include "rebootd_ops.h"

int
rebootd_validate(uint16_t opcode, const struct rebootctl_request *request,
    bool allowed, int *howtop)
{
	int howto;

	if (howtop == NULL)
		return (EINVAL);
	switch (opcode) {
	case REBOOTCTL_OP_STATUS:
		return (0);
	case REBOOTCTL_OP_CANCEL:
		return (allowed ? 0 : EACCES);
	case REBOOTCTL_OP_REBOOT:
	case REBOOTCTL_OP_SHUTDOWN:
		break;
	default:
		return (EOPNOTSUPP);
	}
	if (!allowed)
		return (EACCES);
	if (opcode == REBOOTCTL_OP_REBOOT) {
		if (request == NULL ||
		    (request->howto & ~REBOOTCTL_ALLOWED_FLAGS) != 0 ||
		    request->delay_ms > REBOOTCTL_MAX_DELAY_MS)
			return (EINVAL);
		howto = request->howto;
	} else {
		if (request != NULL && (request->howto != 0 ||
		    request->delay_ms > REBOOTCTL_MAX_DELAY_MS))
			return (EINVAL);
		howto = RB_HALT | RB_POWEROFF;
	}
	*howtop = howto;
	return (0);
}

int
rebootd_execute(uint16_t opcode, const struct rebootctl_request *request,
    bool allowed, _Atomic bool *pending, const struct rebootd_backend *backend)
{
	bool expected;
	int error, howto;

	if (pending == NULL || backend == NULL || backend->reboot == NULL)
		return (EINVAL);
	error = rebootd_validate(opcode, request, allowed, &howto);
	if (error != 0 || opcode == REBOOTCTL_OP_STATUS)
		return (error);
	if (opcode == REBOOTCTL_OP_CANCEL) {
		expected = true;
		return (atomic_compare_exchange_strong_explicit(pending,
		    &expected, false, memory_order_acq_rel, memory_order_acquire) ?
		    0 : ENOENT);
	}
	expected = false;
	if (!atomic_compare_exchange_strong_explicit(pending, &expected, true,
	    memory_order_acq_rel, memory_order_acquire))
		return (EALREADY);
	if (backend->reboot(howto, backend->context) == -1) {
		error = errno;
		atomic_store_explicit(pending, false, memory_order_release);
		return (error != 0 ? error : EIO);
	}
	return (0);
}
