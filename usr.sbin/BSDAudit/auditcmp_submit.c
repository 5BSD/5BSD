/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <auditcmp.h>

#include "auditcmp_submit.h"

int
auditcmp_submit_record(const char *provider, int event,
    const struct auditcmp_submit_request *request, bool rate_allowed,
    const struct auditcmp_backend *backend)
{
	char operation[AUDITCMP_MAX_OPERATION + 1];
	char subject[AUDITCMP_MAX_SUBJECT + 1];
	int error;

	if (provider == NULL || request == NULL || backend == NULL ||
	    backend->submit == NULL)
		return (EINVAL);
	if (event == 0)
		return (EACCES);
	if (!rate_allowed)
		return (EAGAIN);
	if (request->subject_length == 0 ||
	    request->subject_length > AUDITCMP_MAX_SUBJECT ||
	    request->operation_length == 0 ||
	    request->operation_length > AUDITCMP_MAX_OPERATION)
		return (EINVAL);
	memcpy(subject, request->subject, request->subject_length);
	subject[request->subject_length] = '\0';
	memcpy(operation, request->operation, request->operation_length);
	operation[request->operation_length] = '\0';
	if (memchr(subject, '\0', request->subject_length) != NULL ||
	    memchr(operation, '\0', request->operation_length) != NULL)
		return (EINVAL);
	if (backend->submit(event, request->error, provider, subject, operation,
	    backend->context) == -1) {
		error = errno;
		return (error != 0 ? error : EIO);
	}
	return (0);
}
