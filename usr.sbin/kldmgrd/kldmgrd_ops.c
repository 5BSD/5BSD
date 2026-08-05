/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/linker.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <kldmgr.h>

#include "kldmgrd_ops.h"

int
kldmgrd_module_name_valid(const char *name, size_t length)
{
	size_t i, name_length;

	if (name == NULL || length == 0)
		return (0);
	name_length = strnlen(name, length);
	if (name_length == 0 || name_length >= length)
		return (0);
	for (i = 0; i < name_length; i++) {
		if ((name[i] >= 'a' && name[i] <= 'z') ||
		    (name[i] >= 'A' && name[i] <= 'Z') ||
		    (name[i] >= '0' && name[i] <= '9') ||
		    name[i] == '_' || name[i] == '-' || name[i] == '.')
			continue;
		return (0);
	}
	return (1);
}

int
kldmgrd_execute_module(uint16_t opcode,
    const struct kldmgr_module_request *request, bool allowed,
    const struct kldmgrd_backend *backend, int *result_id)
{
	int id, saved_error;

	if (result_id == NULL)
		return (EINVAL);
	*result_id = -1;
	if (request == NULL || backend == NULL || backend->load == NULL ||
	    backend->find == NULL || backend->unload == NULL)
		return (EINVAL);
	if (!allowed)
		return (EACCES);
	if (!kldmgrd_module_name_valid(request->name, sizeof(request->name)))
		return (EINVAL);
	switch (opcode) {
	case KLDMGR_OP_LOAD:
		id = backend->load(request->name, backend->context);
		if (id == -1) {
			saved_error = errno;
			return (saved_error != 0 ? saved_error : EIO);
		}
		*result_id = id;
		return (0);
	case KLDMGR_OP_UNLOAD:
		id = backend->find(request->name, backend->context);
		if (id == -1) {
			saved_error = errno;
			return (saved_error != 0 ? saved_error : EIO);
		}
		if (backend->unload(id, backend->context) == -1) {
			saved_error = errno;
			return (saved_error != 0 ? saved_error : EIO);
		}
		*result_id = id;
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

int
kldmgrd_list(bool allowed, const struct kldmgrd_backend *backend,
    struct kldmgr_list_entry *entries, size_t capacity, size_t *count)
{
	struct kld_file_stat status;
	size_t used;
	int error, id;

	if (count == NULL)
		return (EINVAL);
	*count = 0;
	if (backend == NULL || backend->next == NULL || backend->stat == NULL ||
	    (capacity != 0 && entries == NULL))
		return (EINVAL);
	if (!allowed)
		return (EACCES);
	used = 0;
	id = 0;
	while (used < capacity) {
		id = backend->next(id, backend->context);
		if (id == -1) {
			error = errno;
			return (error != 0 ? error : EIO);
		}
		if (id == 0)
			break;
		memset(&status, 0, sizeof(status));
		status.version = sizeof(status);
		if (backend->stat(id, &status, backend->context) == -1) {
			error = errno;
			return (error != 0 ? error : EIO);
		}
		entries[used].id = id;
		strlcpy(entries[used].name, status.name,
		    sizeof(entries[used].name));
		used++;
	}
	*count = used;
	return (0);
}
