/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BHYVE_SNAPSHOT_IDENTITY_H_
#define	_BHYVE_SNAPSHOT_IDENTITY_H_

#include <sys/param.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * Serialize an external-backend identity without importing source bytes into
 * the destination.  Validation and restore consume the complete bounded
 * record and compare it with the already-open destination backend.
 */
static inline int
vm_snapshot_identity_string(const char *current, uint32_t maximum,
    struct vm_snapshot_meta *meta)
{
	char *saved;
	uint32_t current_length, saved_length;
	size_t length, limit;
	int error;

	if (meta == NULL || maximum == 0)
		return (EINVAL);
	if ((size_t)maximum == SIZE_MAX)
		return (EOVERFLOW);
	limit = (size_t)maximum + 1;
	length = current == NULL ? 0 : strnlen(current, limit);
	if (length > maximum || length > UINT32_MAX)
		return (E2BIG);
	current_length = (uint32_t)length;
	saved_length = current_length;
	saved = NULL;
	if (meta->op == VM_SNAPSHOT_SAVE) {
		/*
		 * Preflight the complete record and stage aliased input before the
		 * length field can overwrite it.  A short output buffer therefore
		 * remains unchanged.
		 */
		if (length > SIZE_MAX - sizeof(saved_length) ||
		    meta->buffer.buf_rem < sizeof(saved_length) + length)
			return (E2BIG);
		if (length != 0) {
			saved = malloc(length);
			if (saved == NULL)
				return (ENOMEM);
			memmove(saved, current, length);
		}
	}
	SNAPSHOT_LE32_OR_LEAVE(saved_length, meta, error, done);
	if (saved_length > maximum) {
		error = E2BIG;
		goto done;
	}
	if (meta->op == VM_SNAPSHOT_SAVE) {
		if (saved_length != 0)
			SNAPSHOT_BUF_OR_LEAVE(saved,
			    saved_length, meta, error, done);
		error = 0;
		goto done;
	}
	saved = malloc(MAX(saved_length, 1));
	if (saved == NULL) {
		error = ENOMEM;
		goto done;
	}
	SNAPSHOT_BUF_OR_LEAVE(saved, saved_length, meta, error, free_saved);
	error = saved_length == current_length &&
	    (saved_length == 0 ||
	    memcmp(saved, current, saved_length) == 0) ? 0 : EINVAL;
free_saved:
done:
	free(saved);
	return (error);
}

#endif /* _BHYVE_SNAPSHOT_IDENTITY_H_ */
