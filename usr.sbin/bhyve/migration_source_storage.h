/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BHYVE_MIGRATION_SOURCE_STORAGE_H_
#define _BHYVE_MIGRATION_SOURCE_STORAGE_H_
#include "migration_source_owner.h"

struct migration_source_storage {
	int directory;
	int error;
	bool prepared;
};

/* Run before cap_enter and before publishing the IPC thread. Keep failures
 * too: a request must not substitute another root after sandbox entry. */
static inline int
migration_source_storage_prepare(struct migration_source_storage *storage)
{
	if (storage == NULL)
		return (EINVAL);
	if (!storage->prepared) {
		storage->directory = -1;
		storage->error = migration_source_canonical_root_open(&storage->directory);
		storage->prepared = true;
	}
	return (storage->error);
}

static inline int
migration_source_storage_check(struct migration_source_storage *storage,
    int requested)
{
	if (storage == NULL || !storage->prepared)
		return (ENXIO);
	if (storage->error != 0)
		return (storage->error);
	return (migration_source_root_pin(&storage->directory, requested));
}
#endif
