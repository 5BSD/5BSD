/*- SPDX-License-Identifier: BSD-2-Clause */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <filesystemcmp.h>

#include "rebootd_state.h"
#include "rebootd_store.h"

#define	REBOOTD_STATE_FILE	"schedule"
#define	REBOOTD_STATE_TEMP	"schedule.new"

struct rebootd_store {
	struct filesystemcmp_client *client;
	struct filesystemcmp_handle root;
};

static void
close_handle(struct rebootd_store *store, struct filesystemcmp_handle handle)
{

	(void)filesystemcmp_close_handle(store->client, handle);
}

int
rebootd_store_open(struct rebootd_store **storep)
{
	struct rebootd_store *store;
	int error;

	if (storep == NULL)
		return (errno = EINVAL, -1);
	*storep = NULL;
	store = calloc(1, sizeof(*store));
	if (store == NULL)
		return (-1);
	if (filesystemcmp_open(&store->client) == -1 ||
	    filesystemcmp_open_namespace(store->client,
	    FILESYSTEMCMP_NAMESPACE_PERSISTENT, &store->root) == -1) {
		error = errno != 0 ? errno : EIO;
		filesystemcmp_close(store->client);
		free(store);
		return (errno = error, -1);
	}
	*storep = store;
	return (0);
}

int
rebootd_store_load(struct rebootd_store *store,
    struct rebootd_state_record *record)
{
	struct filesystemcmp_handle_reply object;
	struct filesystemcmp_stat_reply status;
	ssize_t length;
	int error;

	if (store == NULL || record == NULL)
		return (errno = EINVAL, -1);
	memset(record, 0, sizeof(*record));
	if (filesystemcmp_lookup(store->client, store->root,
	    REBOOTD_STATE_FILE, &object) == -1) {
		if (errno != ENOENT)
			return (-1);
		rebootd_state_seal(record);
		return (rebootd_store_save(store, record, NULL));
	}
	if (filesystemcmp_stat(store->client, object.handle, &status) == -1 ||
	    status.type != FILESYSTEMCMP_TYPE_REGULAR ||
	    status.size != sizeof(*record)) {
		error = errno != 0 ? errno : EPROTO;
		close_handle(store, object.handle);
		return (errno = error, -1);
	}
	length = filesystemcmp_pread(store->client, object.handle, record,
	    sizeof(*record), 0);
	error = errno;
	close_handle(store, object.handle);
	if (length != sizeof(*record))
		return (errno = length < 0 && error != 0 ? error : EPROTO, -1);
	if (!rebootd_state_valid(record))
		return (errno = EPROTO, -1);
	return (0);
}

int
rebootd_store_save(struct rebootd_store *store,
    const struct rebootd_state_record *record, enum rebootd_store_commit *commitp)
{
	struct filesystemcmp_handle_reply temporary;
	ssize_t length;
	int error;

	if (commitp != NULL)
		*commitp = REBOOTD_STORE_NOT_COMMITTED;
	if (store == NULL || !rebootd_state_valid(record))
		return (errno = EINVAL, -1);
	if (filesystemcmp_unlink(store->client, store->root,
	    REBOOTD_STATE_TEMP, 0) == -1 && errno != ENOENT)
		return (-1);
	if (filesystemcmp_create(store->client, store->root,
	    REBOOTD_STATE_TEMP, FILESYSTEMCMP_CREATE_EXCLUSIVE, 0600,
	    &temporary) == -1)
		return (-1);
	length = filesystemcmp_pwrite(store->client, temporary.handle, record,
	    sizeof(*record), 0);
	if (length != sizeof(*record) ||
	    filesystemcmp_sync(store->client, temporary.handle) == -1) {
		error = length < 0 && errno != 0 ? errno : EIO;
		close_handle(store, temporary.handle);
		(void)filesystemcmp_unlink(store->client, store->root,
		    REBOOTD_STATE_TEMP, 0);
		return (errno = error, -1);
	}
	close_handle(store, temporary.handle);
	if (filesystemcmp_rename(store->client, store->root,
	    REBOOTD_STATE_TEMP, store->root, REBOOTD_STATE_FILE, 0) == -1) {
		error = errno != 0 ? errno : EIO;
		(void)filesystemcmp_unlink(store->client, store->root,
		    REBOOTD_STATE_TEMP, 0);
		errno = error;
		return (-1);
	}
	if (commitp != NULL)
		*commitp = REBOOTD_STORE_VISIBLE;
	if (filesystemcmp_sync(store->client, store->root) == -1)
		return (-1);
	if (commitp != NULL)
		*commitp = REBOOTD_STORE_DURABLE;
	return (0);
}

void
rebootd_store_close(struct rebootd_store *store)
{

	if (store == NULL)
		return;
	close_handle(store, store->root);
	filesystemcmp_close(store->client);
	free(store);
}
