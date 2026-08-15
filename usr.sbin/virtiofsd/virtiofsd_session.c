/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "virtiofsd_export.h"
#include "virtiofsd_fuse.h"
#include "virtiofsd_handle.h"
#include "virtiofsd_session.h"

#define	VIRTIOFSD_DEFAULT_MAX_WRITE	(1024U * 1024U)
#define	VIRTIOFSD_FUSE_ASYNC_READ	UINT32_C(1)
#define	VIRTIOFSD_FUSE_PARALLEL_DIROPS	(UINT32_C(1) << 18)
#define	VIRTIOFSD_FUSE_SUPPORTED_FLAGS	(VIRTIOFSD_FUSE_ASYNC_READ | \
	    VIRTIOFSD_FUSE_PARALLEL_DIROPS)

#define	VIRTIOFSD_SESSION_STATE_MAGIC	UINT32_C(0x44534656) /* "VFSD" */
#define	VIRTIOFSD_SESSION_STATE_VERSION	2U
#define	VIRTIOFSD_SESSION_STATE_INITIALIZED	UINT16_C(1)

struct virtiofsd_session {
	pthread_rwlock_t lifecycle;
	struct virtiofsd_export *export;
	struct virtiofsd_handles *handles;
	enum virtiofsd_fuse_byte_order byte_order;
	size_t maximum_message;
	size_t maximum_handles;
	bool initialized;
};

static uint64_t
node_generation(uint64_t nodeid)
{
	uint32_t generation;

	if (nodeid == VIRTIOFSD_ROOT_NODEID)
		return (1);
	generation = (uint32_t)(nodeid >> 32);
	return (generation == 0 ? 1 : generation);
}

static int
session_error(const struct virtiofsd_fuse_request *request, int error,
    void *response, size_t response_capacity, size_t *written)
{

	if (response_capacity < VIRTIOFSD_FUSE_OUT_HEADER_SIZE)
		return (EMSGSIZE);
	if (virtiofsd_fuse_error_encode(request->byte_order, request->unique,
	    error, response) != 0)
		return (EPROTO);
	*written = VIRTIOFSD_FUSE_OUT_HEADER_SIZE;
	return (0);
}

static int
session_success(const struct virtiofsd_fuse_request *request, void *response,
    size_t response_capacity, size_t *written)
{

	if (response_capacity < VIRTIOFSD_FUSE_OUT_HEADER_SIZE)
		return (EMSGSIZE);
	if (virtiofsd_fuse_success_header_encode(request->byte_order,
	    request->unique, 0, response) != 0)
		return (EPROTO);
	*written = VIRTIOFSD_FUSE_OUT_HEADER_SIZE;
	return (0);
}

static int
session_handle_dup(struct virtiofsd_session *session, uint64_t handle,
    bool directory, uint64_t nodeid, int *fd)
{
	uint64_t owner;
	int error;

	error = virtiofsd_handles_dup(session->handles, handle, directory, fd,
	    &owner);
	if (error == 0 && owner != nodeid) {
		(void)close(*fd);
		*fd = -1;
		error = ESTALE;
	}
	return (error);
}

int
virtiofsd_session_create(struct virtiofsd_export *export,
    size_t maximum_handles, size_t maximum_message,
    struct virtiofsd_session **result)
{
	struct virtiofsd_session *session;
	int error;

	if (export == NULL || maximum_handles == 0 ||
	    maximum_message < VIRTIOFSD_FUSE_IN_HEADER_SIZE ||
	    maximum_message > UINT32_MAX || result == NULL)
		return (EINVAL);
	*result = NULL;
	session = calloc(1, sizeof(*session));
	if (session == NULL)
		return (ENOMEM);
	error = pthread_rwlock_init(&session->lifecycle, NULL);
	if (error != 0) {
		free(session);
		return (error);
	}
	error = virtiofsd_handles_create(maximum_handles, &session->handles);
	if (error != 0) {
		(void)pthread_rwlock_destroy(&session->lifecycle);
		free(session);
		return (error);
	}
	session->export = export;
	session->maximum_handles = maximum_handles;
	session->maximum_message = maximum_message;
	*result = session;
	return (0);
}

void
virtiofsd_session_destroy(struct virtiofsd_session *session)
{

	if (session == NULL)
		return;
	virtiofsd_handles_destroy(session->handles);
	(void)pthread_rwlock_destroy(&session->lifecycle);
	free(session);
}

int
virtiofsd_session_checkpoint(struct virtiofsd_session *session,
    uint8_t output[static VIRTIOFSD_SESSION_STATE_SIZE])
{
	uint16_t flags;
	int error;

	if (session == NULL || output == NULL)
		return (EINVAL);
	pthread_rwlock_wrlock(&session->lifecycle);
	if (virtiofsd_handles_count(session->handles) != 0 ||
	    virtiofsd_export_node_count(session->export) != 1) {
		error = EBUSY;
		goto out;
	}
	if ((session->initialized &&
	    session->byte_order != VIRTIOFSD_FUSE_ORDER_LITTLE &&
	    session->byte_order != VIRTIOFSD_FUSE_ORDER_BIG) ||
	    (!session->initialized &&
	    session->byte_order != VIRTIOFSD_FUSE_ORDER_UNKNOWN)) {
		error = EPROTO;
		goto out;
	}
	flags = session->initialized ?
	    VIRTIOFSD_SESSION_STATE_INITIALIZED : 0;
	le32enc(output, VIRTIOFSD_SESSION_STATE_MAGIC);
	le16enc(output + 4, VIRTIOFSD_SESSION_STATE_VERSION);
	le16enc(output + 6, flags);
	le32enc(output + 8, (uint32_t)session->byte_order);
	le32enc(output + 12, VIRTIOFSD_SESSION_STATE_HEADER_SIZE);
	le32enc(output + 16, 0);
	le32enc(output + 20, 0);
	le64enc(output + 24, 0);
	error = 0;
out:
	pthread_rwlock_unlock(&session->lifecycle);
	return (error);
}

int
virtiofsd_session_checkpoint_size(struct virtiofsd_session *session,
    size_t *result)
{
	size_t export_size, handle_size;
	int error;

	if (session == NULL || result == NULL)
		return (EINVAL);
	pthread_rwlock_wrlock(&session->lifecycle);
	if (virtiofsd_handles_count(session->handles) == 0 &&
	    virtiofsd_export_node_count(session->export) == 1) {
		*result = VIRTIOFSD_SESSION_STATE_SIZE;
		error = 0;
		goto out;
	}
	error = virtiofsd_export_state_size(session->export, &export_size);
	if (error == 0)
		error = virtiofsd_handles_state_size(session->handles,
		    &handle_size);
	if (error == 0 &&
	    (export_size > UINT32_MAX || handle_size > UINT32_MAX ||
	    export_size > SIZE_MAX - VIRTIOFSD_SESSION_STATE_HEADER_SIZE ||
	    handle_size > SIZE_MAX - VIRTIOFSD_SESSION_STATE_HEADER_SIZE -
	    export_size))
		error = EOVERFLOW;
	if (error == 0)
		*result = VIRTIOFSD_SESSION_STATE_HEADER_SIZE + export_size +
		    handle_size;
out:
	pthread_rwlock_unlock(&session->lifecycle);
	return (error);
}

int
virtiofsd_session_checkpoint_write(struct virtiofsd_session *session,
    void *output, size_t capacity, size_t *written)
{
	uint8_t *bytes;
	uint16_t flags;
	size_t export_size, handle_size, amount;
	int error;

	if (session == NULL || output == NULL || written == NULL)
		return (EINVAL);
	*written = 0;
	bytes = output;
	pthread_rwlock_wrlock(&session->lifecycle);
	if ((session->initialized &&
	    session->byte_order != VIRTIOFSD_FUSE_ORDER_LITTLE &&
	    session->byte_order != VIRTIOFSD_FUSE_ORDER_BIG) ||
	    (!session->initialized &&
	    session->byte_order != VIRTIOFSD_FUSE_ORDER_UNKNOWN)) {
		error = EPROTO;
		goto out;
	}
	if (virtiofsd_handles_count(session->handles) == 0 &&
	    virtiofsd_export_node_count(session->export) == 1) {
		if (capacity < VIRTIOFSD_SESSION_STATE_SIZE) {
			error = ENOBUFS;
			goto out;
		}
		flags = session->initialized ?
		    VIRTIOFSD_SESSION_STATE_INITIALIZED : 0;
		le32enc(bytes, VIRTIOFSD_SESSION_STATE_MAGIC);
		le16enc(bytes + 4, VIRTIOFSD_SESSION_STATE_VERSION);
		le16enc(bytes + 6, flags);
		le32enc(bytes + 8, (uint32_t)session->byte_order);
		le32enc(bytes + 12, VIRTIOFSD_SESSION_STATE_HEADER_SIZE);
		le32enc(bytes + 16, 0);
		le32enc(bytes + 20, 0);
		le64enc(bytes + 24, 0);
		*written = VIRTIOFSD_SESSION_STATE_SIZE;
		error = 0;
		goto out;
	}
	error = virtiofsd_export_state_size(session->export, &export_size);
	if (error == 0)
		error = virtiofsd_handles_state_size(session->handles,
		    &handle_size);
	if (error != 0)
		goto out;
	if (export_size > UINT32_MAX || handle_size > UINT32_MAX ||
	    export_size > SIZE_MAX - VIRTIOFSD_SESSION_STATE_HEADER_SIZE ||
	    handle_size > SIZE_MAX - VIRTIOFSD_SESSION_STATE_HEADER_SIZE -
	    export_size || VIRTIOFSD_SESSION_STATE_HEADER_SIZE + export_size +
	    handle_size > capacity) {
		error = ENOBUFS;
		goto out;
	}
	error = virtiofsd_export_state_write(session->export,
	    bytes + VIRTIOFSD_SESSION_STATE_HEADER_SIZE, export_size, &amount);
	if (error != 0 || amount != export_size) {
		if (error == 0)
			error = EPROTO;
		goto out;
	}
	error = virtiofsd_handles_state_write(session->handles,
	    bytes + VIRTIOFSD_SESSION_STATE_HEADER_SIZE + export_size,
	    handle_size, &amount);
	if (error != 0 || amount != handle_size) {
		if (error == 0)
			error = EPROTO;
		goto out;
	}
	flags = session->initialized ? VIRTIOFSD_SESSION_STATE_INITIALIZED : 0;
	le32enc(bytes, VIRTIOFSD_SESSION_STATE_MAGIC);
	le16enc(bytes + 4, VIRTIOFSD_SESSION_STATE_VERSION);
	le16enc(bytes + 6, flags);
	le32enc(bytes + 8, (uint32_t)session->byte_order);
	le32enc(bytes + 12, (uint32_t)(VIRTIOFSD_SESSION_STATE_HEADER_SIZE +
	    export_size + handle_size));
	le32enc(bytes + 16, (uint32_t)export_size);
	le32enc(bytes + 20, (uint32_t)handle_size);
	le64enc(bytes + 24, 0);
	*written = VIRTIOFSD_SESSION_STATE_HEADER_SIZE + export_size +
	    handle_size;
	error = 0;
out:
	pthread_rwlock_unlock(&session->lifecycle);
	return (error);
}

static int
virtiofsd_session_restore_reopen(void *argument, uint64_t nodeid,
    const void *path, size_t path_len, bool directory, uint64_t file_size,
    int *fd)
{

	return (virtiofsd_export_restore_open_path(argument, nodeid, path,
	    path_len, directory, file_size, fd));
}

int
virtiofsd_session_restore(struct virtiofsd_session *session,
    const void *input, size_t input_len)
{
	struct virtiofsd_export_restore *export_restore;
	struct virtiofsd_handles_restore *handles_restore;
	const uint8_t *bytes;
	enum virtiofsd_fuse_byte_order order;
	size_t export_len, handles_len;
	uint16_t version;
	uint16_t flags;
	bool initialized;
	int error;

	if (session == NULL || input == NULL)
		return (EINVAL);
	bytes = input;
	if (input_len < VIRTIOFSD_SESSION_STATE_HEADER_SIZE ||
	    le32dec(bytes) != VIRTIOFSD_SESSION_STATE_MAGIC)
		return (EPROTO);
	version = le16dec(bytes + 4);
	flags = le16dec(bytes + 6);
	order = (enum virtiofsd_fuse_byte_order)le32dec(bytes + 8);
	initialized = (flags & VIRTIOFSD_SESSION_STATE_INITIALIZED) != 0;
	if ((flags & ~VIRTIOFSD_SESSION_STATE_INITIALIZED) != 0 ||
	    (initialized && order != VIRTIOFSD_FUSE_ORDER_LITTLE &&
	    order != VIRTIOFSD_FUSE_ORDER_BIG) ||
	    (!initialized && order != VIRTIOFSD_FUSE_ORDER_UNKNOWN))
		return (EPROTO);
	if (version != VIRTIOFSD_SESSION_STATE_VERSION)
		return (ENOTSUP);
	if (le32dec(bytes + 12) != input_len || le64dec(bytes + 24) != 0)
		return (EPROTO);
	export_len = le32dec(bytes + 16);
	handles_len = le32dec(bytes + 20);
	if (export_len == 0 && handles_len == 0) {
		if (input_len != VIRTIOFSD_SESSION_STATE_HEADER_SIZE)
			return (EPROTO);
		pthread_rwlock_wrlock(&session->lifecycle);
		if (virtiofsd_handles_count(session->handles) != 0 ||
		    virtiofsd_export_node_count(session->export) != 1) {
			error = EBUSY;
		} else {
			session->initialized = initialized;
			session->byte_order = order;
			error = 0;
		}
		pthread_rwlock_unlock(&session->lifecycle);
		return (error);
	}
	if (export_len < 16 || handles_len < 16 ||
	    export_len > input_len - VIRTIOFSD_SESSION_STATE_HEADER_SIZE ||
	    handles_len != input_len - VIRTIOFSD_SESSION_STATE_HEADER_SIZE -
	    export_len)
		return (EPROTO);
	/* Live object tables cannot exist before a successful FUSE_INIT. */
	if (!initialized &&
	    (le32dec(bytes + VIRTIOFSD_SESSION_STATE_HEADER_SIZE + 8) != 0 ||
	    le32dec(bytes + VIRTIOFSD_SESSION_STATE_HEADER_SIZE + export_len +
	    8) != 0))
		return (EPROTO);
	export_restore = NULL;
	handles_restore = NULL;
	pthread_rwlock_wrlock(&session->lifecycle);
	error = virtiofsd_export_restore_prepare(session->export,
	    bytes + VIRTIOFSD_SESSION_STATE_HEADER_SIZE, export_len,
	    &export_restore);
	if (error == 0)
		error = virtiofsd_handles_restore_prepare(session->handles,
		    virtiofsd_session_restore_reopen, export_restore,
		    bytes + VIRTIOFSD_SESSION_STATE_HEADER_SIZE + export_len,
		    handles_len, &handles_restore);
	if (error == 0) {
		virtiofsd_export_restore_commit(session->export, export_restore);
		virtiofsd_handles_restore_commit(session->handles,
		    handles_restore);
		session->initialized = initialized;
		session->byte_order = order;
	}
	pthread_rwlock_unlock(&session->lifecycle);
	virtiofsd_handles_restore_destroy(handles_restore);
	virtiofsd_export_restore_destroy(export_restore);
	return (error);
}

static int
session_init(struct virtiofsd_session *session,
    const struct virtiofsd_fuse_request *request, void *response,
    size_t response_capacity, size_t *written)
{
	struct virtiofsd_fuse_init init;
	uint8_t *bytes;
	uint32_t response_size;
	int error;

	if (session->initialized)
		return (EPROTO);
	error = virtiofsd_fuse_init_decode(request, &init);
	if (error != 0 || init.major == 0)
		return (EPROTO);
	bytes = response;
	if (init.major > VIRTIOFSD_FUSE_KERNEL_VERSION) {
		response_size = VIRTIOFSD_FUSE_OUT_HEADER_SIZE + 8;
		if (response_capacity < response_size)
			return (EMSGSIZE);
		if (virtiofsd_fuse_success_header_encode(request->byte_order,
		    request->unique, 8, bytes) != 0)
			return (EPROTO);
		if (request->byte_order == VIRTIOFSD_FUSE_ORDER_BIG) {
			be32enc(bytes + 16, VIRTIOFSD_FUSE_KERNEL_VERSION);
			be32enc(bytes + 20, VIRTIOFSD_FUSE_KERNEL_MINOR);
		} else {
			le32enc(bytes + 16, VIRTIOFSD_FUSE_KERNEL_VERSION);
			le32enc(bytes + 20, VIRTIOFSD_FUSE_KERNEL_MINOR);
		}
		session->byte_order = request->byte_order;
		session->initialized = false;
		*written = response_size;
		return (0);
	}
	if (init.major < VIRTIOFSD_FUSE_KERNEL_VERSION)
		return (session_error(request, EPROTO, response,
		    response_capacity, written));
	response_size = VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_INIT_OUT_SIZE;
	if (response_capacity < response_size)
		return (EMSGSIZE);
	error = virtiofsd_fuse_init_response_encode(request->byte_order,
	    request->unique, &init, VIRTIOFSD_FUSE_SUPPORTED_FLAGS,
	    MIN(VIRTIOFSD_DEFAULT_MAX_WRITE,
	    (uint32_t)(session->maximum_message -
	    VIRTIOFSD_FUSE_OUT_HEADER_SIZE)), bytes);
	if (error != 0)
		return (error);
	session->byte_order = request->byte_order;
	session->initialized = true;
	*written = response_size;
	return (0);
}

static int
session_lookup(struct virtiofsd_session *session,
    const struct virtiofsd_fuse_request *request, void *response,
    size_t response_capacity, size_t *written)
{
	struct stat sb;
	const void *name;
	size_t name_len;
	uint64_t nodeid;
	int error;

	error = virtiofsd_fuse_name(request, &name, &name_len);
	if (error != 0)
		return (EPROTO);
	error = virtiofsd_export_component_valid(name, name_len);
	if (error == 0)
		error = virtiofsd_export_lookup(session->export,
		    request->nodeid, name, name_len, &nodeid, &sb);
	if (error != 0)
		return (session_error(request, error, response,
		    response_capacity, written));
	if (response_capacity < VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_ENTRY_OUT_SIZE) {
		(void)virtiofsd_export_forget(session->export, nodeid, 1);
		return (EMSGSIZE);
	}
	error = virtiofsd_fuse_entry_response_encode(request->byte_order,
	    request->unique, nodeid, node_generation(nodeid), &sb, response);
	if (error != 0) {
		(void)virtiofsd_export_forget(session->export, nodeid, 1);
		return (error);
	}
	*written = VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_ENTRY_OUT_SIZE;
	return (0);
}

static int
session_getattr(struct virtiofsd_session *session,
    const struct virtiofsd_fuse_request *request, void *response,
    size_t response_capacity, size_t *written)
{
	struct stat sb;
	uint64_t handle;
	uint32_t flags;
	int error, fd;

	error = virtiofsd_fuse_getattr_decode(request, &flags, &handle);
	if (error != 0)
		return (EPROTO);
	if (flags == 0) {
		error = virtiofsd_export_stat(session->export, request->nodeid,
		    &sb);
	} else {
		error = session_handle_dup(session, handle, false,
		    request->nodeid, &fd);
		if (error == ESTALE)
			error = session_handle_dup(session, handle, true,
			    request->nodeid, &fd);
		if (error == 0) {
			if (fstat(fd, &sb) != 0)
				error = errno;
			(void)close(fd);
		}
	}
	if (error != 0)
		return (session_error(request, error, response,
		    response_capacity, written));
	if (response_capacity < VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_ATTR_OUT_SIZE)
		return (EMSGSIZE);
	error = virtiofsd_fuse_attr_response_encode(request->byte_order,
	    request->unique, &sb, response);
	if (error != 0)
		return (error);
	*written = VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_ATTR_OUT_SIZE;
	return (0);
}

static int
session_readlink(struct virtiofsd_session *session,
    const struct virtiofsd_fuse_request *request, void *response,
    size_t response_capacity, size_t *written)
{
	uint8_t target[PATH_MAX + 1];
	size_t length;
	int error;

	if (request->body_len != 0)
		return (EPROTO);
	error = virtiofsd_export_readlink(session->export, request->nodeid,
	    target, sizeof(target), &length);
	if (error != 0)
		return (session_error(request, error, response,
		    response_capacity, written));
	if (response_capacity < VIRTIOFSD_FUSE_OUT_HEADER_SIZE ||
	    length > response_capacity - VIRTIOFSD_FUSE_OUT_HEADER_SIZE)
		return (session_error(request, ERANGE, response,
		    response_capacity, written));
	error = virtiofsd_fuse_success_header_encode(request->byte_order,
	    request->unique, (uint32_t)length, response);
	if (error != 0)
		return (error);
	memcpy((uint8_t *)response + VIRTIOFSD_FUSE_OUT_HEADER_SIZE, target,
	    length);
	*written = VIRTIOFSD_FUSE_OUT_HEADER_SIZE + length;
	return (0);
}

static int
session_statfs(struct virtiofsd_session *session,
    const struct virtiofsd_fuse_request *request, void *response,
    size_t response_capacity, size_t *written)
{
	struct virtiofsd_fuse_statfs wire;
	struct statfs sb;
	int error;

	if (request->body_len != 0)
		return (EPROTO);
	error = virtiofsd_export_statfs(session->export, request->nodeid,
	    &sb);
	if (error != 0)
		return (session_error(request, error, response,
		    response_capacity, written));
	if (sb.f_bsize == 0 || sb.f_bsize > UINT32_MAX)
		return (session_error(request, EOVERFLOW, response,
		    response_capacity, written));
	wire = (struct virtiofsd_fuse_statfs) {
		.blocks = sb.f_blocks,
		.free_blocks = sb.f_bfree,
		.available_blocks = sb.f_bavail < 0 ? 0 :
		    (uint64_t)sb.f_bavail,
		.files = sb.f_files,
		.free_files = sb.f_ffree < 0 ? 0 : (uint64_t)sb.f_ffree,
		.block_size = (uint32_t)sb.f_bsize,
		.maximum_name = sb.f_namemax,
		.fragment_size = (uint32_t)sb.f_bsize,
	};
	if (response_capacity < VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_STATFS_OUT_SIZE)
		return (EMSGSIZE);
	error = virtiofsd_fuse_statfs_response_encode(request->byte_order,
	    request->unique, &wire, response);
	if (error != 0)
		return (error);
	*written = VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_STATFS_OUT_SIZE;
	return (0);
}

static int
session_access(struct virtiofsd_session *session,
    const struct virtiofsd_fuse_request *request, void *response,
    size_t response_capacity, size_t *written)
{
	struct stat sb;
	uint32_t mask;
	int error;

	error = virtiofsd_fuse_access_decode(request, &mask);
	if (error != 0)
		return (EPROTO);
	error = virtiofsd_export_stat(session->export, request->nodeid, &sb);
	if (error != 0)
		return (session_error(request, error, response,
		    response_capacity, written));
	/*
	 * The guest kernel performs mode checks from the attributes above.
	 * The daemon's credential remains the host-side authority boundary.
	 */
	if ((mask & 2U) != 0)
		return (session_error(request, EROFS, response,
		    response_capacity, written));
	return (session_success(request, response, response_capacity, written));
}

static int
session_open(struct virtiofsd_session *session,
    const struct virtiofsd_fuse_request *request, bool directory,
    void *response, size_t response_capacity, size_t *written)
{
	struct stat sb;
	uint8_t path[PATH_MAX];
	size_t path_len;
	uint64_t handle;
	uint32_t guest_flags;
	int error, fd, host_flags;

	error = virtiofsd_fuse_open_decode(request, &guest_flags);
	if (error != 0)
		return (EPROTO);
	/*
	 * Only the Linux access-mode bits affect the read-only backend.
	 * Accept harmless LARGEFILE, DIRECTORY, NOFOLLOW, and CLOEXEC bits.
	 */
	if ((guest_flags & 3U) != 0 ||
	    (guest_flags & ~(UINT32_C(3) | UINT32_C(0x8000) |
	    UINT32_C(0x10000) | UINT32_C(0x20000) |
	    UINT32_C(0x80000))) != 0)
		return (session_error(request, EROFS, response,
		    response_capacity, written));
	error = virtiofsd_export_stat(session->export, request->nodeid, &sb);
	if (error != 0)
		return (session_error(request, error, response,
		    response_capacity, written));
	if (directory != S_ISDIR(sb.st_mode))
		return (session_error(request, directory ? ENOTDIR : EISDIR,
		    response, response_capacity, written));
	host_flags = O_RDONLY | (directory ? O_DIRECTORY : 0);
	error = virtiofsd_export_open(session->export, request->nodeid,
	    host_flags, &fd);
	if (error == 0) {
		error = virtiofsd_export_path(session->export, request->nodeid,
		    path, sizeof(path), &path_len);
		if (error == 0)
			error = virtiofsd_handles_insert_identity(session->handles,
			    fd, request->nodeid, directory, path, path_len,
			    &handle);
		(void)close(fd);
	}
	if (error != 0)
		return (session_error(request, error, response,
		    response_capacity, written));
	if (response_capacity < VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_OPEN_OUT_SIZE) {
		(void)virtiofsd_handles_remove(session->handles, handle,
		    directory);
		return (EMSGSIZE);
	}
	error = virtiofsd_fuse_open_response_encode(request->byte_order,
	    request->unique, handle, response);
	if (error != 0) {
		(void)virtiofsd_handles_remove(session->handles, handle,
		    directory);
		return (error);
	}
	*written = VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_OPEN_OUT_SIZE;
	return (0);
}

static int
session_read(struct virtiofsd_session *session,
    const struct virtiofsd_fuse_request *request, void *response,
    size_t response_capacity, size_t *written)
{
	struct virtiofsd_fuse_read read_request;
	uint8_t *bytes;
	size_t capacity;
	ssize_t amount;
	int error, fd;

	error = virtiofsd_fuse_read_decode(request, &read_request);
	if (error != 0)
		return (EPROTO);
	if (read_request.offset > INT64_MAX)
		return (session_error(request, EOVERFLOW, response,
		    response_capacity, written));
	if (response_capacity < VIRTIOFSD_FUSE_OUT_HEADER_SIZE)
		return (EMSGSIZE);
	capacity = MIN(response_capacity - VIRTIOFSD_FUSE_OUT_HEADER_SIZE,
	    session->maximum_message - VIRTIOFSD_FUSE_OUT_HEADER_SIZE);
	if (read_request.size > capacity)
		return (session_error(request, EINVAL, response,
		    response_capacity, written));
	error = session_handle_dup(session, read_request.handle, false,
	    request->nodeid, &fd);
	if (error != 0)
		return (session_error(request, error, response,
		    response_capacity, written));
	bytes = response;
	do {
		amount = pread(fd, bytes + VIRTIOFSD_FUSE_OUT_HEADER_SIZE,
		    read_request.size, (off_t)read_request.offset);
	} while (amount < 0 && errno == EINTR);
	error = amount < 0 ? errno : 0;
	(void)close(fd);
	if (error != 0)
		return (session_error(request, error, response,
		    response_capacity, written));
	error = virtiofsd_fuse_success_header_encode(request->byte_order,
	    request->unique, (uint32_t)amount, bytes);
	if (error != 0)
		return (error);
	*written = VIRTIOFSD_FUSE_OUT_HEADER_SIZE + (size_t)amount;
	return (0);
}

static uint32_t
session_linux_dirent_type(unsigned char host_type)
{

	switch (host_type) {
	case DT_FIFO:	return (1);
	case DT_CHR:	return (2);
	case DT_DIR:	return (4);
	case DT_BLK:	return (6);
	case DT_REG:	return (8);
	case DT_LNK:	return (10);
	case DT_SOCK:	return (12);
	default:	return (0);
	}
}

static bool
session_dirent_allowed(DIR *directory, const struct dirent *entry)
{
	struct stat sb;

	if (strcmp(entry->d_name, ".") == 0 ||
	    strcmp(entry->d_name, "..") == 0)
		return (true);
	if (fstatat(dirfd(directory), entry->d_name, &sb,
	    AT_SYMLINK_NOFOLLOW | AT_RESOLVE_BENEATH) != 0)
		return (false);
	return (S_ISREG(sb.st_mode) || S_ISDIR(sb.st_mode) ||
	    S_ISLNK(sb.st_mode));
}

static int
session_readdir(struct virtiofsd_session *session,
    const struct virtiofsd_fuse_request *request, void *response,
    size_t response_capacity, size_t *written)
{
	struct virtiofsd_fuse_read read_request;
	struct dirent *entry;
	DIR *directory;
	uint8_t *bytes;
	uint64_t position;
	size_t amount, capacity, entry_size;
	int error, fd;

	error = virtiofsd_fuse_read_decode(request, &read_request);
	if (error != 0)
		return (EPROTO);
	if (response_capacity < VIRTIOFSD_FUSE_OUT_HEADER_SIZE)
		return (EMSGSIZE);
	capacity = MIN(response_capacity - VIRTIOFSD_FUSE_OUT_HEADER_SIZE,
	    session->maximum_message - VIRTIOFSD_FUSE_OUT_HEADER_SIZE);
	if (read_request.size < capacity)
		capacity = read_request.size;
	error = session_handle_dup(session, read_request.handle, true,
	    request->nodeid, &fd);
	if (error != 0)
		return (session_error(request, error, response,
		    response_capacity, written));
	directory = fdopendir(fd);
	if (directory == NULL) {
		error = errno;
		(void)close(fd);
		return (session_error(request, error, response,
		    response_capacity, written));
	}
	bytes = response;
	amount = 0;
	position = 0;
	for (;;) {
		errno = 0;
		entry = readdir(directory);
		if (entry == NULL) {
			error = errno;
			break;
		}
		if (!session_dirent_allowed(directory, entry))
			continue;
		position++;
		if (position <= read_request.offset)
			continue;
		error = virtiofsd_fuse_dirent_encode(request->byte_order,
		    (uint64_t)entry->d_fileno, position,
		    session_linux_dirent_type(entry->d_type), entry->d_name,
		    entry->d_namlen, bytes + VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
		    amount, capacity - amount, &entry_size);
		if (error == ENOBUFS)
			break;
		if (error != 0)
			goto out;
		amount += entry_size;
	}
	if (entry != NULL && error == ENOBUFS)
		error = 0;
out:
	(void)closedir(directory);
	if (error != 0)
		return (session_error(request, error, response,
		    response_capacity, written));
	error = virtiofsd_fuse_success_header_encode(request->byte_order,
	    request->unique, (uint32_t)amount, response);
	if (error != 0)
		return (error);
	*written = VIRTIOFSD_FUSE_OUT_HEADER_SIZE + amount;
	return (0);
}

static int
session_release(struct virtiofsd_session *session,
    const struct virtiofsd_fuse_request *request, bool directory,
    void *response, size_t response_capacity, size_t *written)
{
	uint64_t handle;
	int error;

	error = virtiofsd_fuse_release_decode(request, &handle);
	if (error != 0)
		return (EPROTO);
	error = virtiofsd_handles_remove_node(session->handles, handle, directory,
	    request->nodeid);
	if (error != 0)
		return (session_error(request, error, response,
		    response_capacity, written));
	return (session_success(request, response, response_capacity, written));
}

static int
session_sync_handle(struct virtiofsd_session *session,
    const struct virtiofsd_fuse_request *request, bool directory, bool flush,
    void *response, size_t response_capacity, size_t *written)
{
	uint64_t handle;
	int error, fd;

	if (flush)
		error = virtiofsd_fuse_flush_decode(request, &handle);
	else
		error = virtiofsd_fuse_fsync_decode(request, &handle);
	if (error != 0)
		return (EPROTO);
	error = session_handle_dup(session, handle, directory, request->nodeid,
	    &fd);
	if (error == 0)
		(void)close(fd);
	if (error != 0)
		return (session_error(request, error, response,
		    response_capacity, written));
	/*
	 * The export is immutable.  Once the handle has been validated there
	 * is no dirty data or metadata to flush to the host filesystem.
	 */
	return (session_success(request, response, response_capacity, written));
}

static int
session_forget(struct virtiofsd_session *session,
    const struct virtiofsd_fuse_request *request)
{
	uint64_t count;
	int error;

	error = virtiofsd_fuse_forget_decode(request, &count);
	if (error != 0)
		return (EPROTO);
	if (request->nodeid == VIRTIOFSD_ROOT_NODEID)
		return (0);
	error = virtiofsd_export_forget(session->export, request->nodeid,
	    count);
	/*
	 * FORGET has no reply.  A duplicate or stale notification must not
	 * poison the backend connection.
	 */
	return (error == ESTALE || error == EINVAL ? 0 : error);
}

static int
session_batch_forget(struct virtiofsd_session *session,
    const struct virtiofsd_fuse_request *request)
{
	struct virtiofsd_fuse_forget_one entry;
	uint32_t count, i;
	int error;

	/*
	 * Validate the complete variable-length request before changing any
	 * lookup count.  A malformed final entry must not partially apply the
	 * preceding notifications.
	 */
	error = virtiofsd_fuse_batch_forget_decode(request, &count);
	if (error != 0)
		return (EPROTO);
	for (i = 0; i < count; i++) {
		error = virtiofsd_fuse_batch_forget_entry(request, i, &entry);
		if (error != 0)
			return (EPROTO);
	}
	for (i = 0; i < count; i++) {
		(void)virtiofsd_fuse_batch_forget_entry(request, i, &entry);
		if (entry.nodeid == VIRTIOFSD_ROOT_NODEID)
			continue;
		error = virtiofsd_export_forget(session->export, entry.nodeid,
		    entry.count);
		/*
		 * Like a single FORGET, stale and duplicate notifications are
		 * harmless and cannot be reported to the guest.
		 */
		if (error != 0 && error != ESTALE && error != EINVAL)
			return (error);
	}
	return (0);
}

int
virtiofsd_session_request_expects_reply(struct virtiofsd_session *session,
    const void *input, size_t input_len, bool *expects_reply)
{
	struct virtiofsd_fuse_request request;
	enum virtiofsd_fuse_byte_order expected;
	int error;

	if (session == NULL || input == NULL || expects_reply == NULL ||
	    input_len > session->maximum_message)
		return (EINVAL);
	pthread_rwlock_rdlock(&session->lifecycle);
	expected = session->byte_order;
	if (expected == VIRTIOFSD_FUSE_ORDER_UNKNOWN && input_len >= 8 &&
	    (le32dec((const uint8_t *)input + 4) ==
	    VIRTIOFSD_FUSE_INIT ||
	    be32dec((const uint8_t *)input + 4) ==
	    VIRTIOFSD_FUSE_INIT))
		expected = VIRTIOFSD_FUSE_ORDER_UNKNOWN;
	error = virtiofsd_fuse_request_decode(input, input_len, expected,
	    &request);
	if (error == 0) {
		*expects_reply = request.opcode != VIRTIOFSD_FUSE_FORGET &&
		    request.opcode != VIRTIOFSD_FUSE_BATCH_FORGET;
	}
	pthread_rwlock_unlock(&session->lifecycle);
	return (error);
}

/*
 * Undo server-side resources created by an operation whose successful reply
 * was canceled before publication.  The guest never observed the returned
 * node or handle and therefore cannot send the matching FORGET or RELEASE.
 */
int
virtiofsd_session_discard_result(struct virtiofsd_session *session,
    const void *input, size_t input_len, const void *response,
    size_t response_len)
{
	struct virtiofsd_fuse_request request;
	const uint8_t *bytes;
	enum virtiofsd_fuse_byte_order expected;
	uint32_t length, status;
	uint64_t resource, unique;
	size_t required;
	bool directory;
	int error;

	if (session == NULL || input == NULL || response == NULL ||
	    input_len > session->maximum_message ||
	    response_len < VIRTIOFSD_FUSE_OUT_HEADER_SIZE)
		return (EINVAL);
	bytes = response;
	pthread_rwlock_rdlock(&session->lifecycle);
	expected = session->byte_order;
	error = virtiofsd_fuse_request_decode(input, input_len, expected,
	    &request);
	if (error != 0)
		goto out;
	if (request.byte_order == VIRTIOFSD_FUSE_ORDER_BIG) {
		length = be32dec(bytes);
		status = be32dec(bytes + 4);
		unique = be64dec(bytes + 8);
	} else {
		length = le32dec(bytes);
		status = le32dec(bytes + 4);
		unique = le64dec(bytes + 8);
	}
	if (length != response_len || unique != request.unique) {
		error = EPROTO;
		goto out;
	}
	/* A FUSE error response created no resource and needs no rollback. */
	if (status != 0) {
		error = (int32_t)status < 0 &&
		    response_len == VIRTIOFSD_FUSE_OUT_HEADER_SIZE ? 0 : EPROTO;
		goto out;
	}
	switch (request.opcode) {
	case VIRTIOFSD_FUSE_LOOKUP:
		required = VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
		    VIRTIOFSD_FUSE_ENTRY_OUT_SIZE;
		directory = false;
		break;
	case VIRTIOFSD_FUSE_OPEN:
	case VIRTIOFSD_FUSE_OPENDIR:
		required = VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
		    VIRTIOFSD_FUSE_OPEN_OUT_SIZE;
		directory = request.opcode == VIRTIOFSD_FUSE_OPENDIR;
		break;
	default:
		error = 0;
		goto out;
	}
	if (response_len != required) {
		error = EPROTO;
		goto out;
	}
	resource = request.byte_order == VIRTIOFSD_FUSE_ORDER_BIG ?
	    be64dec(bytes + VIRTIOFSD_FUSE_OUT_HEADER_SIZE) :
	    le64dec(bytes + VIRTIOFSD_FUSE_OUT_HEADER_SIZE);
	if (resource == 0) {
		error = EPROTO;
		goto out;
	}
	if (request.opcode == VIRTIOFSD_FUSE_LOOKUP)
		error = virtiofsd_export_forget(session->export, resource, 1);
	else
		error = virtiofsd_handles_remove(session->handles, resource,
		    directory);
	/*
	 * An exclusive DESTROY may have reclaimed the same resource between
	 * execution and cancellation cleanup.  That already satisfies the
	 * rollback obligation.
	 */
	if (error == ESTALE)
		error = 0;
out:
	pthread_rwlock_unlock(&session->lifecycle);
	return (error);
}

static int
session_execute_locked(struct virtiofsd_session *session,
    const void *input, size_t input_len, void *response,
    size_t response_capacity, size_t *written, bool *reply_required)
{
	struct virtiofsd_fuse_request request;
	struct virtiofsd_handles *old_handles, *replacement;
	enum virtiofsd_fuse_byte_order expected;
	int error;

	expected = session->byte_order;
	error = virtiofsd_fuse_request_decode(input, input_len, expected,
	    &request);
	if (error != 0)
		goto out;
	if (request.opcode != VIRTIOFSD_FUSE_INIT &&
	    !session->initialized) {
		error = EPROTO;
		goto out;
	}
	switch (request.opcode) {
	case VIRTIOFSD_FUSE_INIT:
		error = session_init(session, &request, response,
		    response_capacity, written);
		break;
	case VIRTIOFSD_FUSE_LOOKUP:
		error = session_lookup(session, &request, response,
		    response_capacity, written);
		break;
	case VIRTIOFSD_FUSE_FORGET:
		*reply_required = false;
		error = session_forget(session, &request);
		break;
	case VIRTIOFSD_FUSE_BATCH_FORGET:
		*reply_required = false;
		error = session_batch_forget(session, &request);
		break;
	case VIRTIOFSD_FUSE_GETATTR:
		error = session_getattr(session, &request, response,
		    response_capacity, written);
		break;
	case VIRTIOFSD_FUSE_READLINK:
		error = session_readlink(session, &request, response,
		    response_capacity, written);
		break;
	case VIRTIOFSD_FUSE_OPEN:
		error = session_open(session, &request, false, response,
		    response_capacity, written);
		break;
	case VIRTIOFSD_FUSE_OPENDIR:
		error = session_open(session, &request, true, response,
		    response_capacity, written);
		break;
	case VIRTIOFSD_FUSE_READ:
		error = session_read(session, &request, response,
		    response_capacity, written);
		break;
	case VIRTIOFSD_FUSE_STATFS:
		error = session_statfs(session, &request, response,
		    response_capacity, written);
		break;
	case VIRTIOFSD_FUSE_READDIR:
		error = session_readdir(session, &request, response,
		    response_capacity, written);
		break;
	case VIRTIOFSD_FUSE_RELEASE:
		error = session_release(session, &request, false, response,
		    response_capacity, written);
		break;
	case VIRTIOFSD_FUSE_FLUSH:
		error = session_sync_handle(session, &request, false, true,
		    response, response_capacity, written);
		break;
	case VIRTIOFSD_FUSE_FSYNC:
		error = session_sync_handle(session, &request, false, false,
		    response, response_capacity, written);
		break;
	case VIRTIOFSD_FUSE_RELEASEDIR:
		error = session_release(session, &request, true, response,
		    response_capacity, written);
		break;
	case VIRTIOFSD_FUSE_FSYNCDIR:
		error = session_sync_handle(session, &request, true, false,
		    response, response_capacity, written);
		break;
	case VIRTIOFSD_FUSE_ACCESS:
		error = session_access(session, &request, response,
		    response_capacity, written);
		break;
	case VIRTIOFSD_FUSE_DESTROY:
		if (request.body_len != 0) {
			error = EPROTO;
			break;
		}
		if (response_capacity < VIRTIOFSD_FUSE_OUT_HEADER_SIZE) {
			error = EMSGSIZE;
			break;
		}
		replacement = NULL;
		error = virtiofsd_handles_create(session->maximum_handles,
		    &replacement);
		if (error != 0)
			break;
		old_handles = session->handles;
		session->handles = replacement;
		virtiofsd_handles_destroy(old_handles);
		/*
		 * DESTROY ends the FUSE connection.  A guest is not required to
		 * send FORGET for every node before tearing the connection down, so
		 * retain neither lookup references nor their host descriptors.
		 * Keep slot generations intact: a node ID issued by the destroyed
		 * connection must remain stale if its slot is reused after INIT.
		 */
		virtiofsd_export_reset(session->export);
		session->initialized = false;
		session->byte_order = VIRTIOFSD_FUSE_ORDER_UNKNOWN;
		error = session_success(&request, response, response_capacity,
		    written);
		break;
	default:
		error = session_error(&request, ENOSYS, response,
		    response_capacity, written);
		break;
	}
out:
	return (error);
}

int
virtiofsd_session_execute(struct virtiofsd_session *session,
    const void *input, size_t input_len, void *response,
    size_t response_capacity, size_t *written, bool *reply_required)
{
	uint32_t be_opcode, le_opcode;
	int error;

	if (session == NULL || input == NULL || written == NULL ||
	    reply_required == NULL ||
	    (response == NULL && response_capacity != 0) ||
	    input_len > session->maximum_message)
		return (EINVAL);
	*written = 0;
	*reply_required = true;
	le_opcode = input_len >= 8 ? le32dec((const uint8_t *)input + 4) : 0;
	be_opcode = input_len >= 8 ? be32dec((const uint8_t *)input + 4) : 0;
	if (le_opcode == VIRTIOFSD_FUSE_INIT ||
	    be_opcode == VIRTIOFSD_FUSE_INIT ||
	    le_opcode == VIRTIOFSD_FUSE_DESTROY ||
	    be_opcode == VIRTIOFSD_FUSE_DESTROY) {
		pthread_rwlock_wrlock(&session->lifecycle);
		error = session_execute_locked(session, input, input_len,
		    response, response_capacity, written, reply_required);
		pthread_rwlock_unlock(&session->lifecycle);
		return (error);
	}
	pthread_rwlock_rdlock(&session->lifecycle);
	error = session_execute_locked(session, input, input_len, response,
	    response_capacity, written, reply_required);
	pthread_rwlock_unlock(&session->lifecycle);
	return (error);
}
