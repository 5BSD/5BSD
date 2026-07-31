/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "filesystemcmp.h"

#define	PATH_COMPONENTS_MAX	(FILESYSTEMCMP_PATH_MAX / 2)

struct path_entry {
	struct filesystemcmp_handle handle;
	char	*name;
	bool	 owned;
};

struct filesystemcmp_path_context {
	struct filesystemcmp_client	*client;
	struct filesystemcmp_handle	 root;
	struct path_entry		*entries;
	size_t				 depth;
	pid_t				 owner;
	pthread_mutex_t			 lock;
};

struct path_tokens {
	char	*storage;
	char	*tokens[PATH_COMPONENTS_MAX];
	size_t	 count;
	bool	 absolute;
	bool	 leaf_valid;
	bool	 requires_directory;
};

static int
tokenize(const char *path, struct path_tokens *result)
{
	char *cursor, *token;
	size_t length;

	if (path == NULL || result == NULL) {
		errno = EINVAL;
		return (-1);
	}
	length = strnlen(path, FILESYSTEMCMP_PATH_MAX + 1);
	if (length == 0 || length > FILESYSTEMCMP_PATH_MAX) {
		errno = length == 0 ? ENOENT : ENAMETOOLONG;
		return (-1);
	}
	memset(result, 0, sizeof(*result));
	result->absolute = path[0] == '/';
	result->leaf_valid = path[length - 1] != '/';
	if (result->leaf_valid) {
		const char *leaf;

		leaf = strrchr(path, '/');
		leaf = leaf == NULL ? path : leaf + 1;
		if (*leaf == '\0' || strcmp(leaf, ".") == 0 ||
		    strcmp(leaf, "..") == 0)
			result->leaf_valid = false;
	}
	result->requires_directory = !result->leaf_valid;
	result->storage = strdup(path);
	if (result->storage == NULL)
		return (-1);
	cursor = result->storage;
	while ((token = strsep(&cursor, "/")) != NULL) {
		if (*token == '\0' || strcmp(token, ".") == 0)
			continue;
		if (strlen(token) > FILESYSTEMCMP_NAME_MAX ||
		    result->count == PATH_COMPONENTS_MAX) {
			free(result->storage);
			result->storage = NULL;
			errno = ENAMETOOLONG;
			return (-1);
		}
		result->tokens[result->count++] = token;
	}
	return (0);
}

static void
candidate_discard(struct filesystemcmp_path_context *context,
    struct path_entry *entries, size_t depth)
{
	size_t i;

	for (i = 0; i < depth; i++) {
		if (entries[i].owned)
			(void)filesystemcmp_close_handle(context->client,
			    entries[i].handle);
		free(entries[i].name);
	}
	free(entries);
}

static int
build_locked(struct filesystemcmp_path_context *context,
    const struct path_tokens *tokens, size_t count, bool final_directory,
    struct path_entry **entriesp, size_t *depthp, uint32_t *typep)
{
	struct filesystemcmp_handle_reply child;
	struct path_entry *candidate;
	struct filesystemcmp_handle directory;
	size_t depth, i;
	int error;

	candidate = calloc(PATH_COMPONENTS_MAX, sizeof(*candidate));
	if (candidate == NULL)
		return (-1);
	depth = 0;
	child.type = FILESYSTEMCMP_TYPE_DIRECTORY;
	if (!tokens->absolute) {
		for (i = 0; i < context->depth; i++) {
			candidate[i].handle = context->entries[i].handle;
			candidate[i].name = strdup(context->entries[i].name);
			if (candidate[i].name == NULL)
				goto fail;
		}
		depth = context->depth;
	}
	for (i = 0; i < count; i++) {
		if (strcmp(tokens->tokens[i], "..") == 0) {
			if (depth != 0) {
				if (candidate[depth - 1].owned)
					(void)filesystemcmp_close_handle(
					    context->client,
					    candidate[depth - 1].handle);
				free(candidate[depth - 1].name);
				memset(&candidate[depth - 1], 0,
				    sizeof(candidate[depth - 1]));
				depth--;
			}
			continue;
		}
		directory = depth == 0 ? context->root :
		    candidate[depth - 1].handle;
		if (depth == PATH_COMPONENTS_MAX) {
			errno = ENAMETOOLONG;
			goto fail;
		}
		if (filesystemcmp_lookup(context->client, directory,
		    tokens->tokens[i], &child) == -1)
			goto fail;
		if ((i + 1 < count || final_directory) &&
		    child.type != FILESYSTEMCMP_TYPE_DIRECTORY) {
			(void)filesystemcmp_close_handle(context->client,
			    child.handle);
			errno = ENOTDIR;
			goto fail;
		}
		candidate[depth].handle = child.handle;
		candidate[depth].name = strdup(tokens->tokens[i]);
		candidate[depth].owned = true;
		if (candidate[depth].name == NULL) {
			(void)filesystemcmp_close_handle(context->client,
			    child.handle);
			memset(&candidate[depth], 0, sizeof(candidate[depth]));
			goto fail;
		}
		depth++;
	}
	*entriesp = candidate;
	*depthp = depth;
	*typep = depth == 0 || !candidate[depth - 1].owned ?
	    FILESYSTEMCMP_TYPE_DIRECTORY : child.type;
	return (0);

fail:
	error = errno;
	candidate_discard(context, candidate, depth);
	errno = error;
	return (-1);
}

/*
 * Resolve tokens while the context lock is held.  The returned handle is an
 * independent owned handle, including when the result is the root or an
 * existing cwd ancestor.
 */
static int
resolve_locked(struct filesystemcmp_path_context *context,
    const struct path_tokens *tokens, size_t count, bool final_directory,
    struct filesystemcmp_handle_reply *result)
{
	struct path_entry *candidate;
	struct filesystemcmp_handle handle;
	size_t depth;
	uint32_t type;
	int error;

	if (build_locked(context, tokens, count, final_directory, &candidate,
	    &depth, &type) == -1)
		return (-1);
	if (depth != 0 && candidate[depth - 1].owned) {
		result->handle = candidate[depth - 1].handle;
		result->type = type;
		candidate[depth - 1].owned = false;
	} else {
		handle = depth == 0 ? context->root :
		    candidate[depth - 1].handle;
		if (filesystemcmp_dup(context->client, handle, result) == -1) {
			error = errno;
			candidate_discard(context, candidate, depth);
			errno = error;
			return (-1);
		}
	}
	candidate_discard(context, candidate, depth);
	return (0);
}

static int
context_valid(struct filesystemcmp_path_context *context)
{

	if (context == NULL || context->owner != getpid()) {
		errno = EINVAL;
		return (0);
	}
	return (1);
}

int
filesystemcmp_path_context_open(uint32_t namespace_id,
    struct filesystemcmp_path_context **contextp)
{
	struct filesystemcmp_path_context *context;
	int error;

	if (contextp == NULL ||
	    namespace_id < FILESYSTEMCMP_NAMESPACE_SCRATCH ||
	    namespace_id > FILESYSTEMCMP_NAMESPACE_BUNDLE) {
		errno = EINVAL;
		return (-1);
	}
	*contextp = NULL;
	context = calloc(1, sizeof(*context));
	if (context == NULL)
		return (-1);
	if (filesystemcmp_open(&context->client) == -1 ||
	    filesystemcmp_open_namespace(context->client, namespace_id,
	    &context->root) == -1) {
		error = errno;
		if (context->client != NULL)
			filesystemcmp_close(context->client);
		free(context);
		errno = error;
		return (-1);
	}
	context->entries = calloc(PATH_COMPONENTS_MAX,
	    sizeof(*context->entries));
	if (context->entries == NULL) {
		error = errno;
		(void)filesystemcmp_close_handle(context->client, context->root);
		filesystemcmp_close(context->client);
		free(context);
		errno = error;
		return (-1);
	}
	error = pthread_mutex_init(&context->lock, NULL);
	if (error != 0) {
		(void)filesystemcmp_close_handle(context->client, context->root);
		filesystemcmp_close(context->client);
		free(context->entries);
		free(context);
		errno = error;
		return (-1);
	}
	context->owner = getpid();
	*contextp = context;
	return (0);
}

void
filesystemcmp_path_context_close(struct filesystemcmp_path_context *context)
    __no_lock_analysis
{
	size_t i;

	if (!context_valid(context))
		return;
	(void)pthread_mutex_lock(&context->lock);
	for (i = 0; i < context->depth; i++) {
		(void)filesystemcmp_close_handle(context->client,
		    context->entries[i].handle);
		free(context->entries[i].name);
	}
	(void)filesystemcmp_close_handle(context->client, context->root);
	filesystemcmp_close(context->client);
	free(context->entries);
	(void)pthread_mutex_unlock(&context->lock);
	(void)pthread_mutex_destroy(&context->lock);
	free(context);
}

int
filesystemcmp_path_chdir(struct filesystemcmp_path_context *context,
    const char *path)
    __no_lock_analysis
{
	struct path_tokens tokens;
	struct path_entry *replacement;
	size_t common, depth, i;
	uint32_t type;
	int error;

	if (!context_valid(context) || tokenize(path, &tokens) == -1)
		return (-1);
	error = pthread_mutex_lock(&context->lock);
	if (error != 0) {
		free(tokens.storage);
		errno = error;
		return (-1);
	}
	if (build_locked(context, &tokens, tokens.count, true, &replacement,
	    &depth, &type) == -1)
		goto fail;
	common = 0;
	while (common < depth && common < context->depth &&
	    replacement[common].handle.object ==
	    context->entries[common].handle.object &&
	    replacement[common].handle.generation ==
	    context->entries[common].handle.generation)
		common++;
	for (i = common; i < context->depth; i++)
		(void)filesystemcmp_close_handle(context->client,
		    context->entries[i].handle);
	for (i = 0; i < context->depth; i++)
		free(context->entries[i].name);
	free(context->entries);
	context->entries = replacement;
	context->depth = depth;
	for (i = 0; i < depth; i++)
		context->entries[i].owned = false;
	free(tokens.storage);
	(void)pthread_mutex_unlock(&context->lock);
	return (0);

fail:
	error = errno;
	free(tokens.storage);
	(void)pthread_mutex_unlock(&context->lock);
	errno = error;
	return (-1);
}

int
filesystemcmp_path_getcwd(struct filesystemcmp_path_context *context,
    char *buffer, size_t size)
    __no_lock_analysis
{
	size_t needed, offset, i;
	int error;

	if (!context_valid(context) || buffer == NULL || size == 0) {
		errno = EINVAL;
		return (-1);
	}
	error = pthread_mutex_lock(&context->lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	needed = 2;
	for (i = 0; i < context->depth; i++)
		needed += strlen(context->entries[i].name) + (i != 0);
	if (needed > size) {
		(void)pthread_mutex_unlock(&context->lock);
		errno = ERANGE;
		return (-1);
	}
	offset = 0;
	buffer[offset++] = '/';
	for (i = 0; i < context->depth; i++) {
		if (i != 0)
			buffer[offset++] = '/';
		offset += strlcpy(buffer + offset, context->entries[i].name,
		    size - offset);
	}
	buffer[offset] = '\0';
	(void)pthread_mutex_unlock(&context->lock);
	return (0);
}

int
filesystemcmp_path_lookup(struct filesystemcmp_path_context *context,
    const char *path, struct filesystemcmp_handle_reply *reply)
    __no_lock_analysis
{
	struct path_tokens tokens;
	int error, rv;

	if (!context_valid(context) || reply == NULL ||
	    tokenize(path, &tokens) == -1)
		return (-1);
	error = pthread_mutex_lock(&context->lock);
	if (error != 0) {
		free(tokens.storage);
		errno = error;
		return (-1);
	}
	rv = resolve_locked(context, &tokens, tokens.count,
	    tokens.requires_directory, reply);
	error = errno;
	(void)pthread_mutex_unlock(&context->lock);
	free(tokens.storage);
	errno = error;
	return (rv);
}

static int
resolve_parent_locked(struct filesystemcmp_path_context *context,
    struct path_tokens *tokens, struct filesystemcmp_handle_reply *parent,
    const char **name)
{

	if (!tokens->leaf_valid || tokens->count == 0 ||
	    strcmp(tokens->tokens[tokens->count - 1], "..") == 0) {
		errno = EINVAL;
		return (-1);
	}
	*name = tokens->tokens[tokens->count - 1];
	return (resolve_locked(context, tokens, tokens->count - 1, true,
	    parent));
}

int
filesystemcmp_path_create(struct filesystemcmp_path_context *context,
    const char *path, uint32_t flags, uint32_t mode,
    struct filesystemcmp_handle_reply *reply)
    __no_lock_analysis
{
	struct filesystemcmp_handle_reply parent;
	struct path_tokens tokens;
	const char *name;
	int error, rv;

	if (!context_valid(context) || reply == NULL ||
	    (flags & ~FILESYSTEMCMP_CREATE_MASK) != 0 ||
	    tokenize(path, &tokens) == -1)
		return (-1);
	if ((error = pthread_mutex_lock(&context->lock)) != 0) {
		free(tokens.storage);
		errno = error;
		return (-1);
	}
	rv = resolve_parent_locked(context, &tokens, &parent, &name);
	if (rv == 0) {
		rv = filesystemcmp_create(context->client, parent.handle, name,
		    flags, mode, reply);
		error = errno;
		(void)filesystemcmp_close_handle(context->client, parent.handle);
		errno = error;
	}
	error = errno;
	(void)pthread_mutex_unlock(&context->lock);
	free(tokens.storage);
	errno = error;
	return (rv);
}

int
filesystemcmp_path_unlink(struct filesystemcmp_path_context *context,
    const char *path, uint32_t flags)
    __no_lock_analysis
{
	struct filesystemcmp_handle_reply parent;
	struct path_tokens tokens;
	const char *name;
	int error, rv;

	if (!context_valid(context) || tokenize(path, &tokens) == -1)
		return (-1);
	if ((error = pthread_mutex_lock(&context->lock)) != 0) {
		free(tokens.storage);
		errno = error;
		return (-1);
	}
	rv = resolve_parent_locked(context, &tokens, &parent, &name);
	if (rv == 0) {
		rv = filesystemcmp_unlink(context->client, parent.handle, name,
		    flags);
		error = errno;
		(void)filesystemcmp_close_handle(context->client, parent.handle);
		errno = error;
	}
	error = errno;
	(void)pthread_mutex_unlock(&context->lock);
	free(tokens.storage);
	errno = error;
	return (rv);
}

int
filesystemcmp_path_rename(struct filesystemcmp_path_context *context,
    const char *old_path, const char *new_path, uint32_t flags)
    __no_lock_analysis
{
	struct filesystemcmp_handle_reply old_parent, new_parent;
	struct path_tokens old_tokens, new_tokens;
	const char *old_name, *new_name;
	int error, rv;

	if (!context_valid(context) || tokenize(old_path, &old_tokens) == -1)
		return (-1);
	if (tokenize(new_path, &new_tokens) == -1) {
		free(old_tokens.storage);
		return (-1);
	}
	if ((error = pthread_mutex_lock(&context->lock)) != 0) {
		free(old_tokens.storage);
		free(new_tokens.storage);
		errno = error;
		return (-1);
	}
	rv = resolve_parent_locked(context, &old_tokens, &old_parent,
	    &old_name);
	if (rv == 0) {
		rv = resolve_parent_locked(context, &new_tokens, &new_parent,
		    &new_name);
		if (rv == 0) {
			rv = filesystemcmp_rename(context->client,
			    old_parent.handle, old_name, new_parent.handle,
			    new_name, flags);
			error = errno;
			(void)filesystemcmp_close_handle(context->client,
			    new_parent.handle);
			errno = error;
		}
		error = errno;
		(void)filesystemcmp_close_handle(context->client,
		    old_parent.handle);
		errno = error;
	}
	error = errno;
	(void)pthread_mutex_unlock(&context->lock);
	free(old_tokens.storage);
	free(new_tokens.storage);
	errno = error;
	return (rv);
}

ssize_t
filesystemcmp_path_pread(struct filesystemcmp_path_context *context,
    struct filesystemcmp_handle object, void *buffer, size_t length,
    uint64_t offset)
    __no_lock_analysis
{
	ssize_t result;
	int error;

	if (!context_valid(context))
		return (-1);
	error = pthread_mutex_lock(&context->lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	result = filesystemcmp_pread(context->client, object, buffer, length,
	    offset);
	error = errno;
	(void)pthread_mutex_unlock(&context->lock);
	errno = error;
	return (result);
}

ssize_t
filesystemcmp_path_pwrite(struct filesystemcmp_path_context *context,
    struct filesystemcmp_handle object, const void *buffer, size_t length,
    uint64_t offset)
    __no_lock_analysis
{
	ssize_t result;
	int error;

	if (!context_valid(context))
		return (-1);
	error = pthread_mutex_lock(&context->lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	result = filesystemcmp_pwrite(context->client, object, buffer, length,
	    offset);
	error = errno;
	(void)pthread_mutex_unlock(&context->lock);
	errno = error;
	return (result);
}

int
filesystemcmp_path_stat(struct filesystemcmp_path_context *context,
    struct filesystemcmp_handle object, struct filesystemcmp_stat_reply *reply)
    __no_lock_analysis
{
	int error, result;

	if (!context_valid(context))
		return (-1);
	error = pthread_mutex_lock(&context->lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	result = filesystemcmp_stat(context->client, object, reply);
	error = errno;
	(void)pthread_mutex_unlock(&context->lock);
	errno = error;
	return (result);
}

int
filesystemcmp_path_sync(struct filesystemcmp_path_context *context,
    struct filesystemcmp_handle object)
    __no_lock_analysis
{
	int error, result;

	if (!context_valid(context))
		return (-1);
	error = pthread_mutex_lock(&context->lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	result = filesystemcmp_sync(context->client, object);
	error = errno;
	(void)pthread_mutex_unlock(&context->lock);
	errno = error;
	return (result);
}

int
filesystemcmp_path_close_handle(struct filesystemcmp_path_context *context,
    struct filesystemcmp_handle object)
    __no_lock_analysis
{
	int error, result;

	if (!context_valid(context))
		return (-1);
	error = pthread_mutex_lock(&context->lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	result = filesystemcmp_close_handle(context->client, object);
	error = errno;
	(void)pthread_mutex_unlock(&context->lock);
	errno = error;
	return (result);
}
