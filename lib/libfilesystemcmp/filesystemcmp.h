/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _FILESYSTEMCMP_H_
#define	_FILESYSTEMCMP_H_

#include <sys/types.h>

#include <stddef.h>

#include "filesystemcmp_protocol.h"

__BEGIN_DECLS

struct filesystemcmp_client;
struct filesystemcmp_path_context;

/*
 * Open the FILESYSTEMCMP channel injected by serviced for this local
 * component.  The opaque client owns the correlated channel session.
 */
int	filesystemcmp_open(struct filesystemcmp_client **);
void	filesystemcmp_close(struct filesystemcmp_client *);
int	filesystemcmp_hello(struct filesystemcmp_client *,
	    struct filesystemcmp_hello_reply *reply);
int	filesystemcmp_open_root(struct filesystemcmp_client *,
	    struct filesystemcmp_handle *root);
int	filesystemcmp_open_namespace(struct filesystemcmp_client *,
	    uint32_t namespace_id,
	    struct filesystemcmp_handle *root);
int	filesystemcmp_lookup(struct filesystemcmp_client *,
	    struct filesystemcmp_handle directory,
	    const char *name, struct filesystemcmp_handle_reply *reply);
int	filesystemcmp_open_handle(struct filesystemcmp_client *,
	    struct filesystemcmp_handle object,
	    uint32_t flags, struct filesystemcmp_handle_reply *reply);
int	filesystemcmp_create(struct filesystemcmp_client *,
	    struct filesystemcmp_handle directory,
	    const char *name, uint32_t flags, uint32_t mode,
	    struct filesystemcmp_handle_reply *reply);
ssize_t	filesystemcmp_pread(struct filesystemcmp_client *,
	    struct filesystemcmp_handle object,
	    void *buffer, size_t length, uint64_t offset);
ssize_t	filesystemcmp_pwrite(struct filesystemcmp_client *,
	    struct filesystemcmp_handle object,
	    const void *buffer, size_t length, uint64_t offset);
int	filesystemcmp_stat(struct filesystemcmp_client *,
	    struct filesystemcmp_handle object,
	    struct filesystemcmp_stat_reply *reply);
int	filesystemcmp_unlink(struct filesystemcmp_client *,
	    struct filesystemcmp_handle directory,
	    const char *name, uint32_t flags);
int	filesystemcmp_rename(struct filesystemcmp_client *,
	    struct filesystemcmp_handle old_directory, const char *old_name,
	    struct filesystemcmp_handle new_directory, const char *new_name,
	    uint32_t flags);
int	filesystemcmp_close_handle(struct filesystemcmp_client *,
	    struct filesystemcmp_handle object);
int	filesystemcmp_sync(struct filesystemcmp_client *,
	    struct filesystemcmp_handle object);
int	filesystemcmp_dup(struct filesystemcmp_client *,
	    struct filesystemcmp_handle object,
	    struct filesystemcmp_handle_reply *reply);

/*
 * A path context owns an independent logical current directory.  Absolute
 * paths start at its delegated namespace root; ".." cannot cross that root.
 */
int	filesystemcmp_path_context_open(uint32_t namespace_id,
	    struct filesystemcmp_path_context **);
void	filesystemcmp_path_context_close(struct filesystemcmp_path_context *);
int	filesystemcmp_path_chdir(struct filesystemcmp_path_context *,
	    const char *path);
int	filesystemcmp_path_getcwd(struct filesystemcmp_path_context *,
	    char *buffer, size_t size);
int	filesystemcmp_path_lookup(struct filesystemcmp_path_context *,
	    const char *path, struct filesystemcmp_handle_reply *reply);
int	filesystemcmp_path_create(struct filesystemcmp_path_context *,
	    const char *path, uint32_t flags, uint32_t mode,
	    struct filesystemcmp_handle_reply *reply);
int	filesystemcmp_path_unlink(struct filesystemcmp_path_context *,
	    const char *path, uint32_t flags);
int	filesystemcmp_path_rename(struct filesystemcmp_path_context *,
	    const char *old_path, const char *new_path, uint32_t flags);
ssize_t	filesystemcmp_path_pread(struct filesystemcmp_path_context *,
	    struct filesystemcmp_handle object,
	    void *buffer, size_t length, uint64_t offset);
ssize_t	filesystemcmp_path_pwrite(struct filesystemcmp_path_context *,
	    struct filesystemcmp_handle object,
	    const void *buffer, size_t length, uint64_t offset);
int	filesystemcmp_path_stat(struct filesystemcmp_path_context *,
	    struct filesystemcmp_handle object,
	    struct filesystemcmp_stat_reply *reply);
int	filesystemcmp_path_sync(struct filesystemcmp_path_context *,
	    struct filesystemcmp_handle object);
int	filesystemcmp_path_close_handle(struct filesystemcmp_path_context *,
	    struct filesystemcmp_handle object);

/* Provider and advanced-client framing primitives. */
int	filesystemcmp_validate_message(const struct filesystemcmp_msg *msg,
	    size_t received, enum filesystemcmp_message_role role);
int	filesystemcmp_message_init(struct filesystemcmp_msg *msg,
	    uint16_t opcode, uint32_t flags);
int	filesystemcmp_message_init_reply(struct filesystemcmp_msg *reply,
	    const struct filesystemcmp_msg *request, int status);
int	filesystemcmp_validate_fds(const struct filesystemcmp_msg *msg,
	    size_t nfds, enum filesystemcmp_message_role role);
__END_DECLS

#endif /* !_FILESYSTEMCMP_H_ */
