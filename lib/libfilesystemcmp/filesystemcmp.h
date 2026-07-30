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

#define	FILESYSTEMCMP_ENV	"FILESYSTEMCMP"

/*
 * NULL selects the serviced-owned environment selector, then the conventional
 * "filesystem" key.  The returned close-on-exec fd belongs to the caller.
 * Typed operations are synchronous and serialized within the library.
 */
int	filesystemcmp_open(const char *component);
int	filesystemcmp_hello(int fd, struct filesystemcmp_hello_reply *reply);
int	filesystemcmp_open_root(int fd, struct filesystemcmp_handle *root);
int	filesystemcmp_lookup(int fd, struct filesystemcmp_handle directory,
	    const char *name, struct filesystemcmp_handle_reply *reply);
int	filesystemcmp_open_handle(int fd, struct filesystemcmp_handle object,
	    uint32_t flags, struct filesystemcmp_handle_reply *reply);
int	filesystemcmp_create(int fd, struct filesystemcmp_handle directory,
	    const char *name, uint32_t flags, uint32_t mode,
	    struct filesystemcmp_handle_reply *reply);
ssize_t	filesystemcmp_pread(int fd, struct filesystemcmp_handle object,
	    void *buffer, size_t length, uint64_t offset);
ssize_t	filesystemcmp_pwrite(int fd, struct filesystemcmp_handle object,
	    const void *buffer, size_t length, uint64_t offset);
int	filesystemcmp_stat(int fd, struct filesystemcmp_handle object,
	    struct filesystemcmp_stat_reply *reply);
int	filesystemcmp_unlink(int fd, struct filesystemcmp_handle directory,
	    const char *name, uint32_t flags);
int	filesystemcmp_rename(int fd,
	    struct filesystemcmp_handle old_directory, const char *old_name,
	    struct filesystemcmp_handle new_directory, const char *new_name,
	    uint32_t flags);
int	filesystemcmp_close_handle(int fd,
	    struct filesystemcmp_handle object);

/* Provider and advanced-client framing primitives. */
int	filesystemcmp_validate_message(const struct filesystemcmp_msg *msg,
	    size_t received);
int	filesystemcmp_validate_fds(const struct filesystemcmp_msg *msg,
	    size_t nfds);
int	filesystemcmp_send_message(int fd, const void *message, size_t length,
	    const int *fds, size_t nfds);
ssize_t	filesystemcmp_receive_message(int fd, void *message, size_t capacity,
	    int *fds, size_t *nfds);

__END_DECLS

#endif /* !_FILESYSTEMCMP_H_ */
