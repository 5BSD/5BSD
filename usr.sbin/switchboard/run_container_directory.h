/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_RUN_CONTAINER_DIRECTORY_H
#define SWITCHBOARD_RUN_CONTAINER_DIRECTORY_H
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/* The caller must own the parent namespace against concurrent mutation.
 * Existing entries, including symlinks and empty directories, are never adopted.
 * Failed open leaves the new entry for explicit cleanup rather than guessing
 * whether a pathname still names the directory just created. */
static inline int
sb_run_container_create(int parent, const char *leaf)
{
	if (mkdirat(parent, leaf, 0700) == -1)
		return (-1);
	return (openat(parent, leaf,
	    O_DIRECTORY | O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
}

/* Launch-only authority: consume it before handing the directory to service
 * code. Failure is fatal to the launch, including failure after fchdir. */
static inline int
sb_run_container_enter(int fd)
{
	cap_rights_t rights;

	if (fchdir(fd) == -1 || cap_rights_get(fd, &rights) == -1)
		return (-1);
	cap_rights_clear(&rights, CAP_FCHDIR);
	return (cap_rights_limit(fd, &rights));
}
#endif
