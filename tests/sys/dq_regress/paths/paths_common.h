/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Shared helpers of the path-syscall regression tests.
 *
 * These programs try to break the behaviour of FreeBSD's path system
 * calls for ordinary processes (processes not attached to a dq(4)
 * controller).  Every expected value is the one the kernel source from
 * before DescriptorQueue stage 1c (commit 3f330ee172d) gives; where the
 * answer depends on the file system, the test computes it with an oracle
 * that does not go through a path lookup (the descriptor variant of the
 * same operation) or names the accepted set and says so in a comment
 * marked "TBC".
 */

#ifndef _PATHS_COMMON_H_
#define	_PATHS_COMMON_H_

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <atf-c.h>

/*
 * CHECK_ERR: the call returns -1 with errno == err.  CHECK_OK: the call
 * does not return -1.  Both record a failure and continue, so one run
 * reports every broken case.
 */
#define	CHECK_ERR(call, err) do {					\
	long _r;							\
	int _e;								\
									\
	errno = 0;							\
	_r = (long)(call);						\
	_e = errno;							\
	ATF_CHECK_MSG(_r == -1 && _e == (err),				\
	    "line %d: %s: returned %ld errno %d (%s), expected -1 "	\
	    "errno %d (%s)", __LINE__, #call, _r, _e, strerror(_e),	\
	    (int)(err), strerror(err));					\
} while (0)

#define	CHECK_OK(call) do {						\
	long _r;							\
	int _e;								\
									\
	errno = 0;							\
	_r = (long)(call);						\
	_e = errno;							\
	ATF_CHECK_MSG(_r != -1,						\
	    "line %d: %s: returned %ld errno %d (%s), expected success",\
	    __LINE__, #call, _r, _e, strerror(_e));			\
} while (0)

#define	REQUIRE_OK(call) do {						\
	long _r;							\
	int _e;								\
									\
	errno = 0;							\
	_r = (long)(call);						\
	_e = errno;							\
	ATF_REQUIRE_MSG(_r != -1,					\
	    "line %d: %s: returned %ld errno %d (%s), expected success",\
	    __LINE__, #call, _r, _e, strerror(_e));			\
} while (0)

/* The result of a call as an errno: 0 on success. */
#define	ERRNO_OF(call)	(errno = 0, ((long)(call) == -1 ? errno : 0))

/* Create a regular file holding text (or empty); aborts the case on error. */
void	 pc_mkfile(const char *path, const char *text);
/* mkdir that aborts the case on error. */
void	 pc_mkdir(const char *path);
/* symlink that aborts the case on error. */
void	 pc_symlink(const char *target, const char *path);
/* Remove whatever is at path (file, link or empty directory); no error. */
void	 pc_remove(const char *path);
/* The inode number of path (lstat when nofollow); aborts on error. */
ino_t	 pc_ino(const char *path, bool nofollow);

/*
 * A page whose address is not mapped: a pointer into it faults in
 * copyinstr.  The mapping is released at exit.
 */
const char *pc_unmapped(void);

/*
 * The bytes of s (without its NUL) placed so that they end exactly at the
 * start of an unmapped page: copyinstr faults after reading them.  With
 * withnul, the NUL is placed as the last mapped byte instead, so the
 * string is complete and must be looked up normally.
 */
const char *pc_straddle(const char *s, bool withnul);

/*
 * A path of exactly len bytes (strlen) naming head/.../tail, padded with
 * repeated slashes between head and tail.  buf holds at least len + 1.
 */
void	 pc_longpath(char *buf, size_t len, const char *head,
	    const char *tail);

/* A name of exactly len copies of c (len < NAME_MAX * 2). */
void	 pc_name(char *buf, size_t len, char c);

/*
 * A chain of n symbolic links prefix0 -> prefix1 -> ... -> prefix(n-1) ->
 * target, so that resolving prefix0 follows exactly n links.
 */
void	 pc_symlink_chain(const char *prefix, int n, const char *target);

/* sysctl int read and write; return false when the node is absent. */
bool	 pc_sysctl_get(const char *name, int *valp);
bool	 pc_sysctl_set(const char *name, int val);

/* Whether the effective user is root. */
bool	 pc_is_root(void);

/* A pipe's read end, a UNIX socket, all owned until exit. */
int	 pc_pipefd(void);
int	 pc_sockfd(void);

/* Count the entries of the current directory (excluding . and ..). */
int	 pc_dirent_count(const char *dir);

/*
 * Whether the configuration variable "pre1c" is true (kyua -v
 * test_suites.FreeBSD.pre1c=yes, atf: -v pre1c=yes): the run is a
 * baseline on the kernel from before stage 1c, and the rows that crash
 * that kernel (upstream bugs fixed on this branch, each recorded in
 * /home/koryheard/5bsd-issues) are skipped.  On the current kernel every
 * row runs.
 */
static inline bool
pc_pre1c(const atf_tc_t *tc)
{

	return (atf_tc_get_config_var_as_bool_wd(tc, "pre1c", false));
}

#endif /* !_PATHS_COMMON_H_ */
