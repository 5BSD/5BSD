/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Global state a case changes, saved in its work directory and put back by
 * its cleanup: sysctl values, fault-injection counters and file modes.
 * The cleanup routines make no ATF calls (a cleanup may run after the body
 * failed half-way, or never got to the change), and put back the value
 * read before the change, never an assumed default.  See dqt.h.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dqt.h"

#define	DQT_SAVE_MAX	256	/* a saved value: integers and short strings */

static void
dqt_save_path(const char *kind, const char *name, char *path, size_t len)
{

	(void)snprintf(path, len, "dqt-saved.%s.%s", kind, name);
}

/* Write len bytes to path once: the first save is the original value. */
static void
dqt_save_bytes(const char *path, const void *buf, size_t len)
{
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd == -1 && errno == EEXIST)
		return;
	ATF_REQUIRE_MSG(fd != -1, "%s: %s", path, strerror(errno));
	ATF_REQUIRE_MSG(write(fd, buf, len) == (ssize_t)len, "%s: %s", path,
	    strerror(errno));
	ATF_REQUIRE_EQ(0, close(fd));
}

static ssize_t
dqt_load_bytes(const char *path, void *buf, size_t len)
{
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return (-1);
	n = read(fd, buf, len);
	(void)close(fd);
	return (n);
}

void
dqt_sysctl_save(const char *name)
{
	char buf[DQT_SAVE_MAX], path[PATH_MAX];
	size_t len;

	len = sizeof(buf);
	ATF_REQUIRE_MSG(sysctlbyname(name, buf, &len, NULL, 0) == 0,
	    "sysctl %s: %s", name, strerror(errno));
	dqt_save_path("sysctl", name, path, sizeof(path));
	dqt_save_bytes(path, buf, len);
}

void
dqt_sysctl_save_set_uint(const char *name, u_int value)
{

	dqt_sysctl_save(name);
	dqt_sysctl_set_uint(name, value);
}

void
dqt_sysctl_save_set_int(const char *name, int value)
{

	dqt_sysctl_save(name);
	ATF_REQUIRE_MSG(sysctlbyname(name, NULL, NULL, &value,
	    sizeof(value)) == 0, "sysctl %s=%d: %s", name, value,
	    strerror(errno));
}

bool
dqt_sysctl_restore(const char *name)
{
	char buf[DQT_SAVE_MAX], path[PATH_MAX];
	ssize_t n;

	dqt_save_path("sysctl", name, path, sizeof(path));
	n = dqt_load_bytes(path, buf, sizeof(buf));
	if (n <= 0)
		return (false);	/* never saved: never changed */
	if (sysctlbyname(name, NULL, NULL, buf, (size_t)n) != 0) {
		fprintf(stderr, "cleanup: sysctl %s: %s\n", name,
		    strerror(errno));
		return (false);
	}
	(void)unlink(path);
	return (true);
}

void
dqt_knob_save(const char *name)
{
	u_int v;

	ATF_REQUIRE_MSG(dqt_sysctl_get_uint(name, &v), "sysctl %s: %s", name,
	    strerror(errno));
	ATF_REQUIRE_EQ_MSG(0, v, "%s is already armed (%u): a case before "
	    "this one left it set", name, v);
	dqt_sysctl_save(name);
}

void
dqt_knob_arm(const char *name, u_int n)
{

	dqt_knob_save(name);
	dqt_sysctl_set_uint(name, n);
}

void
dqt_knob_check_consumed(const char *name)
{
	u_int v;

	ATF_REQUIRE_MSG(dqt_sysctl_get_uint(name, &v), "sysctl %s: %s", name,
	    strerror(errno));
	ATF_CHECK_EQ_MSG(0, v, "%s: %u injected faults were not consumed",
	    name, v);
}

void
dqt_knob_disarm(const char *name)
{

	(void)dqt_sysctl_restore(name);
}

void
dqt_mode_save_set(const char *file, mode_t mode)
{
	char path[PATH_MAX];
	struct stat st;

	ATF_REQUIRE_MSG(stat(file, &st) == 0, "%s: %s", file, strerror(errno));
	dqt_save_path("mode", file[0] == '/' ? file + 1 : file, path,
	    sizeof(path));
	for (char *p = path; *p != '\0'; p++)
		if (*p == '/')
			*p = '_';
	dqt_save_bytes(path, &st.st_mode, sizeof(st.st_mode));
	ATF_REQUIRE_MSG(chmod(file, mode) == 0, "chmod %s %o: %s", file,
	    (unsigned)mode, strerror(errno));
}

bool
dqt_mode_restore(const char *file)
{
	char path[PATH_MAX];
	mode_t mode;

	dqt_save_path("mode", file[0] == '/' ? file + 1 : file, path,
	    sizeof(path));
	for (char *p = path; *p != '\0'; p++)
		if (*p == '/')
			*p = '_';
	if (dqt_load_bytes(path, &mode, sizeof(mode)) != sizeof(mode))
		return (false);
	if (chmod(file, mode & ALLPERMS) != 0) {
		fprintf(stderr, "cleanup: chmod %s: %s\n", file,
		    strerror(errno));
		return (false);
	}
	(void)unlink(path);
	return (true);
}
