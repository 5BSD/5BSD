/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Fault-injection coverage for the syscall / allocator FAILURE arms of
 * blued_config_load_fd() (config.c, usr.sbin/bluetooth/blued).
 *
 *   lseek(fd, 0, SEEK_SET) < 0  -> return -1   (config.c:845)
 *   malloc(st_size + 1) == NULL -> return -1   (config.c:849)
 *
 * Both arms guard real runtime failures on an already-fstat'd descriptor
 * (a seek error, or OOM sizing the file buffer) and are unreachable with a
 * healthy fd + allocator.  We reach them with linker --wrap(3) seams on
 * lseek() and malloc(): each wrapper fails the Nth (1-based) call after the
 * test arms it and otherwise tail-calls __real_<sym>.  --wrap only redirects
 * the references emitted from config.o and this test object, so libc/libucl
 * internal allocations and seeks are unaffected.
 *
 * Oracle: config.h documents blued_config_load_fd() as returning 0 on
 * success and -1 on failure; a failed seek or buffer allocation must surface
 * -1 without mutating the (defaults-initialised) config beyond what a normal
 * failed load leaves.
 *
 * Links with: config.c
 * LDFLAGS: -Wl,--wrap=lseek -Wl,--wrap=malloc
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

/* ================================================================
 * Fault-injection seams (fail the Nth 1-based call when armed).
 * ================================================================ */
static long	fi_lseek_at, fi_lseek_n;
static long	fi_malloc_at, fi_malloc_n;

static int
fi_hit(long *at, long *n)
{

	(*n)++;
	return (*at != 0 && *n == *at);
}

static void
fault_reset(void)
{

	fi_lseek_at = fi_lseek_n = 0;
	fi_malloc_at = fi_malloc_n = 0;
}

extern off_t	__real_lseek(int, off_t, int);
off_t
__wrap_lseek(int fd, off_t offset, int whence)
{

	if (fi_hit(&fi_lseek_at, &fi_lseek_n)) {
		errno = ESPIPE;			/* plausible: unseekable fd */
		return ((off_t)-1);
	}
	return (__real_lseek(fd, offset, whence));
}

extern void	*__real_malloc(size_t);
void *
__wrap_malloc(size_t size)
{

	if (fi_hit(&fi_malloc_at, &fi_malloc_n)) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_malloc(size));
}

/* Create a temp file holding valid config text; returns an open RDONLY fd. */
static int
temp_cfg_fd(void)
{
	char tmpl[] = "/tmp/blued_cfg_fault.XXXXXX";
	const char *text = "reconnect = true;\n";
	int fd, rfd;
	size_t len = strlen(text);

	fd = mkstemp(tmpl);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(write(fd, text, len) == (ssize_t)len);
	ATF_REQUIRE(close(fd) == 0);
	rfd = open(tmpl, O_RDONLY);
	ATF_REQUIRE(rfd >= 0);
	(void)unlink(tmpl);
	return (rfd);
}

/* ================================================================
 * lseek() fails after a successful fstat: load must return -1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_load_fd_lseek_fails);
ATF_TC_BODY(fault_load_fd_lseek_fails, tc)
{
	struct blued_config cfg;
	int fd;

	fault_reset();
	fd = temp_cfg_fd();
	blued_config_defaults(&cfg);

	/* Fail the first lseek reference from config.c (the SEEK_SET rewind). */
	fi_lseek_n = 0;
	fi_lseek_at = 1;
	ATF_CHECK_EQ(blued_config_load_fd(&cfg, fd), -1);
	fi_lseek_at = 0;

	(void)close(fd);
}

/* ================================================================
 * malloc() of the file buffer fails: load must return -1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_load_fd_malloc_fails);
ATF_TC_BODY(fault_load_fd_malloc_fails, tc)
{
	struct blued_config cfg;
	int fd;

	fault_reset();
	fd = temp_cfg_fd();
	blued_config_defaults(&cfg);

	/*
	 * fstat + lseek perform no allocation, so the first malloc reference
	 * reached inside blued_config_load_fd() is the file buffer (line 848).
	 */
	fi_malloc_n = 0;
	fi_malloc_at = 1;
	ATF_CHECK_EQ(blued_config_load_fd(&cfg, fd), -1);
	fi_malloc_at = 0;

	(void)close(fd);
}

/* ================================================================
 * Control: with both seams disarmed the same fd loads cleanly (return 0),
 * confirming the wrappers are transparent and the failures above were
 * solely fault-driven.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_load_fd_clean_when_disarmed);
ATF_TC_BODY(fault_load_fd_clean_when_disarmed, tc)
{
	struct blued_config cfg;
	int fd;

	fault_reset();
	fd = temp_cfg_fd();
	blued_config_defaults(&cfg);

	ATF_CHECK_EQ(blued_config_load_fd(&cfg, fd), 0);

	(void)close(fd);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fault_load_fd_lseek_fails);
	ATF_TP_ADD_TC(tp, fault_load_fd_malloc_fails);
	ATF_TP_ADD_TC(tp, fault_load_fd_clean_when_disarmed);

	return (atf_no_error());
}
