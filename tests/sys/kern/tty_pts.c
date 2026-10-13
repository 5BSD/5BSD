/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <termios.h>

#include <atf-c.h>
#include <libutil.h>

/* Just a little more concise. */
#define	newpty(masterp, slavep)	openpty((masterp), (slavep), NULL, NULL, NULL)

ATF_TC_WITHOUT_HEAD(fionread);
ATF_TC_BODY(fionread, tc)
{
	char rbuf[32];
	char buf[] = "Hello";
	int master, slave;
	int bytes;

	ATF_REQUIRE_EQ(0, newpty(&master, &slave));

	/* Should be empty to begin with. */
	ATF_REQUIRE_EQ(0, ioctl(master, FIONREAD, &bytes));
	ATF_REQUIRE_EQ(0, bytes);

	ATF_REQUIRE_EQ(sizeof(buf) - 1, write(slave, buf, sizeof(buf) - 1));
	ATF_REQUIRE_EQ(0, ioctl(master, FIONREAD, &bytes));
	ATF_REQUIRE_EQ(sizeof(buf) - 1, bytes);

	/* Drain what we have available, should result in 0 bytes again. */
	ATF_REQUIRE_EQ(sizeof(buf) - 1, read(master, rbuf, sizeof(rbuf)));
	ATF_REQUIRE_EQ(0, ioctl(master, FIONREAD, &bytes));
	ATF_REQUIRE_EQ(0, bytes);

	/*
	 * Write once more, then close the slave side with data still in the
	 * buffer.
	 */
	ATF_REQUIRE_EQ(sizeof(buf) - 1, write(slave, buf, sizeof(buf) - 1));
	ATF_REQUIRE_EQ(0, ioctl(master, FIONREAD, &bytes));
	ATF_REQUIRE_EQ(sizeof(buf) - 1, bytes);

	ATF_REQUIRE_EQ(0, close(slave));

	/*
	 * The tty's output queue is discarded upon close, so we shouldn't have
	 * anything else to read().
	 */
	ATF_REQUIRE_EQ(0, ioctl(master, FIONREAD, &bytes));
	ATF_REQUIRE_EQ(0, bytes);
	ATF_REQUIRE_EQ(0, read(master, rbuf, sizeof(rbuf)));
}

/* The clone device is provided by the core, without the old pty module. */
ATF_TC_WITHOUT_HEAD(ptmx_core);
ATF_TC_BODY(ptmx_core, tc)
{
	struct stat st;
	struct termios term;
	struct pollfd pfd;
	char path[128], byte;
	int master, slave, unit;

	master = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_NONBLOCK);
	ATF_REQUIRE(master >= 0);
	ATF_REQUIRE_EQ(0, fstat(master, &st));
	ATF_REQUIRE(S_ISCHR(st.st_mode));
	ATF_REQUIRE_EQ(0, ioctl(master, TIOCGPTN, &unit));
	ATF_REQUIRE(unit >= 0);
	ATF_REQUIRE_EQ(0, grantpt(master));
	ATF_REQUIRE_EQ(0, unlockpt(master));
	ATF_REQUIRE_EQ(0, ptsname_r(master, path, sizeof(path)));
	ATF_REQUIRE(strncmp(path, "/dev/pts/", 9) == 0);
	slave = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
	ATF_REQUIRE(slave >= 0);
	ATF_REQUIRE_EQ(0, tcgetattr(slave, &term));
	cfmakeraw(&term);
	ATF_REQUIRE_EQ(0, tcsetattr(slave, TCSANOW, &term));
	ATF_REQUIRE_EQ(1, write(master, "m", 1));
	pfd = (struct pollfd){ .fd = slave, .events = POLLIN };
	ATF_REQUIRE_EQ(1, poll(&pfd, 1, 1000));
	ATF_REQUIRE_EQ(1, read(slave, &byte, 1));
	ATF_REQUIRE_EQ('m', byte);
	ATF_REQUIRE_EQ(1, write(slave, "s", 1));
	pfd.fd = master;
	ATF_REQUIRE_EQ(1, poll(&pfd, 1, 1000));
	ATF_REQUIRE_EQ(1, read(master, &byte, 1));
	ATF_REQUIRE_EQ('s', byte);
	ATF_REQUIRE_EQ(0, close(slave));
	ATF_REQUIRE_EQ(0, close(master));
}

ATF_TC_WITHOUT_HEAD(legacy_names_absent);
ATF_TC_BODY(legacy_names_absent, tc)
{
	int fd;

	fd = open("/dev/ptyp0", O_RDWR | O_NOCTTY);
	ATF_REQUIRE_EQ(-1, fd);
	ATF_REQUIRE_EQ(ENOENT, errno);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fionread);
	ATF_TP_ADD_TC(tp, ptmx_core);
	ATF_TP_ADD_TC(tp, legacy_names_absent);
	return (atf_no_error());
}
