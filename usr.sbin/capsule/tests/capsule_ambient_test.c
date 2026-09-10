/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Unit tests for the Capsule §21 ambient-lookup fd-hygiene helper
 * (capsule_ambient.h capsule_ambient_pin), the pure extraction of
 * capsule_set_ambient_lookup()'s body.  Covers the audit's fd-hygiene points:
 *  - fd < 0 is rejected with EBADF and nothing is stored;
 *  - a second install closes the descriptor the first one pinned;
 *  - the pinned master keeps FD_CLOEXEC set (closes on getty's execve) and is
 *    CLOFORK-unlocked (survives the getty fork).
 */
#include <sys/capsicum.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <atf-c.h>

#include "capsule_ambient.h"

/* A live descriptor to pin; the read end of a pipe is convenient and real. */
static int
make_fd(void)
{
	int p[2];

	ATF_REQUIRE_EQ(0, pipe(p));
	(void)close(p[1]);
	return (p[0]);
}

/* fd < 0 must be rejected with EBADF and leave the slot untouched. */
ATF_TC_WITHOUT_HEAD(negative_fd_rejected);
ATF_TC_BODY(negative_fd_rejected, tc)
{
	int slot = -1;

	errno = 0;
	ATF_CHECK_EQ(-1, capsule_ambient_pin(&slot, -1));
	ATF_CHECK_EQ(EBADF, errno);
	ATF_CHECK_EQ_MSG(-1, slot, "slot must stay empty on rejection");

	/* A non-empty slot must also survive a rejected install unchanged. */
	slot = make_fd();
	errno = 0;
	ATF_CHECK_EQ(-1, capsule_ambient_pin(&slot, -5));
	ATF_CHECK_EQ(EBADF, errno);
	ATF_CHECK(fcntl(slot, F_GETFD) != -1);	/* still open */
	(void)close(slot);
}

/*
 * A successful pin must leave the master with FD_CLOEXEC set (so it closes on
 * the getty child's execve) and CLOFORK unlocked (so it survives the fork).
 */
ATF_TC_WITHOUT_HEAD(pin_sets_cloexec_and_clofork);
ATF_TC_BODY(pin_sets_cloexec_and_clofork, tc)
{
	int slot = -1;
	int fd = make_fd();
	int flags;

	ATF_REQUIRE_EQ(0, capsule_ambient_pin(&slot, fd));
	ATF_CHECK_EQ_MSG(fd, slot, "the pinned fd must be stored in the slot");

	flags = fcntl(slot, F_GETFD);
	ATF_REQUIRE(flags != -1);
	ATF_CHECK_MSG((flags & FD_CLOEXEC) != 0,
	    "the master must keep FD_CLOEXEC so it closes on execve");

	/*
	 * CLOFORK must be UNLOCKED: capsule_ambient_pin sets
	 * CAP_CLOFORK_UNLOCKED, which means the fd is NOT close-on-fork and the
	 * limit may still be tightened later.  Re-applying UNLOCKED must
	 * therefore succeed (a LOCKED fd would reject the downgrade).
	 */
	ATF_CHECK_MSG(cap_clofork_limit(slot, CAP_CLOFORK_UNLOCKED) == 0,
	    "the master must be CLOFORK-unlocked (survives the getty fork)");

	(void)close(slot);
}

/* Installing a second channel must close the descriptor the first one pinned. */
ATF_TC_WITHOUT_HEAD(second_install_closes_first);
ATF_TC_BODY(second_install_closes_first, tc)
{
	int slot = -1;
	int first = make_fd();
	int second = make_fd();

	ATF_REQUIRE_EQ(0, capsule_ambient_pin(&slot, first));
	ATF_REQUIRE_EQ(first, slot);

	ATF_REQUIRE_EQ(0, capsule_ambient_pin(&slot, second));
	ATF_CHECK_EQ_MSG(second, slot, "slot must now hold the replacement");

	/* The first descriptor must have been closed by the replacement. */
	errno = 0;
	ATF_CHECK_EQ_MSG(-1, fcntl(first, F_GETFD),
	    "the previously pinned fd must be closed on replace");
	ATF_CHECK_EQ(EBADF, errno);

	(void)close(slot);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, negative_fd_rejected);
	ATF_TP_ADD_TC(tp, pin_sets_cloexec_and_clofork);
	ATF_TP_ADD_TC(tp, second_install_closes_first);
	return (atf_no_error());
}
