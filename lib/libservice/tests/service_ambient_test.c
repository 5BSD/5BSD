/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Ambient lookup-channel helper tests (§21).
 *
 * The environment round-trip, the ambient descriptor marking, and the
 * rejection of an absent or non-channel SERVICE_LOOKUP_FD run anywhere.  The
 * one case that proves service_ambient_lookup_fd() accepts a genuine
 * mac_capability channel needs the channel device and is gated: it skips
 * cleanly when the device is unavailable.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "service_bootstrap.h"

/*
 * Create one genuine mac_capability instance descriptor (it answers
 * MAC_CAPABILITY_GETINFO), or -1 with errno == ENODEV when the device is
 * unavailable so the gated case can skip.
 */
static int
make_capability_fd(void)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR);
	if (control == -1) {
		errno = ENODEV;
		return (-1);
	}
	memset(&connect, 0, sizeof(connect));
	strlcpy(connect.name, "channel", sizeof(connect.name));
	if (ioctl(control, MAC_CAPABILITY_CONNECT, &connect) == -1) {
		error = errno;
		close(control);
		errno = error != 0 ? error : ENODEV;
		return (-1);
	}
	close(control);
	return (connect.fd);
}

ATF_TC_WITHOUT_HEAD(absent_env_returns_minus1);
ATF_TC_BODY(absent_env_returns_minus1, tc)
{

	/* No SERVICE_LOOKUP_FD in the environment: discovery yields nothing. */
	ATF_REQUIRE_EQ(0, unsetenv(SERVICE_LOOKUP_ENV));
	ATF_CHECK_EQ(-1, service_ambient_lookup_fd());
}

ATF_TC_WITHOUT_HEAD(malformed_env_returns_minus1);
ATF_TC_BODY(malformed_env_returns_minus1, tc)
{

	/* A non-numeric or out-of-range value is rejected, not misparsed. */
	ATF_REQUIRE_EQ(0, setenv(SERVICE_LOOKUP_ENV, "not-a-number", 1));
	ATF_CHECK_EQ(-1, service_ambient_lookup_fd());
	ATF_REQUIRE_EQ(0, setenv(SERVICE_LOOKUP_ENV, "-3", 1));
	ATF_CHECK_EQ(-1, service_ambient_lookup_fd());
	(void)unsetenv(SERVICE_LOOKUP_ENV);
}

ATF_TC_WITHOUT_HEAD(non_channel_fd_rejected);
ATF_TC_BODY(non_channel_fd_rejected, tc)
{
	int pfd[2];
	char buf[16];

	/*
	 * A SERVICE_LOOKUP_FD that names an open descriptor which is NOT a
	 * mac_capability channel (here a pipe) is rejected: discovery must not
	 * hand back an arbitrary inherited fd.
	 */
	ATF_REQUIRE_EQ(0, pipe(pfd));
	(void)snprintf(buf, sizeof(buf), "%d", pfd[0]);
	ATF_REQUIRE_EQ(0, setenv(SERVICE_LOOKUP_ENV, buf, 1));
	ATF_CHECK_EQ(-1, service_ambient_lookup_fd());
	(void)unsetenv(SERVICE_LOOKUP_ENV);
	close(pfd[0]);
	close(pfd[1]);
}

ATF_TC_WITHOUT_HEAD(install_marks_ambient_and_sets_env);
ATF_TC_BODY(install_marks_ambient_and_sets_env, tc)
{
	const char *value;
	char expected[16];
	int pfd[2], flags;

	/*
	 * service_install_ambient_lookup() makes the descriptor ambient
	 * (§21.1) and advertises its number.  The ambient marking is a property
	 * of any descriptor, so a pipe suffices to observe it.
	 */
	ATF_REQUIRE_EQ(0, pipe(pfd));
	ATF_REQUIRE_EQ(0, fcntl(pfd[0], F_SETFD, FD_CLOEXEC));

	ATF_REQUIRE_EQ(0, service_install_ambient_lookup(pfd[0]));

	/* Not close-on-exec: survives exec. */
	flags = fcntl(pfd[0], F_GETFD);
	ATF_REQUIRE(flags != -1);
	ATF_CHECK_EQ(0, flags & FD_CLOEXEC);
	/* CAP_CLOFORK_UNLOCKED accepted (idempotent): survives fork. */
	ATF_CHECK_EQ(0, cap_clofork_limit(pfd[0], CAP_CLOFORK_UNLOCKED));

	/* The environment names exactly this descriptor. */
	(void)snprintf(expected, sizeof(expected), "%d", pfd[0]);
	value = getenv(SERVICE_LOOKUP_ENV);
	ATF_REQUIRE(value != NULL);
	ATF_CHECK_STREQ(expected, value);

	(void)unsetenv(SERVICE_LOOKUP_ENV);
	close(pfd[0]);
	close(pfd[1]);
}

ATF_TC(roundtrip_real_channel);
ATF_TC_HEAD(roundtrip_real_channel, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "install then lookup round-trips a genuine mac_capability channel");
}
ATF_TC_BODY(roundtrip_real_channel, tc)
{
	int fd, got;

	fd = make_capability_fd();
	if (fd == -1)
		atf_tc_skip("mac_capability channel device unavailable");

	(void)unsetenv(SERVICE_LOOKUP_ENV);
	ATF_REQUIRE_EQ(0, service_install_ambient_lookup(fd));

	got = service_ambient_lookup_fd();
	ATF_CHECK_EQ(fd, got);

	(void)unsetenv(SERVICE_LOOKUP_ENV);
	close(fd);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, absent_env_returns_minus1);
	ATF_TP_ADD_TC(tp, malformed_env_returns_minus1);
	ATF_TP_ADD_TC(tp, non_channel_fd_rejected);
	ATF_TP_ADD_TC(tp, install_marks_ambient_and_sets_env);
	ATF_TP_ADD_TC(tp, roundtrip_real_channel);
	return (atf_no_error());
}
