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

ATF_TC_WITHOUT_HEAD(fixed_fd_non_channel_rejected);
ATF_TC_BODY(fixed_fd_non_channel_rejected, tc)
{
	int pfd[2], saved;

	/*
	 * With SERVICE_LOOKUP_FD absent, discovery falls back to probing the
	 * getty-path fixed descriptor (SERVICE_LOOKUP_FIXED_FD).  A non-channel
	 * descriptor parked there (here a pipe) must be rejected exactly as an
	 * env-named non-channel is, so a stale or unrelated fd 3 never leaks
	 * through as an ambient channel.  This case needs no device.
	 */
	ATF_REQUIRE_EQ(0, unsetenv(SERVICE_LOOKUP_ENV));

	/* Preserve whatever the harness left at fd 3, restore it afterward. */
	saved = dup(SERVICE_LOOKUP_FIXED_FD);

	ATF_REQUIRE_EQ(0, pipe(pfd));
	ATF_REQUIRE(dup2(pfd[0], SERVICE_LOOKUP_FIXED_FD) ==
	    SERVICE_LOOKUP_FIXED_FD);

	ATF_CHECK_EQ(-1, service_ambient_lookup_fd());

	if (SERVICE_LOOKUP_FIXED_FD != pfd[0])
		(void)close(SERVICE_LOOKUP_FIXED_FD);
	close(pfd[0]);
	close(pfd[1]);
	if (saved >= 0) {
		(void)dup2(saved, SERVICE_LOOKUP_FIXED_FD);
		close(saved);
	}
}

ATF_TC(fixed_fd_probed_when_env_absent);
ATF_TC_HEAD(fixed_fd_probed_when_env_absent, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "env absent: a genuine channel at the fixed fd is discovered");
}
ATF_TC_BODY(fixed_fd_probed_when_env_absent, tc)
{
	int fd, saved, got;

	/*
	 * The getty-path carry: oracle-init pins the channel at
	 * SERVICE_LOOKUP_FIXED_FD with no environment variable set.  A genuine
	 * mac_capability channel parked there must be discovered and returned.
	 * Gated on the channel device; skips cleanly when unavailable.
	 */
	fd = make_capability_fd();
	if (fd == -1)
		atf_tc_skip("mac_capability channel device unavailable");

	ATF_REQUIRE_EQ(0, unsetenv(SERVICE_LOOKUP_ENV));

	saved = dup(SERVICE_LOOKUP_FIXED_FD);
	ATF_REQUIRE(dup2(fd, SERVICE_LOOKUP_FIXED_FD) ==
	    SERVICE_LOOKUP_FIXED_FD);
	if (fd != SERVICE_LOOKUP_FIXED_FD)
		close(fd);

	got = service_ambient_lookup_fd();
	ATF_CHECK_EQ(SERVICE_LOOKUP_FIXED_FD, got);

	(void)close(SERVICE_LOOKUP_FIXED_FD);
	if (saved >= 0) {
		(void)dup2(saved, SERVICE_LOOKUP_FIXED_FD);
		close(saved);
	}
}

ATF_TC(env_takes_precedence_over_fixed_fd);
ATF_TC_HEAD(env_takes_precedence_over_fixed_fd, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "a valid env-named channel wins over the fixed-fd fallback");
}
ATF_TC_BODY(env_takes_precedence_over_fixed_fd, tc)
{
	int envfd, fixedfd, saved, got;
	char buf[16];

	/*
	 * When SERVICE_LOOKUP_FD names a live channel, the env source wins even
	 * if a different channel also sits at the fixed fd; the fixed fd is only
	 * a fallback for the getty hop.  Two channels are needed, so this is
	 * gated on the device.
	 */
	envfd = make_capability_fd();
	if (envfd == -1)
		atf_tc_skip("mac_capability channel device unavailable");
	fixedfd = make_capability_fd();
	if (fixedfd == -1) {
		close(envfd);
		atf_tc_skip("mac_capability channel device unavailable");
	}

	saved = dup(SERVICE_LOOKUP_FIXED_FD);
	/* Keep envfd off the fixed slot so the two are distinct. */
	if (envfd == SERVICE_LOOKUP_FIXED_FD) {
		int moved = fcntl(envfd, F_DUPFD, SERVICE_LOOKUP_FIXED_FD + 1);

		ATF_REQUIRE(moved >= 0);
		close(envfd);
		envfd = moved;
	}
	ATF_REQUIRE(dup2(fixedfd, SERVICE_LOOKUP_FIXED_FD) ==
	    SERVICE_LOOKUP_FIXED_FD);
	if (fixedfd != SERVICE_LOOKUP_FIXED_FD)
		close(fixedfd);

	(void)snprintf(buf, sizeof(buf), "%d", envfd);
	ATF_REQUIRE_EQ(0, setenv(SERVICE_LOOKUP_ENV, buf, 1));

	got = service_ambient_lookup_fd();
	ATF_CHECK_EQ(envfd, got);

	(void)unsetenv(SERVICE_LOOKUP_ENV);
	close(envfd);
	(void)close(SERVICE_LOOKUP_FIXED_FD);
	if (saved >= 0) {
		(void)dup2(saved, SERVICE_LOOKUP_FIXED_FD);
		close(saved);
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, absent_env_returns_minus1);
	ATF_TP_ADD_TC(tp, malformed_env_returns_minus1);
	ATF_TP_ADD_TC(tp, non_channel_fd_rejected);
	ATF_TP_ADD_TC(tp, install_marks_ambient_and_sets_env);
	ATF_TP_ADD_TC(tp, roundtrip_real_channel);
	ATF_TP_ADD_TC(tp, fixed_fd_non_channel_rejected);
	ATF_TP_ADD_TC(tp, fixed_fd_probed_when_env_absent);
	ATF_TP_ADD_TC(tp, env_takes_precedence_over_fixed_fd);
	return (atf_no_error());
}
