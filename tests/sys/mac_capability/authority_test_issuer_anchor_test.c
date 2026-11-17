/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The anchor of a test-issuer kernel (options MAC_CAPABILITY_TEST_PERMISSIVE,
 * booted with kern.mac_capability.test_issuer=1): PID 1's attempt to create
 * its issuer, here debug.mac_capability.test_issuer_anchor, revokes every
 * test issuer still alive, and no test issuer can be created afterwards.
 *
 * The anchor lasts for the boot, so this program runs only in a guest of
 * its own: the runner sets test_suites.FreeBSD.authority_anchor=1 for it
 * (require.config), and every other test-issuer case expects an unanchored
 * boot.
 */

#include <sys/param.h>
#include <sys/cap_authority.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	THREADS		8
#define	HELD_MAX	4096

static int
op(int cmd, int fd, void *data)
{

	return (syscall(SYS_cap_process, cmd, fd, 0, data));
}

static void
state(char *buf, size_t size)
{
	size_t len = size - 1;

	memset(buf, 0, size);
	ATF_REQUIRE_MSG(sysctlbyname("kern.mac_capability.test_issuer_state",
	    buf, &len, NULL, 0) == 0, "not a test-issuer kernel: %s",
	    strerror(errno));
}

static int
issue(int issuer)
{
	struct cap_authority_spec spec = {
		.version = CAP_AUTH_VERSION, .kind = CAP_AUTH_MANAGED,
	};

	return (op(CAP_AUTH_ISSUE, issuer, &spec));
}

static _Atomic int anchored;
static _Atomic int held_count;
static int held[HELD_MAX];

/* Create test issuers until the anchor; keep every one created. */
static void *
creator(void *arg __unused)
{
	int fd, n;

	for (;;) {
		fd = op(CAP_AUTH_ISSUER_CREATE, -1, NULL);
		if (fd < 0) {
			if (errno != EPERM)
				return ((void *)(intptr_t)errno);
			/* Only refused once anchored. */
			if (!atomic_load(&anchored))
				return ((void *)(intptr_t)-1);
			return (NULL);
		}
		n = atomic_fetch_add(&held_count, 1);
		if (n >= HELD_MAX) {
			close(fd);
			atomic_fetch_sub(&held_count, 1);
			continue;
		}
		held[n] = fd;
	}
}

ATF_TC(anchor);
ATF_TC_HEAD(anchor, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The anchor revokes every live test issuer and what it produced, refuses new ones, and races creation safely");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.config", "authority_anchor");
	atf_tc_set_md_var(tc, "timeout", "600");
}
ATF_TC_BODY(anchor, tc)
{
	struct cap_authority_constraint constraint = { .nexec = 1 };
	struct cap_authority_lease_create lease = { .seconds = 600 }, refused;
	struct cap_authority_application app;
	struct cap_authority_bind bind;
	struct cap_authority_info info;
	pthread_t threads[THREADS];
	char buf[32];
	void *result;
	int issuer, constrained, spare, image, one = 1, n;

	state(buf, sizeof(buf));
	ATF_REQUIRE_MSG(strcmp(buf, "anchored") != 0,
	    "the boot is already anchored");

	/* One test issuer with everything it can produce. */
	issuer = op(CAP_AUTH_ISSUER_CREATE, -1, NULL);
	ATF_REQUIRE_MSG(issuer >= 0, "relaxed create: %s", strerror(errno));
	constrained = issue(issuer);
	spare = issue(issuer);
	ATF_REQUIRE(constrained >= 0 && spare >= 0);
	/* A private image: a registration must not touch a shared binary. */
	ATF_REQUIRE(system("cp /usr/bin/true ./image") == 0);
	image = open("./image", O_RDONLY);
	ATF_REQUIRE(image >= 0);
	constraint.token_fd = constrained;
	constraint.executable_fds[0] = image;
	ATF_REQUIRE_MSG(op(CAP_AUTH_CONSTRAIN, issuer, &constraint) == 0,
	    "constrain: %s", strerror(errno));
	app = (struct cap_authority_application){ .token_fd = constrained };
	ATF_REQUIRE_MSG(op(CAP_AUTH_REGISTER_APP, issuer, &app) == 0,
	    "register: %s", strerror(errno));
	ATF_REQUIRE_MSG(op(CAP_AUTH_LEASE_CREATE, issuer, &lease) == 0,
	    "lease: %s", strerror(errno));
	ATF_REQUIRE(op(CAP_AUTH_LEASE_CHECK, lease.control_fd, NULL) == 0);
	ATF_REQUIRE(op(CAP_AUTH_TOKEN_INFO, spare, &info) == 0);
	ATF_REQUIRE_EQ(info.revoked, 0);

	/* Creators race the anchor. */
	for (int i = 0; i < THREADS; i++)
		ATF_REQUIRE(pthread_create(&threads[i], NULL, creator,
		    NULL) == 0);
	usleep(1000 * (50 + arc4random_uniform(200)));
	atomic_store(&anchored, 1);
	ATF_REQUIRE_MSG(sysctlbyname("debug.mac_capability.test_issuer_anchor",
	    NULL, NULL, &one, sizeof(one)) == 0, "anchor: %s",
	    strerror(errno));
	for (int i = 0; i < THREADS; i++) {
		ATF_REQUIRE(pthread_join(threads[i], &result) == 0);
		ATF_CHECK_MSG(result == NULL,
		    "creator %d: %s", i, (intptr_t)result == -1 ?
		    "refused before the anchor" : strerror((int)(intptr_t)result));
	}
	n = atomic_load(&held_count);
	printf("test issuers created during the race: %d\n", n);

	state(buf, sizeof(buf));
	ATF_CHECK_STREQ(buf, "anchored");
	/* Nothing can be created any more. */
	ATF_CHECK_ERRNO(EPERM, op(CAP_AUTH_ISSUER_CREATE, -1, NULL) == -1);
	/* What the first issuer produced is revoked. */
	ATF_REQUIRE(op(CAP_AUTH_TOKEN_INFO, spare, &info) == 0);
	ATF_CHECK_EQ_MSG(info.revoked, 1, "grant not revoked");
	ATF_CHECK_ERRNO(EPERM,
	    op(CAP_AUTH_LEASE_CHECK, lease.control_fd, NULL) == -1);
	/* A revoked issuer refuses new work. */
	ATF_CHECK_ERRNO(EPERM, issue(issuer) == -1);
	constraint.token_fd = spare;
	ATF_CHECK_ERRNO(EPERM, op(CAP_AUTH_CONSTRAIN, issuer, &constraint) == -1);
	refused = (struct cap_authority_lease_create){ .seconds = 600 };
	ATF_CHECK_ERRNO(EPERM, op(CAP_AUTH_LEASE_CREATE, issuer, &refused) == -1);
	bind = (struct cap_authority_bind){ .token_fd = spare,
	    .capability_fd = -1 };
	ATF_CHECK_ERRNO(EPERM, op(CAP_AUTH_BIND, issuer, &bind) == -1);
	app = (struct cap_authority_application){ .token_fd = spare };
	ATF_CHECK_ERRNO(EPERM, op(CAP_AUTH_REGISTER_APP, issuer, &app) == -1);
	/* So does every issuer created during the race. */
	for (int i = 0; i < n; i++) {
		ATF_CHECK_ERRNO(EPERM, issue(held[i]) == -1);
		close(held[i]);
	}
	close(spare); close(constrained); close(image); close(issuer);
	close(lease.control_fd); close(lease.owner_fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, anchor);
	return (atf_no_error());
}
