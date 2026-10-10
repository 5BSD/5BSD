/* SPDX-License-Identifier: BSD-2-Clause */
/* Starnix socket_test.cc SndRcvBufSockOpt.DoubledOnGet, rewritten and
 * extended with native-limit, alias and failure-atomicity checks.
 * Reference: 8a938a3224e768f6254ee12d240b6492361ebccf. */
#include "linux_test.h"
#define ENOPROTOOPT 92
static long
getbuf(long fd, int option, int *value)
{
	int len = sizeof(*value);
	long r = sys5(SYS_getsockopt, fd, 1, option, value, &len);
	return (r == 0 && len != sizeof(*value) ? -1 : r);
}
static long
setbuf(long fd, int option, int value)
{
	return (sys5(SYS_setsockopt, fd, 1, option, &value, sizeof(value)));
}
static int
probe(int mode)
{
	long fd = -1, alias = -1;
	int rc = 0, value, before, after, zero, large;
#define CHECK(c, n) do { if (!(c)) { rc = (n); goto out; } } while (0)
	/* INET stream/datagram and UNIX stream/datagram share these options. */
	for (int family = 1; family <= 2; family++) {
		for (int type = 1; type <= 2; type++) {
			fd = sys3(SYS_socket, family, type | O_CLOEXEC, 0);
			CHECK(fd >= 0, 1);
			alias = sys1(SYS_dup, fd);
			CHECK(alias >= 0, 2);
			for (int opt = 7; opt <= 8; opt++) {
				CHECK(setbuf(fd, opt, 8192) == 0, 3);
				CHECK(getbuf(alias, opt, &value) == 0, 4);
				if (mode == 0) {
					CHECK(value == 16384, 5);
					CHECK(setbuf(alias, opt, 16384) == 0, 6);
					CHECK(getbuf(fd, opt, &value) == 0 && value == 32768, 7);
				} else if (mode == 1) {
					CHECK(setbuf(fd, opt, 0) == 0, 8);
					CHECK(getbuf(fd, opt, &zero) == 0 && zero > 0, 9);
					CHECK(setbuf(fd, opt, 1) == 0, 10);
					CHECK(getbuf(fd, opt, &value) == 0 && value == zero, 11);
					CHECK(setbuf(fd, opt, 0x7fffffff) == 0, 12);
					CHECK(getbuf(fd, opt, &large) == 0 && large >= zero, 13);
					CHECK(setbuf(fd, opt, -1) == 0, 14);
					CHECK(getbuf(fd, opt, &value) == 0 && value == large, 15);
				} else {
					CHECK(getbuf(fd, opt, &before) == 0, 16);
					CHECK(sys5(SYS_setsockopt, fd, 1, opt, &value, 3) == -EINVAL, 17);
					CHECK(sys5(SYS_setsockopt, fd, 1, opt, 0, 4) == -EFAULT, 18);
					CHECK(getbuf(fd, opt, &after) == 0 && after == before, 19);
					/* This case runs unprivileged: no CAP_NET_ADMIN. */
					CHECK(setbuf(fd, opt + 25, 8192) == -EPERM, 20);
					CHECK(getbuf(fd, opt, &after) == 0 && after == before, 21);
					CHECK(getbuf(fd, opt + 25, &value) == -ENOPROTOOPT, 22);
				}
			}
			(void)sys1(SYS_close, alias); alias = -1;
			(void)sys1(SYS_close, fd); fd = -1;
		}
	}
out:
	if (alias >= 0) (void)sys1(SYS_close, alias);
	if (fd >= 0) (void)sys1(SYS_close, fd);
	return (rc);
}
static int doubled(void) { return (probe(0)); }
static int limits(void) { return (probe(1)); }
static int rejected(void) { return (probe(2)); }
static int
test(int argc, char **argv, char **envp)
{
	static const struct subtest cases[] = {
		{ "doubled", doubled }, { "limits", limits }, { "rejected", rejected },
	};
	(void)envp;
	return (run_subtests(argc, argv, cases, sizeof(cases) / sizeof(cases[0])));
}
