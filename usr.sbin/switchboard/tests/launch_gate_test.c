/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/event.h>
#include <unistd.h>
#include <errno.h>
#include <atf-c.h>

static int fault, registrations, releases, revoked, channels_closed, cleanup;
static int
fault_kevent(int kq, const struct kevent *changes, int nc,
    struct kevent *events, int ne, const struct timespec *timeout)
{
	registrations++;
	if (fault == 1 || fault == 3) {
		if (fault == 3)
			ATF_REQUIRE_EQ(0, kevent(kq, changes, 1, NULL, 0, NULL));
		return (errno = EIO, -1);
	}
	return (kevent(kq, changes, nc, events, ne, timeout));
}
static ssize_t
fault_write(int fd, const void *bytes, size_t length)
{
	releases++;
	if (fault == 2)
		return (errno = EPIPE, -1);
	return (write(fd, bytes, length));
}
#define kevent(...) fault_kevent(__VA_ARGS__)
#define write(...) fault_write(__VA_ARGS__)
#include "../execute.c"
#undef write
#undef kevent

struct switchboard_state sd;
void
svc_authority_revoke_unit(const struct svc_runtime *svc __unused)
{
	revoked++;
}
void
domain_unit_channels_close(const struct svc_runtime *svc __unused)
{
	channels_closed++;
}
int
capsule_release_manifest(int fd __unused, const struct svc_manifest *m __unused)
{
	/* Also prove a cleanup error cannot replace the launch error. */
	return (errno = ENOTCONN, -1);
}
void
supervisor_cleanup_failed_launch(struct svc_runtime *svc)
{
	ATF_REQUIRE(svc->launch == NULL);
	ATF_REQUIRE(svc->pid > 0);
	ATF_REQUIRE(fcntl(svc->pd_fd, F_GETFD) >= 0);
	ATF_REQUIRE(fcntl(svc->coalition_fd, F_GETFD) >= 0);
	cleanup++;
}

ATF_TC(launch_gate_failures);
ATF_TC_HEAD(launch_gate_failures, tc)
{
	atf_tc_set_md_var(tc, "timeout", "20");
	atf_tc_set_md_var(tc, "descr",
	    "Actual execute.c gate failure retains child and coalition for cleanup");
}
ATF_TC_BODY(launch_gate_failures, tc)
{
	struct svc_runtime svc;
	int gate[2], coalition[2], proof[2], kq, status, result, lease;
	char byte;

	for (fault = 0; fault <= 3; fault++) {
		memset(&svc, 0, sizeof(svc));
		registrations = releases = revoked = channels_closed = cleanup = 0;
		svc.manifest.unix_protocol = true;
		strlcpy(svc.manifest.label, "org.test.launch", sizeof(svc.manifest.label));
		ATF_REQUIRE_EQ(0, pipe(gate));
		ATF_REQUIRE_EQ(0, pipe(coalition));
		ATF_REQUIRE_EQ(0, pipe(proof));
		kq = kqueue();
		ATF_REQUIRE(kq >= 0);
		svc.coalition_fd = coalition[0];
		svc.channel_fd = -1;
		svc.launch = calloc(1, sizeof(*svc.launch));
		ATF_REQUIRE(svc.launch != NULL);
		lease = svc.launch->capprotect_fd = open("/dev/null", O_RDONLY);
		ATF_REQUIRE(lease >= 0);
		svc.pid = pdfork(&svc.pd_fd, PD_CLOEXEC);
		ATF_REQUIRE(svc.pid >= 0);
		if (svc.pid == 0) {
			close(gate[1]);
			close(proof[0]);
			if (read(gate[0], &byte, 1) == 1 && byte == 'R')
				(void)write(proof[1], "X", 1);
			_exit(0);
		}
		close(gate[0]);
		close(proof[1]);
		result = svc_launch_release(&svc, kq, gate[1]);
		if (fault == 0) {
			ATF_REQUIRE_EQ(0, result);
			ATF_CHECK_EQ(1, read(proof[0], &byte, 1));
			ATF_CHECK_EQ('X', byte);
			ATF_CHECK_EQ(0, cleanup);
			ATF_CHECK(svc.launch != NULL);
			free(svc.launch);
			close(lease);
		} else {
			ATF_CHECK_EQ(fault == 2 ? EPIPE : EIO, errno);
			ATF_REQUIRE_EQ(-1, result);
			ATF_CHECK_EQ(0, read(proof[0], &byte, 1));
			ATF_CHECK_EQ(1, revoked);
			ATF_CHECK_EQ(1, channels_closed);
			ATF_CHECK_EQ(1, cleanup);
			ATF_CHECK_ERRNO(EBADF, fcntl(lease, F_GETFD) == -1);
		}
		ATF_CHECK_EQ(1, registrations);
		ATF_CHECK_EQ(fault == 1 || fault == 3 ? 0 : 1, releases);
		ATF_CHECK_ERRNO(EBADF, fcntl(gate[1], F_GETFD) == -1);
		do {
			result = pdwait(svc.pd_fd, &status, WEXITED, NULL, NULL);
		} while (result == -1 && errno == EINTR);
		ATF_CHECK_MSG(result == 0 || (result == -1 &&
		    (errno == ECHILD || errno == ESRCH)),
		    "pdwait result=%d errno=%d", result, errno);
		close(svc.pd_fd);
		close(coalition[0]);
		close(coalition[1]);
		close(proof[0]);
		close(kq);
	}
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, launch_gate_failures);
	return (atf_no_error());
}
