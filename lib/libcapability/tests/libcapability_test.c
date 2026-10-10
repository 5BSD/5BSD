/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/ioctl.h>
#include <sys/event.h>
#include <sys/mman.h>

#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_coalition_proto.h>
#include <dev/mac_capability/mac_capability_capprotect_proto.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <capability.h>

ATF_TC_WITHOUT_HEAD(get_info_arguments);
ATF_TC_BODY(get_info_arguments, tc)
{
	struct capability_info information;

	memset(&information, 0, sizeof(information));
	information.size = 1;
	ATF_CHECK_ERRNO(EINVAL,
	    capability_get_info(0, &information) == -1);
	information.size = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    capability_get_info(-1, &information) == -1);
	ATF_CHECK_ERRNO(EINVAL, capability_get_info(0, NULL) == -1);
}

ATF_TC_WITHOUT_HEAD(kernel_call_arguments_and_cleanup);
ATF_TC_BODY(kernel_call_arguments_and_cleanup, tc)
{
	char request, reply[8];
	int request_fds[CAPABILITY_CALL_MAX_FDS + 1];
	int reply_fds[CAPABILITY_CALL_MAX_FDS + 1];
	size_t reply_length, reply_nfds;

	request = 'q';
	reply_length = sizeof(reply);
	reply_nfds = 0;
	ATF_CHECK_ERRNO(EINVAL, capability_kernel_call(-1, &request,
	    sizeof(request), NULL, 0, reply, &reply_length, NULL,
	    &reply_nfds) == -1);
	ATF_CHECK_EQ(0, reply_length);
	ATF_CHECK_EQ(0, reply_nfds);

	reply_length = 1;
	reply_nfds = 0;
	ATF_CHECK_ERRNO(EINVAL, capability_kernel_call(0, NULL, 1, NULL, 0,
	    reply, &reply_length, NULL, &reply_nfds) == -1);
	ATF_CHECK_EQ(0, reply_length);
	ATF_CHECK_EQ(0, reply_nfds);

	reply_length = 0;
	reply_nfds = 1;
	ATF_CHECK_ERRNO(EINVAL, capability_kernel_call(0, &request,
	    sizeof(request), NULL, 0, NULL, &reply_length, NULL,
	    &reply_nfds) == -1);
	ATF_CHECK_EQ(0, reply_length);
	ATF_CHECK_EQ(0, reply_nfds);

	memset(request_fds, 0, sizeof(request_fds));
	reply_fds[0] = 99;
	reply_fds[1] = 99;
	reply_length = sizeof(reply);
	reply_nfds = 2;
	ATF_CHECK_ERRNO(EINVAL, capability_kernel_call(0, &request,
	    sizeof(request), request_fds, CAPABILITY_CALL_MAX_FDS + 1,
	    reply, &reply_length, reply_fds, &reply_nfds) == -1);
	ATF_CHECK_EQ(0, reply_length);
	ATF_CHECK_EQ(0, reply_nfds);
	ATF_CHECK_EQ(-1, reply_fds[0]);
	ATF_CHECK_EQ(-1, reply_fds[1]);

	reply_length = sizeof(reply);
	reply_nfds = CAPABILITY_CALL_MAX_FDS + 1;
	ATF_CHECK_ERRNO(EINVAL, capability_kernel_call(0, &request,
	    sizeof(request), NULL, 0, reply, &reply_length, reply_fds,
	    &reply_nfds) == -1);
	ATF_CHECK_EQ(0, reply_length);
	ATF_CHECK_EQ(0, reply_nfds);
}

ATF_TC_WITHOUT_HEAD(wrong_type_preserves_request_descriptors);
ATF_TC_BODY(wrong_type_preserves_request_descriptors, tc)
{
	struct capability_info information;
	char request, reply[8];
	int fd, pipefd[2], reply_fds[2];
	size_t reply_length, reply_nfds;

	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	memset(&information, 0, sizeof(information));
	ATF_CHECK_ERRNO(ENOTTY, capability_get_info(fd, &information) == -1);
	ATF_REQUIRE_EQ(0, pipe(pipefd));
	request = 'q';
	reply_fds[0] = 99;
	reply_fds[1] = 99;
	reply_length = sizeof(reply);
	reply_nfds = 2;
	ATF_CHECK_ERRNO(ENOTTY, capability_kernel_call(fd, &request,
	    sizeof(request), &pipefd[0], 1, reply, &reply_length, reply_fds,
	    &reply_nfds) == -1);
	ATF_CHECK_EQ(0, reply_length);
	ATF_CHECK_EQ(0, reply_nfds);
	ATF_CHECK_EQ(-1, reply_fds[0]);
	ATF_CHECK_EQ(-1, reply_fds[1]);
	ATF_CHECK(fcntl(pipefd[0], F_GETFD) >= 0);
	close(pipefd[0]);
	close(pipefd[1]);
	close(fd);
}

ATF_TC(live_channel_metadata);
ATF_TC_HEAD(live_channel_metadata, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "GETINFO returns validated metadata for a live kernel channel service");
}
ATF_TC_BODY(live_channel_metadata, tc)
{
	struct mac_capability_connect_args connect;
	struct capability_info information;
	int control;

	control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE_MSG(control >= 0, "open mac_capability: %s",
	    strerror(errno));
	memset(&connect, 0, sizeof(connect));
	strlcpy(connect.name, "channel", sizeof(connect.name));
	ATF_REQUIRE_EQ_MSG(0, ioctl(control, MAC_CAPABILITY_CONNECT, &connect),
	    "connect channel: %s", strerror(errno));
	close(control);
	memset(&information, 0, sizeof(information));
	information.size = sizeof(information);
	ATF_REQUIRE_EQ(0, capability_get_info(connect.fd, &information));
	ATF_CHECK_STREQ("channel", information.name);
	ATF_CHECK_EQ(sizeof(information), information.size);
	ATF_CHECK(information.message_limit > 0);
	ATF_CHECK(information.queue_depth > 0);
	ATF_CHECK(information.max_fds <= CAPABILITY_CALL_MAX_FDS);
	close(connect.fd);
}

ATF_TC(live_zero_length_kernel_call);
ATF_TC_HEAD(live_zero_length_kernel_call, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_capprotect");
	atf_tc_set_md_var(tc, "descr",
	    "A successful no-reply kernel call preserves the complete userspace ABI object");
}
ATF_TC_BODY(live_zero_length_kernel_call, tc)
{
	struct mac_capability_connect_args connect;
	struct cp_request request;
	size_t reply_length, reply_nfds;
	int control;

	control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE_MSG(control >= 0, "open mac_capability: %s",
	    strerror(errno));
	memset(&connect, 0, sizeof(connect));
	strlcpy(connect.name, "capprotect", sizeof(connect.name));
	ATF_REQUIRE_EQ_MSG(0, ioctl(control, MAC_CAPABILITY_CONNECT, &connect),
	    "connect capprotect: %s", strerror(errno));
	close(control);
	memset(&request, 0, sizeof(request));
	request.op = CP_OP_SHIELD;
	request.flags = CP_SF_CORE;
	reply_length = 0;
	reply_nfds = 0;
	ATF_REQUIRE_EQ_MSG(0, capability_kernel_call(connect.fd, &request,
	    sizeof(request), NULL, 0, NULL, &reply_length, NULL, &reply_nfds),
	    "shield call: %s", strerror(errno));
	ATF_CHECK_EQ(0, reply_length);
	ATF_CHECK_EQ(0, reply_nfds);
	close(connect.fd);
}

ATF_TC_WITHOUT_HEAD(coalition_arguments);
ATF_TC_BODY(coalition_arguments, tc)
{
	struct capability_coalition_status status = { .size = 1 }, before;

	before = status;
	ATF_CHECK_ERRNO(EINVAL, capability_coalition_watch(-1) == -1);
	ATF_CHECK_ERRNO(EINVAL, capability_coalition_status(0, &status) == -1);
	ATF_CHECK_ERRNO(EINVAL, capability_coalition_receive(0, &status) == -1);
	ATF_CHECK_EQ(0, memcmp(&before, &status, sizeof(status)));
	ATF_CHECK_ERRNO(EINVAL, capability_coalition_status(0, NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, capability_coalition_receive(-1, &status) == -1);
}

ATF_TC(live_coalition_cleanup);
ATF_TC_HEAD(live_coalition_cleanup, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
	atf_tc_set_md_var(tc, "descr", "Library cleanup views preserve completion and failure outcomes");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(live_coalition_cleanup, tc)
{
	struct capability_coalition_status state, before;
	struct coalition_req_hdr request = { .op = COALITION_OP_ENLIST };
	struct coalition_reply reply;
	struct kevent event;
	struct timespec timeout = { .tv_sec = 5 };
	int device, control, watch, kq, shm, flags;

	device = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE(device >= 0);
	for (unsigned fail = 0; fail < 2; fail++) {
		control = capability_service_connect(device, "coalition");
		ATF_REQUIRE(control >= 0);
		watch = capability_coalition_watch(control);
		ATF_REQUIRE(watch >= 0);
		flags = fcntl(watch, F_GETFD);
		ATF_REQUIRE(flags >= 0);
		ATF_CHECK_EQ(FD_CLOEXEC | FD_CLOFORK,
		    flags & (FD_CLOEXEC | FD_CLOFORK));
		flags = fcntl(watch, F_GETFL);
		ATF_REQUIRE(flags >= 0);
		ATF_CHECK((flags & O_NONBLOCK) != 0);
		memset(&state, 0, sizeof(state));
		ATF_REQUIRE_EQ(0, capability_coalition_status(control, &state));
		ATF_CHECK_EQ(CAPABILITY_COALITION_ACTIVE, state.phase);
		ATF_REQUIRE_EQ(0, capability_coalition_status(watch, &state));
		ATF_CHECK_EQ(sizeof(state), state.size);
		before = state;
		ATF_CHECK_ERRNO(EAGAIN, capability_coalition_receive(watch, &state) == -1);
		ATF_CHECK_EQ(0, memcmp(&before, &state, sizeof(state)));
		shm = -1;
		if (fail) {
			shm = memfd_create("lib-coalition-cleanup", MFD_ALLOW_SEALING);
			ATF_REQUIRE(shm >= 0);
			ATF_REQUIRE_EQ(0, ftruncate(shm, 4096));
			ATF_REQUIRE_EQ(0, fcntl(shm, F_ADD_SEALS, F_SEAL_SHRINK));
			ATF_REQUIRE_EQ(0, capability_service_call_fds(control, &request,
			    sizeof(request), &shm, 1, &reply, sizeof(reply), NULL, 0));
			ATF_REQUIRE_EQ(0, reply.status);
		}
		kq = kqueue();
		ATF_REQUIRE(kq >= 0);
		EV_SET(&event, watch, EVFILT_READ, EV_ADD, 0, 0, NULL);
		ATF_REQUIRE_EQ(0, kevent(kq, &event, 1, NULL, 0, NULL));
		ATF_REQUIRE_EQ(0, close(control));
		ATF_REQUIRE_EQ(1, kevent(kq, NULL, 0, &event, 1, &timeout));
		ATF_REQUIRE_EQ(0, capability_coalition_receive(watch, &state));
		ATF_CHECK_EQ(fail ? CAPABILITY_COALITION_FAILED :
		    CAPABILITY_COALITION_COMPLETE, state.phase);
		ATF_CHECK_EQ(fail ? EPERM : 0, state.cleanup_error);
		ATF_CHECK_EQ(0, state.processes | state.forks | state.jails |
		    state.nested | state.capabilities | state.external);
		before = state;
		ATF_REQUIRE_EQ(0, capability_coalition_status(watch, &state));
		ATF_CHECK_EQ(0, memcmp(&before, &state, sizeof(state)));
		ATF_CHECK_ERRNO(EAGAIN, capability_coalition_receive(watch, &state) == -1);
		ATF_CHECK_EQ(0, memcmp(&before, &state, sizeof(state)));
		close(kq);
		close(watch);
		if (shm >= 0)
			close(shm);
	}
	close(device);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, coalition_arguments);
	ATF_TP_ADD_TC(tp, live_coalition_cleanup);
	ATF_TP_ADD_TC(tp, get_info_arguments);
	ATF_TP_ADD_TC(tp, kernel_call_arguments_and_cleanup);
	ATF_TP_ADD_TC(tp, wrong_type_preserves_request_descriptors);
	ATF_TP_ADD_TC(tp, live_channel_metadata);
	ATF_TP_ADD_TC(tp, live_zero_length_kernel_call);
	return (atf_no_error());
}
