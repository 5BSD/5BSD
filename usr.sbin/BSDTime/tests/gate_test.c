/* SPDX-License-Identifier: BSD-2-Clause */
/* Real clock-gate coverage: run only in a disposable capability-plane VM. */
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_system_proto.h>

#include <atf-c.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <libservice.h>
#include <string.h>
#include <unistd.h>

#include "BSDTime_test.h"
#include "config.h"
#include "timecmp.h"
static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (control < 0)
		return (-1);
	memset(&connect, 0, sizeof(connect));
	strlcpy(connect.name, name, sizeof(connect.name));
	if (ioctl(control, MAC_CAPABILITY_CONNECT, &connect) == -1) {
		error = errno;
		close(control);
		errno = error;
		return (-1);
	}
	close(control);
	return (connect.fd);
}

static int
mint_settime_token(void)
{
	struct mac_capability_call_args ca;
	struct sys_request req;
	int sysfd, tok = -1;

	sysfd = capability_connect("system");
	if (sysfd < 0)
		return (-1);
	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_CLAIM;
	req.gates = SYS_GATE_SETTIME;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_len = 0;
	if (ioctl(sysfd, MAC_CAPABILITY_CALL, &ca) != 0)
		goto fail;
	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_MINT;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_fds = &tok;
	ca.reply_nfds = 1;
	ca.reply_len = 0;
	if (ioctl(sysfd, MAC_CAPABILITY_CALL, &ca) != 0 || tok < 0)
		goto fail;
	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_AUTHORIZE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_len = 0;
	if (ioctl(tok, MAC_CAPABILITY_CALL, &ca) != 0) {
		close(tok);
		goto fail;
	}
	return (tok); /* keep sysfd open: the claim must outlive the token */
fail:
	close(sysfd);
	return (-1);
}

ATF_TC(gate_roundtrip);
ATF_TC_HEAD(gate_roundtrip, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Real time gate in disposable VM; requires vm_clock_test=true");
}
ATF_TC_BODY(gate_roundtrip, tc)
{
	if (!atf_tc_get_config_var_as_bool_wd(tc, "vm_clock_test", false))
		atf_tc_skip(
		    "requires disposable VM and vm_clock_test=true; does change guest time");
	int ends[2], status;
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	pid_t child = fork();
	ATF_REQUIRE(child >= 0);
	if (!child) {
		close(ends[0]);
		int token = mint_settime_token();
		if (token < 0)
			_exit(2);
		bsdtime_test_set_token(token);
		struct timecmp_config config;
		timecmp_config_defaults(&config);
		config.default_set = true;
		if (cap_enter() != 0)
			_exit(3);
		_exit(bsdtime_test_serve_session(ends[1],
		    "org.test.bsdtime.client", &config));
	}
	close(ends[1]);
	struct timecmp_client *client;
	struct timespec now;
	struct timeval delta = { 0 }, old;
	ATF_REQUIRE_EQ(0, timecmp_client_create(ends[0], &client));
	ATF_REQUIRE_EQ(0, timecmp_get(client, &now));
	ATF_REQUIRE_EQ(0, timecmp_set(client, &now));
	ATF_REQUIRE_EQ(0, timecmp_adjust(client, &delta, &old));
	timecmp_client_close(client);
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE_EQ(0, status);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, gate_roundtrip);
	return (atf_no_error());
}
