/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Process discovery authority/transport tests and session mint wire tests.
 * Legacy environment variables and fixed descriptors never grant discovery.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <channel.h>

#include "libservice.h"
#include "switchboard_svc_proto.h"
#include "service_bootstrap.h"

/*
 * Create a connected mac_capability channel pair via the channel device, or -1
 * with errno == ENODEV when the device is unavailable so a gated case can skip.
 * *client_end is the endpoint an inheritor probes; *switchboard_end is the end the
 * test's responder drives.  Both are returned as bare descriptors.
 */
static int
create_channel_pair(int *client_end, int *switchboard_end)
{
	int pair[2];

	if (mac_capability_channel_create(pair) == -1)
		return (-1);
	*client_end = pair[0];
	*switchboard_end = pair[1];
	return (0);
}

/*
 * A minimal switchboard-side responder that pumps one channel from a helper thread
 * and answers SVC_OP_AMBIENT_HELLO.  In RESP_LOOKUP mode it replies with the
 * magic ack (modeling domain.c's lookup channel); in RESP_ENOTSUP mode it
 * replies ENOTSUP (modeling svc_proto.c's unit control channel default), so the
 * probe must reject it.
 */
enum responder_mode {
	RESP_LOOKUP = 0,
	RESP_ENOTSUP = 1
};

struct responder {
	struct channel		*chan;
	enum responder_mode	 mode;
	pthread_t		 thread;
	volatile int		 stop;

};

static void
responder_request(struct channel *ch, struct channel_message *req, void *ctx)
{
	struct responder *r = ctx;
	uint32_t op = 0;

	(void)ch;
	if (channel_message_length(req) >= sizeof(op))
		memcpy(&op, channel_message_data(req), sizeof(op));
	if (op == SVC_OP_AMBIENT_HELLO && r->mode == RESP_LOOKUP) {
		struct svc_ambient_hello_reply rep = {
			.status = 0,
			.magic = SVC_AMBIENT_HELLO_MAGIC,
		};

		(void)channel_send_reply(req, &(struct channel_outgoing){
			.size = sizeof(struct channel_outgoing),
			.data = &rep,
			.length = sizeof(rep),
		});
	} else {
		struct svc_reply rep = { .status = ENOTSUP };

		(void)channel_send_reply(req, &(struct channel_outgoing){
			.size = sizeof(struct channel_outgoing),
			.data = &rep,
			.length = sizeof(rep),
		});
	}
	channel_message_free(req);
}

static void *
responder_thread(void *arg)
{
	struct responder *r = arg;

	while (!r->stop) {
		int wants, ready;

		wants = channel_wants_write(r->chan);
		if (wants == -1)
			wants = 0;
		ready = channel_wait(r->chan, wants, 20);
		if (ready <= 0)
			continue;
		if ((ready & CHANNEL_WAIT_WRITE) != 0)
			(void)channel_flush(r->chan);
		if ((ready & CHANNEL_WAIT_READ) != 0)
			(void)channel_dispatch(r->chan);
	}
	return (NULL);
}

static int
responder_start(struct responder *r, int switchboard_end, enum responder_mode mode)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);

	memset(r, 0, sizeof(*r));
	r->mode = mode;
	if (channel_create(switchboard_end, &options, &r->chan) == -1)
		return (-1);
	if (channel_set_request_handler(r->chan, responder_request, r) == -1) {
		channel_destroy(r->chan);
		r->chan = NULL;
		return (-1);
	}
	if (pthread_create(&r->thread, NULL, responder_thread, r) != 0) {
		channel_destroy(r->chan);
		r->chan = NULL;
		return (-1);
	}
	return (0);
}

static void
responder_stop(struct responder *r)
{

	if (r->chan == NULL)
		return;
	r->stop = 1;
	(void)pthread_join(r->thread, NULL);
	channel_destroy(r->chan);
}

static void
isolate_ambient_lookup(void)
{
	if (service_clear_ambient_lookup() == -1)
		atf_tc_skip("process discovery context unavailable");
	ATF_REQUIRE_EQ(0, unsetenv(SERVICE_LOOKUP_ENV));
}

ATF_TC_WITHOUT_HEAD(environment_cannot_grant_discovery);
ATF_TC_BODY(environment_cannot_grant_discovery, tc)
{
	int pair[2];
	char text[32];

	(void)tc;
	isolate_ambient_lookup();
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(pair));
	snprintf(text, sizeof(text), "%d", pair[0]);
	ATF_REQUIRE_EQ(0, setenv(SERVICE_LOOKUP_ENV, text, 1));
	ATF_CHECK_EQ(-1, service_ambient_lookup_fd());
	ATF_CHECK_EQ(ENOENT, errno);
	close(pair[0]);
	close(pair[1]);
}

ATF_TC_WITHOUT_HEAD(non_channel_install_rejected);
ATF_TC_BODY(non_channel_install_rejected, tc)
{
	int pair[2];

	(void)tc;
	isolate_ambient_lookup();
	ATF_REQUIRE_EQ(0, pipe(pair));
	ATF_CHECK_EQ(-1, service_install_ambient_lookup(pair[0]));
	ATF_CHECK_EQ(EINVAL, errno);
	close(pair[0]);
	close(pair[1]);
}

ATF_TC_WITHOUT_HEAD(context_holds_reference);
ATF_TC_BODY(context_holds_reference, tc)
{
	struct mac_cap_process_info info;
	int pair[2], fd;

	(void)tc;
	isolate_ambient_lookup();
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(pair));
	ATF_REQUIRE_EQ(0, service_install_ambient_lookup(pair[0]));
	ATF_CHECK(fcntl(pair[0], F_GETFD) & FD_CLOEXEC);
	ATF_CHECK(getenv(SERVICE_LOOKUP_ENV) == NULL);
	close(pair[0]);
	ATF_REQUIRE_EQ(0, service_process_info(&info));
	ATF_CHECK_EQ(1, info.present);
	fd = syscall(SYS_cap_process, MAC_CAP_PROCESS_GET, -1, 0, NULL);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK(fcntl(fd, F_GETFD) & FD_CLOEXEC);
	close(fd);
	ATF_REQUIRE_EQ(0, service_clear_ambient_lookup());
	ATF_CHECK_EQ(-1, service_ambient_lookup_fd());
	ATF_CHECK_EQ(ENOENT, errno);
	close(pair[1]);
}

ATF_TC_WITHOUT_HEAD(wrong_protocol_fails_closed);
ATF_TC_BODY(wrong_protocol_fails_closed, tc)
{
	struct responder responder;
	int client, provider;

	(void)tc;
	isolate_ambient_lookup();
	ATF_REQUIRE_EQ(0, create_channel_pair(&client, &provider));
	ATF_REQUIRE_EQ(0, responder_start(&responder, provider, RESP_ENOTSUP));
	ATF_REQUIRE_EQ(0, service_install_ambient_lookup(client));
	ATF_CHECK_EQ(-1, service_ambient_lookup_fd());
	ATF_REQUIRE_EQ(0, service_clear_ambient_lookup());
	responder_stop(&responder);
	close(client);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, environment_cannot_grant_discovery);
	ATF_TP_ADD_TC(tp, non_channel_install_rejected);
	ATF_TP_ADD_TC(tp, context_holds_reference);
	ATF_TP_ADD_TC(tp, wrong_protocol_fails_closed);
	return (atf_no_error());
}
