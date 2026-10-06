/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Software identity: wire and identity
 * contract between the kernel stamp, libchannel, libservice, and SwitchBoard.
 *
 * Layout cases need no live capability plane.  The sender-ABI cases build a
 * real channel pair over /dev/mac_capability and skip when it is absent.
 */

#include <sys/types.h>
#include <sys/ioctl.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>
#include <channel.h>
#include <libservice.h>
#include <service_bootstrap.h>
#include <service_private.h>
#include <switchboard_svc_proto.h>

/*
 * --- Layout contract (compile-time) ---------------------------------------
 */
_Static_assert(sizeof(struct svc_new_client_msg) == 752,
    "svc_new_client_msg wire layout");
_Static_assert(offsetof(struct svc_new_client_msg, client_nonce) == 416,
    "client_nonce layout");
_Static_assert(offsetof(struct svc_new_client_msg, client_abi) == 424,
    "client_abi follows client_nonce");
_Static_assert(sizeof(struct service_identity) == 760,
    "service_identity layout");
_Static_assert(sizeof(struct service_message_metadata) == 56,
    "service_message_metadata layout");
_Static_assert(sizeof(struct channel_sender) == 32,
    "channel_sender layout");
_Static_assert(sizeof(struct mac_capability_cred_trailer) == 24,
    "cred trailer size is part of the ioctl numbers");
_Static_assert(SERVICE_CLIENT_ABI_NATIVE == CHANNEL_ABI_NATIVE &&
    CHANNEL_ABI_NATIVE == MAC_CAPABILITY_ABI_NATIVE &&
    SVC_CLIENT_ABI_NATIVE == MAC_CAPABILITY_ABI_NATIVE &&
    SERVICE_CLIENT_ABI_LINUX == MAC_CAPABILITY_ABI_LINUX &&
    SVC_CLIENT_ABI_LINUX == MAC_CAPABILITY_ABI_LINUX &&
    SERVICE_CLIENT_ABI_UNKNOWN == 0 && CHANNEL_ABI_UNKNOWN == 0,
    "ABI codes agree across kernel, libchannel, libservice, switchboard");

ATF_TC_WITHOUT_HEAD(wire_layout);
ATF_TC_BODY(wire_layout, tc)
{
	struct svc_new_client_msg nc;
	struct service_identity id;
	struct service_message_metadata md;

	(void)tc;
	/* Runtime mirrors of the static asserts, so a report shows numbers. */
	ATF_CHECK_EQ(752u, (unsigned)sizeof(nc));
	ATF_CHECK_EQ(64u, (unsigned)sizeof(nc.client_label));
	ATF_CHECK_EQ(760u, (unsigned)sizeof(id));
	ATF_CHECK_EQ(56u, (unsigned)sizeof(md));
	/* The identity stamp fields follow rights in order. */
	ATF_CHECK_EQ(offsetof(struct service_identity, rights) + 8,
	    offsetof(struct service_identity, client_nonce));
	ATF_CHECK_EQ(offsetof(struct service_identity, client_nonce) + 8,
	    offsetof(struct service_identity, client_abi));
	ATF_CHECK_EQ(offsetof(struct service_message_metadata, sender_prison) +
	    4, offsetof(struct service_message_metadata, sender_abi));
}

static void
capability_channel_pair(int *first, int *second)
{
	int pair[2], error;

	error = mac_capability_channel_create(pair);
	if (error == -1 && errno == ENOSYS)
		atf_tc_skip("kernel channel creation syscall unavailable");
	ATF_REQUIRE_MSG(error == 0, "channel pair: %s", strerror(errno));
	*first = pair[0];
	*second = pair[1];
}

struct echo_provider {
	struct channel *channel;
	struct channel_sender seen;
	unsigned replies;
	int error;
};

static void
echo_request(struct channel *channel, struct channel_message *message,
    void *cookie)
{
	struct echo_provider *provider = cookie;
	const struct channel_sender *sender;

	(void)channel;
	sender = channel_message_sender(message);
	if (sender != NULL)
		provider->seen = *sender;
	if (channel_send_reply(message,
	    &(struct channel_outgoing)CHANNEL_OUTGOING_INITIALIZER("ok", 2))
	    == -1)
		provider->error = errno;
	provider->replies++;
	channel_message_free(message);
}

static void *
echo_thread(void *cookie)
{
	struct echo_provider *provider = cookie;
	int ready;

	while (provider->replies == 0 && provider->error == 0) {
		ready = channel_wait(provider->channel, 0, 5000);
		if (ready <= 0) {
			provider->error = ready == 0 ? ETIMEDOUT : errno;
			break;
		}
		if (channel_dispatch(provider->channel) < 0) {
			provider->error = errno;
			break;
		}
	}
	return (NULL);
}

/*
 * A provider built on libchannel sees the stamped sender ABI on a request,
 * and a client built on libservice sees it in the reply's message metadata
 * (metadata_from_message copies channel_sender.abi -> sender_abi).  The
 * provider's reply is kernel-originated on the credential side, so its
 * metadata carries no uid stamp and ABI UNKNOWN; the request side carries
 * the process's own identity.
 */
ATF_TC_WITH_CLEANUP(sender_abi_round_trip);
ATF_TC_HEAD(sender_abi_round_trip, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "sender ABI is stamped on requests and surfaced by libchannel and libservice");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sender_abi_round_trip, tc)
{
	struct channel_options provider_options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct echo_provider provider;
	struct service_session *session;
	struct service_message message = {
		.size = sizeof(message),
		.data = "hi",
		.length = 2,
	};
	char buf[8];
	struct service_reply reply = {
		.size = sizeof(reply),
		.data = buf,
		.capacity = sizeof(buf),
	};
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	pthread_t thread;
	int client_fd, provider_fd;

	(void)tc;
	memset(&provider, 0, sizeof(provider));
	capability_channel_pair(&client_fd, &provider_fd);
	ATF_REQUIRE_EQ(0, channel_create(provider_fd, &provider_options,
	    &provider.channel));
	ATF_REQUIRE_EQ(0, channel_set_request_handler(provider.channel,
	    echo_request, &provider));
	ATF_REQUIRE_EQ(0, pthread_create(&thread, NULL, echo_thread,
	    &provider));

	ATF_REQUIRE_EQ(0, service_session_create(client_fd, &session));
	options.timeout_ms = 5000;
	ATF_REQUIRE_MSG(service_session_call(session, &message, &reply,
	    &options) == 0, "session call: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, pthread_join(thread, NULL));
	ATF_CHECK_EQ(0, provider.error);
	ATF_CHECK_EQ(1u, provider.replies);

	/* Request side: the provider saw this process's stamp. */
	ATF_CHECK_EQ(getuid(), provider.seen.uid);
	ATF_CHECK_EQ(getgid(), provider.seen.gid);
	ATF_CHECK(provider.seen.nonce != 0);

	/* Reply side: libservice's metadata mirrors the reply's stamp. */
	ATF_CHECK_EQ(2u, (unsigned)reply.length);
	ATF_CHECK_EQ(sizeof(reply.metadata), reply.metadata.size);
	ATF_CHECK_EQ(2u, (unsigned)reply.metadata.payload_length);
	/* A reply sent by this same process is stamped with its identity. */
	ATF_CHECK_EQ(getuid(), reply.metadata.sender_uid);
	ATF_CHECK_EQ(provider.seen.nonce, reply.metadata.sender_nonce);

	if (provider.seen.abi == CHANNEL_ABI_UNKNOWN)
		atf_tc_expect_fail("running kernel does not stamp the sender ABI");
	ATF_CHECK_EQ(CHANNEL_ABI_NATIVE, provider.seen.abi);
	ATF_CHECK_EQ(SERVICE_CLIENT_ABI_NATIVE, reply.metadata.sender_abi);

	service_session_close(session);
	channel_destroy(provider.channel);
}
ATF_TC_CLEANUP(sender_abi_round_trip, tc)
{
	(void)tc;
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, wire_layout);
	ATF_TP_ADD_TC(tp, sender_abi_round_trip);
	return (atf_no_error());
}
