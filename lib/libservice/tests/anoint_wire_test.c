/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * IPC anointments v1 (docs/ipc-anointments-design.md): wire and identity
 * contract between the kernel stamp, libchannel, libservice, switchboard
 * (proto 13) and system.auth (proto 2).
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
#include "authagent_proto.h"

/*
 * --- Layout contract (compile-time) ---------------------------------------
 */
_Static_assert(SWITCHBOARD_SVC_PROTO_VERSION == 15, "proto 15 expected");
_Static_assert(AUTHAGENTD_PROTO_VERSION == 3, "authagent proto 3 expected");
_Static_assert(sizeof(struct svc_new_client_msg) == 752,
    "svc_new_client_msg is 432 (v13) + container[64] (v14) + groups[4][64] (v15)");
_Static_assert(offsetof(struct svc_new_client_msg, client_nonce) == 416,
    "client_nonce appended after the v12 body");
_Static_assert(offsetof(struct svc_new_client_msg, client_abi) == 424,
    "client_abi follows client_nonce");
_Static_assert(sizeof(struct svc_mint_domain_req) ==
    24 + SVC_ANOINT_MAX * SVC_ANOINT_NAME_MAX,
    "mint request carries the anointment set");
_Static_assert(offsetof(struct svc_mint_domain_req, nanointments) == 16,
    "v12 mint request prefix unchanged");
_Static_assert(sizeof(struct service_identity) == 760,
    "service_identity is 440 + container[64] (container-model) + groups[4][64]");
_Static_assert(sizeof(struct service_message_metadata) == 56,
    "service_message_metadata size unchanged by sender_abi");
_Static_assert(sizeof(struct channel_sender) == 32,
    "channel_sender size unchanged by abi");
_Static_assert(sizeof(struct mac_capability_cred_trailer) == 24,
    "cred trailer size is part of the ioctl numbers");
_Static_assert(sizeof(struct authagent_elevate_req) == 336,
    "authagent_elevate_req layout");
_Static_assert(sizeof(struct authagent_mint_auth_req) == 272,
    "authagent_mint_auth_req layout");
_Static_assert(SERVICE_ANOINT_NAME_MAX == SVC_ANOINT_NAME_MAX &&
    SERVICE_ANOINT_MAX == SVC_ANOINT_MAX &&
    AUTHAGENT_NAME_MAX == SVC_ANOINT_NAME_MAX,
    "anointment name bounds agree across the three headers");
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
	ATF_CHECK_EQ(13, SWITCHBOARD_SVC_PROTO_VERSION);
	ATF_CHECK_EQ(432u, (unsigned)sizeof(nc));
	ATF_CHECK_EQ(64u, (unsigned)sizeof(nc.client_label));
	ATF_CHECK_EQ(440u, (unsigned)sizeof(id));
	ATF_CHECK_EQ(56u, (unsigned)sizeof(md));
	ATF_CHECK_EQ(0x2u, SVC_MINT_FLAG_ANOINT_ALL);
	ATF_CHECK_EQ(0x4u, SVC_MINT_FLAG_ADMIN_RIGHTS);
	ATF_CHECK((SVC_MINT_FLAG_RESEND & SVC_MINT_FLAG_ANOINT_ALL) == 0);
	ATF_CHECK((SVC_MINT_FLAG_RESEND & SVC_MINT_FLAG_ADMIN_RIGHTS) == 0);
	/*
	 * The identity fields overlay what used to be reserved[3]: a v12
	 * provider that zero-checked reserved[] reads nonce/abi there now.
	 */
	ATF_CHECK_EQ(offsetof(struct service_identity, rights) + 8,
	    offsetof(struct service_identity, client_nonce));
	ATF_CHECK_EQ(offsetof(struct service_identity, client_nonce) + 8,
	    offsetof(struct service_identity, client_abi));
	ATF_CHECK_EQ(offsetof(struct service_message_metadata, sender_prison) +
	    4, offsetof(struct service_message_metadata, sender_abi));
}

/*
 * --- Mint request anointment fill -----------------------------------------
 */
ATF_TC_WITHOUT_HEAD(mint_req_anoint_fill);
ATF_TC_BODY(mint_req_anoint_fill, tc)
{
	struct svc_mint_domain_req req;
	char names[SVC_ANOINT_MAX + 1][SERVICE_ANOINT_NAME_MAX];
	char toolong[SERVICE_ANOINT_NAME_MAX];
	unsigned i;

	(void)tc;
	for (i = 0; i < SVC_ANOINT_MAX + 1; i++)
		snprintf(names[i], sizeof(names[i]), "org.5bsd.test.%u", i);

	/* Plain set. */
	memset(&req, 0, sizeof(req));
	ATF_REQUIRE_EQ(0, service_mint_req_anoint(&req, names, 2, false,
	    false));
	ATF_CHECK_EQ(2u, req.nanointments);
	ATF_CHECK_EQ(0u, req.flags);
	ATF_CHECK_STREQ("org.5bsd.test.0", req.anointments[0]);
	ATF_CHECK_STREQ("org.5bsd.test.1", req.anointments[1]);
	ATF_CHECK_EQ(0, req.anointments[2][0]);

	/* Full set is exactly the wire bound. */
	memset(&req, 0, sizeof(req));
	ATF_REQUIRE_EQ(0, service_mint_req_anoint(&req, names, SVC_ANOINT_MAX,
	    false, false));
	ATF_CHECK_EQ((unsigned)SVC_ANOINT_MAX, req.nanointments);

	/* One over the bound is EINVAL, untouched. */
	memset(&req, 0, sizeof(req));
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_mint_req_anoint(&req, names,
	    SVC_ANOINT_MAX + 1, false, false) == -1);
	ATF_CHECK_EQ(0u, req.nanointments);

	/* n > 0 with NULL names is EINVAL. */
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_mint_req_anoint(&req, NULL, 1, false,
	    false) == -1);

	/* Empty name and unterminated (max-length) name are EINVAL. */
	memset(&req, 0, sizeof(req));
	names[1][0] = '\0';
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_mint_req_anoint(&req, names, 2, false,
	    false) == -1);
	memset(toolong, 'a', sizeof(toolong));
	memset(&req, 0, sizeof(req));
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_mint_req_anoint(&req,
	    (const char (*)[SERVICE_ANOINT_NAME_MAX])toolong, 1, false,
	    false) == -1);

	/* `all` sets the flag and drops the list; admin_rights is a flag. */
	memset(&req, 0, sizeof(req));
	req.flags = SVC_MINT_FLAG_RESEND;
	ATF_REQUIRE_EQ(0, service_mint_req_anoint(&req, names, 1, true, true));
	ATF_CHECK_EQ(SVC_MINT_FLAG_RESEND | SVC_MINT_FLAG_ANOINT_ALL |
	    SVC_MINT_FLAG_ADMIN_RIGHTS, req.flags);
	ATF_CHECK_EQ(0u, req.nanointments);
	ATF_CHECK_EQ(0, req.anointments[0][0]);

	/* The historical SYSTEM mint == all + admin_rights, USER == neither. */
	memset(&req, 0, sizeof(req));
	ATF_REQUIRE_EQ(0, service_mint_req_anoint(&req, NULL, 0, true, true));
	ATF_CHECK_EQ(SVC_MINT_FLAG_ANOINT_ALL | SVC_MINT_FLAG_ADMIN_RIGHTS,
	    req.flags);
	memset(&req, 0, sizeof(req));
	ATF_REQUIRE_EQ(0, service_mint_req_anoint(&req, NULL, 0, false,
	    false));
	ATF_CHECK_EQ(0u, req.flags);
	ATF_CHECK_EQ(0u, req.nanointments);
}

/*
 * --- Mint API argument validation (no plane needed) -----------------------
 */
ATF_TC_WITHOUT_HEAD(mint_anointed_arguments);
ATF_TC_BODY(mint_anointed_arguments, tc)
{
	char names[1][SERVICE_ANOINT_NAME_MAX] = { "org.5bsd.x" };
	int fd = 12345;

	(void)tc;
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_mint_session_domain_anointed(-1,
	    SERVICE_MINT_USER, 1000, names, 1, false, false, &fd) == -1);
	ATF_CHECK_EQ(12345, fd);	/* rejected before *out_fd is touched */
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_mint_session_domain_anointed(0,
	    SERVICE_MINT_USER, 1000, names, 1, false, false, NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_mint_session_domain_anointed(0,
	    (enum service_mint_kind)7, 1000, names, 1, false, false,
	    &fd) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_context_mint_domain_anointed(NULL,
	    SERVICE_MINT_USER, 1000, names, 1, false, false, &fd) == -1);
}

/*
 * --- service_elevate argument validation ----------------------------------
 */
ATF_TC_WITHOUT_HEAD(elevate_arguments);
ATF_TC_BODY(elevate_arguments, tc)
{
	char longname[AUTHAGENT_NAME_MAX + 1];
	char longpw[AUTHAGENT_PASSWORD_MAX + 1];
	int fd, nullfd, saved;

	(void)tc;
	memset(longname, 'n', sizeof(longname));
	longname[sizeof(longname) - 1] = '\0';
	memset(longpw, 'p', sizeof(longpw));
	longpw[sizeof(longpw) - 1] = '\0';

	fd = 777;
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_elevate(NULL, "pw", 100, &fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_elevate("org.5bsd.x", NULL, 100,
	    &fd) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_elevate("org.5bsd.x", "pw", 100,
	    NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_elevate("", "pw", 100, &fd) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_elevate(longname, "pw", 100,
	    &fd) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_elevate("org.5bsd.x", longpw, 100,
	    &fd) == -1);
	/* Exactly-max-length (no room for NUL) is over-long too. */
	longname[AUTHAGENT_NAME_MAX - 1] = 'n';
	longname[AUTHAGENT_NAME_MAX] = '\0';
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_elevate(longname, "pw", 100,
	    &fd) == -1);

	/*
	 * Well-formed arguments but no ambient lookup channel: make sure
	 * neither the env source nor the fixed-fd carry resolves, then expect
	 * service_ambient_lookup_fd()'s ENOENT to surface unchanged.
	 */
	ATF_REQUIRE_EQ(0, unsetenv(SERVICE_LOOKUP_ENV));
	nullfd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(nullfd >= 0);
	/*
	 * The fixed-fd slot may already be in use by the test runner (kyua hands
	 * ATF its results file on a low descriptor); park whatever is there and
	 * restore it afterwards, or the results file is clobbered and the case
	 * reports as broken.
	 */
	saved = fcntl(SERVICE_LOOKUP_FIXED_FD, F_DUPFD_CLOEXEC, 10);
	ATF_REQUIRE_EQ(SERVICE_LOOKUP_FIXED_FD,
	    dup2(nullfd, SERVICE_LOOKUP_FIXED_FD));
	fd = 777;
	errno = 0;
	ATF_CHECK_ERRNO(ENOENT, service_elevate("org.5bsd.x", "pw", 100,
	    &fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	/* An empty password is a valid argument; it still fails on reach. */
	errno = 0;
	ATF_CHECK_ERRNO(ENOENT, service_elevate("org.5bsd.x", "", 100,
	    &fd) == -1);
	if (saved >= 0) {
		ATF_REQUIRE_EQ(SERVICE_LOOKUP_FIXED_FD,
		    dup2(saved, SERVICE_LOOKUP_FIXED_FD));
		close(saved);
	} else
		close(SERVICE_LOOKUP_FIXED_FD);
	close(nullfd);
}

/*
 * --- Sender ABI over a real channel pair ----------------------------------
 */
static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR);
	if (control < 0) {
		if (errno == ENOENT || errno == ENXIO || errno == ENODEV ||
		    errno == EACCES || errno == EPERM)
			atf_tc_skip("no usable /dev/mac_capability: %s",
			    strerror(errno));
		atf_tc_fail("open mac_capability: %s", strerror(errno));
	}
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

static void
capability_channel_pair(int *first, int *second)
{
	struct mac_capability_recvmsg_args receive;
	struct mac_capability_sendmsg_args send;
	uint32_t op;

	*first = capability_connect("channel");
	if (*first < 0)
		atf_tc_skip("connect channel: %s", strerror(errno));
	op = CHANNEL_OP_CREATE;
	memset(&send, 0, sizeof(send));
	send.payload = &op;
	send.payload_len = sizeof(op);
	ATF_REQUIRE(ioctl(*first, MAC_CAPABILITY_SENDMSG, &send) == 0);
	memset(&receive, 0, sizeof(receive));
	receive.fds = second;
	receive.nfds = 1;
	ATF_REQUIRE(ioctl(*first, MAC_CAPABILITY_RECVMSG, &receive) == 0);
	ATF_REQUIRE_EQ(1, receive.nfds);
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

/*
 * --- service_elevate boundaries (no plane needed) --------------------------
 *
 * Each case pins one edge of the client-side contract.  "ok-shaped" means
 * the arguments pass validation and the call proceeds to reach the agent;
 * with no ambient channel that reach fails ENOENT, which is therefore the
 * marker "accepted by the argument layer".  Every case parks whatever sits
 * on the fixed-fd slot (kyua's results file, usually) and restores it.
 */
struct no_channel {
	int	saved;
	int	nullfd;
};

static void
no_channel_begin(struct no_channel *nc)
{

	ATF_REQUIRE_EQ(0, unsetenv(SERVICE_LOOKUP_ENV));
	nc->nullfd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(nc->nullfd >= 0);
	nc->saved = fcntl(SERVICE_LOOKUP_FIXED_FD, F_DUPFD_CLOEXEC, 10);
	ATF_REQUIRE_EQ(SERVICE_LOOKUP_FIXED_FD,
	    dup2(nc->nullfd, SERVICE_LOOKUP_FIXED_FD));
}

static void
no_channel_end(struct no_channel *nc)
{

	if (nc->saved >= 0) {
		ATF_REQUIRE_EQ(SERVICE_LOOKUP_FIXED_FD,
		    dup2(nc->saved, SERVICE_LOOKUP_FIXED_FD));
		close(nc->saved);
	} else
		close(SERVICE_LOOKUP_FIXED_FD);
	close(nc->nullfd);
}

/* "a." + (len - 2) 'a's, NUL-terminated: a well-shaped name of `len`. */
static void
shaped_name(char *buf, size_t bufsz, size_t len)
{

	ATF_REQUIRE(len + 1 <= bufsz);
	memset(buf, 'a', len);
	buf[1] = '.';
	buf[len] = '\0';
}

ATF_TC_WITHOUT_HEAD(elevate_name_63_ok_64_einval);
ATF_TC_BODY(elevate_name_63_ok_64_einval, tc)
{
	struct no_channel nc;
	char name[AUTHAGENT_NAME_MAX + 8];
	int fd;

	(void)tc;
	no_channel_begin(&nc);
	/* 63: ok-shaped, proceeds to reach -> ENOENT. */
	shaped_name(name, sizeof(name), AUTHAGENT_NAME_MAX - 1);
	fd = 777;
	errno = 0;
	ATF_CHECK_ERRNO(ENOENT, service_elevate(name, "pw", 100, &fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	/* 64: EINVAL, never reaches. */
	shaped_name(name, sizeof(name), AUTHAGENT_NAME_MAX);
	fd = 777;
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_elevate(name, "pw", 100, &fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	/* 65 and a very long one: EINVAL, strnlen-bounded (no over-read). */
	shaped_name(name, sizeof(name), AUTHAGENT_NAME_MAX + 1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_elevate(name, "pw", 100, &fd) == -1);
	/* 64 non-NUL bytes with no terminator in reach: bounded, EINVAL. */
	memset(name, 'a', sizeof(name));
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_elevate(name, "pw", 100, &fd) == -1);
	/* 1: the shortest non-empty name is ok-shaped for the library. */
	errno = 0;
	ATF_CHECK_ERRNO(ENOENT, service_elevate("a", "pw", 100, &fd) == -1);
	no_channel_end(&nc);
}

/*
 * The library checks only the LENGTH of the name; syntax ("*", "nodot",
 * dots) is the agent's decision.  Pinned so a client-side tightening shows
 * up as a deliberate change rather than a surprise.
 */
ATF_TC_WITHOUT_HEAD(elevate_name_syntax_left_to_agent);
ATF_TC_BODY(elevate_name_syntax_left_to_agent, tc)
{
	struct no_channel nc;
	int fd;

	(void)tc;
	no_channel_begin(&nc);
	errno = 0;
	ATF_CHECK_ERRNO(ENOENT, service_elevate("*", "pw", 100, &fd) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(ENOENT, service_elevate("nodot", "pw", 100, &fd) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(ENOENT, service_elevate(".a.b.", "pw", 100, &fd) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(ENOENT, service_elevate("a b", "pw", 100, &fd) == -1);
	no_channel_end(&nc);
}

ATF_TC_WITHOUT_HEAD(elevate_password_255_ok_256_einval);
ATF_TC_BODY(elevate_password_255_ok_256_einval, tc)
{
	struct no_channel nc;
	char pw[AUTHAGENT_PASSWORD_MAX + 8];
	int fd;

	(void)tc;
	no_channel_begin(&nc);
	/* 255: ok-shaped. */
	memset(pw, 'p', sizeof(pw));
	pw[AUTHAGENT_PASSWORD_MAX - 1] = '\0';
	fd = 777;
	errno = 0;
	ATF_CHECK_ERRNO(ENOENT, service_elevate("org.5bsd.x", pw, 100,
	    &fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	/* 256: EINVAL. */
	memset(pw, 'p', sizeof(pw));
	pw[AUTHAGENT_PASSWORD_MAX] = '\0';
	fd = 777;
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_elevate("org.5bsd.x", pw, 100,
	    &fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	/* 257 and unterminated: EINVAL, strnlen-bounded. */
	memset(pw, 'p', sizeof(pw));
	pw[AUTHAGENT_PASSWORD_MAX + 1] = '\0';
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_elevate("org.5bsd.x", pw, 100,
	    &fd) == -1);
	memset(pw, 'p', sizeof(pw));
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_elevate("org.5bsd.x", pw, 100,
	    &fd) == -1);
	/* Empty is ok-shaped (the agent decides), as is a space. */
	errno = 0;
	ATF_CHECK_ERRNO(ENOENT, service_elevate("org.5bsd.x", "", 100,
	    &fd) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(ENOENT, service_elevate("org.5bsd.x", " ", 100,
	    &fd) == -1);
	no_channel_end(&nc);
}

/*
 * timeout_ms is not validated by the argument layer: 0 and UINT_MAX are
 * both accepted and handed to service_session_call() as-is.  Documented
 * behaviour (0 is then whatever the call layer makes of it); a change here
 * is a contract change.
 */
ATF_TC_WITHOUT_HEAD(elevate_timeout_zero_accepted);
ATF_TC_BODY(elevate_timeout_zero_accepted, tc)
{
	struct no_channel nc;
	int fd;

	(void)tc;
	no_channel_begin(&nc);
	fd = 777;
	errno = 0;
	ATF_CHECK_ERRNO(ENOENT, service_elevate("org.5bsd.x", "pw", 0,
	    &fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	errno = 0;
	ATF_CHECK_ERRNO(ENOENT, service_elevate("org.5bsd.x", "pw", UINT_MAX,
	    &fd) == -1);
	no_channel_end(&nc);
}

ATF_TC_WITHOUT_HEAD(elevate_null_out_fd_einval);
ATF_TC_BODY(elevate_null_out_fd_einval, tc)
{
	struct no_channel nc;

	(void)tc;
	no_channel_begin(&nc);
	/* With every other argument valid, NULL out_fd alone is EINVAL... */
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_elevate("org.5bsd.x", "pw", 100,
	    NULL) == -1);
	/* ...and it is checked before reach (ENOENT would mean it was not). */
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_elevate("org.5bsd.x", "", 0,
	    NULL) == -1);
	/* All three NULL is EINVAL, not a crash. */
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_elevate(NULL, NULL, 100, NULL) == -1);
	no_channel_end(&nc);
}

/* After ANY EINVAL, *out_fd is -1 (set before validation), never stale. */
ATF_TC_WITHOUT_HEAD(elevate_out_fd_is_minus_one_after_einval);
ATF_TC_BODY(elevate_out_fd_is_minus_one_after_einval, tc)
{
	char longname[AUTHAGENT_NAME_MAX + 1];
	char longpw[AUTHAGENT_PASSWORD_MAX + 1];
	int fd;

	(void)tc;
	memset(longname, 'n', sizeof(longname));
	longname[sizeof(longname) - 1] = '\0';
	memset(longpw, 'p', sizeof(longpw));
	longpw[sizeof(longpw) - 1] = '\0';

	fd = 777;
	ATF_CHECK_ERRNO(EINVAL, service_elevate(NULL, "pw", 100, &fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	fd = 777;
	ATF_CHECK_ERRNO(EINVAL, service_elevate("org.5bsd.x", NULL, 100,
	    &fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	fd = 777;
	ATF_CHECK_ERRNO(EINVAL, service_elevate("", "pw", 100, &fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	fd = 777;
	ATF_CHECK_ERRNO(EINVAL, service_elevate(longname, "pw", 100,
	    &fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	fd = 777;
	ATF_CHECK_ERRNO(EINVAL, service_elevate("org.5bsd.x", longpw, 100,
	    &fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	/* A positive-looking stale value and 0 are both overwritten. */
	fd = 0;
	ATF_CHECK_ERRNO(EINVAL, service_elevate("", "pw", 100, &fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	fd = INT_MAX;
	ATF_CHECK_ERRNO(EINVAL, service_elevate("", "pw", 100, &fd) == -1);
	ATF_CHECK_EQ(-1, fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, wire_layout);
	ATF_TP_ADD_TC(tp, mint_req_anoint_fill);
	ATF_TP_ADD_TC(tp, mint_anointed_arguments);
	ATF_TP_ADD_TC(tp, elevate_arguments);
	ATF_TP_ADD_TC(tp, sender_abi_round_trip);
	/* service_elevate boundaries. */
	ATF_TP_ADD_TC(tp, elevate_name_63_ok_64_einval);
	ATF_TP_ADD_TC(tp, elevate_name_syntax_left_to_agent);
	ATF_TP_ADD_TC(tp, elevate_password_255_ok_256_einval);
	ATF_TP_ADD_TC(tp, elevate_timeout_zero_accepted);
	ATF_TP_ADD_TC(tp, elevate_null_out_fd_einval);
	ATF_TP_ADD_TC(tp, elevate_out_fd_is_minus_one_after_einval);
	return (atf_no_error());
}
