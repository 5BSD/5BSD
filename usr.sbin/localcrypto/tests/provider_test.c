/*- SPDX-License-Identifier: BSD-2-Clause */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/cryptodesc.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <opencrypto/cryptodev.h>

#include <libservice.h>
#include <cryptocmp_protocol.h>

#include "localcrypto_test.h"

struct raw_fixture {
	struct service_session	*session;
	pid_t			 child;
};

static void
require_plane(void)
{
	int fd;

	fd = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		atf_tc_skip("plane device /dev/mac_capability unavailable: %s",
		    strerror(errno));
	close(fd);
	fd = open("/dev/crypto", O_RDWR);
	if (fd < 0)
		atf_tc_skip("cryptodev /dev/crypto unavailable: %s",
		    strerror(errno));
	close(fd);
}

static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE_MSG(control >= 0, "open mac_capability: %s",
	    strerror(errno));
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
channel_pair(int *client, int *provider)
{
	struct mac_capability_recvmsg_args receive;
	struct mac_capability_sendmsg_args send;
	uint32_t operation;

	*client = capability_connect("channel");
	ATF_REQUIRE(*client >= 0);
	operation = CHANNEL_OP_CREATE;
	memset(&send, 0, sizeof(send));
	send.payload = &operation;
	send.payload_len = sizeof(operation);
	ATF_REQUIRE_EQ(0, ioctl(*client, MAC_CAPABILITY_SENDMSG, &send));
	memset(&receive, 0, sizeof(receive));
	receive.fds = provider;
	receive.nfds = 1;
	ATF_REQUIRE_EQ(0, ioctl(*client, MAC_CAPABILITY_RECVMSG, &receive));
	ATF_REQUIRE_EQ(1, receive.nfds);
}

/*
 * Stand up an owner-scoped provider worker bound to a caller-supplied owner
 * label.  Each fixture is a distinct worker sharing the one kernel named-key
 * store, so keys minted under one label are invisible to another.
 */
static void
raw_fixture_create(struct raw_fixture *fixture, const char *owner)
{
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(localcrypto_test_serve(provider, owner));
	}
	close(provider);
	ATF_REQUIRE_EQ(0, service_session_create(client, &fixture->session));
}

static void
raw_fixture_destroy(struct raw_fixture *fixture, int expected_status)
{
	int status;

	service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(expected_status, WEXITSTATUS(status));
}

static void
raw_fixture_destroy_any(struct raw_fixture *fixture)
{
	int status;

	service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
}

/*
 * Send a well-formed named-key request and return the daemon's errno-style
 * status (0 on success, positive errno on rejection).  On a successful lease the
 * delivered descriptor is returned through out_fd.
 */
static int
named_op(struct raw_fixture *fixture, uint16_t opcode, const void *payload,
    size_t paylen, uint64_t *generation, int *out_fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct cryptocmp_msg msg;
	struct cryptocmp_named_reply reply;
	uint8_t request[sizeof(struct cryptocmp_msg) +
	    sizeof(struct cryptocmp_named_create)];
	int fd;

	ATF_REQUIRE(paylen <= sizeof(request) - sizeof(msg));
	memset(&msg, 0, sizeof(msg));
	msg.magic = CRYPTOCMP_MAGIC;
	msg.version = CRYPTOCMP_VERSION;
	msg.opcode = opcode;
	memset(request, 0, sizeof(request));
	memcpy(request, &msg, sizeof(msg));
	memcpy(request + sizeof(msg), payload, paylen);
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = request;
	outgoing.length = sizeof(msg) + paylen;
	fd = -1;
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	if (out_fd != NULL) {
		incoming.fds = &fd;
		incoming.fd_capacity = 1;
	}
	options.timeout_ms = 2000;
	ATF_REQUIRE_EQ(0, service_session_call(fixture->session, &outgoing,
	    &incoming, &options));
	if (out_fd != NULL)
		*out_fd = fd;
	if (generation != NULL)
		*generation = reply.generation;
	return (-reply.msg.status);
}

/*
 * Read-only introspection: send a NAMED_STAT request for name and return the
 * daemon's errno-style status.  On success the key metadata is returned through
 * info.  No descriptor is ever delivered for a STAT (the reply is data-only), so
 * this helper never receives an fd.
 */
static int
stat_op(struct raw_fixture *fixture, const char *name,
    struct cryptocmp_named_info *info)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct cryptocmp_msg msg;
	struct cryptocmp_named_stat req;
	struct cryptocmp_named_stat_reply reply;
	uint8_t request[sizeof(struct cryptocmp_msg) +
	    sizeof(struct cryptocmp_named_stat)];

	memset(&msg, 0, sizeof(msg));
	msg.magic = CRYPTOCMP_MAGIC;
	msg.version = CRYPTOCMP_VERSION;
	msg.opcode = CRYPTOCMP_OP_NAMED_STAT;
	memset(&req, 0, sizeof(req));
	strlcpy(req.name, name, sizeof(req.name));
	memcpy(request, &msg, sizeof(msg));
	memcpy(request + sizeof(msg), &req, sizeof(req));
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = request;
	outgoing.length = sizeof(request);
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 2000;
	ATF_REQUIRE_EQ(0, service_session_call(fixture->session, &outgoing,
	    &incoming, &options));
	if (reply.msg.status == 0 && info != NULL)
		*info = reply.info;
	return (-reply.msg.status);
}

/* Send an arbitrary (possibly malformed) request; return service_session_call's
 * result and, when a reply arrives, its errno-style status. */
static int
send_raw(struct service_session *session, const void *data, size_t length,
    int attach_fd, int *status)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct cryptocmp_named_reply reply;
	int rc, fd;

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = data;
	outgoing.length = length;
	if (attach_fd >= 0) {
		fd = attach_fd;
		outgoing.fds = &fd;
		outgoing.nfds = 1;
	}
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 2000;
	rc = service_session_call(session, &outgoing, &incoming, &options);
	if (rc == 0 && status != NULL)
		*status = -reply.msg.status;
	return (rc);
}

/* A documented, policy-valid symmetric profile for a named key. */
static struct cryptocmp_generate
sample_generate(void)
{
	struct cryptocmp_generate generate;

	memset(&generate, 0, sizeof(generate));
	generate.cipher = CRYPTO_AES_CBC;
	generate.keylen = 32;
	generate.rights = CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_DECRYPT;
	generate.crid = CRYPTO_FLAG_SOFTWARE;
	generate.ivlen = 16;
	generate.maclen = 0;
	return (generate);
}

/*
 * Mint an unkeyed-digest session descriptor for the given plain-hash algorithm.
 * Returns the daemon's errno-style status; on success the delivered
 * DTYPE_CRYPTO descriptor is returned through out_fd.
 */
static int
digest_op(struct raw_fixture *fixture, uint32_t alg, uint32_t ttl, int *out_fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct cryptocmp_msg msg;
	struct cryptocmp_digest digest;
	struct cryptocmp_msg reply;
	uint8_t request[sizeof(struct cryptocmp_msg) +
	    sizeof(struct cryptocmp_digest)];
	int fd;

	memset(&msg, 0, sizeof(msg));
	msg.magic = CRYPTOCMP_MAGIC;
	msg.version = CRYPTOCMP_VERSION;
	msg.opcode = CRYPTOCMP_OP_DIGEST;
	memset(&digest, 0, sizeof(digest));
	digest.alg = alg;
	digest.ttl = ttl;
	memcpy(request, &msg, sizeof(msg));
	memcpy(request + sizeof(msg), &digest, sizeof(digest));
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = request;
	outgoing.length = sizeof(request);
	fd = -1;
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	incoming.fds = &fd;
	incoming.fd_capacity = 1;
	options.timeout_ms = 2000;
	ATF_REQUIRE_EQ(0, service_session_call(fixture->session, &outgoing,
	    &incoming, &options));
	if (out_fd != NULL)
		*out_fd = fd;
	return (-reply.status);
}

/*
 * Request nbytes of CSPRNG output.  Returns the daemon's errno-style status; on
 * success the reply's declared byte count is returned through got and the bytes
 * are copied into buf (capacity buflen).
 */
static int
random_op(struct raw_fixture *fixture, uint32_t nbytes, uint8_t *buf,
    size_t buflen, uint32_t *got)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct cryptocmp_msg msg;
	struct cryptocmp_random request;
	struct cryptocmp_random_reply reply;
	uint8_t reqbuf[sizeof(struct cryptocmp_msg) +
	    sizeof(struct cryptocmp_random)];

	memset(&msg, 0, sizeof(msg));
	msg.magic = CRYPTOCMP_MAGIC;
	msg.version = CRYPTOCMP_VERSION;
	msg.opcode = CRYPTOCMP_OP_RANDOM;
	memset(&request, 0, sizeof(request));
	request.nbytes = nbytes;
	memcpy(reqbuf, &msg, sizeof(msg));
	memcpy(reqbuf + sizeof(msg), &request, sizeof(request));
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = reqbuf;
	outgoing.length = sizeof(reqbuf);
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 2000;
	ATF_REQUIRE_EQ(0, service_session_call(fixture->session, &outgoing,
	    &incoming, &options));
	if (reply.msg.status == 0) {
		if (got != NULL)
			*got = reply.nbytes;
		if (buf != NULL && reply.nbytes <= buflen)
			memcpy(buf, reply.data, reply.nbytes);
	}
	return (-reply.msg.status);
}

/*
 * An unkeyed digest is delivered as a session descriptor the client streams data
 * through: the daemon mints a DTYPE_CRYPTO fd for the requested plain hash, and
 * a CIOCCRYPT authentication pass over the classic NIST input "abc" reproduces
 * the published SHA-256 vector — proving both the descriptor and its right.
 */
ATF_TC(digest_descriptor);
ATF_TC_HEAD(digest_descriptor, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "An unkeyed-digest descriptor computes a known SHA-256 vector");
}
ATF_TC_BODY(digest_descriptor, tc)
{
	static const uint8_t sha256_abc[32] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
	};
	struct raw_fixture fixture;
	struct crypt_op cop;
	uint8_t digest[sizeof(sha256_abc)];
	int fd;

	require_plane();
	raw_fixture_create(&fixture, "org.test.digest");

	fd = -1;
	ATF_CHECK_EQ(0, digest_op(&fixture, CRYPTO_SHA2_256, 60, &fd));
	ATF_REQUIRE(fd >= 0);
	memset(&cop, 0, sizeof(cop));
	cop.op = COP_ENCRYPT;
	cop.len = 3;
	cop.src = "abc";
	cop.mac = digest;
	memset(digest, 0, sizeof(digest));
	ATF_REQUIRE_MSG(ioctl(fd, CIOCCRYPT, &cop) == 0,
	    "CIOCCRYPT on digest descriptor: %s", strerror(errno));
	ATF_CHECK_EQ(0, memcmp(digest, sha256_abc, sizeof(sha256_abc)));
	close(fd);

	raw_fixture_destroy(&fixture, 0);
}

/*
 * CSPRNG: a request returns exactly the byte count asked for, and two draws of
 * the same size differ (a smoke check that real entropy is flowing, not a fixed
 * buffer).
 */
ATF_TC(random_bytes);
ATF_TC_HEAD(random_bytes, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "CSPRNG returns the requested count and successive draws differ");
}
ATF_TC_BODY(random_bytes, tc)
{
	struct raw_fixture fixture;
	uint8_t first[64], second[64];
	uint32_t got;

	require_plane();
	raw_fixture_create(&fixture, "org.test.random");

	got = 0;
	memset(first, 0, sizeof(first));
	ATF_CHECK_EQ(0, random_op(&fixture, sizeof(first), first, sizeof(first),
	    &got));
	ATF_CHECK_EQ(sizeof(first), got);

	got = 0;
	memset(second, 0, sizeof(second));
	ATF_CHECK_EQ(0, random_op(&fixture, sizeof(second), second,
	    sizeof(second), &got));
	ATF_CHECK_EQ(sizeof(second), got);
	ATF_CHECK(memcmp(first, second, sizeof(first)) != 0);

	/* A single-byte and a max-size draw both honour the requested count. */
	got = 0;
	ATF_CHECK_EQ(0, random_op(&fixture, 1, first, sizeof(first), &got));
	ATF_CHECK_EQ(1, got);

	raw_fixture_destroy(&fixture, 0);
}

/*
 * The digest and random handlers fail closed on the same boundaries the other
 * ops enforce: an unsupported hash algorithm (EPROTONOSUPPORT), an over-cap byte
 * count (EINVAL), an attached descriptor (EPROTO), and a length that does not
 * match the opcode (EPROTO).
 */
ATF_TC(digest_random_malformed);
ATF_TC_HEAD(digest_random_malformed, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Digest/random requests are rejected fail-closed at their boundaries");
}
ATF_TC_BODY(digest_random_malformed, tc)
{
	struct raw_fixture fixture;
	struct cryptocmp_msg msg;
	struct cryptocmp_digest digest;
	struct cryptocmp_random request;
	uint8_t reqbuf[sizeof(struct cryptocmp_msg) +
	    sizeof(struct cryptocmp_digest)];
	int fd, status, rc, pipefd[2];

	require_plane();
	raw_fixture_create(&fixture, "org.test.dr.malformed");

	/* A keyed-HMAC selector is not an unkeyed digest. */
	fd = -1;
	ATF_CHECK_EQ(EPROTONOSUPPORT,
	    digest_op(&fixture, CRYPTO_SHA2_256_HMAC, 60, &fd));
	ATF_CHECK_EQ(-1, fd);

	/* An over-cap random request is rejected. */
	ATF_CHECK_EQ(EINVAL, random_op(&fixture, CRYPTOCMP_MAX_RANDOM_BYTES + 1,
	    NULL, 0, NULL));
	/* A zero-length random request is rejected. */
	ATF_CHECK_EQ(EINVAL, random_op(&fixture, 0, NULL, 0, NULL));

	/* A digest request with a truncated body (header only). */
	memset(&msg, 0, sizeof(msg));
	msg.magic = CRYPTOCMP_MAGIC;
	msg.version = CRYPTOCMP_VERSION;
	msg.opcode = CRYPTOCMP_OP_DIGEST;
	memcpy(reqbuf, &msg, sizeof(msg));
	status = 0;
	ATF_CHECK_EQ(0, send_raw(fixture.session, reqbuf, sizeof(msg), -1,
	    &status));
	ATF_CHECK_EQ(EPROTO, status);

	/* A random request with a trailing byte (wrong length). */
	msg.opcode = CRYPTOCMP_OP_RANDOM;
	memset(&request, 0, sizeof(request));
	request.nbytes = 16;
	memcpy(reqbuf, &msg, sizeof(msg));
	memcpy(reqbuf + sizeof(msg), &request, sizeof(request));
	status = 0;
	ATF_CHECK_EQ(0, send_raw(fixture.session, reqbuf,
	    sizeof(msg) + sizeof(request) + 1, -1, &status));
	ATF_CHECK_EQ(EPROTO, status);

	raw_fixture_destroy(&fixture, 0);

	/* An attached descriptor on a digest request must not be interpreted. */
	raw_fixture_create(&fixture, "org.test.dr.fd");
	ATF_REQUIRE_EQ(0, pipe(pipefd));
	memset(&msg, 0, sizeof(msg));
	msg.magic = CRYPTOCMP_MAGIC;
	msg.version = CRYPTOCMP_VERSION;
	msg.opcode = CRYPTOCMP_OP_DIGEST;
	memset(&digest, 0, sizeof(digest));
	digest.alg = CRYPTO_SHA2_256;
	memcpy(reqbuf, &msg, sizeof(msg));
	memcpy(reqbuf + sizeof(msg), &digest, sizeof(digest));
	status = 0;
	rc = send_raw(fixture.session, reqbuf, sizeof(reqbuf), pipefd[0],
	    &status);
	if (rc == 0)
		ATF_CHECK_EQ(EPROTO, status);
	else
		ATF_CHECK_EQ(-1, rc);
	close(pipefd[0]);
	close(pipefd[1]);
	raw_fixture_destroy_any(&fixture);
}

/*
 * Crown-jewel isolation regression: named keys are scoped to the owner label
 * bound to the unforgeable channel identity.  A key minted by one owner label is
 * invisible to a session running under a different label — lease/rotate/delete
 * fail closed (ENOENT, the kernel key store's owner-scoped miss) — while the
 * owning label reaches its own key.
 */
ATF_TC(named_key_is_owner_scoped);
ATF_TC_HEAD(named_key_is_owner_scoped, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A named key is reachable only under the owner label that minted it");
}
ATF_TC_BODY(named_key_is_owner_scoped, tc)
{
	struct cryptocmp_named_create create;
	struct cryptocmp_named_lease lease;
	struct cryptocmp_named_control control;
	struct raw_fixture owner_a, owner_b;
	uint64_t generation;
	int fd;

	require_plane();
	raw_fixture_create(&owner_a, "org.test.owner.a");
	raw_fixture_create(&owner_b, "org.test.owner.b");

	/* owner A mints a named key. */
	memset(&create, 0, sizeof(create));
	strlcpy(create.name, "owner-scope-regress.1", sizeof(create.name));
	create.generate = sample_generate();
	ATF_CHECK_EQ(0, named_op(&owner_a, CRYPTOCMP_OP_NAMED_CREATE, &create,
	    sizeof(create), &generation, NULL));

	/* owner B cannot lease, rotate, or delete A's key: owner-scoped miss. */
	memset(&lease, 0, sizeof(lease));
	strlcpy(lease.name, "owner-scope-regress.1", sizeof(lease.name));
	lease.rights = CRYPTODESC_RIGHT_ENCRYPT;
	lease.ttl = 60;
	fd = -1;
	ATF_CHECK_EQ(ENOENT, named_op(&owner_b, CRYPTOCMP_OP_NAMED_LEASE, &lease,
	    sizeof(lease), NULL, &fd));
	ATF_CHECK_EQ(-1, fd);

	memset(&control, 0, sizeof(control));
	strlcpy(control.name, "owner-scope-regress.1", sizeof(control.name));
	ATF_CHECK_EQ(ENOENT, named_op(&owner_b, CRYPTOCMP_OP_NAMED_ROTATE,
	    &control, sizeof(control), NULL, NULL));
	ATF_CHECK_EQ(ENOENT, named_op(&owner_b, CRYPTOCMP_OP_NAMED_DELETE,
	    &control, sizeof(control), NULL, NULL));

	/* owner A reaches its own key: lease returns a descriptor, then rotate
	 * and delete succeed. */
	fd = -1;
	ATF_CHECK_EQ(0, named_op(&owner_a, CRYPTOCMP_OP_NAMED_LEASE, &lease,
	    sizeof(lease), &generation, &fd));
	ATF_CHECK(fd >= 0);
	if (fd >= 0)
		close(fd);
	ATF_CHECK_EQ(0, named_op(&owner_a, CRYPTOCMP_OP_NAMED_ROTATE, &control,
	    sizeof(control), &generation, NULL));
	ATF_CHECK_EQ(0, named_op(&owner_a, CRYPTOCMP_OP_NAMED_DELETE, &control,
	    sizeof(control), &generation, NULL));

	raw_fixture_destroy(&owner_b, 0);
	raw_fixture_destroy(&owner_a, 0);
}

/*
 * Read-only introspection is owner-scoped and non-mutating.  A key is visible to
 * a STAT only under the owner label that minted it (a foreign label and an
 * absent name both fail closed with ENOENT), the returned metadata matches the
 * key's create profile, and a STAT tracks a rotate's generation bump without
 * itself minting a descriptor or changing the key — a final delete makes the
 * key vanish from STAT.
 */
ATF_TC(named_key_stat);
ATF_TC_HEAD(named_key_stat, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "NAMED_STAT is owner-scoped, non-minting, and tracks the generation");
}
ATF_TC_BODY(named_key_stat, tc)
{
	struct cryptocmp_named_create create;
	struct cryptocmp_named_control control;
	struct cryptocmp_named_info info;
	struct raw_fixture owner_a, owner_b;
	uint64_t generation, rotated;

	require_plane();
	raw_fixture_create(&owner_a, "org.test.stat.a");
	raw_fixture_create(&owner_b, "org.test.stat.b");

	/* owner A mints a named key with a known profile. */
	memset(&create, 0, sizeof(create));
	strlcpy(create.name, "stat.key.1", sizeof(create.name));
	create.generate = sample_generate();
	ATF_CHECK_EQ(0, named_op(&owner_a, CRYPTOCMP_OP_NAMED_CREATE, &create,
	    sizeof(create), &generation, NULL));

	/* A STAT of a nonexistent name fails closed with ENOENT. */
	ATF_CHECK_EQ(ENOENT, stat_op(&owner_a, "stat.key.absent", NULL));

	/* owner A observes its key: created generation and create-time metadata. */
	memset(&info, 0, sizeof(info));
	ATF_CHECK_EQ(0, stat_op(&owner_a, "stat.key.1", &info));
	ATF_CHECK_EQ(generation, info.generation);
	ATF_CHECK_EQ((uint32_t)(CRYPTODESC_RIGHT_ENCRYPT |
	    CRYPTODESC_RIGHT_DECRYPT), info.rights);
	ATF_CHECK_EQ((uint32_t)CRYPTO_AES_CBC, info.cipher);
	ATF_CHECK_EQ(0u, info.mac);
	ATF_CHECK_EQ(32u, info.keylen);
	ATF_CHECK_EQ(0u, info.mackeylen);

	/* owner B cannot see A's key: owner-scoped miss, not a disclosure. */
	ATF_CHECK_EQ(ENOENT, stat_op(&owner_b, "stat.key.1", NULL));

	/* A rotate bumps the generation; STAT reflects it without minting. */
	memset(&control, 0, sizeof(control));
	strlcpy(control.name, "stat.key.1", sizeof(control.name));
	ATF_CHECK_EQ(0, named_op(&owner_a, CRYPTOCMP_OP_NAMED_ROTATE, &control,
	    sizeof(control), &rotated, NULL));
	ATF_CHECK(rotated > generation);
	memset(&info, 0, sizeof(info));
	ATF_CHECK_EQ(0, stat_op(&owner_a, "stat.key.1", &info));
	ATF_CHECK_EQ(rotated, info.generation);

	/* Two consecutive STATs return the same generation: STAT does not mutate. */
	memset(&info, 0, sizeof(info));
	ATF_CHECK_EQ(0, stat_op(&owner_a, "stat.key.1", &info));
	ATF_CHECK_EQ(rotated, info.generation);

	/* After delete the key is gone from STAT. */
	ATF_CHECK_EQ(0, named_op(&owner_a, CRYPTOCMP_OP_NAMED_DELETE, &control,
	    sizeof(control), NULL, NULL));
	ATF_CHECK_EQ(ENOENT, stat_op(&owner_a, "stat.key.1", NULL));

	raw_fixture_destroy(&owner_b, 0);
	raw_fixture_destroy(&owner_a, 0);
}

/*
 * The provider fails closed on malformed requests: a bad magic/version, an
 * out-of-range opcode, a length that does not match the opcode, and any attached
 * descriptor (the handler requires a zero fd count) are all rejected with EPROTO
 * rather than reaching the crypto control device.
 */
ATF_TC(malformed_request_is_rejected);
ATF_TC_HEAD(malformed_request_is_rejected, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Malformed crypto requests are rejected fail-closed with EPROTO");
}
ATF_TC_BODY(malformed_request_is_rejected, tc)
{
	struct raw_fixture fixture, attach;
	struct cryptocmp_msg msg;
	struct cryptocmp_generate generate;
	uint8_t request[sizeof(struct cryptocmp_msg) +
	    sizeof(struct cryptocmp_generate)];
	int status, rc, pipefd[2];

	require_plane();
	raw_fixture_create(&fixture, "org.test.malformed");
	generate = sample_generate();

	/* Wrong protocol version. */
	memset(&msg, 0, sizeof(msg));
	msg.magic = CRYPTOCMP_MAGIC;
	msg.version = CRYPTOCMP_VERSION + 1;
	msg.opcode = CRYPTOCMP_OP_GENERATE;
	memset(request, 0, sizeof(request));
	memcpy(request, &msg, sizeof(msg));
	memcpy(request + sizeof(msg), &generate, sizeof(generate));
	status = 0;
	ATF_CHECK_EQ(0, send_raw(fixture.session, request, sizeof(request), -1,
	    &status));
	ATF_CHECK_EQ(EPROTO, status);

	/* Out-of-range opcode. */
	msg.version = CRYPTOCMP_VERSION;
	msg.opcode = 99;
	memcpy(request, &msg, sizeof(msg));
	status = 0;
	ATF_CHECK_EQ(0, send_raw(fixture.session, request, sizeof(request), -1,
	    &status));
	ATF_CHECK_EQ(EPROTO, status);

	/* Valid opcode, but a truncated body (header only). */
	msg.opcode = CRYPTOCMP_OP_GENERATE;
	memcpy(request, &msg, sizeof(msg));
	status = 0;
	ATF_CHECK_EQ(0, send_raw(fixture.session, request, sizeof(msg), -1,
	    &status));
	ATF_CHECK_EQ(EPROTO, status);

	raw_fixture_destroy(&fixture, 0);

	/*
	 * An attached descriptor on an otherwise-valid request must not be
	 * interpreted.  The handler requires fd_count == 0 and replies EPROTO;
	 * on a fresh session so a terminal channel policy cannot mask the check.
	 */
	raw_fixture_create(&attach, "org.test.malformed.fd");
	ATF_REQUIRE_EQ(0, pipe(pipefd));
	memset(&msg, 0, sizeof(msg));
	msg.magic = CRYPTOCMP_MAGIC;
	msg.version = CRYPTOCMP_VERSION;
	msg.opcode = CRYPTOCMP_OP_GENERATE;
	memcpy(request, &msg, sizeof(msg));
	memcpy(request + sizeof(msg), &generate, sizeof(generate));
	status = 0;
	rc = send_raw(attach.session, request, sizeof(request), pipefd[0],
	    &status);
	if (rc == 0)
		ATF_CHECK_EQ(EPROTO, status);
	else
		ATF_CHECK_EQ(-1, rc);
	close(pipefd[0]);
	close(pipefd[1]);
	raw_fixture_destroy_any(&attach);
}

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{

	ATF_CHECK_ERRNO(EINVAL, localcrypto_test_serve(-1, "org.test") == -1);
	ATF_CHECK_ERRNO(EINVAL, localcrypto_test_serve(0, NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, localcrypto_test_serve(0, "") == -1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, named_key_is_owner_scoped);
	ATF_TP_ADD_TC(tp, named_key_stat);
	ATF_TP_ADD_TC(tp, malformed_request_is_rejected);
	ATF_TP_ADD_TC(tp, digest_descriptor);
	ATF_TP_ADD_TC(tp, random_bytes);
	ATF_TP_ADD_TC(tp, digest_random_malformed);
	ATF_TP_ADD_TC(tp, arguments);
	return (atf_no_error());
}
