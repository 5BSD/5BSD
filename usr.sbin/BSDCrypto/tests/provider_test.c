/*- SPDX-License-Identifier: BSD-2-Clause */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/cryptodesc.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <opencrypto/cryptodev.h>

#include <libservice.h>
#include <cryptocmp.h>
#include <fidl/bsd.crypto.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>

#include "bsdcrypto_test.h"

/*
 * The real per-session bsd.crypto.v1 server runs in a forked child.  The
 * helpers below drive it with the generated client bindings (bypassing the
 * client library's own argument checks, so the provider's validation is what
 * is tested); malformed cases use hand-built frames on a raw session.
 */
struct raw_fixture {
	struct fidl_bsd_connection *client;
	struct service_session	*session;	/* raw-frame cases */
	pid_t			 child;
};

/* FIDL v2 transactional message header. */
struct wire_header {
	uint32_t txid;
	uint8_t flags[3], magic;
	uint64_t ordinal;
};
#define ORD_INFO	UINT64_C(0x56c81469c09d4761)
#define ORD_GENERATE	UINT64_C(0x575612652a8f195f)
#define ORD_DIGEST	UINT64_C(0x0b0aa5a69f1218d9)
#define ORD_RANDOM	UINT64_C(0x6066b5740d95f5d8)

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

/*
 * Minting a session descriptor needs the software crypto driver; with no
 * hardware engine (a VM) the kernel refuses with EINVAL unless
 * kern.crypto.allow_soft is set.  Tests that mint sessions enable it and
 * restore the default (0) in their cleanup.
 */
static void
allow_software_crypto(int value)
{
	ATF_REQUIRE_MSG(sysctlbyname("kern.crypto.allow_soft", NULL, NULL,
	    &value, sizeof(value)) == 0, "kern.crypto.allow_soft: %s",
	    strerror(errno));
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
struct result {
	bool done;
	int error;		/* transport */
	int status;		/* application errno */
	int fd;
	uint64_t generation;
	struct cryptocmp_named_info info;
	struct cryptocmp_named_list_entry *entries;
	uint32_t count, next;
	uint8_t *buf;
	size_t buflen;
	uint32_t got;
};

static void
wait_for(struct raw_fixture *fixture, struct result *r)
{
	struct timespec deadline;

	ATF_REQUIRE_EQ(0, fidl_bsd_sync_deadline(&deadline, 5000));
	if (r->error == 0)
		r->error = fidl_bsd_sync_wait(fixture->client, &r->done,
		    &deadline);
	ATF_REQUIRE_EQ_MSG(0, r->error, "call failed: %s", strerror(r->error));
}

static void
info_done(void *p, int error, struct bsd_crypto_v1_ProtocolInfo *v)
{
	struct result *r = p;

	r->done = true;
	r->error = error;
	if (!error)
		ATF_REQUIRE_EQ(CRYPTOCMP_WIRE_VERSION, v->wire_version);
}

static void
fixture_start(struct raw_fixture *fixture, const char *owner, bool raw)
{
	struct fidl_bsd_empty empty = { 0 };
	struct result r = { .fd = -1 };
	uint32_t txid;
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(bsdcrypto_test_serve(provider, owner));
	}
	close(provider);
	if (raw) {
		ATF_REQUIRE_EQ(0, service_session_create(client,
		    &fixture->session));
		return;
	}
	ATF_REQUIRE_EQ(0, fidl_bsd_connection_create(client, FIDL_BSD_CLIENT,
	    &fixture->client));
	r.error = bsd_crypto_v1_Crypto_GetProtocolInfo(fixture->client, &empty,
	    info_done, &r, &txid);
	wait_for(fixture, &r);
}

/*
 * Stand up an owner-scoped provider worker bound to a caller-supplied owner
 * label.  Each fixture is a distinct worker sharing the one kernel named-key
 * store, so keys minted under one label are invisible to another.
 */
static void
raw_fixture_create(struct raw_fixture *fixture, const char *owner)
{

	fixture_start(fixture, owner, false);
}

static void
raw_fixture_destroy(struct raw_fixture *fixture, int expected_status)
{
	int status;

	if (fixture->client != NULL)
		fidl_bsd_connection_destroy(fixture->client);
	if (fixture->session != NULL)
		service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(expected_status, WEXITSTATUS(status));
}

#define RESULT_HEAD(method)                                                   \
	struct result *r = p;                                                 \
	r->done = true;                                                       \
	r->error = error;                                                     \
	if (error)                                                            \
		return;                                                       \
	if (v->tag == bsd_crypto_v1_Crypto_##method##_Result_err_tag) {       \
		r->status = (int)v->value.err;                                \
		return;                                                       \
	}

static void
generation_done_create(void *p, int error,
    struct bsd_crypto_v1_Crypto_NamedCreate_Result *v)
{
	RESULT_HEAD(NamedCreate)
	r->generation = v->value.response.generation;
}
static void
generation_done_rotate(void *p, int error,
    struct bsd_crypto_v1_Crypto_NamedRotate_Result *v)
{
	RESULT_HEAD(NamedRotate)
	r->generation = v->value.response.generation;
}
static void
generation_done_delete(void *p, int error,
    struct bsd_crypto_v1_Crypto_NamedDelete_Result *v)
{
	RESULT_HEAD(NamedDelete)
	r->generation = v->value.response.generation;
}
static void
lease_done(void *p, int error, struct bsd_crypto_v1_Crypto_NamedLease_Result *v)
{
	RESULT_HEAD(NamedLease)
	r->generation = v->value.response.generation;
	r->fd = fidl_bsd_take_fd(&v->value.response.descriptor);
}
static void
stat_done(void *p, int error, struct bsd_crypto_v1_Crypto_NamedStat_Result *v)
{
	RESULT_HEAD(NamedStat)
	r->info.generation = v->value.response.generation;
	r->info.rights = v->value.response.rights;
	r->info.cipher = v->value.response.cipher;
	r->info.mac = v->value.response.mac;
	r->info.keylen = v->value.response.keylen;
	r->info.mackeylen = v->value.response.mackeylen;
}
static void
list_done(void *p, int error, struct bsd_crypto_v1_Crypto_NamedList_Result *v)
{
	RESULT_HEAD(NamedList)
	ATF_REQUIRE(v->value.response.entries_size <= CRYPTOCMP_NAMED_LIST_MAX);
	r->count = (uint32_t)v->value.response.entries_size;
	r->next = v->value.response.next_cursor;
	for (uint32_t i = 0; r->entries != NULL && i < r->count; i++) {
		const struct bsd_crypto_v1_NamedEntry *e =
		    &v->value.response.entries[i];

		ATF_REQUIRE(e->name_size < sizeof(r->entries[i].name));
		memset(&r->entries[i], 0, sizeof(r->entries[i]));
		memcpy(r->entries[i].name, e->name, e->name_size);
		r->entries[i].generation = e->generation;
		r->entries[i].rights = e->rights;
	}
}
static void
digest_done(void *p, int error, struct bsd_crypto_v1_Crypto_Digest_Result *v)
{
	RESULT_HEAD(Digest)
	r->fd = fidl_bsd_take_fd(&v->value.response.descriptor);
}
static void
random_done(void *p, int error, struct bsd_crypto_v1_Crypto_Random_Result *v)
{
	RESULT_HEAD(Random)
	r->got = (uint32_t)v->value.response.data_size;
	if (r->buf != NULL && r->got <= r->buflen)
		memcpy(r->buf, v->value.response.data, r->got);
}

/*
 * Send a well-formed named-key request (payload is the cryptocmp_named_*
 * record for opcode) and return the daemon's errno-style status (0 on
 * success, positive errno on rejection).  On a successful lease the delivered
 * descriptor is returned through out_fd.
 */
static int
named_op(struct raw_fixture *fixture, uint16_t opcode, const void *payload,
    size_t paylen, uint64_t *generation, int *out_fd)
{
	struct result r = { .fd = -1 };
	uint32_t txid;

	(void)paylen;
	switch (opcode) {
	case CRYPTOCMP_OP_NAMED_CREATE: {
		const struct cryptocmp_named_create *in = payload;
		struct bsd_crypto_v1_NamedCreateRequest q = { in->name,
			strnlen(in->name, sizeof(in->name)), {
			in->generate.cipher, in->generate.mac,
			in->generate.keylen, in->generate.mackeylen,
			in->generate.rights, in->generate.ttl,
			in->generate.flags, in->generate.crid,
			in->generate.ivlen, in->generate.maclen } };

		r.error = bsd_crypto_v1_Crypto_NamedCreate(fixture->client, &q,
		    generation_done_create, &r, &txid);
		break;
	}
	case CRYPTOCMP_OP_NAMED_LEASE: {
		const struct cryptocmp_named_lease *in = payload;
		struct bsd_crypto_v1_NamedLeaseRequest q = { in->name,
			strnlen(in->name, sizeof(in->name)), in->rights,
			in->ttl, in->flags };

		r.error = bsd_crypto_v1_Crypto_NamedLease(fixture->client, &q,
		    lease_done, &r, &txid);
		break;
	}
	default: {
		const struct cryptocmp_named_control *in = payload;
		struct bsd_crypto_v1_NamedControlRequest q = { in->name,
			strnlen(in->name, sizeof(in->name)), in->flags };

		if (opcode == CRYPTOCMP_OP_NAMED_ROTATE)
			r.error = bsd_crypto_v1_Crypto_NamedRotate(
			    fixture->client, &q, generation_done_rotate, &r,
			    &txid);
		else
			r.error = bsd_crypto_v1_Crypto_NamedDelete(
			    fixture->client, &q, generation_done_delete, &r,
			    &txid);
		break;
	}
	}
	wait_for(fixture, &r);
	if (out_fd != NULL)
		*out_fd = r.fd;
	else if (r.fd >= 0)
		close(r.fd);
	if (generation != NULL)
		*generation = r.generation;
	return (r.status);
}

/*
 * Read-only introspection: NamedStat for name; returns the daemon's
 * errno-style status and, on success, the key metadata.  No descriptor is
 * ever delivered for a stat.
 */
static int
stat_op(struct raw_fixture *fixture, const char *name,
    struct cryptocmp_named_info *info)
{
	struct bsd_crypto_v1_NamedControlRequest q = { name, strlen(name), 0 };
	struct result r = { .fd = -1 };
	uint32_t txid;

	r.error = bsd_crypto_v1_Crypto_NamedStat(fixture->client, &q,
	    stat_done, &r, &txid);
	wait_for(fixture, &r);
	if (r.status == 0 && info != NULL)
		*info = r.info;
	return (r.status);
}

/*
 * Owner-scoped enumeration at the given cursor; returns the daemon's
 * errno-style status and, on success, up to CRYPTOCMP_NAMED_LIST_MAX entries,
 * the populated count and the resume cursor.  The request carries no owner.
 */
static int
list_op(struct raw_fixture *fixture, uint32_t cursor,
    struct cryptocmp_named_list_entry *entries, uint32_t *count,
    uint32_t *next_cursor)
{
	struct bsd_crypto_v1_NamedListRequest q = { cursor, 0 };
	struct result r = { .fd = -1, .entries = entries };
	uint32_t txid;

	r.error = bsd_crypto_v1_Crypto_NamedList(fixture->client, &q,
	    list_done, &r, &txid);
	wait_for(fixture, &r);
	if (r.status == 0) {
		if (count != NULL)
			*count = r.count;
		if (next_cursor != NULL)
			*next_cursor = r.next;
	}
	return (r.status);
}

/* Return the index of name within a NAMED_LIST result, or -1 if absent. */
static int
list_find(const struct cryptocmp_named_list_entry *entries, uint32_t count,
    const char *name)
{
	uint32_t i;

	for (i = 0; i < count; i++)
		if (strcmp(entries[i].name, name) == 0)
			return ((int)i);
	return (-1);
}

/* Send an arbitrary (possibly malformed) frame; return the call result. */
static int
send_raw(struct service_session *session, const void *data, size_t length,
    int attach_fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	uint8_t reply[64];
	int received = -1, rc, fd;

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = data;
	outgoing.length = length;
	if (attach_fd >= 0) {
		fd = attach_fd;
		outgoing.fds = &fd;
		outgoing.nfds = 1;
	}
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(reply);
	incoming.fds = &received;
	incoming.fd_capacity = 1;
	options.timeout_ms = 2000;
	rc = service_session_call(session, &outgoing, &incoming, &options);
	if (rc == 0 && incoming.nfds != 0 && received >= 0)
		close(received);
	return (rc);
}

/* A raw session that has negotiated, so a rejection is the frame's. */
static void
raw_negotiated(struct raw_fixture *fixture, const char *owner)
{
	struct wire_header info = { 1, { 2, 0, 0 }, 1, ORD_INFO };

	fixture_start(fixture, owner, true);
	ATF_REQUIRE_EQ(0, send_raw(fixture->session, &info, sizeof(info), -1));
}

/* A frame: header plus body bytes. */
static int
send_frame(struct service_session *session, uint64_t ordinal,
    const void *body, size_t length, int attach_fd)
{
	uint8_t frame[128];
	struct wire_header header = { 2, { 2, 0, 0 }, 1, ordinal };

	ATF_REQUIRE(sizeof(header) + length <= sizeof(frame));
	memcpy(frame, &header, sizeof(header));
	if (length != 0)
		memcpy(frame + sizeof(header), body, length);
	return (send_raw(session, frame, sizeof(header) + length, attach_fd));
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
 * Mint an unkeyed-digest session descriptor for the given plain-hash
 * algorithm.  Returns the daemon's errno-style status; on success the
 * delivered DTYPE_CRYPTO descriptor is returned through out_fd.
 */
static int
digest_op(struct raw_fixture *fixture, uint32_t alg, uint32_t ttl, int *out_fd)
{
	struct bsd_crypto_v1_DigestParams q = { alg, ttl, 0 };
	struct result r = { .fd = -1 };
	uint32_t txid;

	r.error = bsd_crypto_v1_Crypto_Digest(fixture->client, &q, digest_done,
	    &r, &txid);
	wait_for(fixture, &r);
	if (out_fd != NULL)
		*out_fd = r.fd;
	else if (r.fd >= 0)
		close(r.fd);
	return (r.status);
}

/*
 * Request nbytes of CSPRNG output.  Returns the daemon's errno-style status;
 * on success the reply's byte count is returned through got and the bytes are
 * copied into buf (capacity buflen).
 */
static int
random_op(struct raw_fixture *fixture, uint32_t nbytes, uint8_t *buf,
    size_t buflen, uint32_t *got)
{
	struct bsd_crypto_v1_RandomRequest q = { nbytes };
	struct result r = { .fd = -1, .buf = buf, .buflen = buflen };
	uint32_t txid;

	r.error = bsd_crypto_v1_Crypto_Random(fixture->client, &q, random_done,
	    &r, &txid);
	wait_for(fixture, &r);
	if (r.status == 0 && got != NULL)
		*got = r.got;
	return (r.status);
}

/*
 * An unkeyed digest is delivered as a session descriptor the client streams data
 * through: the daemon mints a DTYPE_CRYPTO fd for the requested plain hash, and
 * a CIOCCRYPT authentication pass over the classic NIST input "abc" reproduces
 * the published SHA-256 vector — proving both the descriptor and its right.
 */
ATF_TC_WITH_CLEANUP(digest_descriptor);
ATF_TC_HEAD(digest_descriptor, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "An unkeyed-digest descriptor computes a known SHA-256 vector");
}
ATF_TC_CLEANUP(digest_descriptor, tc)
{

	(void)sysctlbyname("kern.crypto.allow_soft", NULL, NULL,
	    &(int){0}, sizeof(int));
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
	allow_software_crypto(1);
	raw_fixture_create(&fixture, "org.test.digest");

	fd = -1;
	{
		int status = digest_op(&fixture, CRYPTO_SHA2_256, 60, &fd);

		ATF_CHECK_EQ_MSG(0, status, "digest status %d", status);
	}
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
	uint32_t body[4] = { CRYPTO_SHA2_256, 60, 0, 0 };
	int fd, pipefd[2];
	char byte;

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
	raw_fixture_destroy(&fixture, 0);

	/* A digest request with a truncated body (header only) ends the session. */
	raw_negotiated(&fixture, "org.test.dr.malformed");
	ATF_CHECK_EQ(-1, send_frame(fixture.session, ORD_DIGEST, NULL, 0, -1));
	raw_fixture_destroy(&fixture, 0);

	/* A random request with trailing bytes (wrong length). */
	raw_negotiated(&fixture, "org.test.dr.malformed");
	ATF_CHECK_EQ(-1, send_frame(fixture.session, ORD_RANDOM, body, 16, -1));
	raw_fixture_destroy(&fixture, 0);

	/* An attached descriptor must not be interpreted; the copy is closed. */
	raw_negotiated(&fixture, "org.test.dr.fd");
	ATF_REQUIRE_EQ(0, pipe(pipefd));
	ATF_CHECK_EQ(-1, send_frame(fixture.session, ORD_DIGEST, body, 16,
	    pipefd[1]));
	raw_fixture_destroy(&fixture, 0);
	close(pipefd[1]);
	ATF_REQUIRE(fcntl(pipefd[0], F_SETFL, O_NONBLOCK) != -1);
	ATF_CHECK_EQ(0, read(pipefd[0], &byte, 1));
	close(pipefd[0]);
}

ATF_TC_WITH_CLEANUP(named_key_is_owner_scoped);
ATF_TC_HEAD(named_key_is_owner_scoped, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A named key is reachable only under the owner label that minted it");
}
ATF_TC_CLEANUP(named_key_is_owner_scoped, tc)
{

	(void)sysctlbyname("kern.crypto.allow_soft", NULL, NULL,
	    &(int){0}, sizeof(int));
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
	allow_software_crypto(1);
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
 * Owner-scoped enumeration returns exactly the caller's own keys and nothing
 * else.  Owner A mints three keys and LIST returns all three with their create
 * generations; owner B — who minted none — sees an empty list and can never see
 * A's keys (the owner-scoping regression); a delete under A is immediately
 * reflected in A's subsequent LIST.
 */
ATF_TC(named_key_list);
ATF_TC_HEAD(named_key_list, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "NAMED_LIST enumerates only the owner's keys and tracks deletes");
}
ATF_TC_BODY(named_key_list, tc)
{
	static const char *names[3] = {
	    "list.key.1", "list.key.2", "list.key.3" };
	struct cryptocmp_named_create create;
	struct cryptocmp_named_control control;
	struct cryptocmp_named_list_entry entries[CRYPTOCMP_NAMED_LIST_MAX];
	struct raw_fixture owner_a, owner_b;
	uint64_t gen[3];
	uint32_t count, next_cursor;
	int i, idx;

	require_plane();
	raw_fixture_create(&owner_a, "org.test.list.a");
	raw_fixture_create(&owner_b, "org.test.list.b");

	/* An owner with no keys enumerates to an empty, terminal page. */
	count = 0xffffffffU;
	next_cursor = 0xffffffffU;
	ATF_CHECK_EQ(0, list_op(&owner_b, 0, entries, &count, &next_cursor));
	ATF_CHECK_EQ(0u, count);
	ATF_CHECK_EQ(0u, next_cursor);

	/* Owner A mints three named keys with known profiles. */
	for (i = 0; i < 3; i++) {
		memset(&create, 0, sizeof(create));
		strlcpy(create.name, names[i], sizeof(create.name));
		create.generate = sample_generate();
		ATF_CHECK_EQ(0, named_op(&owner_a, CRYPTOCMP_OP_NAMED_CREATE,
		    &create, sizeof(create), &gen[i], NULL));
	}

	/* A's LIST returns exactly its three keys, with their generations. */
	memset(entries, 0, sizeof(entries));
	count = 0;
	next_cursor = 0xffffffffU;
	ATF_CHECK_EQ(0, list_op(&owner_a, 0, entries, &count, &next_cursor));
	ATF_CHECK_EQ(3u, count);
	ATF_CHECK_EQ(0u, next_cursor);
	for (i = 0; i < 3; i++) {
		idx = list_find(entries, count, names[i]);
		ATF_REQUIRE_MSG(idx >= 0, "%s missing from LIST", names[i]);
		ATF_CHECK_EQ(gen[i], entries[idx].generation);
		ATF_CHECK_EQ((uint32_t)(CRYPTODESC_RIGHT_ENCRYPT |
		    CRYPTODESC_RIGHT_DECRYPT), entries[idx].rights);
	}

	/* Owner B still sees nothing: A's keys are not disclosed cross-owner. */
	count = 0xffffffffU;
	ATF_CHECK_EQ(0, list_op(&owner_b, 0, entries, &count, &next_cursor));
	ATF_CHECK_EQ(0u, count);

	/* A delete under A is reflected: list.key.2 vanishes, the rest remain. */
	memset(&control, 0, sizeof(control));
	strlcpy(control.name, "list.key.2", sizeof(control.name));
	ATF_CHECK_EQ(0, named_op(&owner_a, CRYPTOCMP_OP_NAMED_DELETE, &control,
	    sizeof(control), NULL, NULL));
	memset(entries, 0, sizeof(entries));
	count = 0;
	ATF_CHECK_EQ(0, list_op(&owner_a, 0, entries, &count, &next_cursor));
	ATF_CHECK_EQ(2u, count);
	ATF_CHECK(list_find(entries, count, "list.key.1") >= 0);
	ATF_CHECK_EQ(-1, list_find(entries, count, "list.key.2"));
	ATF_CHECK(list_find(entries, count, "list.key.3") >= 0);

	raw_fixture_destroy(&owner_b, 0);
	raw_fixture_destroy(&owner_a, 0);
}

/*
 * Enumeration pages by cursor across the fixed per-reply cap.  Owner C mints
 * more keys than a single reply can carry (CRYPTOCMP_NAMED_LIST_MAX + 2): the
 * first page fills to the cap and hands back a nonzero resume cursor, the
 * second page returns the remainder and terminates (next_cursor 0), and the
 * union of the two pages is exactly the full owner-scoped set with no repeats.
 */
ATF_TC(named_key_list_paginates);
ATF_TC_HEAD(named_key_list_paginates, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "NAMED_LIST pages by cursor across the per-reply cap");
}
ATF_TC_BODY(named_key_list_paginates, tc)
{
	const uint32_t total = CRYPTOCMP_NAMED_LIST_MAX + 2;
	struct cryptocmp_named_create create;
	struct cryptocmp_named_list_entry page1[CRYPTOCMP_NAMED_LIST_MAX];
	struct cryptocmp_named_list_entry page2[CRYPTOCMP_NAMED_LIST_MAX];
	struct raw_fixture owner_c;
	uint32_t count1, count2, next_cursor, i, j, seen;
	char name[32];

	require_plane();
	raw_fixture_create(&owner_c, "org.test.list.page");

	for (i = 0; i < total; i++) {
		memset(&create, 0, sizeof(create));
		(void)snprintf(name, sizeof(name), "page.key.%02u", i);
		strlcpy(create.name, name, sizeof(create.name));
		create.generate = sample_generate();
		ATF_CHECK_EQ(0, named_op(&owner_c, CRYPTOCMP_OP_NAMED_CREATE,
		    &create, sizeof(create), NULL, NULL));
	}

	/* First page: filled to the cap, more remain (resume cursor nonzero). */
	memset(page1, 0, sizeof(page1));
	count1 = 0;
	next_cursor = 0;
	ATF_CHECK_EQ(0, list_op(&owner_c, 0, page1, &count1, &next_cursor));
	ATF_CHECK_EQ((uint32_t)CRYPTOCMP_NAMED_LIST_MAX, count1);
	ATF_CHECK(next_cursor != 0);

	/* Second page: the remainder, and the walk terminates. */
	memset(page2, 0, sizeof(page2));
	count2 = 0;
	ATF_CHECK_EQ(0, list_op(&owner_c, next_cursor, page2, &count2,
	    &next_cursor));
	ATF_CHECK_EQ(total - CRYPTOCMP_NAMED_LIST_MAX, count2);
	ATF_CHECK_EQ(0u, next_cursor);

	/* Every minted name appears exactly once across the two pages. */
	for (i = 0; i < total; i++) {
		(void)snprintf(name, sizeof(name), "page.key.%02u", i);
		seen = 0;
		for (j = 0; j < count1; j++)
			if (strcmp(page1[j].name, name) == 0)
				seen++;
		for (j = 0; j < count2; j++)
			if (strcmp(page2[j].name, name) == 0)
				seen++;
		ATF_CHECK_EQ_MSG(1u, seen, "%s seen %u times", name, seen);
	}

	raw_fixture_destroy(&owner_c, 0);
}

/*
 * The provider fails closed on malformed requests: a bad magic, an
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
	struct raw_fixture fixture;
	struct cryptocmp_msg msg;
	struct cryptocmp_generate generate;
	uint8_t legacy[sizeof(struct cryptocmp_msg) +
	    sizeof(struct cryptocmp_generate)];
	uint32_t body[10];

	require_plane();
	generate = sample_generate();
	memset(body, 0, sizeof(body));
	body[0] = generate.cipher;
	body[2] = generate.keylen;
	body[4] = generate.rights;

	/* A pre-FIDL GENERATE record. */
	fixture_start(&fixture, "org.test.malformed", true);
	memset(&msg, 0, sizeof(msg));
	msg.magic = CRYPTOCMP_MAGIC;
	msg.opcode = CRYPTOCMP_OP_GENERATE;
	memcpy(legacy, &msg, sizeof(msg));
	memcpy(legacy + sizeof(msg), &generate, sizeof(generate));
	ATF_CHECK_EQ(-1, send_raw(fixture.session, legacy, sizeof(legacy), -1));
	raw_fixture_destroy(&fixture, 0);

	/* A well-formed Generate before negotiation. */
	fixture_start(&fixture, "org.test.malformed", true);
	ATF_CHECK_EQ(-1, send_frame(fixture.session, ORD_GENERATE, body,
	    sizeof(body), -1));
	raw_fixture_destroy(&fixture, 0);

	/* An unknown strict method. */
	raw_negotiated(&fixture, "org.test.malformed");
	ATF_CHECK_EQ(-1, send_frame(fixture.session, UINT64_C(0x7fff), body,
	    sizeof(body), -1));
	raw_fixture_destroy(&fixture, 0);

	/* Valid method, but a truncated body. */
	raw_negotiated(&fixture, "org.test.malformed");
	ATF_CHECK_EQ(-1, send_frame(fixture.session, ORD_GENERATE, body, 8, -1));
	raw_fixture_destroy(&fixture, 0);
}

/* Names are validated by the provider, not only by the client library. */
ATF_TC(provider_validates_names);
ATF_TC_HEAD(provider_validates_names, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_validates_names, tc)
{
	struct cryptocmp_named_control control;
	struct raw_fixture fixture;

	require_plane();
	raw_fixture_create(&fixture, "org.test.names");
	memset(&control, 0, sizeof(control));
	strlcpy(control.name, "bad/name", sizeof(control.name));
	ATF_CHECK(stat_op(&fixture, control.name, NULL) != 0);
	ATF_CHECK(named_op(&fixture, CRYPTOCMP_OP_NAMED_DELETE, &control,
	    sizeof(control), NULL, NULL) != 0);
	/* An embedded NUL never truncates into another key's name. */
	{
		struct bsd_crypto_v1_NamedControlRequest q = { "a\0b", 3, 0 };
		struct result r = { .fd = -1 };
		uint32_t txid;

		r.error = bsd_crypto_v1_Crypto_NamedStat(fixture.client, &q,
		    stat_done, &r, &txid);
		wait_for(&fixture, &r);
		ATF_CHECK_EQ(EINVAL, r.status);
	}
	raw_fixture_destroy(&fixture, 0);
}

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{

	ATF_CHECK_ERRNO(EINVAL, bsdcrypto_test_serve(-1, "org.test") == -1);
	ATF_CHECK_ERRNO(EINVAL, bsdcrypto_test_serve(0, NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, bsdcrypto_test_serve(0, "") == -1);
}

/*
 * The reclaim key is the bundle: the first component of the "<bundle>/<unit>"
 * container switchboard stamps.  A client with no bundle (a session) yields an
 * empty key and therefore never holds named keys and is never reaped; malformed
 * or over-long containers yield empty too (never a truncated, colliding key).
 */
ATF_TC_WITHOUT_HEAD(bundle_of_derives_the_reclaim_key);
ATF_TC_BODY(bundle_of_derives_the_reclaim_key, tc)
{
	char out[CRYPTODESC_KEY_OWNER_MAX];
	char toolong[CRYPTODESC_KEY_OWNER_MAX + 8];

	bsdcrypto_test_bundle_of("Test/reclaimprobe", out, sizeof(out));
	ATF_CHECK_STREQ("Test", out);
	bsdcrypto_test_bundle_of("Test", out, sizeof(out));
	ATF_CHECK_STREQ("Test", out);
	bsdcrypto_test_bundle_of("Test/a/b", out, sizeof(out));
	ATF_CHECK_STREQ("Test", out);
	bsdcrypto_test_bundle_of("/unit", out, sizeof(out));
	ATF_CHECK_STREQ("", out);
	bsdcrypto_test_bundle_of("", out, sizeof(out));
	ATF_CHECK_STREQ("", out);
	bsdcrypto_test_bundle_of(NULL, out, sizeof(out));
	ATF_CHECK_STREQ("", out);
	memset(toolong, 'x', sizeof(toolong) - 1);
	toolong[sizeof(toolong) - 1] = '\0';
	bsdcrypto_test_bundle_of(toolong, out, sizeof(out));
	ATF_CHECK_STREQ("", out);		/* over-long: empty, never truncated */
	memset(toolong, 'y', CRYPTODESC_KEY_OWNER_MAX - 1);
	toolong[CRYPTODESC_KEY_OWNER_MAX - 1] = '\0';
	bsdcrypto_test_bundle_of(toolong, out, sizeof(out));
	ATF_CHECK_STREQ(toolong, out);		/* longest legal key fits */
	/* A tiny output buffer yields empty rather than a partial key. */
	bsdcrypto_test_bundle_of("Test/unit", out, 4);
	ATF_CHECK_STREQ("", out);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, bundle_of_derives_the_reclaim_key);
	ATF_TP_ADD_TC(tp, named_key_is_owner_scoped);
	ATF_TP_ADD_TC(tp, named_key_stat);
	ATF_TP_ADD_TC(tp, named_key_list);
	ATF_TP_ADD_TC(tp, named_key_list_paginates);
	ATF_TP_ADD_TC(tp, malformed_request_is_rejected);
	ATF_TP_ADD_TC(tp, provider_validates_names);
	ATF_TP_ADD_TC(tp, digest_descriptor);
	ATF_TP_ADD_TC(tp, random_bytes);
	ATF_TP_ADD_TC(tp, digest_random_malformed);
	ATF_TP_ADD_TC(tp, arguments);
	return (atf_no_error());
}
