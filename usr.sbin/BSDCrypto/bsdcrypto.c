/*- SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/cryptodesc.h>
#include <auditcmp.h>
#include <auditcmp_server.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <capreclaim.h>
#include <cryptodesc.h>
#include <cryptocmp.h>
#include <fidl/bsd.crypto.v1/c/bsd.h>
#include <libservice.h>
#include <extensioncmp.h>
#include <service_runtime.h>
#include <logcmp.h>

#include "policy.h"
#include "crypto_probes.h"
#ifdef BSDCRYPTO_TESTING
#include "bsdcrypto_test.h"
#endif

#define CRYPTOCMP_NAME "system.Crypto"

static int control_fd = -1;
struct crypto_worker {
	char	owner[CRYPTODESC_KEY_OWNER_MAX];
	char	actor[64];
	struct auditcmp_client *audit;
	bool	negotiated;
	int	error;		/* a handler-detected protocol or reply failure */
};

static int
harden_control_descriptor(bool worker)
{
	static const unsigned long commands[] = {
		CIOCGCRYPTODESCGENERATE,
		CIOCGCRYPTOKEYDESC,
		CIOCGCRYPTONAMEDKEY,
		CIOCGCRYPTONAMEDLEASE,
		CIOCCRYPTONAMEDROTATE,
		CIOCCRYPTONAMEDDELETE,
		CIOCGCRYPTONAMEDSTAT,
		CIOCGCRYPTONAMEDLIST,
		CIOCGCRYPTOOWNERLIST,
	};
	cap_rights_t rights;

	if (cap_xfer_limit(control_fd, CAP_XFER_NONE) == -1 ||
	    (worker && cap_clofork_limit(control_fd, CAP_CLOFORK_LOCKED) == -1) ||
	    cap_cloexec_limit(control_fd, CAP_CLOEXEC_LOCKED) == -1 ||
	    cap_ioctls_limit(control_fd, commands, nitems(commands)) == -1)
		return (-1);
	cap_rights_init(&rights, CAP_IOCTL);
	return (cap_rights_limit(control_fd, &rights));
}

static void
audit_operation(struct crypto_worker *worker, const char *operation, int error)
{

	if (worker->audit != NULL)
		(void)auditcmp_submit(worker->audit, worker->actor, operation, error);
}
/*
 * bsd.crypto.v1 method handlers.  Every method but GetProtocolInfo requires a
 * negotiated session.  The owner is the session's channel label (never a wire
 * argument) for every named-key method.  Each method is audited and fires the
 * request-done probe with the historical CRYPTOCMP_OP_* code; a failed reply
 * closes the connection.
 */
static bool
session_ready(struct crypto_worker *worker,
    struct fidl_bsd_connection *connection, uint32_t opcode)
{

	if (worker->negotiated)
		return (true);
	worker->error = EPROTO;
	audit_operation(worker, "malformed-request", EPROTO);
	CRYPTO_PROBE_REQUEST_DONE(opcode, -EPROTO, EPROTO);
	fidl_bsd_connection_close(connection, EPROTO);
	return (false);
}

static void
request_done(struct crypto_worker *worker,
    struct fidl_bsd_connection *connection, uint32_t opcode,
    const char *operation, int error, int transport_error)
{

	audit_operation(worker, operation, error);
	if (transport_error != 0) {
		worker->error = transport_error;
		fidl_bsd_connection_close(connection, transport_error);
	}
	CRYPTO_PROBE_REQUEST_DONE(opcode, error == 0 ? 0 : -error,
	    transport_error);
}

/*
 * Harden a delivered crypto descriptor (a session or named-key lease) as a
 * single-hop capability: this delivery is the one-and-only delegation
 * (CAP_XFER_ONCE: the client's copy is non-re-delegable, matching the
 * owner-scoping the daemon enforces), it survives one more fork, and it is
 * close-on-exec locked.  The op rights are already fixed in-kernel
 * (cd_rights).  Fail closed: a descriptor that cannot be confined is never
 * delivered; the method fails instead.  Returns 0 or an errno, consuming *fd
 * on failure.
 */
static int
harden_delivery(int *fd)
{
	int error;

	if (service_harden_fd(*fd, SERVICE_HARDEN_XFER_ONCE |
	    SERVICE_HARDEN_CLOFORK_ONCE) == 0)
		return (0);
	error = errno;
	syslog(LOG_WARNING, "harden delivered descriptor: %m; withholding");
	(void)close(*fd);
	*fd = -1;
	return (error);
}

/* A received key name as the policy layer's fixed NUL-terminated field. */
static int
copy_name(char *out, size_t size, const char *name, size_t length)
{

	if (length == 0 || length >= size ||
	    memchr(name, '\0', length) != NULL)
		return (EINVAL);
	memset(out, 0, size);
	memcpy(out, name, length);
	return (0);
}

static void
generate_session(const struct bsd_crypto_v1_GenerateParams *in,
    struct cryptocmp_generate *out)
{

	memset(out, 0, sizeof(*out));
	out->cipher = in->cipher;
	out->mac = in->mac;
	out->keylen = in->keylen;
	out->mackeylen = in->mackeylen;
	out->rights = in->rights;
	out->ttl = in->ttl;
	out->flags = in->flags;
	out->crid = in->crid;
	out->ivlen = in->ivlen;
	out->maclen = in->maclen;
}

static void
session_parameters(const struct cryptocmp_generate *generate,
    struct session2_op *session)
{

	memset(session, 0, sizeof(*session));
	session->cipher = generate->cipher;
	session->mac = generate->mac;
	session->keylen = generate->keylen;
	session->key = NULL;
	session->mackeylen = generate->mackeylen;
	session->mackey = NULL;
	session->crid = generate->crid;
	session->ivlen = generate->ivlen;
	session->maclen = generate->maclen;
}

static void
protocol_info(void *arg, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct crypto_worker *worker = arg;
	struct bsd_crypto_v1_ProtocolInfo info = { CRYPTOCMP_WIRE_VERSION };
	int error;

	error = bsd_crypto_v1_Crypto_GetProtocolInfo_reply(connection, request,
	    &info);
	worker->negotiated = error == 0;
	if (error != 0) {
		worker->error = error;
		fidl_bsd_connection_close(connection, error);
	}
	CRYPTO_PROBE_REQUEST_DONE(0, 0, error);
}

/* Reply with a session descriptor (Generate and Digest). */
static int
reply_session(struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, uint32_t opcode, int error, int fd)
{
	if (opcode == CRYPTOCMP_OP_GENERATE) {
		struct bsd_crypto_v1_Crypto_Generate_Result reply = { 0 };

		reply.tag = error ? bsd_crypto_v1_Crypto_Generate_Result_err_tag :
		    bsd_crypto_v1_Crypto_Generate_Result_response_tag;
		if (error)
			reply.value.err = (uint32_t)error;
		else
			reply.value.response.descriptor = fd;
		return (bsd_crypto_v1_Crypto_Generate_reply(connection, request,
		    &reply));
	} else {
		struct bsd_crypto_v1_Crypto_Digest_Result reply = { 0 };

		reply.tag = error ? bsd_crypto_v1_Crypto_Digest_Result_err_tag :
		    bsd_crypto_v1_Crypto_Digest_Result_response_tag;
		if (error)
			reply.value.err = (uint32_t)error;
		else
			reply.value.response.descriptor = fd;
		return (bsd_crypto_v1_Crypto_Digest_reply(connection, request,
		    &reply));
	}
}

static void
generate(void *arg, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_crypto_v1_GenerateParams *in)
{
	struct crypto_worker *worker = arg;
	struct cryptocmp_generate params;
	struct session2_op session;
	int error = 0, fd = -1;

	if (!session_ready(worker, connection, CRYPTOCMP_OP_GENERATE))
		return;
	generate_session(in, &params);
	if (cryptocmp_policy_validate(&params) != 0)
		error = errno;
	else {
		session_parameters(&params, &session);
		if (cryptodesc_mint_generated(control_fd, &session,
		    params.rights, params.ttl, &fd) != 0)
			error = errno;
		else
			error = harden_delivery(&fd);
	}
	/* The bindings send a private duplicate; ours is closed below. */
	request_done(worker, connection, CRYPTOCMP_OP_GENERATE,
	    "descriptor-generate", error, reply_session(connection, request,
	    CRYPTOCMP_OP_GENERATE, error, fd));
	if (fd >= 0)
		close(fd);
}

static void
generate_key(void *arg, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_crypto_v1_KeyParams *in)
{
	struct crypto_worker *worker = arg;
	struct bsd_crypto_v1_Crypto_GenerateKey_Result reply = { 0 };
	struct cryptocmp_key_generate params;
	uint8_t public_key[CRYPTODESC_ED25519_PUBLIC_SIZE];
	int error = 0, fd = -1;

	_Static_assert(sizeof(public_key) ==
	    sizeof(reply.value.response.public_key), "public key size");
	if (!session_ready(worker, connection, CRYPTOCMP_OP_GENERATE_KEY))
		return;
	memset(public_key, 0, sizeof(public_key));
	memset(&params, 0, sizeof(params));
	params.type = in->type;
	params.rights = in->rights;
	params.ttl = in->ttl;
	params.flags = in->flags;
	if (cryptocmp_key_policy_validate(&params) != 0)
		error = errno;
	else if (cryptodesc_mint_key(control_fd, params.type, params.rights,
	    params.ttl, public_key, &fd) != 0)
		error = errno;
	else
		error = harden_delivery(&fd);
	reply.tag = error ? bsd_crypto_v1_Crypto_GenerateKey_Result_err_tag :
	    bsd_crypto_v1_Crypto_GenerateKey_Result_response_tag;
	if (error)
		reply.value.err = (uint32_t)error;
	else {
		reply.value.response.descriptor = fd;
		memcpy(reply.value.response.public_key, public_key,
		    sizeof(public_key));
	}
	request_done(worker, connection, CRYPTOCMP_OP_GENERATE_KEY,
	    "key-generate", error, bsd_crypto_v1_Crypto_GenerateKey_reply(
	    connection, request, &reply));
	if (fd >= 0)
		close(fd);
	explicit_bzero(public_key, sizeof(public_key));
	explicit_bzero(&reply, sizeof(reply));
}

static void
named_create(void *arg, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request,
    struct bsd_crypto_v1_NamedCreateRequest *in)
{
	struct crypto_worker *worker = arg;
	struct bsd_crypto_v1_Crypto_NamedCreate_Result reply = { 0 };
	struct cryptocmp_named_create create;
	struct session2_op session;
	uint64_t generation = 0;
	int error;

	if (!session_ready(worker, connection, CRYPTOCMP_OP_NAMED_CREATE))
		return;
	memset(&create, 0, sizeof(create));
	error = copy_name(create.name, sizeof(create.name), in->name,
	    in->name_size);
	if (error == 0) {
		generate_session(&in->params, &create.generate);
		if (cryptocmp_named_create_policy_validate(&create) != 0)
			error = errno;
		else {
			session_parameters(&create.generate, &session);
			if (cryptodesc_named_create(control_fd, create.name,
			    worker->owner, &session, create.generate.rights,
			    &generation) != 0)
				error = errno;
		}
	}
	reply.tag = error ? bsd_crypto_v1_Crypto_NamedCreate_Result_err_tag :
	    bsd_crypto_v1_Crypto_NamedCreate_Result_response_tag;
	if (error)
		reply.value.err = (uint32_t)error;
	else
		reply.value.response.generation = generation;
	request_done(worker, connection, CRYPTOCMP_OP_NAMED_CREATE,
	    "named-create", error, bsd_crypto_v1_Crypto_NamedCreate_reply(
	    connection, request, &reply));
}

static void
named_lease(void *arg, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request,
    struct bsd_crypto_v1_NamedLeaseRequest *in)
{
	struct crypto_worker *worker = arg;
	struct bsd_crypto_v1_Crypto_NamedLease_Result reply = { 0 };
	struct cryptocmp_named_lease lease;
	uint64_t generation = 0;
	int error, fd = -1;

	if (!session_ready(worker, connection, CRYPTOCMP_OP_NAMED_LEASE))
		return;
	memset(&lease, 0, sizeof(lease));
	error = copy_name(lease.name, sizeof(lease.name), in->name,
	    in->name_size);
	lease.rights = in->rights;
	lease.ttl = in->ttl;
	lease.flags = in->flags;
	if (error == 0 && cryptocmp_named_lease_policy_validate(&lease) != 0)
		error = errno;
	else if (error == 0 && cryptodesc_named_lease(control_fd, lease.name,
	    worker->owner, lease.rights, lease.ttl, &generation, &fd) != 0)
		error = errno;
	else if (error == 0)
		error = harden_delivery(&fd);
	reply.tag = error ? bsd_crypto_v1_Crypto_NamedLease_Result_err_tag :
	    bsd_crypto_v1_Crypto_NamedLease_Result_response_tag;
	if (error)
		reply.value.err = (uint32_t)error;
	else {
		reply.value.response.descriptor = fd;
		reply.value.response.generation = generation;
	}
	request_done(worker, connection, CRYPTOCMP_OP_NAMED_LEASE,
	    "named-lease", error, bsd_crypto_v1_Crypto_NamedLease_reply(
	    connection, request, &reply));
	if (fd >= 0)
		close(fd);
}

static void
named_change(struct crypto_worker *worker,
    struct fidl_bsd_connection *connection, struct fidl_bsd_request *request,
    const struct bsd_crypto_v1_NamedControlRequest *in, uint32_t opcode)
{
	struct cryptocmp_named_control control;
	uint64_t generation = 0;
	int error, reply_error;

	if (!session_ready(worker, connection, opcode))
		return;
	memset(&control, 0, sizeof(control));
	error = copy_name(control.name, sizeof(control.name), in->name,
	    in->name_size);
	control.flags = in->flags;
	if (error == 0 && cryptocmp_named_control_policy_validate(&control) !=
	    0)
		error = errno;
	else if (error == 0 && (opcode == CRYPTOCMP_OP_NAMED_ROTATE ?
	    cryptodesc_named_rotate(control_fd, control.name, worker->owner,
	    &generation) : cryptodesc_named_delete(control_fd, control.name,
	    worker->owner, &generation)) != 0)
		error = errno;
	if (opcode == CRYPTOCMP_OP_NAMED_ROTATE) {
		struct bsd_crypto_v1_Crypto_NamedRotate_Result reply = { 0 };

		reply.tag = error ?
		    bsd_crypto_v1_Crypto_NamedRotate_Result_err_tag :
		    bsd_crypto_v1_Crypto_NamedRotate_Result_response_tag;
		if (error)
			reply.value.err = (uint32_t)error;
		else
			reply.value.response.generation = generation;
		reply_error = bsd_crypto_v1_Crypto_NamedRotate_reply(connection,
		    request, &reply);
	} else {
		struct bsd_crypto_v1_Crypto_NamedDelete_Result reply = { 0 };

		reply.tag = error ?
		    bsd_crypto_v1_Crypto_NamedDelete_Result_err_tag :
		    bsd_crypto_v1_Crypto_NamedDelete_Result_response_tag;
		if (error)
			reply.value.err = (uint32_t)error;
		else
			reply.value.response.generation = generation;
		reply_error = bsd_crypto_v1_Crypto_NamedDelete_reply(connection,
		    request, &reply);
	}
	request_done(worker, connection, opcode,
	    opcode == CRYPTOCMP_OP_NAMED_ROTATE ? "named-rotate" :
	    "named-delete", error, reply_error);
}

static void
named_rotate(void *arg, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request,
    struct bsd_crypto_v1_NamedControlRequest *in)
{
	named_change(arg, connection, request, in, CRYPTOCMP_OP_NAMED_ROTATE);
}

static void
named_delete(void *arg, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request,
    struct bsd_crypto_v1_NamedControlRequest *in)
{
	named_change(arg, connection, request, in, CRYPTOCMP_OP_NAMED_DELETE);
}

static void
digest(void *arg, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_crypto_v1_DigestParams *in)
{
	struct crypto_worker *worker = arg;
	struct cryptocmp_digest params;
	struct session2_op session;
	int error = 0, fd = -1;

	if (!session_ready(worker, connection, CRYPTOCMP_OP_DIGEST))
		return;
	memset(&params, 0, sizeof(params));
	params.alg = in->alg;
	params.ttl = in->ttl;
	params.flags = in->flags;
	if (cryptocmp_digest_policy_validate(&params) != 0)
		error = errno;
	else {
		/*
		 * An unkeyed hash is an ordinary DIGEST-mode session with no
		 * cipher and no MAC key.  It reuses the generated-session mint
		 * path and is delivered as a DTYPE_CRYPTO descriptor the client
		 * streams data through; CRYPTODESC_RIGHT_AUTH is the right the
		 * kernel requires to compute a digest.
		 */
		memset(&session, 0, sizeof(session));
		session.mac = params.alg;
		if (cryptodesc_mint_generated(control_fd, &session,
		    CRYPTODESC_RIGHT_AUTH, params.ttl, &fd) != 0)
			error = errno;
		else
			error = harden_delivery(&fd);
	}
	request_done(worker, connection, CRYPTOCMP_OP_DIGEST, "digest", error,
	    reply_session(connection, request, CRYPTOCMP_OP_DIGEST, error, fd));
	if (fd >= 0)
		close(fd);
}

static void
random_bytes(void *arg, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_crypto_v1_RandomRequest *in)
{
	struct crypto_worker *worker = arg;
	struct bsd_crypto_v1_Crypto_Random_Result reply = { 0 };
	struct cryptocmp_random params = { in->nbytes };
	uint8_t data[CRYPTOCMP_MAX_RANDOM_BYTES];
	int error = 0;

	if (!session_ready(worker, connection, CRYPTOCMP_OP_RANDOM))
		return;
	if (cryptocmp_random_policy_validate(&params) != 0)
		error = errno;
	if (error) {
		reply.tag = bsd_crypto_v1_Crypto_Random_Result_err_tag;
		reply.value.err = (uint32_t)error;
	} else {
		/*
		 * CSPRNG bytes are not secret-key material to confine, so they
		 * are returned inline; the local buffer is scrubbed after the
		 * send.
		 */
		arc4random_buf(data, params.nbytes);
		reply.tag = bsd_crypto_v1_Crypto_Random_Result_response_tag;
		reply.value.response.data = data;
		reply.value.response.data_size = params.nbytes;
	}
	request_done(worker, connection, CRYPTOCMP_OP_RANDOM, "random", error,
	    bsd_crypto_v1_Crypto_Random_reply(connection, request, &reply));
	explicit_bzero(data, sizeof(data));
}

static void
named_stat(void *arg, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request,
    struct bsd_crypto_v1_NamedControlRequest *in)
{
	struct crypto_worker *worker = arg;
	struct bsd_crypto_v1_Crypto_NamedStat_Result reply = { 0 };
	struct cryptocmp_named_stat params;
	struct cryptodesc_named_stat stat;
	int error;

	if (!session_ready(worker, connection, CRYPTOCMP_OP_NAMED_STAT))
		return;
	memset(&params, 0, sizeof(params));
	memset(&stat, 0, sizeof(stat));
	error = copy_name(params.name, sizeof(params.name), in->name,
	    in->name_size);
	params.flags = in->flags;
	/*
	 * Read-only introspection: resolve the key owner-scoped on
	 * worker->owner (never a wire-supplied owner) and copy out its
	 * metadata.  No descriptor is minted and the key is not mutated; a
	 * miss is ENOENT.
	 */
	if (error == 0 && cryptocmp_named_stat_policy_validate(&params) != 0)
		error = errno;
	else if (error == 0 && cryptodesc_named_stat(control_fd, params.name,
	    worker->owner, &stat) != 0)
		error = errno;
	reply.tag = error ? bsd_crypto_v1_Crypto_NamedStat_Result_err_tag :
	    bsd_crypto_v1_Crypto_NamedStat_Result_response_tag;
	if (error)
		reply.value.err = (uint32_t)error;
	else {
		reply.value.response.generation = stat.cd_generation;
		reply.value.response.rights = stat.cd_rights;
		reply.value.response.cipher = stat.cd_cipher;
		reply.value.response.mac = stat.cd_mac;
		reply.value.response.keylen = stat.cd_keylen;
		reply.value.response.mackeylen = stat.cd_mackeylen;
	}
	request_done(worker, connection, CRYPTOCMP_OP_NAMED_STAT, "named-stat",
	    error, bsd_crypto_v1_Crypto_NamedStat_reply(connection, request,
	    &reply));
}

static void
named_list(void *arg, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_crypto_v1_NamedListRequest *in)
{
	struct crypto_worker *worker = arg;
	struct bsd_crypto_v1_Crypto_NamedList_Result reply = { 0 };
	struct cryptocmp_named_list params = { in->cursor, in->flags };
	struct cryptodesc_named_list_entry list[CRYPTODESC_NAMED_LIST_MAX];
	struct bsd_crypto_v1_NamedEntry out[CRYPTOCMP_NAMED_LIST_MAX];
	uint32_t count = 0, next = 0, i;
	int error = 0;

	if (!session_ready(worker, connection, CRYPTOCMP_OP_NAMED_LIST))
		return;
	memset(list, 0, sizeof(list));
	/*
	 * Owner-scoped enumeration: resolve the walk on worker->owner (never a
	 * wire-supplied owner) and copy out only names, generations and
	 * rights.  No descriptor is minted, no key is mutated, and no key
	 * material leaves the kernel; an out-of-range cursor is an empty page.
	 */
	if (cryptocmp_named_list_policy_validate(&params) != 0)
		error = errno;
	else if (cryptodesc_named_list(control_fd, worker->owner,
	    params.cursor, list, CRYPTODESC_NAMED_LIST_MAX, &count, &next) != 0)
		error = errno;
	CRYPTO_PROBE_NAMED_LIST(worker->owner, count, error);
	if (error) {
		reply.tag = bsd_crypto_v1_Crypto_NamedList_Result_err_tag;
		reply.value.err = (uint32_t)error;
	} else {
		if (count > CRYPTOCMP_NAMED_LIST_MAX)
			count = CRYPTOCMP_NAMED_LIST_MAX;
		for (i = 0; i < count; i++) {
			out[i].name = list[i].cd_name;
			out[i].name_size = strnlen(list[i].cd_name,
			    sizeof(list[i].cd_name));
			out[i].generation = list[i].cd_generation;
			out[i].rights = list[i].cd_rights;
		}
		reply.tag = bsd_crypto_v1_Crypto_NamedList_Result_response_tag;
		reply.value.response.entries = out;
		reply.value.response.entries_size = count;
		reply.value.response.next_cursor = next;
	}
	request_done(worker, connection, CRYPTOCMP_OP_NAMED_LIST, "named-list",
	    error, bsd_crypto_v1_Crypto_NamedList_reply(connection, request,
	    &reply));
	explicit_bzero(list, sizeof(list));
}

/* A connection the bindings closed for a malformed or unknown frame. */
static bool
protocol_rejection(int error)
{

	return (error != 0 && error != EPIPE && error != ECONNRESET &&
	    error != ECANCELED && error != ETIMEDOUT && error != ENOTCONN);
}

/*
 * The owner-scoped request/channel core.  The immutable owner label (bound to
 * the unforgeable channel peer identity by the caller) is threaded into every
 * named-key operation via crypto_worker::owner, so a session can only reach the
 * keys minted under its own label.  Both the production worker and the test
 * entrypoint drive this same path; only the surrounding sandbox setup differs.
 */
static int
serve_session(int fd, const char *owner, const char *actor, struct auditcmp_client *audit)
{
	static const struct bsd_crypto_v1_Crypto_server handlers = {
		.GetProtocolInfo = protocol_info,
		.Generate = generate,
		.GenerateKey = generate_key,
		.NamedCreate = named_create,
		.NamedLease = named_lease,
		.NamedRotate = named_rotate,
		.NamedDelete = named_delete,
		.Digest = digest,
		.Random = random_bytes,
		.NamedStat = named_stat,
		.NamedList = named_list
	};
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	struct fidl_bsd_connection *connection;
	struct crypto_worker state;
	int error;

	memset(&state, 0, sizeof(state));
	strlcpy(state.owner, owner, sizeof(state.owner));
	strlcpy(state.actor, actor, sizeof(state.actor));
	state.audit = audit;
	/* One request at a time; requests carry no descriptors. */
	options.max_pending_requests = 1;
	options.max_queued_messages = 8;
	options.max_queued_bytes = 16 * 1024;
	options.max_queued_fds = 1;
	if (fidl_bsd_connection_create_with_options(fd, FIDL_BSD_SERVER,
	    &options, &connection) != 0) {
		(void)close(fd);
		return (1);
	}
	/* Delivered descriptors are hardened by harden_delivery(). */
	fidl_bsd_connection_preserve_sent_inheritance(connection);
	if (bsd_crypto_v1_Crypto_bind(connection, &handlers, &state) != 0) {
		fidl_bsd_connection_destroy(connection);
		return (1);
	}
	/*
	 * The client disconnecting, or a frame the bindings refuse, ends the
	 * worker cleanly; a refused frame is audited like any malformed
	 * request.
	 */
	do
		error = fidl_bsd_connection_poll(connection, -1);
	while (error == 0);
	if (state.error == 0 && protocol_rejection(error)) {
		audit_operation(&state, "malformed-request", EPROTO);
		CRYPTO_PROBE_REQUEST_DONE(0, -EPROTO, 0);
	}
	fidl_bsd_connection_destroy(connection);
	return (0);
}

/*
 * The connecting unit's bundle -- the reclaim key -- is the first component of
 * the container "<bundle>/<unit>" switchboard stamps on the channel.  Empty when
 * the client has no bundle (a session), which then holds no named keys, and
 * empty (never truncated) when the component would not fit the key.
 */
static void
bundle_of(const char *container, char *out, size_t outsz)
{
	const char *slash;
	size_t n;

	out[0] = '\0';
	if (container == NULL)
		return;
	slash = strchr(container, '/');
	n = slash != NULL ? (size_t)(slash - container) : strlen(container);
	if (n == 0 || n >= outsz)
		return;
	memcpy(out, container, n);
	out[n] = '\0';
}

#ifdef BSDCRYPTO_TESTING
/* Test seam: the reclaim key derived from a stamped container. */
void
bsdcrypto_test_bundle_of(const char *container, char *out, size_t outsz)
{
	bundle_of(container, out, outsz);
}

/*
 * Test entrypoint: run the real owner-scoped serve path against a caller-owned
 * channel descriptor with a caller-supplied owner label.  It opens and hardens
 * the /dev/crypto control descriptor exactly as production does but omits the
 * switchboard-only sandbox wrappers (worker protect/authority-drop/cap_enter) and
 * the audit client, which require a live plane.  Named-key ownership is enforced
 * by the kernel key store keyed on (name, owner), so this exercises the true
 * isolation property.
 */
int
bsdcrypto_test_serve(int fd, const char *owner_label)
{

	if (fd < 0 || owner_label == NULL ||
	    strnlen(owner_label, CRYPTODESC_KEY_OWNER_MAX) == 0 ||
	    strnlen(owner_label, CRYPTODESC_KEY_OWNER_MAX) ==
	    CRYPTODESC_KEY_OWNER_MAX)
		return (errno = EINVAL, -1);
	control_fd = open("/dev/crypto", O_RDWR);
	if (control_fd < 0)
		return (-1);
	if (harden_control_descriptor(true) == -1)
		return (1);
	return (serve_session(fd, owner_label, owner_label, NULL));
}
#endif /* BSDCRYPTO_TESTING */

#ifndef BSDCRYPTO_TESTING

/*
 * Container-model key reclaim (docs/book/src/plane/containers-and-storage.md, keys in the
 * kernel).  Named keys are owned by the connecting unit's bundle; a forked
 * reconcile child compares the keystore's owners against the installed bundles
 * (System/, Apps/) and drops the keys of any bundle that is gone.
 */
#define	CRYPTO_SYSTEM_DIR	"/Capabilities/System"
#define	CRYPTO_APPS_DIR		"/Capabilities/Apps"
#define	CRYPTO_RUN_LIVE_DIR	"/Capabilities/Run/live"	/* running markers */
#define	CRYPTO_RECLAIM_INTERVAL	300	/* grace window for the timer passes */
#define	CRYPTO_RECLAIM_POLL	3	/* while awaiting the first pass */
#define	CRYPTO_RECLAIM_INTERVAL_MIN	10
#define	CRYPTO_RECLAIM_INTERVAL_MAX	86400

/*
 * The reconcile cadence (== grace window) may be set through the unit's
 * manifest environment, CRYPTO_RECLAIM_INTERVAL, within bounds; anything
 * else keeps the default.
 */
static unsigned
reclaim_interval(void)
{
	const char *s = getenv("CRYPTO_RECLAIM_INTERVAL");
	char *end;
	long v;

	if (s == NULL || *s == '\0')
		return (CRYPTO_RECLAIM_INTERVAL);
	errno = 0;
	v = strtol(s, &end, 10);
	if (errno != 0 || *end != '\0' || v < CRYPTO_RECLAIM_INTERVAL_MIN ||
	    v > CRYPTO_RECLAIM_INTERVAL_MAX)
		return (CRYPTO_RECLAIM_INTERVAL);
	return ((unsigned)v);
}
#define	CRYPTO_RECLAIM_MAX_ROUNDS 4096	/* deletion renumbers; bound the re-list */

/*
 * Drop every named key owned by `owner`.  Re-list from cursor zero each round
 * because deletion renumbers the owner-filtered set.  Returns the number
 * reclaimed, or -1 on a hard list failure.
 */
static int
drop_owner_keys(const char *owner)
{
	struct cryptodesc_named_list_entry entries[CRYPTODESC_NAMED_LIST_MAX];
	uint64_t generation;
	uint32_t count, next_cursor, i, reclaimed, rounds;
	int deleted_this_round;

	if (owner == NULL || owner[0] == '\0' ||
	    strnlen(owner, CRYPTODESC_KEY_OWNER_MAX) == CRYPTODESC_KEY_OWNER_MAX)
		return (0);
	reclaimed = 0;
	for (rounds = 0; rounds < CRYPTO_RECLAIM_MAX_ROUNDS; rounds++) {
		count = 0;
		next_cursor = 0;
		memset(entries, 0, sizeof(entries));
		if (cryptodesc_named_list(control_fd, owner, 0, entries,
		    CRYPTODESC_NAMED_LIST_MAX, &count, &next_cursor) != 0)
			return (-1);
		if (count == 0)
			return ((int)reclaimed);
		deleted_this_round = 0;
		for (i = 0; i < count; i++) {
			generation = 0;
			if (cryptodesc_named_delete(control_fd, entries[i].cd_name,
			    owner, &generation) == 0) {
				reclaimed++;
				deleted_this_round = 1;
			}
		}
		if (deleted_this_round == 0)
			break;
	}
	return ((int)reclaimed);
}

/* libcapreclaim enumerate: emit each distinct owner (bundle) holding keys. */
static int
crypto_enumerate(void *arg __unused,
    void (*emit)(void *emit_arg, const char *owner), void *emit_arg)
{
	char owners[CRYPTODESC_OWNER_LIST_MAX][CRYPTODESC_KEY_OWNER_MAX];
	uint32_t cursor, count, next_cursor, i;

	cursor = 0;
	do {
		if (cryptodesc_owner_list(control_fd, cursor, owners,
		    CRYPTODESC_OWNER_LIST_MAX, &count, &next_cursor) != 0)
			return (-1);
		for (i = 0; i < count; i++)
			emit(emit_arg, owners[i]);
		cursor = next_cursor;
	} while (next_cursor != 0);
	return (0);
}

/* libcapreclaim destroy: drop a gone bundle's keys. */
static int
crypto_destroy(void *arg __unused, const char *owner)
{
	int n;

	n = drop_owner_keys(owner);
	CRYPTO_PROBE_RECLAIM_DROP(owner, n, n < 0 ? errno : 0);
	if (n > 0)
		logcmp_log(LOG_NOTICE,
		    "reclaim: dropped %d key(s) for uninstalled bundle %s", n,
		    owner);
	else if (n < 0)
		logcmp_log(LOG_WARNING,
		    "reclaim: dropping keys for uninstalled bundle %s: %m", owner);
	return (n < 0 ? -1 : 0);
}

/*
 * The reconcile loop.  Runs in a forked child that holds only the retained
 * control descriptor and the switchboard-delivered install-directory
 * descriptors (manifest directories = [...]) and never accepts client input.
 * The provider is born in capability mode, so the install roots are read via
 * those delivered descriptors -- a path open would fail ECAPMODE and silently
 * disable reclaim.  Reaps immediately on the first settled boot pass and
 * seen-gone-twice thereafter; System/ existing is the readiness gate, so a
 * missing/undelivered install root reaps nothing.
 */
static void __dead2
crypto_reaper_loop(void)
{
	struct capreclaim r = CAPRECLAIM_INIT;
	struct capreclaim_stats stats;
	enum capreclaim_when when = CAPRECLAIM_BOOT;
	unsigned nap;
	int sys_fd, apps_fd, run_fd;

	setproctitle("[CRYPTO] capability component [reclaim]");
	r.enumerate = crypto_enumerate;
	r.destroy = crypto_destroy;
	r.stats = &stats;
	r.status_dirfd = capreclaim_status_dir();	/* -1 if unavailable: no record */
	r.status_name = "Crypto";
	if (service_resource_dir(CRYPTO_SYSTEM_DIR, &sys_fd) == -1)
		sys_fd = -1;
	if (service_resource_dir(CRYPTO_APPS_DIR, &apps_fd) == -1)
		apps_fd = -1;
	if (service_resource_dir(CRYPTO_RUN_LIVE_DIR, &run_fd) == -1)
		run_fd = -1;
	for (;;) {
		if (sys_fd != -1) {
			int n;

			r.sources[0].fd = sys_fd;
			r.sources[0].strip_cap = true;
			r.sources[1].fd = apps_fd;	/* -1 if absent: skipped */
			r.sources[1].strip_cap = true;
			r.sources[2].fd = run_fd;	/* Run/live/<bundle>: running */
			r.sources[2].strip_cap = false;
			r.nsources = 3;
			n = capreclaim_run(&r, when);
			CRYPTO_PROBE_RECLAIM_PASS((int)when, stats.nlive,
			    stats.nowned, stats.norphans, stats.ndestroyed,
			    stats.nfailed);
			if (n == -1)
				logcmp_log(LOG_WARNING,
				    "reclaim: %s pass failed: %m",
				    when == CAPRECLAIM_BOOT ? "boot" : "timer");
			else if (n > 0 || stats.nfailed > 0)
				logcmp_log(LOG_NOTICE,
				    "reclaim: %s pass dropped keys of %d bundle%s "
				    "(%u live, %u owned, %u orphaned, %u failed)",
				    when == CAPRECLAIM_BOOT ? "boot" : "timer",
				    n, n == 1 ? "" : "s", stats.nlive, stats.nowned,
				    stats.norphans, stats.nfailed);
			/* A floored pass saw nothing: the boot pass is still owed. */
			if (n >= 0 && !stats.floored)
				when = CAPRECLAIM_TIMER;
		}
		nap = (when == CAPRECLAIM_BOOT) ? CRYPTO_RECLAIM_POLL :
		    reclaim_interval();
		(void)sleep(nap);
	}
}

/*
 * Fork the key-reclaim child.  Called after the control descriptor is retained
 * and hardened, so the child inherits control_fd along with the delivered
 * install-directory descriptors.  Non-fatal: a fork failure just defers
 * cleanup.
 */
static int
start_reaper(void)
{
	pid_t pid;
	int pd;

	pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON | PD_NOWAITPID);
	if (pid == -1) {
		logcmp_log(LOG_WARNING, "reclaim: pdfork: %m");
		return (-1);
	}
	if (pid == 0) {
		(void)signal(SIGCHLD, SIG_DFL);
		crypto_reaper_loop();
		/* NOTREACHED */
	}
	return (pd);
}

static int
worker(int fd, const char *owner, const char *actor)
{
	struct auditcmp_client *audit;
	int result;

	setproctitle("-BSDCrypto: %s", actor);
	audit = NULL;
	if (auditcmp_client_open(&audit) == -1 ||
	    harden_control_descriptor(true) == -1) {
		auditcmp_client_close(audit);
		return (1);
	}
	if (service_worker_enter_capability_mode(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOFDRECV |
	    SERVICE_PROTECT_NOEXEC | SERVICE_PROTECT_NOSOCK) == -1) {
		auditcmp_client_close(audit);
		return (1);
	}
	result = serve_session(fd, owner, actor, audit);
	auditcmp_client_close(audit);
	return (result);
}

static int
start_session(int fd, const char *peer_label, const char *actor, int *pdp)
{
	int pd;
	pid_t pid;
	char owner[CRYPTODESC_KEY_OWNER_MAX];

	/*
	 * `owner` is the connecting unit's bundle (the reclaim key); it may be
	 * empty for a client with no bundle (e.g. a session), which then holds no
	 * named keys -- the named-key ops reject an empty owner on their own.  An
	 * over-length owner is malformed.
	 */
	if (strnlen(peer_label, sizeof(owner)) == sizeof(owner))
		return (errno = EINVAL, -1);
	strlcpy(owner, peer_label, sizeof(owner));
	/*
	 * pdfork (not fork): the parent watches the returned process descriptor on
	 * its kqueue so it can bound the live-worker count.  A pdfork'd worker is
	 * reaped via pdwait on that descriptor, not SIGCHLD, so it does not depend
	 * on SIGCHLD disposition.  The reclaim child also uses a procdesc.
	 */
	pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON | PD_NOWAITPID);
	if (pid == -1)
		return (-1);
	if (pid == 0)
		_exit(worker(fd, owner, actor));
	*pdp = pd;
	return (0);
}

#define	CRYPTOCMP_MAX_WORKERS	4096u

struct crypto_worker_ent {
	struct service_process process; /* First: shared teardown owns this node. */
	char label[64];
};

#define	CRYPTO_MAX_LABEL_WORKERS	64u

/* The caller serializes admission and removal using authenticated labels. */
static bool
crypto_worker_admit(const struct service_process *workers, const char *label)
{
	unsigned same = 0;

	for (; workers != NULL; workers = workers->next)
		if (strcmp(((const struct crypto_worker_ent *)workers)->label, label) == 0 &&
		    ++same >= CRYPTO_MAX_LABEL_WORKERS)
			return (false);
	return (true);
}


static void
crypto_worker_remove(struct service_process **head,
    struct service_process *w, size_t *count)
{
	struct service_process **cursor;
	int status;

	for (cursor = head; *cursor != NULL && *cursor != w;
	    cursor = &(*cursor)->next)
		;
	if (*cursor == w)
		*cursor = w->next;
	(void)pdwait(w->pd, &status, WEXITED | WNOHANG, NULL, NULL);
	(void)close(w->pd);
	free(w);
	if (*count != 0)
		(*count)--;
}

/* Stop admission workers before acknowledging provider shutdown. */
static int
crypto_workers_stop(struct service_process **head, size_t *count)
{
	int result;

	result = service_processes_stop(head);
	*count = 0;
	return (result);
}

/* Distinct startup exit codes make pre-readiness failures diagnosable in
 * switchboard's service-exit log, even before the logging provider is reachable. */
#define STARTUP_CHECK(test, code) do { if ((test) == -1) { \
    logcmp_log(LOG_ERR, "startup step %d failed: %m", code); \
    result = (code); goto out; } } while (0)

int
main(void)
{
	struct service_process *workers = NULL, *reaper = NULL, *w;
	struct service_context *ctx = NULL;
	struct service_identity id;
	struct service_listener *listener;
	struct service_provider *provider = NULL;
	struct kevent event, change;
	char bundle[CRYPTODESC_KEY_OWNER_MAX];
	size_t nworkers = 0, nreapers = 0;
	int fd, kq = -1, result = 1;

	setproctitle("[CRYPTO] capability component");
	openlog("bsdcrypto", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	/* Session and reclaim children are explicitly reaped through procdescs. */

	/*
	 * /dev/crypto is provided either by a static `device cryptodev` compiled
	 * into the trusted kernel (the 5BSD default -- see sys/amd64/conf/GENERIC) or
	 * by the loadable cryptodev.ko module.  Ask bsdextension (system.SystemExtension)
	 * to load the module by name -- [CRYPTO] self-serves it rather than relying
	 * on PID 1 or switchboard -- but treat that as BEST-EFFORT: a built-in
	 * cryptodev is not a loadable file, so the load reports ENOENT (not the
	 * EEXIST that an already-loaded module reports) even though /dev/crypto is
	 * present and usable.  The openat("crypto") + STARTUP_CHECK(control_fd)
	 * below is the real, authoritative test of whether the device is usable, so
	 * a failed ensure must not by itself abort startup (which would loop the
	 * provider until switchboard's circuit breaker disabled it).  Done before
	 * becoming a provider and entering capability mode.
	 */
	STARTUP_CHECK(service_acquire(&ctx), 10);
	if (service_ensure_extension(ctx, "cryptodev") == -1)
		logcmp_log(LOG_NOTICE, "ensure cryptodev module: %m; continuing "
		    "(cryptodev may be built into the kernel)");
	service_release(ctx);
	ctx = NULL;

	/*
	 * Born in capability mode: switchboard delivered /dev as a directory
	 * descriptor (manifest directories = ["/dev"]); open the control node
	 * beneath it with openat(2) rather than a global path.
	 */
	{
		int devdir;

		STARTUP_CHECK(service_resource_dir("/dev", &devdir), 12);
		control_fd = openat(devdir, "crypto", O_RDWR);
	}
	/*
	 * Self-harden the long-lived accept/fork parent.  It must still pdfork
	 * workers and receive connection descriptors, so NOFORK/NOFDRECV are not
	 * applied; NOPRIVS is safe because the /dev/crypto control descriptor is
	 * already open (mirrors bsdnetwork's parent protect mask).
	 */
	STARTUP_CHECK(control_fd, 13);
	STARTUP_CHECK(harden_control_descriptor(false), 14);
	/*
	 * Start the key-reclaim child now: control_fd is retained and hardened
	 * (its ioctl allow-list includes owner/named list + delete), so the child
	 * inherits it along with the switchboard-delivered install directories.
	 */
	reaper = calloc(1, sizeof(*reaper));
	if (reaper != NULL) {
		reaper->pd = start_reaper();
		if (reaper->pd == -1) {
			free(reaper);
			reaper = NULL;
		} else
			nreapers = 1;
	} else
		logcmp_log(LOG_WARNING, "reclaim: allocate tracker: %m");
	STARTUP_CHECK(service_provider_create(&provider), 16);
	STARTUP_CHECK(service_provider_authorize_capabilities(provider), 17);
	STARTUP_CHECK(service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOEXEC), 18);
	STARTUP_CHECK(service_provider_expose(provider, CRYPTOCMP_NAME, &listener), 19);
	/*
	 * A kqueue drives the accept loop AND watches each worker's process
	 * descriptor so the live-worker count stays bounded (CRYPTOCMP_MAX_WORKERS):
	 * a client cannot fork-bomb the broker by churning connections.
	 */
	kq = kqueuex(KQUEUE_CLOEXEC);
	STARTUP_CHECK(kq, 22);
	EV_SET(&change, service_listener_fd(listener), EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, listener);
	STARTUP_CHECK(kevent(kq, &change, 1, NULL, 0, NULL), 23);
	STARTUP_CHECK(service_provider_enter_capability_mode(provider), 20);
	STARTUP_CHECK(service_provider_ready(provider), 21);

	for (;;) {
		if (kevent(kq, NULL, 0, &event, 1, NULL) == -1) {
			if (errno == EINTR)
				continue;
			goto out;
		}
		if (event.filter == EVFILT_PROCDESC) {
			crypto_worker_remove(&workers, event.udata, &nworkers);
			continue;
		}
		memset(&id, 0, sizeof(id));
		id.size = sizeof(id);
		if (service_listener_accept(listener, &id, &fd) == -1) {
			if (errno == EINTR)
				continue;
			if (service_provider_quiescing(provider) == 1) {
				if (nworkers != 0) {
					if (service_provider_quiesce_complete(provider,
					    EBUSY) == 0)
						continue;
					if (errno != EINVAL)
						goto out;
				}
				result = 0;
			}
			goto out;
		}
		if (nworkers >= CRYPTOCMP_MAX_WORKERS ||
		    !crypto_worker_admit(workers, id.client_label)) {
			logcmp_log(LOG_WARNING, "worker limit reached; dropping %s",
			    id.client_label);
			close(fd);
			continue;
		}
		bundle_of(id.container, bundle, sizeof(bundle));
		w = calloc(1, sizeof(struct crypto_worker_ent));
		if (w == NULL || start_session(fd, bundle, id.client_label,
		    &w->pd) == -1) {
			logcmp_log(LOG_WARNING, "session for %s rejected: %m",
			    id.client_label);
			free(w);
			close(fd);
			continue;
		}
		close(fd);
		EV_SET(&change, w->pd, EVFILT_PROCDESC, EV_ADD | EV_ENABLE,
		    NOTE_EXIT, 0, w);
		if (service_harden_fd(w->pd, 0) == -1 ||
		    kevent(kq, &change, 1, NULL, 0, NULL) == -1) {
			int status;

			/*
			 * Cannot watch it.  The child is running under a
			 * PD_DAEMON descriptor, so close(pd) alone would NOT kill
			 * it -- it would keep serving its client as an unwatched,
			 * unreapable orphan holding privileged state.  KILL it,
			 * reap it, then drop our handle.  It is not on the list
			 * yet and was never counted (nworkers++ is below), so do
			 * not touch nworkers (crypto_worker_remove would, and
			 * would also fail to kill a live PD_DAEMON child).
			 */
			logcmp_log(LOG_WARNING, "procdesc watch for %s: %m",
			    id.client_label);
			(void)pdkill(w->pd, SIGKILL);
			while (pdwait(w->pd, &status, WEXITED, NULL, NULL) == -1 &&
			    errno == EINTR)
				;
			(void)close(w->pd);
			free(w);
			continue;
		}
		strlcpy(((struct crypto_worker_ent *)w)->label,
		    id.client_label, sizeof(((struct crypto_worker_ent *)w)->label));
		w->next = workers;
		workers = w;
		nworkers++;
	}
out:
	if (crypto_workers_stop(&workers, &nworkers) == -1 && result == 0)
		result = 1;
	if (crypto_workers_stop(&reaper, &nreapers) == -1 && result == 0)
		result = 1;
	if (kq != -1)
		close(kq);
	if (control_fd != -1) {
		close(control_fd);
		control_fd = -1;
	}
	if (ctx != NULL)
		service_release(ctx);
	if (result == 0 && service_provider_quiesce_complete(provider, 0) == -1)
		result = 1;
	if (provider != NULL)
		service_provider_destroy(provider);
	return (result);
}
#endif /* !BSDCRYPTO_TESTING */
