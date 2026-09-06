/*- SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/procdesc.h>
#include <sys/types.h>
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
#include <channel.h>
#include <cryptodesc.h>
#include <cryptocmp_protocol.h>
#include <libservice.h>
#include <logcmp.h>

#include "policy.h"
#ifdef LOCALCRYPTO_TESTING
#include "localcrypto_test.h"
#endif

#define CRYPTOCMP_NAME "system.Crypto"
static int control_fd;
struct crypto_worker {
	char	owner[CRYPTODESC_KEY_OWNER_MAX];
	struct auditcmp_client *audit;
};

static int
harden_control_descriptor(void)
{
	static const unsigned long commands[] = {
		CIOCGCRYPTODESCGENERATE,
		CIOCGCRYPTOKEYDESC,
		CIOCGCRYPTONAMEDKEY,
		CIOCGCRYPTONAMEDLEASE,
		CIOCCRYPTONAMEDROTATE,
		CIOCCRYPTONAMEDDELETE,
		CIOCGCRYPTONAMEDSTAT,
	};
	cap_rights_t rights;

	if (cap_xfer_limit(control_fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(control_fd, CAP_CLOFORK_LOCKED) == -1 ||
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
		(void)auditcmp_submit(worker->audit, worker->owner, operation, error);
}
static void
request(struct channel *c __unused, struct channel_message *m, void *arg __unused)
{
	const struct cryptocmp_msg *in;
	const struct cryptocmp_generate *generate;
	const struct cryptocmp_key_generate *key_generate;
	const struct cryptocmp_named_create *named_create;
	const struct cryptocmp_named_lease *named_lease;
	const struct cryptocmp_named_control *named_control;
	const struct cryptocmp_named_stat *named_stat;
	const struct cryptocmp_digest *digest;
	const struct cryptocmp_random *random_request;
	struct cryptocmp_msg out;
	struct cryptocmp_key_reply key_out;
	struct cryptocmp_named_reply named_out;
	struct cryptocmp_named_stat_reply stat_out;
	struct cryptocmp_random_reply random_out;
	struct cryptodesc_named_stat stat;
	struct session2_op session;
	struct crypto_worker *worker;
	const char *operation;
	const void *reply_data;
	size_t reply_length;
	uint8_t public_key[CRYPTODESC_ED25519_PUBLIC_SIZE];
	uint64_t generation;
	uint32_t random_bytes;
	int fd, error, deliver_fd;

	fd = -1;
	error = EPROTO;
	operation = "malformed-request";
	in = channel_message_data(m);
	memset(&out, 0, sizeof(out));
	memset(&key_out, 0, sizeof(key_out));
	memset(&named_out, 0, sizeof(named_out));
	memset(&stat_out, 0, sizeof(stat_out));
	memset(&random_out, 0, sizeof(random_out));
	memset(&stat, 0, sizeof(stat));
	memset(public_key, 0, sizeof(public_key));
	generation = 0;
	random_bytes = 0;
	worker = arg;
	if (channel_message_length(m) >= sizeof(*in) &&
	    channel_message_fd_count(m) == 0 &&
	    in->magic == CRYPTOCMP_MAGIC &&
	    in->version == CRYPTOCMP_VERSION &&
	    in->opcode >= CRYPTOCMP_OP_GENERATE &&
	    in->opcode <= CRYPTOCMP_OP_NAMED_STAT) {
		out.opcode = in->opcode;
		if (in->opcode == CRYPTOCMP_OP_GENERATE &&
		    channel_message_length(m) == sizeof(*in) + sizeof(*generate)) {
			operation = "descriptor-generate";
			generate = (const struct cryptocmp_generate *)(in + 1);
			if (cryptocmp_policy_validate(generate) != 0) {
				error = errno;
				goto reply;
			}
			memset(&session, 0, sizeof(session));
			session.cipher = generate->cipher;
			session.mac = generate->mac;
			session.keylen = generate->keylen;
			session.key = NULL;
			session.mackeylen = generate->mackeylen;
			session.mackey = NULL;
			session.crid = generate->crid;
			session.ivlen = generate->ivlen;
			session.maclen = generate->maclen;
			if (cryptodesc_mint_generated(control_fd, &session,
			    generate->rights, generate->ttl, &fd) == 0)
				error = 0;
			else
				error = errno;
		} else if (in->opcode == CRYPTOCMP_OP_GENERATE_KEY &&
		    channel_message_length(m) == sizeof(*in) + sizeof(*key_generate)) {
			operation = "key-generate";
			key_generate = (const struct cryptocmp_key_generate *)(in + 1);
			if (cryptocmp_key_policy_validate(key_generate) != 0) {
				error = errno;
				goto reply;
			}
			if (cryptodesc_mint_key(control_fd, key_generate->type,
			    key_generate->rights, key_generate->ttl, public_key, &fd) == 0)
				error = 0;
			else
				error = errno;
		} else if (in->opcode == CRYPTOCMP_OP_NAMED_CREATE &&
		    channel_message_length(m) == sizeof(*in) + sizeof(*named_create)) {
			operation = "named-create";
			named_create = (const struct cryptocmp_named_create *)(in + 1);
			if (cryptocmp_named_create_policy_validate(named_create) != 0) {
				error = errno;
				goto reply;
			}
			memset(&session, 0, sizeof(session));
			session.cipher = named_create->generate.cipher;
			session.mac = named_create->generate.mac;
			session.keylen = named_create->generate.keylen;
			session.mackeylen = named_create->generate.mackeylen;
			session.crid = named_create->generate.crid;
			session.ivlen = named_create->generate.ivlen;
			session.maclen = named_create->generate.maclen;
			if (cryptodesc_named_create(control_fd, named_create->name,
			    worker->owner, &session, named_create->generate.rights,
			    &generation) == 0)
				error = 0;
			else
				error = errno;
		} else if (in->opcode == CRYPTOCMP_OP_NAMED_LEASE &&
		    channel_message_length(m) == sizeof(*in) + sizeof(*named_lease)) {
			operation = "named-lease";
			named_lease = (const struct cryptocmp_named_lease *)(in + 1);
			if (cryptocmp_named_lease_policy_validate(named_lease) != 0) {
				error = errno;
				goto reply;
			}
			if (cryptodesc_named_lease(control_fd, named_lease->name,
			    worker->owner, named_lease->rights, named_lease->ttl,
			    &generation, &fd) == 0)
				error = 0;
			else
				error = errno;
		} else if ((in->opcode == CRYPTOCMP_OP_NAMED_ROTATE ||
		    in->opcode == CRYPTOCMP_OP_NAMED_DELETE) &&
		    channel_message_length(m) == sizeof(*in) + sizeof(*named_control)) {
			operation = in->opcode == CRYPTOCMP_OP_NAMED_ROTATE ?
			    "named-rotate" : "named-delete";
			named_control = (const struct cryptocmp_named_control *)(in + 1);
			if (cryptocmp_named_control_policy_validate(named_control) != 0) {
				error = errno;
				goto reply;
			}
			if ((in->opcode == CRYPTOCMP_OP_NAMED_ROTATE ?
			    cryptodesc_named_rotate(control_fd, named_control->name,
			    worker->owner, &generation) : cryptodesc_named_delete(control_fd,
			    named_control->name, worker->owner, &generation)) == 0)
				error = 0;
			else
				error = errno;
		} else if (in->opcode == CRYPTOCMP_OP_NAMED_STAT &&
		    channel_message_length(m) == sizeof(*in) + sizeof(*named_stat)) {
			operation = "named-stat";
			named_stat = (const struct cryptocmp_named_stat *)(in + 1);
			if (cryptocmp_named_stat_policy_validate(named_stat) != 0) {
				error = errno;
				goto reply;
			}
			/*
			 * Read-only introspection: resolve the key owner-scoped
			 * on worker->owner (never a wire-supplied owner) and copy
			 * out its metadata.  No descriptor is minted and the key
			 * is not mutated; a miss is ENOENT.
			 */
			if (cryptodesc_named_stat(control_fd, named_stat->name,
			    worker->owner, &stat) == 0)
				error = 0;
			else
				error = errno;
		} else if (in->opcode == CRYPTOCMP_OP_DIGEST &&
		    channel_message_length(m) == sizeof(*in) + sizeof(*digest)) {
			operation = "digest";
			digest = (const struct cryptocmp_digest *)(in + 1);
			if (cryptocmp_digest_policy_validate(digest) != 0) {
				error = errno;
				goto reply;
			}
			/*
			 * An unkeyed hash is an ordinary DIGEST-mode session with
			 * no cipher and no MAC key.  It reuses the generated-session
			 * mint path (which randomises nothing when both key lengths
			 * are zero) and is delivered as a DTYPE_CRYPTO descriptor the
			 * client streams data through; CRYPTODESC_RIGHT_AUTH is the
			 * right the kernel requires to compute a digest.
			 */
			memset(&session, 0, sizeof(session));
			session.cipher = 0;
			session.mac = digest->alg;
			session.keylen = 0;
			session.key = NULL;
			session.mackeylen = 0;
			session.mackey = NULL;
			session.crid = 0;
			session.ivlen = 0;
			session.maclen = 0;
			if (cryptodesc_mint_generated(control_fd, &session,
			    CRYPTODESC_RIGHT_AUTH, digest->ttl, &fd) == 0)
				error = 0;
			else
				error = errno;
		} else if (in->opcode == CRYPTOCMP_OP_RANDOM &&
		    channel_message_length(m) == sizeof(*in) + sizeof(*random_request)) {
			operation = "random";
			random_request = (const struct cryptocmp_random *)(in + 1);
			if (cryptocmp_random_policy_validate(random_request) != 0) {
				error = errno;
				goto reply;
			}
			/*
			 * CSPRNG bytes are not secret-key material to confine, so
			 * they are returned inline; the reply buffer is scrubbed
			 * after the send regardless.
			 */
			random_bytes = random_request->nbytes;
			arc4random_buf(random_out.data, random_bytes);
			error = 0;
		}
	}

reply:
	out.magic = CRYPTOCMP_MAGIC;
	out.version = CRYPTOCMP_VERSION;
	out.status = error == 0 ? 0 : -error;
	key_out.msg = out;
	named_out.msg = out;
	named_out.generation = generation;
	stat_out.msg = out;
	if (error == 0 && out.opcode == CRYPTOCMP_OP_NAMED_STAT) {
		stat_out.info.generation = stat.cd_generation;
		stat_out.info.rights = stat.cd_rights;
		stat_out.info.cipher = stat.cd_cipher;
		stat_out.info.mac = stat.cd_mac;
		stat_out.info.keylen = stat.cd_keylen;
		stat_out.info.mackeylen = stat.cd_mackeylen;
	}
	random_out.msg = out;
	random_out.nbytes = error == 0 ? random_bytes : 0;
	audit_operation(worker, operation, error);
	if (out.opcode == CRYPTOCMP_OP_GENERATE_KEY)
		memcpy(key_out.public_key, public_key, sizeof(key_out.public_key));
	/*
	 * Select the reply shape by opcode: keyed-descriptor replies carry the
	 * public key, named-key replies carry the generation, a random reply
	 * carries a variable-length inline payload, and everything else (plain
	 * descriptor mints and malformed requests) uses the bare header.  A
	 * delivered descriptor accompanies only the successful mint/lease ops.
	 */
	switch (out.opcode) {
	case CRYPTOCMP_OP_GENERATE_KEY:
		reply_data = &key_out;
		reply_length = sizeof(key_out);
		break;
	case CRYPTOCMP_OP_NAMED_CREATE:
	case CRYPTOCMP_OP_NAMED_LEASE:
	case CRYPTOCMP_OP_NAMED_ROTATE:
	case CRYPTOCMP_OP_NAMED_DELETE:
		reply_data = &named_out;
		reply_length = sizeof(named_out);
		break;
	case CRYPTOCMP_OP_NAMED_STAT:
		reply_data = &stat_out;
		reply_length = sizeof(stat_out);
		break;
	case CRYPTOCMP_OP_RANDOM:
		reply_data = &random_out;
		reply_length = offsetof(struct cryptocmp_random_reply, data) +
		    (error == 0 ? random_bytes : 0);
		break;
	default:
		reply_data = &out;
		reply_length = sizeof(out);
		break;
	}
	deliver_fd = error == 0 && (out.opcode == CRYPTOCMP_OP_GENERATE ||
	    out.opcode == CRYPTOCMP_OP_GENERATE_KEY ||
	    out.opcode == CRYPTOCMP_OP_NAMED_LEASE ||
	    out.opcode == CRYPTOCMP_OP_DIGEST) ? 1 : 0;
	(void)channel_send_reply(m, &(struct channel_outgoing){
	    .size = sizeof(struct channel_outgoing),
	    .data = reply_data,
	    .length = reply_length,
	    .fds = deliver_fd != 0 ? &fd : NULL,
	    .nfds = deliver_fd });
	if (fd >= 0)
		close(fd);
	explicit_bzero(public_key, sizeof(public_key));
	explicit_bzero(&key_out, sizeof(key_out));
	explicit_bzero(&named_out, sizeof(named_out));
	explicit_bzero(&stat_out, sizeof(stat_out));
	explicit_bzero(&random_out, sizeof(random_out));
	channel_message_free(m);
}

/*
 * The owner-scoped request/channel core.  The immutable owner label (bound to
 * the unforgeable channel peer identity by the caller) is threaded into every
 * named-key operation via crypto_worker::owner, so a session can only reach the
 * keys minted under its own label.  Both the production worker and the test
 * entrypoint drive this same path; only the surrounding sandbox setup differs.
 */
static int
serve_session(int fd, const char *owner, struct auditcmp_client *audit)
{
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct crypto_worker state;
	struct channel *channel;
	int ready, result, wants_write;

	memset(&state, 0, sizeof(state));
	strlcpy(state.owner, owner, sizeof(state.owner));
	state.audit = audit;
	channel = NULL;
	result = 1;
	if (channel_create(fd, &options, &channel) == -1)
		goto out;
	if (channel_set_request_handler(channel, request, &state) == -1) {
		goto out;
	}
	/*
	 * A provider-side fault (wait/flush failure) is a meaningful error and is
	 * reflected in the exit status; a read/dispatch break is the ordinary case
	 * of the client disconnecting and terminates the worker cleanly.
	 */
	result = 0;
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1) {
			result = 1;
			break;
		}
		ready = channel_wait(channel, wants_write, -1);
		if (ready == -1) {
			result = 1;
			break;
		}
		if ((ready & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(channel) == -1) {
			result = 1;
			break;
		}
		if ((ready & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(channel) == -1)
			break;
	}
out:
	if (channel != NULL)
		channel_destroy(channel);
	return (result);
}

#ifdef LOCALCRYPTO_TESTING
/*
 * Test entrypoint: run the real owner-scoped serve path against a caller-owned
 * channel descriptor with a caller-supplied owner label.  It opens and hardens
 * the /dev/crypto control descriptor exactly as production does but omits the
 * serviced-only sandbox wrappers (worker protect/authority-drop/cap_enter) and
 * the audit client, which require a live plane.  Named-key ownership is enforced
 * by the kernel key store keyed on (name, owner), so this exercises the true
 * isolation property.
 */
int
localcrypto_test_serve(int fd, const char *owner_label)
{

	if (fd < 0 || owner_label == NULL ||
	    strnlen(owner_label, CRYPTODESC_KEY_OWNER_MAX) == 0 ||
	    strnlen(owner_label, CRYPTODESC_KEY_OWNER_MAX) ==
	    CRYPTODESC_KEY_OWNER_MAX)
		return (errno = EINVAL, -1);
	control_fd = open("/dev/crypto", O_RDWR);
	if (control_fd < 0)
		return (-1);
	if (harden_control_descriptor() == -1)
		return (1);
	return (serve_session(fd, owner_label, NULL));
}
#endif /* LOCALCRYPTO_TESTING */

#ifndef LOCALCRYPTO_TESTING
static int
worker(int fd, int audit_fd, const char *owner)
{
	struct auditcmp_client *audit;
	int result;

	audit = NULL;
	if (auditcmp_client_adopt(audit_fd, &audit) == -1 ||
	    harden_control_descriptor() == -1) {
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
	result = serve_session(fd, owner, audit);
	auditcmp_client_close(audit);
	return (result);
}

static int
start_session(int fd, const char *peer_label)
{
	int audit_fd, pd;
	pid_t pid;
	char owner[CRYPTODESC_KEY_OWNER_MAX];

	audit_fd = -1;
	if (strnlen(peer_label, sizeof(owner)) == 0 ||
	    strnlen(peer_label, sizeof(owner)) == sizeof(owner))
		return (errno = EINVAL, -1);
	strlcpy(owner, peer_label, sizeof(owner));
	if (auditcmp_client_prepare(&audit_fd) == -1)
		return (-1);
	pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
	if (pid == -1) {
		close(audit_fd);
		return (-1);
	}
	if (pid == 0)
		_exit(worker(fd, audit_fd, owner));
	close(audit_fd);
	close(pd);
	return (0);
}

int
main(void)
{
	struct service_context *ctx = NULL;
	struct service_identity id;
	struct service_listener *listener;
	struct service_provider *provider;
	int fd;

	setproctitle("[CRYPTO] capability component");
	openlog("localcrypto", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	/*
	 * /dev/crypto is provided by the cryptodev module.  Ensure it is loaded
	 * before opening the control device: sysextd owns kernel-module loading
	 * (system.SystemExtension), so [CRYPTO] self-serves the module by name
	 * rather than relying on PID 1 or serviced to load it.  This is done
	 * before becoming a provider and entering capability mode.
	 */
	if (service_acquire(&ctx) == -1 ||
	    service_ensure_extension(ctx, "cryptodev") == -1)
		return (1);
	service_release(ctx);

	/*
	 * Born in capability mode: serviced delivered /dev as a directory
	 * descriptor (manifest directories = ["/dev"]); open the control node
	 * beneath it with openat(2) rather than a global path.
	 */
	{
		int devdir;

		if (service_resource_dir("/dev", &devdir) == -1)
			return (1);
		control_fd = openat(devdir, "crypto", O_RDWR);
	}
	/*
	 * Self-harden the long-lived accept/fork parent.  It must still pdfork
	 * workers and receive connection descriptors, so NOFORK/NOFDRECV are not
	 * applied; NOPRIVS is safe because the /dev/crypto control descriptor is
	 * already open (mirrors localnetwork's parent protect mask).
	 */
	if (control_fd < 0 || service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_provider_expose(provider, CRYPTOCMP_NAME, &listener) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		return (1);
	for (;;) {
		memset(&id, 0, sizeof(id));
		id.size = sizeof(id);
		if (service_listener_accept(listener, &id, &fd) == -1)
			return (1);
		if (start_session(fd, id.client_label) == -1)
			logcmp_log(LOG_WARNING, "session for %s rejected: %m",
			    id.client_label);
		close(fd);
	}
}
#endif /* !LOCALCRYPTO_TESTING */
