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
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <channel.h>
#include <cryptodesc.h>
#include <cryptocmp_protocol.h>
#include <libservice.h>

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
	struct cryptocmp_msg out;
	struct cryptocmp_key_reply key_out;
	struct cryptocmp_named_reply named_out;
	struct session2_op session;
	struct crypto_worker *worker;
	const char *operation;
	uint8_t public_key[CRYPTODESC_ED25519_PUBLIC_SIZE];
	uint64_t generation;
	int fd, error;

	fd = -1;
	error = EPROTO;
	operation = "malformed-request";
	in = channel_message_data(m);
	memset(&out, 0, sizeof(out));
	memset(&key_out, 0, sizeof(key_out));
	memset(&named_out, 0, sizeof(named_out));
	memset(public_key, 0, sizeof(public_key));
	generation = 0;
	worker = arg;
	if (channel_message_length(m) >= sizeof(*in) &&
	    channel_message_fd_count(m) == 0 &&
	    in->magic == CRYPTOCMP_MAGIC &&
	    in->version == CRYPTOCMP_VERSION &&
	    in->opcode >= CRYPTOCMP_OP_GENERATE &&
	    in->opcode <= CRYPTOCMP_OP_NAMED_DELETE) {
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
		}
	}

reply:
	out.magic = CRYPTOCMP_MAGIC;
	out.version = CRYPTOCMP_VERSION;
	out.status = error == 0 ? 0 : -error;
	key_out.msg = out;
	named_out.msg = out;
	named_out.generation = generation;
	audit_operation(worker, operation, error);
	if (out.opcode == CRYPTOCMP_OP_GENERATE_KEY)
		memcpy(key_out.public_key, public_key, sizeof(key_out.public_key));
	(void)channel_send_reply(m, &(struct channel_outgoing){
	    .size = sizeof(struct channel_outgoing),
	    .data = out.opcode == CRYPTOCMP_OP_GENERATE_KEY ? (const void *)&key_out :
	    out.opcode >= CRYPTOCMP_OP_NAMED_CREATE ? (const void *)&named_out :
	    (const void *)&out,
	    .length = out.opcode == CRYPTOCMP_OP_GENERATE_KEY ? sizeof(key_out) :
	    out.opcode >= CRYPTOCMP_OP_NAMED_CREATE ? sizeof(named_out) : sizeof(out),
	    .fds = error == 0 && (out.opcode == CRYPTOCMP_OP_GENERATE ||
	    out.opcode == CRYPTOCMP_OP_GENERATE_KEY ||
	    out.opcode == CRYPTOCMP_OP_NAMED_LEASE) ? &fd : NULL,
	    .nfds = error == 0 && (out.opcode == CRYPTOCMP_OP_GENERATE ||
	    out.opcode == CRYPTOCMP_OP_GENERATE_KEY ||
	    out.opcode == CRYPTOCMP_OP_NAMED_LEASE) ? 1 : 0 });
	if (fd >= 0)
		close(fd);
	explicit_bzero(public_key, sizeof(public_key));
	explicit_bzero(&key_out, sizeof(key_out));
	explicit_bzero(&named_out, sizeof(named_out));
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
	if (service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOFDRECV |
	    SERVICE_PROTECT_NOEXEC | SERVICE_PROTECT_NOSOCK) == -1) {
		auditcmp_client_close(audit);
		return (1);
	}
	service_worker_drop_inherited_authority();
	if (cap_enter() == -1) {
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

	control_fd = open("/dev/crypto", O_RDWR);
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
			syslog(LOG_WARNING, "session for %s rejected: %m",
			    id.client_label);
		close(fd);
	}
}
#endif /* !LOCALCRYPTO_TESTING */
