/*- SPDX-License-Identifier: BSD-2-Clause */
#include <sys/capsicum.h>
#include <sys/procdesc.h>
#include <sys/types.h>
#include <sys/cryptodesc.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <channel.h>
#include <cryptodesc.h>
#include <cryptocmp_protocol.h>
#include <libservice.h>

#include "policy.h"

#define CRYPTOCMP_NAME "org.5bsd.CryptoCmp"
static int control_fd;
struct crypto_worker { int terminal_error; };
static void
request(struct channel *c __unused, struct channel_message *m, void *arg __unused)
{
	const struct cryptocmp_msg *in;
	const struct cryptocmp_generate *generate;
	const struct cryptocmp_key_generate *key_generate;
	struct cryptocmp_msg out;
	struct cryptocmp_key_reply key_out;
	struct session2_op session;
	uint8_t public_key[CRYPTODESC_ED25519_PUBLIC_SIZE];
	int fd, error;

	fd = -1;
	error = EPROTO;
	in = channel_message_data(m);
	memset(&out, 0, sizeof(out));
	memset(&key_out, 0, sizeof(key_out));
	memset(public_key, 0, sizeof(public_key));
	if (channel_message_length(m) >= sizeof(*in) &&
	    channel_message_fd_count(m) == 0 &&
	    in->magic == CRYPTOCMP_MAGIC &&
	    in->version == CRYPTOCMP_VERSION &&
	    (in->opcode == CRYPTOCMP_OP_GENERATE ||
	    in->opcode == CRYPTOCMP_OP_GENERATE_KEY)) {
		out.opcode = in->opcode;
		if (in->opcode == CRYPTOCMP_OP_GENERATE &&
		    channel_message_length(m) == sizeof(*in) + sizeof(*generate)) {
			generate = (const struct cryptocmp_generate *)(in + 1);
			if (cryptocmp_policy_validate(generate) != 0)
				goto reply;
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
			key_generate = (const struct cryptocmp_key_generate *)(in + 1);
			if (cryptocmp_key_policy_validate(key_generate) != 0)
				goto reply;
			if (cryptodesc_mint_key(control_fd, key_generate->type,
			    key_generate->rights, key_generate->ttl, public_key, &fd) == 0)
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
	if (out.opcode == CRYPTOCMP_OP_GENERATE_KEY)
		memcpy(key_out.public_key, public_key, sizeof(key_out.public_key));
	(void)channel_send_reply(m, &(struct channel_outgoing){
	    .size = sizeof(struct channel_outgoing),
	    .data = out.opcode == CRYPTOCMP_OP_GENERATE_KEY ?
	    (const void *)&key_out : (const void *)&out,
	    .length = out.opcode == CRYPTOCMP_OP_GENERATE_KEY ?
	    sizeof(key_out) : sizeof(out), .fds = error == 0 ? &fd : NULL,
	    .nfds = error == 0 ? 1 : 0 });
	if (fd >= 0)
		close(fd);
	explicit_bzero(public_key, sizeof(public_key));
	explicit_bzero(&key_out, sizeof(key_out));
	channel_message_free(m);
}

static int
worker(int fd)
{
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct crypto_worker state;
	struct channel *channel;
	int ready, wants_write;

	memset(&state, 0, sizeof(state));
	if (service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOFDRECV |
	    SERVICE_PROTECT_NOEXEC | SERVICE_PROTECT_NOSOCK) == -1)
		return (1);
	service_worker_drop_inherited_authority();
	if (cap_enter() == -1 || channel_create(fd, &options, &channel) == -1)
		return (1);
	if (channel_set_request_handler(channel, request, &state) == -1) {
		channel_destroy(channel);
		return (1);
	}
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1 || (ready = channel_wait(channel,
		    wants_write, -1)) == -1 ||
		    ((ready & CHANNEL_WAIT_WRITE) != 0 && channel_flush(channel) == -1) ||
		    ((ready & CHANNEL_WAIT_READ) != 0 && channel_dispatch(channel) == -1))
			break;
	}
	channel_destroy(channel);
	return (0);
}

static int
start_session(int fd)
{
	struct service_component_bootstrap *boot;
	int pd;
	pid_t pid;

	boot = NULL;
	if (service_component_accept(fd, &boot) == -1)
		return (-1);
	if (strcmp(service_component_interface(boot), CRYPTOCMP_INTERFACE) != 0 ||
	    strcmp(service_component_interface_version(boot),
	    CRYPTOCMP_INTERFACE_VERSION) != 0 ||
	    service_component_resource_count(boot) != 0) {
		(void)service_component_fail(boot, EPROTO);
		return (-1);
	}
	pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
	if (pid == -1) {
		(void)service_component_fail(boot, errno);
		return (-1);
	}
	if (pid == 0)
		_exit(worker(fd));
	if (service_component_complete(boot, SERVICE_COMPONENT_MEMBER_PROCDESC,
	    pd) == -1) {
		(void)pdkill(pd, SIGKILL);
		close(pd);
		return (-1);
	}
	close(pd);
	return (0);
}
int
main(void)
{
	struct service_provider *p; struct service_listener *l; struct service_identity id; int fd;

	setproctitle("[CRYPTO] capability component");
	control_fd = open("/dev/crypto", O_RDWR); if (control_fd < 0 || service_provider_create(&p) == -1 || service_provider_authorize_capabilities(p) == -1 || service_provider_expose(p, CRYPTOCMP_NAME, &l) == -1 || service_provider_enter_capability_mode(p) == -1 || service_provider_ready(p) == -1) return (1);
	for (;;) { memset(&id,0,sizeof(id)); id.size=sizeof(id); if (service_listener_accept(l,&id,&fd)==-1) return (1); (void)start_session(fd); close(fd); }
}
