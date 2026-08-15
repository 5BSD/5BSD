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
	const struct { struct cryptocmp_msg msg; struct cryptocmp_generate generate; } *in;
	struct cryptocmp_msg out;
	struct session2_op session;
	unsigned char key[64], mackey[64];
	int fd, error;

	fd = -1;
	error = EPROTO;
	in = channel_message_data(m);
	memset(&out, 0, sizeof(out));
	if (channel_message_length(m) == sizeof(*in) &&
	    channel_message_fd_count(m) == 0 &&
	    in->msg.magic == CRYPTOCMP_MAGIC &&
	    in->msg.version == CRYPTOCMP_VERSION &&
	    in->msg.opcode == CRYPTOCMP_OP_GENERATE &&
	    in->generate.keylen <= sizeof(key) &&
	    in->generate.mackeylen <= sizeof(mackey) &&
	    cryptocmp_policy_validate(&in->generate) == 0) {
		if (in->generate.keylen != 0)
			arc4random_buf(key, in->generate.keylen);
		if (in->generate.mackeylen != 0)
			arc4random_buf(mackey, in->generate.mackeylen);
		memset(&session, 0, sizeof(session));
		session.cipher = in->generate.cipher;
		session.mac = in->generate.mac;
		session.keylen = in->generate.keylen;
		session.key = in->generate.keylen == 0 ? NULL : key;
		session.mackeylen = in->generate.mackeylen;
		session.mackey = in->generate.mackeylen == 0 ? NULL : mackey;
		session.crid = in->generate.crid;
		session.ivlen = in->generate.ivlen;
		session.maclen = in->generate.maclen;
		if (cryptodesc_mint(control_fd, &session, in->generate.rights,
		    &fd) == 0)
			error = 0;
		else
			error = errno;
	}
	explicit_bzero(key, sizeof(key));
	explicit_bzero(mackey, sizeof(mackey));
	out.magic = CRYPTOCMP_MAGIC;
	out.version = CRYPTOCMP_VERSION;
	out.opcode = CRYPTOCMP_OP_GENERATE;
	out.status = error == 0 ? 0 : -error;
	(void)channel_send_reply(m, &(struct channel_outgoing){
	    .size = sizeof(struct channel_outgoing), .data = &out,
	    .length = sizeof(out), .fds = error == 0 ? &fd : NULL,
	    .nfds = error == 0 ? 1 : 0 });
	if (fd >= 0)
		close(fd);
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
