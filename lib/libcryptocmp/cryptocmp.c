/*- SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libservice.h>
#include "cryptocmp.h"

struct cryptocmp_client { struct service_session *session; pid_t owner; };
int
cryptocmp_open(struct cryptocmp_client **out)
{
	struct service_context *context; struct cryptocmp_client *client; int fd;
	if (out == NULL) return (errno = EINVAL, -1);
	*out = NULL;
	if ((client = calloc(1, sizeof(*client))) == NULL || service_acquire(&context) == -1)
		goto fail;
	if (service_local_component_open(context, CRYPTOCMP_INTERFACE, CRYPTOCMP_INTERFACE_VERSION, &fd) == -1) { service_release(context); goto fail; }
	service_release(context);
	if (service_session_create(fd, &client->session) == -1) { close(fd); goto fail; }
	client->owner = getpid(); *out = client; return (0);
fail: free(client); return (-1);
}
void
cryptocmp_close(struct cryptocmp_client *client)
{ if (client != NULL) { service_session_close(client->session); free(client); } }
int
cryptocmp_generate(struct cryptocmp_client *client, const struct cryptocmp_generate *request, int *descriptor)
{
	struct { struct cryptocmp_msg msg; struct cryptocmp_generate generate; } wire;
	struct cryptocmp_msg reply; struct service_message outgoing; struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER; int fd = -1;
	if (client == NULL || request == NULL || descriptor == NULL || client->owner != getpid()) return (errno = EINVAL, -1);
	memset(&wire, 0, sizeof(wire)); wire.msg.magic = CRYPTOCMP_MAGIC; wire.msg.version = CRYPTOCMP_VERSION; wire.msg.opcode = CRYPTOCMP_OP_GENERATE; wire.generate = *request;
	memset(&outgoing, 0, sizeof(outgoing)); outgoing.size = sizeof(outgoing); outgoing.data = &wire; outgoing.length = sizeof(wire);
	memset(&incoming, 0, sizeof(incoming)); incoming.size = sizeof(incoming); incoming.data = &reply; incoming.capacity = sizeof(reply); incoming.fds = &fd; incoming.fd_capacity = 1; options.timeout_ms = 30000;
	if (service_session_call(client->session, &outgoing, &incoming, &options) == -1) return (-1);
	if (incoming.length != sizeof(reply) || reply.magic != CRYPTOCMP_MAGIC || reply.version != CRYPTOCMP_VERSION || reply.opcode != CRYPTOCMP_OP_GENERATE || incoming.nfds != (reply.status == 0 ? 1 : 0)) return (errno = EPROTO, -1);
	if (reply.status != 0) return (errno = -reply.status, -1);
	*descriptor = fd; return (0);
}
