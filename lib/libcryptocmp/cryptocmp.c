/*- SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <crypto/cryptodev.h>
#include <libservice.h>
#include "cryptocmp.h"

struct cryptocmp_client { struct service_session *session; pid_t owner; };

static bool
valid_status(int32_t status)
{

	return (status <= 0 && status >= -ELAST);
}

static int
reject_reply(int fd)
{

	if (fd >= 0)
		(void)close(fd);
	errno = EPROTO;
	return (-1);
}
int
cryptocmp_open(struct cryptocmp_client **out)
{
	struct cryptocmp_client *client; int fd;
	if (out == NULL) return (errno = EINVAL, -1);
	*out = NULL;
	if ((client = calloc(1, sizeof(*client))) == NULL)
		goto fail;
	if (service_open(CRYPTOCMP_INTERFACE, &fd) == -1) goto fail;
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
	*descriptor = -1;
	memset(&wire, 0, sizeof(wire)); wire.msg.magic = CRYPTOCMP_MAGIC; wire.msg.version = CRYPTOCMP_VERSION; wire.msg.opcode = CRYPTOCMP_OP_GENERATE; wire.generate = *request;
	memset(&outgoing, 0, sizeof(outgoing)); outgoing.size = sizeof(outgoing); outgoing.data = &wire; outgoing.length = sizeof(wire);
	memset(&incoming, 0, sizeof(incoming)); incoming.size = sizeof(incoming); incoming.data = &reply; incoming.capacity = sizeof(reply); incoming.fds = &fd; incoming.fd_capacity = 1; options.timeout_ms = 30000;
	if (service_session_call(client->session, &outgoing, &incoming, &options) == -1) return (-1);
	if (incoming.length != sizeof(reply) || reply.magic != CRYPTOCMP_MAGIC || reply.version != CRYPTOCMP_VERSION || reply.opcode != CRYPTOCMP_OP_GENERATE || !valid_status(reply.status) || incoming.nfds != (reply.status == 0 ? 1 : 0)) return (reject_reply(incoming.nfds != 0 ? fd : -1));
	if (reply.status != 0) return (errno = -reply.status, -1);
	*descriptor = fd; return (0);
}

int
cryptocmp_generate_key(struct cryptocmp_client *client,
    const struct cryptocmp_key_generate *request, uint8_t public_key[32],
    int *descriptor)
{
	struct { struct cryptocmp_msg msg; struct cryptocmp_key_generate key; } wire;
	struct cryptocmp_key_reply reply;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	int fd = -1;

	if (client == NULL || request == NULL || public_key == NULL ||
	    descriptor == NULL || client->owner != getpid())
		return (errno = EINVAL, -1);
	*descriptor = -1;
	memset(public_key, 0, 32);
	memset(&wire, 0, sizeof(wire));
	wire.msg.magic = CRYPTOCMP_MAGIC;
	wire.msg.version = CRYPTOCMP_VERSION;
	wire.msg.opcode = CRYPTOCMP_OP_GENERATE_KEY;
	wire.key = *request;
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &wire;
	outgoing.length = sizeof(wire);
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	incoming.fds = &fd;
	incoming.fd_capacity = 1;
	options.timeout_ms = 30000;
	if (service_session_call(client->session, &outgoing, &incoming, &options) == -1)
		return (-1);
	if (incoming.length != sizeof(reply) || reply.msg.magic != CRYPTOCMP_MAGIC ||
	    reply.msg.version != CRYPTOCMP_VERSION ||
	    reply.msg.opcode != CRYPTOCMP_OP_GENERATE_KEY ||
	    !valid_status(reply.msg.status) ||
	    incoming.nfds != (reply.msg.status == 0 ? 1 : 0))
		return (reject_reply(incoming.nfds != 0 ? fd : -1));
	if (reply.msg.status != 0)
		return (errno = -reply.msg.status, -1);
	memcpy(public_key, reply.public_key, sizeof(reply.public_key));
	*descriptor = fd;
	return (0);
}

int
cryptocmp_digest(struct cryptocmp_client *client, uint32_t alg, uint32_t ttl,
    uint32_t flags, int *descriptor)
{
	struct { struct cryptocmp_msg msg; struct cryptocmp_digest digest; } wire;
	struct cryptocmp_msg reply;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	int fd = -1;

	if (client == NULL || descriptor == NULL || client->owner != getpid())
		return (errno = EINVAL, -1);
	*descriptor = -1;
	if (alg != CRYPTO_SHA2_256 && alg != CRYPTO_SHA2_384 &&
	    alg != CRYPTO_SHA2_512)
		return (errno = EINVAL, -1);
	memset(&wire, 0, sizeof(wire));
	wire.msg.magic = CRYPTOCMP_MAGIC;
	wire.msg.version = CRYPTOCMP_VERSION;
	wire.msg.opcode = CRYPTOCMP_OP_DIGEST;
	wire.digest.alg = alg;
	wire.digest.ttl = ttl;
	wire.digest.flags = flags;
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &wire;
	outgoing.length = sizeof(wire);
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	incoming.fds = &fd;
	incoming.fd_capacity = 1;
	options.timeout_ms = 30000;
	if (service_session_call(client->session, &outgoing, &incoming, &options) == -1)
		return (-1);
	if (incoming.length != sizeof(reply) || reply.magic != CRYPTOCMP_MAGIC ||
	    reply.version != CRYPTOCMP_VERSION ||
	    reply.opcode != CRYPTOCMP_OP_DIGEST || !valid_status(reply.status) ||
	    incoming.nfds != (reply.status == 0 ? 1 : 0))
		return (reject_reply(incoming.nfds != 0 ? fd : -1));
	if (reply.status != 0)
		return (errno = -reply.status, -1);
	*descriptor = fd;
	return (0);
}

int
cryptocmp_random(struct cryptocmp_client *client, void *buf, size_t nbytes)
{
	struct { struct cryptocmp_msg msg; struct cryptocmp_random random; } wire;
	struct cryptocmp_random_reply reply;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	int fd = -1;

	if (client == NULL || buf == NULL || client->owner != getpid() ||
	    nbytes == 0 || nbytes > CRYPTOCMP_MAX_RANDOM_BYTES)
		return (errno = EINVAL, -1);
	memset(buf, 0, nbytes);
	memset(&wire, 0, sizeof(wire));
	wire.msg.magic = CRYPTOCMP_MAGIC;
	wire.msg.version = CRYPTOCMP_VERSION;
	wire.msg.opcode = CRYPTOCMP_OP_RANDOM;
	wire.random.nbytes = (uint32_t)nbytes;
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &wire;
	outgoing.length = sizeof(wire);
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	incoming.fds = &fd;
	incoming.fd_capacity = 0;
	options.timeout_ms = 30000;
	if (service_session_call(client->session, &outgoing, &incoming, &options) == -1)
		return (-1);
	if (incoming.length < offsetof(struct cryptocmp_random_reply, data) ||
	    reply.msg.magic != CRYPTOCMP_MAGIC ||
	    reply.msg.version != CRYPTOCMP_VERSION ||
	    reply.msg.opcode != CRYPTOCMP_OP_RANDOM ||
	    !valid_status(reply.msg.status) || incoming.nfds != 0) {
		explicit_bzero(&reply, sizeof(reply));
		return (reject_reply(incoming.nfds != 0 ? fd : -1));
	}
	if (reply.msg.status != 0) {
		errno = -reply.msg.status;
		explicit_bzero(&reply, sizeof(reply));
		return (-1);
	}
	if (reply.nbytes != (uint32_t)nbytes ||
	    reply.nbytes > CRYPTOCMP_MAX_RANDOM_BYTES ||
	    incoming.length !=
	    offsetof(struct cryptocmp_random_reply, data) + reply.nbytes) {
		explicit_bzero(&reply, sizeof(reply));
		return (reject_reply(-1));
	}
	memcpy(buf, reply.data, reply.nbytes);
	explicit_bzero(&reply, sizeof(reply));
	return (0);
}

static int
cryptocmp_named_call(struct cryptocmp_client *client, uint16_t opcode,
    const void *payload, size_t payload_length, uint64_t *generation,
    int *descriptor)
{
	struct { struct cryptocmp_msg msg; uint8_t payload[sizeof(struct cryptocmp_named_create)]; } wire;
	struct cryptocmp_named_reply reply;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	int fd = -1;

	if (client == NULL || payload == NULL || generation == NULL ||
	    client->owner != getpid() || payload_length > sizeof(wire.payload) ||
	    (descriptor == NULL && opcode == CRYPTOCMP_OP_NAMED_LEASE) ||
	    (descriptor != NULL && opcode != CRYPTOCMP_OP_NAMED_LEASE))
		return (errno = EINVAL, -1);
	*generation = 0;
	if (descriptor != NULL)
		*descriptor = -1;
	memset(&wire, 0, sizeof(wire));
	wire.msg.magic = CRYPTOCMP_MAGIC;
	wire.msg.version = CRYPTOCMP_VERSION;
	wire.msg.opcode = opcode;
	memcpy(wire.payload, payload, payload_length);
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &wire;
	outgoing.length = sizeof(wire.msg) + payload_length;
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	incoming.fds = &fd;
	incoming.fd_capacity = descriptor == NULL ? 0 : 1;
	options.timeout_ms = 30000;
	if (service_session_call(client->session, &outgoing, &incoming, &options) == -1)
		return (-1);
	if (incoming.length != sizeof(reply) || reply.msg.magic != CRYPTOCMP_MAGIC ||
	    reply.msg.version != CRYPTOCMP_VERSION || reply.msg.opcode != opcode ||
	    !valid_status(reply.msg.status) ||
	    incoming.nfds != (reply.msg.status == 0 && descriptor != NULL ? 1 : 0))
		return (reject_reply(incoming.nfds != 0 ? fd : -1));
	if (reply.msg.status != 0)
		return (errno = -reply.msg.status, -1);
	*generation = reply.generation;
	if (descriptor != NULL)
		*descriptor = fd;
	return (0);
}

int
cryptocmp_named_create(struct cryptocmp_client *client, const char *name,
    const struct cryptocmp_generate *request, uint64_t *generation)
{
	struct cryptocmp_named_create create;

	if (name == NULL || request == NULL || strnlen(name, sizeof(create.name)) == 0 ||
	    strnlen(name, sizeof(create.name)) == sizeof(create.name))
		return (errno = EINVAL, -1);
	memset(&create, 0, sizeof(create));
	strlcpy(create.name, name, sizeof(create.name));
	create.generate = *request;
	return (cryptocmp_named_call(client, CRYPTOCMP_OP_NAMED_CREATE, &create,
	    sizeof(create), generation, NULL));
}

int
cryptocmp_named_lease(struct cryptocmp_client *client, const char *name,
    uint32_t rights, uint32_t ttl, uint64_t *generation, int *descriptor)
{
	struct cryptocmp_named_lease lease;

	if (name == NULL || strnlen(name, sizeof(lease.name)) == 0 ||
	    strnlen(name, sizeof(lease.name)) == sizeof(lease.name))
		return (errno = EINVAL, -1);
	memset(&lease, 0, sizeof(lease));
	strlcpy(lease.name, name, sizeof(lease.name));
	lease.rights = rights;
	lease.ttl = ttl;
	return (cryptocmp_named_call(client, CRYPTOCMP_OP_NAMED_LEASE, &lease,
	    sizeof(lease), generation, descriptor));
}

static int
cryptocmp_named_change(struct cryptocmp_client *client, uint16_t opcode,
    const char *name, uint64_t *generation)
{
	struct cryptocmp_named_control control;

	if (name == NULL || strnlen(name, sizeof(control.name)) == 0 ||
	    strnlen(name, sizeof(control.name)) == sizeof(control.name))
		return (errno = EINVAL, -1);
	memset(&control, 0, sizeof(control));
	strlcpy(control.name, name, sizeof(control.name));
	return (cryptocmp_named_call(client, opcode, &control, sizeof(control),
	    generation, NULL));
}

int
cryptocmp_named_rotate(struct cryptocmp_client *client, const char *name,
    uint64_t *generation)
{

	return (cryptocmp_named_change(client, CRYPTOCMP_OP_NAMED_ROTATE, name,
	    generation));
}

int
cryptocmp_named_delete(struct cryptocmp_client *client, const char *name,
    uint64_t *generation)
{

	return (cryptocmp_named_change(client, CRYPTOCMP_OP_NAMED_DELETE, name,
	    generation));
}
