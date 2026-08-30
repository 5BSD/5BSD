/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/capsicum.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include "tracecmp.h"
#include "tracecmp_server.h"
#include "tracecmp_probes.h"

union tracecmp_buffer {
	max_align_t align;
	uint8_t bytes[TRACECMP_MAX_MESSAGE];
};

static int
tracecmp_header_validate(const struct tracecmp_msg *msg, size_t length,
    enum tracecmp_message_role role)
{

	if (msg == NULL || length < sizeof(*msg) ||
	    length > TRACECMP_MAX_MESSAGE ||
	    (role != TRACECMP_MESSAGE_REQUEST &&
	    role != TRACECMP_MESSAGE_REPLY &&
	    role != TRACECMP_MESSAGE_EVENT) ||
	    msg->magic != TRACECMP_MAGIC ||
	    msg->version != TRACECMP_ABI_VERSION ||
	    msg->opcode < TRACECMP_OP_HELLO ||
	    msg->opcode > TRACECMP_OP_STATS ||
	    (msg->flags & ~TRACECMP_MSG_F_MASK) != 0 ||
	    (role != TRACECMP_MESSAGE_REPLY && msg->status != 0) ||
	    (role == TRACECMP_MESSAGE_REPLY &&
	    (msg->status > 0 || msg->status < -ELAST))) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

int
tracecmp_message_init(struct tracecmp_msg *msg, uint16_t opcode,
    uint32_t flags)
{

	if (msg == NULL || opcode < TRACECMP_OP_HELLO ||
	    opcode > TRACECMP_OP_STATS ||
	    (flags & ~TRACECMP_MSG_F_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(msg, 0, sizeof(*msg));
	msg->magic = TRACECMP_MAGIC;
	msg->version = TRACECMP_ABI_VERSION;
	msg->opcode = opcode;
	msg->flags = flags;
	return (0);
}

int
tracecmp_message_init_reply(struct tracecmp_msg *reply,
    const struct tracecmp_msg *request, int status)
{

	if (reply == NULL || request == NULL ||
	    tracecmp_header_validate(request, sizeof(*request),
	    TRACECMP_MESSAGE_REQUEST) == -1 ||
	    status > 0 || status < -ELAST) {
		errno = EINVAL;
		return (-1);
	}
	memset(reply, 0, sizeof(*reply));
	reply->magic = TRACECMP_MAGIC;
	reply->version = TRACECMP_ABI_VERSION;
	reply->opcode = request->opcode;
	reply->status = status;
	return (0);
}

int
tracecmp_validate_message(const struct tracecmp_msg *msg, size_t length,
    enum tracecmp_message_role role)
{
	size_t payload;

	if (tracecmp_header_validate(msg, length, role) == -1)
		return (-1);
	payload = length - sizeof(*msg);
	if (role == TRACECMP_MESSAGE_EVENT) {
		errno = EPROTO;
		return (-1);
	}
	if (role == TRACECMP_MESSAGE_REQUEST) {
		if (payload != 0) {
			errno = EPROTO;
			return (-1);
		}
		return (0);
	}
	if (msg->status != 0 && payload != 0) {
		errno = EPROTO;
		return (-1);
	}
	if (msg->status != 0)
		return (0);
	if (msg->opcode == TRACECMP_OP_HELLO) {
		const struct tracecmp_hello_reply *hello;

		if (payload != sizeof(*hello))
			goto invalid;
		hello = (const void *)(msg + 1);
		if (hello->version != TRACECMP_ABI_VERSION ||
		    (hello->features & ~TRACECMP_FEATURE_RAW_DTRACE_FD) != 0 ||
		    hello->reserved[0] != 0 || hello->reserved[1] != 0)
			goto invalid;
	} else if (msg->opcode == TRACECMP_OP_STATS) {
		if (payload != sizeof(struct tracecmp_stats))
			goto invalid;
	} else if (payload != 0) {
		goto invalid;
	}
	return (0);

invalid:
	errno = EPROTO;
	return (-1);
}

int
tracecmp_validate_fds(const struct tracecmp_msg *msg, size_t nfds,
    enum tracecmp_message_role role)
{
	size_t expected;

	if (msg == NULL) {
		errno = EINVAL;
		return (-1);
	}
	expected = role == TRACECMP_MESSAGE_REPLY &&
	    msg->opcode == TRACECMP_OP_OPEN && msg->status == 0 ? 1 : 0;
	if (nfds != expected) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

static int
rpc(struct service_session *client, uint16_t opcode,
    union tracecmp_buffer *reply,
    int *returned_fd)
{
	struct tracecmp_msg request, *message;
	struct service_call_options options =
	    SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	size_t received;
	uint16_t received_opcode;

	memset(&request, 0, sizeof(request));
	if (tracecmp_message_init(&request, opcode, 0) == -1)
		return (-1);
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &request;
	outgoing.length = sizeof(request);
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(*reply);
	incoming.fds = returned_fd;
	incoming.fd_capacity = returned_fd != NULL ? 1 : 0;
	options.timeout_ms = 30000;
	if (service_session_call(client, &outgoing, &incoming, &options) == -1) {
		TRACECMP_PROBE_SEND(opcode, sizeof(request), errno);
		return (-1);
	}
	TRACECMP_PROBE_SEND(opcode, sizeof(request), 0);
	received = incoming.length;
	message = (void *)reply;
	received_opcode = received >= sizeof(*message) ? message->opcode : 0;
	TRACECMP_PROBE_RECEIVE(received_opcode, received, 0);
	if (tracecmp_validate_message(message, received,
	    TRACECMP_MESSAGE_REPLY) == -1 ||
	    tracecmp_validate_fds(message, incoming.nfds,
	    TRACECMP_MESSAGE_REPLY) == -1 ||
	    message->opcode != opcode) {
		if (incoming.nfds != 0 && returned_fd != NULL)
			close(*returned_fd);
		TRACECMP_PROBE_REJECT(received_opcode, EPROTO);
		errno = EPROTO;
		return (-1);
	}
	if (message->status != 0) {
		TRACECMP_PROBE_REJECT(message->opcode, -message->status);
		errno = -message->status;
		return (-1);
	}
	return (0);
}

static int
harden_delegated_fd(int fd)
{

	if (fd < 0 || cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1)
		return (-1);
	return (0);
}

static uint64_t
round_down_power_of_two(uint64_t value)
{
	uint64_t result;

	result = 1;
	while (result <= value / 2)
		result <<= 1;
	return (result);
}

#ifdef TRACECMP_TESTING
void tracecmp_test_calculate_sizes(uint64_t, uint32_t, uint64_t *,
    uint64_t *);
#endif

static void
tracecmp_calculate_sizes(uint64_t memory, uint32_t cpus,
    uint64_t *buffer_size, uint64_t *dynamic_size)
{
	const uint64_t mib = UINT64_C(1024) * 1024;
	uint64_t per_cpu;

	*buffer_size = 4 * mib;
	*dynamic_size = 4 * mib;
	if (memory == 0 || cpus == 0)
		return;
	per_cpu = memory / (UINT64_C(256) * cpus);
	if (per_cpu < 64 * 1024)
		per_cpu = 64 * 1024;
	else if (per_cpu > 32 * mib)
		per_cpu = 32 * mib;
	*buffer_size = round_down_power_of_two(per_cpu);
	memory /= UINT64_C(8192);
	if (memory > 64 * mib)
		memory = 64 * mib;
	if (memory >= mib)
		*dynamic_size = round_down_power_of_two(memory);
}

static void
tracecmp_default_sizes(uint64_t *buffer_size, uint64_t *dynamic_size)
{
	uint64_t memory;
	long cpus, page_size, pages;

	cpus = sysconf(_SC_NPROCESSORS_ONLN);
	page_size = sysconf(_SC_PAGESIZE);
	pages = sysconf(_SC_PHYS_PAGES);
	if (cpus <= 0 || page_size <= 0 || pages <= 0 ||
	    (uint64_t)cpus > UINT32_MAX ||
	    (uint64_t)pages > UINT64_MAX / (uint64_t)page_size) {
		tracecmp_calculate_sizes(0, 0, buffer_size, dynamic_size);
		return;
	}
	memory = (uint64_t)pages * (uint64_t)page_size;
	tracecmp_calculate_sizes(memory, (uint32_t)cpus, buffer_size,
	    dynamic_size);
}

#ifdef TRACECMP_TESTING
void
tracecmp_test_calculate_sizes(uint64_t memory, uint32_t cpus,
    uint64_t *buffer_size, uint64_t *dynamic_size)
{

	tracecmp_calculate_sizes(memory, cpus, buffer_size, dynamic_size);
}
#endif

static int
tracecmp_apply_tuning(dtrace_hdl_t *dtp)
{
	char aggregation[32], buffer[32], dynamic[32];
	uint64_t buffer_size, dynamic_size;

	tracecmp_default_sizes(&buffer_size, &dynamic_size);
	(void) snprintf(buffer, sizeof(buffer), "%ju",
	    (uintmax_t)buffer_size);
	(void) snprintf(aggregation, sizeof(aggregation), "%ju",
	    (uintmax_t)buffer_size);
	(void) snprintf(dynamic, sizeof(dynamic), "%ju",
	    (uintmax_t)dynamic_size);
	return (dtrace_setopt(dtp, "bufresize", "auto") == -1 ||
	    dtrace_setopt(dtp, "bufpolicy", "switch") == -1 ||
	    dtrace_setopt(dtp, "bufsize", buffer) == -1 ||
	    dtrace_setopt(dtp, "aggsize", aggregation) == -1 ||
	    dtrace_setopt(dtp, "dynvarsize", dynamic) == -1 ||
	    dtrace_setopt(dtp, "switchrate", "250ms") == -1 ? -1 : 0);
}

int
tracecmp_open(int *dtracefd)
{
	union tracecmp_buffer reply;
	struct tracecmp_hello_reply *hello;
	struct service_session *client;
	int fd, error, result;

	if (dtracefd == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*dtracefd = -1;
	fd = -1;
	error = service_open(TRACECMP_INTERFACE, &fd) == -1 ? errno : 0;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	if (service_session_create(fd, &client) == -1) {
		error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	result = rpc(client, TRACECMP_OP_HELLO, &reply, NULL);
	if (result == 0) {
		hello = (void *)((struct tracecmp_msg *)reply.bytes + 1);
		if ((hello->features & TRACECMP_FEATURE_RAW_DTRACE_FD) == 0) {
			errno = EOPNOTSUPP;
			result = -1;
		}
	}
	if (result == 0)
		result = rpc(client, TRACECMP_OP_OPEN, &reply, dtracefd);
	if (result == 0 && harden_delegated_fd(*dtracefd) == -1) {
		error = errno;
		(void)close(*dtracefd);
		*dtracefd = -1;
		result = -1;
	}
	if (result == -1 && error == 0)
		error = errno;
	service_session_close(client);
	TRACECMP_PROBE_OPEN(__DECONST(char *, TRACECMP_INTERFACE), error);
	errno = error;
	return (result);
}

dtrace_hdl_t *
tracecmp_dtrace_open(int flags, int *errp)
{
	dtrace_hdl_t *dtp;
	int fd, error;

	if ((flags & ~DTRACE_O_MASK) != 0 || (flags & DTRACE_O_NODEV) != 0) {
		if (errp != NULL)
			*errp = EINVAL;
		errno = EINVAL;
		return (NULL);
	}
	fd = -1;
	if (tracecmp_open(&fd) == -1) {
		if (errp != NULL)
			*errp = errno;
		return (NULL);
	}
	dtp = dtrace_fdopen(fd, DTRACE_VERSION, flags, errp);
	error = errno;
	(void) close(fd);
	if (dtp != NULL && tracecmp_apply_tuning(dtp) == -1) {
		error = dtrace_errno(dtp);
		dtrace_close(dtp);
		dtp = NULL;
		if (errp != NULL)
			*errp = error;
	}
	errno = error;
	return (dtp);
}
