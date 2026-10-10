/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libservice.h>
#include <service_runtime.h>
#include <powercmp_protocol.h>
#include "config.h"
#include "BSDPower_test.h"

static int listen_fd, ack_fd, providers[3], quiesce_mode;
int __wrap_service_listener_fd(const struct service_listener *);
int __wrap_service_listener_accept(struct service_listener *,
    struct service_identity *, int *);
int __wrap_service_provider_quiescing(struct service_provider *);
int __wrap_service_provider_quiesce_complete(struct service_provider *, int);

int
__wrap_service_listener_fd(const struct service_listener *listener)
{
	(void)listener;
	return (listen_fd);
}
int
__wrap_service_listener_accept(struct service_listener *listener,
    struct service_identity *identity, int *fd)
{
	int index;
	(void)listener;
	if (read(listen_fd, &index, sizeof(index)) != sizeof(index))
		return (errno = EPIPE, -1);
	if (index < 0) {
		quiesce_mode = index == -2 ? 1 : 2;
		return (errno = EINTR, -1);
	}
	if (index >= 3 || providers[index] < 0)
		return (errno = EINVAL, -1);
	snprintf(identity->client_label, sizeof(identity->client_label),
	    "test.power.%d", index);
	*fd = providers[index];
	providers[index] = -1;
	return (0);
}
int
__wrap_service_provider_quiescing(struct service_provider *provider)
{
	(void)provider;
	return (quiesce_mode != 0);
}
int
__wrap_service_provider_quiesce_complete(struct service_provider *provider,
    int status)
{
	(void)provider;
	if (quiesce_mode == 2)
		return (errno = EINVAL, -1); /* Explicit stop cannot be refused. */
	if (write(ack_fd, &status, sizeof(status)) != sizeof(status))
		return (-1);
	quiesce_mode = 0;
	return (0);
}

static void
channel_pair(int *client, int *provider)
{
	struct mac_capability_connect_args connect = { 0 };
	struct mac_capability_sendmsg_args send = { 0 };
	struct mac_capability_recvmsg_args receive = { 0 };
	uint32_t operation = CHANNEL_OP_CREATE;
	int control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE(control >= 0);
	strlcpy(connect.name, "channel", sizeof(connect.name));
	ATF_REQUIRE_EQ(0, ioctl(control, MAC_CAPABILITY_CONNECT, &connect));
	close(control);
	*client = connect.fd;
	send.payload = &operation;
	send.payload_len = sizeof(operation);
	ATF_REQUIRE_EQ(0, ioctl(*client, MAC_CAPABILITY_SENDMSG, &send));
	receive.fds = provider;
	receive.nfds = 1;
	ATF_REQUIRE_EQ(0, ioctl(*client, MAC_CAPABILITY_RECVMSG, &receive));
	ATF_REQUIRE_EQ(1, receive.nfds);
}

static int
rpc(struct service_session *session, uint16_t opcode, uint32_t *count)
{
	struct {
		struct powercmp_msg header;
		struct powercmp_body body;
	} request = { .header = { .magic = POWERCMP_MAGIC } }, reply;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing = { .size = sizeof(outgoing) };
	struct service_reply incoming = { .size = sizeof(incoming) };
	request.header.opcode = opcode;
	request.body.state = opcode == POWERCMP_OP_SUSPEND ? 3 : 0;
	outgoing.data = &request;
	outgoing.length = opcode == POWERCMP_OP_SUSPEND ?
	    sizeof(request) : sizeof(request.header);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 2000;
	if (service_session_call(session, &outgoing, &incoming, &options) == -1)
		return (-1);
	ATF_REQUIRE_EQ(0, powercmp_validate_message(&reply.header,
	    incoming.length, POWERCMP_MESSAGE_REPLY));
	ATF_REQUIRE_EQ(opcode, reply.header.opcode);
	if (count != NULL && reply.header.status == 0)
		*count = reply.body.supported;
	return (-reply.header.status);
}

ATF_TC(shared_reactor_leases_and_stop);
ATF_TC_HEAD(shared_reactor_leases_and_stop, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "20");
}
ATF_TC_BODY(shared_reactor_leases_and_stop, tc)
{
	struct powercmp_config config;
	struct service_session *clients[3];
	int endpoints[3], control[2], ack[2], status, command;
	uint32_t count = 0;
	pid_t child;

	powercmp_config_defaults(&config);
	config.default_suspend = config.default_inhibit = true;
	ATF_REQUIRE_EQ(0, pipe(control));
	ATF_REQUIRE_EQ(0, pipe(ack));
	for (int i = 0; i < 3; i++)
		channel_pair(&endpoints[i], &providers[i]);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(control[1]);
		close(ack[0]);
		listen_fd = control[0];
		ack_fd = ack[1];
		for (int i = 0; i < 3; i++)
			close(endpoints[i]);
		bsdpower_test_set_acpi_fd(-1);
		status = bsdpower_test_serve_reactor(NULL, NULL, &config);
		if (write(ack_fd, &status, sizeof(status)) != sizeof(status))
			_exit(2);
		/* Stay alive so process exit cannot hide leaked session channels. */
		if (read(listen_fd, &command, sizeof(command)) != sizeof(command))
			_exit(3);
		_exit(status == 0 ? 0 : 1);
	}
	close(control[0]);
	close(ack[1]);
	for (int i = 0; i < 3; i++) {
		close(providers[i]);
		ATF_REQUIRE_EQ(0, service_session_create(endpoints[i], &clients[i]));
		ATF_REQUIRE_EQ(sizeof(i), write(control[1], &i, sizeof(i)));
	}
	ATF_REQUIRE_EQ(0, rpc(clients[0], POWERCMP_OP_INHIBIT, NULL));
	ATF_REQUIRE_EQ(0, rpc(clients[1], POWERCMP_OP_INHIBIT, NULL));
	ATF_REQUIRE_EQ(0, rpc(clients[2], POWERCMP_OP_INHIBITORS, &count));
	ATF_CHECK_EQ(2, count);
	ATF_CHECK_EQ(EBUSY, rpc(clients[2], POWERCMP_OP_SUSPEND, NULL));
	service_session_close(clients[1]);
	for (unsigned i = 0; i < 100; i++) {
		ATF_REQUIRE_EQ(0, rpc(clients[2], POWERCMP_OP_INHIBITORS, &count));
		if (count == 1)
			break;
		usleep(10000);
	}
	ATF_REQUIRE_EQ(1, count);
	ATF_REQUIRE_EQ(0, rpc(clients[0], POWERCMP_OP_UNINHIBIT, NULL));
	ATF_CHECK_EQ(ENODEV, rpc(clients[2], POWERCMP_OP_SUSPEND, NULL));
	ATF_REQUIRE_EQ(0, rpc(clients[0], POWERCMP_OP_INHIBIT, NULL));
	command = -2; /* Ask the real reactor to refuse idle quiesce. */
	ATF_REQUIRE_EQ(sizeof(command), write(control[1], &command, sizeof(command)));
	struct pollfd pfd = { .fd = ack[0], .events = POLLIN };
	ATF_REQUIRE_EQ(1, poll(&pfd, 1, 2000));
	ATF_REQUIRE_EQ(sizeof(status), read(ack[0], &status, sizeof(status)));
	ATF_CHECK_EQ(EBUSY, status);
	ATF_REQUIRE_EQ(0, rpc(clients[2], POWERCMP_OP_INHIBITORS, &count));
	ATF_CHECK_EQ(1, count);
	command = -1; /* Explicit stop wins even with a held inhibitor. */
	ATF_REQUIRE_EQ(sizeof(command), write(control[1], &command, sizeof(command)));
	ATF_REQUIRE_EQ(1, poll(&pfd, 1, 2000));
	ATF_REQUIRE_EQ(sizeof(status), read(ack[0], &status, sizeof(status)));
	ATF_REQUIRE_EQ(0, status);
	ATF_CHECK_EQ(-1, rpc(clients[0], POWERCMP_OP_INHIBITORS, &count));
	ATF_CHECK_EQ(-1, rpc(clients[2], POWERCMP_OP_INHIBITORS, &count));
	command = 1;
	ATF_REQUIRE_EQ(sizeof(command), write(control[1], &command, sizeof(command)));
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	service_session_close(clients[0]);
	service_session_close(clients[2]);
	close(control[1]);
	close(ack[0]);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, shared_reactor_leases_and_stop);
	return (atf_no_error());
}
