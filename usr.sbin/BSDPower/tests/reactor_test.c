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
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libservice.h>
#include <service_runtime.h>
#include <powercmp.h>
#include "config.h"
#include "BSDPower_test.h"

#define TEST_ENDPOINTS 66
static int listen_fd, ack_fd, providers[TEST_ENDPOINTS], quiesce_mode;
static int provider_count = 3;
static bool shared_label;
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
	if (index >= provider_count || providers[index] < 0)
		return (errno = EINVAL, -1);
	snprintf(identity->client_label, sizeof(identity->client_label),
	    "test.power.%d", shared_label && index != 5 ? 0 : index);
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

enum op { INHIBIT, UNINHIBIT, INHIBITORS, SUSPEND };
/*
 * One call through the real client.  Returns the application errno (0 for
 * success), or -1 when the session failed (closed, refused or timed out).
 */
static int
rpc(struct powercmp_client *client, enum op op, uint32_t *count)
{
	uint32_t value = 0;
	int result;
	ATF_REQUIRE_EQ(0, service_budget_begin(2000));
	switch (op) {
	case INHIBIT:
		result = powercmp_inhibit(client);
		break;
	case UNINHIBIT:
		result = powercmp_uninhibit(client);
		break;
	case INHIBITORS:
		result = powercmp_inhibitors(client, &value);
		break;
	default:
		result = powercmp_suspend(client, 3);
		break;
	}
	service_budget_end();
	if (result == 0) {
		if (count != NULL)
			*count = value;
		return (0);
	}
	switch (errno) {
	case EPERM:
	case EALREADY:
	case ENOENT:
	case EBUSY:
	case ENODEV:
	case ENOTSUP:
		return (errno);
	default:
		return (-1);
	}
}

ATF_TC(shared_reactor_leases_and_stop);
ATF_TC_HEAD(shared_reactor_leases_and_stop, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "38");
}
ATF_TC_BODY(shared_reactor_leases_and_stop, tc)
{
	struct powercmp_config config;
	struct powercmp_client *clients[3];
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
		ATF_REQUIRE_EQ(0, powercmp_client_create(endpoints[i], &clients[i]));
		ATF_REQUIRE_EQ(sizeof(i), write(control[1], &i, sizeof(i)));
	}
	ATF_REQUIRE_EQ(0, rpc(clients[0], INHIBIT, NULL));
	ATF_REQUIRE_EQ(0, rpc(clients[1], INHIBIT, NULL));
	ATF_REQUIRE_EQ(0, rpc(clients[2], INHIBITORS, &count));
	ATF_CHECK_EQ(2, count);
	ATF_CHECK_EQ(EBUSY, rpc(clients[2], SUSPEND, NULL));
	powercmp_client_close(clients[1]);
	for (unsigned i = 0; i < 100; i++) {
		ATF_REQUIRE_EQ(0, rpc(clients[2], INHIBITORS, &count));
		if (count == 1)
			break;
		usleep(10000);
	}
	ATF_REQUIRE_EQ(1, count);
	ATF_REQUIRE_EQ(0, rpc(clients[0], UNINHIBIT, NULL));
	ATF_CHECK_EQ(ENODEV, rpc(clients[2], SUSPEND, NULL));
	ATF_REQUIRE_EQ(0, rpc(clients[0], INHIBIT, NULL));
	command = -2; /* Ask the real reactor to refuse idle quiesce. */
	ATF_REQUIRE_EQ(sizeof(command), write(control[1], &command, sizeof(command)));
	struct pollfd pfd = { .fd = ack[0], .events = POLLIN };
	ATF_REQUIRE_EQ(1, poll(&pfd, 1, 2000));
	ATF_REQUIRE_EQ(sizeof(status), read(ack[0], &status, sizeof(status)));
	ATF_CHECK_EQ(EBUSY, status);
	ATF_REQUIRE_EQ(0, rpc(clients[2], INHIBITORS, &count));
	ATF_CHECK_EQ(1, count);
	/* The real 30-second idle limit exempts the session holding a lease. */
	uint64_t idle_until = service_monotime_ms() + 31000;
	while (service_monotime_ms() < idle_until)
		usleep(100000);
	ATF_CHECK_EQ(-1, rpc(clients[2], INHIBITORS, &count));
	ATF_REQUIRE_EQ(0, rpc(clients[0], INHIBITORS, &count));
	ATF_CHECK_EQ(1, count);
	command = -1; /* Explicit stop wins even with a held inhibitor. */
	ATF_REQUIRE_EQ(sizeof(command), write(control[1], &command, sizeof(command)));
	ATF_REQUIRE_EQ(1, poll(&pfd, 1, 2000));
	ATF_REQUIRE_EQ(sizeof(status), read(ack[0], &status, sizeof(status)));
	ATF_REQUIRE_EQ(0, status);
	ATF_CHECK_EQ(-1, rpc(clients[0], INHIBITORS, &count));
	ATF_CHECK_EQ(-1, rpc(clients[2], INHIBITORS, &count));
	command = 1;
	ATF_REQUIRE_EQ(sizeof(command), write(control[1], &command, sizeof(command)));
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	powercmp_client_close(clients[0]);
	powercmp_client_close(clients[2]);
	close(control[1]);
	close(ack[0]);
}

static void
admission_limit(bool per_label)
{
	struct powercmp_config config;
	struct powercmp_client *clients[TEST_ENDPOINTS] = { 0 };
	int endpoints[TEST_ENDPOINTS], control[2], ack[2];
	int initial = per_label ? 6 : 65, denied = per_label ? 4 : 64;
	uint32_t count_expected = per_label ? 5 : 64;
	int command, status;
	uint32_t count;
	pid_t child;

	shared_label = per_label;
	provider_count = initial + 1;
	powercmp_config_defaults(&config);
	config.default_inhibit = true;
	ATF_REQUIRE_EQ(0, pipe(control));
	ATF_REQUIRE_EQ(0, pipe(ack));
	for (int i = 0; i < provider_count; i++)
		channel_pair(&endpoints[i], &providers[i]);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(control[1]);
		close(ack[0]);
		listen_fd = control[0];
		ack_fd = ack[1];
		for (int i = 0; i < provider_count; i++)
			close(endpoints[i]);
		bsdpower_test_set_acpi_fd(-1);
		status = bsdpower_test_serve_reactor(NULL, NULL, &config);
		if (write(ack_fd, &status, sizeof(status)) != sizeof(status))
			_exit(2);
		if (read(listen_fd, &command, sizeof(command)) != sizeof(command))
			_exit(3);
		_exit(status == 0 ? 0 : 1);
	}
	close(control[0]);
	close(ack[1]);
	for (int i = 0; i < provider_count; i++) {
		close(providers[i]);
		ATF_REQUIRE_EQ(0, powercmp_client_create(endpoints[i], &clients[i]));
	}
	for (int i = 0; i < initial; i++) {
		ATF_REQUIRE_EQ(sizeof(i), write(control[1], &i, sizeof(i)));
		if (i == denied) {
			ATF_CHECK_EQ(-1, rpc(clients[i], INHIBIT, NULL));
			powercmp_client_close(clients[i]);
			clients[i] = NULL;
		} else
			ATF_REQUIRE_EQ(0, rpc(clients[i], INHIBIT, NULL));
	}
	ATF_REQUIRE_EQ(0, rpc(clients[1], INHIBITORS, &count));
	ATF_CHECK_EQ(count_expected, count);
	powercmp_client_close(clients[0]);
	clients[0] = NULL;
	for (unsigned i = 0; i < 100; i++) {
		ATF_REQUIRE_EQ(0, rpc(clients[1], INHIBITORS, &count));
		if (count == (uint32_t)count_expected - 1)
			break;
		usleep(10000);
	}
	ATF_REQUIRE_EQ(count_expected - 1, count);
	/* Reuse the released slot, including its old provider-assigned owner ID. */
	ATF_REQUIRE_EQ(sizeof(initial), write(control[1], &initial, sizeof(initial)));
	ATF_REQUIRE_EQ(0, rpc(clients[initial], INHIBIT, NULL));
	ATF_REQUIRE_EQ(0, rpc(clients[1], INHIBITORS, &count));
	ATF_CHECK_EQ(count_expected, count);
	command = -1;
	ATF_REQUIRE_EQ(sizeof(command), write(control[1], &command, sizeof(command)));
	struct pollfd pfd = { .fd = ack[0], .events = POLLIN };
	ATF_REQUIRE_EQ(1, poll(&pfd, 1, 2000));
	ATF_REQUIRE_EQ(sizeof(status), read(ack[0], &status, sizeof(status)));
	ATF_REQUIRE_EQ(0, status);
	for (int i = 0; i < provider_count; i++) {
		if (clients[i] == NULL)
			continue;
		ATF_CHECK_EQ(-1, rpc(clients[i], INHIBITORS, &count));
		powercmp_client_close(clients[i]);
	}
	command = 1;
	ATF_REQUIRE_EQ(sizeof(command), write(control[1], &command, sizeof(command)));
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	close(control[1]);
	close(ack[0]);
}
ATF_TC(per_label_admission_and_slot_reuse);
ATF_TC_HEAD(per_label_admission_and_slot_reuse, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(per_label_admission_and_slot_reuse, tc)
{
	admission_limit(true);
}
ATF_TC(total_admission_and_slot_reuse);
ATF_TC_HEAD(total_admission_and_slot_reuse, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(total_admission_and_slot_reuse, tc)
{
	admission_limit(false);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, per_label_admission_and_slot_reuse);
	ATF_TP_ADD_TC(tp, total_admission_and_slot_reuse);
	ATF_TP_ADD_TC(tp, shared_reactor_leases_and_stop);
	return (atf_no_error());
}
