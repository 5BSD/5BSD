/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/envfd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <atf-c.h>
#include <channel.h>
#include <component_session.h>
#include <libservice.h>
#include <service_bootstrap.h>

struct event_close_context {
	struct service_session	*client;
	int			 started_fd;
	int			 error;
};

struct session_provider_context {
	int	fd;
	int	ready_fd;
	int	event_fd;
	int	large_reply_fd;
	int	late_reply_fd;
	int	error;
	unsigned requests;
};

static int
test_session_call(struct service_session *session, const void *request,
    size_t request_length, void *reply, size_t reply_capacity,
    uint32_t timeout_ms, size_t *received)
{
	struct service_call_options options =
	    SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = request;
	outgoing.length = request_length;
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = reply_capacity;
	options.timeout_ms = timeout_ms;
	if (service_session_call(session, &outgoing, &incoming, &options) == -1)
		return (-1);
	if (received != NULL)
		*received = incoming.length;
	return (0);
}

struct component_provider_context {
	int			 fd;
	int			 member_fd;
	int			 error;
	size_t			 nfds;
	struct component_session_bootstrap bootstrap;
};

struct component_reply_context {
	bool			 done;
	int			 error;
	int			 member_fd;
	uint64_t		 reply_token;
	struct component_session_reply reply;
};

static void *
component_provider_thread(void *argument)
{
	struct component_provider_context *context;
	struct service_component_bootstrap *bootstrap;
	size_t i, nfds;
	int fd;

	context = argument;
	bootstrap = NULL;
	if (service_component_accept(context->fd, &bootstrap) == -1) {
		context->error = errno;
		return (NULL);
	}
	context->bootstrap.instance_id =
	    service_component_instance_id(bootstrap);
	nfds = service_component_resource_count(bootstrap);
	context->nfds = nfds;
	for (i = 0; i < nfds; i++) {
		fd = service_component_take_resource(bootstrap, i);
		if (fd == -1) {
			context->error = errno;
			service_component_abort(bootstrap);
			return (NULL);
		}
		close(fd);
	}
	if (service_component_complete(bootstrap,
	    SERVICE_COMPONENT_MEMBER_PROCDESC, context->member_fd) == -1)
		context->error = errno;
	return (NULL);
}

static void
component_client_reply(struct channel_request *request,
    struct channel_message *message, int error, void *argument)
{
	struct component_reply_context *context;

	context = argument;
	if (error != 0)
		context->error = error;
	else if (channel_message_length(message) != sizeof(context->reply) ||
	    channel_message_fd_count(message) != 1)
		context->error = EPROTO;
	else {
		context->reply_token = channel_message_token(message);
		memcpy(&context->reply, channel_message_data(message),
		    sizeof(context->reply));
		context->member_fd = channel_message_take_fd(message, 0);
		if (context->member_fd == -1)
			context->error = errno;
	}
	if (message != NULL)
		channel_message_free(message);
	channel_request_release(request);
	context->done = true;
}

static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR);
	ATF_REQUIRE(control >= 0);
	memset(&connect, 0, sizeof(connect));
	strlcpy(connect.name, name, sizeof(connect.name));
	if (ioctl(control, MAC_CAPABILITY_CONNECT, &connect) == -1) {
		error = errno;
		close(control);
		errno = error;
		return (-1);
	}
	close(control);
	return (connect.fd);
}

static void
capability_channel_pair(int *first, int *second)
{
	struct mac_capability_recvmsg_args receive;
	struct mac_capability_sendmsg_args send;
	uint32_t op;

	*first = capability_connect("channel");
	ATF_REQUIRE(*first >= 0);
	op = CHANNEL_OP_CREATE;
	memset(&send, 0, sizeof(send));
	send.payload = &op;
	send.payload_len = sizeof(op);
	ATF_REQUIRE(ioctl(*first, MAC_CAPABILITY_SENDMSG, &send) == 0);
	memset(&receive, 0, sizeof(receive));
	receive.fds = second;
	receive.nfds = 1;
	ATF_REQUIRE(ioctl(*first, MAC_CAPABILITY_RECVMSG, &receive) == 0);
	ATF_REQUIRE_EQ(1, receive.nfds);
}

static void *
event_close_thread(void *argument)
{
	struct event_close_context *context;
	struct service_call_options options =
	    SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_reply incoming;
	char byte, event[8];

	context = argument;
	byte = 1;
	ATF_REQUIRE(write(context->started_fd, &byte, sizeof(byte)) ==
	    sizeof(byte));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = event;
	incoming.capacity = sizeof(event);
	errno = 0;
	if (service_session_receive_event(context->client, &incoming,
	    &options) != -1)
		context->error = 0;
	else
		context->error = errno;
	return (NULL);
}

static void
session_provider_request(struct channel *channel,
    struct channel_message *message, void *argument)
{
	static const char large_reply[] = "reply-larger-than-buffer";
	static const char late_reply[] = "late";
	static const char ok_reply[] = "ok";
	struct session_provider_context *context;
	struct channel_outgoing outgoing;
	struct timespec delay;
	const char *data;
	int *fdp;

	(void)channel;
	context = argument;
	if (channel_message_length(message) != 1 ||
	    channel_message_fd_count(message) != 0) {
		context->error = EPROTO;
		channel_message_free(message);
		return;
	}
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	fdp = NULL;
	switch (*(const char *)channel_message_data(message)) {
	case 'L':
		data = large_reply;
		outgoing.length = sizeof(large_reply);
		fdp = &context->large_reply_fd;
		break;
	case 'T':
		delay.tv_sec = 0;
		delay.tv_nsec = 100 * 1000 * 1000;
		(void)nanosleep(&delay, NULL);
		data = late_reply;
		outgoing.length = sizeof(late_reply);
		fdp = &context->late_reply_fd;
		break;
	case 'K':
		data = ok_reply;
		outgoing.length = sizeof(ok_reply);
		break;
	default:
		context->error = EPROTO;
		channel_message_free(message);
		return;
	}
	outgoing.data = data;
	if (fdp != NULL) {
		outgoing.fds = fdp;
		outgoing.nfds = 1;
	}
	if (channel_send_reply(message, &outgoing) == -1)
		context->error = errno;
	if (fdp != NULL && *fdp >= 0) {
		(void)close(*fdp);
		*fdp = -1;
	}
	context->requests++;
	channel_message_free(message);
}

static void *
session_provider_thread(void *argument)
{
	static const char event_data[] = "event-with-fd";
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct session_provider_context *context;
	struct channel_outgoing outgoing;
	struct channel *channel;
	struct pollfd descriptor;
	char ready;
	int result, wants_write;

	context = argument;
	if (channel_create(context->fd, &options, &channel) == -1) {
		context->error = errno;
		return (NULL);
	}
	if (channel_set_request_handler(channel, session_provider_request,
	    context) == -1) {
		context->error = errno;
		channel_destroy(channel);
		return (NULL);
	}
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = event_data;
	outgoing.length = sizeof(event_data);
	outgoing.fds = &context->event_fd;
	outgoing.nfds = 1;
	if (channel_send_event(channel, &outgoing) == -1) {
		context->error = errno;
		channel_destroy(channel);
		return (NULL);
	}
	(void)close(context->event_fd);
	context->event_fd = -1;
	ready = 1;
	if (write(context->ready_fd, &ready, sizeof(ready)) != sizeof(ready)) {
		context->error = errno != 0 ? errno : EIO;
		channel_destroy(channel);
		return (NULL);
	}
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1)
			break;
		memset(&descriptor, 0, sizeof(descriptor));
		descriptor.fd = channel_fd(channel);
		descriptor.events = POLLIN | (wants_write ? POLLOUT : 0);
		do {
			result = poll(&descriptor, 1, 1000);
		} while (result == -1 && errno == EINTR);
		if (result == -1) {
			context->error = errno;
			break;
		}
		if (result == 0)
			continue;
		if ((descriptor.revents & POLLOUT) != 0 &&
		    channel_flush(channel) == -1)
			break;
		if ((descriptor.revents &
		    (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0 &&
		    channel_dispatch(channel) == -1)
			break;
	}
	if (context->error == 0 && errno != ECONNRESET &&
	    errno != ECANCELED && errno != EPIPE)
		context->error = errno;
	channel_destroy(channel);
	return (NULL);
}

static int
install_bootstrap(const struct service_bootstrap *bootstrap, size_t size)
{
	struct envfd_create_options options =
	    ENVFD_CREATE_OPTIONS_INITIALIZER(size);
	ssize_t written;
	int fd;

	options.eco_flags = ENVFD_WRITE_ONCE;
	fd = envfd_create(SERVICE_BOOTSTRAP_ENVFD_NAME, &options);
	if (fd == -1)
		return (-1);
	written = write(fd, bootstrap, size);
	if (written != (ssize_t)size)
		return (-1);
	if (fd != SERVICE_BOOTSTRAP_FD) {
		if (dup2(fd, SERVICE_BOOTSTRAP_FD) != SERVICE_BOOTSTRAP_FD)
			return (-1);
		close(fd);
	}
	return (0);
}

static void
valid_empty_bootstrap(struct service_bootstrap *bootstrap)
{

	memset(bootstrap, 0, sizeof(*bootstrap));
	bootstrap->magic = SERVICE_BOOTSTRAP_MAGIC;
	bootstrap->version = SERVICE_BOOTSTRAP_VERSION;
	bootstrap->header_size = offsetof(struct service_bootstrap, label);
	bootstrap->total_size = sizeof(*bootstrap);
	bootstrap->channel_fd = 3;
	bootstrap->capprotect_fd = -1;
	strlcpy(bootstrap->label, "org.test.bootstrap",
	    sizeof(bootstrap->label));
}

enum bootstrap_case {
	BOOTSTRAP_ABSENT,
	BOOTSTRAP_TRUNCATED,
	BOOTSTRAP_ZERO,
	BOOTSTRAP_VERSION,
	BOOTSTRAP_RESERVED,
	BOOTSTRAP_FLAGS,
	BOOTSTRAP_COUNT,
	BOOTSTRAP_LABEL,
	BOOTSTRAP_UNUSED,
	BOOTSTRAP_CAPPROTECT,
	BOOTSTRAP_TOKEN_LAYOUT,
	BOOTSTRAP_WRITABLE,
	BOOTSTRAP_BAD_CHANNEL,
	BOOTSTRAP_ENV_VALUE,
	BOOTSTRAP_WRONG_TYPE
};

static int
run_bootstrap_case(enum bootstrap_case test_case, int expected_errno)
{
	struct service_bootstrap bootstrap;
	struct service_context *context;
	cap_rights_t rights;
	pid_t pid;
	int fd, status;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(SERVICE_BOOTSTRAP_FD);
		unsetenv(SERVICE_BOOTSTRAP_ENV);
		if (test_case != BOOTSTRAP_ABSENT) {
			if (setenv(SERVICE_BOOTSTRAP_ENV,
			    test_case == BOOTSTRAP_ENV_VALUE ? "4" : "5",
			    1) == -1)
				_exit(6);
			memset(&bootstrap, 0, sizeof(bootstrap));
			if (test_case != BOOTSTRAP_TRUNCATED &&
			    test_case != BOOTSTRAP_ZERO)
				valid_empty_bootstrap(&bootstrap);
			if (test_case == BOOTSTRAP_VERSION)
				bootstrap.version++;
			if (test_case == BOOTSTRAP_RESERVED)
				bootstrap.reserved[3] = 1;
			if (test_case == BOOTSTRAP_FLAGS)
				bootstrap.flags = UINT32_C(0x80000000);
			if (test_case == BOOTSTRAP_COUNT)
				bootstrap.ntokens =
				    SERVICE_BOOTSTRAP_TOKEN_MAX + 1;
			if (test_case == BOOTSTRAP_LABEL)
				memset(bootstrap.label, 'x',
				    sizeof(bootstrap.label));
			if (test_case == BOOTSTRAP_UNUSED)
				bootstrap.token_fds[1] = 42;
			if (test_case == BOOTSTRAP_CAPPROTECT)
				bootstrap.capprotect_fd = 4;
			if (test_case == BOOTSTRAP_TOKEN_LAYOUT) {
				bootstrap.ntokens = 1;
				bootstrap.token_fds[0] = 7;
			}
			if (test_case == BOOTSTRAP_BAD_CHANNEL) {
				fd = open("/dev/null", O_RDONLY);
				if (fd == -1 || dup2(fd, 3) != 3)
					_exit(2);
				if (fd != 3)
					close(fd);
			}
			if (test_case == BOOTSTRAP_WRONG_TYPE) {
				fd = open("/dev/null", O_RDONLY);
				if (fd == -1 ||
				    dup2(fd, SERVICE_BOOTSTRAP_FD) !=
				    SERVICE_BOOTSTRAP_FD)
					_exit(3);
				if (fd != SERVICE_BOOTSTRAP_FD)
					close(fd);
			} else if (install_bootstrap(&bootstrap,
			    test_case == BOOTSTRAP_TRUNCATED ? 1 :
			    sizeof(bootstrap)) == -1)
				_exit(3);
			if (test_case == BOOTSTRAP_BAD_CHANNEL) {
				cap_rights_init(&rights, CAP_READ, CAP_FSTAT,
				    CAP_IOCTL);
				if (cap_rights_limit(SERVICE_BOOTSTRAP_FD,
				    &rights) == -1 ||
				    cap_ioctls_limit(SERVICE_BOOTSTRAP_FD,
				    (const unsigned long[]){ ENVFD_GETINFO },
				    1) == -1)
					_exit(5);
			}
		}
		errno = 0;
		if (service_acquire(&context) != -1 || errno != expected_errno)
			_exit(4);
		errno = 0;
		if (service_acquire(&context) != -1 || errno != expected_errno)
			_exit(7);
		errno = 0;
		_exit(service_acquire(&context) == -1 &&
		    errno == expected_errno ? 0 : 8);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	return (WIFEXITED(status) ? WEXITSTATUS(status) : 255);
}

ATF_TC(shared_context);
ATF_TC_HEAD(shared_context, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "service contexts initialize once, support independent library borrows, and reject inherited authority after fork");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(shared_context, tc)
{
	struct service_bootstrap bootstrap;
	struct service_context *first, *second;
	struct service_provider *provider;
	pid_t child, grandchild;
	int channel[2], status;

	(void)tc;
	capability_channel_pair(&channel[0], &channel[1]);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (dup2(channel[0], 3) != 3)
			_exit(1);
		if (channel[0] != 3)
			close(channel[0]);
		close(channel[1]);
		close(SERVICE_BOOTSTRAP_FD);
		valid_empty_bootstrap(&bootstrap);
		if (setenv(SERVICE_BOOTSTRAP_ENV, "5", 1) == -1 ||
		    install_bootstrap(&bootstrap, sizeof(bootstrap)) == -1)
			_exit(2);
		if (service_acquire(&first) == -1 ||
		    service_acquire(&second) == -1 || first != second)
			_exit(3);
		errno = 0;
		if (service_local_component_open(first, "org.5bsd.filesystem",
		    "2.0.0", &channel[0]) != -1 ||
		    errno != EPROTONOSUPPORT)
			_exit(11);
		errno = 0;
		if (service_local_component_open(first, "org.test.unknown",
		    "1.0.0", &channel[0]) != -1 || errno != ENOENT)
			_exit(12);
		errno = 0;
		if (service_local_component_open(first, "org.5bsd.filesystem",
		    "1.0.0", &channel[0]) != -1 || errno != ENOENT)
			_exit(13);
		if (service_provider_create(&provider) == -1)
			_exit(9);
		errno = 0;
		if (service_provider_ready(provider) != -1 || errno != EPERM)
			_exit(10);
		service_provider_destroy(provider);
		service_release(first);
		if (service_acquire(&first) == -1)
			_exit(4);
		service_release(first);
		grandchild = fork();
		if (grandchild == -1)
			_exit(5);
		if (grandchild == 0) {
			errno = 0;
			_exit(service_acquire(&first) == -1 &&
			    errno == ECHILD ? 0 : 1);
		}
		if (waitpid(grandchild, &status, 0) != grandchild ||
		    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
			_exit(6);
		service_release(second);
		_exit(0);
	}
	close(channel[0]);
	close(channel[1]);
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

ATF_TC(bootstrap_validation);
ATF_TC_HEAD(bootstrap_validation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "service_acquire rejects absent, truncated, malformed, and wrongly typed bootstrap descriptors");
}
ATF_TC_BODY(bootstrap_validation, tc)
{
	(void)tc;
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_ABSENT, EBADF));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_TRUNCATED, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_ZERO, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_VERSION, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_RESERVED, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_FLAGS, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_COUNT, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_LABEL, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_UNUSED, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_CAPPROTECT, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_TOKEN_LAYOUT, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_WRITABLE, EINVAL));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_BAD_CHANNEL, EINVAL));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_ENV_VALUE, EPROTO));
	ATF_CHECK_EQ(0, run_bootstrap_case(BOOTSTRAP_WRONG_TYPE, EINVAL));
}

ATF_TC(api_rejects_invalid_descriptors_and_arguments);
ATF_TC_HEAD(api_rejects_invalid_descriptors_and_arguments, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "libservice validates descriptor types, arguments, and payload sizes");
}

ATF_TC_BODY(api_rejects_invalid_descriptors_and_arguments, tc)
{
	struct service_component_bootstrap *component_bootstrap;
	struct service_listener *listener;
	struct service_session *session;
	int fd;

	(void)tc;
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    service_authorize_capabilities(NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_supervisor_fd(NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_supervisor_status(NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    service_provider_expose(NULL, "org.test", &listener) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    service_provider_worker_channel(NULL, &fd, &fd) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_provider_quiescing(NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    service_provider_quiesce_complete(NULL, 0) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_listener_close(NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_connect(NULL, NULL, &fd) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    service_component_accept(-1, &component_bootstrap) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_component_accept(fd, NULL) == -1);
	errno = 0;
	ATF_CHECK(service_session_create(fd, &session) == -1);
	ATF_CHECK(fcntl(fd, F_GETFD) != -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_session_fail(NULL, EPROTO) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    service_component_complete(NULL,
	    SERVICE_COMPONENT_MEMBER_PROCDESC, -1) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    service_component_fail(NULL, EACCES) == -1);
	close(fd);
}

ATF_TC(component_bootstrap_roundtrip);
ATF_TC_HEAD(component_bootstrap_roundtrip, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "component bootstrap keeps semantic instance identity separate from channel correlation and preserves attachment order");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}

ATF_TC_BODY(component_bootstrap_roundtrip, tc)
{
	struct channel_options channel_options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
	struct component_session_bootstrap message;
	struct component_provider_context provider;
	struct component_reply_context reply;
	struct channel_request *request;
	struct channel *channel;
	struct pollfd descriptor;
	pthread_t thread;
	int endpoints[2], member[2], resource[2], result, wants_write;

	(void)tc;
	capability_channel_pair(&endpoints[0], &endpoints[1]);
	ATF_REQUIRE(pipe(member) == 0);
	ATF_REQUIRE(pipe(resource) == 0);
	memset(&provider, 0, sizeof(provider));
	provider.fd = endpoints[1];
	provider.member_fd = member[0];
	ATF_REQUIRE_EQ(0, pthread_create(&thread, NULL,
	    component_provider_thread, &provider));
	ATF_REQUIRE(channel_create(endpoints[0], &channel_options, &channel) ==
	    0);
	memset(&message, 0, sizeof(message));
	message.magic = COMPONENT_SESSION_MAGIC;
	message.version = COMPONENT_SESSION_VERSION;
	message.header_size = sizeof(message);
	message.instance_id = UINT64_C(0x1122334455667788);
	strlcpy(message.name, "filesystem", sizeof(message.name));
	strlcpy(message.interface, "org.5bsd.component.filesystem",
	    sizeof(message.interface));
	strlcpy(message.interface_version, "1.0.0",
	    sizeof(message.interface_version));
	strlcpy(message.client_label, "org.test.component-client",
	    sizeof(message.client_label));
	memset(&reply, 0, sizeof(reply));
	reply.member_fd = -1;
	ATF_REQUIRE(channel_send_request(channel,
	    &(struct channel_outgoing){
		.size = sizeof(struct channel_outgoing),
		.data = &message,
		.length = sizeof(message),
		.fds = &resource[0],
		.nfds = 1
	    }, component_client_reply, &reply, &request) == 0);
	while (!reply.done) {
		wants_write = channel_wants_write(channel);
		ATF_REQUIRE(wants_write >= 0);
		memset(&descriptor, 0, sizeof(descriptor));
		descriptor.fd = channel_fd(channel);
		descriptor.events = POLLIN | (wants_write ? POLLOUT : 0);
		do {
			result = poll(&descriptor, 1, 5000);
		} while (result == -1 && errno == EINTR);
		ATF_REQUIRE(result > 0);
		if ((descriptor.revents & POLLOUT) != 0)
			ATF_REQUIRE(channel_flush(channel) == 0);
		if ((descriptor.revents &
		    (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0)
			ATF_REQUIRE(channel_dispatch(channel) == 0);
	}
	ATF_REQUIRE_EQ(0, pthread_join(thread, NULL));
	ATF_CHECK_EQ(0, provider.error);
	ATF_CHECK_EQ(1, provider.nfds);
	ATF_CHECK_EQ(message.instance_id,
	    provider.bootstrap.instance_id);
	ATF_CHECK_EQ(0, reply.error);
	ATF_CHECK(reply.member_fd >= 0);
	ATF_CHECK(reply.reply_token != 0);
	ATF_CHECK(reply.reply_token != message.instance_id);
	ATF_CHECK_EQ(message.instance_id, reply.reply.instance_id);
	ATF_CHECK_EQ(COMPONENT_SESSION_MEMBER_PROCDESC,
	    reply.reply.member_type);
	close(reply.member_fd);
	channel_destroy(channel);
	close(endpoints[1]);
	close(member[0]);
	close(member[1]);
	close(resource[0]);
	close(resource[1]);
}

static int
reject_component_bootstrap(const void *payload, size_t length)
{
	struct mac_capability_sendmsg_args send;
	struct component_provider_context provider;
	pthread_t thread;
	int endpoints[2], error;

	capability_channel_pair(&endpoints[0], &endpoints[1]);
	memset(&provider, 0, sizeof(provider));
	provider.fd = endpoints[1];
	provider.member_fd = -1;
	ATF_REQUIRE_EQ(0, pthread_create(&thread, NULL,
	    component_provider_thread, &provider));
	memset(&send, 0, sizeof(send));
	send.payload = payload;
	send.payload_len = length;
	send.reply_token = 1;
	ATF_REQUIRE(ioctl(endpoints[0], MAC_CAPABILITY_SENDMSG, &send) == 0);
	ATF_REQUIRE_EQ(0, pthread_join(thread, NULL));
	error = provider.error;
	close(endpoints[0]);
	close(endpoints[1]);
	return (error);
}

ATF_TC(component_bootstrap_rejects_obsolete_and_malformed_fields);
ATF_TC_HEAD(component_bootstrap_rejects_obsolete_and_malformed_fields, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "component bootstrap rejects obsolete trailing options, reserved "
	    "fields, versions, and unterminated identity fields");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}

ATF_TC_BODY(component_bootstrap_rejects_obsolete_and_malformed_fields, tc)
{
	struct {
		struct component_session_bootstrap header;
		uint32_t obsolete_options;
	} extended;
	struct component_session_bootstrap message;

	(void)tc;
	memset(&message, 0, sizeof(message));
	message.magic = COMPONENT_SESSION_MAGIC;
	message.version = COMPONENT_SESSION_VERSION;
	message.header_size = sizeof(message);
	message.instance_id = 1;
	strlcpy(message.name, "filesystem", sizeof(message.name));
	strlcpy(message.interface, "org.5bsd.component.filesystem",
	    sizeof(message.interface));
	strlcpy(message.interface_version, "1.0.0",
	    sizeof(message.interface_version));
	strlcpy(message.client_label, "org.test.client",
	    sizeof(message.client_label));

	message.version--;
	ATF_CHECK_EQ(EPROTO,
	    reject_component_bootstrap(&message, sizeof(message)));
	message.version = COMPONENT_SESSION_VERSION;
	message.reserved[0] = 1;
	ATF_CHECK_EQ(EPROTO,
	    reject_component_bootstrap(&message, sizeof(message)));
	message.reserved[0] = 0;
	memset(message.interface, 'x', sizeof(message.interface));
	ATF_CHECK_EQ(EPROTO,
	    reject_component_bootstrap(&message, sizeof(message)));

	memset(&extended, 0, sizeof(extended));
	extended.header = message;
	strlcpy(extended.header.interface, "org.5bsd.component.filesystem",
	    sizeof(extended.header.interface));
	extended.obsolete_options = 3;
	ATF_CHECK_EQ(EPROTO,
	    reject_component_bootstrap(&extended, sizeof(extended)));
}

ATF_TC(component_bootstrap_timeout);
ATF_TC_HEAD(component_bootstrap_timeout, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a connected peer that never bootstraps cannot pin a component factory");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "timeout", "15");
}

ATF_TC_BODY(component_bootstrap_timeout, tc)
{
	struct service_component_bootstrap *bootstrap;
	struct timespec before, after;
	int endpoints[2], saved_errno;
	double elapsed;

	(void)tc;
	capability_channel_pair(&endpoints[0], &endpoints[1]);
	ATF_REQUIRE(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
	errno = 0;
	ATF_CHECK(service_component_accept(endpoints[1], &bootstrap) == -1);
	saved_errno = errno;
	ATF_REQUIRE(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
	elapsed = after.tv_sec - before.tv_sec +
	    (after.tv_nsec - before.tv_nsec) / 1000000000.0;
	ATF_CHECK_EQ(ETIMEDOUT, saved_errno);
	ATF_CHECK(elapsed >= 1.5);
	ATF_CHECK(elapsed < 5.0);
	close(endpoints[0]);
	close(endpoints[1]);
}

ATF_TC(service_session_lifecycle);
ATF_TC_HEAD(service_session_lifecycle, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "multiplexed client owns its channel, rejects invalid calls, and fails closed after fork");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}

ATF_TC_BODY(service_session_lifecycle, tc)
{
	struct event_close_context context;
	struct service_call_options options =
	    SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_session *client;
	pthread_t thread;
	char reply[8];
	pid_t child;
	int fd, peer, started[2], status;

	(void)tc;
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_session_create(-1, &client) == -1);
	service_session_close(NULL);
	capability_channel_pair(&fd, &peer);
	ATF_REQUIRE_EQ(0, service_session_create(fd, &client));
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.length = 1;
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 0;
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_session_call(client, &outgoing,
	    &incoming, &options) == -1);
	ATF_REQUIRE_EQ(0, service_session_fail(client, EPROTO));
	errno = 0;
	ATF_CHECK_ERRNO(EPROTO,
	    test_session_call(client, "x", 1, reply, sizeof(reply), 0,
	    NULL) == -1);
	/* A later invalidation cannot disguise the first protocol failure. */
	ATF_REQUIRE_EQ(0, service_session_fail(client, EIO));
	errno = 0;
	ATF_CHECK_ERRNO(EPROTO,
	    test_session_call(client, "x", 1, reply, sizeof(reply), 0,
	    NULL) == -1);
	service_session_close(client);
	close(peer);
	capability_channel_pair(&fd, &peer);
	ATF_REQUIRE_EQ(0, service_session_create(fd, &client));
	ATF_REQUIRE(pipe(started) == 0);
	memset(&context, 0, sizeof(context));
	context.client = client;
	context.started_fd = started[1];
	ATF_REQUIRE_EQ(0, pthread_create(&thread, NULL, event_close_thread,
	    &context));
	ATF_REQUIRE(read(started[0], reply, 1) == 1);
	/*
	 * Fork while another thread is dispatching the same client.  The
	 * atfork registry must quiesce both mutex domains and abandon child
	 * authority without running the vanished thread's callbacks.
	 */
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		errno = 0;
		if (test_session_call(client, "x", 1, reply, sizeof(reply), 0,
		    NULL) != -1 ||
		    errno != ECHILD)
			_exit(1);
		service_session_close(client);
		_exit(0);
	}
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	service_session_close(client);
	ATF_REQUIRE_EQ(0, pthread_join(thread, NULL));
	ATF_CHECK_EQ(ECANCELED, context.error);
	errno = 0;
	ATF_CHECK_ERRNO(EBADF, fcntl(fd, F_GETFD) == -1);
	close(started[0]);
	close(started[1]);
	close(peer);
}

ATF_TC(service_session_payload_and_attachment_lifecycle);
ATF_TC_HEAD(service_session_payload_and_attachment_lifecycle, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "managed sessions report reply sizes, retain retryable events, discard late replies, and close unclaimed descriptors");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "timeout", "15");
}

ATF_TC_BODY(service_session_payload_and_attachment_lifecycle, tc)
{
	struct service_call_options options =
	    SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct session_provider_context provider;
	struct service_session *session;
	struct timespec timeout_after, timeout_before;
	pthread_t thread;
	char byte, event[32], reply[64], small[4];
	int channel[2], event_pipe[2], large_pipe[2], late_pipe[2];
	int ready_pipe[2], received_fd, flags;
	size_t received;

	(void)tc;
	capability_channel_pair(&channel[0], &channel[1]);
	ATF_REQUIRE(pipe(event_pipe) == 0);
	ATF_REQUIRE(pipe(large_pipe) == 0);
	ATF_REQUIRE(pipe(late_pipe) == 0);
	ATF_REQUIRE(pipe(ready_pipe) == 0);
	flags = fcntl(event_pipe[0], F_GETFL);
	ATF_REQUIRE(flags != -1);
	ATF_REQUIRE(fcntl(event_pipe[0], F_SETFL, flags | O_NONBLOCK) == 0);
	flags = fcntl(large_pipe[0], F_GETFL);
	ATF_REQUIRE(flags != -1);
	ATF_REQUIRE(fcntl(large_pipe[0], F_SETFL, flags | O_NONBLOCK) == 0);
	flags = fcntl(late_pipe[0], F_GETFL);
	ATF_REQUIRE(flags != -1);
	ATF_REQUIRE(fcntl(late_pipe[0], F_SETFL, flags | O_NONBLOCK) == 0);

	memset(&provider, 0, sizeof(provider));
	provider.fd = channel[1];
	provider.ready_fd = ready_pipe[1];
	provider.event_fd = event_pipe[1];
	provider.large_reply_fd = large_pipe[1];
	provider.late_reply_fd = late_pipe[1];
	ATF_REQUIRE_EQ(0, pthread_create(&thread, NULL,
	    session_provider_thread, &provider));
	ATF_REQUIRE_EQ(0, service_session_create(channel[0], &session));
	ATF_REQUIRE(read(ready_pipe[0], &byte, sizeof(byte)) == sizeof(byte));

	/*
	 * The provider queued this event before publishing readiness.  A zero
	 * timeout must still perform one nonblocking channel dispatch.
	 */
	options.timeout_ms = 0;
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = small;
	incoming.capacity = sizeof(small);
	errno = 0;
	ATF_CHECK_ERRNO(EMSGSIZE,
	    service_session_receive_event(session, &incoming, &options) == -1);
	ATF_CHECK_EQ(sizeof("event-with-fd"), incoming.length);
	ATF_CHECK_EQ(1, incoming.nfds);
	errno = 0;
	ATF_CHECK_ERRNO(EAGAIN,
	    read(event_pipe[0], &byte, sizeof(byte)) == -1);

	options.timeout_ms = 2000;
	received_fd = -1;
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = event;
	incoming.capacity = sizeof(event);
	incoming.fds = &received_fd;
	incoming.fd_capacity = 1;
	ATF_REQUIRE_EQ(0,
	    service_session_receive_event(session, &incoming, &options));
	ATF_CHECK_EQ(sizeof("event-with-fd"), incoming.length);
	ATF_CHECK_EQ(1, incoming.nfds);
	ATF_CHECK_STREQ("event-with-fd", event);
	ATF_REQUIRE(received_fd >= 0);
	close(received_fd);
	ATF_CHECK_EQ(0, read(event_pipe[0], &byte, sizeof(byte)));

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = "L";
	outgoing.length = 1;
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = small;
	incoming.capacity = sizeof(small);
	errno = 0;
	ATF_CHECK_ERRNO(EMSGSIZE,
	    service_session_call(session, &outgoing, &incoming, &options) ==
	    -1);
	ATF_CHECK_EQ(sizeof("reply-larger-than-buffer"), incoming.length);
	ATF_CHECK_EQ(1, incoming.nfds);
	ATF_CHECK_EQ(0, read(large_pipe[0], &byte, sizeof(byte)));

	errno = 0;
	ATF_REQUIRE(clock_gettime(CLOCK_MONOTONIC, &timeout_before) == 0);
	ATF_CHECK_ERRNO(ETIMEDOUT,
	    test_session_call(session, "T", 1, reply, sizeof(reply), 10,
	    NULL) == -1);
	ATF_REQUIRE(clock_gettime(CLOCK_MONOTONIC, &timeout_after) == 0);
	ATF_CHECK_MSG(timeout_after.tv_sec - timeout_before.tv_sec +
	    (timeout_after.tv_nsec - timeout_before.tv_nsec) / 1000000000.0 <
	    0.075, "10 ms call deadline exceeded its scheduling allowance");
	ATF_REQUIRE_EQ(0,
	    test_session_call(session, "K", 1, reply, sizeof(reply), 2000,
	    &received));
	ATF_CHECK_EQ(sizeof("ok"), received);
	ATF_CHECK_STREQ("ok", reply);
	ATF_CHECK_EQ(0, read(late_pipe[0], &byte, sizeof(byte)));

	service_session_close(session);
	ATF_REQUIRE_EQ(0, pthread_join(thread, NULL));
	ATF_CHECK_EQ(0, provider.error);
	ATF_CHECK_EQ(3, provider.requests);
	close(event_pipe[0]);
	close(large_pipe[0]);
	close(late_pipe[0]);
	close(ready_pipe[0]);
	close(ready_pipe[1]);
}

ATF_TC(service_session_close_cancels_event);
ATF_TC_HEAD(service_session_close_cancels_event, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "closing a managed channel safely cancels and joins an active event waiter");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}

ATF_TC_BODY(service_session_close_cancels_event, tc)
{
	struct event_close_context context;
	struct service_session *client;
	pthread_t thread;
	char byte;
	int channel[2], started[2];

	(void)tc;
	capability_channel_pair(&channel[0], &channel[1]);
	ATF_REQUIRE(pipe(started) == 0);
	ATF_REQUIRE_EQ(0, service_session_create(channel[0], &client));
	memset(&context, 0, sizeof(context));
	context.client = client;
	context.started_fd = started[1];
	ATF_REQUIRE_EQ(0, pthread_create(&thread, NULL, event_close_thread,
	    &context));
	ATF_REQUIRE(read(started[0], &byte, sizeof(byte)) == sizeof(byte));
	service_session_close(client);
	ATF_REQUIRE_EQ(0, pthread_join(thread, NULL));
	ATF_CHECK_EQ(ECANCELED, context.error);
	close(channel[1]);
	close(started[0]);
	close(started[1]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, bootstrap_validation);
	ATF_TP_ADD_TC(tp, shared_context);
	ATF_TP_ADD_TC(tp, api_rejects_invalid_descriptors_and_arguments);
	ATF_TP_ADD_TC(tp, component_bootstrap_roundtrip);
	ATF_TP_ADD_TC(tp,
	    component_bootstrap_rejects_obsolete_and_malformed_fields);
	ATF_TP_ADD_TC(tp, component_bootstrap_timeout);
	ATF_TP_ADD_TC(tp, service_session_lifecycle);
	ATF_TP_ADD_TC(tp, service_session_payload_and_attachment_lifecycle);
	ATF_TP_ADD_TC(tp, service_session_close_cancels_event);
	return (atf_no_error());
}
