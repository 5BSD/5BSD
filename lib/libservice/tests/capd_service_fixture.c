/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Deterministic managed-service fixture for capability stack tests.
 */

#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <channel.h>
#include <capability.h>
#include <libservice.h>
#include <service_bootstrap.h>
#include <service_private.h>
#include <serviced_svc_proto.h>

static struct service_context *fixture_service_context;
static struct service_provider *fixture_service_provider;

static char result_cwd[PATH_MAX];
static int result_dir_fd = -1;

static int
fixture_service_initialize(void)
{
	int error, fd;

	if (fixture_service_context != NULL)
		return (0);
	if (service_acquire(&fixture_service_context) == -1)
		goto fail;
	if (service_provider_create(&fixture_service_provider) == -1) {
		error = errno;
		service_release(fixture_service_context);
		fixture_service_context = NULL;
		errno = error;
		goto fail;
	}
	return (0);
fail:
	/* Leave a diagnostic the harness file listing will surface even
	 * though our stderr is discarded. */
	error = errno;
	if (result_dir_fd >= 0)
		fd = openat(result_dir_fd, "fixture-init-failure.result",
		    O_WRONLY | O_CREAT | O_APPEND, 0644);
	else
		fd = open("fixture-init-failure.result",
		    O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd >= 0) {
		dprintf(fd, "pid=%d step=init errno=%d\n", (int)getpid(),
		    error);
		close(fd);
	}
	errno = error;
	return (-1);
}

static int
fixture_service_connect(const char *name)
{
	int fd;

	if (service_connect(fixture_service_context, name, &fd) == -1)
		return (-1);
	return (fd);
}

static int
fixture_service_supervisor_fd(void)
{

	return (service_supervisor_fd(fixture_service_context));
}

static int
fixture_service_supervisor_status(void)
{

	return (service_supervisor_status(fixture_service_context));
}

static int
fixture_service_channel_fd(void)
{

	return (service_private_control_fd(fixture_service_context));
}

static const char *
fixture_service_label(void)
{

	return (service_label(fixture_service_context));
}

static int
fixture_service_capability_open(const char *name, const char *type, int *fd)
{

	return (service_capability_open(fixture_service_context, name, type, fd));
}

static int
fixture_service_ready(void)
{
	const char *step;
	int error, fd;

	step = "capmode";
	if (service_provider_enter_capability_mode(fixture_service_provider) ==
	    -1)
		goto fail;
	step = "ready";
	if (service_provider_ready(fixture_service_provider) == -1)
		goto fail;
	return (0);
fail:
	error = errno;
	if (result_dir_fd >= 0)
		fd = openat(result_dir_fd, "fixture-init-failure.result",
		    O_WRONLY | O_CREAT | O_APPEND, 0644);
	else
		fd = open("fixture-init-failure.result",
		    O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd >= 0) {
		dprintf(fd, "pid=%d step=%s errno=%d\n", (int)getpid(), step,
		    error);
		close(fd);
	}
	errno = error;
	return (-1);
}

struct event_receive {
	void	*data;
	size_t	 capacity;
	ssize_t	 length;
	int	 error;
};

static void
receive_event(struct channel *channel __unused,
    struct channel_message *message, void *argument)
{
	struct event_receive *receive;

	receive = argument;
	if (channel_message_fd_count(message) != 0 ||
	    channel_message_length(message) > receive->capacity)
		receive->error = EMSGSIZE;
	else {
		memcpy(receive->data, channel_message_data(message),
		    channel_message_length(message));
		receive->length = (ssize_t)channel_message_length(message);
	}
	channel_message_free(message);
}

static int
pump_channel(struct channel *channel, bool until_event,
    struct event_receive *receive)
{
	int result, wants_write;

	for (;;) {
		if (until_event && (receive->length >= 0 || receive->error != 0))
			return (receive->error == 0 ? 0 : -1);
		wants_write = channel_wants_write(channel);
		if (wants_write == -1)
			return (-1);
		if (!until_event && !wants_write)
			return (0);
		result = channel_wait(channel, wants_write, 5000);
		if (result == 0) {
			errno = ETIMEDOUT;
			return (-1);
		}
		if (result == -1 ||
		    ((result & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(channel) == -1) ||
		    ((result & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(channel) == -1))
			return (-1);
	}
}

static int
fixture_event_send(int fd, const void *data, size_t length)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
	struct channel *channel;
	int owned, result;

	owned = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (owned == -1)
		return (-1);
	if (channel_create(owned, &options, &channel) == -1) {
		result = errno;
		close(owned);
		errno = result;
		return (-1);
	}
	result = channel_send_event(channel, &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(data, length));
	if (result == 0)
		result = pump_channel(channel, false, NULL);
	channel_destroy(channel);
	return (result);
}

static ssize_t
fixture_event_recv(int fd, void *data, size_t capacity)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
	struct event_receive receive;
	struct channel *channel;
	int error, owned;

	owned = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (owned == -1)
		return (-1);
	if (channel_create(owned, &options, &channel) == -1) {
		error = errno;
		close(owned);
		errno = error;
		return (-1);
	}
	memset(&receive, 0, sizeof(receive));
	receive.data = data;
	receive.capacity = capacity;
	receive.length = -1;
	if (channel_set_event_handler(channel, receive_event, &receive) == -1 ||
	    pump_channel(channel, true, &receive) == -1) {
		error = receive.error != 0 ? receive.error : errno;
		channel_destroy(channel);
		errno = error;
		return (-1);
	}
	channel_destroy(channel);
	return (receive.length);
}

static volatile sig_atomic_t enter_requested;

static ssize_t
fixture_session_call(struct service_session *session, const void *request,
    size_t request_length, void *reply, size_t reply_capacity,
    uint32_t timeout_ms)
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
	return ((ssize_t)incoming.length);
}

static ssize_t
fixture_session_event(struct service_session *session, void *event,
    size_t event_capacity, struct service_message_metadata *metadata,
    uint32_t timeout_ms)
{
	struct service_call_options options =
	    SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_reply incoming;

	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = event;
	incoming.capacity = event_capacity;
	options.timeout_ms = timeout_ms;
	if (service_session_receive_event(session, &incoming, &options) == -1)
		return (-1);
	if (metadata != NULL)
		*metadata = incoming.metadata;
	return ((ssize_t)incoming.length);
}

static void
request_capmode(int signal __unused)
{

	enter_requested = 1;
}

static int
legacy_ready_only(void)
{
	struct service_session *client;
	struct svc_req_hdr req;
	struct svc_reply reply;
	ssize_t received;
	int fd;

	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_READY;
	fd = fcntl(fixture_service_channel_fd(), F_DUPFD_CLOEXEC, 0);
	if (fd == -1)
		return (-1);
	if (service_session_create(fd, &client) == -1) {
		int error;

		error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	memset(&reply, 0, sizeof(reply));
	received = fixture_session_call(client, &req, sizeof(req), &reply,
	    sizeof(reply), 5000);
	service_session_close(client);
	if (received != sizeof(reply)) {
		if (received >= 0)
			errno = EPROTO;
		return (-1);
	}
	if (reply.status != 0) {
		errno = reply.status;
		return (-1);
	}
	return (0);
}

static int
legacy_status_request(const void *request, size_t request_length)
{
	struct service_session *client;
	struct svc_reply reply;
	ssize_t received;
	int fd;

	fd = fcntl(fixture_service_channel_fd(), F_DUPFD_CLOEXEC, 0);
	if (fd == -1)
		return (-1);
	if (service_session_create(fd, &client) == -1) {
		int error;

		error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	memset(&reply, 0, sizeof(reply));
	received = fixture_session_call(client, request, request_length, &reply,
	    sizeof(reply), 5000);
	service_session_close(client);
	if (received != sizeof(reply)) {
		if (received >= 0)
			errno = EPROTO;
		return (-1);
	}
	return (reply.status);
}

static int
legacy_name_request(uint32_t op, const char *name)
{
	struct svc_name_claim_req claim;
	struct svc_name_withdraw_req withdraw;

	switch (op) {
	case SVC_OP_NAME_CLAIM:
		memset(&claim, 0, sizeof(claim));
		claim.op = op;
		strlcpy(claim.name, name, sizeof(claim.name));
		return (legacy_status_request(&claim, sizeof(claim)));
	case SVC_OP_NAME_WITHDRAW:
		memset(&withdraw, 0, sizeof(withdraw));
		withdraw.op = op;
		strlcpy(withdraw.name, name, sizeof(withdraw.name));
		return (legacy_status_request(&withdraw, sizeof(withdraw)));
	default:
		errno = EINVAL;
		return (-1);
	}
}

static int
legacy_name_result(const char *name, int status)
{
	struct svc_name_result_req result;

	memset(&result, 0, sizeof(result));
	result.op = SVC_OP_NAME_RESULT;
	result.status = status;
	strlcpy(result.name, name, sizeof(result.name));
	return (legacy_status_request(&result, sizeof(result)));
}

static void
prepare_results(void)
{

	if (getcwd(result_cwd, sizeof(result_cwd)) == NULL)
		err(1, "getcwd");
	result_dir_fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (result_dir_fd == -1)
		err(1, "open current directory");
}

static void
write_result(const char *path, const char *format, ...)
{
	va_list ap;
	FILE *out;
	const char *relative;
	int fd;

	relative = path;
	if (path[0] == '/' &&
	    strncmp(path, result_cwd, strlen(result_cwd)) == 0 &&
	    path[strlen(result_cwd)] == '/')
		relative = path + strlen(result_cwd) + 1;
	fd = openat(result_dir_fd, relative,
	    O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		err(1, "openat %s", path);
	out = fdopen(fd, "w");
	if (out == NULL)
		err(1, "fdopen %s", path);
	va_start(ap, format);
	if (vfprintf(out, format, ap) < 0)
		err(1, "write %s", path);
	va_end(ap);
	if (fclose(out) == EOF)
		err(1, "close %s", path);
}

/*
 * Record a failure reason into the scenario's result file before exiting.
 * Service-launched fixtures have no visible stderr (serviced discards it), so
 * err()/errx() diagnostics are lost; this surfaces the reason to the test.
 */
static void fixture_fail(const char *result, const char *fmt, ...) __dead2;
static void
fixture_fail(const char *result, const char *fmt, ...)
{
	va_list ap;
	char detail[224];
	int saved_errno;

	saved_errno = errno;
	va_start(ap, fmt);
	(void)vsnprintf(detail, sizeof(detail), fmt, ap);
	va_end(ap);
	write_result(result, "event=fixture-error errno=%d detail=%s\n",
	    saved_errno, detail);
	_exit(1);
}

static void hold(void) __dead2;
static void
hold(void)
{

	for (;;)
		pause();
}

static void
require_confined_endpoint(int fd)
{

	/*
	 * A delivered endpoint has already been attenuated: the client end to
	 * CAP_XFER_NONE, the provider end to CAP_XFER_ONCE (it may still hand
	 * off to one worker).  Neither may be raised back toward the maximal
	 * transfer budget; cap_xfer_limit only reduces, so requesting
	 * CAP_XFER_TWICE must fail with ENOTCAPABLE for both.
	 */
	errno = 0;
	if (cap_xfer_limit(fd, CAP_XFER_TWICE) != -1 || errno != ENOTCAPABLE)
		errx(1, "peer endpoint is not transfer-confined");
}

struct accept_result {
	char	label[128];
	char	service_name[256];
	struct service_listener *listener;
	int	fd;
	int	error;
};

struct mux_call {
	struct service_session	*client;
	char			 request[16];
	char			 reply[16];
	ssize_t			 received;
	int			 error;
};

struct mux_provider {
	struct channel_message	*requests[3];
	size_t			 count;
	int			 error;
};

static void
mux_request(struct channel *channel __unused,
    struct channel_message *message, void *argument)
{
	struct mux_provider *provider;

	provider = argument;
	if (provider->count == nitems(provider->requests) ||
	    channel_message_fd_count(message) != 0 ||
	    channel_message_length(message) == 0 ||
	    ((const char *)channel_message_data(message))
	    [channel_message_length(message) - 1] != '\0') {
		provider->error = EPROTO;
		channel_message_free(message);
		return;
	}
	provider->requests[provider->count++] = message;
}

struct activation_state {
	const char	*name;
	unsigned	 calls;
};

static int
activation_callback(const char *name, void *argument)
{
	struct activation_state *state;

	state = argument;
	if (strcmp(name, state->name) != 0)
		return (EPROTO);
	(void)__atomic_add_fetch(&state->calls, 1, __ATOMIC_SEQ_CST);
	return (0);
}

static void *
accept_thread(void *argument)
{
	struct accept_result *result;

	result = argument;
	struct service_identity identity = {
		.size = sizeof(identity)
	};

	if (service_listener_accept(result->listener, &identity,
	    &result->fd) == -1)
		result->fd = -1;
	if (result->fd != -1)
		strlcpy(result->label, identity.client_label,
		    sizeof(result->label));
	if (result->fd != -1)
		strlcpy(result->service_name, identity.service_name,
		    sizeof(result->service_name));
	result->error = result->fd == -1 ? errno : 0;
	return (NULL);
}

static void *
mux_call_thread(void *argument)
{
	struct mux_call *call;
	call = argument;
	call->received = fixture_session_call(call->client, call->request,
	    strlen(call->request) + 1, call->reply, sizeof(call->reply), 5000);
	call->error = call->received == -1 ? errno : 0;
	return (NULL);
}

static int
scenario_mux_provider(const char *result)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct mux_provider provider;
	struct service_identity identity;
	struct service_listener *listener;
	struct channel *channel;
	const char *request;
	int client, i, poll_result, wants_write;

	if (fixture_service_initialize() == -1 ||
	    service_provider_expose(fixture_service_provider, "org.test.transport-mux", &listener) == -1 ||
	    fixture_service_ready() == -1)
		err(1, "mux provider initialization");
	memset(&identity, 0, sizeof(identity));
	identity.size = sizeof(identity);
	if (service_listener_accept(listener, &identity, &client) == -1)
		err(1, "mux provider accept");
	if (channel_create(client, &options, &channel) == -1)
		err(1, "channel_create");
	memset(&provider, 0, sizeof(provider));
	if (channel_set_request_handler(channel, mux_request, &provider) == -1)
		err(1, "channel_set_request_handler");
	while (provider.count != nitems(provider.requests)) {
		poll_result = channel_wait(channel, 0, 5000);
		if (poll_result <= 0 || channel_dispatch(channel) == -1)
			err(1, "mux request dispatch");
		if (provider.error != 0)
			errx(1, "invalid multiplexed request");
	}
	if (channel_send_event(channel, &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER("event", 6)) == -1)
		err(1, "mux event");
	for (i = 2; i >= 0; i--) {
		request = channel_message_data(provider.requests[i]);
		if (channel_send_reply(provider.requests[i],
		    &(struct channel_outgoing)CHANNEL_OUTGOING_INITIALIZER(
		    request, channel_message_length(provider.requests[i]))) ==
		    -1)
			err(1, "mux reply");
		channel_message_free(provider.requests[i]);
	}
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1)
			err(1, "mux channel state");
		if (!wants_write)
			break;
		poll_result = channel_wait(channel, 1, 5000);
		if (poll_result <= 0 || channel_flush(channel) == -1)
			err(1, "mux flush");
	}
	channel_destroy(channel);
	write_result(result,
	    "requests=3\nreplies=reordered\nevent=sent\nclient=%s\n",
	    identity.client_label);
	hold();
}

static int
scenario_mux_client(const char *result)
{
	struct service_message_metadata metadata;
	struct service_session *client;
	struct mux_call calls[3];
	pthread_t threads[3];
	char event[16], late[16];
	ssize_t received;
	int fd, i, terminal_error;

	if (fixture_service_initialize() == -1 || fixture_service_ready() == -1)
		fixture_fail(result, "mux client initialization");
	fd = fixture_service_connect("org.test.transport-mux");
	if (fd == -1 || service_session_create(fd, &client) == -1)
		fixture_fail(result, "mux client connect fd=%d", fd);
	memset(calls, 0, sizeof(calls));
	for (i = 0; i < 3; i++) {
		calls[i].client = client;
		snprintf(calls[i].request, sizeof(calls[i].request),
		    "request-%d", i);
		if (pthread_create(&threads[i], NULL, mux_call_thread,
		    &calls[i]) != 0)
			fixture_fail(result, "mux pthread_create");
	}
	for (i = 0; i < 3; i++) {
		if (pthread_join(threads[i], NULL) != 0)
			fixture_fail(result, "mux pthread_join");
		if (calls[i].received <= 0 || calls[i].error != 0 ||
		    strcmp(calls[i].request, calls[i].reply) != 0)
			fixture_fail(result, "reply correlation failed call=%d "
			    "received=%zd error=%d req=%s reply=%s", i,
			    calls[i].received, calls[i].error, calls[i].request,
			    calls[i].reply);
	}
	memset(&metadata, 0, sizeof(metadata));
	metadata.size = sizeof(metadata);
	received = fixture_session_event(client, event, sizeof(event),
	    &metadata, 5000);
	if (received != 6 || strcmp(event, "event") != 0)
		fixture_fail(result, "unsolicited event routing failed "
		    "received=%zd", received);
	errno = 0;
	received = fixture_session_call(client, "late", 5, late,
	    sizeof(late), 1000);
	terminal_error = received == -1 ? errno : 0;
	if (received != -1 ||
	    (terminal_error != ECONNRESET && terminal_error != EPIPE))
		fixture_fail(result, "peer death was not reported: %d",
		    terminal_error);
	service_session_close(client);
	write_result(result,
	    "calls=3\ncorrelated=yes\nevent=event\npeer_death_errno=%d\n",
	    terminal_error);
	hold();
}

static int
scenario_ready(const char *result)
{

	if (fixture_service_initialize() == -1 || fixture_service_ready() == -1)
		err(1, "service initialization");
	write_result(result, "CAPD-TEST/1 event=ready channel_fd=%d\n",
	    fixture_service_channel_fd());
	hold();
}

static int
scenario_provider(const char *registered, const char *result)
{
	struct accept_result accepted;
	struct service_listener *listener;
	pthread_t thread;
	char label[128], message[256];
	ssize_t n;
	int client, lookup_errno, peer;

	if (fixture_service_initialize() == -1)
		err(1, "fixture_service_initialize");
	/* Registration precedes READY so dependents cannot race the name. */
	if (service_provider_expose(fixture_service_provider, "org.test.ls-provider", &listener) == -1)
		err(1, "service_provider_expose");
	if (fixture_service_ready() == -1)
		err(1, "service_ready");
	memset(&accepted, 0, sizeof(accepted));
	accepted.listener = listener;
	accepted.fd = -1;
	if (pthread_create(&thread, NULL, accept_thread, &accepted) != 0)
		errx(1, "pthread_create");
	write_result(registered, "step=pre-concurrent-lookup\n");
	errno = 0;
	peer = fixture_service_connect("no.such.concurrent-service");
	lookup_errno = errno;
	if (peer != -1 || lookup_errno != ENOENT) {
		write_result(registered,
		    "step=concurrent-lookup fd=%d errno=%d\n", peer,
		    lookup_errno);
		errx(1, "concurrent lookup returned fd=%d errno=%d", peer,
		    lookup_errno);
	}
	write_result(registered,
	    "CAPD-TEST/1 event=registered name=org.test.ls-provider "
	    "concurrent_lookup_errno=%d\n", lookup_errno);
	if (pthread_join(thread, NULL) != 0)
		errx(1, "pthread_join");
	if (accepted.fd == -1) {
		errno = accepted.error;
		err(1, "service_listener_accept");
	}
	client = accepted.fd;
	strlcpy(label, accepted.label, sizeof(label));
	require_confined_endpoint(client);
	if (fixture_event_send(client, "hello", 6) == -1)
		err(1, "channel_send_event");
	n = fixture_event_recv(client, message, sizeof(message));
	if (n == -1)
		err(1, "channel_dispatch");
	write_result(result,
	    "CAPD-TEST/1 event=exchange client_label=%s message=%.*s confined=yes\n",
	    label, (int)n, message);
	close(client);
	hold();
}

static int
scenario_client(const char *result)
{
	char message[256];
	ssize_t n;
	int peer;

	if (fixture_service_initialize() == -1 || fixture_service_ready() == -1)
		err(1, "service initialization");
	peer = fixture_service_connect("org.test.ls-provider");
	if (peer == -1)
		err(1, "service_lookup");
	require_confined_endpoint(peer);
	n = fixture_event_recv(peer, message, sizeof(message));
	if (n == -1) {
		write_result(result, "event=exchange error=recv errno=%d\n",
		    errno);
		err(1, "channel_dispatch");
	}
	if (fixture_event_send(peer, "world", 6) == -1) {
		write_result(result, "event=exchange error=send errno=%d\n",
		    errno);
		err(1, "channel_send_event");
	}
	write_result(result,
	    "CAPD-TEST/1 event=exchange greeting=%.*s confined=yes\n",
	    (int)n, message);
	close(peer);
	hold();
}

static int
scenario_multi_provider(const char *first, const char *second,
    const char *registered, const char *result)
{
	struct activation_state activation[2];
	struct accept_result accepted[2];
	struct service_listener *listeners[2];
	pthread_t threads[2];
	int i;

	memset(activation, 0, sizeof(activation));
	activation[0].name = first;
	activation[1].name = second;
	if (fixture_service_initialize() == -1 ||
	    service_provider_expose_lazy(fixture_service_provider, first, activation_callback, &activation[0],
	    &listeners[0]) == -1 ||
	    service_provider_expose_lazy(fixture_service_provider, second, activation_callback, &activation[1],
	    &listeners[1]) == -1 ||
	    fixture_service_ready() == -1)
		err(1, "multi-provider initialization");
	memset(accepted, 0, sizeof(accepted));
	for (i = 0; i < 2; i++) {
		accepted[i].listener = listeners[i];
		accepted[i].fd = -1;
		if (pthread_create(&threads[i], NULL, accept_thread,
		    &accepted[i]) != 0)
			errx(1, "pthread_create");
	}
	write_result(registered,
	    "listeners_ready=1\nlistener_fds_distinct=%d\n",
	    service_listener_fd(listeners[0]) !=
	    service_listener_fd(listeners[1]));
	for (i = 0; i < 2; i++) {
		if (pthread_join(threads[i], NULL) != 0)
			errx(1, "pthread_join");
		if (accepted[i].fd == -1) {
			errno = accepted[i].error;
			err(1, "service_listener_accept");
		}
		if (fixture_event_send(accepted[i].fd, accepted[i].service_name,
		    strlen(accepted[i].service_name) + 1) == -1)
			err(1, "channel_send_event");
		/*
		 * Keep the accepted endpoint open: a fire-and-forget event is
		 * only queued on the peer, and closing here revokes the peer
		 * before the client has received it.  A real provider holds
		 * the session for its lifetime; hold() below keeps these live.
		 */
	}
	write_result(result,
	    "first=%s\nsecond=%s\nfirst_client=%s\nsecond_client=%s\n"
	    "first_activations=%u\nsecond_activations=%u\n"
	    "publication_ack_before_accept=yes\n",
	    accepted[0].service_name, accepted[1].service_name,
	    accepted[0].label, accepted[1].label,
	    __atomic_load_n(&activation[0].calls, __ATOMIC_SEQ_CST),
	    __atomic_load_n(&activation[1].calls, __ATOMIC_SEQ_CST));
	hold();
}

static int
scenario_partial_provider(const char *first, const char *result)
{
	struct service_listener *listener;
	int ready_error;

	if (fixture_service_initialize() == -1 ||
	    service_provider_expose(fixture_service_provider, first,
	    &listener) == -1)
		fixture_fail(result, "partial-provider initialization");
	errno = 0;
	if (fixture_service_ready() != -1)
		fixture_fail(result, "incomplete provides set unexpectedly "
		    "became ready");
	ready_error = errno;
	write_result(result, "process_ready=0\nready_errno=%d\n",
	    ready_error);
	hold();
}

static int
scenario_delayed_provider(const char *name, const char *delay_text,
    const char *started, const char *result)
{
	struct service_identity identity;
	struct service_listener *listener;
	char *end;
	long delay;
	int client;

	errno = 0;
	delay = strtol(delay_text, &end, 10);
	if (errno != 0 || end == delay_text || *end != '\0' ||
	    delay < 0 || delay > 30000)
		errx(1, "invalid provider delay");
	if (fixture_service_initialize() == -1 ||
	    service_provider_expose(fixture_service_provider, name, &listener) == -1)
		err(1, "delayed-provider initialization");
	write_result(started, "pid=%jd exposed=1\n", (intmax_t)getpid());
	if (poll(NULL, 0, (int)delay) == -1)
		err(1, "provider delay");
	if (fixture_service_ready() == -1)
		err(1, "delayed-provider readiness");
	memset(&identity, 0, sizeof(identity));
	identity.size = sizeof(identity);
	if (service_listener_accept(listener, &identity, &client) == -1)
		err(1, "delayed-provider accept");
	if (fixture_event_send(client, name, strlen(name) + 1) == -1)
		err(1, "delayed-provider send");
	write_result(result, "accepted=%s\nclient=%s\n", name,
	    identity.client_label);
	/* Hold the endpoint open past the fire-and-forget send (see the
	 * multi-provider note): closing here would revoke the client's peer
	 * before it receives the queued event. */
	hold();
}

static int
scenario_crash_client(const char *name, const char *started,
    const char *result)
{
	char reply[SERVICED_NAME_MAX + 1];
	ssize_t received;
	int peer;

	if (fixture_service_initialize() == -1 || fixture_service_ready() == -1)
		err(1, "crash-client initialization");
	write_result(started, "pid=%jd waiting=1\n", (intmax_t)getpid());
	peer = fixture_service_connect(name);
	if (peer == -1)
		err(1, "crash-client connect");
	received = fixture_event_recv(peer, reply, sizeof(reply));
	if (received <= 0 || (size_t)received > sizeof(reply) ||
	    reply[received - 1] != '\0')
		errx(1, "crash-client invalid provider reply");
	write_result(result, "connected=1\nreply=%s\npid=%jd\n", reply,
	    (intmax_t)getpid());
	close(peer);
	hold();
}

static int
scenario_named_client(const char *name, const char *result)
{
	char routed[256];
	ssize_t received;
	int fd;

	if (fixture_service_initialize() == -1 || fixture_service_ready() == -1)
		err(1, "named-client initialization");
	fd = fixture_service_connect(name);
	if (fd == -1) {
		write_result(result, "requested=%s\nerror=connect\nerrno=%d\n",
		    name, errno);
		err(1, "service_connect %s", name);
	}
	received = fixture_event_recv(fd, routed, sizeof(routed));
	if (received <= 0 || (size_t)received > sizeof(routed) ||
	    routed[received - 1] != '\0') {
		write_result(result,
		    "requested=%s\nerror=event_recv\nreceived=%zd\nerrno=%d\n",
		    name, received, errno);
		errx(1, "invalid routed-name reply");
	}
	write_result(result, "requested=%s\nrouted=%s\n", name, routed);
	close(fd);
	hold();
}

static int
scenario_lookup_missing(const char *result)
{
	int fd, saved_errno;

	if (fixture_service_initialize() == -1 || fixture_service_ready() == -1)
		err(1, "service initialization");
	errno = 0;
	fd = fixture_service_connect("no.such.service");
	saved_errno = errno;
	write_result(result,
	    "CAPD-TEST/1 event=lookup fd=%d errno=%d\n", fd, saved_errno);
	hold();
}

static int
scenario_register(const char *name, const char *result)
{
	struct service_listener *listener;
	int rc, saved_errno;

	if (fixture_service_initialize() == -1)
		err(1, "fixture_service_initialize");
	errno = 0;
	rc = service_provider_expose(fixture_service_provider, name, &listener);
	saved_errno = errno;
	write_result(result,
	    "CAPD-TEST/1 event=register pid=%jd name=%s rc=%d errno=%d\n",
	    (intmax_t)getpid(), name, rc, saved_errno);
	/*
	 * A rejected claim may leave a declared provides[] name unclaimed, so
	 * READY must not be attempted on the failure path.  The exposure error
	 * itself is the result under test.
	 */
	if (rc == 0 && fixture_service_ready() == -1)
		err(1, "service_ready");
	hold();
}

static int
scenario_self_lookup(const char *name, const char *result)
{
	struct service_listener *listener;
	int fd, saved_errno;

	if (fixture_service_initialize() == -1)
		err(1, "fixture_service_initialize");
	if (service_provider_expose(fixture_service_provider, name, &listener) == -1)
		err(1, "service_provider_expose");
	if (fixture_service_ready() == -1)
		err(1, "service_ready");
	errno = 0;
	fd = fixture_service_connect(name);
	saved_errno = errno;
	write_result(result,
	    "CAPD-TEST/1 event=self-lookup fd=%d errno=%d\n",
	    fd, saved_errno);
	if (fd != -1)
		close(fd);
	hold();
}

static int
scenario_token_inventory(const char *result)
{
	struct stat sb;
	pid_t pid;
	int confined, fd, fork_hidden, status, valid;

	if (fixture_service_initialize() == -1 || fixture_service_ready() == -1)
		err(1, "service initialization");
	confined = 0;
	valid = 0;
	for (fd = 6; fd <= 8; fd++) {
		if (fstat(fd, &sb) == 0) {
			valid++;
			errno = 0;
			if (cap_xfer_limit(fd, CAP_XFER_ONCE) == -1 &&
			    errno == ENOTCAPABLE)
				confined++;
		}
	}
	pid = fork();
	if (pid == -1)
		err(1, "fork");
	if (pid == 0) {
		for (fd = 6; fd <= 8; fd++) {
			errno = 0;
			if (fcntl(fd, F_GETFD) != -1 || errno != EBADF)
				_exit(1);
		}
		_exit(0);
	}
	if (waitpid(pid, &status, 0) != pid)
		err(1, "waitpid");
	fork_hidden = WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 3 : 0;
	write_result(result,
	    "channel_fd=%d\ntoken_fds=6,7,8\nvalid_tokens=%d\n"
	    "confined_tokens=%d\nfork_hidden_tokens=%d\n",
	    fixture_service_channel_fd(), valid, confined, fork_hidden);
	hold();
}

static int
scenario_token_activate(const char *target, const char *result)
{
	int after_errno, before_errno, fd, token_fd, consumed;

	if (fixture_service_initialize() == -1)
		err(1, "fixture_service_initialize");
	token_fd = 6;
	fd = open(target, O_RDONLY);
	before_errno = fd == -1 ? errno : 0;
	if (fd != -1)
		close(fd);
	if (service_provider_authorize_capabilities(fixture_service_provider) == -1)
		err(1, "service_authorize_capabilities");
	/* Check before open() can reuse the consumed descriptor number. */
	errno = 0;
	consumed = fcntl(token_fd, F_GETFD) == -1 && errno == EBADF;
	fd = open(target, O_RDONLY);
	after_errno = fd == -1 ? errno : 0;
	write_result(result,
	    "before_denied=%d\nauthorize=ok\ntoken_consumed=%d\n"
	    "after_open=%s\nafter_errno=%d\n",
	    before_errno == EACCES || before_errno == EPERM, consumed,
	    fd >= 0 ? "ok" : "failed", after_errno);
	if (fd != -1)
		close(fd);
	if (fixture_service_ready() == -1)
		err(1, "service_ready");
	hold();
}

static int
scenario_manifest_report(int argc, char **argv)
{
	const char *empty, *mode, *unit_dir;

	if (argc != 5)
		errx(1, "manifest-report requires result and two literal arguments");
	if (fixture_service_initialize() == -1)
		err(1, "fixture_service_initialize");
	mode = getenv("APP_MODE");
	empty = getenv("EMPTY");
	unit_dir = getenv(SERVICE_UNIT_DIR_ENV);
	write_result(argv[2],
	    "argc=3\narg1=%s\narg2=%s\nmode=%s\nempty=%s\nunit_dir=%s\n",
	    argv[3], argv[4], mode == NULL ? "missing" : mode,
	    empty == NULL ? "missing" : empty,
	    unit_dir == NULL ? "missing" : unit_dir);
	if (fixture_service_ready() == -1)
		err(1, "service_ready");
	hold();
}

static int
scenario_authorize_tokens(const char *result)
{
	if (fixture_service_initialize() == -1)
		err(1, "fixture_service_initialize");
	if (service_provider_authorize_capabilities(fixture_service_provider) == -1)
		err(1, "service_authorize_capabilities");
	write_result(result, "fds=6,7,8\nauthorized=yes\n");
	if (fixture_service_ready() == -1)
		err(1, "service_ready");
	hold();
}

static int
scenario_capability_services(const char *result)
{
	static const char *const names[] = {
	    "mount", "node", "accounting", "identity"
	};
	struct capability_info info;
	FILE *out;
	size_t i;
	int confined, fd;

	if (fixture_service_initialize() == -1)
		err(1, "fixture_service_initialize");
	if (getenv("AUTHORITYD_TOKEN_FDS") != NULL ||
	    getenv("AUTHORITYD_CAPABILITY_FDS") != NULL ||
	    getenv("SERVICED_COMPONENT_FDS") != NULL)
		errx(1, "legacy descriptor environment leaked");
	if (getenv(SERVICE_BOOTSTRAP_ENV) == NULL ||
	    strcmp(getenv(SERVICE_BOOTSTRAP_ENV), "5") != 0)
		errx(1, "bootstrap environment descriptor discovery missing");
	out = fopen(result, "w");
	if (out == NULL)
		err(1, "fopen %s", result);
	for (i = 0; i < nitems(names); i++) {
		if (fixture_service_capability_open(names[i], names[i], &fd) == -1)
			err(1, "service_capability_open %s", names[i]);
		memset(&info, 0, sizeof(info));
		if (capability_get_info(fd, &info) == -1 ||
		    strcmp(info.name, names[i]) != 0)
			errx(1, "wrong capability service descriptor for %s",
			    names[i]);
		errno = 0;
		confined = cap_xfer_limit(fd, CAP_XFER_ONCE) == -1 &&
		    errno == ENOTCAPABLE;
		fprintf(out, "%s=valid confined=%d\n", names[i], confined);
		close(fd);
		if (fixture_service_capability_open(names[i], names[i], &fd) == -1)
			err(1, "reopen capability service %s", names[i]);
		close(fd);
	}
	if (fclose(out) == EOF)
		err(1, "close %s", result);
	fd = -1;
	if (fixture_service_capability_open("channel", "channel", &fd) != -1 ||
	    errno != EINVAL || fd != -1)
		errx(1, "invalid capability service name was accepted");
	fd = -1;
	errno = 0;
	if (fixture_service_capability_open("mount", "node", &fd) != -1 ||
	    errno != EFTYPE || fd != -1)
		errx(1, "capability service type mismatch was accepted");
	if (fixture_service_ready() == -1)
		err(1, "service_ready");
	hold();
}

static int
scenario_storage_directory(const char *role, const char *result)
{
	struct stat sb;
	const char payload[] = "persistent storage probe\n";
	int confined, dirfd, fd, mismatch;

	if (fixture_service_initialize() == -1 ||
	    service_provider_authorize_capabilities(fixture_service_provider) == -1 ||
	    service_provider_enter_capability_mode(fixture_service_provider) == -1)
		fixture_fail(result, "storage service initialization");
	dirfd = -1;
	if (fixture_service_capability_open(role, "directory", &dirfd) == -1)
		fixture_fail(result, "open directory %s", role);
	if (fstat(dirfd, &sb) == -1 || !S_ISDIR(sb.st_mode))
		fixture_fail(result, "%s is not a directory mode=%#o", role,
		    (unsigned)sb.st_mode);
	fd = -1;
	errno = 0;
	mismatch = fixture_service_capability_open(role, "zfshandle", &fd);
	if (mismatch != -1 || errno != EFTYPE || fd != -1)
		fixture_fail(result, "%s accepted the wrong descriptor type "
		    "rc=%d errno=%d", role, mismatch, errno);
	fd = openat(dirfd, "storage-probe", O_WRONLY | O_CREAT | O_TRUNC |
	    O_CLOEXEC, 0600);
	if (fd == -1 || write(fd, payload, sizeof(payload) - 1) !=
	    (ssize_t)(sizeof(payload) - 1) || fsync(fd) == -1)
		fixture_fail(result, "write storage probe fd=%d", fd);
	close(fd);
	errno = 0;
	confined = cap_xfer_limit(dirfd, CAP_XFER_ONCE) == -1 &&
	    errno == ENOTCAPABLE;
	close(dirfd);
	if (!confined)
		fixture_fail(result, "%s remained transferable", role);
	if (service_provider_ready(fixture_service_provider) == -1)
		fixture_fail(result, "service_provider_ready");
	write_result(result,
	    "role=%s\ndirectory=ok\ntype_mismatch=EFTYPE\n"
	    "write=ok\nconfined=1\n", role);
	hold();
}

static int
scenario_unregister(const char *name, const char *registered,
    const char *result)
{
	struct service_listener *listener;

	if (fixture_service_initialize() == -1 ||
	    service_provider_expose(fixture_service_provider, name,
	    &listener) == -1)
		err(1, "claim initialization");
	write_result(registered, "register_status=0\n");
	if (fixture_service_ready() == -1)
		err(1, "service_ready");
	if (service_listener_close(listener) == -1)
		err(1, "service_listener_close");
	write_result(result, "unregister_status=0\n");
	hold();
}

static int
scenario_claim_protocol(const char *name, const char *result)
{
	int duplicate, first, reclaim, repeated_withdraw, unauthorized, withdraw;

	if (fixture_service_initialize() == -1)
		err(1, "fixture_service_initialize");
	unauthorized = legacy_name_request(SVC_OP_NAME_CLAIM,
	    "org.test.undeclared");
	first = legacy_name_request(SVC_OP_NAME_CLAIM, name);
	duplicate = legacy_name_request(SVC_OP_NAME_CLAIM, name);
	withdraw = legacy_name_request(SVC_OP_NAME_WITHDRAW, name);
	repeated_withdraw = legacy_name_request(SVC_OP_NAME_WITHDRAW, name);
	reclaim = legacy_name_request(SVC_OP_NAME_CLAIM, name);
	if (unauthorized < 0 || first < 0 || duplicate < 0 || withdraw < 0 ||
	    repeated_withdraw < 0 || reclaim < 0)
		err(1, "name lifecycle request");
	if (unauthorized != EACCES || first != 0 || duplicate != EALREADY ||
	    withdraw != 0 || repeated_withdraw != ENOENT || reclaim != 0)
		errx(1, "unexpected name lifecycle status: %d/%d/%d/%d/%d/%d",
		    unauthorized, first, duplicate, withdraw, repeated_withdraw,
		    reclaim);
	write_result(result,
	    "unauthorized=EACCES\nfirst=ok\nduplicate=EALREADY\n"
	    "withdraw=ok\nrepeated_withdraw=ENOENT\nreclaim=ok\n");
	if (fixture_service_ready() == -1)
		err(1, "service_ready after reclaim");
	hold();
}

static int
scenario_cancel_activation(const char *name, const char *started,
    const char *trigger, const char *result)
{
	const char *relative;
	int fd, late_status, withdraw_status;

	if (fixture_service_initialize() == -1)
		err(1, "fixture_service_initialize");
	if (legacy_name_request(SVC_OP_NAME_CLAIM, name) != 0)
		errx(1, "initial name claim failed");
	if (legacy_ready_only() == -1)
		err(1, "READY");
	if (cap_enter() == -1)
		err(1, "cap_enter");
	write_result(started, "ready=1\n");

	relative = trigger;
	if (trigger[0] == '/' &&
	    strncmp(trigger, result_cwd, strlen(result_cwd)) == 0 &&
	    trigger[strlen(result_cwd)] == '/')
		relative = trigger + strlen(result_cwd) + 1;
	for (;;) {
		fd = openat(result_dir_fd, relative, O_RDONLY | O_CLOEXEC);
		if (fd >= 0) {
			close(fd);
			break;
		}
		if (errno != ENOENT)
			err(1, "openat trigger %s", trigger);
		if (poll(NULL, 0, 10) == -1)
			err(1, "poll trigger");
	}

	withdraw_status = legacy_name_request(SVC_OP_NAME_WITHDRAW, name);
	late_status = legacy_name_result(name, 0);
	if (withdraw_status != 0 || late_status != EPROTO)
		errx(1, "unexpected cancellation status: withdraw=%d late=%d",
		    withdraw_status, late_status);
	write_result(result,
	    "withdraw=ok\npending=ECANCELED\nlate_result=EPROTO\n");
	hold();
}

static int
scenario_protect(const char *result)
{

	if (fixture_service_initialize() == -1 || fixture_service_ready() == -1)
		err(1, "service initialization");
	if (service_provider_protect(fixture_service_provider, SERVICE_PROTECT_EXTERNAL) == -1)
		err(1, "service_provider_protect");
	write_result(result,
	    "CAPD-TEST/1 event=protected pid=%jd protected=yes\n",
	    (intmax_t)getpid());
	hold();
}

static int
scenario_compat_ready(int argc, char **argv)
{
	struct service_listener *listener;
	const char *name;
	char path[256];

	listener = NULL;
	if (fixture_service_initialize() == -1)
		err(1, "service initialization");
	if (argc == 3 && service_provider_expose(fixture_service_provider, argv[2], &listener) == -1)
		err(1, "service_provider_expose %s", argv[2]);
	if (fixture_service_ready() == -1)
		err(1, "service_ready");
	name = strrchr(argv[0], '/');
	name = name == NULL ? argv[0] : name + 1;
	if (snprintf(path, sizeof(path), "%s.ready", name) >=
	    (int)sizeof(path))
		errx(1, "ready result path is too long");
	write_result(path, "ready\n");
	hold();
}

/*
 * Crash on the first launch, then behave like compat-ready on every later one.
 * The invocation count lives in a persistent statefile, updated before the
 * capability sandbox is entered.  This must be a single-exec service program:
 * the bootstrap descriptor is CAP_CLOEXEC_ONCE and would not survive a wrapper
 * script re-exec'ing a separate helper.
 */
static int
scenario_crash_once(const char *statefile, const char *ready_name,
    const char *expose_name)
{
	struct service_listener *listener;
	char path[256];
	long count;
	FILE *sf;

	count = 0;
	sf = fopen(statefile, "r");
	if (sf != NULL) {
		if (fscanf(sf, "%ld", &count) != 1)
			count = 0;
		fclose(sf);
	}
	count++;
	sf = fopen(statefile, "w");
	if (sf != NULL) {
		fprintf(sf, "%ld\n", count);
		fclose(sf);
	}
	if (count <= 1)
		_exit(1);
	if (fixture_service_initialize() == -1)
		err(1, "crash-once init");
	/*
	 * Claim the declared IPC name before reporting ready: serviced rejects
	 * a readiness that arrives before every provides[] name is claimed.
	 */
	listener = NULL;
	if (expose_name != NULL && expose_name[0] != '\0' &&
	    strcmp(expose_name, "-") != 0 &&
	    service_provider_expose(fixture_service_provider, expose_name,
	    &listener) == -1)
		err(1, "crash-once expose %s", expose_name);
	if (fixture_service_ready() == -1)
		err(1, "crash-once readiness");
	if (snprintf(path, sizeof(path), "%s.ready", ready_name) >=
	    (int)sizeof(path))
		errx(1, "crash-once ready path is too long");
	write_result(path, "ready\n");
	hold();
}

static int
scenario_supervisor_monitor(const char *ready, const char *result)
{
	struct pollfd event;
	int status_error;

	if (fixture_service_initialize() == -1)
		err(1, "fixture_service_initialize");
	event.fd = fixture_service_supervisor_fd();
	event.events = POLLIN;
	if (event.fd == -1 || fixture_service_supervisor_status() == -1 ||
	    fixture_service_ready() == -1)
		err(1, "supervisor monitor initialization");
	write_result(ready, "monitor_ready=1\n");
	if (poll(&event, 1, 30000) != 1 || (event.revents & POLLIN) == 0)
		errx(1, "supervisor event did not become readable");
	errno = 0;
	if (fixture_service_supervisor_status() != -1)
		errx(1, "supervisor status remained healthy");
	status_error = errno;
	write_result(result, "supervisor_lost=1\nerrno=%d\n", status_error);
	return (0);
}

static int
scenario_compat_lookup(void)
{
	char result_path[256], target_path[256], target[256];
	const char *label;
	FILE *input;
	int fd, rc, saved_errno;

	if (fixture_service_initialize() == -1)
		err(1, "fixture_service_initialize");
	label = fixture_service_label();
	if (label == NULL || label[0] == '\0')
		errx(1, "service label is unavailable");
	if (snprintf(target_path, sizeof(target_path), "%s.target", label) >=
	    (int)sizeof(target_path) ||
	    snprintf(result_path, sizeof(result_path), "%s.result", label) >=
	    (int)sizeof(result_path))
		errx(1, "lookup fixture path is too long");
	/* Runtime labels are bundle/unit; keep the marker names flat. */
	for (char *p = target_path; *p != '\0'; p++)
		if (*p == '/')
			*p = '.';
	for (char *p = result_path; *p != '\0'; p++)
		if (*p == '/')
			*p = '.';
	input = fopen(target_path, "r");
	if (input == NULL)
		err(1, "fopen %s", target_path);
	if (fgets(target, sizeof(target), input) == NULL)
		errx(1, "empty lookup target");
	(void)fclose(input);
	target[strcspn(target, "\r\n")] = '\0';
	if (fixture_service_ready() == -1)
		err(1, "service readiness");
	errno = 0;
	fd = fixture_service_connect(target);
	saved_errno = errno;
	rc = fd == -1 ? 1 : 0;
	write_result(result_path, "fd=%d\nerrno=%d\nrc=%d\n",
	    fd, saved_errno, rc);
	if (fd != -1)
		close(fd);
	return (rc);
}

static int
scenario_readiness_gate(const char *protocol_result,
    const char *capmode_result)
{

	if (fixture_service_initialize() == -1)
		err(1, "fixture_service_initialize");
	if (signal(SIGUSR1, request_capmode) == SIG_ERR)
		err(1, "signal");
	if (legacy_ready_only() == -1)
		err(1, "legacy READY");
	write_result(protocol_result, "pid=%jd protocol_ready=1\n",
	    (intmax_t)getpid());
	while (!enter_requested)
		pause();
	if (cap_enter() == -1)
		err(1, "cap_enter");
	write_result(capmode_result, "pid=%jd capmode=1\n",
	    (intmax_t)getpid());
	hold();
}

static int
scenario_quiesce(const char *name, const char *ready, const char *result)
{
	struct service_identity identity;
	struct service_listener *listener;
	int fd;

	listener = NULL;
	if (fixture_service_initialize() == -1 ||
	    service_provider_expose(fixture_service_provider, name,
	    &listener) == -1 || fixture_service_ready() == -1)
		err(1, "quiesce provider initialization");
	write_result(ready, "ready=1\n");
	memset(&identity, 0, sizeof(identity));
	identity.size = sizeof(identity);
	errno = 0;
	{
		int accept_rc, accept_errno, quiescing;

		accept_rc = service_listener_accept(listener, &identity, &fd);
		accept_errno = errno;
		quiescing = service_provider_quiescing(fixture_service_provider);
		if (accept_rc != -1 || accept_errno != ECANCELED ||
		    quiescing != 1)
			fixture_fail(result, "listener was not quiesced "
			    "atomically accept_rc=%d accept_errno=%d "
			    "quiescing=%d", accept_rc, accept_errno, quiescing);
	}
	if (service_provider_quiesce_complete(fixture_service_provider, 0) == -1)
		fixture_fail(result, "quiesce_complete errno=%d", errno);
	write_result(result, "admission=closed\nresult=complete\n");
	for (;;)
		pause();
}

static int
scenario_worker_channel(const char *result)
{
	char message[32];
	ssize_t received;
	pid_t child;
	int provider_fd, status, worker_fd;

	if (fixture_service_initialize() == -1 ||
	    service_provider_worker_channel(fixture_service_provider,
	    &provider_fd, &worker_fd) == -1)
		err(1, "service_provider_worker_channel");
	child = fork();
	if (child == -1)
		err(1, "fork worker");
	if (child == 0) {
		if (fcntl(provider_fd, F_GETFD) != -1 || errno != EBADF)
			_exit(10);
		if (fcntl(worker_fd, F_GETFD) == -1)
			_exit(11);
		errno = 0;
		if (cap_xfer_limit(worker_fd, CAP_XFER_ONCE) != -1 ||
		    errno != ENOTCAPABLE)
			_exit(12);
		if (fixture_event_send(worker_fd, "worker", 7) == -1)
			_exit(13);
		close(worker_fd);
		_exit(0);
	}
	close(worker_fd);
	if (fixture_service_ready() == -1)
		fixture_fail(result, "worker-channel readiness");
	received = fixture_event_recv(provider_fd, message, sizeof(message));
	if (received != 7 || strcmp(message, "worker") != 0)
		fixture_fail(result, "worker-channel payload mismatch "
		    "received=%zd msg=%.*s", received,
		    received > 0 ? (int)received : 0, message);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		fixture_fail(result, "worker child failed: status=%#x", status);
	errno = 0;
	if (cap_xfer_limit(provider_fd, CAP_XFER_ONCE) != -1 ||
	    errno != ENOTCAPABLE)
		fixture_fail(result, "provider endpoint remained transferable "
		    "errno=%d", errno);
	close(provider_fd);
	write_result(result,
	    "pair=private\nprovider_in_child=closed\nworker_in_child=open\n"
	    "transfer=none\npayload=worker\n");
	hold();
}

/*
 * Provider-driven idle shutdown (Phase 2).  After becoming ready the provider
 * declares an idle timeout; serviced stops it after that interval yet keeps
 * its name reservation so the next lookup relaunches it.  Only the first
 * incarnation arms idle (tracked in a statefile) so a relaunched provider
 * stays up for the test's assertions.  Each launch records its pid under a
 * distinct marker so the harness can prove the process actually changed.
 */
static int
scenario_idle(const char *name, const char *seconds_str, const char *prefix)
{
	struct service_listener *listener;
	char statefile[256], marker[256];
	const char *errstr;
	unsigned seconds;
	long count;
	FILE *sf;

	if (snprintf(statefile, sizeof(statefile), "%s.count", prefix) >=
	    (int)sizeof(statefile))
		errx(1, "idle statefile path too long");
	count = 0;
	sf = fopen(statefile, "r");
	if (sf != NULL) {
		if (fscanf(sf, "%ld", &count) != 1)
			count = 0;
		fclose(sf);
	}
	count++;
	sf = fopen(statefile, "w");
	if (sf != NULL) {
		fprintf(sf, "%ld\n", count);
		fclose(sf);
	}
	seconds = (unsigned)strtonum(seconds_str, 0, 3600, &errstr);
	if (errstr != NULL)
		errx(1, "idle seconds '%s': %s", seconds_str, errstr);
	listener = NULL;
	if (fixture_service_initialize() == -1 ||
	    service_provider_expose(fixture_service_provider, name,
	    &listener) == -1 || fixture_service_ready() == -1)
		err(1, "idle provider initialization");
	if (snprintf(marker, sizeof(marker), "%s.launch%ld", prefix, count) >=
	    (int)sizeof(marker))
		errx(1, "idle marker path too long");
	write_result(marker, "pid=%jd\n", (intmax_t)getpid());
	if (count == 1 &&
	    service_idle_shutdown(fixture_service_context, seconds) == -1)
		err(1, "service_idle_shutdown");
	hold();
}

/*
 * Arm an idle timeout, then immediately cancel it with seconds == 0.  serviced
 * must clear the pending stop, so the provider stays running past the timeout.
 */
static int
scenario_idle_cancel(const char *name, const char *seconds_str,
    const char *ready)
{
	struct service_listener *listener;
	const char *errstr;
	unsigned seconds;

	seconds = (unsigned)strtonum(seconds_str, 1, 3600, &errstr);
	if (errstr != NULL)
		errx(1, "idle seconds '%s': %s", seconds_str, errstr);
	listener = NULL;
	if (fixture_service_initialize() == -1 ||
	    service_provider_expose(fixture_service_provider, name,
	    &listener) == -1 || fixture_service_ready() == -1)
		err(1, "idle-cancel provider initialization");
	if (service_idle_shutdown(fixture_service_context, seconds) == -1 ||
	    service_idle_shutdown(fixture_service_context, 0) == -1)
		err(1, "service_idle_shutdown");
	write_result(ready, "pid=%jd cancelled=1\n", (intmax_t)getpid());
	hold();
}

/*
 * Private-helper provider (§ service_helper_open).  A helper unit publishes no
 * ipc name; serviced injects the synthetic bundle-local provider name
 * "helper.<bundle-id>.<unit>" into its manifest.  The helper program does not
 * receive that name as an argument — it reconstructs it from its own runtime
 * label ("<bundle-id>/<unit>", '/' flattened to '.') exactly as libcapbundle
 * does — then exposes it and serves one client.  Reaching this scenario at all
 * proves the parent's service_helper_open() drove an on-demand launch of the
 * declared helper; the "pong" exchange proves the delivered channel works.
 */
static int
scenario_helper_provider(const char *result)
{
	struct service_identity identity;
	struct service_listener *listener;
	const char *label;
	char synthetic[SERVICED_NAME_MAX + 1];
	char *p;
	int client;

	if (fixture_service_initialize() == -1)
		fixture_fail(result, "helper-provider init errno=%d", errno);
	label = fixture_service_label();
	if (label == NULL || label[0] == '\0')
		fixture_fail(result, "helper-provider label unavailable");
	if (snprintf(synthetic, sizeof(synthetic), "helper.%s", label) >=
	    (int)sizeof(synthetic))
		fixture_fail(result, "helper-provider synthetic name too long");
	for (p = synthetic; *p != '\0'; p++)
		if (*p == '/')
			*p = '.';
	if (service_provider_expose(fixture_service_provider, synthetic,
	    &listener) == -1)
		fixture_fail(result, "helper-provider expose %s errno=%d",
		    synthetic, errno);
	if (fixture_service_ready() == -1)
		fixture_fail(result, "helper-provider readiness errno=%d", errno);
	write_result(result, "helper=exposed\nname=%s\n", synthetic);
	memset(&identity, 0, sizeof(identity));
	identity.size = sizeof(identity);
	if (service_listener_accept(listener, &identity, &client) == -1)
		fixture_fail(result, "helper-provider accept errno=%d", errno);
	if (fixture_event_send(client, "pong", 5) == -1)
		fixture_fail(result, "helper-provider send errno=%d", errno);
	/* Hold the endpoint open past the fire-and-forget send (see the
	 * multi-provider note); closing here would revoke the parent's peer. */
	hold();
}

/*
 * Private-helper consumer.  A boot-start parent unit that opens a helper
 * declared in its own bundle by short unit name.  service_helper_open() drives
 * the on-demand launch and returns a confined client endpoint; the parent reads
 * the helper's "pong" to prove the channel is live end to end.
 */
static int
scenario_helper_open(const char *name, const char *result)
{
	char message[64];
	ssize_t n;
	int confined, fd, saved_errno;

	if (fixture_service_initialize() == -1 || fixture_service_ready() == -1)
		fixture_fail(result, "helper-open init errno=%d", errno);
	/*
	 * Breadcrumb: record that the parent launched and reported ready before
	 * attempting the open.  Every later path overwrites this and then holds,
	 * so the runtime container (and this result) survives for inspection
	 * whether the open succeeds or fails — a restart="never" unit that exits
	 * would have its container reclaimed, erasing the evidence.
	 */
	write_result(result, "helper_open=started\nname=%s\n", name);
	fd = -1;
	errno = 0;
	if (service_helper_open(fixture_service_context, name, &fd) == -1) {
		saved_errno = errno;
		write_result(result, "helper_open=failed\nname=%s\nerrno=%d\n",
		    name, saved_errno);
		hold();
	}
	/* A delivered endpoint is transfer-confined to the consumer. */
	errno = 0;
	confined = cap_xfer_limit(fd, CAP_XFER_TWICE) == -1 &&
	    errno == ENOTCAPABLE;
	n = fixture_event_recv(fd, message, sizeof(message));
	if (n <= 0 || (size_t)n > sizeof(message) || message[n - 1] != '\0') {
		write_result(result, "helper_open=connected\nname=%s\n"
		    "exchange=failed\nreceived=%zd\nerrno=%d\n", name, n, errno);
		hold();
	}
	write_result(result, "helper_open=ok\nname=%s\nreceived=%.*s\n"
	    "confined=%d\n", name, (int)n, message, confined);
	close(fd);
	hold();
}

static void
usage(void)
{

	fprintf(stderr,
	    "usage: capd_service_fixture ready result\n"
	    "       capd_service_fixture provider registered result\n"
	    "       capd_service_fixture client result\n"
	    "       capd_service_fixture multi-provider first second "
	    "registered result\n"
	    "       capd_service_fixture partial-provider first result\n"
	    "       capd_service_fixture delayed-provider name delay-ms "
	    "started result\n"
	    "       capd_service_fixture crash-client name started result\n"
	    "       capd_service_fixture named-client name result\n"
	    "       capd_service_fixture lookup-missing result\n"
	    "       capd_service_fixture register name result\n"
	    "       capd_service_fixture self-lookup name result\n"
	    "       capd_service_fixture token-inventory result\n"
	    "       capd_service_fixture token-activate target result\n"
	    "       capd_service_fixture manifest-report result arg1 arg2\n"
	    "       capd_service_fixture authorize-tokens result\n"
	    "       capd_service_fixture capability-services result\n"
	    "       capd_service_fixture storage-directory role result\n"
	    "       capd_service_fixture unregister name registered result\n"
	    "       capd_service_fixture claim-protocol name result\n"
	    "       capd_service_fixture cancel-activation name started "
	    "trigger result\n"
	    "       capd_service_fixture protect result\n"
	    "       capd_service_fixture compat-ready [provided-name]\n"
	    "       capd_service_fixture supervisor-monitor ready result\n"
	    "       capd_service_fixture compat-lookup\n"
	    "       capd_service_fixture readiness-gate protocol capmode\n"
	    "       capd_service_fixture quiesce name ready result\n"
	    "       capd_service_fixture worker-channel result\n"
	    "       capd_service_fixture idle-provider name seconds prefix\n"
	    "       capd_service_fixture idle-cancel name seconds ready\n"
	    "       capd_service_fixture helper-provider result\n"
	    "       capd_service_fixture helper-open name result\n");
	exit(64);
}

int
main(int argc, char **argv)
{

	prepare_results();
	if (argc == 3 && strcmp(argv[1], "ready") == 0)
		return (scenario_ready(argv[2]));
	if (argc == 4 && strcmp(argv[1], "provider") == 0)
		return (scenario_provider(argv[2], argv[3]));
	if (argc == 3 && strcmp(argv[1], "client") == 0)
		return (scenario_client(argv[2]));
	if (argc == 3 && strcmp(argv[1], "mux-provider") == 0)
		return (scenario_mux_provider(argv[2]));
	if (argc == 3 && strcmp(argv[1], "mux-client") == 0)
		return (scenario_mux_client(argv[2]));
	if (argc == 6 && strcmp(argv[1], "multi-provider") == 0)
		return (scenario_multi_provider(argv[2], argv[3], argv[4],
		    argv[5]));
	if (argc == 4 && strcmp(argv[1], "partial-provider") == 0)
		return (scenario_partial_provider(argv[2], argv[3]));
	if (argc == 6 && strcmp(argv[1], "delayed-provider") == 0)
		return (scenario_delayed_provider(argv[2], argv[3], argv[4],
		    argv[5]));
	if (argc == 5 && strcmp(argv[1], "crash-client") == 0)
		return (scenario_crash_client(argv[2], argv[3], argv[4]));
	if (argc == 4 && strcmp(argv[1], "named-client") == 0)
		return (scenario_named_client(argv[2], argv[3]));
	if (argc == 3 && strcmp(argv[1], "lookup-missing") == 0)
		return (scenario_lookup_missing(argv[2]));
	if (argc == 4 && strcmp(argv[1], "register") == 0)
		return (scenario_register(argv[2], argv[3]));
	if (argc == 4 && strcmp(argv[1], "self-lookup") == 0)
		return (scenario_self_lookup(argv[2], argv[3]));
	if (argc == 3 && strcmp(argv[1], "token-inventory") == 0)
		return (scenario_token_inventory(argv[2]));
	if (argc == 4 && strcmp(argv[1], "token-activate") == 0)
		return (scenario_token_activate(argv[2], argv[3]));
	if (argc >= 2 && strcmp(argv[1], "manifest-report") == 0)
		return (scenario_manifest_report(argc, argv));
	if (argc == 3 && strcmp(argv[1], "authorize-tokens") == 0)
		return (scenario_authorize_tokens(argv[2]));
	if (argc == 3 && strcmp(argv[1], "capability-services") == 0)
		return (scenario_capability_services(argv[2]));
	if (argc == 4 && strcmp(argv[1], "storage-directory") == 0)
		return (scenario_storage_directory(argv[2], argv[3]));
	if (argc == 5 && strcmp(argv[1], "unregister") == 0)
		return (scenario_unregister(argv[2], argv[3], argv[4]));
	if (argc == 4 && strcmp(argv[1], "claim-protocol") == 0)
		return (scenario_claim_protocol(argv[2], argv[3]));
	if (argc == 6 && strcmp(argv[1], "cancel-activation") == 0)
		return (scenario_cancel_activation(argv[2], argv[3], argv[4],
		    argv[5]));
	if (argc == 3 && strcmp(argv[1], "protect") == 0)
		return (scenario_protect(argv[2]));
	if ((argc == 2 || argc == 3) &&
	    strcmp(argv[1], "compat-ready") == 0)
		return (scenario_compat_ready(argc, argv));
	if (argc == 5 && strcmp(argv[1], "crash-once") == 0)
		return (scenario_crash_once(argv[2], argv[3], argv[4]));
	if (argc == 4 && strcmp(argv[1], "supervisor-monitor") == 0)
		return (scenario_supervisor_monitor(argv[2], argv[3]));
	if (argc == 2 && strcmp(argv[1], "compat-lookup") == 0)
		return (scenario_compat_lookup());
	if (argc == 4 && strcmp(argv[1], "readiness-gate") == 0)
		return (scenario_readiness_gate(argv[2], argv[3]));
	if (argc == 5 && strcmp(argv[1], "quiesce") == 0)
		return (scenario_quiesce(argv[2], argv[3], argv[4]));
	if (argc == 3 && strcmp(argv[1], "worker-channel") == 0)
		return (scenario_worker_channel(argv[2]));
	if (argc == 5 && strcmp(argv[1], "idle-provider") == 0)
		return (scenario_idle(argv[2], argv[3], argv[4]));
	if (argc == 5 && strcmp(argv[1], "idle-cancel") == 0)
		return (scenario_idle_cancel(argv[2], argv[3], argv[4]));
	if (argc == 3 && strcmp(argv[1], "helper-provider") == 0)
		return (scenario_helper_provider(argv[2]));
	if (argc == 4 && strcmp(argv[1], "helper-open") == 0)
		return (scenario_helper_open(argv[2], argv[3]));
	usage();
}
