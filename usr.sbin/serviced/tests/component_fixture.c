/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Behavioral fixture for serviced capability-component integration tests.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <filesystemcmp.h>
#include <logcmp.h>
#include <networkcmp.h>
#include <notify.h>
#include <tracecmp.h>

static struct service_context *fixture_service_context;

static int
fixture_service_initialize(void)
{

	if (fixture_service_context != NULL)
		return (0);
	return (service_acquire(&fixture_service_context));
}

static int
fixture_service_ready(void)
{

	if (service_enter_capability_mode(fixture_service_context) == -1)
		return (-1);
	return (service_ready(fixture_service_context));
}

struct log_thread_context {
	struct logcmp_client	*client;
	unsigned		 first;
	unsigned		 count;
	int			 error;
};

struct notify_thread_context {
	struct notify_client	*client;
	unsigned		 count;
	int			 error;
};

struct filesystem_thread_context {
	struct filesystemcmp_handle root;
	struct filesystemcmp_client *client;
	unsigned		 count;
	int			 error;
};

struct network_thread_context {
	struct networkcmp_client *client;
	unsigned	 count;
	int		 error;
};

static void *
network_thread(void *argument)
{
	struct network_thread_context *context;
	struct networkcmp_hello_reply hello;
	unsigned i;

	context = argument;
	for (i = 0; i < context->count; i++)
		if (networkcmp_hello(context->client, &hello) == -1 ||
		    hello.version != NETWORKCMP_ABI_VERSION) {
			context->error = errno != 0 ? errno : EPROTO;
			break;
		}
	return (NULL);
}

static void *
filesystem_thread(void *argument)
{
	struct filesystem_thread_context *context;
	struct filesystemcmp_stat_reply status;
	unsigned i;

	context = argument;
	for (i = 0; i < context->count; i++)
		if (filesystemcmp_stat(context->client, context->root,
		    &status) == -1 ||
		    status.type != FILESYSTEMCMP_TYPE_DIRECTORY) {
			context->error = errno != 0 ? errno : EPROTO;
			break;
		}
	return (NULL);
}

static int
emit_log(struct logcmp_client *client, const char *message)
{
	static const char case_value[] = "serviced";
	static const char result_value[] = "ok";
	struct logcmp_attribute attributes[2];
	struct logcmp_emit_options options;
	struct logcmp_logger *logger;
	int error;

	memset(attributes, 0, sizeof(attributes));
	attributes[0].size = sizeof(attributes[0]);
	attributes[0].key = "case";
	attributes[0].type = LOGCMP_ATTR_STRING;
	attributes[0].privacy = LOGCMP_PRIVACY_PUBLIC;
	attributes[0].value = case_value;
	attributes[0].value_length = sizeof(case_value) - 1;
	attributes[1].size = sizeof(attributes[1]);
	attributes[1].key = "result";
	attributes[1].type = LOGCMP_ATTR_STRING;
	attributes[1].privacy = LOGCMP_PRIVACY_PUBLIC;
	attributes[1].value = result_value;
	attributes[1].value_length = sizeof(result_value) - 1;
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_INFO;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = message;
	options.attributes = attributes;
	options.nattributes = nitems(attributes);
	if (logcmp_logger_create(client, "org.5bsd.serviced.tests",
	    "integration", &logger) == -1)
		return (-1);
	if (logcmp_emit(logger, &options) == -1) {
		error = errno;
		logcmp_logger_destroy(logger);
		errno = error;
		return (-1);
	}
	logcmp_logger_destroy(logger);
	return (0);
}

static void *
log_thread(void *argument)
{
	struct log_thread_context *context;
	char message[64];
	unsigned i;

	context = argument;
	for (i = 0; i < context->count; i++) {
		(void)snprintf(message, sizeof(message), "integration record %u",
		    context->first + i);
		if (emit_log(context->client, message) == -1) {
			context->error = errno;
			break;
		}
	}
	return (NULL);
}

static void *
notify_thread(void *argument)
{
	struct notify_thread_context *context;
	struct notify_stats stats;
	unsigned i;

	context = argument;
	for (i = 0; i < context->count; i++)
		if (notify_stats(context->client, &stats) == -1) {
			context->error = errno;
			break;
		}
	return (NULL);
}

static int
run_filesystem_consumer(const char *output_path)
{
	struct filesystem_thread_context contexts[2];
	struct filesystemcmp_hello_reply hello;
	struct filesystemcmp_handle scratch, persistent, bundle;
	struct filesystemcmp_handle_reply object;
	struct filesystemcmp_path_context *path_context;
	struct filesystemcmp_stat_reply status;
	struct filesystemcmp_client *component, *reopened, *second;
	pthread_t threads[2];
	char cwd[32], data[8] = {};
	int hidden_fd, out;

	out = open(output_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (out == -1 || fixture_service_initialize() == -1 ||
	    service_authorize_capabilities(fixture_service_context) == -1)
		return (1);
	/*
	 * The raw storage backing is delivered to the filesystem component, not
	 * to this consumer: a direct capability open of it must be denied.
	 */
	hidden_fd = -1;
	errno = 0;
	if (service_capability_open(fixture_service_context, "storage:local",
	    "zfshandle", &hidden_fd) != -1 || errno != ENOENT || hidden_fd != -1)
		return (1);
	if (service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOEXEC | SERVICE_PROTECT_NOSOCK) == -1)
		return (1);
	if (filesystemcmp_open(&component) == -1 || fixture_service_ready() == -1 ||
	    filesystemcmp_hello(component, &hello) == -1 ||
	    (hello.features & (FILESYSTEMCMP_FEATURE_PERSISTENT |
	    FILESYSTEMCMP_FEATURE_BUNDLE)) !=
	    (FILESYSTEMCMP_FEATURE_PERSISTENT |
	    FILESYSTEMCMP_FEATURE_BUNDLE) ||
	    filesystemcmp_open_namespace(component,
	    FILESYSTEMCMP_NAMESPACE_SCRATCH, &scratch) == -1 ||
	    filesystemcmp_open_namespace(component,
	    FILESYSTEMCMP_NAMESPACE_PERSISTENT, &persistent) == -1 ||
	    filesystemcmp_open_namespace(component,
	    FILESYSTEMCMP_NAMESPACE_BUNDLE, &bundle) == -1)
		return (1);
	if (filesystemcmp_open(&second) == -1 ||
	    filesystemcmp_hello(second, &hello) == -1)
		return (1);
	memset(contexts, 0, sizeof(contexts));
	contexts[0].client = component;
	contexts[0].root = scratch;
	contexts[0].count = 100;
	contexts[1].client = second;
	contexts[1].root = scratch;
	contexts[1].count = 100;
	if (pthread_create(&threads[0], NULL, filesystem_thread,
	    &contexts[0]) != 0 ||
	    pthread_create(&threads[1], NULL, filesystem_thread,
	    &contexts[1]) != 0 ||
	    pthread_join(threads[0], NULL) != 0 ||
	    pthread_join(threads[1], NULL) != 0 ||
	    contexts[0].error != 0 || contexts[1].error != 0)
		return (1);
	filesystemcmp_close(second);
	if (filesystemcmp_open(&reopened) == -1 ||
	    filesystemcmp_hello(reopened, &hello) == -1)
		return (1);
	filesystemcmp_close(reopened);
	if (filesystemcmp_create(component, scratch, "temporary",
	    FILESYSTEMCMP_CREATE_EXCLUSIVE, 0600, &object) == -1 ||
	    filesystemcmp_pwrite(component, object.handle, "tmp", 3, 0) != 3)
		return (1);
	if (filesystemcmp_path_context_open(FILESYSTEMCMP_NAMESPACE_SCRATCH,
	    &path_context) == -1 ||
	    filesystemcmp_path_create(path_context, "work",
	    FILESYSTEMCMP_CREATE_EXCLUSIVE | FILESYSTEMCMP_CREATE_DIRECTORY,
	    0700, &object) == -1 ||
	    filesystemcmp_path_close_handle(path_context, object.handle) == -1 ||
	    filesystemcmp_path_chdir(path_context, "work") == -1 ||
	    filesystemcmp_path_getcwd(path_context, cwd, sizeof(cwd)) == -1 ||
	    strcmp(cwd, "/work") != 0 ||
	    filesystemcmp_path_create(path_context, "./relative",
	    FILESYSTEMCMP_CREATE_EXCLUSIVE, 0600, &object) == -1 ||
	    filesystemcmp_path_pwrite(path_context, object.handle, "path", 4,
	    0) != 4 ||
	    filesystemcmp_path_close_handle(path_context, object.handle) == -1 ||
	    filesystemcmp_path_lookup(path_context, "../work/relative",
	    &object) == -1 ||
	    object.type != FILESYSTEMCMP_TYPE_REGULAR ||
	    filesystemcmp_path_pread(path_context, object.handle, data, 4, 0) !=
	    4 || memcmp(data, "path", 4) != 0 ||
	    filesystemcmp_path_stat(path_context, object.handle, &status) == -1 ||
	    status.type != FILESYSTEMCMP_TYPE_REGULAR || status.size != 4 ||
	    filesystemcmp_path_close_handle(path_context, object.handle) == -1 ||
	    filesystemcmp_path_chdir(path_context, "../../../") == -1 ||
	    filesystemcmp_path_getcwd(path_context, cwd, sizeof(cwd)) == -1 ||
	    strcmp(cwd, "/") != 0)
		return (1);
	filesystemcmp_path_context_close(path_context);
	if (filesystemcmp_create(component, persistent, "state",
	    0, 0600, &object) == -1 ||
	    filesystemcmp_pwrite(component, object.handle, "durable", 7, 0) !=
	    7 ||
	    filesystemcmp_sync(component, object.handle) == -1 ||
	    filesystemcmp_sync(component, persistent) == -1 ||
	    filesystemcmp_pread(component, object.handle, data,
	    sizeof(data), 0) != 7 || memcmp(data, "durable", 7) != 0)
		return (1);
	/*
	 * The delivered bundle namespace is the .cap root: the program lives at
	 * Units/<unit>.unit/bin/<unit>, where <unit> is this program's name.
	 */
	{
		char unit_dir[128];

		if (snprintf(unit_dir, sizeof(unit_dir), "%s.unit",
		    getprogname()) >= (int)sizeof(unit_dir))
			return (1);
		if (filesystemcmp_lookup(component, bundle, "Units",
		    &object) == -1 ||
		    object.type != FILESYSTEMCMP_TYPE_DIRECTORY ||
		    filesystemcmp_lookup(component, object.handle, unit_dir,
		    &object) == -1 ||
		    object.type != FILESYSTEMCMP_TYPE_DIRECTORY ||
		    filesystemcmp_lookup(component, object.handle, "bin",
		    &object) == -1 ||
		    object.type != FILESYSTEMCMP_TYPE_DIRECTORY ||
		    filesystemcmp_lookup(component, object.handle,
		    getprogname(), &object) == -1 ||
		    filesystemcmp_stat(component, object.handle, &status) == -1 ||
		    status.type != FILESYSTEMCMP_TYPE_REGULAR ||
		    status.size == 0)
			return (1);
	}
	errno = 0;
	if (filesystemcmp_create(component, bundle, "forbidden",
	    FILESYSTEMCMP_CREATE_EXCLUSIVE, 0600, &object) != -1 ||
	    errno != EROFS)
		return (1);
	filesystemcmp_close(component);
	if (filesystemcmp_open(&reopened) == -1 ||
	    filesystemcmp_hello(reopened, &hello) == -1)
		return (1);
	filesystemcmp_close(reopened);
	if (dprintf(out,
	    "scratch=ok\npersistent=ok\nbundle=ok\nbundle_readonly=ok\n"
	    "durable_sync=ok\nlogical_cwd=ok\nmulti_open=ok\nconcurrent=ok\n"
	    "close_reopen=ok\nraw_storage_hidden=ok\n") < 0)
		return (1);
	close(out);
	return (0);
}

static int
run_log_consumer(const char *output_path)
{
	struct log_thread_context contexts[2];
	struct logcmp_client *client, *second, *reopened;
	struct logcmp_stats stats;
	pthread_t threads[2];
	int inherited[64], j, out, status;
	pid_t child;

	out = open(output_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (out == -1 || fixture_service_initialize() == -1 ||
	    service_authorize_capabilities(fixture_service_context) == -1 ||
	    logcmp_client_open(&client) == -1 ||
	    logcmp_client_open(&second) == -1 || client != second ||
	    (child = fork()) == -1)
		return (1);
	if (child == 0) {
		if (logcmp_stats(client, &stats) != -1)
			_exit(1);
		for (j = 0; j < (int)nitems(inherited); j++) {
			inherited[j] = open("/dev/null", O_RDONLY | O_CLOEXEC);
			if (inherited[j] == -1)
				_exit(1);
		}
		logcmp_client_close(client);
		for (j = 0; j < (int)nitems(inherited); j++) {
			if (fcntl(inherited[j], F_GETFD) == -1)
				_exit(1);
			close(inherited[j]);
		}
		_exit(0);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0 ||
	    service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOEXEC | SERVICE_PROTECT_NOSOCK) == -1 ||
	    fixture_service_ready() == -1)
		return (1);
	memset(contexts, 0, sizeof(contexts));
	contexts[0].client = client;
	contexts[0].count = 50;
	contexts[1].client = second;
	contexts[1].first = 50;
	contexts[1].count = 50;
	if (pthread_create(&threads[0], NULL, log_thread, &contexts[0]) != 0 ||
	    pthread_create(&threads[1], NULL, log_thread, &contexts[1]) != 0 ||
	    pthread_join(threads[0], NULL) != 0 ||
	    pthread_join(threads[1], NULL) != 0 ||
	    contexts[0].error != 0 || contexts[1].error != 0 ||
	    logcmp_flush(client) == -1 ||
	    logcmp_stats(client, &stats) == -1 ||
	    stats.accepted != 100 || stats.rejected != 0)
		return (1);
	logcmp_client_close(client);
	if (emit_log(second, "after first close") == -1 ||
	    logcmp_flush(second) == -1)
		return (1);
	logcmp_client_close(second);
	if (logcmp_client_open(&reopened) == -1 ||
	    emit_log(reopened, "after reopen") == -1 ||
	    logcmp_flush(reopened) == -1 ||
	    logcmp_stats(reopened, &stats) == -1 ||
	    stats.accepted != 102 || stats.rejected != 0)
		return (1);
	if (dprintf(out,
	    "logging=ok\nmulti_open=ok\nconcurrent=ok\nreopen=ok\n"
	    "fork_isolated=ok\naccepted=%ju\n",
	    (uintmax_t)stats.accepted) < 0)
		return (1);
	logcmp_client_close(reopened);
	close(out);
	return (0);
}

static int
run_network_consumer(const char *output_path)
{
	struct network_thread_context contexts[2];
	struct networkcmp_endpoint endpoint;
	struct networkcmp_handle socket;
	struct networkcmp_hello_reply hello;
	struct networkcmp_client *client, *reopened, *second;
	pthread_t threads[2];
	int out, status, i;

	out = open(output_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (out == -1 || fixture_service_initialize() == -1 ||
	    service_authorize_capabilities(fixture_service_context) == -1 ||
	    service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOEXEC | SERVICE_PROTECT_NOSOCK) == -1 ||
	    networkcmp_client_open(&client) == -1 ||
	    networkcmp_client_open(&second) == -1 ||
	    fixture_service_ready() == -1 ||
	    networkcmp_hello(client, &hello) == -1 ||
	    (hello.features & NETWORKCMP_FEATURE_TCP) == 0)
		return (1);
	memset(contexts, 0, sizeof(contexts));
	contexts[0].client = client;
	contexts[0].count = 100;
	contexts[1].client = second;
	contexts[1].count = 100;
	if (pthread_create(&threads[0], NULL, network_thread, &contexts[0]) !=
	    0 ||
	    pthread_create(&threads[1], NULL, network_thread, &contexts[1]) !=
	    0 ||
	    pthread_join(threads[0], NULL) != 0 ||
	    pthread_join(threads[1], NULL) != 0 ||
	    contexts[0].error != 0 || contexts[1].error != 0)
		return (1);
	networkcmp_client_close(second);
	if (networkcmp_client_open(&reopened) == -1 ||
	    networkcmp_hello(reopened, &hello) == -1)
		return (1);
	networkcmp_client_close(reopened);
	memset(&endpoint, 0, sizeof(endpoint));
	endpoint.family = NETWORKCMP_AF_INET4;
	endpoint.address[0] = 127;
	endpoint.address[3] = 1;
	endpoint.port = 9;
	if (networkcmp_socket(client, NETWORKCMP_AF_INET4,
	    NETWORKCMP_SOCK_STREAM, IPPROTO_TCP, 0, &socket) == -1)
		return (1);
	errno = 0;
	if (networkcmp_bind(client, socket, &endpoint) != -1 ||
	    errno != EACCES)
		return (1);
	status = networkcmp_connect(client, socket, &endpoint);
	if (status == -1 && errno != EINPROGRESS && errno != ECONNREFUSED)
		return (1);
	for (i = 0; status == -1 && errno == EINPROGRESS && i < 200; i++) {
		status = networkcmp_connect_status(client, socket);
		if (status == 0)
			break;
		if (errno == ECONNREFUSED)
			break;
		if (errno != EINPROGRESS)
			return (1);
		usleep(5000);
	}
	if (i == 200 || networkcmp_close_socket(client, socket) == -1)
		return (1);
	networkcmp_client_close(client);
	if (networkcmp_client_open(&reopened) == -1 ||
	    networkcmp_hello(reopened, &hello) == -1)
		return (1);
	networkcmp_client_close(reopened);
	if (dprintf(out, "network=ok\nnonblocking=ok\nconnect_status=ok\n"
	    "connect_only=ok\nprovider_owned_sockets=ok\nmulti_session=ok\n"
	    "concurrent=ok\nclose_reopen=ok\n") < 0)
		return (1);
	close(out);
	return (0);
}

static int
run_trace_consumer(const char *output_path)
{
	int out, tracefd, trace_error;

	out = open(output_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (out == -1 || fixture_service_initialize() == -1 ||
	    service_authorize_capabilities(fixture_service_context) == -1 ||
	    service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOEXEC | SERVICE_PROTECT_NOSOCK) == -1)
		return (1);
	errno = 0;
	trace_error = tracecmp_open(&tracefd) == -1 ? errno : 0;
	if (trace_error != EOPNOTSUPP || tracefd != -1 ||
	    fixture_service_ready() == -1)
		return (1);
	if (dprintf(out,
	    "trace=ok\nraw_descriptor=denied\ntrace_errno=%d\n",
	    trace_error) < 0)
		return (1);
	close(out);
	return (0);
}

static int
run_notify_subscriber(const char *output_path)
{
	struct notify_thread_context contexts[2];
	struct notify_client *client, *second, *reopened;
	struct notify_stats stats;
	pthread_t threads[2];
	int inherited[64], j, out, status;
	pid_t child;

	out = open(output_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (out == -1 || fixture_service_initialize() == -1 ||
	    service_authorize_capabilities(fixture_service_context) == -1 ||
	    notify_client_open(&client) == -1 ||
	    notify_client_open(&second) == -1 ||
	    (child = fork()) == -1)
		return (1);
	if (child == 0) {
		if (notify_stats(client, &stats) != -1)
			_exit(1);
		for (j = 0; j < (int)nitems(inherited); j++) {
			inherited[j] = open("/dev/null", O_RDONLY | O_CLOEXEC);
			if (inherited[j] == -1)
				_exit(1);
		}
		notify_client_close(client);
		for (j = 0; j < (int)nitems(inherited); j++) {
			if (fcntl(inherited[j], F_GETFD) == -1)
				_exit(1);
			close(inherited[j]);
		}
		_exit(0);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0 ||
	    service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOEXEC | SERVICE_PROTECT_NOSOCK) == -1)
		return (1);
	errno = 0;
	if (notify_subscribe(client, "integration.forbidden") != -1 ||
	    errno != EACCES)
		return (1);
	errno = 0;
	if (notify_publish(client, "integration.ready", "denied", 6) != -1 ||
	    errno != EACCES)
		return (1);
	errno = 0;
	if (notify_timer_add(client, 42, 10, 0) != -1 ||
	    errno != EACCES || fixture_service_ready() == -1)
		return (1);
	memset(contexts, 0, sizeof(contexts));
	contexts[0].client = client;
	contexts[0].count = 100;
	contexts[1].client = second;
	contexts[1].count = 100;
	if (pthread_create(&threads[0], NULL, notify_thread, &contexts[0]) != 0 ||
	    pthread_create(&threads[1], NULL, notify_thread, &contexts[1]) != 0 ||
	    pthread_join(threads[0], NULL) != 0 ||
	    pthread_join(threads[1], NULL) != 0 ||
	    contexts[0].error != 0 || contexts[1].error != 0)
		return (1);
	notify_client_close(second);
	if (notify_client_open(&reopened) == -1 ||
	    notify_stats(reopened, &stats) == -1)
		return (1);
	if (dprintf(out,
	    "notification=ok\ndefault_deny=ok\nmulti_open=ok\n"
	    "concurrent=ok\nclose_reopen=ok\nfork_isolated=ok\n") < 0)
		return (1);
	notify_client_close(reopened);
	notify_client_close(client);
	close(out);
	return (0);
}

static int
run_notify_publisher(void)
{
	struct notify_client *client;

	if (fixture_service_initialize() == -1 || service_authorize_capabilities(fixture_service_context) == -1 ||
	    service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOEXEC | SERVICE_PROTECT_NOSOCK) == -1 ||
	    notify_client_open(&client) == -1 ||
	    fixture_service_ready() == -1)
		return (1);
	errno = 0;
	if (notify_publish(client, "integration.forbidden", "no", 2) != -1 ||
	    errno != EACCES)
		return (1);
	errno = 0;
	if (notify_subscribe(client, "integration.ready") != -1 ||
	    errno != EACCES)
		return (1);
	errno = 0;
	if (notify_timer_add(client, 9, 10, 0) != -1 ||
	    errno != EACCES)
		return (1);
	notify_client_close(client);
	return (0);
}

int
main(int argc, char **argv)
{

	if (argc == 3 && strcmp(argv[1], "filesystem-consumer") == 0)
		return (run_filesystem_consumer(argv[2]));
	if (argc == 3 && strcmp(argv[1], "log-consumer") == 0)
		return (run_log_consumer(argv[2]));
	if (argc == 3 && strcmp(argv[1], "network-consumer") == 0)
		return (run_network_consumer(argv[2]));
	if (argc == 3 && strcmp(argv[1], "trace-consumer") == 0)
		return (run_trace_consumer(argv[2]));
	if (argc == 3 && strcmp(argv[1], "notify-subscriber") == 0)
		return (run_notify_subscriber(argv[2]));
	if (argc == 2 && strcmp(argv[1], "notify-publisher") == 0)
		return (run_notify_publisher());
	fprintf(stderr,
	    "usage: component_fixture filesystem-consumer output | "
	    "log-consumer output | "
	    "network-consumer output | trace-consumer output | "
	    "notify-subscriber output | "
	    "notify-publisher\n");
	return (2);
}
