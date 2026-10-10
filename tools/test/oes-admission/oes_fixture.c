/* SPDX-License-Identifier: BSD-2-Clause */
/* Disposable VM fixture: real OES factory, no filesystem/storage backend. */
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <capsule_ctl.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <liboes.h>
#include <libservice.h>
#include <switchboard_ctl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "oes_factory.h"
#include "coalition_fixture.h"
#include "oes_broker_protocol.h"

static int
provider(void)
{
	struct service_provider *provider;
	struct service_listener *listener;
	struct service_identity id;
	struct pollfd pollfd;
	int root, fd, status, readyfd;
	pid_t child;

	if (service_resource_dir("/", &root) == -1)
		err(1, "provider root resource");
	readyfd = openat(root, "tmp/oes-provider-ready",
	    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	if (readyfd == -1)
		err(1, "provider readiness file");
	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_expose(provider, OES_BROKER_ENDPOINT, &listener) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		err(1, "OES provider setup");
	/* Publish only after SwitchBoard acknowledges application readiness. */
	if (write(readyfd, "ready\n", 6) != 6 || close(readyfd) == -1)
		err(1, "provider readiness publication");
	pollfd = (struct pollfd){ .fd = service_listener_fd(listener),
	    .events = POLLIN };
	for (;;) {
		if (poll(&pollfd, 1, -1) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "provider poll");
		}
		memset(&id, 0, sizeof(id));
		id.size = sizeof(id);
		if (service_listener_accept(listener, &id, &fd) == -1) {
			if (service_provider_quiescing(provider) == 1)
				return (service_provider_quiesce_complete(provider, 0) == 0 ? 0 : 1);
			if (errno == EAGAIN || errno == EINTR)
				continue;
			err(1, "provider accept");
		}
		child = fork();
		if (child == -1)
			err(1, "factory fork");
		if (child == 0)
			_exit(bsdfilesystem_oes_serve(root, fd));
		close(fd);
		if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
		    WEXITSTATUS(status) != 0)
			err(1, "factory completion");
	}
}

static void
wait_provider(void)
{
	struct timespec start, now, delay = { .tv_nsec = 100000000 };
	struct stat st;

	if (clock_gettime(CLOCK_MONOTONIC, &start) == -1)
		err(1, "readiness clock");
	for (;;) {
		if (stat("/tmp/oes-provider-ready", &st) == 0 &&
		    S_ISREG(st.st_mode) && st.st_uid == 0 && st.st_size == 6)
			return;
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
			err(1, "readiness clock");
		if (now.tv_sec - start.tv_sec >= 60)
			errx(1, "provider readiness timed out");
		nanosleep(&delay, NULL);
	}
}

static int
consumer(const char *expectation, const char *path, uid_t uid)
{
	oes_client_t *client;
	oes_event_type_t event = OES_EVENT_NOTIFY_EXEC;
	uint32_t mode, scope;
	int error, fd, raw;
	bool allow = strcmp(expectation, "allow") == 0;

	if (geteuid() != uid || getuid() != uid)
		errx(1, "unexpected consumer uid");
	wait_provider();
	/* Denials must be tested against an endpoint already proven usable. */
	if (!allow) {
		struct timespec start, now, delay = { .tv_nsec = 100000000 };

		if (clock_gettime(CLOCK_MONOTONIC, &start) == -1)
			err(1, "client clock");
		while (access("/tmp/oes-allow", F_OK) == -1) {
			if (errno != ENOENT)
				err(1, "approved result wait");
			if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
				err(1, "client clock");
			if (now.tv_sec - start.tv_sec >= 10)
				errx(1, "approved client did not establish endpoint readiness");
			nanosleep(&delay, NULL);
		}
	}
	client = oes_client_create_brokered();
	error = errno;
	if (allow) {
		if (client == NULL)
			err(1, "approved OES lookup");
		if (oes_get_mode(client, &mode, NULL, NULL) == -1 ||
		    mode != OES_MODE_NOTIFY || oes_get_scope(client, &scope) == -1 ||
		    scope != OES_SCOPE_GLOBAL ||
		    oes_subscribe(client, &event, 1, OES_SUB_REPLACE) == -1)
			err(1, "approved OES client use");
		raw = oes_client_fd(client);
		oes_client_destroy(client);
		if (fcntl(raw, F_GETFD) != -1 || errno != EBADF)
			errx(1, "OES descriptor leaked");
	} else {
		if (client != NULL)
			errx(1, "unapproved OES client admitted");
		/* Discovery masks a gated name as absent. */
		if (error != ENOENT && error != EACCES)
			errx(1, "unexpected denial error %d", error);
	}
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd == -1)
		err(1, "result open");
	if (dprintf(fd, "%s uid=%u\n", expectation, (unsigned)uid) < 0 ||
	    close(fd) == -1)
		err(1, "result write");
	return (0);
}

static void
print_log(FILE *serial, const char *path)
{
	char buffer[1024];
	FILE *file = fopen(path, "r");

	if (file == NULL)
		return;
	fprintf(serial, "OES_STACK_LOG %s\n", path);
	while (fgets(buffer, sizeof(buffer), file) != NULL)
		fputs(buffer, serial);
	fclose(file);
}

static bool
result_ready(const char *name, const char *expected, uid_t uid)
{
	char path[128], text[128];
	struct stat st;
	FILE *file;
	bool valid;

	snprintf(path, sizeof(path), "/tmp/oes-%s", name);
	file = fopen(path, "r");
	if (file == NULL)
		return (false);
	valid = fstat(fileno(file), &st) == 0 && st.st_uid == uid &&
	    fgets(text, sizeof(text), file) != NULL && strcmp(text, expected) == 0;
	fclose(file);
	return (valid);
}

static int
poweroff(void)
{
	struct service_session *session;
	struct ctl_request request = { .op = CTL_OP_POWEROFF };
	struct ctl_reply data;
	struct service_message message = { .size = sizeof(message),
	    .data = &request, .length = sizeof(request) };
	struct service_reply reply = { .size = sizeof(reply),
	    .data = &data, .capacity = sizeof(data) };
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	int fd, result, error;

	if (service_open(SWITCHBOARD_LIFECYCLE_NAME, &fd) == -1)
		return (-1);
	if (service_session_create(fd, &session) == -1) {
		error = errno;
		close(fd);
		return (errno = error, -1);
	}
	options.timeout_ms = 5000;
	result = service_session_call(session, &message, &reply, &options);
	error = errno;
	if (result == 0 && (reply.length != sizeof(data) || reply.nfds != 0 ||
	    data.flags != 0 || data.status != 0)) {
		result = -1;
		error = EPROTO;
	}
	service_session_close(session);
	return (errno = error, result);
}

static pid_t
start_application(const char *program, const char *expectation, const char *result)
{
	pid_t child = fork();

	if (child == -1)
		err(1, "application fork");
	if (child == 0) {
		if (setgroups(0, NULL) == -1 || setgid(65534) == -1 ||
		    setuid(65534) == -1)
			err(1, "application credentials");
		execl(program, program, "consumer", expectation, result, "65534", NULL);
		err(1, "application exec");
	}
	return (child);
}

/* 1: all exited successfully, 0: still running, -1: failed. */
static int
applications_done(pid_t *children, size_t count, FILE *serial)
{
	int status;
	pid_t result;
	bool done = true;

	for (size_t i = 0; i < count; i++) {
		if (children[i] < 0)
			continue;
		result = waitpid(children[i], &status, WNOHANG);
		if (result == children[i]) {
			children[i] = -1;
			if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
				fprintf(serial, "OES_APPLICATION_FAIL index=%zu status=%d\n",
				    i, status);
				return (-1);
			}
		} else if (result == -1 && errno != EINTR) {
			fprintf(serial, "OES_APPLICATION_FAIL index=%zu errno=%d\n",
			    i, errno);
			return (-1);
		} else
			done = false;
	}
	return (done);
}

static int
coordinator(void)
{
	struct timespec start, now, delay = { .tv_nsec = 100000000 };
	FILE *serial;
	pid_t children[3];
	int fd, applications;
	bool ready = false;

	fd = open("/dev/console", O_WRONLY | O_NOCTTY);
	if (fd == -1 || (serial = fdopen(fd, "w")) == NULL)
		err(1, "coordinator console");
	setvbuf(serial, NULL, _IONBF, 0);
	wait_provider();
	children[0] = start_application(
	    "/Capabilities/System/OESApplicationAllowed.cap/Units/client.unit/bin/client",
	    "allow", "/tmp/oes-app-allow");
	children[1] = start_application(
	    "/Capabilities/System/OESApplicationDenied.cap/Units/client.unit/bin/client",
	    "deny", "/tmp/oes-app-deny");
	children[2] = start_application("/tests/oes-unregistered", "deny", "/tmp/oes-unregistered");
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		applications = applications_done(children, 3, serial);
		if (applications == -1)
			break;
		ready = result_ready("allow", "allow uid=65534\n", 65534) &&
		    result_ready("deny", "deny uid=65534\n", 65534) &&
		    result_ready("root-deny", "deny uid=0\n", 0) &&
		    result_ready("wrong-attribute", "deny uid=65534\n", 65534) &&
		    result_ready("app-allow", "allow uid=65534\n", 65534) &&
		    result_ready("app-deny", "deny uid=65534\n", 65534) &&
		    result_ready("unregistered", "deny uid=65534\n", 65534) &&
		    applications == 1;
		if (ready)
			break;
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - start.tv_sec >= 25)
			break;
		nanosleep(&delay, NULL);
	}
	fprintf(serial, "%s\n", ready ? "OES_ADMISSION_PASS" : "OES_ADMISSION_FAIL");
	if (ready && coalition_exercise(serial) == -1)
		ready = false;
	print_log(serial, "/var/log/capability.log");
	fprintf(serial, "%s\n", ready ? "RUNTIME_VM_PASS" : "RUNTIME_VM_FAIL");
	/* The runner additionally requires Capsule's clean guest poweroff. */
	if (poweroff() == -1) {
		fprintf(serial, "RUNTIME_VM_FAIL poweroff request errno=%d\n", errno);
		return (1);
	}
	for (;;)
		pause();
}

int
main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "prepare-coalition") == 0)
		return (coalition_prepare() == 0 ? 0 : 1);
	if (argc == 3 && strcmp(argv[1], "coalition-worker") == 0)
		return (coalition_worker(argv[2]));
	if (argc == 2 && strcmp(argv[1], "coordinator") == 0)
		return (coordinator());
	if (argc == 2 && strcmp(argv[1], "provider") == 0)
		return (provider());
	if (argc == 5 && strcmp(argv[1], "consumer") == 0 &&
	    (strcmp(argv[2], "allow") == 0 || strcmp(argv[2], "deny") == 0) &&
	    (strcmp(argv[4], "0") == 0 || strcmp(argv[4], "65534") == 0))
		return (consumer(argv[2], argv[3], (uid_t)strtoul(argv[4], NULL, 10)));
	errx(64, "invalid fixture arguments");
}
