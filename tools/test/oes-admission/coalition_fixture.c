/* SPDX-License-Identifier: BSD-2-Clause */
/* Private VM only: mutate one tmpfs bundle through the public reload API. */
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <libservice.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <switchboard_ctl.h>
#include <time.h>
#include <unistd.h>

#include "coalition_fixture.h"

#define BUNDLE "/Capabilities/System/CoalitionLifecycle.cap"
#define UNIT BUNDLE "/Units/worker.unit"
#define LABEL "system.CoalitionLifecycle/worker"
#define RUNTIME "/Capabilities/Run/system_CoalitionLifecycle_worker"

static int
write_file(const char *path, const char *text)
{
	char temp[1024];
	FILE *file;
	int error;

	if (snprintf(temp, sizeof(temp), "%s.new", path) >= (int)sizeof(temp))
		return (errno = ENAMETOOLONG, -1);
	file = fopen(temp, "w");
	if (file == NULL)
		return (-1);
	if (fputs(text, file) == EOF || fflush(file) == EOF) {
		error = errno;
		fclose(file);
		unlink(temp);
		return (errno = error, -1);
	}
	if (fclose(file) == EOF)
		return (-1);
	return (rename(temp, path));
}

static int
manifest(unsigned generation, bool remove)
{
	char text[1024];

	if (remove) {
		/* A valid bundle has no undeclared unit directories. */
		if (unlink(UNIT "/bin/worker") == -1 ||
		    unlink(UNIT "/Unit.ucl") == -1 ||
		    rmdir(UNIT "/bin") == -1 || rmdir(UNIT) == -1)
			return (-1);
	} else {
		snprintf(text, sizeof(text),
		    "program=\"worker\"; activation={boot=true;}; ambient=true; "
		    "protocol=\"unix\"; restart=\"never\"; user=\"root\"; "
		    "arguments=[\"coalition-worker\",\"%u\"];\n", generation);
		if (write_file(UNIT "/Unit.ucl", text) == -1)
			return (-1);
	}
	snprintf(text, sizeof(text),
	    "schema=\"org.5bsd.capability-bundle\"; "
	    "bundle_id=\"system.CoalitionLifecycle\"; version=\"1.0.%u\"; "
	    "sequence=%u; author=\"5BSD\"; publisher=\"org.5bsd.base\"; "
	    "units=[%s\"keeper\"];\n", generation, generation,
	    remove ? "" : "\"worker\",");
	return (write_file(BUNDLE "/Bundle.ucl", text));
}

int
coalition_prepare(void)
{
	const char *dirs[] = { BUNDLE "/Units", UNIT, UNIT "/bin",
	    BUNDLE "/Units/keeper.unit", BUNDLE "/Units/keeper.unit/bin" };
	const char *programs[] = { UNIT "/bin/worker",
	    BUNDLE "/Units/keeper.unit/bin/keeper" };
	char bytes[16384];
	ssize_t n;
	int in, out;

	for (unsigned i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
		if (mkdir(dirs[i], 0755) == -1)
			return (-1);
	for (unsigned i = 0; i < sizeof(programs) / sizeof(programs[0]); i++) {
		in = open("/tests/oes-unregistered", O_RDONLY);
		out = open(programs[i], O_WRONLY | O_CREAT | O_EXCL, 0555);
		if (in == -1 || out == -1)
			return (-1);
		while ((n = read(in, bytes, sizeof(bytes))) > 0) {
			ssize_t off = 0;
			while (off < n) {
				ssize_t written = write(out, bytes + off, n - off);
				if (written <= 0)
					return (-1);
				off += written;
			}
		}
		if (n == -1 || close(out) == -1)
			return (-1);
		close(in);
	}
	if (write_file(BUNDLE "/Units/keeper.unit/Unit.ucl",
	    "program=\"keeper\"; activation={exec=true;};\n") == -1)
		return (-1);
	return (manifest(1, false));
}

int
coalition_worker(const char *generation)
{
	char path[128], text[128];
	int fd, ready[2];
	pid_t child;
	char byte;

	/* O_EXCL catches runtime reuse before the previous generation was cleaned. */
	fd = open(RUNTIME "/held", O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd == -1 || pipe(ready) == -1)
		return (1);
	child = fork();
	if (child == -1)
		return (1);
	if (child == 0) {
		close(ready[0]);
		/* Outlive the leader's ordinary SIGTERM; coalition cleanup kills us. */
		signal(SIGTERM, SIG_IGN);
		(void)write(ready[1], "R", 1);
		close(ready[1]);
		for (;;)
			pause();
	}
	close(ready[1]);
	if (read(ready[0], &byte, 1) != 1)
		return (1);
	close(ready[0]);
	snprintf(path, sizeof(path), "/tmp/coalition-generation-%s", generation);
	snprintf(text, sizeof(text), "%d %d\n", getpid(), child);
	if (write_file(path, text) == -1)
		return (1);
	for (;;)
		pause();
}

static int
control(uint32_t op, char *summary, size_t size)
{
	struct service_session *session;
	struct sctl_request request = { .op = op };
	struct { struct sctl_reply header; char text[SWITCHBOARD_CTL_SUMMARY_MAX]; } data;
	struct service_message message = { .size = sizeof(message),
	    .data = &request, .length = sizeof(request) };
	struct service_reply reply = { .size = sizeof(reply),
	    .data = &data, .capacity = sizeof(data) };
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	int fd, result, error;

	if (service_open(SWITCHBOARD_CONTROL_NAME, &fd) == -1)
		return (-1);
	if (service_session_create(fd, &session) == -1) {
		error = errno;
		close(fd);
		return (errno = error, -1);
	}
	options.timeout_ms = 30000;
	result = service_session_call(session, &message, &reply, &options);
	error = errno;
	service_session_close(session);
	if (result == -1)
		return (errno = error, -1);
	if (reply.length < sizeof(data.header) || data.header.flags >= size ||
	    data.header.flags > sizeof(data.text) || data.header.status > ELAST ||
	    reply.length != sizeof(data.header) + data.header.flags)
		return (errno = EPROTO, -1);
	if (data.header.status != 0)
		return (errno = data.header.status, -1);
	memcpy(summary, data.text, data.header.flags);
	summary[data.header.flags] = '\0';
	return (0);
}

static bool
gone(pid_t pid)
{
	return (kill(pid, 0) == -1 && errno == ESRCH);
}

static int
wait_generation(unsigned generation, pid_t *leader, pid_t *descendant)
{
	char path[128];
	struct timespec start, now, delay = { .tv_nsec = 100000000 };
	FILE *file;
	int fields;

	snprintf(path, sizeof(path), "/tmp/coalition-generation-%u", generation);
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		file = fopen(path, "r");
		if (file != NULL) {
			fields = fscanf(file, "%d %d", leader, descendant);
			fclose(file);
			return (fields == 2 && *leader > 1 && *descendant > 1 ? 0 : -1);
		}
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - start.tv_sec >= 60)
			return (errno = ETIMEDOUT, -1);
		nanosleep(&delay, NULL);
	}
}

int
coalition_exercise(FILE *serial)
{
	char summary[SWITCHBOARD_CTL_SUMMARY_MAX + 1] = "";
	pid_t leader[2], child[2];
	struct timespec start, now, delay = { .tv_nsec = 100000000 };
	struct stat st;

	if (wait_generation(1, &leader[0], &child[0]) == -1 ||
	    manifest(2, false) == -1 ||
	    control(SCTL_OP_RELOAD, summary, sizeof(summary)) == -1)
		goto fail;
	fprintf(serial, "COALITION_RELOAD %s\n", summary);
	if (wait_generation(2, &leader[1], &child[1]) == -1 ||
	    leader[0] == leader[1] || !gone(leader[0]) || !gone(child[0]))
		goto fail;
	if (manifest(3, true) == -1 ||
	    control(SCTL_OP_RELOAD, summary, sizeof(summary)) == -1)
		goto fail;
	fprintf(serial, "COALITION_REMOVE %s\n", summary);
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		if (control(SCTL_OP_STATUS, summary, sizeof(summary)) == -1)
			goto fail;
		if (strstr(summary, LABEL) == NULL && gone(leader[1]) && gone(child[1]) &&
		    stat(RUNTIME, &st) == -1 && errno == ENOENT)
			break;
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - start.tv_sec >= 60) {
			errno = ETIMEDOUT;
			goto fail;
		}
		nanosleep(&delay, NULL);
	}
	fprintf(serial, "COALITION_LIFECYCLE_PASS\n");
	return (0);
fail:
	fprintf(serial, "COALITION_LIFECYCLE_FAIL errno=%d status=%s\n", errno, summary);
	return (-1);
}
