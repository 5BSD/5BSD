/* Unit coverage for the actual oeslogger JSON emitter. */
#include <sys/wait.h>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int oeslogger_program_main(int, char **);
#define main oeslogger_program_main
#include "../../../../share/examples/oes/oeslogger.c"
#undef main

typedef union {
	oes_message_t msg;
	uint8_t raw[OES_MSG_MAX_SIZE];
} logger_message;

static uint32_t
append_string(logger_message *storage, uint32_t *next, const char *value)
{
	uint32_t off;
	size_t length;

	off = *next;
	length = strlen(value) + 1;
	memcpy(storage->raw + off, value, length);
	*next += (uint32_t)length;
	return (off);
}

static int
require_field(const char *json, const char *field)
{

	if (strstr(json, field) != NULL)
		return (0);
	fprintf(stderr, "FAIL: oeslogger output missing %s\n", field);
	return (1);
}

static int
test_cli_list_options(void)
{
	char arg0[] = "oeslogger";
	char arg1[] = "-d";
	char arg2[] = "-n";
	char arg3[] = "-m";
	char arg4[] = "/tmp";
	char arg5[] = "-l";
	char *argv[] = {
		arg0, arg1, arg2, arg3, arg4, arg5, NULL,
	};
	pid_t child;
	int fd, status;

	child = fork();
	if (child < 0)
		return (1);
	if (child == 0) {
		fd = open("/dev/null", O_WRONLY);
		if (fd >= 0) {
			dup2(fd, STDERR_FILENO);
			close(fd);
		}
		optind = 1;
		_exit(oeslogger_program_main(6, argv));
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0) {
		fprintf(stderr, "FAIL: oeslogger rejected -d/-n/-m options\n");
		return (1);
	}
	return (0);
}

static int
test_live_cli_configuration(void)
{
	char arg0[] = "oeslogger";
	char arg1[] = "-d";
	char arg2[] = "-n";
	char arg3[] = "-m";
	char arg4[] = "/tmp/oeslogger-test-muted";
	char arg5[] = "open";
	char *argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, NULL };
	char output[2048];
	struct pollfd pfd;
	pid_t child;
	ssize_t n, used;
	int fds[2], i, status;

	if (pipe(fds) != 0)
		return (1);
	child = fork();
	if (child < 0)
		return (1);
	if (child == 0) {
		close(fds[0]);
		dup2(fds[1], STDERR_FILENO);
		close(fds[1]);
		optind = 1;
		running = 1;
		_exit(oeslogger_program_main(6, argv));
	}
	close(fds[1]);
	used = 0;
	pfd.fd = fds[0];
	pfd.events = POLLIN;
	for (i = 0; i < 30 && used < (ssize_t)sizeof(output) - 1; i++) {
		if (poll(&pfd, 1, 100) <= 0)
			continue;
		n = read(fds[0], output + used, sizeof(output) - 1 - used);
		if (n <= 0)
			break;
		used += n;
		output[used] = '\0';
		if (strstr(output, "listening for events") != NULL)
			break;
	}
	if (used == 0 || strstr(output, "listening for events") == NULL) {
		kill(child, SIGKILL);
		waitpid(child, &status, 0);
		close(fds[0]);
		fprintf(stderr, "FAIL: oeslogger did not finish live setup\n");
		return (1);
	}
	if (kill(child, SIGTERM) != 0) {
		perror("kill oeslogger");
		kill(child, SIGKILL);
		waitpid(child, &status, 0);
		close(fds[0]);
		return (1);
	}
	close(fds[0]);
	for (i = 0; i < 20; i++) {
		if (waitpid(child, &status, WNOHANG) == child)
			break;
		usleep(100000);
	}
	if (i == 20) {
		kill(child, SIGKILL);
		waitpid(child, &status, 0);
		fprintf(stderr, "FAIL: configured oeslogger ignored SIGTERM\n");
		return (1);
	}
	if (!WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0) {
		fprintf(stderr, "FAIL: configured oeslogger did not stop cleanly\n");
		return (1);
	}
	printf("    PASS: oeslogger applies -d/-n/-m and subscribes live\n");
	return (0);
}

static int
test_json_escaping(void)
{
	static const char input[] = { '"', '\\', '\n', 1, (char)0xc0, 'x' };
	const char expected[] = "\"\\\"\\\\\\n\\u0001\\u00c0x\"";
	char *json;
	size_t json_len;
	FILE *fp;
	int failed;

	json = NULL;
	json_len = 0;
	fp = open_memstream(&json, &json_len);
	if (fp == NULL)
		return (1);
	json_escape_n(input, sizeof(input), fp);
	fclose(fp);
	failed = strcmp(json, expected) != 0;
	if (failed)
		fprintf(stderr, "FAIL: JSON escaping produced %s\n", json);
	else
		printf("    PASS: oeslogger escapes controls and invalid UTF-8\n");
	free(json);
	return (failed);
}

static int
test_exec_offset_overflow(void)
{
	logger_message storage;
	oes_message_t *msg;
	char *json;
	size_t json_len;
	int failed;

	memset(&storage, 0, sizeof(storage));
	msg = &storage.msg;
	msg->em_version = OES_MESSAGE_VERSION;
	msg->em_struct_size = sizeof(*msg);
	msg->em_size = sizeof(*msg);
	msg->em_event = OES_EVENT_NOTIFY_EXEC;
	msg->em_action = OES_ACTION_NOTIFY;
	msg->em_event_data.exec.argv_off = UINT32_MAX - 4;
	msg->em_event_data.exec.argv_len = 32;
	msg->em_event_data.exec.envp_off = UINT32_MAX - 4;
	msg->em_event_data.exec.envp_len = 32;
	json = NULL;
	json_len = 0;
	outfp = open_memstream(&json, &json_len);
	if (outfp == NULL)
		return (1);
	pretty = false;
	running = 1;
	(void)handle_event(NULL, msg, NULL);
	fclose(outfp);
	failed = strstr(json, "\"argv\":[]") == NULL ||
	    strstr(json, "\"envp\":[]") == NULL;
	if (failed)
		fprintf(stderr, "FAIL: overflowed exec ranges were emitted\n");
	else
		printf("    PASS: overflowed exec ranges are rejected\n");
	free(json);
	return (failed);
}

int
main(void)
{
	logger_message storage;
	oes_message_t *msg;
	char *json;
	size_t json_len;
	uint32_t next;
	int errors;

	memset(&storage, 0, sizeof(storage));
	msg = &storage.msg;
	msg->em_version = OES_MESSAGE_VERSION;
	msg->em_struct_size = sizeof(*msg);
	msg->em_event = OES_EVENT_NOTIFY_OPEN;
	msg->em_action = OES_ACTION_NOTIFY;
	msg->em_id = 11;
	msg->em_seq_num = 7;
	msg->em_global_seq_num = 9;
	msg->em_wall_time.tv_sec = 1;
	msg->em_wall_time.tv_nsec = 2;
	msg->em_time.tv_sec = 3;
	msg->em_time.tv_nsec = 4;
	msg->em_thread.et_flags = OES_THREAD_META_PRESENT;
	msg->em_thread.et_id = 42;
	strlcpy(msg->em_thread.et_name, "worker",
	    sizeof(msg->em_thread.et_name));
	msg->em_process.ep_pid = 123;
	msg->em_process.ep_flags = EP_FLAG_OES_CLIENT;
	strlcpy(msg->em_process.ep_comm, "actor",
	    sizeof(msg->em_process.ep_comm));
	next = sizeof(*msg);
	msg->em_process.ep_path_off = append_string(&storage, &next,
	    "/usr/bin/actor");
	msg->em_event_data.open.file.ef_path_off = append_string(&storage, &next,
	    "/tmp/object");
	msg->em_size = OES_MSG_ALIGNED(next);

	json = NULL;
	json_len = 0;
	outfp = open_memstream(&json, &json_len);
	if (outfp == NULL)
		return (1);
	pretty = false;
	running = 1;
	if (!handle_event(NULL, msg, NULL))
		return (1);
	fclose(outfp);

	errors = 0;
	errors += require_field(json, "\"event_type\":\"NOTIFY_OPEN\"");
	errors += require_field(json, "\"seq_num\":7");
	errors += require_field(json, "\"global_seq_num\":9");
	errors += require_field(json,
	    "\"timestamp\":\"1970-01-01T00:00:01.000000002Z\"");
	errors += require_field(json, "\"thread\":{\"id\":42");
	errors += require_field(json, "\"path\":\"/usr/bin/actor\"");
	errors += require_field(json, "\"path\":\"/tmp/object\"");
	errors += require_field(json, "\"path_unavailable\":false");
	errors += require_field(json, "\"is_oes_client\":true");
	errors += test_cli_list_options();
	errors += test_live_cli_configuration();
	errors += test_json_escaping();
	errors += test_exec_offset_overflow();
	if (json_len == 0 || json[json_len - 1] != '\n') {
		fprintf(stderr, "FAIL: oeslogger output is not JSON Lines\n");
		errors++;
	}
	free(json);
	if (errors == 0)
		printf("oeslogger output: ok\n");
	return (errors != 0);
}
