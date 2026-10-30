/* SPDX-License-Identifier: BSD-2-Clause */
/* Console observer: results arrive through the manager-authenticated endpoint. */
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "storage_test.h"
#include <stdio.h>
#include <string.h>
#include <libservice.h>
#include <libservice_session.h>
int
main(int argc, char **argv)
{
	struct service_session *session;
	struct storage_test_request request = { .version = STORAGE_TEST_VERSION };
	struct storage_test_result result;
	char extra;
	size_t i;
	struct service_message message = { .size = sizeof(message), .data = &request, .length = sizeof(request) };
	struct service_reply reply = { .size = sizeof(reply), .data = &result, .capacity = sizeof(result) };
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	int fd;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc == 2 && strcmp(argv[1], "--provider-crash") == 0)
		request.flags = STORAGE_TEST_CRASH;
	else if (argc != 1)
		return (1);
	fd = open("/etc/storage-test-challenge", O_RDONLY | O_NOFOLLOW);
	if (fd == -1 || read(fd, request.challenge, sizeof(request.challenge)) != sizeof(request.challenge) ||
	    read(fd, &extra, 1) != 0 || close(fd) == -1) {
		puts("STORAGE_PROVIDER_FAIL invalid challenge input");
		return (1);
	}
	for (i = 0; i < sizeof(request.challenge); i++) {
		if (!((request.challenge[i] >= '0' && request.challenge[i] <= '9') ||
		    (request.challenge[i] >= 'a' && request.challenge[i] <= 'f'))) {
			puts("STORAGE_PROVIDER_FAIL invalid challenge encoding");
			return (1);
		}
	}
	options.timeout_ms = 45000;
	if (service_open("test.StorageClient", &fd) == -1 ||
	    service_session_create(fd, &session) == -1 ||
	    service_session_call(session, &message, &reply, &options) == -1 ||
	    reply.length != sizeof(result) || reply.nfds != 0) {
		printf("STORAGE_PROVIDER_FAIL observer errno=%d\n", errno);
		return (1);
	}
	service_session_close(session);
	printf("STORAGE_WORKER_MANAGEMENT_CHECK result=%u\n", result.worker_management);
	printf("STORAGE_CHANNEL_AFTER_FORK result=%d errno=%d\n",
	    result.channel_fork.result, result.channel_fork.error);
	printf("STORAGE_RETAINED_AFTER_FORK read=%d read_errno=%d write=%d write_errno=%d\n",
	    result.fork_read_result, result.fork_read_errno,
	    result.fork_write_result, result.fork_write_errno);
	printf("STORAGE_RETAINED_AFTER_CLEAR read=%d read_errno=%d write=%d write_errno=%d\n",
	    result.retained_read_result, result.retained_read_errno,
	    result.retained_write_result, result.retained_write_errno);
	static const char *operations[] = {"open", "create", "truncate", "setmode"};
	if (request.flags & STORAGE_TEST_CRASH)
		printf("STORAGE_PROVIDER_RESTART recovered=%u read=%d read_errno=%d write=%d write_errno=%d\n",
		    result.restart_recovered, result.restart_read.result, result.restart_read.error,
		    result.restart_write.result, result.restart_write.error);
	static const char *release_operations[] = {"read", "write", "open"};
	for (unsigned scope = 0; scope < STORAGE_TEST_SCOPES; scope++)
		for (unsigned operation = 0; operation < STORAGE_RELEASE_OPERATIONS; operation++)
			printf("STORAGE_AFTER_RELEASE scope=%u op=%s result=%d errno=%d\n",
			    scope, release_operations[operation], result.release[scope][operation].result,
			    result.release[scope][operation].error);
	for (i = 0; i < STORAGE_NAMESPACE_OPERATIONS; i++) {
		printf("STORAGE_NAMESPACE_AFTER_FORK op=%s result=%d errno=%d\n",
		    operations[i], result.fork_namespace[i].result, result.fork_namespace[i].error);
		printf("STORAGE_NAMESPACE_AFTER_CLEAR op=%s result=%d errno=%d\n",
		    operations[i], result.clear_namespace[i].result, result.clear_namespace[i].error);
	}
	if (result.line != 0 || (result.phase != STORAGE_TEST_CREATED &&
	    result.phase != STORAGE_TEST_RECOVERED)) {
		printf("STORAGE_PROVIDER_FAIL client line=%d errno=%d\n", result.line, result.error);
		return (1);
	}
	printf("STORAGE_PROVIDER_PASS phase=%s challenge=%.*s scopes=4\n",
	    result.phase == STORAGE_TEST_CREATED ? "created" : "recovered",
	    (int)sizeof(request.challenge), request.challenge);
	return (0);
}
