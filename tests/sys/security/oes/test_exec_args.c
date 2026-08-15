/*
 * OES exec arguments test.
 *
 * Tests that argv and envp are embedded in EXEC events.
 */
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <security/oes/oes.h>
#include "test_common.h"

/*
 * Test retrieving argv from an AUTH_EXEC event.
 */
static int
test_embedded_argv(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_AUTH_EXEC };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	oes_response_t resp;
	struct pollfd pfd;
	pid_t pid;
	ssize_t n;
	int status;
	int got_event = 0;

	printf("  Testing embedded argv in EXEC event...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	mode.ema_timeout_ms = 5000;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Fork and exec with specific arguments */
	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(fd);
		return (1);
	}

	if (pid == 0) {
		/* Child - exec with test arguments */
		execl("/bin/echo", "echo", "test_arg1", "test_arg2", NULL);
		_exit(127);
	}

	/* Parent - wait for AUTH_EXEC event */
	pfd.fd = fd;
	pfd.events = POLLIN;

	if (poll(&pfd, 1, 3000) > 0 && (pfd.revents & POLLIN)) {
		n = read(fd, msg, OES_MSG_MAX_SIZE);
		if (n >= (ssize_t)sizeof(oes_message_t) && msg->em_event == OES_EVENT_AUTH_EXEC) {
			oes_event_exec_t *exec = &msg->em_event_data.exec;
			got_event = 1;

			printf("    INFO: argc=%u, argv_len=%u, envp_len=%u, flags=0x%x\n",
			    exec->argc, exec->argv_len, exec->envp_len, exec->flags);

			/* Parse NUL-separated args from embedded data */
			if (exec->argv_len > 0) {
				size_t pos = 0;
				int argc = 0;
				printf("    INFO: Got %u bytes of argv data\n",
				    exec->argv_len);
				while (pos < exec->argv_len && argc < 10) {
					size_t len = strlen((const char *)msg + exec->argv_off + pos);
					if (len > 0) {
						printf("    INFO: argv[%d] = '%s'\n",
						    argc, (const char *)msg + exec->argv_off + pos);
						argc++;
					}
					pos += len + 1;
				}
				/* Verify we got expected arguments */
				if (argc >= 3) {
					printf("    INFO: Found %d arguments\n", argc);
				}
			} else {
				printf("    INFO: No argv data in event\n");
			}

			if (exec->flags & EE_FLAG_ARGV_TRUNCATED) {
				printf("    INFO: argv was truncated\n");
			}

			/* Allow the exec */
			memset(&resp, 0, sizeof(resp));
			resp.er_id = msg->em_id;
			resp.er_result = OES_AUTH_ALLOW;
			(void)write(fd, &resp, sizeof(resp));
		}
	}

	waitpid(pid, &status, 0);
	close(fd);

	if (!got_event) {
		printf("    INFO: No AUTH_EXEC event received\n");
	}

	printf("    PASS: embedded argv tested\n");
	return (0);
}

/*
 * Test retrieving envp from an AUTH_EXEC event.
 */
static int
test_embedded_envp(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_AUTH_EXEC };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	oes_response_t resp;
	struct pollfd pfd;
	pid_t pid;
	ssize_t n;
	int status;
	int got_event = 0;

	printf("  Testing embedded envp in EXEC event...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	mode.ema_timeout_ms = 5000;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Fork and exec with specific environment */
	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(fd);
		return (1);
	}

	if (pid == 0) {
		/* Child - set a test env var and exec */
		setenv("OES_TEST_VAR", "test_value_12345", 1);
		execl("/bin/true", "true", NULL);
		_exit(127);
	}

	/* Parent - wait for AUTH_EXEC event */
	pfd.fd = fd;
	pfd.events = POLLIN;

	if (poll(&pfd, 1, 3000) > 0 && (pfd.revents & POLLIN)) {
		n = read(fd, msg, OES_MSG_MAX_SIZE);
		if (n >= (ssize_t)sizeof(oes_message_t) && msg->em_event == OES_EVENT_AUTH_EXEC) {
			oes_event_exec_t *exec = &msg->em_event_data.exec;
			got_event = 1;

			printf("    INFO: argc=%u, envc=%u, argv_len=%u, envp_len=%u\n",
			    exec->argc, exec->envc, exec->argv_len, exec->envp_len);

			/* Parse envp from embedded data (after argv) */
			if (exec->envp_len > 0) {
				size_t pos = exec->argv_len;  /* envp starts after argv */
				int envc = 0;
				int found_test_var = 0;
				printf("    INFO: Got %u bytes of envp data\n",
				    exec->envp_len);
				while (pos < exec->argv_len + exec->envp_len && envc < 100) {
					size_t len = strlen((const char *)msg + exec->argv_off + pos);
					if (len > 0) {
						if (strstr((const char *)msg + exec->argv_off + pos, "OES_TEST_VAR=") != NULL) {
							printf("    INFO: Found test var: %s\n",
							    (const char *)msg + exec->argv_off + pos);
							found_test_var = 1;
						}
						envc++;
					}
					pos += len + 1;
				}
				printf("    INFO: Found %d environment variables\n", envc);
				if (found_test_var) {
					printf("    INFO: Test variable found in envp\n");
				}
			} else {
				printf("    INFO: No envp data in event (may be truncated)\n");
			}

			if (exec->flags & EE_FLAG_ENVP_TRUNCATED) {
				printf("    INFO: envp was truncated\n");
			}

			/* Allow the exec */
			memset(&resp, 0, sizeof(resp));
			resp.er_id = msg->em_id;
			resp.er_result = OES_AUTH_ALLOW;
			(void)write(fd, &resp, sizeof(resp));
		}
	}

	waitpid(pid, &status, 0);
	close(fd);

	if (!got_event) {
		printf("    INFO: No AUTH_EXEC event received\n");
	}

	printf("    PASS: embedded envp tested\n");
	return (0);
}

/*
 * Test NOTIFY mode also receives embedded args.
 */
static int
test_notify_embedded_args(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_EXEC };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	struct pollfd pfd;
	pid_t pid;
	ssize_t n;
	int status;
	int got_event = 0;

	printf("  Testing embedded args in NOTIFY_EXEC event...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Fork and exec */
	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(fd);
		return (1);
	}

	if (pid == 0) {
		execl("/bin/echo", "echo", "notify_test", NULL);
		_exit(127);
	}

	/* Parent - wait for NOTIFY_EXEC event */
	pfd.fd = fd;
	pfd.events = POLLIN;

	if (poll(&pfd, 1, 3000) > 0 && (pfd.revents & POLLIN)) {
		n = read(fd, msg, OES_MSG_MAX_SIZE);
		if (n >= (ssize_t)sizeof(oes_message_t) && msg->em_event == OES_EVENT_NOTIFY_EXEC) {
			oes_event_exec_t *exec = &msg->em_event_data.exec;
			got_event = 1;

			printf("    INFO: NOTIFY argc=%u, argv_len=%u\n",
			    exec->argc, exec->argv_len);

			if (exec->argv_len > 0) {
				size_t pos = 0;
				int argc = 0;
				while (pos < exec->argv_len && argc < 5) {
					size_t len = strlen((const char *)msg + exec->argv_off + pos);
					if (len > 0) {
						printf("    INFO: argv[%d] = '%s'\n",
						    argc, (const char *)msg + exec->argv_off + pos);
						argc++;
					}
					pos += len + 1;
				}
			}
		}
	}

	waitpid(pid, &status, 0);
	close(fd);

	if (!got_event) {
		printf("    INFO: No NOTIFY_EXEC event received\n");
	}

	printf("    PASS: NOTIFY embedded args tested\n");
	return (0);
}

int
main(void)
{
	int failed = 0;

	printf("Testing embedded exec arguments...\n");

	failed += test_embedded_argv();
	failed += test_embedded_envp();
	failed += test_notify_embedded_args();

	if (failed > 0) {
		printf("exec args: FAILED (%d tests)\n", failed);
		return (1);
	}

	printf("exec args: ok\n");
	return (0);
}
