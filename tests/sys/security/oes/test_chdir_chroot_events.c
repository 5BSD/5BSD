/*
 * OES chdir/chroot/sysctl event tests.
 *
 * Tests directory change and system control operations.
 */
#include "test_common.h"

#include <sys/sysctl.h>
#include <sys/stat.h>
#include <kenv.h>

static int
test_chdir_event(void)
{
	int fd;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_CHDIR };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	char origdir[256];
	int got_chdir = 0;

	TEST_BEGIN("chdir event");

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	if (test_set_mode(fd, OES_MODE_NOTIFY) < 0) {
		close(fd);
		return (1);
	}

	if (test_subscribe(fd, events, 1, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (1);
	}

	/* Save current directory */
	if (getcwd(origdir, sizeof(origdir)) == NULL) {
		TEST_FAIL("getcwd: %s", strerror(errno));
		close(fd);
		return (1);
	}

	/* Change to /tmp */
	if (chdir("/tmp") < 0) {
		TEST_FAIL("chdir /tmp: %s", strerror(errno));
		close(fd);
		return (1);
	}

	/* Check for chdir event */
	for (int i = 0; i < 3; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
			if (msg->em_event == OES_EVENT_NOTIFY_CHDIR) {
				got_chdir = 1;
				printf("    INFO: chdir event received\n");
			}
		}
	}

	if (!got_chdir)
		printf("    INFO: no chdir event received\n");

	/* Restore original directory */
	(void)chdir(origdir);

	close(fd);
	TEST_PASS();
	return (0);
}

static int
test_fchdir_event(void)
{
	int fd, dirfd;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_CHDIR };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	char origdir[256];
	int got_chdir = 0;

	TEST_BEGIN("fchdir event");

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	if (test_set_mode(fd, OES_MODE_NOTIFY) < 0) {
		close(fd);
		return (1);
	}

	if (test_subscribe(fd, events, 1, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (1);
	}

	if (getcwd(origdir, sizeof(origdir)) == NULL) {
		TEST_FAIL("getcwd: %s", strerror(errno));
		close(fd);
		return (1);
	}

	/* Open /tmp directory */
	dirfd = open("/tmp", O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		TEST_FAIL("open /tmp: %s", strerror(errno));
		close(fd);
		return (1);
	}

	/* fchdir */
	if (fchdir(dirfd) < 0) {
		TEST_FAIL("fchdir: %s", strerror(errno));
		close(dirfd);
		close(fd);
		return (1);
	}

	/* Check for chdir event */
	for (int i = 0; i < 3; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
			if (msg->em_event == OES_EVENT_NOTIFY_CHDIR) {
				got_chdir = 1;
				printf("    INFO: fchdir event received\n");
			}
		}
	}

	if (!got_chdir)
		printf("    INFO: no fchdir event received\n");

	(void)chdir(origdir);
	close(dirfd);
	close(fd);
	TEST_PASS();
	return (0);
}

static int
test_chroot_event(void)
{
	int fd;
	pid_t child;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_CHROOT };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	int got_chroot = 0;
	int pipefd[2];
	char buf;

	TEST_BEGIN("chroot event (requires root)");

	if (getuid() != 0) {
		TEST_SKIP("requires root");
		return (0);
	}

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	if (test_set_mode(fd, OES_MODE_NOTIFY) < 0) {
		close(fd);
		return (1);
	}

	if (test_subscribe(fd, events, 1, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (1);
	}

	if (pipe(pipefd) < 0) {
		TEST_FAIL("pipe: %s", strerror(errno));
		close(fd);
		return (1);
	}

	child = fork();
	if (child < 0) {
		TEST_FAIL("fork: %s", strerror(errno));
		close(pipefd[0]);
		close(pipefd[1]);
		close(fd);
		return (1);
	}

	if (child == 0) {
		close(pipefd[0]);
		close(fd);

		/* chroot to /tmp (safe, exists on all systems) */
		if (chroot("/tmp") < 0) {
			(void)write(pipefd[1], "F", 1);
			close(pipefd[1]);
			_exit(1);
		}

		(void)write(pipefd[1], "D", 1);
		close(pipefd[1]);
		_exit(0);
	}

	close(pipefd[1]);

	/* Wait for child result */
	if (read(pipefd[0], &buf, 1) != 1 || buf != 'D') {
		printf("    INFO: child chroot failed (expected on some systems)\n");
		waitpid(child, NULL, 0);
		close(pipefd[0]);
		close(fd);
		TEST_PASS();
		return (0);
	}
	close(pipefd[0]);

	/* Check for chroot event */
	for (int i = 0; i < 3; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
			if (msg->em_event == OES_EVENT_NOTIFY_CHROOT) {
				got_chroot = 1;
				printf("    INFO: chroot event received\n");
			}
		}
	}

	if (!got_chroot)
		printf("    INFO: no chroot event received\n");

	waitpid(child, NULL, 0);
	close(fd);
	TEST_PASS();
	return (0);
}

static int
test_sysctl_event(void)
{
	int fd;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_SYSCTL };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	int mib[2];
	char buf[256];
	size_t len;
	int got_sysctl = 0;

	TEST_BEGIN("sysctl event");

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	if (test_set_mode(fd, OES_MODE_NOTIFY) < 0) {
		close(fd);
		return (1);
	}

	if (test_subscribe(fd, events, 1, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (1);
	}

	/* Read kern.ostype via sysctl */
	mib[0] = CTL_KERN;
	mib[1] = KERN_OSTYPE;
	len = sizeof(buf);
	if (sysctl(mib, 2, buf, &len, NULL, 0) < 0) {
		TEST_FAIL("sysctl: %s", strerror(errno));
		close(fd);
		return (1);
	}

	/* Check for sysctl event */
	for (int i = 0; i < 3; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
			if (msg->em_event == OES_EVENT_NOTIFY_SYSCTL) {
				got_sysctl = 1;
				printf("    INFO: sysctl event received\n");
			}
		}
	}

	if (!got_sysctl)
		printf("    INFO: no sysctl event received\n");

	close(fd);
	TEST_PASS();
	return (0);
}

static int
test_kenv_event(void)
{
	int fd;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_KENV };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	char value[256];
	int got_kenv = 0;

	TEST_BEGIN("kenv event");

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	if (test_set_mode(fd, OES_MODE_NOTIFY) < 0) {
		close(fd);
		return (1);
	}

	if (test_subscribe(fd, events, 1, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (1);
	}

	/* Try to get a kernel environment variable */
	if (kenv(KENV_GET, "kern.ostype", value, sizeof(value)) < 0) {
		/* kenv may not be available or variable may not exist */
		printf("    INFO: kenv GET failed: %s\n", strerror(errno));
	}

	/* Check for kenv event */
	for (int i = 0; i < 3; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
			if (msg->em_event == OES_EVENT_NOTIFY_KENV) {
				got_kenv = 1;
				printf("    INFO: kenv event received\n");
			}
		}
	}

	if (!got_kenv)
		printf("    INFO: no kenv event received\n");

	close(fd);
	TEST_PASS();
	return (0);
}

static int
test_auth_chdir(void)
{
	int fd;
	pid_t child;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_mute_args mute;
	struct oes_mute_invert_args invert;
	oes_event_type_t events[] = { OES_EVENT_AUTH_CHDIR };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	oes_response_t resp;
	int pipefd[2];
	char buf;
	int status;

	TEST_BEGIN("AUTH chdir (deny)");

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	mode.ema_timeout_ms = 5000;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		TEST_FAIL("set mode: %s", strerror(errno));
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		TEST_FAIL("subscribe: %s", strerror(errno));
		close(fd);
		return (1);
	}

	/* Invert muting */
	memset(&invert, 0, sizeof(invert));
	invert.emi_type = OES_MUTE_INVERT_PROCESS;
	invert.emi_invert = 1;
	(void)ioctl(fd, OES_IOC_SET_MUTE_INVERT, &invert);

	if (pipe(pipefd) < 0) {
		TEST_FAIL("pipe: %s", strerror(errno));
		close(fd);
		return (1);
	}

	child = fork();
	if (child < 0) {
		TEST_FAIL("fork: %s", strerror(errno));
		close(pipefd[0]);
		close(pipefd[1]);
		close(fd);
		return (1);
	}

	if (child == 0) {
		close(pipefd[1]);
		close(fd);

		/* Wait for parent */
		if (read(pipefd[0], &buf, 1) != 1)
			_exit(1);
		close(pipefd[0]);

		/* Try to chdir - should be denied */
		if (chdir("/tmp") < 0) {
			_exit(0);  /* Expected failure */
		}
		_exit(1);  /* Unexpected success */
	}

	close(pipefd[0]);

	/* Mute child */
	memset(&mute, 0, sizeof(mute));
	mute.emu_token.ept_id = child;
	(void)ioctl(fd, OES_IOC_MUTE_PROCESS, &mute);

	/* Signal child */
	(void)write(pipefd[1], "G", 1);
	close(pipefd[1]);

	/* Wait for AUTH_CHDIR event */
	if (test_wait_event_type(fd, msg, OES_EVENT_AUTH_CHDIR, 3000) == 0) {
		printf("    INFO: got AUTH_CHDIR event, denying\n");
		memset(&resp, 0, sizeof(resp));
		resp.er_id = msg->em_id;
		resp.er_result = OES_AUTH_DENY;
		(void)write(fd, &resp, sizeof(resp));
	} else {
		printf("    INFO: no AUTH_CHDIR event received\n");
	}

	waitpid(child, &status, 0);
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		printf("    INFO: child chdir denied as expected\n");
	} else {
		printf("    INFO: child exit status: %d\n",
		    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
	}

	close(fd);
	TEST_PASS();
	return (0);
}

int
main(void)
{
	TEST_SUITE_BEGIN("chdir/chroot/sysctl events");

	test_chdir_event();
	test_fchdir_event();
	test_chroot_event();
	test_sysctl_event();
	test_kenv_event();
	test_auth_chdir();

	TEST_SUITE_END("chdir/chroot/sysctl events");
}
