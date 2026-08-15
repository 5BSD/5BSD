/*
 * OES edge case and boundary tests.
 *
 * Tests long paths, maximum values, boundary conditions.
 */
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/oes/oes.h>

static int
test_long_path_mute(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_mute_path_args mute_path;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_OPEN };
	char long_path[MAXPATHLEN];

	printf("  Testing long path muting (MAXPATHLEN=%d)...\n", MAXPATHLEN);

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
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

	/* Create a path at MAXPATHLEN-1 (max valid length) */
	memset(long_path, 'a', MAXPATHLEN - 2);
	long_path[0] = '/';
	long_path[MAXPATHLEN - 2] = '\0';

	memset(&mute_path, 0, sizeof(mute_path));
	strlcpy(mute_path.emp_path, long_path, sizeof(mute_path.emp_path));
	mute_path.emp_type = OES_MUTE_PATH_PREFIX;

	if (ioctl(fd, OES_IOC_MUTE_PATH, &mute_path) < 0) {
		if (errno == ENAMETOOLONG) {
			printf("    INFO: very long path rejected (expected)\n");
		} else {
			perror("OES_IOC_MUTE_PATH");
		}
	} else {
		printf("    INFO: very long path accepted\n");
	}

	close(fd);
	printf("    PASS: long path handled\n");
	return (0);
}

static int
test_empty_path_mute(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_mute_path_args mute_path;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_OPEN };

	printf("  Testing empty path muting...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
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

	/* Empty path */
	memset(&mute_path, 0, sizeof(mute_path));
	mute_path.emp_path[0] = '\0';
	mute_path.emp_type = OES_MUTE_PATH_LITERAL;

	if (ioctl(fd, OES_IOC_MUTE_PATH, &mute_path) == 0) {
		printf("    INFO: empty path accepted\n");
	} else {
		printf("    INFO: empty path rejected (errno=%d)\n", errno);
	}

	close(fd);
	printf("    PASS: empty path handled\n");
	return (0);
}

static int
test_root_path_mute(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_mute_path_args mute_path;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_OPEN };

	printf("  Testing root path muting...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
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

	/* Root path "/" */
	memset(&mute_path, 0, sizeof(mute_path));
	strlcpy(mute_path.emp_path, "/", sizeof(mute_path.emp_path));
	mute_path.emp_type = OES_MUTE_PATH_PREFIX;

	if (ioctl(fd, OES_IOC_MUTE_PATH, &mute_path) < 0) {
		perror("OES_IOC_MUTE_PATH");
		close(fd);
		return (1);
	}

	/* Unmute */
	if (ioctl(fd, OES_IOC_UNMUTE_PATH, &mute_path) < 0) {
		perror("OES_IOC_UNMUTE_PATH");
		close(fd);
		return (1);
	}

	close(fd);
	printf("    PASS: root path mute/unmute works\n");
	return (0);
}

static int
test_many_subscribed_events(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[50]; /* Many events */
	int i;

	printf("  Testing many subscribed events...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
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

	/* Fill with various NOTIFY events */
	events[0] = OES_EVENT_NOTIFY_EXEC;
	events[1] = OES_EVENT_NOTIFY_FORK;
	events[2] = OES_EVENT_NOTIFY_EXIT;
	events[3] = OES_EVENT_NOTIFY_OPEN;
	events[4] = OES_EVENT_NOTIFY_CREATE;
	events[5] = OES_EVENT_NOTIFY_UNLINK;
	events[6] = OES_EVENT_NOTIFY_RENAME;
	events[7] = OES_EVENT_NOTIFY_READ;
	events[8] = OES_EVENT_NOTIFY_WRITE;
	events[9] = OES_EVENT_NOTIFY_STAT;
	for (i = 10; i < 50; i++)
		events[i] = OES_EVENT_NOTIFY_LOOKUP;

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 50;
	sub.esa_flags = OES_SUB_REPLACE;

	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		if (errno == EINVAL || errno == E2BIG) {
			printf("    INFO: many events rejected (expected)\n");
		} else {
			perror("OES_IOC_SUBSCRIBE");
		}
	} else {
		printf("    INFO: many events accepted\n");
	}

	close(fd);
	printf("    PASS: many events handled\n");
	return (0);
}

static int
test_self_mute_pid_zero(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_mute_args mute;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_EXEC };

	printf("  Testing mute with PID 0 and SELF flag...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
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

	/* Self-mute with pid=0 and SELF flag */
	memset(&mute, 0, sizeof(mute));
	mute.emu_token.ept_id = 0;
	mute.emu_flags = OES_MUTE_SELF;

	if (ioctl(fd, OES_IOC_MUTE_PROCESS, &mute) < 0) {
		perror("OES_IOC_MUTE_PROCESS");
		close(fd);
		return (1);
	}

	/* Unmute */
	if (ioctl(fd, OES_IOC_UNMUTE_PROCESS, &mute) < 0) {
		perror("OES_IOC_UNMUTE_PROCESS");
		close(fd);
		return (1);
	}

	close(fd);
	printf("    PASS: self-mute with PID 0 works\n");
	return (0);
}

static int
test_duplicate_mute(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_mute_args mute;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_EXEC };

	printf("  Testing duplicate mute...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
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

	/* Mute self twice */
	memset(&mute, 0, sizeof(mute));
	mute.emu_flags = OES_MUTE_SELF;

	if (ioctl(fd, OES_IOC_MUTE_PROCESS, &mute) < 0) {
		perror("OES_IOC_MUTE_PROCESS (1)");
		close(fd);
		return (1);
	}

	/* Mute again - should be idempotent or error */
	if (ioctl(fd, OES_IOC_MUTE_PROCESS, &mute) < 0) {
		printf("    INFO: duplicate mute rejected (errno=%d)\n", errno);
	} else {
		printf("    INFO: duplicate mute accepted (idempotent)\n");
	}

	close(fd);
	printf("    PASS: duplicate mute handled\n");
	return (0);
}

static int
test_unmute_not_muted(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_mute_args mute;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_EXEC };

	printf("  Testing unmute when not muted...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
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

	/* Try to unmute without muting first */
	memset(&mute, 0, sizeof(mute));
	mute.emu_flags = OES_MUTE_SELF;

	if (ioctl(fd, OES_IOC_UNMUTE_PROCESS, &mute) < 0) {
		printf("    INFO: unmute when not muted rejected\n");
	} else {
		printf("    INFO: unmute when not muted accepted (no-op)\n");
	}

	close(fd);
	printf("    PASS: unmute when not muted handled\n");
	return (0);
}

static int
test_special_paths(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_mute_path_args mute_path;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_OPEN };
	const char *paths[] = {
		"/dev/null",
		"/dev/zero",
		"/proc",
		"/tmp",
		"//double//slashes//",
		"/trailing/",
		"/./dot/./path",
	};
	size_t i;

	printf("  Testing special paths...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
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

	for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		memset(&mute_path, 0, sizeof(mute_path));
		strlcpy(mute_path.emp_path, paths[i], sizeof(mute_path.emp_path));
		mute_path.emp_type = OES_MUTE_PATH_LITERAL;

		if (ioctl(fd, OES_IOC_MUTE_PATH, &mute_path) < 0) {
			printf("    INFO: path '%s' rejected\n", paths[i]);
		} else {
			/* Unmute */
			(void)ioctl(fd, OES_IOC_UNMUTE_PATH, &mute_path);
		}
	}

	close(fd);
	printf("    PASS: special paths handled\n");
	return (0);
}

int
main(void)
{
	int failed = 0;

	printf("Testing edge cases...\n");

	failed += test_long_path_mute();
	failed += test_empty_path_mute();
	failed += test_root_path_mute();
	failed += test_many_subscribed_events();
	failed += test_self_mute_pid_zero();
	failed += test_duplicate_mute();
	failed += test_unmute_not_muted();
	failed += test_special_paths();

	if (failed > 0) {
		printf("edge cases: FAILED (%d tests)\n", failed);
		return (1);
	}

	printf("edge cases: ok\n");
	return (0);
}
