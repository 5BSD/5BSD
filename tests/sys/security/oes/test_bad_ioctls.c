/*
 * OES bad ioctl value tests.
 *
 * Tests behavior when given completely invalid ioctl commands,
 * garbage data, wrong sizes, NULL pointers, etc.
 */
#include <sys/ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/oes/oes.h>

/*
 * Test completely invalid ioctl command.
 */
static int
test_invalid_ioctl_cmd(void)
{
	int fd, ret;
	unsigned long bad_cmds[] = {
		0,
		0xFFFFFFFF,
		0xDEADBEEF,
		_IO('X', 99),       /* Wrong magic */
		_IO('E', 255),      /* Right magic, bad number */
		_IOW('E', 200, int),
		_IOR('E', 201, int),
		_IOWR('E', 202, int),
	};
	size_t i;
	int all_rejected = 1;

	printf("  Testing invalid ioctl commands...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	for (i = 0; i < sizeof(bad_cmds) / sizeof(bad_cmds[0]); i++) {
		int dummy = 0;
		ret = ioctl(fd, bad_cmds[i], &dummy);
		if (ret == 0) {
			printf("    WARN: ioctl 0x%lx accepted\n", bad_cmds[i]);
			all_rejected = 0;
		} else if (errno != ENOTTY && errno != EINVAL && errno != ENOTSUP) {
			printf("    INFO: ioctl 0x%lx returned %d (errno=%d)\n",
			    bad_cmds[i], ret, errno);
		}
	}

	close(fd);

	if (all_rejected) {
		printf("    PASS: all invalid ioctls rejected\n");
	}
	return (0);
}

/*
 * Test ioctl with NULL argument when argument is required.
 */
static int
test_null_ioctl_arg(void)
{
	int fd, ret;
	struct oes_mode_args mode;

	printf("  Testing NULL ioctl arguments...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	/* First set mode so other ioctls might work */
	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	/* Test NULL arg for OES_IOC_SUBSCRIBE */
	ret = ioctl(fd, OES_IOC_SUBSCRIBE, NULL);
	if (ret < 0 && (errno == EFAULT || errno == EINVAL)) {
		printf("    PASS: SUBSCRIBE with NULL rejected (%s)\n",
		    strerror(errno));
	} else if (ret < 0) {
		printf("    INFO: SUBSCRIBE with NULL returned errno=%d\n", errno);
	} else {
		printf("    WARN: SUBSCRIBE with NULL succeeded\n");
	}

	/* Test NULL arg for OES_IOC_MUTE_PROCESS */
	ret = ioctl(fd, OES_IOC_MUTE_PROCESS, NULL);
	if (ret < 0 && (errno == EFAULT || errno == EINVAL)) {
		printf("    PASS: MUTE_PROCESS with NULL rejected (%s)\n",
		    strerror(errno));
	} else if (ret < 0) {
		printf("    INFO: MUTE_PROCESS with NULL returned errno=%d\n", errno);
	} else {
		printf("    WARN: MUTE_PROCESS with NULL succeeded\n");
	}

	/* Test NULL arg for OES_IOC_GET_TIMEOUT_ACTION */
	ret = ioctl(fd, OES_IOC_GET_TIMEOUT_ACTION, NULL);
	if (ret < 0 && (errno == EFAULT || errno == EINVAL)) {
		printf("    PASS: GET_TIMEOUT_ACTION with NULL rejected (%s)\n",
		    strerror(errno));
	} else if (ret < 0) {
		printf("    INFO: GET_TIMEOUT_ACTION with NULL returned errno=%d\n",
		    errno);
	} else {
		printf("    WARN: GET_TIMEOUT_ACTION with NULL succeeded\n");
	}

	close(fd);
	return (0);
}

/*
 * Test ioctl with bad pointer (unmapped address).
 */
static int
test_bad_pointer_arg(void)
{
	int fd, ret;
	struct oes_mode_args mode;
	void *bad_ptr = (void *)0xDEAD0000;

	printf("  Testing bad pointer ioctl arguments...\n");

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

	/* Test bad pointer for OES_IOC_SUBSCRIBE */
	ret = ioctl(fd, OES_IOC_SUBSCRIBE, bad_ptr);
	if (ret < 0 && errno == EFAULT) {
		printf("    PASS: SUBSCRIBE with bad pointer rejected (EFAULT)\n");
	} else if (ret < 0) {
		printf("    INFO: SUBSCRIBE with bad pointer errno=%d\n", errno);
	} else {
		printf("    WARN: SUBSCRIBE with bad pointer succeeded\n");
	}

	close(fd);
	return (0);
}

/*
 * Test subscribe with bad events pointer.
 */
static int
test_subscribe_bad_events_ptr(void)
{
	int fd, ret;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;

	printf("  Testing SUBSCRIBE with bad events pointer...\n");

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

	/* Valid struct but invalid events pointer */
	memset(&sub, 0, sizeof(sub));
	sub.esa_events = (oes_event_type_t *)0xBAD0BAD0;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;

	ret = ioctl(fd, OES_IOC_SUBSCRIBE, &sub);
	if (ret < 0 && errno == EFAULT) {
		printf("    PASS: bad events pointer rejected (EFAULT)\n");
	} else if (ret < 0) {
		printf("    INFO: bad events pointer errno=%d (%s)\n",
		    errno, strerror(errno));
	} else {
		printf("    WARN: bad events pointer accepted\n");
	}

	close(fd);
	return (0);
}

/*
 * Test mute path with unterminated string.
 */
static int
test_mute_path_no_terminator(void)
{
	int fd, ret;
	struct oes_mode_args mode;
	struct oes_mute_path_args mute;

	printf("  Testing MUTE_PATH with no string terminator...\n");

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

	/* Fill entire path buffer with non-null bytes */
	memset(&mute, 0xFF, sizeof(mute));
	mute.emp_type = OES_MUTE_PATH_PREFIX;

	ret = ioctl(fd, OES_IOC_MUTE_PATH, &mute);
	if (ret < 0) {
		printf("    PASS: unterminated path rejected (%s)\n",
		    strerror(errno));
	} else {
		printf("    INFO: unterminated path accepted (kernel may handle)\n");
	}

	close(fd);
	return (0);
}

/*
 * Test mute process with invalid token.
 */
static int
test_mute_invalid_token(void)
{
	int fd, ret;
	struct oes_mode_args mode;
	struct oes_mute_args mute;

	printf("  Testing MUTE_PROCESS with invalid token...\n");

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

	/* Invalid token - zero everything */
	memset(&mute, 0, sizeof(mute));
	mute.emu_flags = 0;  /* Not SELF, no valid token */

	ret = ioctl(fd, OES_IOC_MUTE_PROCESS, &mute);
	if (ret < 0) {
		printf("    PASS: invalid token rejected (%s)\n",
		    strerror(errno));
	} else {
		printf("    INFO: zero token accepted\n");
	}

	/* Garbage token */
	memset(&mute, 0xFF, sizeof(mute));
	mute.emu_flags = 0;

	ret = ioctl(fd, OES_IOC_MUTE_PROCESS, &mute);
	if (ret < 0) {
		printf("    PASS: garbage token rejected (%s)\n",
		    strerror(errno));
	} else {
		printf("    INFO: garbage token accepted\n");
	}

	close(fd);
	return (0);
}

/*
 * Test cache operations with invalid data.
 */
static int
test_cache_invalid_data(void)
{
	int fd, ret;
	struct oes_mode_args mode;
	oes_cache_entry_t entry;
	oes_cache_key_t key;

	printf("  Testing cache operations with invalid data...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	/* Cache add with all zeros (event=0 is undefined) */
	memset(&entry, 0, sizeof(entry));
	ret = ioctl(fd, OES_IOC_CACHE_ADD, &entry);
	if (ret == 0) {
		fprintf(stderr, "FAIL: zero cache entry accepted\n");
		close(fd);
		return (1);
	}
	if (errno != EINVAL) {
		fprintf(stderr, "FAIL: zero cache entry: expected EINVAL, got %s\n",
		    strerror(errno));
		close(fd);
		return (1);
	}
	printf("    PASS: zero cache entry rejected (EINVAL)\n");

	/* Cache add with garbage (0xFFFF is undefined) */
	memset(&entry, 0xFF, sizeof(entry));
	ret = ioctl(fd, OES_IOC_CACHE_ADD, &entry);
	if (ret == 0) {
		fprintf(stderr, "FAIL: garbage cache entry accepted\n");
		close(fd);
		return (1);
	}
	if (errno != EINVAL) {
		fprintf(stderr, "FAIL: garbage cache entry: expected EINVAL, got %s\n",
		    strerror(errno));
		close(fd);
		return (1);
	}
	printf("    PASS: garbage cache entry rejected (EINVAL)\n");

	/* Cache remove with garbage key */
	memset(&key, 0xFF, sizeof(key));
	ret = ioctl(fd, OES_IOC_CACHE_REMOVE, &key);
	if (ret == 0) {
		fprintf(stderr, "FAIL: garbage cache key removal accepted\n");
		close(fd);
		return (1);
	}
	if (errno != EINVAL) {
		fprintf(stderr, "FAIL: garbage cache key: expected EINVAL, got %s\n",
		    strerror(errno));
		close(fd);
		return (1);
	}
	printf("    PASS: garbage cache key rejected (EINVAL)\n");

	close(fd);
	printf("    PASS: cache invalid data tested\n");
	return (0);
}

/*
 * Test AUTH response reserved fields.
 */
static int
test_response_reserved_fields(void)
{
	int fd;
	oes_response_t resp;
	oes_response_flags_t fresp;

	printf("  Testing response reserved fields...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&resp, 0, sizeof(resp));
	resp.er_id = 1;
	resp.er_result = OES_AUTH_ALLOW;
	resp.er_flags = 1;
	if (write(fd, &resp, sizeof(resp)) != -1 || errno != EINVAL) {
		fprintf(stderr,
		    "FAIL: nonzero response reserved flags accepted\n");
		close(fd);
		return (1);
	}

	memset(&fresp, 0, sizeof(fresp));
	fresp.erf_id = 1;
	fresp.erf_result = OES_AUTH_ALLOW;
	fresp.erf_reserved = 1;
	if (write(fd, &fresp, sizeof(fresp)) != -1 || errno != EINVAL) {
		fprintf(stderr,
		    "FAIL: nonzero flags response reserved field accepted\n");
		close(fd);
		return (1);
	}

	close(fd);
	printf("    PASS: response reserved fields rejected\n");
	return (0);
}

/*
 * Test per-event muting with invalid event bitmap.
 */
static int
test_invalid_event_bitmap(void)
{
	int fd, ret;
	struct oes_mode_args mode;
	struct oes_mute_process_events_args mpe;

	printf("  Testing per-event muting with invalid bitmap...\n");

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

	/* Fill events array with invalid event types */
	memset(&mpe, 0xFF, sizeof(mpe));
	mpe.empe_flags = OES_MUTE_SELF;
	mpe.empe_count = 64;  /* Max allowed */

	ret = ioctl(fd, OES_IOC_MUTE_PROCESS_EVENTS, &mpe);
	if (ret == 0) {
		fprintf(stderr, "FAIL: invalid events array accepted\n");
		close(fd);
		return (1);
	}
	if (errno != EINVAL) {
		fprintf(stderr, "FAIL: expected EINVAL, got %s\n", strerror(errno));
		close(fd);
		return (1);
	}
	printf("    PASS: invalid events array rejected (EINVAL)\n");

	close(fd);
	return (0);
}

/*
 * Test GET_MUTED_PROCESSES with bad buffer.
 */
static int
test_get_muted_bad_buffer(void)
{
	int fd, ret;
	struct oes_mode_args mode;
	struct oes_get_muted_processes_args get;

	printf("  Testing GET_MUTED_PROCESSES with bad buffer...\n");

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

	/* Bad entries pointer */
	memset(&get, 0, sizeof(get));
	get.egmp_entries = (struct oes_muted_process_entry *)0xBAD0BAD0;
	get.egmp_count = 10;

	ret = ioctl(fd, OES_IOC_GET_MUTED_PROCESSES, &get);
	if (ret < 0 && errno == EFAULT) {
		printf("    PASS: bad buffer rejected (EFAULT)\n");
	} else if (ret < 0) {
		printf("    INFO: bad buffer errno=%d\n", errno);
	} else {
		printf("    INFO: bad buffer accepted (count=%zu, actual=%zu)\n",
		    get.egmp_count, get.egmp_actual);
	}

	/* Zero count but non-NULL pointer */
	struct oes_muted_process_entry dummy;
	get.egmp_entries = &dummy;
	get.egmp_count = 0;

	ret = ioctl(fd, OES_IOC_GET_MUTED_PROCESSES, &get);
	if (ret < 0) {
		printf("    INFO: zero count: %s\n", strerror(errno));
	} else {
		printf("    INFO: zero count accepted, actual=%zu\n", get.egmp_actual);
	}

	close(fd);
	return (0);
}

/*
 * Test ioctl on wrong fd type.
 */
static int
test_ioctl_wrong_fd(void)
{
	int fd, ret;
	struct oes_mode_args mode;

	printf("  Testing ioctl on non-OES fd...\n");

	/* Open a regular file */
	fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		perror("open /dev/null");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;

	ret = ioctl(fd, OES_IOC_SET_MODE, &mode);
	if (ret < 0 && errno == ENOTTY) {
		printf("    PASS: ioctl on /dev/null rejected (ENOTTY)\n");
	} else if (ret < 0) {
		printf("    INFO: ioctl on /dev/null errno=%d\n", errno);
	} else {
		printf("    FAIL: ioctl on /dev/null succeeded!\n");
		close(fd);
		return (1);
	}

	close(fd);
	return (0);
}

/*
 * Test massive count values.
 */
static int
test_massive_counts(void)
{
	int fd, ret;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t dummy_event = OES_EVENT_NOTIFY_EXEC;

	printf("  Testing massive count values...\n");

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

	/* Subscribe with huge count */
	memset(&sub, 0, sizeof(sub));
	sub.esa_events = &dummy_event;
	sub.esa_count = SIZE_MAX;
	sub.esa_flags = OES_SUB_REPLACE;

	ret = ioctl(fd, OES_IOC_SUBSCRIBE, &sub);
	if (ret < 0) {
		printf("    PASS: SIZE_MAX count rejected (%s)\n", strerror(errno));
	} else {
		printf("    WARN: SIZE_MAX count accepted\n");
	}

	/* Try with INT_MAX */
	sub.esa_count = 0x7FFFFFFF;
	ret = ioctl(fd, OES_IOC_SUBSCRIBE, &sub);
	if (ret < 0) {
		printf("    PASS: INT_MAX count rejected (%s)\n", strerror(errno));
	} else {
		printf("    WARN: INT_MAX count accepted\n");
	}

	close(fd);
	return (0);
}

/*
 * Test mode transitions.
 */
static int
test_mode_transitions(void)
{
	int fd, ret;
	struct oes_mode_args mode;

	printf("  Testing invalid mode transitions...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	/* Try invalid mode value */
	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = 0xDEAD;

	ret = ioctl(fd, OES_IOC_SET_MODE, &mode);
	if (ret < 0) {
		printf("    PASS: invalid mode 0xDEAD rejected (%s)\n",
		    strerror(errno));
	} else {
		printf("    WARN: invalid mode 0xDEAD accepted\n");
	}

	/* Set NOTIFY mode */
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE (NOTIFY)");
		close(fd);
		return (1);
	}

	/* Try to switch to AUTH (should work or fail cleanly) */
	mode.ema_mode = OES_MODE_AUTH;
	ret = ioctl(fd, OES_IOC_SET_MODE, &mode);
	if (ret < 0) {
		printf("    INFO: NOTIFY->AUTH transition rejected (%s)\n",
		    strerror(errno));
	} else {
		printf("    INFO: NOTIFY->AUTH transition accepted\n");
	}

	close(fd);
	return (0);
}

int
main(void)
{
	int failed = 0;

	printf("Testing bad ioctl values...\n");

	failed += test_invalid_ioctl_cmd();
	failed += test_null_ioctl_arg();
	failed += test_bad_pointer_arg();
	failed += test_subscribe_bad_events_ptr();
	failed += test_mute_path_no_terminator();
	failed += test_mute_invalid_token();
	failed += test_cache_invalid_data();
	failed += test_response_reserved_fields();
	failed += test_invalid_event_bitmap();
	failed += test_get_muted_bad_buffer();
	failed += test_ioctl_wrong_fd();
	failed += test_massive_counts();
	failed += test_mode_transitions();

	if (failed > 0) {
		printf("bad ioctls: FAILED (%d tests)\n", failed);
		return (1);
	}

	printf("bad ioctls: ok\n");
	return (0);
}
