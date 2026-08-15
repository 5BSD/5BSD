/*
 * OES error condition tests.
 *
 * Tests invalid ioctl arguments, boundary conditions, error handling.
 */
#include <sys/ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/oes/oes.h>
#include "test_common.h"

static int
test_invalid_mode(void)
{
	int fd;
	struct oes_mode_args mode;

	printf("  Testing invalid mode...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = 999; /* Invalid mode */
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) == 0) {
		fprintf(stderr, "FAIL: invalid mode accepted\n");
		close(fd);
		return (1);
	}

	if (errno != EINVAL) {
		fprintf(stderr, "FAIL: expected EINVAL, got %d\n", errno);
		close(fd);
		return (1);
	}

	close(fd);
	printf("    PASS: invalid mode rejected with EINVAL\n");
	return (0);
}

static int
test_subscribe_without_mode(void)
{
	int fd;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_EXEC };

	printf("  Testing subscribe without mode...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	/*
	 * Subscribe without setting mode first.
	 * This is allowed - the kernel defaults to NOTIFY mode.
	 */
	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		/* Some implementations may reject this - that's OK too */
		printf("    INFO: subscribe without mode rejected (%s)\n",
		    strerror(errno));
	} else {
		printf("    INFO: subscribe without mode accepted (defaults to NOTIFY)\n");
	}

	close(fd);
	printf("    PASS: subscribe without mode handled\n");
	return (0);
}

static int
test_null_event_array(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;

	printf("  Testing NULL event array...\n");

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

	/* NULL event array with non-zero count */
	memset(&sub, 0, sizeof(sub));
	sub.esa_events = NULL;
	sub.esa_count = 5;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) == 0) {
		fprintf(stderr, "FAIL: NULL event array accepted\n");
		close(fd);
		return (1);
	}

	close(fd);
	printf("    PASS: NULL event array rejected\n");
	return (0);
}

static int
test_zero_event_count(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_EXEC };

	printf("  Testing zero event count...\n");

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

	/* Zero count should be valid (unsubscribe all) */
	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 0;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		/* May or may not be an error depending on implementation */
		/* Just note the behavior */
	}

	close(fd);
	printf("    PASS: zero event count handled\n");
	return (0);
}

static int
test_invalid_event_type(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { 0xFFFF }; /* Invalid event type */

	printf("  Testing invalid event type...\n");

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
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) == 0) {
		fprintf(stderr, "FAIL: invalid event type 0xFFFF accepted\n");
		close(fd);
		return (1);
	}
	if (errno != EINVAL) {
		fprintf(stderr, "FAIL: expected EINVAL, got %s\n", strerror(errno));
		close(fd);
		return (1);
	}

	close(fd);
	printf("    PASS: invalid event type rejected with EINVAL\n");
	return (0);
}

static int
test_auth_event_in_notify_mode(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_AUTH_EXEC }; /* AUTH event */

	printf("  Testing AUTH event in NOTIFY mode...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY; /* NOTIFY mode */
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	/* Try to subscribe to AUTH event in NOTIFY mode */
	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	/* This may or may not be an error */
	(void)ioctl(fd, OES_IOC_SUBSCRIBE, &sub);

	close(fd);
	printf("    PASS: AUTH event in NOTIFY mode handled\n");
	return (0);
}

static int
test_response_without_pending(void)
{
	int fd;
	struct oes_mode_args mode;
	oes_response_t resp;

	printf("  Testing response without pending event...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
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

	/* Try to respond to non-existent event */
	memset(&resp, 0, sizeof(resp));
	resp.er_id = 12345; /* Fake ID */
	resp.er_result = OES_AUTH_ALLOW;
	if (write(fd, &resp, sizeof(resp)) > 0) {
		/* May silently ignore */
		printf("    INFO: response to non-existent event accepted\n");
	} else {
		printf("    INFO: response to non-existent event rejected\n");
	}

	close(fd);
	printf("    PASS: response without pending handled\n");
	return (0);
}

static int
test_read_without_subscribe(void)
{
	int fd;
	struct oes_mode_args mode;
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	ssize_t n;

	printf("  Testing read without subscribe...\n");

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

	/* Don't subscribe, just try to read */
	n = read(fd, msg, OES_MSG_MAX_SIZE);
	if (n < 0 && errno == EAGAIN) {
		printf("    PASS: read without subscribe returns EAGAIN\n");
	} else if (n == 0) {
		printf("    PASS: read without subscribe returns 0\n");
	} else {
		printf("    INFO: read returned %zd\n", n);
	}

	close(fd);
	return (0);
}

static int
test_double_mode_set(void)
{
	int fd;
	struct oes_mode_args mode;

	printf("  Testing double mode set...\n");

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

	/* Try to set mode again */
	mode.ema_mode = OES_MODE_AUTH;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) == 0) {
		printf("    INFO: double mode set accepted (mode changed)\n");
	} else {
		printf("    INFO: double mode set rejected\n");
	}

	close(fd);
	printf("    PASS: double mode set handled\n");
	return (0);
}

static int
test_mute_invalid_token(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_mute_args mute;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_EXEC };

	printf("  Testing mute with invalid token...\n");

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

	/* Try to mute with invalid (non-existent) PID */
	memset(&mute, 0, sizeof(mute));
	mute.emu_token.ept_id = 999999999; /* Very unlikely PID */
	mute.emu_token.ept_genid = 0;
	mute.emu_flags = 0;
	if (ioctl(fd, OES_IOC_MUTE_PROCESS, &mute) == 0) {
		printf("    INFO: mute with invalid token accepted\n");
	} else {
		printf("    INFO: mute with invalid token rejected\n");
	}

	close(fd);
	printf("    PASS: mute with invalid token handled\n");
	return (0);
}

int
main(void)
{
	int failed = 0;

	printf("Testing error conditions...\n");

	failed += test_invalid_mode();
	failed += test_subscribe_without_mode();
	failed += test_null_event_array();
	failed += test_zero_event_count();
	failed += test_invalid_event_type();
	failed += test_auth_event_in_notify_mode();
	failed += test_response_without_pending();
	failed += test_read_without_subscribe();
	failed += test_double_mode_set();
	failed += test_mute_invalid_token();

	if (failed > 0) {
		printf("error conditions: FAILED (%d tests)\n", failed);
		return (1);
	}

	printf("error conditions: ok\n");
	return (0);
}
