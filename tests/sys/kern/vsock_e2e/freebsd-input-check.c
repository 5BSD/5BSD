/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Rebuilt-FreeBSD guest verifier for the bhyve VirtIO input device.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/time.h>

#include <dev/evdev/input.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct expected_event {
	uint16_t type;
	uint16_t code;
	int32_t value;
};

static const struct expected_event expected[] = {
	{ EV_KEY, KEY_A, 1 },
	{ EV_SYN, SYN_REPORT, 0 },
	{ EV_REL, REL_X, 7 },
	{ EV_ABS, ABS_X, 321 },
	{ EV_KEY, KEY_A, 0 },
	{ EV_SYN, SYN_REPORT, 0 },
};

static bool
event_matches(const struct input_event *event, size_t index)
{

	if (index >= nitems(expected))
		return (false);
	return (event->type == expected[index].type &&
	    event->code == expected[index].code &&
	    event->value == expected[index].value);
}

static int
find_device(const char *wanted)
{
	char name[128], path[64];
	int fd, unit;

	for (unit = 0; unit < 64; unit++) {
		if (snprintf(path, sizeof(path), "/dev/input/event%d", unit) >=
		    (int)sizeof(path))
			errx(1, "input device path overflow");
		fd = open(path, O_RDWR | O_NONBLOCK);
		if (fd < 0) {
			if (errno == ENOENT)
				continue;
			err(1, "open %s", path);
		}
		memset(name, 0, sizeof(name));
		if (ioctl(fd, EVIOCGNAME(sizeof(name) - 1), name) >= 0 &&
		    strcmp(name, wanted) == 0)
			return (fd);
		close(fd);
	}
	errx(1, "VirtIO input device named %s not found", wanted);
}

static int
self_test(void)
{
	struct input_event event;

	memset(&event, 0, sizeof(event));
	event.type = expected[0].type;
	event.code = expected[0].code;
	event.value = expected[0].value;
	if (!event_matches(&event, 0))
		errx(1, "input event ABI self-test failed");
	event.value++;
	if (event_matches(&event, 0))
		errx(1, "input event mismatch self-test failed");
	if (event_matches(&event, nitems(expected)))
		errx(1, "input event bounds self-test failed");
	memset(&event, 0, sizeof(event));
	event.type = expected[nitems(expected) - 1].type;
	event.code = expected[nitems(expected) - 1].code;
	event.value = expected[nitems(expected) - 1].value;
	if (!event_matches(&event, nitems(expected) - 1))
		errx(1, "input event terminal self-test failed");
	puts("SELFTEST PASS");
	return (0);
}

int
main(int argc, char **argv)
{
	struct input_event events[16], status;
	struct pollfd pfd;
	size_t matched;
	ssize_t n;
	int fd, remaining;

	if (argc == 2 && strcmp(argv[1], "--self-test") == 0)
		return (self_test());
	if (argc != 2)
		errx(2, "usage: freebsd-input-check device-name | --self-test");

	fd = find_device(argv[1]);
	printf("READY\n");
	fflush(stdout);
	matched = 0;
	remaining = 20000;
	pfd.fd = fd;
	pfd.events = POLLIN;
	while (matched < nitems(expected) && remaining > 0) {
		int elapsed, result;

		elapsed = remaining < 250 ? remaining : 250;
		result = poll(&pfd, 1, elapsed);
		if (result < 0) {
			if (errno == EINTR)
				continue;
			err(1, "poll input events");
		}
		remaining -= elapsed;
		if (result == 0)
			continue;
		n = read(fd, events, sizeof(events));
		if (n < 0) {
			if (errno == EAGAIN)
				continue;
			err(1, "read input events");
		}
		if (n == 0 || n % (ssize_t)sizeof(events[0]) != 0)
			errx(1, "partial input event stream: %zd", n);
		for (size_t i = 0; i < (size_t)n / sizeof(events[0]); i++) {
			if (!event_matches(&events[i], matched))
				errx(1, "unexpected event %u/%u/%d at %zu",
				    events[i].type, events[i].code,
				    events[i].value, matched);
			matched++;
			if (matched == nitems(expected))
				break;
		}
	}
	if (matched != nitems(expected))
		errx(1, "input event sequence timed out at %zu/%zu", matched,
		    nitems(expected));

	memset(&status, 0, sizeof(status));
	gettimeofday(&status.time, NULL);
	status.type = EV_LED;
	status.code = LED_CAPSL;
	status.value = 1;
	n = write(fd, &status, sizeof(status));
	if (n != sizeof(status)) {
		if (n < 0)
			err(1, "write LED status");
		errx(1, "short LED status write: %zd", n);
	}
	puts("PASS");
	close(fd);
	return (0);
}
