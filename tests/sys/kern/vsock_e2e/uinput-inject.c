/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Create a deterministic host evdev device for the bhyve virtio-input
 * end-to-end test.  The device stays alive while bhyve has it open, injects
 * one key frame on command, and verifies the guest's LED status response.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/time.h>

#include <dev/evdev/input.h>
#include <dev/evdev/uinput.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool
valid_sysname(const char *name)
{
	const char *unit;

	if (strncmp(name, "event", 5) != 0)
		return (false);
	unit = name + 5;
	if (*unit == '\0')
		return (false);
	for (; *unit != '\0'; unit++)
		if (*unit < '0' || *unit > '9')
			return (false);
	return (true);
}

static bool
valid_command(const char *command, size_t length)
{
	static const char expected[] = "tap\n";

	return (length == sizeof(expected) - 1 &&
	    memcmp(command, expected, sizeof(expected) - 1) == 0);
}

static bool
has_caps_led(const struct input_event *events, size_t count, int32_t value)
{
	size_t i;

	for (i = 0; i < count; i++)
		if (events[i].type == EV_LED && events[i].code == LED_CAPSL &&
		    events[i].value == value)
			return (true);
	return (false);
}

static int
get_caps_led(int fd)
{
	uint8_t leds[howmany(LED_CNT, 8)];

	memset(leds, 0, sizeof(leds));
	if (ioctl(fd, EVIOCGLED(sizeof(leds)), leds) < 0)
		err(1, "get LED state");
	return ((leds[LED_CAPSL / 8] >> (LED_CAPSL % 8)) & 1);
}

static void
drain_output_events(int fd)
{
	struct input_event events[16];
	ssize_t n;

	for (;;) {
		n = read(fd, events, sizeof(events));
		if (n > 0) {
			if (n % sizeof(events[0]) != 0)
				errx(1, "partial setup event from uinput: %zd", n);
			continue;
		}
		if (n < 0 && errno == EAGAIN)
			return;
		if (n < 0)
			err(1, "drain uinput setup events");
		return;
	}
}

static int
self_test(void)
{
	struct input_event events[3];
	const char *invalid_names[] = {
		"", "event", "eventx", "mouse0", "../event0", "event1/x"
	};
	const char *invalid_commands[] = { "", "tap", "tap\r\n", "tap\nmore" };
	size_t i;

	if (!valid_sysname("event0") || !valid_sysname("event123"))
		errx(1, "valid event sysname rejected");
	for (i = 0; i < nitems(invalid_names); i++)
		if (valid_sysname(invalid_names[i]))
			errx(1, "invalid event sysname accepted: %s",
			    invalid_names[i]);
	if (!valid_command("tap\n", 4))
		errx(1, "valid control command rejected");
	for (i = 0; i < nitems(invalid_commands); i++)
		if (valid_command(invalid_commands[i],
		    strlen(invalid_commands[i])))
			errx(1, "invalid control command accepted");
	memset(events, 0, sizeof(events));
	events[0].type = EV_LED;
	events[0].code = LED_CAPSL;
	events[0].value = 0;
	events[1].type = EV_KEY;
	events[1].code = KEY_A;
	events[1].value = 1;
	if (has_caps_led(events, 2, 1))
		errx(1, "false LED response accepted");
	events[2].type = EV_LED;
	events[2].code = LED_CAPSL;
	events[2].value = 1;
	if (!has_caps_led(events, 3, 1))
		errx(1, "valid LED response rejected");
	puts("SELFTEST PASS");
	return (0);
}

static void
write_event(int fd, uint16_t type, uint16_t code, int32_t value)
{
	struct input_event event;
	ssize_t n;

	memset(&event, 0, sizeof(event));
	gettimeofday(&event.time, NULL);
	event.type = type;
	event.code = code;
	event.value = value;
	n = write(fd, &event, sizeof(event));
	if (n != sizeof(event)) {
		if (n < 0)
			err(1, "write input event");
		errx(1, "short input event write: %zd", n);
	}
}

int
main(int argc, char **argv)
{
	struct uinput_setup setup;
	struct uinput_abs_setup abs_setup;
	struct pollfd pfd;
	struct input_event events[16];
	char command[32], event_path[PATH_MAX], sysname[32];
	ssize_t n;
	int control, event_fd, expected_led, fd, elapsed, i;
	bool kernel_selftest, led_seen;

	if (argc == 2 && strcmp(argv[1], "--self-test") == 0)
		return (self_test());
	kernel_selftest = argc == 2 &&
	    strcmp(argv[1], "--kernel-self-test") == 0;
	if (!kernel_selftest && argc != 3)
		errx(2, "usage: uinput-inject control-fifo device-name | "
		    "--self-test | --kernel-self-test");
	control = -1;
	event_fd = -1;
	fd = open("/dev/uinput", O_RDWR | O_NONBLOCK);
	if (fd < 0)
		err(1, "open /dev/uinput");

	memset(&setup, 0, sizeof(setup));
	setup.id.bustype = BUS_VIRTUAL;
	setup.id.vendor = 0x1af4;
	setup.id.product = 0xe2e1;
	setup.id.version = 1;
	if (strlcpy(setup.name, kernel_selftest ?
	    "bhyve-uinput-kernel-selftest" : argv[2], sizeof(setup.name)) >=
	    sizeof(setup.name))
		errx(2, "device name is too long");
	memset(&abs_setup, 0, sizeof(abs_setup));
	abs_setup.code = ABS_X;
	abs_setup.absinfo.minimum = 0;
	abs_setup.absinfo.maximum = 1023;
	abs_setup.absinfo.resolution = 10;
	if (ioctl(fd, UI_DEV_SETUP, &setup) < 0 ||
	    ioctl(fd, UI_SET_EVBIT, EV_SYN) < 0 ||
	    ioctl(fd, UI_SET_EVBIT, EV_KEY) < 0 ||
	    ioctl(fd, UI_SET_EVBIT, EV_REL) < 0 ||
	    ioctl(fd, UI_SET_EVBIT, EV_ABS) < 0 ||
	    ioctl(fd, UI_SET_EVBIT, EV_LED) < 0 ||
	    ioctl(fd, UI_SET_KEYBIT, KEY_A) < 0 ||
	    ioctl(fd, UI_SET_RELBIT, REL_X) < 0 ||
	    ioctl(fd, UI_SET_LEDBIT, LED_CAPSL) < 0 ||
	    ioctl(fd, UI_ABS_SETUP, &abs_setup) < 0 ||
	    ioctl(fd, UI_DEV_CREATE) < 0)
		err(1, "configure uinput device");

	memset(sysname, 0, sizeof(sysname));
	if (ioctl(fd, UI_GET_SYSNAME(sizeof(sysname)), sysname) < 0)
		err(1, "get uinput sysname");
	if (!valid_sysname(sysname))
		errx(1, "unsafe uinput sysname: %s", sysname);
	if (snprintf(event_path, sizeof(event_path), "/dev/input/%s",
	    sysname) >= (int)sizeof(event_path))
		errx(1, "uinput event path is too long");
	event_fd = open(event_path, O_RDWR | O_NONBLOCK);
	if (event_fd < 0)
		err(1, "open %s", event_path);
	expected_led = !get_caps_led(event_fd);
	drain_output_events(fd);
	if (kernel_selftest) {
		/* FreeBSD reports LEDs on state transitions, not duplicate levels. */
		write_event(event_fd, EV_LED, LED_CAPSL, expected_led);
	} else {
		/*
		 * Linux initializes the new virtio-input LED state to off.  Match
		 * the disposable host device to it so the guest's later value=1 is
		 * guaranteed to be a transition even if the host inherited Caps
		 * Lock on when uinput registered the device.
		 */
		if (get_caps_led(event_fd) != 0)
			write_event(event_fd, EV_LED, LED_CAPSL, 0);
		if (get_caps_led(event_fd) != 0)
			errx(1, "could not normalize Caps Lock LED state");
		drain_output_events(fd);
		expected_led = 1;
		printf("/dev/input/%s\n", sysname);
		fflush(stdout);

		/* O_RDWR keeps the FIFO from reporting EOF between shell writes. */
		control = open(argv[1], O_RDWR);
		if (control < 0)
			err(1, "open control fifo");
		n = read(control, command, sizeof(command) - 1);
		if (n < 0)
			err(1, "read control fifo");
		command[n] = '\0';
		if (!valid_command(command, (size_t)n))
			errx(1, "unexpected command: %s", command);

		write_event(fd, EV_KEY, KEY_A, 1);
		write_event(fd, EV_SYN, SYN_REPORT, 0);
		write_event(fd, EV_REL, REL_X, 7);
		write_event(fd, EV_ABS, ABS_X, 321);
		write_event(fd, EV_KEY, KEY_A, 0);
		write_event(fd, EV_SYN, SYN_REPORT, 0);
	}

	led_seen = false;
	pfd.fd = fd;
	pfd.events = POLLIN;
	for (elapsed = 0; elapsed < 20000 && !led_seen; elapsed += 250) {
		/*
		 * bhyve exclusively grabs the evdev client, so another client
		 * cannot receive its output events.  EVIOCGLED reads the device's
		 * global output state and remains valid while grabbed.  This is the
		 * actual effect a keyboard provider needs to observe.
		 */
		if (get_caps_led(event_fd) == expected_led) {
			fprintf(stderr, "uinput-inject: observed LED_CAPSL=%d "
			    "through evdev state\n", expected_led);
			led_seen = true;
			break;
		}
		i = poll(&pfd, 1, 250);
		if (i < 0) {
			if (errno == EINTR)
				continue;
			err(1, "poll LED response");
		}
		if (i == 0)
			continue;
		n = read(fd, events, sizeof(events));
		if (n < 0) {
			if (errno == EAGAIN)
				continue;
			err(1, "read LED response");
		}
		if (n % sizeof(events[0]) != 0)
			errx(1, "partial LED event from uinput: %zd", n);
		for (size_t j = 0; j < (size_t)n / sizeof(events[0]); j++)
			fprintf(stderr, "uinput-inject: output type=%u code=%u "
			    "value=%d\n", events[j].type, events[j].code,
			    events[j].value);
		led_seen = has_caps_led(events,
		    (size_t)n / sizeof(events[0]), expected_led);
	}
	if (!led_seen)
		errx(1, "guest LED response timed out");
	close(event_fd);
	event_fd = -1;
	if (ioctl(fd, UI_DEV_DESTROY) < 0)
		err(1, "destroy uinput device");
	if (control >= 0)
		close(control);
	close(fd);
	if (kernel_selftest)
		puts("KERNEL SELFTEST PASS");
	return (0);
}
