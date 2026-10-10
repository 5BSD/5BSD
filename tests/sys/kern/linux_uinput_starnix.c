/* SPDX-License-Identifier: BSD-2-Clause */
/* Starnix uinput_test.cc test ideas, revision
 * 8a938a3224e768f6254ee12d240b6492361ebccf; rewritten for native uinput.
 * Creates a private synthetic device; delivery tests inject events. VM only. */
#include "linux_test.h"
#define UI_CREATE 0x5501UL
#define UI_DESTROY 0x5502UL
#define UI_SETUP 0x405c5503UL
#define UI_ABS_SIZE(n) (0x40005504UL | ((unsigned long)(n) << 16))
#define UI_ABS_SETUP UI_ABS_SIZE(28)
#define UI_VERSION 0x8004552dUL
#define UI_BIT(n) (0x40045500UL | (n))
#define UI_PHYS 0x4008556cUL
#define UI_SYSNAME(n) (0x8000552cUL | ((unsigned long)(n) << 16))
struct setup { u16 bus, vendor, product, version; char name[80]; u32 ff; };
struct abs_setup { u16 code, pad; int value, min, max, fuzz, flat, resolution; };
_Static_assert(sizeof(struct setup) == 92, "uinput setup ABI");
_Static_assert(sizeof(struct abs_setup) == 28, "uinput absolute setup ABI");
struct input_event { long sec, usec; u16 type, code; int value; };
_Static_assert(sizeof(struct input_event) == 24, "amd64 input event ABI");

/* Independently check delivery and state, beyond the reference write tests. */
static int
check_events(long fd, long reader, int axis, int fault)
{
	struct input_event event = { .type = axis ? 3 : 1,
	    .code = axis ? 0 : 30 };
	struct input_event sync = {0}, received[4];
	struct { int fd; short events, revents; } pollfd = { reader, 1, 0 };
	if (fault) {
		if (sys3(SYS_write, fd, 0, sizeof(event)) != -EFAULT)
			return (50);
		if (sys3(SYS_read, reader, received, sizeof(received)) != -EAGAIN)
			return (51);
	}
	for (unsigned round = 0; round < 2; round++) {
		event.value = axis ? (round ? 63 : 17) : (round ? 0 : 1);
		if (sys3(SYS_write, fd, &event, sizeof(event)) != sizeof(event))
			return (52);
		/* Input is packetized: no readable record until SYN_REPORT. */
		pollfd.revents = 0;
		if (sys3(SYS_poll, &pollfd, 1, 0) != 0)
			return (53);
		if (sys3(SYS_write, fd, &sync, sizeof(sync)) != sizeof(sync))
			return (54);
		pollfd.revents = 0;
		if (sys3(SYS_poll, &pollfd, 1, 1000) != 1 || pollfd.revents != 1)
			return (55);
		if (sys3(SYS_read, reader, received, sizeof(received)) !=
		    2 * sizeof(event))
			return (56);
		if (received[0].type != event.type || received[0].code != event.code ||
		    received[0].value != event.value || received[1].type != 0 ||
		    received[1].code != 0)
			return (57);
		if (axis) {
			struct { int value, min, max, fuzz, flat, resolution; } info;
			if (sys3(SYS_ioctl, reader, 0x80184540UL, &info) != 0 ||
			    info.value != event.value || info.min != 0 || info.max != 100)
				return (58);
		} else {
			unsigned char keys[96];
			xmemset(keys, 0, sizeof(keys));
			if (sys3(SYS_ioctl, reader, 0x80604518UL, keys) != sizeof(keys) ||
			    ((keys[30 / 8] >> (30 % 8)) & 1) != (unsigned)event.value)
				return (59);
		}
		if (sys3(SYS_read, reader, received, sizeof(received)) != -EAGAIN)
			return (60);
	}
	return (0);
}

static int
test(int argc, char **argv, char **envp)
{
	struct setup s = { .bus = 6, .name = "starnix-linux-uinput" };
	struct abs_setup a = { .code = 0, .max = 100 };
	unsigned char full[80], buf[88];
	unsigned version = 0;
	int rc = 0;
	long event = -1;
	long n, fd = sys3(SYS_open, "/dev/uinput", O_RDWR | O_NONBLOCK, 0);
	(void)envp;
	if (argc != 2 || fd < 0)
		return (1);
#define CHECK(x, n) do { if (!(x)) { rc = (n); goto out; } } while (0)
	CHECK(sys3(SYS_ioctl, fd, UI_VERSION, &version) == 0 && version == 5, 2);
	CHECK(sys3(SYS_ioctl, fd, UI_VERSION, 0) == -EFAULT, 3);
	CHECK(sys3(SYS_ioctl, fd, UI_SETUP, 0) == -EFAULT, 4);
	CHECK(sys3(SYS_ioctl, fd, UI_CREATE, 0) == -EINVAL, 5);
	CHECK(sys3(SYS_ioctl, fd, UI_SYSNAME(80), full) == -ENOENT, 6);
	/* All immediate bit-setter families with real native support. */
	static const unsigned setters[] = {100, 101, 102, 103, 104, 105, 106, 109, 110};
	for (unsigned i = 0; i < sizeof(setters) / sizeof(setters[0]); i++) {
		CHECK(sys3(SYS_ioctl, fd, UI_BIT(setters[i]), -1) == -EINVAL, 7);
		CHECK(sys3(SYS_ioctl, fd, UI_BIT(setters[i]), 0) == 0, 8);
	}
	CHECK(sys3(SYS_ioctl, fd, UI_BIT(100), 1) == 0, 9); /* EV_KEY */
	CHECK(sys3(SYS_ioctl, fd, UI_BIT(101), 30) == 0, 10); /* KEY_A */
	CHECK(sys3(SYS_ioctl, fd, UI_BIT(100), 3) == 0, 11); /* EV_ABS */
	CHECK(sys3(SYS_ioctl, fd, UI_ABS_SETUP, &a) == 0, 12);
	if (argv[1][0] == 'a') {
		CHECK(sys3(SYS_ioctl, fd, UI_ABS_SIZE(29), &a) == -E2BIG, 30);
		CHECK(sys3(SYS_ioctl, fd, UI_ABS_SETUP, 0) == -EFAULT, 31);
		a.code = 64;
		CHECK(sys3(SYS_ioctl, fd, UI_ABS_SETUP, &a) == -ERANGE, 32);
		a.code = 0;
		a.min = 101;
		CHECK(sys3(SYS_ioctl, fd, UI_ABS_SETUP, &a) == -EINVAL, 33);
		a.min = 0;
		a.flat = 101;
		CHECK(sys3(SYS_ioctl, fd, UI_ABS_SETUP, &a) == -EINVAL, 34);
		a.flat = 0;
		a.code = 47; /* ABS_MT_SLOT */
		CHECK(sys3(SYS_ioctl, fd, UI_ABS_SETUP, &a) == -EINVAL, 35);
		a.code = 0;
		CHECK(sys3(SYS_ioctl, fd, UI_ABS_SIZE(0), 0) == 0, 36);
		/* Last field omitted: resolution must be zero, not stale. */
		a.resolution = 91;
		CHECK(sys3(SYS_ioctl, fd, UI_ABS_SIZE(24), &a) == 0, 37);
	}
	CHECK(sys3(SYS_ioctl, fd, UI_PHYS, "starnix/linux0") == 0, 13);
	CHECK(sys3(SYS_ioctl, fd, UI_PHYS, 0) == -EFAULT, 14);
	CHECK(sys3(SYS_ioctl, fd, UI_SETUP, &s) == 0, 15);
	if (argv[1][0] == 'v')
		goto out;
	CHECK(sys3(SYS_ioctl, fd, UI_CREATE, 0) == 0, 16);
	CHECK(sys3(SYS_ioctl, fd, UI_CREATE, 0) == -EINVAL, 17);
	CHECK(sys3(SYS_ioctl, fd, UI_BIT(101), 31) == -EINVAL, 18);
	CHECK(sys3(SYS_ioctl, fd, UI_SETUP, &s) == -EINVAL, 19);
	xmemset(full, 0xcd, sizeof(full));
	n = sys3(SYS_ioctl, fd, UI_SYSNAME(sizeof(full)), full);
	CHECK(n > 1 && n < (long)sizeof(full) && full[n - 1] == 0, 20);
	for (unsigned i = n; i < sizeof(full); i++)
		CHECK(full[i] == 0xcd, 21);
	CHECK(sys3(SYS_ioctl, fd, UI_SYSNAME(0), 0) == -EINVAL, 22);
	if (argv[1][0] == 'a' || argv[1][0] == 'e' || argv[1][0] == 'f') {
		char path[100] = "/dev/input/";
		for (unsigned i = 0; i < (unsigned)n; i++) path[11 + i] = full[i];
		event = sys3(SYS_open, path, O_RDONLY | O_NONBLOCK, 0);
		CHECK(event >= 0, 38);
		struct { int value, min, max, fuzz, flat, resolution; } info;
		CHECK(sys3(SYS_ioctl, event, 0x80184540UL, &info) == 0, 39);
		CHECK(info.min == 0 && info.max == 100 && info.resolution == 0, 40);
		if (argv[1][0] != 'a') {
			rc = check_events(fd, event, argv[1][1] == 'a', argv[1][0] == 'f');
			if (rc != 0)
				goto out;
		}
		CHECK(sys1(SYS_close, event) == 0, 41);
		event = -1;
	}
	for (unsigned length = 1; length <= (unsigned)n + 4; length++) {
		unsigned copied = length < (unsigned)n ? length : (unsigned)n;
		xmemset(buf, 0xcd, sizeof(buf));
		CHECK(sys3(SYS_ioctl, fd, UI_SYSNAME(length), buf) == copied, 23);
		for (unsigned i = 0; i < sizeof(buf); i++)
			CHECK(buf[i] == (i >= copied ? 0xcd :
			    i == copied - 1 ? 0 : full[i]), 24);
	}
	CHECK(sys3(SYS_ioctl, fd, UI_DESTROY, 0) == 0, 25);
	CHECK(sys3(SYS_ioctl, fd, UI_SYSNAME(80), full) == -ENOENT, 26);
	CHECK(sys3(SYS_ioctl, fd, UI_DESTROY, 0) == 0, 27);
out:
	if (event >= 0)
		(void)sys1(SYS_close, event);
	(void)sys3(SYS_ioctl, fd, UI_DESTROY, 0);
	(void)sys1(SYS_close, fd);
	return (rc);
}
