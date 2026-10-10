/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Starnix input_test.cc GetDeviceName and ioctl_test.cc EVIOCGNAME tests,
 * commit 8a938a3224e768f6254ee12d240b6492361ebccf.  Use Linux's truncated
 * prefix semantics, not Starnix's explicitly different NUL termination.
 * The native fixture creates the named device and supplies its path.
 */
#include "linux_test.h"

#define EVIOCSTRING(q, n) ((0x80004506UL + (q)) | ((unsigned long)(n) << 16))

/* Query the fixture's idle state and advertised keyboard capabilities. */
static int
bitmaps(long fd, int zero)
{
	static const struct { unsigned nr, bytes; int bit; } queries[] = {
		{ 0x09, 8, -1 }, /* properties */
		{ 0x18, 96, -1 }, /* held keys */
		{ 0x19, 8, -1 }, /* LEDs */
		{ 0x1a, 8, -1 }, /* sounds */
		{ 0x1b, 8, -1 }, /* switches */
		{ 0x20, 8, 1 }, /* EV_KEY (EV_SYN is also advertised) */
		{ 0x21, 96, 30 }, /* KEY_A */
		{ 0x22, 8, -1 }, /* relative axes */
		{ 0x23, 8, -1 }, /* absolute axes */
		{ 0x35, 16, -1 }, /* no force-feedback capabilities */
	};
	unsigned char buffer[112];
	for (unsigned q = 0; q < sizeof(queries) / sizeof(queries[0]); q++) {
		unsigned long base = 0x80004500UL | queries[q].nr;
		if (zero) {
			if (sys3(SYS_ioctl, fd, base, 0) != 0)
				return (40 + q);
			continue;
		}
		for (unsigned length = 1; length <= queries[q].bytes + 8; length++) {
			unsigned copied = length < queries[q].bytes ? length : queries[q].bytes;
			xmemset(buffer, 0xcd, sizeof(buffer));
			if (sys3(SYS_ioctl, fd, base | ((unsigned long)length << 16),
			    buffer) != (long)copied)
				return (60 + q);
			for (unsigned i = copied; i < sizeof(buffer); i++)
				if (buffer[i] != 0xcd)
					return (80 + q);
			/* Event-type bits may include native auto-repeat support. */
			if (queries[q].nr != 0x20) {
				for (unsigned i = 0; i < copied; i++) {
					unsigned expected = queries[q].bit >= 0 &&
					    i == (unsigned)queries[q].bit / 8 ?
					    1U << (queries[q].bit % 8) : 0;
					if (buffer[i] != expected)
						return (100 + q);
				}
			} else if ((buffer[0] & 3) != 3)
				return (120);
		}
	}
	return (0);
}

static int
test(int argc, char **argv, char **envp)
{
	static const char *const names[] = {
		"starnix-input-probe", "starnix/input0", "starnix-serial"
	};
	unsigned char buffer[64];
	long fd, result;
	size_t length, copied, i, width;
	int rc = 0;

	(void)envp;
	if (argc != 3)
		return (1);
	fd = sys3(SYS_open, argv[1], O_RDONLY | O_NONBLOCK, 0);
	if (fd < 0)
		return (2);
	if (argv[2][0] == 'm') {
		rc = bitmaps(fd, argv[2][1] == 'z');
		(void)sys1(SYS_close, fd);
		return (rc);
	}
	for (unsigned q = 0; q < 3 && rc == 0; q++) {
		const char *name = names[q];
		for (width = 0; name[width] != '\0'; width++)
			;
		width++;
		if (argv[2][0] == 'z') {
			if (sys3(SYS_ioctl, fd, EVIOCSTRING(q, 0), 0) != 0)
				rc = 3 + q * 10;
			continue;
		}
		for (length = 1; length <= width + 8; length++) {
			xmemset(buffer, 0xcd, sizeof(buffer));
			copied = length < width ? length : width;
			result = sys3(SYS_ioctl, fd, EVIOCSTRING(q, length), buffer);
			if (result != (long)copied) {
				rc = 4 + q * 10;
				break;
			}
			for (i = 0; i < sizeof(buffer); i++) {
				if (buffer[i] != (i < copied ?
				    (unsigned char)name[i] : 0xcd)) {
					rc = 5 + q * 10;
					break;
				}
			}
			if (rc != 0)
				break;
		}
	}
	(void)sys1(SYS_close, fd);
	return (rc);
}
