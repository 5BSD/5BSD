/* SPDX-License-Identifier: BSD-2-Clause */
/* Test ideas: Starnix terminal_test.cc, ioctl_TCSETSF and PacketMode,
 * revision 8a938a3224e768f6254ee12d240b6492361ebccf. */
#include "linux_test.h"

struct kernel_termios {
	u32 iflag, oflag, cflag, lflag;
	u8 line, cc[19];
};
_Static_assert(sizeof(struct kernel_termios) == 36, "Linux termios ABI");

static int
open_pair(long *master, long *slave, int raw)
{
	int zero = 0;
	struct kernel_termios t;

	*slave = -1;
	*master = sys3(SYS_open, "/dev/ptmx", O_RDWR | O_NOCTTY | O_NONBLOCK, 0);
	if (*master < 0)
		return (1);
	if (sys3(SYS_ioctl, *master, 0x40045431, &zero) != 0)
		return (2);
	*slave = sys3(SYS_ioctl, *master, 0x5441,
	    O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (*slave < 0)
		return (3);
	if (!raw)
		return (0);
	if (sys3(SYS_ioctl, *slave, 0x5401, &t) != 0)
		return (4);
	t.lflag &= ~(2U | 8U); /* ICANON | ECHO */
	t.cc[6] = 1; /* VMIN */
	t.cc[5] = 0; /* VTIME */
	if (sys3(SYS_ioctl, *slave, 0x5402, &t) != 0)
		return (5);
	return (0);
}

static int
probe(int packet)
{
	struct kernel_termios t;
	char buffer[8];
	long master, slave;
	int rc, value;

	rc = open_pair(&master, &slave, !packet);
	if (rc != 0)
		goto out;
#define CHECK(x, n) do { if (!(x)) { rc = (n); goto out; } } while (0)
	if (!packet) {
		struct { int fd; short events, revents; } pfd = {
			.fd = slave, .events = 1 /* POLLIN */
		};
		CHECK(sys3(SYS_write, master, "hello", 5) == 5, 6);
		/* Linux may deliver input through the line discipline later. */
		CHECK(sys3(SYS_poll, &pfd, 1, 1000) == 1 &&
		    (pfd.revents & 1) != 0, 22);
		value = -1;
		CHECK(sys3(SYS_ioctl, slave, 0x541b, &value) == 0 &&
		    value == 5, 7); /* FIONREAD */
		CHECK(sys3(SYS_ioctl, slave, 0x5401, &t) == 0, 8);
		CHECK(sys3(SYS_ioctl, slave, 0x5404, &t) == 0, 9); /* TCSETSF */
		CHECK(sys3(SYS_ioctl, slave, 0x541b, &value) == 0 &&
		    value == 0, 10);
		CHECK(sys3(SYS_read, slave, buffer, sizeof(buffer)) == -EAGAIN, 11);
	} else {
		value = 1;
		CHECK(sys3(SYS_ioctl, slave, 0x5420, &value) == -ENOTTY, 12);
		CHECK(sys3(SYS_ioctl, master, 0x5420, &value) == 0, 13);
		CHECK(sys3(SYS_write, slave, "hello", 5) == 5, 14);
		CHECK(sys3(SYS_read, master, buffer, 1) == 1 && buffer[0] == 0, 15);
		CHECK(sys3(SYS_read, master, buffer, sizeof(buffer)) == 6 &&
		    buffer[0] == 0, 16);
		for (int i = 0; i < 5; i++)
			CHECK(buffer[i + 1] == "hello"[i], 17);
		value = 0;
		CHECK(sys3(SYS_ioctl, master, 0x5420, &value) == 0, 18);
		CHECK(sys3(SYS_write, slave, "plain", 5) == 5, 19);
		CHECK(sys3(SYS_read, master, buffer, sizeof(buffer)) == 5, 20);
		for (int i = 0; i < 5; i++)
			CHECK(buffer[i] == "plain"[i], 21);
	}
out:
	if (slave >= 0)
		(void)sys1(SYS_close, slave);
	if (master >= 0)
		(void)sys1(SYS_close, master);
	return (rc);
}

static int flush_input(void) { return (probe(0)); }
static int packet_mode(void) { return (probe(1)); }
static int
packet_events(void)
{
	struct kernel_termios t;
	struct { int fd; short events, revents; } pfd;
	long master, slave;
	char c;
	int on = 1, rc = open_pair(&master, &slave, 0);
	if (rc != 0)
		goto out;
	/* Isolate packet behavior from the separate open-flag regression. */
	CHECK(sys3(SYS_fcntl, master, 4, O_NONBLOCK) == 0, 29);
	CHECK(sys3(SYS_ioctl, master, 0x5420, &on) == 0, 30);
	CHECK(sys3(SYS_read, master, &c, 1) == -EAGAIN, 31);
	CHECK(sys3(SYS_ioctl, slave, 0x5401, &t) == 0, 32);
	t.iflag |= 0x400; /* IXON */
	CHECK(sys3(SYS_ioctl, slave, 0x5402, &t) == 0, 33);
	/* Drain at most one coalesced control packet. */
	long n = sys3(SYS_read, master, &c, 1);
	CHECK(n == 1 || n == -EAGAIN, 34);
	t.iflag &= ~0x400U;
	CHECK(sys3(SYS_ioctl, slave, 0x5402, &t) == 0, 35);
	pfd.fd = master;
	pfd.events = 3; /* POLLIN | POLLPRI */
	pfd.revents = 0;
	CHECK(sys3(SYS_poll, &pfd, 1, 1000) == 1 && (pfd.revents & 3), 36);
	CHECK(sys3(SYS_read, master, &c, 1) == 1 && c == 0x10, 37);
	CHECK(sys3(SYS_read, master, &c, 1) == -EAGAIN, 38);
out:
	if (slave >= 0)
		(void)sys1(SYS_close, slave);
	if (master >= 0)
		(void)sys1(SYS_close, master);
	return (rc);
}

static int
master_nonblock(void)
{
	long master, slave;
	char c;
	int rc = open_pair(&master, &slave, 0);
	if (rc != 0)
		goto out;
	/* Check flags first so the old kernel fails without hanging. */
	CHECK((sys3(SYS_fcntl, master, 3, 0) & O_NONBLOCK) != 0, 40);
	CHECK(sys3(SYS_read, master, &c, 1) == -EAGAIN, 41);
out:
	if (slave >= 0)
		(void)sys1(SYS_close, slave);
	if (master >= 0)
		(void)sys1(SYS_close, master);
	return (rc);
}

static int
test(int argc, char **argv, char **envp)
{
	static const struct subtest cases[] = {
		{ "flush_input", flush_input },
		{ "packet_mode", packet_mode },
		{ "packet_events", packet_events },
		{ "master_nonblock", master_nonblock },
	};
	(void)envp;
	return (run_subtests(argc, argv, cases, sizeof(cases) / sizeof(cases[0])));
}
