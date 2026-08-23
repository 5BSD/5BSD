/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * TU-include coverage harness for usr.sbin/bhyve/uart_backend.c.
 *
 * uart_backend.c is the tty/socket/stdio backend behind uart_emul.  It has no
 * public seam for its static entry points (ttyopen, uart_tcp_listener, the
 * per-mode backend openers), so this test neutralises the bhyve-only headers
 * with the harness mocks, supplies a self-contained mevent and vm_snapshot
 * implementation, and then #includes the translation unit directly to reach
 * the file-static functions.
 *
 * Every assertion is checked against an INDEPENDENT oracle (termios/tty
 * semantics, the FIFO ring-buffer contract, POSIX socket/pipe behaviour, and
 * a hand-rolled little-endian snapshot codec) -- never against the
 * implementation's own output.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

/*
 * Force the non-Capsicum build.  The real caph_* calls errx() on the sandbox
 * step, which cannot succeed inside the test jail; the guarded blocks are
 * simply compiled out (llvm-cov does not count preprocessed-away lines).
 */
#ifndef WITHOUT_CAPSICUM
#define	WITHOUT_CAPSICUM	1
#endif

/*
 * Pull in the harness mock of mevent.h and suppress the real bhyve mevent.h
 * (its include guard is predefined so uart_backend.c's quote-include of it,
 * resolved relative to its own directory, expands to nothing).
 */
#define	_MEVENT_H_
#include "mevent.h"

/*
 * Snapshot metadata types and wire-helper macros come from the harness
 * snapshot.h; the real bhyve snapshot.h (pulled in by the DUT relative to its
 * own directory) is suppressed via its include guard so the two do not clash.
 */
#include <machine/vmm_snapshot.h>
#include "snapshot.h"
#define	_BHYVE_SNAPSHOT_

/* uart_backend.c reads/writes this global (declared in the real debug.h). */
extern int raw_stdio;
int raw_stdio = 0;

/* -------------------------------------------------------------------------
 * Mock mevent implementation.  The harness mevent.h only forward-declares
 * struct mevent; we own the full definition and a tiny bookkeeping layer so
 * tests can drive the callbacks and observe enable/disable/close activity.
 * ------------------------------------------------------------------------- */
struct mevent {
	int		fd;
	enum ev_type	type;
	void	      (*cb)(int, enum ev_type, void *);
	void	       *arg;
	bool		enabled;
};

static int	g_add_calls;
static int	g_enable_calls;
static int	g_disable_calls;
static int	g_delclose_calls;
static bool	g_add_fail;
static bool	g_enable_fail;
static bool	g_disable_fail;

static void
mock_mevent_reset(void)
{
	g_add_calls = g_enable_calls = g_disable_calls = g_delclose_calls = 0;
	g_add_fail = g_enable_fail = g_disable_fail = false;
}

struct mevent *
mevent_add(int fd, enum ev_type type,
    void (*cb)(int, enum ev_type, void *), void *arg)
{
	struct mevent *m;

	g_add_calls++;
	if (g_add_fail)
		return (NULL);
	m = calloc(1, sizeof(*m));
	if (m == NULL)
		return (NULL);
	m->fd = fd;
	m->type = type;
	m->cb = cb;
	m->arg = arg;
	m->enabled = true;
	return (m);
}

int
mevent_enable(struct mevent *m)
{
	g_enable_calls++;
	if (g_enable_fail)
		return (EBADF);
	if (m != NULL)
		m->enabled = true;
	return (0);
}

int
mevent_disable(struct mevent *m)
{
	g_disable_calls++;
	if (g_disable_fail)
		return (EBADF);
	if (m != NULL)
		m->enabled = false;
	return (0);
}

int
mevent_delete_close(struct mevent *m)
{
	g_delclose_calls++;
	if (m != NULL) {
		if (m->fd >= 0)
			(void)close(m->fd);
		free(m);
	}
	return (0);
}

/* -------------------------------------------------------------------------
 * Mock vm_snapshot codec.  A self-contained little-endian buffer serialiser,
 * independent of the checkpoint daemon, so snapshot save/restore can be
 * round-tripped and validated in-process.
 * ------------------------------------------------------------------------- */
void
vm_snapshot_buf_err(const char *bufname __unused, const enum vm_snapshot_op op __unused)
{
}

int
vm_snapshot_buf(void *data, size_t len, struct vm_snapshot_meta *meta)
{
	struct vm_snapshot_buffer *b = &meta->buffer;

	if (b->buf_rem < len)
		return (E2BIG);
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(b->buf, data, len);
	else
		memcpy(data, b->buf, len);
	b->buf += len;
	b->buf_rem -= len;
	return (0);
}

int
vm_snapshot_le32(uint32_t *v, struct vm_snapshot_meta *meta)
{
	return (vm_snapshot_buf(v, sizeof(*v), meta));
}

/* Pull in the production translation unit under test. */
#include "uart_backend.c"

/* ----------------------------------------------------------------------- */

static void
test_drain(int fd __unused, enum ev_type type __unused, void *arg __unused)
{
}

static void
ignore_sigpipe(void)
{
	(void)signal(SIGPIPE, SIG_IGN);
}

/*
 * libc-only pseudo-terminal opener (avoids linking libutil so the coverage
 * harness link line stays minimal).  Returns 0 on success and fills the
 * master/slave descriptors; NAME, if non-NULL, receives the slave path.
 */
static int
my_openpty(int *amaster, int *aslave, char *name)
{
	int mfd, sfd;
	char *sname;

	mfd = posix_openpt(O_RDWR | O_NOCTTY);
	if (mfd == -1)
		return (-1);
	if (grantpt(mfd) != 0 || unlockpt(mfd) != 0) {
		(void)close(mfd);
		return (-1);
	}
	sname = ptsname(mfd);
	if (sname == NULL) {
		(void)close(mfd);
		return (-1);
	}
	sfd = open(sname, O_RDWR | O_NOCTTY);
	if (sfd == -1) {
		(void)close(mfd);
		return (-1);
	}
	if (name != NULL)
		(void)strcpy(name, sname);
	*amaster = mfd;
	*aslave = sfd;
	return (0);
}

/* Return a nonblocking pipe pair; aborts the case on failure. */
static void
make_nb_pipe(int fds[2])
{
	int fl;

	ATF_REQUIRE_EQ(0, pipe(fds));
	fl = fcntl(fds[0], F_GETFL);
	ATF_REQUIRE(fl != -1);
	ATF_REQUIRE(fcntl(fds[0], F_SETFL, fl | O_NONBLOCK) != -1);
}

/* =====================================================================
 * FIFO ring-buffer contract (no tty/mevent attached).
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(fifo_ring_contract);
ATF_TC_BODY(fifo_ring_contract, tc)
{
	struct uart_softc *sc;
	int i, c;

	mock_mevent_reset();
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	/* Freshly initialised state per the init contract. */
	ATF_CHECK_EQ(-1, sc->log_fd);
	ATF_CHECK_EQ(-1, sc->tty.rfd);
	ATF_CHECK_EQ(-1, sc->tty.wfd);
	ATF_CHECK(!sc->tty.opened);

	/* Capacity is the compile-time FIFO size regardless of reset size. */
	ATF_CHECK_EQ(FIFOSZ, uart_rxfifo_size(sc));

	uart_rxfifo_reset(sc, 8);
	ATF_CHECK_EQ(0, uart_rxfifo_numchars(sc));
	/* Empty FIFO yields -1. */
	ATF_CHECK_EQ(-1, uart_rxfifo_getchar(sc));

	/* Fill exactly to the reset size (loopback path == direct putchar). */
	for (i = 0; i < 8; i++)
		ATF_CHECK_EQ(0, uart_rxfifo_putchar(sc, (uint8_t)(0x40 + i),
		    true));
	ATF_CHECK_EQ(8, uart_rxfifo_numchars(sc));
	/* Overflow past size is rejected. */
	ATF_CHECK_EQ(-1, uart_rxfifo_putchar(sc, 0xff, true));
	ATF_CHECK_EQ(8, uart_rxfifo_numchars(sc));

	/* FIFO order preserved. */
	for (i = 0; i < 8; i++) {
		c = uart_rxfifo_getchar(sc);
		ATF_CHECK_EQ(0x40 + i, c);
	}
	ATF_CHECK_EQ(-1, uart_rxfifo_getchar(sc));

	/* Size clamping: <1 becomes 1, >FIFOSZ becomes FIFOSZ. */
	uart_rxfifo_reset(sc, 0);
	ATF_CHECK_EQ(0, uart_rxfifo_putchar(sc, 'a', true));
	ATF_CHECK_EQ(-1, uart_rxfifo_putchar(sc, 'b', true)); /* size==1 full */

	uart_rxfifo_reset(sc, 100000);
	for (i = 0; i < FIFOSZ; i++)
		ATF_CHECK_EQ(0, uart_rxfifo_putchar(sc, (uint8_t)i, true));
	ATF_CHECK_EQ(-1, uart_rxfifo_putchar(sc, 0, true)); /* clamped */

	/* No mevent activity while no tty is attached. */
	ATF_CHECK_EQ(0, g_enable_calls);
	ATF_CHECK_EQ(0, g_disable_calls);

	free(sc);
}

/* =====================================================================
 * Flow control against a mock mevent: full FIFO disables RX, draining a
 * previously-full FIFO re-enables it, and mevent errors are tolerated.
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(fifo_flow_control_mevent);
ATF_TC_BODY(fifo_flow_control_mevent, tc)
{
	struct uart_softc *sc;
	int i;

	mock_mevent_reset();
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);

	uart_rxfifo_reset(sc, 4);
	/* Attach a fake tty + event so the flow-control hooks fire. */
	sc->tty.opened = true;
	sc->mev = mevent_add(7, EVF_READ, test_drain, sc);
	ATF_REQUIRE(sc->mev != NULL);

	/* Filling to capacity must disable the receive event exactly once. */
	for (i = 0; i < 4; i++)
		ATF_CHECK_EQ(0, uart_rxfifo_putchar(sc, (uint8_t)i, true));
	ATF_CHECK_EQ(1, g_disable_calls);

	/* Draining one char from a full FIFO must re-enable it. */
	ATF_CHECK_EQ(0, uart_rxfifo_getchar(sc));
	ATF_CHECK_EQ(1, g_enable_calls);

	/* mevent failure paths are logged, not fatal. */
	g_disable_fail = true;
	ATF_CHECK_EQ(0, uart_rxfifo_putchar(sc, 0x55, true)); /* refills full */
	g_disable_fail = false;
	g_enable_fail = true;
	ATF_CHECK(uart_rxfifo_getchar(sc) >= 0);
	g_enable_fail = false;

	mevent_delete_close(sc->mev);
	free(sc);
}

/* =====================================================================
 * uart_rxfifo_reset with an attached tty flushes stale input and re-arms.
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(rxfifo_reset_with_tty);
ATF_TC_BODY(rxfifo_reset_with_tty, tc)
{
	struct uart_softc *sc;
	int p[2];

	mock_mevent_reset();
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);

	make_nb_pipe(p);
	ATF_REQUIRE_EQ(3, write(p[1], "abc", 3)); /* stale input to flush */

	sc->tty.opened = true;
	sc->tty.rfd = p[0];
	sc->mev = mevent_add(p[0], EVF_READ, test_drain, sc);
	ATF_REQUIRE(sc->mev != NULL);

	uart_rxfifo_reset(sc, 16);
	/* The reset re-arms the receive event. */
	ATF_CHECK(g_enable_calls >= 1);
	/* Stale bytes were drained from the fd. */
	{
		char b;
		ATF_CHECK_EQ(-1, read(p[0], &b, 1));
		ATF_CHECK_EQ(EAGAIN, errno);
	}

	/* Exercise the enable-failure warnc branch on reset. */
	g_enable_fail = true;
	uart_rxfifo_reset(sc, 16);
	g_enable_fail = false;

	mevent_delete_close(sc->mev);
	(void)close(p[1]);
	free(sc);
}

/* =====================================================================
 * uart_rxfifo_putchar host-output path: console log tee, tty write, drop,
 * and socket write-error disconnect.
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(putchar_output_paths);
ATF_TC_BODY(putchar_output_paths, tc)
{
	struct uart_softc *sc;
	char logpath[] = "/tmp/uart_log.XXXXXX";
	char rbuf[8];
	int logfd, p[2], sp[2];

	ignore_sigpipe();
	mock_mevent_reset();
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	uart_rxfifo_reset(sc, 16);

	/* No tty, no log: byte is dropped but the call still succeeds. */
	ATF_CHECK_EQ(0, uart_rxfifo_putchar(sc, 'X', false));

	/* Console log tee is unconditional even with no client attached. */
	logfd = mkstemp(logpath);
	ATF_REQUIRE(logfd != -1);
	sc->log_fd = logfd;
	ATF_CHECK_EQ(0, uart_rxfifo_putchar(sc, 'L', false));
	{
		int rd = open(logpath, O_RDONLY);
		ATF_REQUIRE(rd != -1);
		ATF_CHECK_EQ(1, read(rd, rbuf, sizeof(rbuf)));
		ATF_CHECK_EQ('L', rbuf[0]);
		(void)close(rd);
	}
	sc->log_fd = -1;
	(void)close(logfd);
	(void)unlink(logpath);

	/* Opened non-socket tty: byte is written to the fd. */
	ATF_REQUIRE_EQ(0, pipe(p));
	sc->tty.opened = true;
	sc->tty.is_socket = false;
	sc->tty.wfd = p[1];
	ATF_CHECK_EQ(0, uart_rxfifo_putchar(sc, 'Z', false));
	ATF_CHECK_EQ(1, read(p[0], rbuf, sizeof(rbuf)));
	ATF_CHECK_EQ('Z', rbuf[0]);
	(void)close(p[0]);
	(void)close(p[1]);

	/* Socket peer gone: write() -> -1/EPIPE triggers TCP disconnect. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	sc->tty.opened = true;
	sc->tty.is_socket = true;
	sc->tty.rfd = sc->tty.wfd = sp[0];
	sc->mev = mevent_add(sp[0], EVF_READ, test_drain, sc);
	ATF_REQUIRE(sc->mev != NULL);
	(void)close(sp[1]); /* peer closed */
	/* First write may buffer; loop until the disconnect is observed. */
	{
		int i;
		for (i = 0; i < 4 && sc->tty.opened; i++)
			(void)uart_rxfifo_putchar(sc, 'q', false);
	}
	ATF_CHECK(!sc->tty.opened);
	ATF_CHECK_EQ(-1, sc->tty.rfd);
	ATF_CHECK_EQ(1, g_delclose_calls);

	free(sc);
}

/* =====================================================================
 * uart_rxfifo_drain: normal RX fill, socket EOF disconnect, and both
 * loopback branches.
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(drain_paths);
ATF_TC_BODY(drain_paths, tc)
{
	struct uart_softc *sc;
	int p[2], sp[2], i, c;

	mock_mevent_reset();

	/* Normal (non-loopback) drain fills the FIFO from the fd. */
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	uart_rxfifo_reset(sc, 16);
	make_nb_pipe(p);
	ATF_REQUIRE_EQ(5, write(p[1], "hello", 5));
	sc->tty.opened = true;
	sc->tty.is_socket = false;
	sc->tty.rfd = p[0];
	uart_rxfifo_drain(sc, false);
	ATF_CHECK_EQ(5, uart_rxfifo_numchars(sc));
	{
		const char *exp = "hello";
		for (i = 0; i < 5; i++) {
			c = uart_rxfifo_getchar(sc);
			ATF_CHECK_EQ(exp[i], c);
		}
	}
	(void)close(p[0]);
	(void)close(p[1]);
	free(sc);

	/* Non-loopback drain: read()==0 on a socket => disconnect. */
	mock_mevent_reset();
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	uart_rxfifo_reset(sc, 16);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	ATF_REQUIRE_EQ(3, write(sp[1], "abc", 3));
	(void)close(sp[1]); /* EOF after 3 bytes */
	sc->tty.opened = true;
	sc->tty.is_socket = true;
	sc->tty.rfd = sp[0];
	sc->mev = mevent_add(sp[0], EVF_READ, test_drain, sc);
	ATF_REQUIRE(sc->mev != NULL);
	uart_rxfifo_drain(sc, false);
	ATF_CHECK_EQ(3, uart_rxfifo_numchars(sc));
	ATF_CHECK(!sc->tty.opened);      /* EOF disconnected the socket */
	ATF_CHECK_EQ(1, g_delclose_calls);
	free(sc);

	/* Loopback drain, data available: reads one byte, no disconnect. */
	mock_mevent_reset();
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	uart_rxfifo_reset(sc, 16);
	make_nb_pipe(p);
	ATF_REQUIRE_EQ(1, write(p[1], "y", 1));
	sc->tty.opened = true;
	sc->tty.is_socket = false;
	sc->tty.rfd = p[0];
	uart_rxfifo_drain(sc, true);
	ATF_CHECK(sc->tty.opened);       /* non-socket, stays open */
	(void)close(p[0]);
	(void)close(p[1]);
	free(sc);

	/* Loopback drain, socket EOF: read()==0 => disconnect. */
	mock_mevent_reset();
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	uart_rxfifo_reset(sc, 16);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	(void)close(sp[1]); /* immediate EOF */
	sc->tty.opened = true;
	sc->tty.is_socket = true;
	sc->tty.rfd = sp[0];
	sc->mev = mevent_add(sp[0], EVF_READ, test_drain, sc);
	ATF_REQUIRE(sc->mev != NULL);
	uart_rxfifo_drain(sc, true);
	ATF_CHECK(!sc->tty.opened);
	ATF_CHECK_EQ(1, g_delclose_calls);
	free(sc);
}

/* =====================================================================
 * uart_tcp_disconnect: the mev==NULL fallback that closes tty.rfd directly.
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(tcp_disconnect_fallback);
ATF_TC_BODY(tcp_disconnect_fallback, tc)
{
	struct uart_softc *sc;
	int sp[2];
	char b;

	mock_mevent_reset();
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	sc->mev = NULL;
	sc->tty.opened = true;
	sc->tty.is_socket = true;
	sc->tty.rfd = sc->tty.wfd = sp[0];

	uart_tcp_disconnect(sc);
	ATF_CHECK(!sc->tty.opened);
	ATF_CHECK_EQ(-1, sc->tty.rfd);
	/* Independent proof the fd was closed: the peer now sees EOF. */
	ATF_CHECK_EQ(0, read(sp[1], &b, 1));
	(void)close(sp[1]);
	free(sc);
}

/* =====================================================================
 * ttyopen / ttyclose against a real pty (raw-mode setup + restore).
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(ttyopen_rawmode_pty);
ATF_TC_BODY(ttyopen_rawmode_pty, tc)
{
	struct ttyfd tf;
	struct termios before, after, orig_snapshot;
	int mfd, sfd;

	if (my_openpty(&mfd, &sfd, NULL) != 0)
		atf_tc_skip("openpty unavailable: %s", strerror(errno));

	ATF_REQUIRE_EQ(0, tcgetattr(sfd, &before));
	ATF_REQUIRE(before.c_lflag & ICANON); /* cooked before */

	memset(&tf, 0, sizeof(tf));
	tf.rfd = tf.wfd = sfd;
	tf.is_stdio = false;

	raw_stdio = 0;
	ATF_CHECK_EQ(0, ttyopen(&tf));
	/* Independent oracle: cfmakeraw clears ICANON/ECHO and sets CLOCAL. */
	ATF_REQUIRE_EQ(0, tcgetattr(sfd, &after));
	ATF_CHECK((after.c_lflag & ICANON) == 0);
	ATF_CHECK((after.c_lflag & ECHO) == 0);
	ATF_CHECK(after.c_cflag & CLOCAL);
	ATF_CHECK_EQ(1, raw_stdio);
	ATF_CHECK(!uart_stdio_tty); /* non-stdio must not arm atexit restore */

	/* Non-tty fd: ttyopen is a no-op success. */
	{
		int p[2];
		struct ttyfd nf;
		ATF_REQUIRE_EQ(0, pipe(p));
		memset(&nf, 0, sizeof(nf));
		nf.rfd = nf.wfd = p[0];
		ATF_CHECK_EQ(0, ttyopen(&nf)); /* !isatty -> 0 */
		(void)close(p[0]);
		(void)close(p[1]);
	}

	/* stdio path: records original termios and arms atexit ttyclose. */
	{
		struct ttyfd sf;
		ATF_REQUIRE_EQ(0, tcgetattr(sfd, &orig_snapshot));
		memset(&sf, 0, sizeof(sf));
		sf.rfd = sf.wfd = sfd;
		sf.is_stdio = true;
		uart_stdio_tty = false;
		ATF_CHECK_EQ(0, ttyopen(&sf));
		ATF_CHECK(uart_stdio_tty);
	}

	(void)close(mfd);
	(void)close(sfd);
}

/* =====================================================================
 * ttyclose restores the saved termios via tcsetattr on a controllable fd.
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(ttyclose_restore);
ATF_TC_BODY(ttyclose_restore, tc)
{
	int mfd, sfd, save_stdin;

	if (my_openpty(&mfd, &sfd, NULL) != 0)
		atf_tc_skip("openpty unavailable: %s", strerror(errno));

	/* Redirect STDIN to the pty slave so ttyclose has a tty to act on. */
	save_stdin = dup(STDIN_FILENO);
	ATF_REQUIRE(save_stdin != -1);
	ATF_REQUIRE(dup2(sfd, STDIN_FILENO) != -1);

	ATF_REQUIRE_EQ(0, tcgetattr(STDIN_FILENO, &tio_stdio_orig));
	/* Put the tty into raw so the restore is observable. */
	{
		struct termios raw = tio_stdio_orig;
		cfmakeraw(&raw);
		ATF_REQUIRE_EQ(0, tcsetattr(STDIN_FILENO, TCSANOW, &raw));
	}

	uart_stdio_tty = false;
	ttyclose(); /* disabled: must NOT touch the tty */
	{
		struct termios now;
		ATF_REQUIRE_EQ(0, tcgetattr(STDIN_FILENO, &now));
		ATF_CHECK((now.c_lflag & ICANON) == 0); /* still raw */
	}

	uart_stdio_tty = true;
	ttyclose(); /* enabled: restores tio_stdio_orig (cooked) */
	{
		struct termios now;
		ATF_REQUIRE_EQ(0, tcgetattr(STDIN_FILENO, &now));
		ATF_CHECK(now.c_lflag & ICANON); /* restored to cooked */
	}

	ATF_REQUIRE(dup2(save_stdin, STDIN_FILENO) != -1);
	(void)close(save_stdin);
	(void)close(mfd);
	(void)close(sfd);
}

/* =====================================================================
 * uart_tty_open with a real pty device backend (+ ",log=" suffix peel).
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(tty_backend_open);
ATF_TC_BODY(tty_backend_open, tc)
{
	struct uart_softc *sc;
	char name[128], spec[256];
	char logpath[] = "/tmp/uart_ttylog.XXXXXX";
	int mfd, sfd, logfd;

	if (my_openpty(&mfd, &sfd, name) != 0)
		atf_tc_skip("openpty unavailable: %s", strerror(errno));
	/* Close the slave; the backend opens the path itself. */
	(void)close(sfd);

	logfd = mkstemp(logpath);
	ATF_REQUIRE(logfd != -1);
	(void)close(logfd);

	mock_mevent_reset();
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);

	/* path + ",log=" suffix: the suffix must be peeled before dispatch. */
	(void)snprintf(spec, sizeof(spec), "%s,log=%s", name, logpath);
	ATF_CHECK_EQ(0, uart_tty_open(sc, spec, test_drain, sc));
	ATF_CHECK(sc->tty.opened);
	ATF_CHECK(sc->tty.rfd >= 0);
	ATF_CHECK(!sc->tty.is_stdio);
	ATF_CHECK(!sc->tty.is_socket);
	ATF_CHECK_EQ(1, raw_stdio); /* pty is a tty -> raw mode engaged */
	ATF_CHECK(sc->log_fd >= 0); /* log suffix opened */
	ATF_CHECK_EQ(1, g_add_calls);

	/* Reopen guard: already-opened softc is rejected. */
	ATF_CHECK_EQ(-1, uart_tty_open(sc, name, test_drain, sc));

	if (sc->mev != NULL)
		mevent_delete_close(sc->mev);
	(void)close(mfd);
	(void)unlink(logpath);
	free(sc);
}

/* =====================================================================
 * uart_tty_open argument guards and device-backend error paths.
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(tty_open_error_paths);
ATF_TC_BODY(tty_open_error_paths, tc)
{
	struct uart_softc *sc;
	char tmpfile[] = "/tmp/uart_reg.XXXXXX";
	int fd;

	mock_mevent_reset();
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);

	/* NULL argument guards. */
	ATF_CHECK_EQ(-1, uart_tty_open(NULL, "stdio", test_drain, sc));
	ATF_CHECK_EQ(-1, uart_tty_open(sc, NULL, test_drain, sc));
	ATF_CHECK_EQ(-1, uart_tty_open(sc, "stdio", NULL, sc));

	/* Nonexistent device path: open() fails. */
	ATF_CHECK_EQ(-1, uart_tty_open(sc, "/nonexistent/uart/dev",
	    test_drain, sc));
	ATF_CHECK(!sc->tty.opened);

	/* Regular file: opens but !isatty -> rejected. */
	fd = mkstemp(tmpfile);
	ATF_REQUIRE(fd != -1);
	(void)close(fd);
	ATF_CHECK_EQ(-1, uart_tty_open(sc, tmpfile, test_drain, sc));
	ATF_CHECK(!sc->tty.opened);
	(void)unlink(tmpfile);

	free(sc);
}

/* =====================================================================
 * uart_tty_open device backend where the post-open mevent_add fails,
 * exercising the non-stdio + ",log=" cleanup branch.
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(tty_open_mevent_fail_cleanup);
ATF_TC_BODY(tty_open_mevent_fail_cleanup, tc)
{
	struct uart_softc *sc;
	char name[128], spec[256];
	char logpath[] = "/tmp/uart_ttylog2.XXXXXX";
	int mfd, sfd, logfd;

	if (my_openpty(&mfd, &sfd, name) != 0)
		atf_tc_skip("openpty unavailable: %s", strerror(errno));
	(void)close(sfd);

	logfd = mkstemp(logpath);
	ATF_REQUIRE(logfd != -1);
	(void)close(logfd);

	mock_mevent_reset();
	g_add_fail = true; /* force the post-open mevent_add to fail */
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);

	(void)snprintf(spec, sizeof(spec), "%s,log=%s", name, logpath);
	ATF_CHECK_EQ(-1, uart_tty_open(sc, spec, test_drain, sc));
	/* Full teardown on failure: fd closed, log closed, state cleared. */
	ATF_CHECK(!sc->tty.opened);
	ATF_CHECK_EQ(-1, sc->tty.rfd);
	ATF_CHECK_EQ(-1, sc->log_fd);

	(void)close(mfd);
	(void)unlink(logpath);
	free(sc);
}

/* =====================================================================
 * stdio backend: real pty duplicated onto stdin/stdout, second-open guard,
 * and the mevent_add-failure stdio cleanup branch.
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(stdio_backend_open);
ATF_TC_BODY(stdio_backend_open, tc)
{
	struct uart_softc *sc, *sc2;
	int mfd, sfd, save0, save1;

	if (my_openpty(&mfd, &sfd, NULL) != 0)
		atf_tc_skip("openpty unavailable: %s", strerror(errno));

	save0 = dup(STDIN_FILENO);
	save1 = dup(STDOUT_FILENO);
	ATF_REQUIRE(save0 != -1 && save1 != -1);
	ATF_REQUIRE(dup2(sfd, STDIN_FILENO) != -1);
	ATF_REQUIRE(dup2(sfd, STDOUT_FILENO) != -1);

	mock_mevent_reset();
	uart_stdio = false;
	uart_stdio_tty = false;
	raw_stdio = 0;

	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(0, uart_tty_open(sc, "stdio", test_drain, sc));
	ATF_CHECK(sc->tty.opened);
	ATF_CHECK(sc->tty.is_stdio);
	ATF_CHECK(uart_stdio);
	ATF_CHECK(uart_stdio_tty); /* stdin is a pty -> raw + atexit armed */
	ATF_CHECK_EQ(1, raw_stdio);
	ATF_CHECK_EQ(STDIN_FILENO, sc->tty.rfd);
	ATF_CHECK_EQ(STDOUT_FILENO, sc->tty.wfd);
	/* Independent oracle: stdin was switched to non-blocking. */
	ATF_CHECK(fcntl(STDIN_FILENO, F_GETFL) & O_NONBLOCK);

	/* Second stdio open is rejected because stdio is already in use. */
	sc2 = uart_init();
	ATF_REQUIRE(sc2 != NULL);
	ATF_CHECK_EQ(-1, uart_tty_open(sc2, "stdio", test_drain, sc2));
	ATF_CHECK(!sc2->tty.opened);
	free(sc2);

	if (sc->mev != NULL)
		mevent_delete_close(sc->mev);
	free(sc);

	/* Restore the original stdio termios and fds before returning. */
	if (uart_stdio_tty)
		(void)tcsetattr(STDIN_FILENO, TCSANOW, &tio_stdio_orig);
	ATF_REQUIRE(dup2(save0, STDIN_FILENO) != -1);
	ATF_REQUIRE(dup2(save1, STDOUT_FILENO) != -1);
	(void)close(save0);
	(void)close(save1);
	(void)close(mfd);
	(void)close(sfd);
}

ATF_TC_WITHOUT_HEAD(stdio_backend_mevent_fail);
ATF_TC_BODY(stdio_backend_mevent_fail, tc)
{
	struct uart_softc *sc;
	int mfd, sfd, save0, save1;

	if (my_openpty(&mfd, &sfd, NULL) != 0)
		atf_tc_skip("openpty unavailable: %s", strerror(errno));

	save0 = dup(STDIN_FILENO);
	save1 = dup(STDOUT_FILENO);
	ATF_REQUIRE(save0 != -1 && save1 != -1);
	ATF_REQUIRE(dup2(sfd, STDIN_FILENO) != -1);
	ATF_REQUIRE(dup2(sfd, STDOUT_FILENO) != -1);

	mock_mevent_reset();
	uart_stdio = false;
	uart_stdio_tty = false;
	raw_stdio = 0;
	g_add_fail = true; /* fail the post-open mevent_add on the stdio path */

	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(-1, uart_tty_open(sc, "stdio", test_drain, sc));
	/* stdio cleanup branch resets the globals it set. */
	ATF_CHECK(!uart_stdio);
	ATF_CHECK(!uart_stdio_tty);
	ATF_CHECK_EQ(0, raw_stdio);
	ATF_CHECK(!sc->tty.opened);
	free(sc);

	ATF_REQUIRE(dup2(save0, STDIN_FILENO) != -1);
	ATF_REQUIRE(dup2(save1, STDOUT_FILENO) != -1);
	(void)close(save0);
	(void)close(save1);
	(void)close(mfd);
	(void)close(sfd);
}

/* =====================================================================
 * stdio backend fcntl failure paths: an invalid read fd fails immediately;
 * an invalid write fd rolls back the read-fd flags.  Both drive the stdio
 * cleanup branch in uart_tty_open.
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(stdio_backend_fcntl_fail);
ATF_TC_BODY(stdio_backend_fcntl_fail, tc)
{
	struct uart_softc *sc;
	int save0, save1;

	save0 = dup(STDIN_FILENO);
	save1 = dup(STDOUT_FILENO);
	ATF_REQUIRE(save0 != -1 && save1 != -1);
	mock_mevent_reset();

	/* Read fd invalid: fcntl(F_GETFL) fails, open aborts. */
	uart_stdio = false;
	uart_stdio_tty = false;
	(void)close(STDIN_FILENO);
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(-1, uart_tty_open(sc, "stdio", test_drain, sc));
	ATF_CHECK(!uart_stdio); /* stdio cleanup branch cleared the flag */
	free(sc);
	ATF_REQUIRE(dup2(save0, STDIN_FILENO) != -1);

	/* Write fd invalid: read fd succeeds, write fd fails, flags restored. */
	uart_stdio = false;
	uart_stdio_tty = false;
	(void)close(STDOUT_FILENO);
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(-1, uart_tty_open(sc, "stdio", test_drain, sc));
	ATF_CHECK(!uart_stdio);
	free(sc);
	ATF_REQUIRE(dup2(save1, STDOUT_FILENO) != -1);

	(void)close(save0);
	(void)close(save1);
}

/* =====================================================================
 * uart_open_log failure: an unopenable ",log=" path is reported and the
 * backend still succeeds with logging disabled.
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(log_open_failure);
ATF_TC_BODY(log_open_failure, tc)
{
	struct uart_softc *sc;
	char name[128], spec[256];
	int mfd, sfd;

	if (my_openpty(&mfd, &sfd, name) != 0)
		atf_tc_skip("openpty unavailable: %s", strerror(errno));
	(void)close(sfd);

	mock_mevent_reset();
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);

	(void)snprintf(spec, sizeof(spec),
	    "%s,log=/nonexistent-dir/deeper/uart.log", name);
	ATF_CHECK_EQ(0, uart_tty_open(sc, spec, test_drain, sc));
	ATF_CHECK(sc->tty.opened);
	ATF_CHECK_EQ(-1, sc->log_fd); /* log open failed -> disabled */

	if (sc->mev != NULL)
		mevent_delete_close(sc->mev);
	(void)close(mfd);
	free(sc);
}

/* =====================================================================
 * TCP backend: bind/listen success, listener accept/reject/teardown, and
 * the mevent_add-failure listener cleanup.
 * ===================================================================== */
static int
connect_to(struct uart_softc *sc)
{
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);
	struct pollfd pfd;
	int bind_fd, cfd;

	bind_fd = sc->mev_listen->fd;
	ATF_REQUIRE_EQ(0, getsockname(bind_fd, (struct sockaddr *)&ss, &sl));
	cfd = socket(ss.ss_family, SOCK_STREAM, 0);
	ATF_REQUIRE(cfd != -1);
	ATF_REQUIRE_EQ(0, connect(cfd, (struct sockaddr *)&ss, sl));
	/*
	 * The listener socket is non-blocking; wait until the completed
	 * connection is queued so the subsequent accept4() in the DUT
	 * succeeds deterministically rather than racing the handshake.
	 */
	pfd.fd = bind_fd;
	pfd.events = POLLIN;
	ATF_REQUIRE(poll(&pfd, 1, 5000) == 1);
	return (cfd);
}

ATF_TC_WITHOUT_HEAD(tcp_backend_lifecycle);
ATF_TC_BODY(tcp_backend_lifecycle, tc)
{
	struct uart_softc *sc;
	struct uart_socket_softc *ssc;
	int bind_fd, c1, c2, c3;
	char msg[64];

	ignore_sigpipe();
	mock_mevent_reset();
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);

	ATF_CHECK_EQ(0, uart_tty_open(sc, "tcp=127.0.0.1:0", test_drain, sc));
	ATF_CHECK(sc->tty.is_socket);
	ATF_REQUIRE(sc->mev_listen != NULL); /* connection-oriented: listener only */
	ATF_CHECK(!sc->tty.opened);          /* nothing connected yet */
	bind_fd = sc->mev_listen->fd;
	ssc = sc->mev_listen->arg;
	ATF_REQUIRE(ssc != NULL);

	/* accept() with no pending connection: EAGAIN -> clean no-op. */
	uart_tcp_listener(bind_fd, EVF_READ, ssc);
	ATF_CHECK(!sc->tty.opened);

	/* Real client connect + listener accept establishes the connection. */
	c1 = connect_to(sc);
	uart_tcp_listener(bind_fd, EVF_READ, ssc);
	ATF_CHECK(sc->tty.opened);
	ATF_REQUIRE(sc->mev != NULL);
	ATF_CHECK(sc->tty.rfd >= 0);

	/* Second client while connected: gets rejected with the busy message. */
	c2 = connect_to(sc);
	uart_tcp_listener(bind_fd, EVF_READ, ssc);
	ATF_CHECK(sc->tty.opened); /* first connection still owns the line */
	{
		ssize_t n = recv(c2, msg, sizeof(msg) - 1, 0);
		ATF_REQUIRE(n > 0);
		msg[n] = '\0';
		ATF_CHECK(strstr(msg, "already connected") != NULL);
	}
	(void)close(c2);

	/* Disconnect the active connection through the mev path. */
	uart_tcp_disconnect(sc);
	ATF_CHECK(!sc->tty.opened);
	ATF_CHECK(sc->mev == NULL);
	(void)close(c1);

	/* Listener path where mevent_add fails: connection is torn down. */
	g_add_fail = true;
	c3 = connect_to(sc);
	uart_tcp_listener(bind_fd, EVF_READ, ssc);
	ATF_CHECK(!sc->tty.opened); /* add failed -> not opened */
	g_add_fail = false;
	(void)close(c3);

	mevent_delete_close(sc->mev_listen);
	free(ssc);
	free(sc);
}

/* =====================================================================
 * TCP backend parse / bind error paths.
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(tcp_backend_errors);
ATF_TC_BODY(tcp_backend_errors, tc)
{
	struct uart_softc *sc;

	mock_mevent_reset();

	/* Malformed spec: neither IPv6 nor IPv4 pattern matches. */
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(-1, uart_tty_open(sc, "tcp=garbage", test_drain, sc));
	ATF_CHECK(sc->mev_listen == NULL);
	free(sc);

	/* Non-numeric host: AI_NUMERICHOST getaddrinfo() fails. */
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(-1, uart_tty_open(sc, "tcp=not.a.numeric.host:80",
	    test_drain, sc));
	ATF_CHECK(sc->mev_listen == NULL);
	free(sc);

	/* Listener mevent_add fails during setup: bind_fd + socket_softc are
	 * released and the open fails. */
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	g_add_fail = true;
	ATF_CHECK_EQ(-1, uart_tty_open(sc, "tcp=127.0.0.1:0", test_drain, sc));
	ATF_CHECK(sc->mev_listen == NULL);
	g_add_fail = false;
	free(sc);

	/* Privileged port: bind() fails for a non-root process; the ",log="
	 * file is opened first and must be cleaned up on the failure. */
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	{
		char logpath[] = "/tmp/uart_tcplog.XXXXXX";
		char spec[128];
		int lfd = mkstemp(logpath);
		ATF_REQUIRE(lfd != -1);
		(void)close(lfd);
		(void)snprintf(spec, sizeof(spec),
		    "tcp=127.0.0.1:1,log=%s", logpath);
		if (geteuid() == 0)
			atf_tc_skip("running as root: privileged bind would "
			    "succeed");
		ATF_CHECK_EQ(-1, uart_tty_open(sc, spec, test_drain, sc));
		ATF_CHECK_EQ(-1, sc->log_fd); /* log cleaned up on failure */
		(void)unlink(logpath);
	}
	free(sc);
}

/* =====================================================================
 * IPv6 TCP backend spec parsing (best-effort; skips if ::1 unavailable).
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(tcp_backend_ipv6);
ATF_TC_BODY(tcp_backend_ipv6, tc)
{
	struct uart_softc *sc;
	int rc;

	mock_mevent_reset();
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	rc = uart_tty_open(sc, "tcp=[::1]:0", test_drain, sc);
	if (rc != 0)
		atf_tc_skip("IPv6 loopback bind unavailable in this env");
	ATF_CHECK(sc->tty.is_socket);
	ATF_REQUIRE(sc->mev_listen != NULL);
	{
		struct uart_socket_softc *ssc = sc->mev_listen->arg;
		mevent_delete_close(sc->mev_listen);
		free(ssc);
	}
	free(sc);
}

/* =====================================================================
 * Snapshot codec round-trip + validation + pause/resume.
 * ===================================================================== */
#ifdef BHYVE_SNAPSHOT
static void
meta_init(struct vm_snapshot_meta *meta, uint8_t *buf, size_t sz,
    enum vm_snapshot_op op)
{
	struct vm_snapshot_buffer b = {
		.buf_start = buf,
		.buf_size = sz,
		.buf = buf,
		.buf_rem = sz,
	};

	memset(meta, 0, sizeof(*meta));
	memcpy((void *)&meta->buffer, &b, sizeof(b));
	meta->op = op;
}

ATF_TC_WITHOUT_HEAD(snapshot_roundtrip);
ATF_TC_BODY(snapshot_roundtrip, tc)
{
	struct uart_softc *sc, *sc2;
	struct vm_snapshot_meta meta = { 0 };
	uint8_t buf[256];
	int i, c;

	mock_mevent_reset();

	/* NULL guards. */
	meta_init(&meta, buf, sizeof(buf), VM_SNAPSHOT_SAVE);
	ATF_CHECK_EQ(EINVAL, uart_rxfifo_snapshot(NULL, &meta));
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(EINVAL, uart_rxfifo_snapshot(sc, NULL));

	/* Seed a known FIFO state. */
	uart_rxfifo_reset(sc, 16);
	for (i = 0; i < 6; i++)
		ATF_REQUIRE_EQ(0, uart_rxfifo_putchar(sc, (uint8_t)(0x10 + i),
		    true));
	/* Consume 2 so rindex advances (non-trivial cursor state). */
	ATF_CHECK_EQ(0x10, uart_rxfifo_getchar(sc));
	ATF_CHECK_EQ(0x11, uart_rxfifo_getchar(sc));

	meta_init(&meta, buf, sizeof(buf), VM_SNAPSHOT_SAVE);
	ATF_CHECK_EQ(0, uart_rxfifo_snapshot(sc, &meta));

	/* Restore into a fresh softc and verify the surviving bytes. */
	sc2 = uart_init();
	ATF_REQUIRE(sc2 != NULL);
	uart_rxfifo_reset(sc2, 16);
	meta_init(&meta, buf, sizeof(buf), VM_SNAPSHOT_RESTORE);
	ATF_CHECK_EQ(0, uart_rxfifo_snapshot(sc2, &meta));
	ATF_CHECK_EQ(4, uart_rxfifo_numchars(sc2));
	for (i = 0; i < 4; i++) {
		c = uart_rxfifo_getchar(sc2);
		ATF_CHECK_EQ(0x12 + i, c); /* 0x12..0x15 remained */
	}
	free(sc);
	free(sc2);

	/* Malformed restore: hand-crafted invalid cursor state -> EINVAL. */
	{
		uint8_t bad[256];
		uint32_t rindex = 0, windex = 0, num = 99, size = 16;
		size_t off = 0;
		struct uart_softc *sc3;

		memcpy(bad + off, &rindex, 4); off += 4;
		memcpy(bad + off, &windex, 4); off += 4;
		memcpy(bad + off, &num, 4); off += 4;
		memcpy(bad + off, &size, 4); off += 4;
		memset(bad + off, 0, FIFOSZ);

		sc3 = uart_init();
		ATF_REQUIRE(sc3 != NULL);
		meta_init(&meta, bad, sizeof(bad), VM_SNAPSHOT_RESTORE);
		ATF_CHECK_EQ(EINVAL, uart_rxfifo_snapshot(sc3, &meta));
		free(sc3);
	}
}

ATF_TC_WITHOUT_HEAD(snapshot_pause_resume);
ATF_TC_BODY(snapshot_pause_resume, tc)
{
	struct uart_softc *sc;

	mock_mevent_reset();

	/* NULL guards. */
	ATF_CHECK_EQ(EINVAL, uart_snapshot_pause(NULL));
	ATF_CHECK_EQ(EINVAL, uart_snapshot_resume(NULL));

	/* No tty attached: both are no-ops that keep the lock balanced. */
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(0, uart_snapshot_pause(sc));  /* locks, no mev */
	ATF_CHECK_EQ(0, uart_snapshot_resume(sc)); /* unlocks */
	free(sc);

	/* Attached tty: pause disables, resume re-enables, lock balanced. */
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	uart_rxfifo_reset(sc, 16);
	sc->tty.opened = true;
	sc->mev = mevent_add(9, EVF_READ, test_drain, sc);
	ATF_REQUIRE(sc->mev != NULL);
	ATF_CHECK_EQ(0, uart_snapshot_pause(sc));
	ATF_CHECK_EQ(1, g_disable_calls);
	ATF_CHECK_EQ(0, uart_snapshot_resume(sc));
	ATF_CHECK_EQ(1, g_enable_calls);
	mevent_delete_close(sc->mev);
	free(sc);

	/* pause failure returns the error and releases the lock. */
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	sc->tty.opened = true;
	sc->mev = mevent_add(9, EVF_READ, test_drain, sc);
	ATF_REQUIRE(sc->mev != NULL);
	g_disable_fail = true;
	ATF_CHECK(uart_snapshot_pause(sc) != 0);
	g_disable_fail = false;
	mevent_delete_close(sc->mev);
	free(sc);

	/* resume failure returns the error (retains lock ownership). */
	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	uart_rxfifo_reset(sc, 16);
	sc->tty.opened = true;
	sc->mev = mevent_add(9, EVF_READ, test_drain, sc);
	ATF_REQUIRE(sc->mev != NULL);
	ATF_CHECK_EQ(0, uart_snapshot_pause(sc));
	g_enable_fail = true;
	ATF_CHECK(uart_snapshot_resume(sc) != 0);
	g_enable_fail = false;
	mevent_delete_close(sc->mev);
	free(sc);
}
#endif /* BHYVE_SNAPSHOT */

/* =====================================================================
 * softc lock/unlock wrappers.
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(softc_lock_unlock);
ATF_TC_BODY(softc_lock_unlock, tc)
{
	struct uart_softc *sc;

	sc = uart_init();
	ATF_REQUIRE(sc != NULL);
	/* The wrappers must be a balanced lock/unlock of the real mutex. */
	uart_softc_lock(sc);
	ATF_CHECK_EQ(EBUSY, pthread_mutex_trylock(&sc->mtx));
	uart_softc_unlock(sc);
	ATF_CHECK_EQ(0, pthread_mutex_trylock(&sc->mtx));
	(void)pthread_mutex_unlock(&sc->mtx);
	free(sc);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fifo_ring_contract);
	ATF_TP_ADD_TC(tp, fifo_flow_control_mevent);
	ATF_TP_ADD_TC(tp, rxfifo_reset_with_tty);
	ATF_TP_ADD_TC(tp, putchar_output_paths);
	ATF_TP_ADD_TC(tp, drain_paths);
	ATF_TP_ADD_TC(tp, tcp_disconnect_fallback);
	ATF_TP_ADD_TC(tp, ttyopen_rawmode_pty);
	ATF_TP_ADD_TC(tp, ttyclose_restore);
	ATF_TP_ADD_TC(tp, tty_backend_open);
	ATF_TP_ADD_TC(tp, tty_open_error_paths);
	ATF_TP_ADD_TC(tp, tty_open_mevent_fail_cleanup);
	ATF_TP_ADD_TC(tp, stdio_backend_open);
	ATF_TP_ADD_TC(tp, stdio_backend_mevent_fail);
	ATF_TP_ADD_TC(tp, stdio_backend_fcntl_fail);
	ATF_TP_ADD_TC(tp, log_open_failure);
	ATF_TP_ADD_TC(tp, tcp_backend_lifecycle);
	ATF_TP_ADD_TC(tp, tcp_backend_errors);
	ATF_TP_ADD_TC(tp, tcp_backend_ipv6);
#ifdef BHYVE_SNAPSHOT
	ATF_TP_ADD_TC(tp, snapshot_roundtrip);
	ATF_TP_ADD_TC(tp, snapshot_pause_resume);
#endif
	ATF_TP_ADD_TC(tp, softc_lock_unlock);
	return (atf_no_error());
}
