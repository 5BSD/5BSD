/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2012 NetApp, Inc.
 * Copyright (c) 2013 Neel Natu <neel@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <machine/vmm.h>
#include <machine/vmm_snapshot.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#include <assert.h>
#include <capsicum_helpers.h>
#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <termios.h>
#include <unistd.h>

#include "debug.h"
#include "mevent.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif
#include "uart_backend.h"
#include "uart_backend_model.h"

struct ttyfd {
	bool	opened;
	bool	is_socket;
	bool	is_stdio;
	int	rfd;		/* fd for reading */
	int	wfd;		/* fd for writing, may be == rfd */
};

#define	FIFOSZ	((int)UART_RXFIFO_CAPACITY)

struct fifo {
	uint8_t	buf[FIFOSZ];
	int	rindex;		/* index to read from */
	int	windex;		/* index to write to */
	int	num;		/* number of characters in the fifo */
	int	size;		/* size of the fifo */
};

struct uart_softc {
	struct ttyfd	tty;
	struct fifo	rxfifo;
	struct mevent	*mev;		/* active connection (rx) event */
	struct mevent	*mev_listen;	/* TCP listener accept event */
	int		log_fd;		/* ",log=" console tee, or -1 */
	pthread_mutex_t mtx;
};

struct uart_socket_softc {
	struct uart_softc *softc;
	void (*drain)(int, enum ev_type, void *);
	void *arg;
};

static bool uart_stdio;		/* stdio in use for i/o */
static bool uart_stdio_tty;
static struct termios tio_stdio_orig;

static void uart_tcp_disconnect(struct uart_softc *);

static void
ttyclose(void)
{
	if (uart_stdio_tty)
		(void)tcsetattr(STDIN_FILENO, TCSANOW, &tio_stdio_orig);
}

static int
ttyopen(struct ttyfd *tf)
{
	struct termios orig, new;

	if (!isatty(tf->rfd))
		return (0);
	if (tcgetattr(tf->rfd, &orig) != 0)
		return (-1);
	new = orig;
	cfmakeraw(&new);
	new.c_cflag |= CLOCAL;
	if (tcsetattr(tf->rfd, TCSANOW, &new) != 0)
		return (-1);
	if (tf->is_stdio) {
		tio_stdio_orig = orig;
		uart_stdio_tty = true;
		atexit(ttyclose);
	}
	raw_stdio = 1;
	return (0);
}

static int
ttyread(struct ttyfd *tf, uint8_t *ret)
{
	uint8_t rb;
	int len;

	len = read(tf->rfd, &rb, 1);
	if (ret && len == 1)
		*ret = rb;

	return (len);
}

static int
ttywrite(struct ttyfd *tf, unsigned char wb)
{
	return (write(tf->wfd, &wb, 1));
}

static bool
rxfifo_available(struct uart_softc *sc)
{
	return (sc->rxfifo.num < sc->rxfifo.size);
}

int
uart_rxfifo_getchar(struct uart_softc *sc)
{
	struct fifo *fifo;
	int c, error, wasfull;

	wasfull = 0;
	fifo = &sc->rxfifo;
	if (fifo->num > 0) {
		if (!rxfifo_available(sc))
			wasfull = 1;
		c = fifo->buf[fifo->rindex];
		fifo->rindex = (fifo->rindex + 1) % fifo->size;
		fifo->num--;
		if (wasfull) {
			if (sc->tty.opened) {
				error = mevent_enable(sc->mev);
				if (error != 0)
					warnc(error, "uart: cannot enable receive event");
			}
		}
		return (c);
	} else
		return (-1);
}

int
uart_rxfifo_numchars(struct uart_softc *sc)
{
	return (sc->rxfifo.num);
}

static int
rxfifo_putchar(struct uart_softc *sc, uint8_t ch)
{
	struct fifo *fifo;
	int error;

	fifo = &sc->rxfifo;

	if (fifo->num < fifo->size) {
		fifo->buf[fifo->windex] = ch;
		fifo->windex = (fifo->windex + 1) % fifo->size;
		fifo->num++;
		if (!rxfifo_available(sc)) {
			if (sc->tty.opened) {
				/*
				 * Disable mevent callback if the FIFO is full.
				 */
				error = mevent_disable(sc->mev);
				if (error != 0)
					warnc(error, "uart: cannot disable receive event");
			}
		}
		return (0);
	} else
		return (-1);
}

void
uart_rxfifo_drain(struct uart_softc *sc, bool loopback)
{
	uint8_t ch;
	int len;

	if (loopback) {
		if (ttyread(&sc->tty, &ch) == 0 && sc->tty.is_socket)
			uart_tcp_disconnect(sc);
	} else {
		while (rxfifo_available(sc)) {
			len = ttyread(&sc->tty, &ch);
			if (len <= 0) {
				/* read returning 0 means disconnected. */
				if (len == 0 && sc->tty.is_socket)
					uart_tcp_disconnect(sc);
				break;
			}

			rxfifo_putchar(sc, ch);
		}
	}
}

int
uart_rxfifo_putchar(struct uart_softc *sc, uint8_t ch, bool loopback)
{
	if (loopback)
		return (rxfifo_putchar(sc, ch));

	/*
	 * Tee to the console log (",log=" backend option), if configured,
	 * before considering the socket.  This is unconditional so the full
	 * console stream is captured even when no client is attached.
	 */
	if (sc->log_fd >= 0) {
		ssize_t n;

		do {
			n = write(sc->log_fd, &ch, 1);
		} while (n < 0 && errno == EINTR);
	}

	if (sc->tty.opened) {
		/* write returning -1 means disconnected. */
		if (ttywrite(&sc->tty, ch) == -1 && sc->tty.is_socket &&
		    errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
			uart_tcp_disconnect(sc);
		return (0);
	} else {
		/* Drop on the floor (still logged above if ",log=" set). */
		return (0);
	}
}

void
uart_rxfifo_reset(struct uart_softc *sc, int size)
{
	char flushbuf[32];
	struct fifo *fifo;
	ssize_t nread;
	int error;

	fifo = &sc->rxfifo;
	if (size < 1)
		size = 1;
	else if (size > FIFOSZ)
		size = FIFOSZ;
	bzero(fifo, sizeof(struct fifo));
	fifo->size = size;

	if (sc->tty.opened) {
		/*
		 * Flush any unread input from the tty buffer.
		 */
		while (1) {
			nread = read(sc->tty.rfd, flushbuf, sizeof(flushbuf));
			if (nread != sizeof(flushbuf))
				break;
		}

		/*
		 * Enable mevent to trigger when new characters are available
		 * on the tty fd.
		 */
		error = mevent_enable(sc->mev);
		if (error != 0)
			warnc(error, "uart: cannot enable receive event");
	}
}

int
uart_rxfifo_size(struct uart_softc *sc __unused)
{
	return (FIFOSZ);
}

#ifdef BHYVE_SNAPSHOT
int
uart_rxfifo_snapshot(struct uart_softc *sc, struct vm_snapshot_meta *meta)
{
	uint32_t rindex, windex, num, size;
	uint8_t buf[FIFOSZ];
	int ret;

	if (sc == NULL || meta == NULL)
		return (EINVAL);
	rindex = (uint32_t)sc->rxfifo.rindex;
	windex = (uint32_t)sc->rxfifo.windex;
	num = (uint32_t)sc->rxfifo.num;
	size = (uint32_t)sc->rxfifo.size;
	memcpy(buf, sc->rxfifo.buf, sizeof(buf));
	SNAPSHOT_LE32_OR_LEAVE(rindex, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(windex, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(num, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(size, meta, ret, done);
	SNAPSHOT_BUF_OR_LEAVE(buf, sizeof(buf), meta, ret, done);
	if (!uart_rxfifo_state_valid(rindex, windex, num, size)) {
		ret = EINVAL;
		goto done;
	}
	if (meta->op == VM_SNAPSHOT_RESTORE) {
		sc->rxfifo.rindex = (int)rindex;
		sc->rxfifo.windex = (int)windex;
		sc->rxfifo.num = (int)num;
		sc->rxfifo.size = (int)size;
		memcpy(sc->rxfifo.buf, buf, sizeof(buf));
	}

done:
	return (ret);
}

int
uart_snapshot_pause(struct uart_softc *sc)
{
	int error;

	if (sc == NULL)
		return (EINVAL);
	pthread_mutex_lock(&sc->mtx);
	error = 0;
	if (sc->tty.opened && sc->mev != NULL)
		error = mevent_disable(sc->mev);
	if (error != 0)
		pthread_mutex_unlock(&sc->mtx);
	return (error);
}

int
uart_snapshot_resume(struct uart_softc *sc)
{
	int error;

	if (sc == NULL)
		return (EINVAL);
	error = 0;
	if (sc->tty.opened && sc->mev != NULL && rxfifo_available(sc))
		error = mevent_enable(sc->mev);
	/*
	 * Preserve pause ownership on failure so the caller can retry resume.
	 * The mutex was intentionally retained by uart_snapshot_pause().
	 */
	if (error == 0)
		pthread_mutex_unlock(&sc->mtx);
	return (error);
}
#endif

/*
 * Listen on the TCP port, wait for a connection, then accept it.
 */
static void
uart_tcp_listener(int fd, enum ev_type type __unused, void *arg)
{
	static const char tcp_error_msg[] = "Socket already connected\n";
	struct uart_socket_softc *socket_softc = (struct uart_socket_softc *)
	    arg;
	struct uart_softc *sc = socket_softc->softc;
	int conn_fd;

	conn_fd = accept4(fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (conn_fd == -1)
		goto clean;

	pthread_mutex_lock(&sc->mtx);

	if (sc->tty.opened) {
		(void)send(conn_fd, tcp_error_msg, sizeof(tcp_error_msg), 0);
		pthread_mutex_unlock(&sc->mtx);
		goto clean;
	} else {
		sc->tty.rfd = sc->tty.wfd = conn_fd;
		sc->tty.opened = true;
		sc->mev = mevent_add(sc->tty.rfd, EVF_READ, socket_softc->drain,
		    socket_softc->arg);
		if (sc->mev == NULL) {
			sc->tty.opened = false;
			sc->tty.rfd = sc->tty.wfd = -1;
			pthread_mutex_unlock(&sc->mtx);
			goto clean;
		}
	}

	pthread_mutex_unlock(&sc->mtx);
	return;

clean:
	if (conn_fd != -1)
		close(conn_fd);
}

/*
 * When a connection-oriented protocol disconnects, this handler is used to
 * clean it up.
 *
 * Note that this function is a helper, so the caller is responsible for
 * locking the softc.
 */
static void
uart_tcp_disconnect(struct uart_softc *sc)
{
	if (sc->mev != NULL)
		(void)mevent_delete_close(sc->mev);
	else if (sc->tty.rfd >= 0)
		(void)close(sc->tty.rfd);
	sc->mev = NULL;
	sc->tty.opened = false;
	sc->tty.rfd = sc->tty.wfd = -1;
}

static int
uart_stdio_backend(struct uart_softc *sc)
{
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
	cap_ioctl_t cmds[] = { TIOCGETA, TIOCSETA, TIOCGWINSZ };
#endif
	int rflags, wflags;

	if (uart_stdio)
		return (-1);

	sc->tty.rfd = STDIN_FILENO;
	sc->tty.wfd = STDOUT_FILENO;
	sc->tty.opened = true;
	sc->tty.is_stdio = true;

	rflags = fcntl(sc->tty.rfd, F_GETFL);
	if (rflags == -1 ||
	    fcntl(sc->tty.rfd, F_SETFL, rflags | O_NONBLOCK) != 0)
		return (-1);
	wflags = fcntl(sc->tty.wfd, F_GETFL);
	if (wflags == -1 ||
	    fcntl(sc->tty.wfd, F_SETFL, wflags | O_NONBLOCK) != 0) {
		(void)fcntl(sc->tty.rfd, F_SETFL, rflags);
		return (-1);
	}

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_EVENT, CAP_IOCTL, CAP_READ);
	if (caph_rights_limit(sc->tty.rfd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
	if (caph_ioctls_limit(sc->tty.rfd, cmds, nitems(cmds)) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	uart_stdio = true;

	return (0);
}

static int
uart_tty_backend(struct uart_softc *sc, const char *path)
{
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
	cap_ioctl_t cmds[] = { TIOCGETA, TIOCSETA, TIOCGWINSZ };
#endif
	int fd;

	fd = open(path, O_RDWR | O_NONBLOCK);
	if (fd < 0)
		return (-1);

	if (!isatty(fd)) {
		close(fd);
		return (-1);
	}

	sc->tty.rfd = sc->tty.wfd = fd;
	sc->tty.opened = true;

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_EVENT, CAP_IOCTL, CAP_READ, CAP_WRITE);
	if (caph_rights_limit(fd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
	if (caph_ioctls_limit(fd, cmds, nitems(cmds)) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	return (0);
}

/*
 * Listen on the address and add it to the kqueue.
 *
 * If a connection is established (e.g., the TCP handler is triggered),
 * replace the handler with the connected handler.
 */
static int
uart_tcp_backend(struct uart_softc *sc, const char *path,
    void (*drain)(int, enum ev_type, void *), void *arg)
{
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
	cap_ioctl_t cmds[] = { TIOCGETA, TIOCSETA, TIOCGWINSZ };
#endif
	int bind_fd = -1;
	char addr[256], port[6];
	int domain;
	struct addrinfo hints, *src_addr = NULL;
	struct uart_socket_softc *socket_softc = NULL;

	if (sscanf(path, "tcp=[%255[^]]]:%5s", addr, port) == 2) {
		domain = AF_INET6;
	} else if (sscanf(path, "tcp=%255[^:]:%5s", addr, port) == 2) {
		domain = AF_INET;
	} else {
		warnx("Invalid number of parameter");
		goto clean;
	}

	bind_fd = socket(domain, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (bind_fd < 0)
		goto clean;

	/* Don't let TIME_WAIT remnants of a previous run block the bind. */
	(void)setsockopt(bind_fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 },
	    sizeof(int));

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = domain;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;

	if (getaddrinfo(addr, port, &hints, &src_addr) != 0) {
		warnx("Invalid address %s:%s", addr, port);
		goto clean;
	}

	if (bind(bind_fd, src_addr->ai_addr, src_addr->ai_addrlen) == -1) {
		warn(
		    "bind(%s:%s)",
		    addr, port);
		goto clean;
	}

	freeaddrinfo(src_addr);
	src_addr = NULL;

	int flags = fcntl(bind_fd, F_GETFL);
	if (flags == -1 || fcntl(bind_fd, F_SETFL, flags | O_NONBLOCK) == -1)
		goto clean;

	if (listen(bind_fd, 1) == -1) {
		warnx("listen(%s:%s)", addr, port);
		goto clean;
	}

	/*
	 * Set the connection softc structure, which includes both the softc
	 * and the drain function provided by the frontend.
	 */
	if ((socket_softc = calloc(1, sizeof(struct uart_socket_softc))) ==
	    NULL)
		goto clean;

	sc->tty.is_socket = true;

	socket_softc->softc = sc;
	socket_softc->drain = drain;
	socket_softc->arg = arg;

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_EVENT, CAP_ACCEPT, CAP_RECV, CAP_SEND,
	    CAP_FCNTL, CAP_IOCTL);
	if (caph_rights_limit(bind_fd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
	if (caph_ioctls_limit(bind_fd, cmds, nitems(cmds)) == -1)
		errx(EX_OSERR, "Unable to apply ioctls for sandbox");
	if (caph_fcntls_limit(bind_fd, CAP_FCNTL_SETFL) == -1)
		errx(EX_OSERR, "Unable to apply fcntls for sandbox");
#endif

	if ((sc->mev_listen = mevent_add(bind_fd, EVF_READ, uart_tcp_listener,
	    socket_softc)) == NULL)
		goto clean;

	return (0);

clean:
	if (bind_fd != -1)
		close(bind_fd);
	if (socket_softc != NULL)
		free(socket_softc);
	if (src_addr)
		freeaddrinfo(src_addr);
	return (-1);
}

struct uart_softc *
uart_init(void)
{
	struct uart_softc *sc = calloc(1, sizeof(struct uart_softc));
	if (sc == NULL)
		return (NULL);

	sc->log_fd = -1;
	sc->tty.rfd = sc->tty.wfd = -1;
	if (pthread_mutex_init(&sc->mtx, NULL) != 0) {
		free(sc);
		return (NULL);
	}

	return (sc);
}

/*
 * Open a console log file for the ",log=<path>" backend suffix and record it
 * on the softc.  Every byte the guest transmits is tee'd here unconditionally
 * (see uart_rxfifo_putchar), independent of the underlying backend and of
 * whether any client is attached -- making console capture deterministic.
 * This is intentionally backend-agnostic: it applies to stdio, tcp, and
 * device backends alike.
 */
static void
uart_open_log(struct uart_softc *sc, const char *logpath)
{
	int lf;

	lf = open(logpath, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
	if (lf == -1) {
		warn("uart: cannot open console log %s", logpath);
		return;
	}
#ifndef WITHOUT_CAPSICUM
	{
		cap_rights_t lrights;

		cap_rights_init(&lrights, CAP_WRITE);
		if (caph_rights_limit(lf, &lrights) == -1)
			errx(EX_OSERR, "Unable to apply rights for sandbox");
	}
#endif
	sc->log_fd = lf;
}

int
uart_tty_open(struct uart_softc *sc, const char *path,
    void (*drain)(int, enum ev_type, void *), void *arg)
{
	int retval;
	char *cleanpath, *logspec;

	/*
	 * Peel off an optional ",log=<path>" suffix before dispatching, so the
	 * backends see only their own path syntax.  Works for any backend.
	 */
	if (sc == NULL || path == NULL || drain == NULL || sc->tty.opened ||
	    sc->mev_listen != NULL)
		return (-1);
	cleanpath = strdup(path);
	if (cleanpath == NULL)
		return (-1);
	logspec = strstr(cleanpath, ",log=");
	if (logspec != NULL) {
		char logfile[PATH_MAX];

		if (sscanf(logspec, ",log=%1023[^,]", logfile) == 1)
			uart_open_log(sc, logfile);
		*logspec = '\0';	/* hide suffix from the backend parser */
	}
	path = cleanpath;

	if (strcmp("stdio", path) == 0)
		retval = uart_stdio_backend(sc);
	else if (strncmp("tcp", path, 3) == 0)
		retval = uart_tcp_backend(sc, path, drain, arg);
	else
		retval = uart_tty_backend(sc, path);
	if (retval != 0) {
		if (sc->tty.is_stdio) {
			uart_stdio = false;
			uart_stdio_tty = false;
		} else if (sc->tty.opened && sc->tty.rfd >= 0) {
			(void)close(sc->tty.rfd);
		}
		sc->tty.opened = false;
		sc->tty.is_socket = false;
		sc->tty.is_stdio = false;
		sc->tty.rfd = sc->tty.wfd = -1;
		if (sc->log_fd >= 0) {
			(void)close(sc->log_fd);
			sc->log_fd = -1;
		}
	}

	/*
	 * A connection-oriented protocol should wait for a connection,
	 * so it may not listen to anything during initialization.
	 */
	if (retval == 0 && !sc->tty.is_socket) {
		if (ttyopen(&sc->tty) != 0 ||
		    (sc->mev = mevent_add(sc->tty.rfd, EVF_READ, drain,
		    arg)) == NULL) {
			if (sc->tty.is_stdio) {
				if (uart_stdio_tty)
					(void)tcsetattr(STDIN_FILENO, TCSANOW,
					    &tio_stdio_orig);
				uart_stdio = false;
				uart_stdio_tty = false;
				raw_stdio = 0;
			} else if (sc->tty.rfd >= 0) {
				(void)close(sc->tty.rfd);
			}
			sc->tty.opened = false;
			sc->tty.rfd = sc->tty.wfd = -1;
			if (sc->log_fd >= 0) {
				(void)close(sc->log_fd);
				sc->log_fd = -1;
			}
			retval = -1;
		}
	}

	free(cleanpath);
	return (retval);
}

void
uart_softc_lock(struct uart_softc *sc)
{
	pthread_mutex_lock(&sc->mtx);
}

void
uart_softc_unlock(struct uart_softc *sc)
{
	pthread_mutex_unlock(&sc->mtx);
}
