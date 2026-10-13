/*-
 * Copyright (c) 2020 Domagoj Stolfa
 * Copyright (c) 2021 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from Arm Limited.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from the Kenneth Hayter Scholarship Fund.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atomic>

#include "dtraced.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_errmsg.h"
#include "dtraced_id.h"
#include "dtraced_job.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

namespace dtraced {

client_fd::client_fd(int _kq, int _fd, dtd_initmsg_t initmsg)
    : kq(_kq)
    , fd(_fd)
    , subs(initmsg.subs)
    , cleaned_up(false)
    , id(0)
    , kind(initmsg.kind)
{
	memcpy(this->ident, initmsg.ident, DTRACED_FDIDENTLEN);
	this->id = dtraced_genid();
}

bool
client_fd::enable_read(void *data)
{
	struct kevent change_event[1];

	EV_SET(change_event, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, data);
	return (kevent(this->kq, change_event, 1, NULL, 0, NULL) != -1);
}

bool
client_fd::enable_write(void *data)
{
	struct kevent change_event[1];

	EV_SET(change_event, fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, data);
	return (kevent(this->kq, change_event, 1, NULL, 0, NULL) != -1);
}

bool
client_fd::enable_rw(void *data)
{

	return (this->enable_read(data) && this->enable_write(data));
}

bool
client_fd::re_enable_read(void)
{
	struct kevent change_event[1];

	EV_SET(change_event, this->fd, EVFILT_READ,
	    EV_ENABLE | EV_KEEPUDATA, 0, 0, 0);
	return (kevent(this->kq, change_event, 1, NULL, 0, NULL) != -1);
}

bool
client_fd::re_enable_write(void)
{
	struct kevent change_event[1];

	EV_SET(change_event, this->fd, EVFILT_WRITE,
	    EV_ENABLE | EV_KEEPUDATA, 0, 0, 0);
	return (kevent(this->kq, change_event, 1, NULL, 0, NULL) != -1);
}

bool
client_fd::re_enable_rw(void)
{

	return (this->re_enable_read() && this->re_enable_write());
}

bool
client_fd::disable_read(void)
{
	struct kevent change_event[1];

	EV_SET(change_event, this->fd, EVFILT_READ,
	    EV_DISABLE | EV_KEEPUDATA, 0, 0, 0);
	return (kevent(kq, change_event, 1, NULL, 0, NULL) != -1);
}

bool
client_fd::disable_write(void)
{
	struct kevent change_event[1];

	EV_SET(change_event, this->fd, EVFILT_WRITE,
	    EV_DISABLE | EV_KEEPUDATA, 0, 0, 0);
	return (kevent(kq, change_event, 1, NULL, 0, NULL) != -1);
}

bool
client_fd::disable_rw(void)
{

	return (this->disable_read() && this->disable_write());
}

void
client_fd::close(void)
{

	LOG("close(%s)", std::string(*this).c_str());
	::close(this->fd);
}

void
client_fd::shutdown(void)
{

	::shutdown(this->fd, SHUT_RDWR);
}

client_fd::operator std::string(void) const
{

	return (std::to_string(this->fd) + "-" + std::string(this->ident));
}

client_fd::~client_fd()
{

	LOG("close(%s)", std::string(*this).c_str());
	::close(this->fd);
}

ssize_t
client_fd::send_ack(void)
{

	unsigned char ack = 1;
	return (::send(this->fd, &ack, 1, 0) < 0);
}

ssize_t
client_fd::send_nak(void)
{

	unsigned char ack = 0;
	return (::send(this->fd, &ack, 1, 0) < 0);
}

bool
client_fd::send(void *b, size_t len)
{

	return (::send(this->fd, b, len, 0) == static_cast<ssize_t>(len));
}

bool
client_fd::recv(void *b, size_t len)
{
	size_t nbytes = len;
	char *_buf = (char *)b;

	for (;;) {
		ssize_t rval = ::recv(this->fd, _buf, nbytes, 0);
		if (rval < 0) {
			ERR("recv() failed on %s with: %m", this->ident);
			return (false);
		} else if ((size_t)rval == nbytes)
			return (true);

		if (rval == 0)
			return (false);

		_buf += rval;
		nbytes -= rval;
	}

	// Should not be reachable.
	return (false);
}

int
enable_fd(int kq, int fd, int filt, void *data)
{
	struct kevent change_event[1];

	EV_SET(change_event, fd, filt, EV_ADD | EV_ENABLE, 0, 0, data);
	return (kevent(kq, change_event, 1, NULL, 0, NULL) < 0);
}

int
reenable_fd(int kq, int fd, int filt)
{
	struct kevent change_event[1];

	EV_SET(change_event, fd, filt, EV_ENABLE | EV_KEEPUDATA, 0, 0, 0);
	return (kevent(kq, change_event, 1, NULL, 0, NULL));
}

int
disable_fd(int kq, int fd, int filt)
{
	struct kevent change_event[1];

	EV_SET(change_event, fd, filt, EV_DISABLE | EV_KEEPUDATA, 0, 0, 0);
	return (kevent(kq, change_event, 1, NULL, 0, NULL));
}

int
disable_rw(int kq, int fd)
{

	return (disable_fd(kq, fd, EVFILT_READ) ||
	    disable_fd(kq, fd, EVFILT_WRITE));
}

}
