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
#include <sys/socket.h>
#include <sys/un.h>

#include <assert.h>
#include <dttransport.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_dttransport.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

#include <atomic>

namespace dtraced {

static size_t dirlen;

static void
dtt_elf(state *s, dtt_entry_t *e)
{
	static char tmpfile[MAXPATHLEN];
	static int fd = 0;
	static char *elf = NULL;
	static size_t len = 0;
	static size_t offs = 0;
	char donepath[MAXPATHLEN] = { 0 };

	if (fd == -1)
		return;

	/*
	 * At this point we have the /var/ddtrace/inbound
	 * open and created, so we can just create new files in
	 * it without too much worry of failure because
	 * directory does not exist.
	 */
	if (fd == 0) {
		{
			std::lock_guard lk(s->inbounddir->dirmtx);
			sprintf(tmpfile, "%s.elf.XXXXXXXXXXXXXX",
			    s->inbounddir->full_path().c_str());
		}

		fd = mkstemp(tmpfile);
		if (fd == -1) {
			ERR("failed to mkstemp(%s): %m", tmpfile);
			return;
		}

		elf = (char *)malloc(e->u.elf.totallen);
		if (elf == NULL) {
			ERR("Failed to malloc elf: %m");
			abort();
		}

		memset(elf, 0, e->u.elf.totallen);
		len = e->u.elf.totallen;
	}

	assert(offs < len && "Assertion happens if file was not created");
	if (offs + e->u.elf.len > len) {
		ERR("offs + elflen (%zu) > len (%zu)", offs + e->u.elf.len,
		    len);
		return;
	}

	assert(offs + e->u.elf.len <= len && "Assertion happens if ELF segment length is too long");
	memcpy(elf + offs, e->u.elf.data, e->u.elf.len);
	offs += e->u.elf.len;

	if (e->u.elf.hasmore == 0) {
		if (write(fd, elf, len) < 0) {
			if (errno == EINTR)
				return;

			ERR("failed to write data to %s: %m", tmpfile);
		}

		strncpy(donepath, tmpfile, dirlen);
		strcpy(donepath + dirlen, tmpfile + dirlen + 1);

		if (rename(tmpfile, donepath)) {
			ERR("failed to move %s to %s: %m", tmpfile, donepath);
		}

		free(elf);
		close(fd);
		fd = 0;
		offs = 0;
		len = 0;

		{
			std::lock_guard lk(s->inbounddir->dirmtx);
			sprintf(tmpfile, "%s.elf.XXXXXXXXXXXXXX",
			    s->inbounddir->full_path().c_str());
		}
	}
}

static void
dtt_kill(state *s, dtt_entry_t *e)
{
	std::lock_guard lk(s->killmtx);
	s->pids_to_kill.push(e->u.kill.pid);
	s->killcv.notify_all();
}

static void
dtt_cleanup(state *s)
{
	{
		std::lock_guard lk(s->pidlistmtx);
		while (!s->pidlist.empty()) {
			auto it = s->pidlist.begin();
			pid_t pid = *it;
			s->pidlist.erase(it);
			WARN("SIGKILL %d", pid);
			(void)kill(pid, SIGKILL);
		}
	}

	/* Re-exec ourselves to ensure full cleanup. */
	WARN("re-execing");
	s->re_exec();
}

static int
setup_connection(state *s)
{
	dtd_initmsg_t initmsg;
	struct sockaddr_un addr;
	int sockfd;
	size_t l;

	memset(&initmsg, 0, sizeof(initmsg));

	sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sockfd == -1) {
		ERR("Failed creating a socket: %m");
		return (-1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;

	l = strlcpy(addr.sun_path, DTRACED_SOCKPATH, sizeof(addr.sun_path));
	if (l >= sizeof(addr.sun_path)) {
		ERR("Failed setting addr.sun_path to /var/ddtrace/sub.sock");
		close(sockfd);
		return (-1);
	}

	(void) sem_wait(&s->socksema);

	if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		ERR("connect to /var/ddtrace/sub.sock failed: %m");
		close(sockfd);
		return (-1);
	}

	if (recv(sockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		fprintf(stderr, "Failed to read from sockfd: %m");
		close(sockfd);
		return (-1);
	}

	if (initmsg.kind != DTRACED_KIND_DTRACED) {
		ERR("Expected dtraced kind, got %d", initmsg.kind);
		close(sockfd);
		return (-1);
	}

	memset(&initmsg, 0, sizeof(initmsg));
	initmsg.kind = DTRACED_KIND_FORWARDER;
	initmsg.subs = DTD_SUB_ELFWRITE;
	snprintf(initmsg.ident, DTRACED_FDIDENTLEN, "dtraced-dttransport-%d", getpid());

	if (send(sockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		ERR("Failed to write initmsg to sockfd: %m");
		close(sockfd);
		return (-1);
	}

	return (sockfd);
}

/*
 * Runs in its own thread. Reads ELF files from dttransport and puts them in
 * the inbound directory.
 */
void
listen_dttransport(void *_s)
{
	state *s = (state *)_s;
	dtt_entry_t e;
	int rval;

	{
		std::lock_guard lk(s->inbounddir->dirmtx);
		dirlen = s->inbounddir->full_path().length();
	}

	for (;;) {
		rval = 0;
		while (s->shutdown.load() == 0 && rval == 0) {
			rval = read(s->dtt_fd, &e, sizeof(e));
			if (rval < 0) {
				if (errno == EWOULDBLOCK) {
					usleep(DTRACED_SLEEPTIME);
					rval = 0;
					continue;
				}

				ERR("failed to read event: %m");
				broadcast_shutdown(*s);
				return;
			}
		}

		if (unlikely(s->shutdown.load()))
			break;

		if (unlikely(rval != sizeof(e))) {
			ERR("expected to read size %zu, got %zu", sizeof(e),
			    rval);
			broadcast_shutdown(*s);
			return;
		}

		switch (e.event_kind) {
		case DTT_ELF:
			dtt_elf(s, &e);
			break;

		case DTT_KILL:
			dtt_kill(s, &e);
			break;

		case DTT_CLEANUP_DTRACED:
			dtt_cleanup(s);
			break;

		default:
			ERR("got unknown event (%d) from dttransport",
			    e.event_kind);
			break;
		}
	}

	return;
}

void
write_dttransport(void *_s)
{
	__cleanup(closefd_generic) int sockfd = -1;
	state *s = (state *)_s;
	dtt_entry_t e;
	size_t lentoread, len, totallen;
	uint32_t identifier;
	dtraced_hdr_t header = {};
	ssize_t r;
	uintptr_t msg_ptr;
	unsigned char *msg;

	lentoread = len = totallen = 0;

	sockfd = setup_connection(s);
	if (sockfd == -1) {
		broadcast_shutdown(*s);
		return;
	}

	for (;;) {
		r = 0;
		while (s->shutdown.load() == 0 && r == 0) {
			r = recv(sockfd, &header, DTRACED_MSGHDRSIZE,
			    MSG_DONTWAIT);
			if (r < 0) {
				/*
				 * If there's nothing to read, sleep and try
				 * again.
				 */
				if (errno == EAGAIN) {
					r = 0;
					usleep(DTRACED_SLEEPTIME);
					continue;
				}

				ERR("failed to recv from sub.sock: %m");
				broadcast_shutdown(*s);
				return;
			}
		}

		if (unlikely(s->shutdown.load())) {
			broadcast_shutdown(*s);
			return;
		}

		if (unlikely(r != DTRACED_MSGHDRSIZE)) {
			ERR("expected to read size %zu, got %zu",
			    DTRACED_MSGHDRSIZE, r);
			broadcast_shutdown(*s);
			return;
		}

		if (unlikely(DTRACED_MSG_TYPE(header) != DTRACED_MSG_ELF)) {
			ERR("Received unknown message type: %lu",
			    DTRACED_MSG_TYPE(header));
			broadcast_shutdown(*s);
			return;
		}

		len = DTRACED_MSG_LEN(header);
		msg = (unsigned char *)malloc(len);
		if (msg == NULL) {
			ERR("Failed to allocate a new message: %m");
			abort();
		}

		totallen = len;
		identifier = arc4random();
		msg_ptr = (uintptr_t)msg;
		for (;;) {
			r = recv(sockfd, (void *)msg_ptr, len, 0);
			if (r < 0) {
				ERR("exiting write_dttransport(): %m");
				broadcast_shutdown(*s);
				return;
			} else if ((size_t)r == len)
				break;

			len -= r;
			msg_ptr += r;
		}


		msg_ptr = (uintptr_t)msg;
		len = totallen;

		while (len != 0) {
			memset(&e, 0, sizeof(e));
			lentoread = len > DTT_MAXDATALEN ? DTT_MAXDATALEN : len;

			e.event_kind = DTT_ELF;
			e.u.elf.identifier = identifier;
			e.u.elf.hasmore = len > DTT_MAXDATALEN ? 1 : 0;
			e.u.elf.len = lentoread;
			e.u.elf.totallen = totallen;
			memcpy(e.u.elf.data, msg, lentoread);

			if (unlikely(write(s->dtt_fd, &e, sizeof(e)) < 0)) {
				/*
				 * If we don't have dttransport opened,
				 * we just move on. It might get opened
				 * at some point.
				 */
				broadcast_shutdown(*s);
				return;
			}

			len -= lentoread;
			msg += lentoread;

			assert(len >= 0 && len < totallen);
			assert((uintptr_t)msg >= msg_ptr);
			assert((uintptr_t)msg <= (msg_ptr + totallen));
		}
		assert(len == 0);

		free((void *)msg_ptr);
	}

	return;
}

}
