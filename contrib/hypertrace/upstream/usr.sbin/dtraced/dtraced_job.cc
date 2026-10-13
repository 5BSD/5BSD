/*-
 * Copyright (c) 2023 Domagoj Stolfa
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
#include <sys/stat.h>

#include <assert.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced_clientrequest.h"
#include "dtraced_connection.h"
#include "dtraced_errmsg.h"
#include "dtraced_id.h"
#include "dtraced_job.h"
#include "dtraced_state.h"

namespace dtraced {

void
job::tag(void)
{

	this->init_id = this->connsockfd->id;
	this->id = dtraced_genid();
}

job::job(job_kind job_kind, client_fd *dfdp)
    : kind(job_kind)
{
	dfdp->acquire();
	this->connsockfd = dfdp;
	this->tag();

	this->ident_str[sizeof(this->ident_str) - 1] = '\0';
	sprintf(this->ident_str, "%lx-%lx", this->init_id, this->id);
}

job::~job()
{
	switch (this->kind) {
	case NOTIFY_ELFWRITE: {
		notify_elfwrite_job &ne = this->notify_elfwrite_get();
		free(ne.path);
		this->connsockfd->release();
		break;
	}

	case CLEANUP:
	case KILL:
	case READ_DATA:
		this->connsockfd->release();
		break;

	case SEND_INFO:
		break;

	default:
		break;
	}
}

bool
job::send_elf(void)
{
	using uchar = unsigned char;

	__cleanup(closefd_generic) int elffd = -1;
	dtraced_hdr_t header;

	client_fd &dfd = *this->connsockfd;
	notify_elfwrite_job &ne = this->notify_elfwrite_get();

	struct stat stat;

	DEBUG("%s%s to %s", ne.dir->dirpath, ne.path, std::string(dfd).c_str());

	/*
	 * Sanity assertions.
	 */
	assert(ne.path != NULL);
	assert(ne.pathlen <= MAXPATHLEN);
	assert(ne.dir->dirfd != -1);

	elffd = openat(ne.dir->dirfd, ne.path, O_RDONLY);
	if (elffd == -1) {
		ERR("failed to open %s: %m", ne.path);
		return (false);
	}

	if (fstat(elffd, &stat) != 0) {
		ERR("failed to fstat %s: %m", ne.path);
		return (false);
	}

	size_t elflen = stat.st_size;

	size_t msglen = ne.nosha ? elflen : elflen + SHA256_DIGEST_LENGTH;
	std::vector<uchar> msg(msglen, 0);

	DTRACED_MSG_TYPE(header) = DTRACED_MSG_ELF;
	DTRACED_MSG_LEN(header) = msglen;

	uchar *contents = ne.nosha ? &msg[0] : &msg[0] + SHA256_DIGEST_LENGTH;

	if (read(elffd, contents, elflen) < 0) {
		ERR("failed to read ELF contents: %m");
		return (false);
	}

	if (ne.nosha == false && SHA256(contents, elflen, &msg[0]) == NULL) {
		ERR("failed to create a SHA256 of the file");
		return (false);
	}

	if (!dfd.send(&header, DTRACED_MSGHDRSIZE)) {
		ERR("failed to write to %s (%s, %zu): %m", dfd.ident, ne.path,
		    ne.pathlen);
		return (false);
	}

	if (!dfd.send(&msg[0], msglen)) {
		ERR("failed to write to %s (%s, %zu): %m", dfd.ident, ne.path,
		    ne.pathlen);
		return (false);
	}

	if (!dfd.re_enable_write()) {
		ERR("re_enable_write() failed with: %m");
		return (false);
	}

	return (true);
}

bool
job::send_kill(void)
{
	dtraced_hdr_t header;
	client_fd &dfd = *this->connsockfd;
	kill_job &k = this->kill_get();

	if (k.pid <= 1) {
		ERR("unexpected pid: %d", k.pid);
		return (false);
	}

	/*
	 * For now the header only includes the message kind, so
	 * we don't really make it a structure. In the future,
	 * this might change.
	 */
	DTRACED_MSG_TYPE(header) = DTRACED_MSG_KILL;
	DTRACED_MSG_KILLPID(header) = k.pid;
	DTRACED_MSG_KILLVMID(header) = k.vmid;

	if (!dfd.send(&header, DTRACED_MSGHDRSIZE)) {
		if (errno == EPIPE)
			ERR("failed to write to %s: %m", dfd.ident);
		return (false);
	}

	if (!dfd.re_enable_write()) {
		ERR("re_enable_write() failed with: %m");
		return (false);
	}

	return (true);
}

bool
job::send_info(state &s)
{
	dtraced_hdr_t hdr{};
	client_fd &dfd = *this->connsockfd;
	std::vector<dtraced_infomsg_t> imsgs(s.sockfds.size(), {0, {0}});

	size_t i = 0;
	{
		std::lock_guard lk(s.sockfdsmtx);
		for (client_fd *cp : s.sockfds) {
			imsgs[i].client_kind = cp->kind;
			memcpy(imsgs[i++].client_name, cp->ident,
			    DTRACED_FDIDENTLEN);
		}
	}

	hdr.msg_type = DTRACED_MSG_INFO;
	hdr.info.count = s.sockfds.size();

	if (!dfd.send(&hdr, DTRACED_MSGHDRSIZE))
		return (false);
	return (dfd.send(&imsgs[0],
	    hdr.info.count * sizeof(dtraced_infomsg_t)));
}

bool
job::read_data(state &s)
{
	using uchar = unsigned char;

	client_fd &dfd = *this->connsockfd;
	dtraced_hdr_t header;

	size_t totalbytes;
	if (!dfd.recv(&totalbytes, sizeof(totalbytes)))
		return (false);

	if (totalbytes < DTRACED_MSGHDRSIZE) {
		ERR("bytes to receive (%zu) < DTRACED_MSGHDRSIZE (%zu)",
		    totalbytes, DTRACED_MSGHDRSIZE);
		return (false);
	}

	std::vector<uchar> buf(totalbytes, 0);

	if (!dfd.recv(&buf[0], totalbytes)) {
		if (dfd.send_nak())
			ERR("send_nak() failed on %s with: %m", dfd.ident);

		if (!dfd.re_enable_read())
			ERR("re_enable_read() failed on %s with: %m",
			    dfd.ident);
		return (false);
	}

	/*
	 * We now have our data (ELF file) in buf. Create an ELF
	 * file in /var/ddtrace/base. This will kick off the
	 * listen thread for process_base.
	 */
	memcpy(&header, &buf[0], DTRACED_MSGHDRSIZE);

	client_request cr(s, header, &buf[DTRACED_MSGHDRSIZE],
	    totalbytes - DTRACED_MSGHDRSIZE);
	if (!cr.handle() && dfd.send_nak() < 0) {
		ERR("send_nak() failed on %s with: %m", dfd.ident);
		return (false);
	} else if (dfd.send_ack() < 0) {
		ERR("send_ack() failed on %s with: %m", dfd.ident);
		return (false);
	}

	/*
	 * We are done receiving the data and nothing failed, re-enable the
	 * event and keep going.
	 */
	LOG("re-enable");
	if (!dfd.re_enable_read()) {
		ERR("re_enable_read() failed with: %m");
		return (false);
	}

	return (true);
}

bool
job::send_cleanup()
{
	dtraced_hdr_t header;
	size_t buflen;
	client_fd &dfd = *this->connsockfd;
	cleanup_job &c = *this->cleanup_get();

	DEBUG("CLEANUP to %s", std::string(dfd).c_str());

	DTRACED_MSG_TYPE(header) = DTRACED_MSG_CLEANUP;
	DTRACED_MSG_NUMENTRIES(header) = c.size();

	if (!dfd.send(&header, DTRACED_MSGHDRSIZE)) {
		if (errno != EPIPE)
			ERR("failed to write to %s: %m", dfd.ident);
		return (false);
	}

	for (std::string &entry : c) {
		buflen = entry.length() + 1;
		if (!dfd.send(&buflen, sizeof(buflen))) {
			if (errno != EPIPE)
				ERR("failed to write to %m: %m", dfd.ident);
			return (false);
		}

		if (!dfd.send(&entry[0], buflen)) {
			if (errno != EPIPE)
				ERR("failed to write to %d: %m", dfd.ident);
			return (false);
		}
	}

	if (!dfd.re_enable_write()) {
		ERR("re_enable_write() failed with: %m");
		return (false);
	}

	return (true);
}

}
