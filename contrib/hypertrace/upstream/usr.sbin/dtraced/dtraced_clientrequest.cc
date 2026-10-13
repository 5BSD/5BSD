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

#include "dtraced.h"
#include "dtraced_clientrequest.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_state.h"

namespace dtraced {

client_request::client_request(state &_s, dtraced_hdr_t &h, uchar *b,
    size_t size)
    : s(_s)
    , buf(b)
    , buf_size(size)
    , hdr(h)
{
}

bool
client_request::handle_elfmsg(void)
{
	dir *dir;
	std::string loc { DTRACED_MSG_LOC(this->hdr) };

	if (loc == "base")
		dir = this->s.basedir;
	else if (loc == "outbound")
		dir = this->s.outbounddir;
	else if (loc == "inbound")
		dir = this->s.inbounddir;
	else {
		ERR("unrecognized location: %s", loc.c_str());
		return (false);
	}

	if (!this->s.is_control_machine()) {
		if (DTRACED_MSG_IDENT_PRESENT(this->hdr)) {
			std::array<char, DTRACED_PROGIDENTLEN> ident;
			std::copy_n(std::begin(DTRACED_MSG_IDENT(this->hdr)),
			    DTRACED_PROGIDENTLEN, std::begin(ident));

			std::lock_guard lk(this->s.identlistmtx);
			this->s.identlist.push_back(std::move(ident));
		}
	}

	DEBUG("write_data(%s, [buf], %zu)", dir->dirpath, buf_size);
	if (!dir->write_data(buf, buf_size)) {
		ERR("write_data() failed");
		return (false);
	}

	return (true);
}

bool
client_request::handle_killmsg(void)
{
	job *j;

	/*
	 * We enqueue a KILL message in the joblist
	 * (another thread will simply pick this up). We
	 * need to only do it for FORWARDERs.
	 */
	std::lock_guard lk(this->s.sockfdsmtx);
	for (client_fd *dfdp : this->s.sockfds) {
		client_fd &dfd = *dfdp;

		if (dfd.kind != DTRACED_KIND_FORWARDER)
			continue;

		if (!dfd.is_subscribed(uint32_t(DTD_SUB_KILL)))
			continue;

		j = new job(KILL, dfdp);
		if (j == nullptr) {
			ERR("new job(KILL, %s) failed: %m", dfdp->ident);
			abort();
		}

		kill_job &k = j->kill_get();
		k.pid = DTRACED_MSG_KILLPID(this->hdr);
		k.vmid = DTRACED_MSG_KILLVMID(this->hdr);

		{
			std::lock_guard lk(this->s.joblistmtx);
			this->s.joblist.push_back(j);
		}

		if (!dfd.re_enable_write()) {
			ERR("re_enable_write() failed with: %m");
			return (false);
		}
	}

	return (true);
}

bool
client_request::handle_cleanupmsg(void)
{
	using vecstr = std::vector<std::string>;

	size_t n_entries, len;
	job *j;

	n_entries = DTRACED_MSG_NUMENTRIES(this->hdr);
	vecstr *p_entries = new vecstr(n_entries, 0);
	if (p_entries == nullptr) {
		ERR("failed to create new vector(%zu, 0)", n_entries);
		abort();
	}

	vecstr &entries = *p_entries;
	std::lock_guard lk(this->s.sockfdsmtx);
	for (client_fd *dfdp : this->s.sockfds) {
		client_fd &dfd = *dfdp;

		if (dfd.kind != DTRACED_KIND_FORWARDER)
			continue;

		if (!dfd.is_subscribed(uint32_t(DTD_SUB_CLEANUP)))
			continue;

		for (size_t i = 0; i < n_entries; i++) {
			if (!dfd.recv(&len, sizeof(len)))
				return (false);

			std::vector<char> buf(len);
			if (!dfd.recv(&buf[0], len))
				return (false);
			buf[len - 1] = '\0';
			entries[i] = std::string(&buf[0]);
		}

		j = new job(CLEANUP, dfdp);
		if (j == nullptr) {
			ERR("failed to create new job(CLEANUP, %s)",
			    dfdp->ident);
			abort();
		}

		// XXX: ugly.
		cleanup_job *&c = j->cleanup_get();
		c = p_entries;
		{
			std::lock_guard _lk(this->s.joblistmtx);
			this->s.joblist.push_back(j);
		}

		if (!dfd.re_enable_write()) {
			ERR("re_enable_write() failed with: %m");
			return (false);
		}
	}

	return (true);
}

bool
client_request::handle(void)
{
	switch (DTRACED_MSG_TYPE(this->hdr)) {
	case DTRACED_MSG_ELF:
		return (this->handle_elfmsg());

	case DTRACED_MSG_KILL:
		return (this->handle_killmsg());

	case DTRACED_MSG_CLEANUP:
		return (this->handle_cleanupmsg());

	default:
		ERR("unknown message: %d", DTRACED_MSG_TYPE(this->hdr));
	}

	return (false);
}
}
