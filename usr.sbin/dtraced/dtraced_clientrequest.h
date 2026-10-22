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

#ifndef _DTRACED_CLIENTREQUEST_H_
#define _DTRACED_CLIENTREQUEST_H_

#include "dtraced.h"

#include <array>
#include <vector>

namespace dtraced {

class state;
class client_fd;

class client_request {
	using uchar = unsigned char;

	state &s;
	uchar *buf;
	size_t buf_size;
	dtraced_hdr_t &hdr;
	client_fd *origin;
	dtraced_delivery_status_t status_reply{};
	bool status_ready = false;
	dtraced_stats_t stats_reply{};
	bool stats_ready = false;
	std::vector<uchar> transfer_reply;
	bool transfer_ready = false;
	uint8_t drain_step_reply = 0;
	bool drain_step_ready = false;
	std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE> release_reply{};
	bool release_ready = false;
	bool release_signed = false;

	bool handle_elfmsg(void);
	bool handle_killmsg(void);
	bool handle_kill_appliedmsg(void);
	bool handle_cleanup_appliedmsg(void);
	bool handle_handoffmsg(void);
	bool handle_session_stopmsg(bool release);
	bool handle_consumer_stop_commit(void);
	bool handle_release_recovery(void);
	bool handle_handoff_importmsg(void);
	bool handle_handoff_release_importmsg(void);
	bool handle_handoff_deliverymsg(bool bind);
	bool handle_handoff_killmsg(bool bind);
	bool handle_handoff_cleanupmsg(void);
	bool handle_cleanupmsg(void);
	bool handle_statsmsg(void);
	bool handle_installedmsg(void);
	bool handle_uninstalledmsg(void);
	bool handle_statusmsg(void);
	bool handle_ingress_statusmsg(void);
	bool handle_consumer_executionmsg(void);
	bool handle_consumer_programmsg(void);

    public:
	client_request() = delete;
	client_request(state &, dtraced_hdr_t &, uchar *, size_t,
	    client_fd * = nullptr);
	~client_request() = default;

	bool handle(void);
	const dtraced_delivery_status_t *status_response(void) const
	{
		return (status_ready ? &status_reply : nullptr);
	}
	const dtraced_stats_t *stats_response(void) const
	{
		return (stats_ready ? &stats_reply : nullptr);
	}
/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
	std::vector<uchar> *transfer_response(void)
	{
		return (transfer_ready ? &transfer_reply : nullptr);
	}
/* HT-C END */
	const uint8_t *drain_step_response(void) const
	{
		return (drain_step_ready ? &drain_step_reply : nullptr);
	}
/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
	const uint8_t *release_response(void) const
	{
		return (release_ready ? release_reply.data() : nullptr);
	}
	bool release_response_signed(void) const { return (release_signed); }
/* HT-C END */
};

}

#endif /* _DTRACED_CLIENTREQUEST_H_ */
