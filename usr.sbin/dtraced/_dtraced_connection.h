/*-
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

#ifndef __DTRACED_CONNECTION_H_
#define __DTRACED_CONNECTION_H_

#include <sys/types.h>

#include "dtraced.h"

#include <atomic>
#include <array>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#define DTRACED_FDIDENTLEN             128ull

namespace dtraced {

struct installed_receipt {
	uint64_t delivery_id;
	uint16_t vmid;
	uint64_t epoch;
	std::array<uint8_t, DTRACED_PROGRAM_ID_LEN> program_id;
	std::array<uint8_t, DTRACED_PROGRAM_ID_LEN> source_id;
};
struct outbound_delivery {
	uint64_t delivery_id;
	std::array<uint8_t, DTRACED_PROGRAM_ID_LEN> program_id;
	std::array<uint8_t, DTRACED_PROGRAM_ID_LEN> source_id;
	uint16_t target_vmid;
	uint64_t target_epoch;
	bool accepted = false;
	bool observed = false;
	bool revoked = false;
	bool retired = false;
	uint64_t observer_connection = 0;
	installed_receipt observation{};
};

class client_fd {
	friend class state;

    protected:
	int kq;			  /* the kqueue this fd belongs to */
	int fd;			  /* the actual filedesc */
	uint64_t subs;		  /* events that efd subscribed to */
	std::atomic_int count {}; /* reference count */
    public:
	client_fd() = delete;
	client_fd(int, int, dtd_initmsg_t);
	~client_fd();
	client_fd(const client_fd &) = delete;
	client_fd &operator=(const client_fd &) = delete;

	std::atomic_bool retired {false};
	/* Protected by state::sockfdsmtx while selecting ELF recipients. */
	bool consumer_replay_pending = false;
	std::atomic_bool consumer_replay_registration_pending{false};
	/* HPI1 from the primary ELF receiver, protected by sockfdsmtx. */
	std::array<uint8_t, 32> consumer_program_digest{};
	bool consumer_program_valid = false;
	/* Set once this connection's HPI registration was answered with
	 * success. Until then the event loop dispatches reads on an ELF
	 * receiver (the registration frame); afterwards its inbound bytes are
	 * delivery acknowledgments read by the sending worker. */
	std::atomic_bool consumer_registration_acked{false};
	std::array<uint8_t, 24> consumer_handle_lifetime{};
	int consumer_process_fd = -1; /* verified birth; PD_DAEMON ownership */
	/* HPI1's activated-import census runs once per admitted connection.
	 * A failed census leaves it retryable; activation queues new work itself. */
	bool consumer_import_scan_active = false;
	bool consumer_import_scan_done = false;
	/* Exact imported recipient jobs must be queued only once across HPI1
	 * census and idempotent activation retries on this connection. */
	std::mutex consumer_import_jobs_mtx;
	std::set<std::array<uint8_t, 48>> consumer_import_queued_receipts;
	uintptr_t event_cookie {0};
	std::mutex output_mtx; /* Serialize complete outbound protocol frames. */
	/* Outbound deliveries and observations expire with this connection. */
	std::mutex installed_mtx;
	std::vector<outbound_delivery> outbound_deliveries;
	bool cleaned_up;		/* has this fd been cleaned up */
	uint64_t id;			/* initiator id */
	int kind;			/* consumer/forwarder */
	char ident[DTRACED_FDIDENTLEN]; /* human-readable identifier */
	std::array<uint8_t, 16> session_id{};
	std::array<uint8_t, 16> consumer_birth{};
	bool consumer_birth_valid = false;
	uid_t peer_uid = (uid_t)-1;
	pid_t peer_pid = -1;
	int vm_attestation_fd = -1;
	int vm_epoch_query_fd = -1; /* Release-only channel, opened before cut. */
	uint16_t vmid = 0;
	uint64_t vm_epoch = 0;
	bool current_vm_attestation(void) const;
	bool same_forwarder(const client_fd &) const;

	void acquire(void);
	void release(void);

	bool enable_read(void *);
	bool enable_write(void *);
	bool enable_rw(void *);
	bool re_enable_read(void);
	bool re_enable_write(void);
	void close(void);
	void shutdown(void);

	int get_fd(void);
	bool is_dead(void);
	/* Caller holds state::deadfdsmtx, which protects cleaned_up. */
	bool can_reap(void);
	bool is_subscribed(unsigned long long);

	bool recv(void *, size_t, int64_t = 0);
	bool send(void *, size_t, int64_t = 0);
	/* Caller must first bind this HPI1 consumer to the durable HCP1 owner. */
	bool request_consumer_drain(const dtraced_consumer_drain_t &);
	/* Caller binds this recipient to the stopped source and closes old
	 * admission. Success proves only this consumer's stop, not whole-session
	 * retirement; no continuity ticket or transfer manifest is required. */
	bool request_consumer_stop(const dtraced_consumer_stop_t &);
	bool respond(bool);
	bool respond_with_status(bool, const dtraced_delivery_status_t *,
	    int64_t = 0);
	bool respond_with_stats(bool, const dtraced_stats_t *, int64_t = 0);
	bool respond_with_transfer(bool, std::vector<uint8_t> *,
	    int64_t = 0);
	bool respond_with_drain_step(bool, const uint8_t *, int64_t = 0);
	bool respond_with_release(bool, const uint8_t *, bool, int64_t = 0);
	ssize_t send_ack(void);
	ssize_t send_nak(void);

	operator std::string(void) const;
};

}

#endif // __DTRACED_CONNECTION_H_
