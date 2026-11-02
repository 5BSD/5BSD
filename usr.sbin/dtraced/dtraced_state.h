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

#ifndef _DTRACED_STATE_H_
#define _DTRACED_STATE_H_

#include <sys/types.h>
#include <sys/param.h>
#include <sys/event.h>

#include <semaphore.h>

#include "_dtraced_connection.h"
#include "dtraced.h"
#include "dtraced_events.h"
#include "dtraced_directory.h"
#include "dtraced_release_keys.h"
#include "dtraced_collector_owner.h"

/* Minimum number of host consumer delivery workers on a control machine. */
#define DTRACED_CONSUMER_DELIVERY_WORKERS 4

#include <array>
#include <condition_variable>
#include <list>
#include <mutex>
#include <queue>
#include <set>
#include <shared_mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace dtraced {

class job;

struct guest_delivery {
	uint64_t delivery_id;
	uint16_t vmid;
	uint64_t epoch;
	std::array<uint8_t, 16> program_id;
	std::array<uint8_t, 16> source_id;
	bool terminal_sent = false;
	bool authorized_current = true;
	bool replay_granted = false;
	std::array<uint8_t, 32> replay_digest{};
	bool query_sent = false;
	/* Rekey changes VMID/epoch but preserves the durable journal key. */
	std::array<uint8_t, 16> journal_session_id{};
	uint8_t journal_version = 3;
	std::array<uint8_t, 32> payload_digest{};
};

/*
 * dtraced state structure. This contains everything relevant to dtraced's
 * state management, such as files that exist, connected sockets, etc.
 */
class state {
	friend struct state_thread_test;
	friend struct state_attestation_test;
	friend struct state_admission_test;
	friend void _broadcast_shutdown(state &, const char *, int);
	const char **argv; /* needed in case we need to re-exec. */
	int ctrlmachine;   /* is this a control machine? */

	bool setup_threads(void);
	bool setup_socket(void);

	bool destroy_socket(void);

	bool dispatch_read(client_fd *, struct kevent &);
	bool dispatch_write(client_fd *, struct kevent &);
	bool handle_event(struct kevent &);

	bool handle_job(job *);
	void run_jobs(bool);

	std::thread inboundtd; /* inbound monitoring thread */
	std::thread basetd;    /* base monitoring thread */

	size_t threadpool_size; /* size of the thread pool (workers) */
	/* thread pool for the joblist; on a control machine as many more, but
	 * at least DTRACED_CONSUMER_DELIVERY_WORKERS, deliver ELF to host
	 * consumers (process_consumer_deliveries()) */
	std::vector<std::thread> workers;

	std::thread socktd; /* config socket thread */
	int sockfd;	    /* config socket filedesc */
	std::mutex socket_start_mtx;
	std::condition_variable socket_start_cv;
	bool socket_start_done = false;
	int socket_start_error = 0;
	unsigned directory_start_done = 0;
	int directory_start_error = 0;

	std::thread dtt_listentd; /* read() on dtt_fd */
	std::thread dtt_writetd;  /* write() on dtt_fd */
    public:

	dir *inbounddir;  /* /var/ddtrace/inbound */
	dir *outbounddir; /* /var/ddtrace/outbound */
	dir *basedir;	  /* /var/ddtrace/base */
	release_keys handoff_keys; /* configured host credential and pinned peer */

	/*
	 * Sockets.
	 */
	std::mutex sockfdsmtx;
	/* Keep kqueue dispatch out of a partially registered client. */
	std::mutex admission_register_mtx;
	std::unordered_set<client_fd *> sockfds;
	collector_owner_registry collector_owners;
	event_registry client_events;
	/* Serializes kill publication, subscriber replay, and observations. */
	std::mutex revocationmtx;

	/*
	 * Configuration socket.
	 */
	std::mutex sockmtx; /* config socket mutex */
	sem_t socksema;	    /* config socket semaphore */
	bool socksema_initialized = false;

	/*
	 * dttransport fd and threads
	 */
	int dtt_fd;		  /* dttransport filedesc */

	/*
	 * Thread pool management.
	 */
	std::mutex joblistmtx; /* joblist mutex */
	std::list<job *> joblist;
	std::mutex dispatched_jobsmtx; /* dispatched joblist mutex */

	/* jobs to be picked up by the workers */
	std::list<job *> dispatched_jobs;
	std::condition_variable
	    dispatched_jobscv; /* dispatched joblist condvar */

	/*
	 * Children management.
	 */
	std::thread killtd; /* handle sending kill(SIGTERM) to the guest */
	std::mutex killmtx; /* mutex of the kill list */
	struct pending_kill {
		pid_t pid;
		std::array<uint8_t, 16> source_id;
	};
	std::queue<pending_kill> pids_to_kill;
	std::condition_variable killcv; /* kill list condvar */
	std::thread reaptd;		/* handle reaping children */

	std::unordered_set<pid_t> pidlist; /* a list of pids running */
	std::unordered_map<pid_t, std::array<uint8_t, 16>> pid_sources;
	std::unordered_map<pid_t, guest_delivery> pid_deliveries;
	std::unordered_map<pid_t, int> pidfds; /* procdesc closes on daemon death */
	std::set<std::array<uint8_t, 16>> revoked_sources;
	std::timed_mutex pidlistmtx;	   /* bounded session-stop acquisition */
	/* Cleanup closes admission and waits for in-flight launches before it
	 * snapshots pidlist. A rejected launch's owned_child waits for exit. */
	std::shared_timed_mutex launch_gate;
	std::atomic_bool cleanup_in_progress{false};
	std::mutex install_event_mtx; /* orders install and child exit events */

	/*
	 * filedesc management.
	 */
	/* dead file descriptor list (to close) */
	std::unordered_set<client_fd *> deadfds;
	std::mutex deadfdsmtx; /* mutex for deadfds */
	std::condition_variable deadfdscv;
	uint64_t deadfds_generation = 0; /* guarded by deadfdsmtx */
	std::thread closetd;   /* file descriptor closing thread */

	std::condition_variable jobcleancv; /* job cleaning thread condvar */
	std::thread jobcleantd;		    /* job cleaning thread */

	/*
	 * Consumer threads
	 */
	std::thread consumer_listentd; /* handle consumer messages */
	std::thread consumer_writetd;  /* send messages to consumers */

	std::atomic_int shutdown; /* shutdown flag */
	int nosha;		  /* do we want to checksum? */
	int kq_hdl = -1;	  /* event loop kqueue */

	std::list<std::array<char, DTRACED_PROGIDENTLEN>> identlist;
	std::mutex identlistmtx; /* mutex protecting the ident list */
	/* Volatile authorization-free context for current daemon deliveries only. */
	std::mutex deliverymtx;
	std::vector<guest_delivery> guest_deliveries;
	std::mutex host_ingress_mtx; /* serialize one host guest-ELF token transaction */
	/* One guest outbound writer waits for the matching host ELF receipt. */
	std::mutex host_elf_mtx;
	std::condition_variable host_elf_cv;
	uint64_t host_elf_waiting = 0;
	std::array<uint8_t, 16> host_elf_program{};
	std::array<uint8_t, 16> host_elf_source{};
	std::array<uint8_t, 32> host_elf_digest{};
	bool host_elf_accepted = false;
	/* Serialize guest VM-identity requests; only bhyve supplies the epoch. */
	std::mutex vm_identity_request_mtx;
	std::mutex vm_identity_mtx;
	std::condition_variable vm_identity_cv;
	uint64_t vm_identity_query_id = 0;
	uint16_t vm_identity_vmid = 0;
	uint64_t vm_identity_epoch = 0;
	bool vm_identity_ready = false;

	state() = default;
	~state() = default;

	bool initialize(int, int, int, const char **,
	    const char *release_private_path = nullptr,
	    const char *release_peer_path = nullptr);
	bool finalize(void);
	void report_directory_start(int);
	[[noreturn]] void re_exec(void);
	bool is_control_machine(void);
	bool query_vm_identity(uint16_t &, uint64_t &);

	bool accept_new_connection(void);
	bool queue_replay_kills(client_fd *);
	bool queue_replay_cleanups(client_fd *);
	bool collect_replay_kills(client_fd *, std::vector<durable_kill> &);
	bool wake_handoff_source(const client_fd &);
	void retire_handoff_consumers(uint16_t, uint64_t);
	/* -1 unresolved/error, 0 all discovered owners proven stopped,
	 * 1 one new collector stop was durably recorded. */
	bool recover_collector_owners(
	    const std::vector<durable_consumer_receipt_state> &);
	int stop_fresh_session_step(const durable_session_stop &);
	bool recover_outbound_deliveries(client_fd *);
	bool queue_claimed_source_journal_replays(client_fd *);
	/* Requeue exact pending HTD5s only after forwarder admission. */
	/* Internal event dispatcher; exposed for failure-injection qualification. */
	bool dispatch_event(struct kevent &);
	void process_consumers(void);
	void process_joblist(void);
	void process_consumer_deliveries(void);
	void close_filedescs(void);
	void manage_children(void);
	void reap_children(void);
	void clean_jobs(void);

	int socket(void);

	void kill_socket(client_fd *);

	bool send_info_async(client_fd *);
};

void _broadcast_shutdown(state &, const char *, int);
#define broadcast_shutdown(_a) _broadcast_shutdown((_a), __FILE__, __LINE__)

}

#endif // _DTRACED_STATE_H_
