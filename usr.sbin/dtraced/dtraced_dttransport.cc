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
#include <sys/hypertrace.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/procdesc.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <assert.h>
#include <dttransport.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <poll.h>
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
#include "dtraced_io.h"
#include "dtraced_wire.h"
#include "dtraced_elf.h"
#include "dtraced_process.h"
#include "dtraced_child_ledger.h"
#include "dtraced_socket.h"
#include <algorithm>
#include <chrono>
#include <map>
#include <memory>
#include <new>

#include <atomic>

namespace dtraced {

struct dtt_elf_state {
	hypertrace_elf elf{};
	uint64_t delivery_id{};
	uint16_t vmid{};
	uint64_t epoch{};
	uint8_t program_id[16]{};
	uint8_t source_id[16]{};
	~dtt_elf_state() { hypertrace_elf_reset(&elf); }
};

static bool
dtt_elf(state *s, dtt_elf_state &assembly, const dtt_entry_t *e)
{
	int complete, error;

	if (e->u.elf.len > sizeof(e->u.elf.data))
		return (false);
	const uint8_t zero_id[16] = {};
	if (memcmp(e->u.elf.program_id, zero_id, 16) == 0 ||
	    memcmp(e->u.elf.source_id, zero_id, 16) == 0 ||
	    e->u.elf.delivery_id == 0 || e->u.elf.vmid == 0 ||
	    e->u.elf.vmid >= HYPERTRACE_MAX_VMS || e->u.elf.epoch == 0)
		return (false);
	if (assembly.elf.data == nullptr) {
		assembly.delivery_id = e->u.elf.delivery_id;
		assembly.vmid = e->u.elf.vmid;
		assembly.epoch = e->u.elf.epoch;
		memcpy(assembly.program_id, e->u.elf.program_id, 16);
		memcpy(assembly.source_id, e->u.elf.source_id, 16);
	} else if (assembly.delivery_id != e->u.elf.delivery_id ||
	    assembly.vmid != e->u.elf.vmid ||
	    assembly.epoch != e->u.elf.epoch ||
	    memcmp(assembly.program_id, e->u.elf.program_id, 16) != 0)
		return (false);
	else if (memcmp(assembly.source_id, e->u.elf.source_id, 16) != 0)
		return (false);
	error = hypertrace_elf_append(&assembly.elf, e->u.elf.identifier,
	    e->u.elf.totallen, e->u.elf.data, e->u.elf.len,
	    e->u.elf.hasmore, &complete);
	if (error != 0) {
		ERR("invalid or unallocatable ELF fragment (%d)", error);
		return (false);
	}
	if (!complete)
		return (true);
	if (assembly.elf.total < 4 || memcmp(assembly.elf.data, "\177ELF", 4) != 0)
		return (false);
	guest_delivery delivery{};
	delivery.delivery_id = assembly.delivery_id;
	delivery.vmid = assembly.vmid;
	delivery.epoch = assembly.epoch;
	memcpy(delivery.program_id.data(), assembly.program_id, 16);
	memcpy(delivery.source_id.data(), assembly.source_id, 16);
	delivery.journal_version = 4;
	if (SHA256(assembly.elf.data, assembly.elf.total,
	    delivery.payload_digest.data()) == nullptr)
		return (false);
	bool created = false, duplicate_token = false;
	{
		std::lock_guard lock(s->deliverymtx);
		size_t index = 0;
		while (index < s->guest_deliveries.size() &&
		    s->guest_deliveries[index].program_id != delivery.program_id)
			++index;
		bool existing = index < s->guest_deliveries.size();
		guest_delivery previous{};
		if (existing) {
			previous = s->guest_deliveries[index];
			if (previous.source_id != delivery.source_id) {
				errno = EEXIST;
				return (false);
			}
			duplicate_token = previous.delivery_id == delivery.delivery_id &&
			    previous.vmid == delivery.vmid &&
			    previous.epoch == delivery.epoch;
			if (!previous.authorized_current) {
				/* A fresh token cannot replace a recovered transaction.
				 * An exact retry of the recovered token is still pending
				 * the host status query, not an uninstall. */
				if (duplicate_token) {
					if (previous.terminal_sent) {
						if (!send_uninstall_observation(s->dtt_fd,
						    previous))
							return (false);
					} else if (!s->inbounddir->write_identified_data(
					    assembly.elf.data, assembly.elf.total,
					    assembly.program_id, &created,
					    assembly.source_id))
						return (false);
				} else if (!send_uninstall_observation(s->dtt_fd,
				    delivery))
					return (false);
				hypertrace_elf_reset(&assembly.elf);
				assembly.delivery_id = 0;
				assembly.vmid = 0;
				assembly.epoch = 0;
				memset(assembly.program_id, 0, 16);
				memset(assembly.source_id, 0, 16);
				return (true);
			}
			if (duplicate_token)
				delivery.journal_session_id =
				    previous.journal_session_id;
			s->guest_deliveries[index] = delivery;
		} else {
			if (s->guest_deliveries.size() >= 16384) {
				errno = ENOSPC;
				return (false);
			}
			try {
				s->guest_deliveries.push_back(delivery);
			} catch (const std::bad_alloc &) {
				errno = ENOMEM;
				return (false);
			}
		}
		bool published = s->inbounddir->write_identified_data(
		    assembly.elf.data, assembly.elf.total, assembly.program_id,
		    &created, assembly.source_id);
		if (published && created)
			published = s->inbounddir->record_delivery(
			    guest_delivery_record(delivery), delivery_phase::pending,
			    true);
		if (!published || !created) {
			int saved = errno;
			if (existing)
				s->guest_deliveries[index] = previous;
			else
				s->guest_deliveries.pop_back();
			if (!published) {
				errno = saved;
				return (false);
			}
		}
	}
	/* An existing artifact cannot produce a fresh installation receipt. */
	if (!created && !duplicate_token &&
	    !send_uninstall_observation(s->dtt_fd, delivery))
		return (false);
	hypertrace_elf_reset(&assembly.elf);
	assembly.delivery_id = 0;
	assembly.vmid = 0;
	assembly.epoch = 0;
	memset(assembly.program_id, 0, 16);
	memset(assembly.source_id, 0, 16);
	return (true);
}

static bool
dtt_host_elf(state *s, const dtt_entry_t *e)
{
	const uint8_t zero_id[16] = {};
	if (e->u.installed.delivery_id == 0 || e->u.installed.vmid == 0 ||
	    e->u.installed.vmid >= HYPERTRACE_MAX_VMS ||
	    e->u.installed.epoch == 0 ||
	    memcmp(e->u.installed.program_id, zero_id, 16) == 0 ||
	    memcmp(e->u.installed.source_id, zero_id, 16) == 0 ||
	    e->u.installed.phase != 0 || e->u.installed.revoked != 0 ||
	    e->u.installed.replay != 0 || e->u.installed.query_id != 0 ||
	    memcmp(e->u.installed.digest, (const uint8_t[32]){0}, 32) == 0) {
		errno = EPROTO;
		return (false);
	}
	std::lock_guard lock(s->host_elf_mtx);
	if (s->host_elf_waiting != e->u.installed.delivery_id)
		return (true); /* A late receipt cannot release another sender. */
	if (memcmp(s->host_elf_program.data(), e->u.installed.program_id,
	    16) != 0 || memcmp(s->host_elf_source.data(),
	    e->u.installed.source_id, 16) != 0 ||
	    memcmp(s->host_elf_digest.data(), e->u.installed.digest, 32) != 0) {
		errno = EPROTO;
		return (false);
	}
	s->host_elf_accepted = true;
	s->host_elf_cv.notify_all();
	return (true);
}

static bool
dtt_kill(state *s, dtt_entry_t *e)
{
	const uint8_t zero_id[16] = {};
	if (e->u.kill.pid <= 1 || e->u.kill.vmid == 0 ||
	    e->u.kill.vmid >= HYPERTRACE_MAX_VMS ||
	    e->u.kill.epoch == 0 ||
	    memcmp(e->u.kill.source_id, zero_id, 16) == 0) {
		errno = EPROTO;
		return (false);
	}
	durable_kill record{};
	record.pid = e->u.kill.pid;
	record.vmid = e->u.kill.vmid;
	record.epoch = e->u.kill.epoch;
	memcpy(record.source_id.data(), e->u.kill.source_id, 16);
	if (s->inbounddir == nullptr ||
	    !s->inbounddir->record_kill(record) ||
	    !s->inbounddir->revoke_source(e->u.kill.source_id))
		return (false);
	try {
		state::pending_kill request{e->u.kill.pid, {}};
		memcpy(request.source_id.data(), e->u.kill.source_id, 16);
		/* Match the install/reap ordering while revoking launch authority. */
		std::lock_guard events(s->install_event_mtx);
		{
			std::lock_guard children(s->pidlistmtx);
			s->revoked_sources.insert(request.source_id);
		}
		{
			std::lock_guard deliveries(s->deliverymtx);
			for (auto &delivery : s->guest_deliveries) {
				if (delivery.source_id != request.source_id)
					continue;
				delivery.authorized_current = false;
				bool active = false;
				{
					std::lock_guard children(s->pidlistmtx);
					for (const auto &[pid, child] : s->pid_deliveries)
						if (s->pidlist.count(pid) != 0 &&
						    child.delivery_id == delivery.delivery_id &&
						    child.vmid == delivery.vmid &&
						    child.epoch == delivery.epoch &&
						    child.program_id == delivery.program_id &&
						    child.source_id == delivery.source_id) {
							active = true;
							break;
						}
				}
				if (!active) {
					if (!s->inbounddir->record_delivery(
					    guest_delivery_record(delivery),
					    delivery_phase::exited) ||
					    !send_uninstall_observation(s->dtt_fd, delivery))
						return (false);
					delivery.terminal_sent = true;
				}
			}
		}
		std::lock_guard lk(s->killmtx);
		s->pids_to_kill.push(request);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	s->killcv.notify_all();
	return (true);
}

static durable_kill
kill_record(const dtt_entry_t &e)
{
	durable_kill record{};
	record.pid = e.u.kill.pid;
	record.vmid = e.u.kill.vmid;
	record.epoch = e.u.kill.epoch;
	memcpy(record.source_id.data(), e.u.kill.source_id, 16);
	return (record);
}

static bool
send_kill_applied(int fd, const durable_kill &record)
{
	dtt_entry_t ack{};
	ack.event_kind = DTT_KILL_APPLIED;
	ack.u.kill.pid = record.pid;
	ack.u.kill.vmid = record.vmid;
	ack.u.kill.epoch = record.epoch;
	memcpy(ack.u.kill.source_id, record.source_id.data(), 16);
	ssize_t written;
	do {
		written = write(fd, &ack, sizeof(ack));
	} while (written < 0 && errno == EINTR);
	if (written != (ssize_t)sizeof(ack)) {
		if (written >= 0)
			errno = EIO;
		return (false);
	}
	return (true);
}

template <class Mutex>
static bool
dtt_stop_lock(std::unique_lock<Mutex> &lock, int64_t deadline)
{
	int64_t now = dtraced_io_milliseconds();
	if (now < 0)
		return (false);
	if (now >= deadline ||
	    !lock.try_lock_for(std::chrono::milliseconds(deadline - now))) {
		errno = ETIMEDOUT;
		return (false);
	}
	return (true);
}

bool
quiesce_guest_tracing(state *s, int64_t deadline)
{
	if (s == nullptr || deadline < 0) {
		errno = EINVAL;
		return (false);
	}
	/* No new tracing child may start after this point. Wait for launches
	 * already in flight: they either join pidlist or their owned_child
	 * destructor kills and waits for them before dropping the shared gate. */
	s->cleanup_in_progress.store(true);
	s->host_elf_cv.notify_all();
	std::unique_lock launch_gate(s->launch_gate, std::defer_lock);
	if (!dtt_stop_lock(launch_gate, deadline))
		return (false);
	{
		std::unique_lock lk(s->pidlistmtx, std::defer_lock);
		if (!dtt_stop_lock(lk, deadline))
			return (false);
		/* Verify all child capabilities before signaling any child. A PID
		 * alone must never become authority to kill a recycled process. */
		for (pid_t pid : s->pidlist) {
			auto owned = s->pidfds.find(pid);
			if (pid <= 1 || owned == s->pidfds.end()) {
				errno = EPROTO;
				ERR("traced child %d has no process descriptor: %m",
				    pid);
				return (false);
			}
		}
		for (pid_t pid : s->pidlist) {
			auto owned = s->pidfds.find(pid);
			WARN("SIGKILL traced child %d", pid);
			if (pdkill(owned->second, SIGKILL) != 0 && errno != ESRCH) {
				ERR("cannot stop traced child %d: %m", pid);
				return (false);
			}
		}
		/* A stopped session must have no executing tracing children. Poll
		 * with the same deadline used for admission and registry locks;
		 * the reaper cannot remove descriptors while this lock is held. */
		for (pid_t pid : s->pidlist) {
			int fd = s->pidfds.find(pid)->second;
			struct pollfd ready = {fd, POLLHUP, 0};
			for (;;) {
				int64_t now = dtraced_io_milliseconds();
				if (now < 0 || now >= deadline) {
					if (now >= deadline)
						errno = ETIMEDOUT;
					ERR("timed out stopping traced child %d: %m",
					    pid);
					return (false);
				}
				int result = poll(&ready, 1, (int)(deadline - now));
				if (result < 0 && errno == EINTR)
					continue;
				if (result < 0 || (ready.revents &
				    (POLLERR | POLLNVAL)) != 0) {
					if (result >= 0)
						errno = EIO;
					ERR("cannot wait for traced child %d: %m",
					    pid);
					return (false);
				}
				if (result > 0 &&
				    (ready.revents & POLLHUP) != 0)
					break;
			}
			int status;
			if (pdwait(fd, &status, WEXITED, nullptr, nullptr) != 0 &&
			    errno != ESRCH) {
				ERR("cannot reap traced child %d: %m", pid);
				return (false);
			}
			if (s->inbounddir == nullptr ||
			    !retire_guest_child(s->inbounddir->dirfd, pid)) {
				ERR("cannot retire traced child %d: %m", pid);
				return (false);
			}
		}
	}
	int64_t now = dtraced_io_milliseconds();
	if (now < 0)
		return (false);
	if (now >= deadline) {
		errno = ETIMEDOUT;
		return (false);
	}
	return (true);
}

static void
dtt_cleanup(state *s, const dtt_entry_t *cleanup_event = nullptr)
{
	int64_t deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0 || !quiesce_guest_tracing(s, deadline)) {
		broadcast_shutdown(*s);
		return;
	}

	if (cleanup_event != nullptr) {
		dtt_entry_t applied{};
		applied.event_kind = DTT_CLEANUP_APPLIED;
		applied.u.cleanup = cleanup_event->u.cleanup;
		ssize_t written;
		do {
			written = write(s->dtt_fd, &applied, sizeof(applied));
		} while (written < 0 && errno == EINTR);
		if (written != (ssize_t)sizeof(applied)) {
			if (written >= 0)
				errno = EIO;
			ERR("cannot report applied cleanup: %m");
			broadcast_shutdown(*s);
			return;
		}
	}
	/* Re-exec ourselves to ensure full cleanup. The driver retries the exact
	 * applied report until the host acknowledges its durable journal write. */
	WARN("re-execing");
	s->re_exec();
}

static void
dtt_cleanup_event(state *s, const dtt_entry_t &event)
{
	dtt_vm_identity identity{};
	if (event.event_kind != DTT_CLEANUP_DTRACED ||
	    event.u.cleanup.delivery_id == 0 ||
	    event.u.cleanup.vmid == 0 ||
	    event.u.cleanup.vmid >= HYPERTRACE_MAX_VMS ||
	    event.u.cleanup.epoch == 0 ||
	    ioctl(s->dtt_fd, DTT_GET_VM_IDENTITY, &identity) != 0 ||
	    (identity.flags != 0 && identity.flags != DTT_IDENTITY_FRESH_ACTIVE) ||
	    identity.vmid != event.u.cleanup.vmid ||
	    identity.epoch != event.u.cleanup.epoch) {
		errno = EPROTO;
		broadcast_shutdown(*s);
		return;
	}
	dtt_cleanup(s, &event);
}

/* A fresh-session stop does not rekey or replay journals. The driver owns
 * the stop token and remains fenced after accepting the exact proof. */
static bool
dtt_session_stop_event(state *s, const dtt_entry_t &event)
{
	dtt_vm_identity identity{};
	dtt_cleanup_state stop{};
	if (event.event_kind != DTT_SESSION_STOP ||
	    event.u.cleanup.delivery_id == 0 ||
	    event.u.cleanup.vmid == 0 ||
	    event.u.cleanup.vmid >= HYPERTRACE_MAX_VMS ||
	    event.u.cleanup.epoch == 0 ||
	    ioctl(s->dtt_fd, DTT_GET_VM_IDENTITY, &identity) != 0 ||
	    ioctl(s->dtt_fd, DTT_GET_CLEANUP_STATE, &stop) != 0 ||
	    (identity.flags != 0 && identity.flags != DTT_IDENTITY_FRESH_ACTIVE) ||
	    identity.vmid != event.u.cleanup.vmid ||
	    identity.epoch != event.u.cleanup.epoch || stop.reserved != 0 ||
	    (stop.flags != (DTT_CLEANUP_STATE_PENDING |
	    DTT_CLEANUP_STATE_SESSION_STOP) &&
	    stop.flags != (DTT_CLEANUP_STATE_PENDING |
	    DTT_CLEANUP_STATE_SESSION_STOP | DTT_CLEANUP_STATE_APPLIED)) ||
	    stop.delivery_id != event.u.cleanup.delivery_id ||
	    stop.vmid != event.u.cleanup.vmid ||
	    stop.epoch != event.u.cleanup.epoch) {
		errno = EPROTO;
		return (false);
	}
	int64_t deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0 || !quiesce_guest_tracing(s, deadline))
		return (false);
	dtt_entry_t stopped{};
	stopped.event_kind = DTT_SESSION_STOPPED;
	stopped.u.cleanup = event.u.cleanup;
	for (;;) {
		int64_t now = dtraced_io_milliseconds();
		if (now < 0)
			return (false);
		if (now >= deadline) {
			errno = ETIMEDOUT;
			return (false);
		}
		ssize_t written = write(s->dtt_fd, &stopped, sizeof(stopped));
		if (written < 0 && errno == EINTR)
			continue;
		if (written == (ssize_t)sizeof(stopped))
			return (true);
		if (written >= 0)
			errno = EIO;
		return (false);
	}
}

static bool
send_next_recovery_query(state *s, guest_delivery &outstanding,
    bool &waiting, int64_t &deadline, uint64_t &query_id,
    uint64_t &query_counter)
{
	std::lock_guard deliveries(s->deliverymtx);
	for (auto &delivery : s->guest_deliveries) {
		if (delivery.authorized_current || delivery.query_sent)
			continue;
		if (++query_counter == 0)
			++query_counter;
		deadline = dtraced_io_deadline_after(10000);
		if (deadline < 0)
			return (false);
		if (!send_status_query(s->dtt_fd, delivery, query_counter))
			return (false);
		delivery.query_sent = true;
		outstanding = delivery;
		query_id = query_counter;
		waiting = true;
		return (true);
	}
	waiting = false;
	return (true);
}

static bool
send_outbound_ingress_query(state *s, const durable_delivery &record,
    uint64_t query_id)
{
	if (s->dtt_fd < 0 || record.scope != 2 ||
	    record.journal_version != 4 || record.delivery_id == 0 ||
	    query_id == 0) {
		errno = EINVAL;
		return (false);
	}
	dtt_entry_t query{};
	query.event_kind = DTT_INGRESS_STATUS;
	query.u.installed.delivery_id = record.delivery_id;
	query.u.installed.query_id = query_id;
	memcpy(query.u.installed.program_id, record.program_id.data(), 16);
	memcpy(query.u.installed.source_id, record.source_id.data(), 16);
	ssize_t written;
	do {
		written = write(s->dtt_fd, &query, sizeof(query));
	} while (written < 0 && errno == EINTR);
	if (written != (ssize_t)sizeof(query)) {
		if (written >= 0)
			errno = EIO;
		return (false);
	}
	return (true);
}

bool
state::query_vm_identity(uint16_t &vmid, uint64_t &epoch)
{
	if (this->is_control_machine() || this->dtt_fd < 0) {
		errno = EINVAL;
		return (false);
	}
	std::lock_guard request(this->vm_identity_request_mtx);
	dtt_entry_t query{};
	query.event_kind = DTT_VM_IDENTITY_QUERY;
	do {
		arc4random_buf(&query.u.installed.query_id,
		    sizeof(query.u.installed.query_id));
	} while (query.u.installed.query_id == 0);
	int64_t now = dtraced_io_milliseconds();
	if (now < 0)
		return (false);
	int64_t deadline = dtraced_io_deadline_from(now, 10000);
	if (deadline < 0)
		return (false);
	{
		std::lock_guard identity(this->vm_identity_mtx);
		this->vm_identity_query_id = query.u.installed.query_id;
		this->vm_identity_ready = false;
	}
	for (;;) {
		if (this->shutdown.load()) {
			errno = ECANCELED;
			break;
		}
		now = dtraced_io_milliseconds();
		if (now < 0)
			break;
		if (now >= deadline) {
			errno = ETIMEDOUT;
			break;
		}
		ssize_t written = write(this->dtt_fd, &query, sizeof(query));
		if (written == (ssize_t)sizeof(query)) {
			std::unique_lock identity(this->vm_identity_mtx);
			now = dtraced_io_milliseconds();
			if (now < 0)
				break;
			int64_t remaining = deadline - now;
			if (remaining <= 0) {
				errno = ETIMEDOUT;
				break;
			}
			bool received = this->vm_identity_cv.wait_for(identity,
			    std::chrono::milliseconds(remaining), [&] {
				return (this->vm_identity_ready ||
				    this->shutdown.load());
			    });
			if (received && this->vm_identity_ready &&
			    !this->shutdown.load()) {
				vmid = this->vm_identity_vmid;
				epoch = this->vm_identity_epoch;
				this->vm_identity_query_id = 0;
				this->vm_identity_ready = false;
				return (true);
			}
			errno = this->shutdown.load() ? ECANCELED : ETIMEDOUT;
			break;
		}
		if (written < 0 && (errno == EINTR || errno == EAGAIN ||
		    errno == ENOBUFS)) {
			usleep(DTRACED_SLEEPTIME);
			continue;
		}
		if (written >= 0)
			errno = EIO;
		break;
	}
	std::lock_guard identity(this->vm_identity_mtx);
	this->vm_identity_query_id = 0;
	this->vm_identity_ready = false;
	return (false);
}

static bool
send_next_outbound_ingress_query(state *s,
    const std::vector<durable_delivery> &pending, size_t index,
    bool &waiting, int64_t &deadline, uint64_t &query_id,
    uint64_t &query_counter)
{
	if (index == pending.size()) {
		waiting = false;
		return (true);
	}
	if (++query_counter == 0)
		++query_counter;
	deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0)
		return (false);
	if (!send_outbound_ingress_query(s, pending[index], query_counter))
		return (false);
	query_id = query_counter;
	waiting = true;
	return (true);
}

bool
query_guest_rekey_receipt(int fd, uint8_t kind, uint16_t old_vmid,
    uint64_t old_epoch, uint16_t new_vmid, uint64_t new_epoch,
    uint64_t delivery_id, const uint8_t program_id[16],
    const uint8_t source_id[16], const uint8_t payload_digest[32],
    bool terminal_ok, int64_t deadline)
{
	const uint8_t zero16[16] = {}, zero32[32] = {};
	bool kill = kind == DTT_REKEY_KILL_QUERY;
	uint8_t expected = kind == DTT_REKEY_DELIVERY_QUERY ?
	    DTT_REKEY_DELIVERY_RECEIPT :
	    kind == DTT_REKEY_INGRESS_QUERY ?
	    DTT_REKEY_INGRESS_RECEIPT : DTT_REKEY_KILL_RECEIPT;
	dtt_entry_t query{}, reply{};
	bool saw_rekey_notice = false;
	ssize_t count;
	int64_t now;

	if (fd < 0 || (kind != DTT_REKEY_DELIVERY_QUERY &&
	    kind != DTT_REKEY_INGRESS_QUERY &&
	    kind != DTT_REKEY_KILL_QUERY) || old_vmid == 0 ||
	    (terminal_ok && kind != DTT_REKEY_DELIVERY_QUERY) ||
	    old_vmid >= HYPERTRACE_MAX_VMS || old_epoch == 0 ||
	    new_vmid == 0 || new_vmid >= HYPERTRACE_MAX_VMS ||
	    new_epoch == 0 || (old_vmid == new_vmid &&
	    old_epoch == new_epoch) || delivery_id == 0 ||
	    program_id == nullptr || source_id == nullptr ||
	    payload_digest == nullptr ||
	    memcmp(source_id, zero16, 16) == 0 ||
	    (kill ? (delivery_id <= 1 || delivery_id > INT32_MAX ||
	    memcmp(program_id, zero16, 16) != 0 ||
	    memcmp(payload_digest, zero32, 32) != 0) :
	    (memcmp(program_id, zero16, 16) == 0 ||
	    memcmp(payload_digest, zero32, 32) == 0))) {
		errno = EINVAL;
		return (false);
	}
	query.event_kind = kind;
	query.u.installed.delivery_id = delivery_id;
	query.u.installed.vmid = old_vmid;
	query.u.installed.epoch = old_epoch;
	memcpy(query.u.installed.program_id, program_id, 16);
	memcpy(query.u.installed.source_id, source_id, 16);
	memcpy(query.u.installed.digest, payload_digest, 32);
	do {
		arc4random_buf(&query.u.installed.query_id,
		    sizeof(query.u.installed.query_id));
	} while (query.u.installed.query_id == 0);
	for (;;) {
		now = dtraced_io_milliseconds();
		if (now < 0)
			return (false);
		if (now >= deadline) {
			errno = ETIMEDOUT;
			return (false);
		}
		count = write(fd, &query, sizeof(query));
		if (count == (ssize_t)sizeof(query))
			break;
		if (count < 0 && (errno == EINTR || errno == EAGAIN ||
		    errno == ENOBUFS || errno == EBUSY)) {
			usleep(DTRACED_SLEEPTIME);
			continue;
		}
		if (count >= 0)
			errno = EIO;
		return (false);
	}
	for (;;) {
		now = dtraced_io_milliseconds();
		if (now < 0)
			return (false);
		if (now >= deadline) {
			errno = ETIMEDOUT;
			return (false);
		}
		count = read(fd, &reply, sizeof(reply));
		if (count < 0 && (errno == EINTR || errno == EAGAIN ||
		    errno == EWOULDBLOCK)) {
			usleep(DTRACED_SLEEPTIME);
			continue;
		}
		if (count != (ssize_t)sizeof(reply)) {
			if (count >= 0)
				errno = EPROTO;
			return (false);
		}
		/* A daemon restarted after NODE_REKEY may still have the priority
		 * notice queued. It names only the new incarnation. */
		if (reply.event_kind == DTT_VM_REKEY && !saw_rekey_notice &&
		    reply.u.installed.vmid == new_vmid &&
		    reply.u.installed.epoch == new_epoch) {
			saw_rekey_notice = true;
			continue;
		}
		/* Repeated predecessor crashes can leave several driver-validated
		 * replies. Discard only old-incarnation replies for other nonces;
		 * the fixed deadline still bounds the drain. Re-query each durable
		 * record rather than using an orphan response as authority. */
		if ((reply.event_kind == DTT_REKEY_DELIVERY_RECEIPT ||
		    reply.event_kind == DTT_REKEY_INGRESS_RECEIPT ||
		    reply.event_kind == DTT_REKEY_KILL_RECEIPT) &&
		    reply.u.installed.vmid == old_vmid &&
		    reply.u.installed.epoch == old_epoch &&
		    reply.u.installed.query_id != 0 &&
		    reply.u.installed.query_id != query.u.installed.query_id &&
		    reply.u.installed.delivery_id != 0 &&
		    memcmp(reply.u.installed.source_id, zero16, 16) != 0 &&
		    reply.u.installed.replay == 0) {
			continue;
		}
		if (reply.event_kind != expected ||
		    reply.u.installed.delivery_id != delivery_id ||
		    reply.u.installed.vmid != old_vmid ||
		    reply.u.installed.epoch != old_epoch ||
		    reply.u.installed.query_id != query.u.installed.query_id ||
		    memcmp(reply.u.installed.program_id, program_id, 16) != 0 ||
		    memcmp(reply.u.installed.source_id, source_id, 16) != 0 ||
		    reply.u.installed.replay != 0) {
			errno = EPROTO;
			return (false);
		}
		if (reply.u.installed.phase == 'u' &&
		    reply.u.installed.revoked == 0 &&
		    memcmp(reply.u.installed.digest, zero32, 32) == 0) {
			errno = EAGAIN;
			return (false);
		}
		if (reply.u.installed.phase == 't') {
			if (!terminal_ok ||
			    reply.u.installed.revoked > 1 ||
			    memcmp(reply.u.installed.digest, zero32, 32) != 0) {
				errno = EPROTO;
				return (false);
			}
			return (true);
		}
		if (kill ?
		    ((reply.u.installed.phase != 'p' &&
		    reply.u.installed.phase != 'a') ||
		    reply.u.installed.revoked != 1 ||
		    memcmp(reply.u.installed.digest, zero32, 32) != 0) :
		    ((kind == DTT_REKEY_INGRESS_QUERY ?
		    reply.u.installed.phase != 'a' :
		    (reply.u.installed.phase != 'a' &&
		    reply.u.installed.phase != 'i')) ||
		    reply.u.installed.revoked != 0 ||
		    memcmp(reply.u.installed.digest, payload_digest, 32) != 0)) {
			errno = EPROTO;
			return (false);
		}
		return (true);
	}
}

bool
recover_guest_rekey(state *s, const ::dtt_vm_identity &identity)
{
	const uint8_t zero16[16] = {}, zero32[32] = {};
	::dtt_vm_identity current{};
	dtt_entry_t notice{};
	int64_t deadline;
	ssize_t count;

	if (s == nullptr || s->dtt_fd < 0 || s->inbounddir == nullptr ||
	    s->outbounddir == nullptr || identity.vmid == 0 ||
	    identity.vmid >= HYPERTRACE_MAX_VMS || identity.epoch == 0 ||
	    identity.old_vmid == 0 ||
	    identity.old_vmid >= HYPERTRACE_MAX_VMS ||
	    identity.old_epoch == 0 ||
	    (identity.old_vmid == identity.vmid &&
	    identity.old_epoch == identity.epoch) ||
	    (identity.flags != DTT_IDENTITY_REKEY_PENDING &&
	    identity.flags != DTT_IDENTITY_REKEY_LOCAL_COMMITTED)) {
		errno = EINVAL;
		return (false);
	}
	deadline = dtraced_io_deadline_after(50000);
	if (deadline < 0)
		return (false);
	/* If a former daemon already consumed the notice, the nonblocking
	 * read returns EAGAIN. Any different queued event is unsafe to skip. */
	for (;;) {
		int64_t now = dtraced_io_milliseconds();
		if (now < 0)
			return (false);
		if (now >= deadline) {
			errno = ETIMEDOUT;
			return (false);
		}
		count = read(s->dtt_fd, &notice, sizeof(notice));
		if (count < 0 && errno == EINTR)
			continue;
		if (count < 0 &&
		    (errno == EAGAIN || errno == EWOULDBLOCK))
			break;
		if (count != (ssize_t)sizeof(notice)) {
			if (count >= 0)
				errno = EPROTO;
			return (false);
		}
		if (notice.event_kind == DTT_VM_REKEY &&
		    notice.u.installed.vmid == identity.vmid &&
		    notice.u.installed.epoch == identity.epoch)
			break;
		if ((notice.event_kind == DTT_REKEY_DELIVERY_RECEIPT ||
		    notice.event_kind == DTT_REKEY_INGRESS_RECEIPT ||
		    notice.event_kind == DTT_REKEY_KILL_RECEIPT) &&
		    notice.u.installed.vmid == identity.old_vmid &&
		    notice.u.installed.epoch == identity.old_epoch &&
		    notice.u.installed.query_id != 0 &&
		    notice.u.installed.delivery_id != 0 &&
		    memcmp(notice.u.installed.source_id, zero16, 16) != 0 &&
		    notice.u.installed.replay == 0) {
			continue;
		}
		errno = EPROTO;
		return (false);
	}
	auto receipt_retry = [&](uint8_t kind, uint64_t delivery_id,
	    const uint8_t program_id[16], const uint8_t source_id[16],
	    const uint8_t digest[32], bool terminal_ok) {
		for (;;) {
			int64_t now = dtraced_io_milliseconds();
			if (now < 0)
				return (false);
			if (now >= deadline) {
				errno = ETIMEDOUT;
				return (false);
			}
			if (query_guest_rekey_receipt(s->dtt_fd, kind,
			    identity.old_vmid, identity.old_epoch,
			    identity.vmid, identity.epoch, delivery_id,
			    program_id, source_id, digest, terminal_ok,
			    deadline))
				return (true);
			if (errno != EAGAIN)
				return (false);
			usleep(100000);
		}
	};
	if (identity.flags == DTT_IDENTITY_REKEY_PENDING) {
		auto inbound_receipt = [&](const durable_delivery_state &entry) {
			uint8_t digest[32]{};
			if (entry.record.scope != 1)
				return (false);
			if (entry.record.journal_version == 4) {
				memcpy(digest,
				    entry.record.payload_digest.data(), 32);
				uint8_t actual[32]{};
				bool present = s->inbounddir->hash_identified_data(
				    entry.record.program_id.data(),
				    entry.record.source_id.data(), actual);
				if ((present && memcmp(actual, digest, 32) != 0) ||
				    (!present && (errno != ENOENT ||
				    entry.phase != delivery_phase::terminal))) {
					errno = EPROTO;
					return (false);
				}
			} else if (entry.record.journal_version != 3 ||
			    !s->inbounddir->hash_identified_data(
			    entry.record.program_id.data(),
			    entry.record.source_id.data(), digest))
				return (false);
			return (receipt_retry(DTT_REKEY_DELIVERY_QUERY,
			    entry.record.delivery_id,
			    entry.record.program_id.data(),
			    entry.record.source_id.data(), digest,
			    entry.phase == delivery_phase::terminal));
		};
		auto outbound_receipt = [&](const durable_delivery_state &entry) {
			if (entry.record.scope != 2 ||
			    entry.record.journal_version != 4 ||
			    (entry.phase == delivery_phase::pending &&
			    s->outbounddir->verify_pending_outbound(
			    entry.record) != 1))
				return (false);
			return (receipt_retry(DTT_REKEY_INGRESS_QUERY,
			    entry.record.delivery_id,
			    entry.record.program_id.data(),
			    entry.record.source_id.data(),
			    entry.record.payload_digest.data(), false));
		};
		auto kill_receipt = [&](const durable_kill &entry) {
			return (receipt_retry(DTT_REKEY_KILL_QUERY,
			    (uint64_t)entry.pid, zero16,
			    entry.source_id.data(), zero32, false));
		};
		/* The pair fence and each journal rename are durable exact-retry
		 * operations. A transient fsync or lock failure must not require a
		 * daemon restart while the restored guest is held behind rekey. */
		for (;;) {
			int64_t now = dtraced_io_milliseconds();
			if (now < 0)
				return (false);
			if (now >= deadline) {
				errno = ETIMEDOUT;
				return (false);
			}
			if (s->inbounddir->rekey_guest_journals_with_receipts(
			    *s->outbounddir, identity.old_vmid, identity.old_epoch,
			    identity.vmid, identity.epoch, inbound_receipt,
			    outbound_receipt, kill_receipt))
				break;
			if (errno != EIO && errno != EINTR && errno != EBUSY)
				return (false);
			usleep(100000);
		}
		current = identity;
		current.flags = 0;
		/* The driver accepts an exact COMMIT retry after a lost reply, and
		 * may report EBUSY while the TX ring drains. Keep the same identity
		 * and deadline until the local commit is durable or a hard error. */
		for (;;) {
			int64_t now = dtraced_io_milliseconds();
			if (now < 0)
				return (false);
			if (now >= deadline) {
				errno = ETIMEDOUT;
				return (false);
			}
			if (ioctl(s->dtt_fd, DTT_COMMIT_VM_REKEY, &current) == 0)
				break;
			if (errno != EBUSY && errno != EAGAIN && errno != ENOMEM &&
			    errno != EINTR && errno != EIO)
				return (false);
			usleep(100000);
		}
	} else {
		/* LOCAL_COMMITTED can be recovered without another guest COMMIT.
		 * Retry only transient journal I/O; an incomplete pair at this
		 * phase is a protocol failure, not permission to rewrite it. */
		for (;;) {
			int64_t now = dtraced_io_milliseconds();
			if (now < 0)
				return (false);
			if (now >= deadline) {
				errno = ETIMEDOUT;
				return (false);
			}
			if (s->inbounddir->guest_rekey_pair_complete(
			    *s->outbounddir, identity.old_vmid, identity.old_epoch,
			    identity.vmid, identity.epoch))
				break;
			if (errno != EIO && errno != EINTR)
				return (false);
			usleep(100000);
		}
	}
	/* The host's separate ACK makes the driver clear its rekey flag. No
	 * journal reader or writer thread starts before that exact transition. */
	for (;;) {
		int64_t now = dtraced_io_milliseconds();
		if (now < 0)
			return (false);
		if (now >= deadline) {
			errno = ETIMEDOUT;
			return (false);
		}
		if (ioctl(s->dtt_fd, DTT_GET_VM_IDENTITY, &current) == 0) {
			if (current.vmid != identity.vmid ||
			    current.epoch != identity.epoch ||
			    (current.flags != 0 &&
			    (current.flags != DTT_IDENTITY_REKEY_LOCAL_COMMITTED ||
			    current.old_vmid != identity.old_vmid ||
			    current.old_epoch != identity.old_epoch))) {
				errno = EPROTO;
				return (false);
			}
			if (current.flags == 0)
				return (true);
		} else if (errno != EAGAIN)
			return (false);
		usleep(DTRACED_SLEEPTIME);
	}
}

using outbound_key = std::pair<std::array<uint8_t, 16>, uint64_t>;
struct outbound_observation {
	int64_t next_query;
};

/* Revisit tokens that became uncertain after startup. Guest ELF delivery
 * can take 45 seconds including the host ACK; wait beyond that deadline so
 * a slow but healthy send does not race an unnecessary replay job. */
static bool
scan_runtime_outbound(state *s, std::vector<durable_delivery> &pending,
    std::map<outbound_key, outbound_observation> &observed, int64_t now)
{
	std::vector<durable_delivery_state> records;
	if (!s->outbounddir->list_deliveries(records))
		return (false);
	int64_t next_query = dtraced_io_deadline_from(now, 50000);
	if (next_query < 0)
		return (false);
	try {
		std::map<outbound_key, outbound_observation> next;
		std::vector<durable_delivery> ready;
		for (const auto &entry : records) {
			if (entry.record.scope != 2 ||
			    entry.record.journal_version != 4 ||
			    entry.phase != delivery_phase::pending)
				continue;
			outbound_key key{entry.record.session_id,
			    entry.record.delivery_id};
			auto previous = observed.find(key);
			outbound_observation age = previous == observed.end() ?
			    outbound_observation{next_query} : previous->second;
			if (now >= age.next_query) {
				ready.push_back(entry.record);
				age.next_query = next_query;
			}
			next.emplace(key, age);
		}
		pending.swap(ready);
		observed.swap(next);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	return (true);
}

/* Startup must not strand the writer if the socket thread exits early. */
static int
dtt_wait_socket(state *s, int64_t deadline)
{
	while (!s->shutdown.load()) {
		if (sem_trywait(&s->socksema) == 0)
			return (0);
		if (errno != EAGAIN && errno != EINTR)
			return (-1);
		int64_t now = dtraced_io_milliseconds();
		if (now < 0)
			return (-1);
		if (now >= deadline) {
			errno = ETIMEDOUT;
			return (-1);
		}
		usleep(DTRACED_SLEEPTIME);
	}
	errno = ECANCELED;
	return (-1);
}

/*
 * Outcome of one bridge connection attempt or session.  A session that ends
 * in DTT_BRIDGE_RECONNECT failed one job or lost its connection: the local
 * daemon fails that job and keeps its durable outbound token pending (the
 * forwarder's admission rescans outbound, and listen_dttransport()'s runtime
 * outbound scan queries and replays it), so the bridge reconnects instead of
 * stopping the guest daemon.  DTT_BRIDGE_FATAL is reserved for conditions a
 * reconnect cannot repair, including a malformed frame: the local daemon is
 * this same binary, so that is a protocol violation, not a failed job.
 */
enum dtt_bridge_result {
	DTT_BRIDGE_STOP,	/* shutdown or cleanup owns the exit */
	DTT_BRIDGE_RECONNECT,	/* log, back off, re-register */
	DTT_BRIDGE_FATAL,	/* stop the guest daemon */
};

/* Consecutive failed connection attempts to the local daemon before the
 * bridge gives up, and the reconnect backoff bounds (doubling from the
 * minimum). */
static constexpr unsigned DTT_BRIDGE_SETUP_ATTEMPTS = 6;
static constexpr int64_t DTT_BRIDGE_BACKOFF_MIN_MS = 50;
static constexpr int64_t DTT_BRIDGE_BACKOFF_MAX_MS = 2000;

static bool
dtt_bridge_stopping(state *s)
{

	return (s->shutdown.load() || s->cleanup_in_progress.load());
}

static int
setup_connection(state *s, bool *wait_ready, dtt_bridge_result *failure)
{
	dtd_initmsg_t initmsg;
	struct sockaddr_un addr;
	int sockfd;
	size_t transferred;
	int64_t deadline;

	memset(&initmsg, 0, sizeof(initmsg));
	*failure = DTT_BRIDGE_RECONNECT;

	/* The socket thread reports readiness once; a reconnect does not
	 * wait for it again. */
	if (*wait_ready) {
		deadline = dtraced_io_deadline_after(10000);
		if (deadline < 0 || dtt_wait_socket(s, deadline) != 0) {
			if (errno == ECANCELED || dtt_bridge_stopping(s))
				*failure = DTT_BRIDGE_STOP;
			else {
				ERR("guest bridge: local daemon socket never "
				    "became ready: %m");
				*failure = DTT_BRIDGE_FATAL;
			}
			return (-1);
		}
		*wait_ready = false;
	}

	sockfd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (sockfd == -1) {
		ERR("Failed creating a socket: %m");
		return (-1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;

	static_assert(sizeof(DTRACED_SOCKPATH) <= sizeof(addr.sun_path),
	    "DTRACED_SOCKPATH must fit in sun_path");
	(void)strlcpy(addr.sun_path, DTRACED_SOCKPATH, sizeof(addr.sun_path));

	deadline = dtraced_io_deadline_after(2000);
	if (deadline < 0) {
		close(sockfd);
		return (-1);
	}
	if (dtraced_io_connect(sockfd, (struct sockaddr *)&addr,
	    sizeof(addr), deadline) != 0) {
		ERR("connect to /var/ddtrace/sub.sock failed: %m");
		close(sockfd);
		return (-1);
	}

	if (dtraced_wire_read_init(sockfd, &initmsg,
	    deadline, &transferred) != 0) {
		ERR("guest bridge: no hello from the local daemon: %m");
		close(sockfd);
		return (-1);
	}

	if (!dtraced_wire_valid_server_init(&initmsg)) {
		/* Not a compatible dtraced: retrying cannot help. */
		ERR("Expected dtraced kind, got %d", initmsg.kind);
		*failure = DTT_BRIDGE_FATAL;
		close(sockfd);
		return (-1);
	}

	/* Valid by construction: forwarder kind, ELFWRITE only, nonempty
	 * ident and a nonzero session (guest_forwarder_initmsg()).  Each
	 * connection registers a fresh session. */
	initmsg = guest_forwarder_initmsg(getpid());

	if (dtraced_wire_write_init(sockfd, &initmsg,
	    deadline, &transferred) != 0) {
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
/* An idle stopped VM may remain checkpointed indefinitely. This wait does
 * not grant admission or replay journals and is cancellable on shutdown. */
bool
wait_guest_fresh_prepare(state *s, const dtt_cleanup_state &expected)
{
	if (expected.vmid == 0 || expected.vmid >= HYPERTRACE_MAX_VMS ||
	    expected.epoch == 0 || expected.delivery_id == 0) {
		errno = EINVAL;
		return (false);
	}
	while (!s->shutdown.load()) {
		dtt_cleanup_state stop{};
		dtt_vm_identity identity{};
		if (ioctl(s->dtt_fd, DTT_GET_CLEANUP_STATE, &stop) != 0 ||
		    ioctl(s->dtt_fd, DTT_GET_VM_IDENTITY, &identity) != 0) {
			if (errno == EINTR)
				continue;
			return (false);
		}
		if (stop.reserved != 0 || stop.flags != (DTT_CLEANUP_STATE_PENDING |
		    DTT_CLEANUP_STATE_APPLIED | DTT_CLEANUP_STATE_SESSION_STOP) ||
		    stop.vmid != expected.vmid || stop.epoch != expected.epoch ||
		    stop.delivery_id != expected.delivery_id) {
			errno = ESTALE;
			return (false);
		}
		if (identity.flags == DTT_IDENTITY_FRESH_PENDING ||
		    identity.flags == DTT_IDENTITY_FRESH_READY) {
			if (identity.old_vmid != expected.vmid ||
			    identity.old_epoch != expected.epoch || identity.vmid == 0 ||
			    identity.vmid >= HYPERTRACE_MAX_VMS || identity.epoch == 0 ||
			    identity.epoch == expected.epoch) {
				errno = ESTALE;
				return (false);
			}
			return (true);
		}
		if ((identity.flags != 0 && identity.flags != DTT_IDENTITY_FRESH_ACTIVE) ||
		    identity.vmid != expected.vmid || identity.epoch != expected.epoch) {
			errno = ESTALE;
			return (false);
		}
		usleep(100000);
	}
	errno = ECANCELED;
	return (false);
}

void
listen_dttransport(void *_s)
{
	state *s = (state *)_s;
	dtt_entry_t e;
	int rval;
	std::vector<durable_kill> pending_kill_acks;
	/* A kill journal is the durable authorization fence even if the daemon
	 * crashed before its separate source tombstone was synchronized. */
	if (s->inbounddir != nullptr) {
		std::vector<durable_kill> recovered;
		if (!s->inbounddir->list_kills(recovered)) {
			ERR("cannot read recovered guest kills: %m");
			broadcast_shutdown(*s);
			return;
		}
		try {
			pending_kill_acks.reserve(recovered.size());
			for (const durable_kill &record : recovered) {
				if (!s->inbounddir->revoke_source(
				    record.source_id.data())) {
					ERR("cannot recover guest revocation: %m");
					broadcast_shutdown(*s);
					return;
				}
				{
					std::lock_guard children(s->pidlistmtx);
					s->revoked_sources.insert(record.source_id);
				}
				int applied = s->inbounddir->kill_applied(record);
				if (applied < 0) {
					ERR("cannot inspect recovered kill ACK: %m");
					broadcast_shutdown(*s);
					return;
				}
				if (applied == 0)
					pending_kill_acks.push_back(record);
			}
		} catch (const std::bad_alloc &) {
			errno = ENOMEM;
			ERR("cannot recover guest revocation: %m");
			broadcast_shutdown(*s);
			return;
		}
	}
	size_t kill_ack_index = 0;
	int64_t kill_ack_next = dtraced_io_milliseconds();

	dtt_elf_state assembly;
	guest_delivery outstanding{};
	bool waiting_status = false;
	bool retry_status = false;
	int64_t status_deadline = 0;
	int64_t retry_at = 0;
	uint64_t query_id = 0, query_counter;
	arc4random_buf(&query_counter, sizeof(query_counter));
	std::vector<durable_delivery> outbound_pending;
	if (s->outbounddir != nullptr) {
		std::vector<durable_delivery_state> recovered;
		if (!s->outbounddir->list_deliveries(recovered)) {
			ERR("cannot read recovered outbound deliveries: %m");
			broadcast_shutdown(*s);
			return;
		}
		try {
			outbound_pending.reserve(recovered.size());
			for (const auto &entry : recovered)
				if (entry.record.scope == 2 &&
				    entry.record.journal_version == 4 &&
				    entry.phase == delivery_phase::pending)
					outbound_pending.push_back(entry.record);
		} catch (const std::bad_alloc &) {
			errno = ENOMEM;
			ERR("cannot retain recovered outbound deliveries: %m");
			broadcast_shutdown(*s);
			return;
		}
	}
	size_t outbound_index = 0;
	bool outbound_waiting = false, outbound_retry = false;
	int64_t outbound_deadline = 0, outbound_retry_at = 0;
	int64_t outbound_next_scan = dtraced_io_deadline_after(2000);
	if (outbound_next_scan < 0) {
		ERR("cannot start outbound scan deadline: %m");
		broadcast_shutdown(*s);
		return;
	}
	uint64_t outbound_query_id = 0;
	std::map<outbound_key, outbound_observation> outbound_observed;
	if (!send_next_recovery_query(s, outstanding, waiting_status,
	    status_deadline, query_id, query_counter)) {
		ERR("cannot query recovered guest delivery: %m");
		broadcast_shutdown(*s);
		return;
	}
	if (!send_next_outbound_ingress_query(s, outbound_pending, outbound_index,
	    outbound_waiting, outbound_deadline, outbound_query_id,
	    query_counter)) {
		ERR("cannot query recovered outbound delivery: %m");
		broadcast_shutdown(*s);
		return;
	}

	for (;;) {
		rval = 0;
		while (s->shutdown.load() == 0 && rval == 0) {
			int64_t now = dtraced_io_milliseconds();
			if (now < 0) {
				ERR("cannot read transport deadline clock: %m");
				broadcast_shutdown(*s);
				return;
			}
			if (!pending_kill_acks.empty() &&
			    now >= kill_ack_next) {
				if (kill_ack_index >= pending_kill_acks.size())
					kill_ack_index = 0;
				if (!send_kill_applied(s->dtt_fd,
				    pending_kill_acks[kill_ack_index]) &&
				    errno != EAGAIN && errno != ENOBUFS &&
				    errno != EINVAL) {
					ERR("cannot send durable kill observation: %m");
					broadcast_shutdown(*s);
					return;
				}
				++kill_ack_index;
				kill_ack_next = dtraced_io_deadline_from(now, 100);
				if (kill_ack_next < 0) {
					ERR("cannot schedule durable kill retry: %m");
					broadcast_shutdown(*s);
					return;
				}
			}
			if (s->outbounddir != nullptr && !outbound_waiting &&
			    !outbound_retry && outbound_index == outbound_pending.size() &&
			    now >= outbound_next_scan) {
				if (!scan_runtime_outbound(s, outbound_pending,
				    outbound_observed, now) ||
				    !send_next_outbound_ingress_query(s,
				    outbound_pending, 0, outbound_waiting,
				    outbound_deadline, outbound_query_id,
				    query_counter)) {
					ERR("cannot scan runtime outbound deliveries: %m");
					broadcast_shutdown(*s);
					return;
				}
				outbound_index = 0;
				outbound_next_scan = dtraced_io_deadline_from(now,
				    2000);
				if (outbound_next_scan < 0) {
					ERR("cannot schedule outbound scan: %m");
					broadcast_shutdown(*s);
					return;
				}
			}
			if (outbound_retry &&
			    now >= outbound_retry_at) {
				if (!send_next_outbound_ingress_query(s,
				    outbound_pending, outbound_index,
				    outbound_waiting, outbound_deadline,
				    outbound_query_id, query_counter)) {
					ERR("cannot retry outbound ingest status: %m");
					broadcast_shutdown(*s);
					return;
				}
				outbound_retry = false;
			}
			if (outbound_waiting &&
			    now >= outbound_deadline) {
				if (!send_next_outbound_ingress_query(s,
				    outbound_pending, outbound_index,
				    outbound_waiting, outbound_deadline,
				    outbound_query_id, query_counter)) {
					ERR("cannot repeat outbound ingest status: %m");
					broadcast_shutdown(*s);
					return;
				}
			}
			if (retry_status &&
			    now >= retry_at) {
				if (!send_next_recovery_query(s, outstanding,
				    waiting_status, status_deadline, query_id,
				    query_counter)) {
					ERR("cannot retry recovered delivery status: %m");
					broadcast_shutdown(*s);
					return;
				}
				retry_status = false;
			}
			if (waiting_status &&
			    now >= status_deadline) {
				/* A lost reply must not strand a recovered identity.
				 * A new ID prevents a delayed reply from satisfying it. */
				if (++query_counter == 0)
					++query_counter;
				if (!send_status_query(s->dtt_fd, outstanding,
				    query_counter)) {
					ERR("cannot repeat recovered delivery status: %m");
					broadcast_shutdown(*s);
					return;
				}
				query_id = query_counter;
				status_deadline = dtraced_io_deadline_from(now,
				    10000);
				if (status_deadline < 0) {
					ERR("cannot schedule recovered status retry: %m");
					broadcast_shutdown(*s);
					return;
				}
			}
			rval = read(s->dtt_fd, &e, sizeof(e));
			if (rval < 0) {
				if (errno == EWOULDBLOCK || errno == EINTR) {
					usleep(DTRACED_SLEEPTIME);
					rval = 0;
					continue;
				}

				ERR("failed to read event: %m");
				broadcast_shutdown(*s);
				return;
			}
			if (rval == 0) {
				ERR("dttransport closed during receive");
				broadcast_shutdown(*s);
				return;
			}
		}

		if (unlikely(s->shutdown.load()))
			break;

		if (unlikely(rval != sizeof(e))) {
			ERR("expected to read size %zu, got %d", sizeof(e),
			    rval);
			broadcast_shutdown(*s);
			return;
		}

		switch (e.event_kind) {
		case DTT_ELF:
			if (!dtt_elf(s, assembly, &e)) {
				ERR("ELF receive/publish failed; stopping transport");
				broadcast_shutdown(*s);
				return;
			}
			break;

		case DTT_KILL:
			if (!dtt_kill(s, &e)) {
				ERR("cannot queue dttransport kill event: %m");
				broadcast_shutdown(*s);
				return;
			}
			try {
				const durable_kill record = kill_record(e);
				int applied = s->inbounddir->kill_applied(record);
				if (applied < 0) {
					ERR("cannot inspect durable kill ACK: %m");
					broadcast_shutdown(*s);
					return;
				}
				if (applied == 0 &&
				    std::find_if(pending_kill_acks.begin(),
				    pending_kill_acks.end(), [&](const durable_kill &pending) {
					return pending.pid == record.pid &&
					    pending.vmid == record.vmid &&
					    pending.epoch == record.epoch &&
					    pending.source_id == record.source_id;
				}) == pending_kill_acks.end())
					pending_kill_acks.push_back(record);
			} catch (const std::bad_alloc &) {
				errno = ENOMEM;
				ERR("cannot retain durable kill observation: %m");
				broadcast_shutdown(*s);
				return;
			}
			kill_ack_next = dtraced_io_milliseconds();
			break;

		case DTT_HOST_KILL_APPLIED:
			{
				const durable_kill record = kill_record(e);
				if (record.pid <= 1 || record.vmid == 0 ||
				    record.vmid >= HYPERTRACE_MAX_VMS ||
				    record.epoch == 0 ||
				    s->inbounddir == nullptr ||
				    s->inbounddir->source_revoked(
				    record.source_id.data()) != 1) {
					ERR("invalid host kill observation");
					broadcast_shutdown(*s);
					return;
				}
				auto found = std::find_if(pending_kill_acks.begin(),
				    pending_kill_acks.end(), [&](const durable_kill &pending) {
					return pending.pid == record.pid &&
					    pending.vmid == record.vmid &&
					    pending.epoch == record.epoch &&
					    pending.source_id == record.source_id;
				});
				if (found != pending_kill_acks.end()) {
					if (!s->inbounddir->record_kill_applied(record)) {
						ERR("cannot persist guest kill ACK: %m");
						broadcast_shutdown(*s);
						return;
					}
					pending_kill_acks.erase(found);
					kill_ack_index = 0;
				}
			}
			break;

		case DTT_CLEANUP_DTRACED:
			dtt_cleanup_event(s, e);
			break;

		case DTT_SESSION_STOP:
			if (!dtt_session_stop_event(s, e)) {
				ERR("cannot quiesce guest tracing session: %m");
				broadcast_shutdown(*s);
				return;
			}
			{
				dtt_cleanup_state stopped{};
				stopped.vmid = e.u.cleanup.vmid;
				stopped.epoch = e.u.cleanup.epoch;
				stopped.delivery_id = e.u.cleanup.delivery_id;
				if (wait_guest_fresh_prepare(s, stopped))
					s->re_exec();
				if (!s->shutdown.load()) {
					ERR("stopped guest session changed unexpectedly: %m");
					broadcast_shutdown(*s);
				}
			}
			return;

		case DTT_HOST_INSTALLED:
		case DTT_HOST_UNINSTALLED:
			if (!handle_host_observation(*s, e)) {
				ERR("invalid host lifecycle observation: %m");
				broadcast_shutdown(*s);
				return;
			}
			break;

		case DTT_HOST_ELF:
			if (!dtt_host_elf(s, &e)) {
				ERR("invalid host ELF receipt: %m");
				broadcast_shutdown(*s);
				return;
			}
			break;

		case DTT_HOST_STATUS:
			if (!waiting_status || e.u.installed.query_id != query_id)
				break; /* An older reply cannot settle this query. */
			if (e.u.installed.delivery_id != outstanding.delivery_id ||
			    e.u.installed.vmid != outstanding.vmid ||
			    e.u.installed.epoch != outstanding.epoch ||
			    memcmp(e.u.installed.program_id,
			    outstanding.program_id.data(), 16) != 0 ||
			    memcmp(e.u.installed.source_id,
			    outstanding.source_id.data(), 16) != 0 ||
			    (e.u.installed.phase == 'u' &&
			    (e.u.installed.revoked != 0 ||
			    e.u.installed.replay != 0 ||
			    std::any_of(e.u.installed.digest,
			    e.u.installed.digest + sizeof(e.u.installed.digest),
			    [](uint8_t byte) { return byte != 0; })))) {
				ERR("invalid host delivery status: %m");
				broadcast_shutdown(*s);
				return;
			}
			if (e.u.installed.phase == 'u') {
				/* The host control socket is unavailable. Keep the
				 * journal identity, and retry without granting execution. */
				std::lock_guard deliveries(s->deliverymtx);
				for (auto &delivery : s->guest_deliveries) {
					if (delivery.delivery_id == outstanding.delivery_id &&
					    delivery.vmid == outstanding.vmid &&
					    delivery.epoch == outstanding.epoch &&
					    delivery.program_id == outstanding.program_id &&
					    delivery.source_id == outstanding.source_id) {
						delivery.query_sent = false;
						break;
					}
				}
				waiting_status = false;
				retry_status = true;
				retry_at = dtraced_io_deadline_after(1000);
				if (retry_at < 0) {
					broadcast_shutdown(*s);
					return;
				}
				break;
			}
			if (!handle_host_status(*s, e) ||
			    !send_next_recovery_query(s, outstanding,
			    waiting_status, status_deadline, query_id,
			    query_counter)) {
				ERR("invalid host delivery status: %m");
				broadcast_shutdown(*s);
				return;
			}
			break;

		case DTT_HOST_INGRESS_STATUS:
			if (!outbound_waiting ||
			    e.u.installed.query_id != outbound_query_id)
				break; /* A delayed response cannot settle a newer query. */
			{
				const auto &record = outbound_pending[outbound_index];
				const uint8_t zero_digest[32] = {};
				bool unavailable = e.u.installed.phase == 'u';
				bool absent = e.u.installed.phase == 0;
				bool identified = e.u.installed.phase == 'p' ||
				    e.u.installed.phase == 'a';
				if (e.u.installed.delivery_id != record.delivery_id ||
				    e.u.installed.vmid == 0 ||
				    e.u.installed.vmid >= HYPERTRACE_MAX_VMS ||
				    e.u.installed.epoch == 0 ||
				    memcmp(e.u.installed.program_id,
				    record.program_id.data(), 16) != 0 ||
				    memcmp(e.u.installed.source_id,
				    record.source_id.data(), 16) != 0 ||
				    (!unavailable && !absent && !identified) ||
				    e.u.installed.revoked > 1 ||
				    e.u.installed.replay != 0 ||
				    (unavailable && e.u.installed.revoked != 0) ||
				    ((unavailable || absent) &&
				    memcmp(e.u.installed.digest, zero_digest, 32) != 0) ||
				    (identified &&
				    memcmp(e.u.installed.digest,
				    record.payload_digest.data(), 32) != 0)) {
					errno = EPROTO;
					ERR("invalid host ingest status: %m");
					broadcast_shutdown(*s);
					return;
				}
				int local_phase = s->outbounddir->delivery_status(record);
				if (local_phase < 0) {
					ERR("cannot inspect outbound delivery: %m");
					broadcast_shutdown(*s);
					return;
				}
				if (local_phase != (int)delivery_phase::pending) {
					if (local_phase == (int)delivery_phase::accepted &&
					    !s->outbounddir->retire_accepted_outbound(record)) {
						ERR("cannot retire outbound delivery: %m");
						broadcast_shutdown(*s);
						return;
					}
					++outbound_index;
					if (!send_next_outbound_ingress_query(s,
					    outbound_pending, outbound_index,
					    outbound_waiting, outbound_deadline,
					    outbound_query_id, query_counter)) {
						ERR("cannot query next outbound delivery: %m");
						broadcast_shutdown(*s);
						return;
					}
					break;
				}
				if (unavailable) {
					outbound_waiting = false;
					outbound_retry = true;
					outbound_retry_at =
					    dtraced_io_deadline_after(1000);
					if (outbound_retry_at < 0) {
						broadcast_shutdown(*s);
						return;
					}
					break;
				}
				if (record.vmid != 0 &&
				    (record.vmid != e.u.installed.vmid ||
				    record.epoch != e.u.installed.epoch)) {
					/* A restored guest cannot settle a token from a
					 * different VM incarnation. Keep its journal fence. */
					++outbound_index;
					if (!send_next_outbound_ingress_query(s,
					    outbound_pending, outbound_index,
					    outbound_waiting, outbound_deadline,
					    outbound_query_id, query_counter)) {
						ERR("cannot query next outbound delivery: %m");
						broadcast_shutdown(*s);
						return;
					}
					break;
				}
				if (e.u.installed.phase == 'a' &&
				    (!s->outbounddir->record_delivery(record,
				    delivery_phase::accepted) ||
				    !s->outbounddir->retire_accepted_outbound(record))) {
					ERR("cannot retire accepted outbound delivery: %m");
					broadcast_shutdown(*s);
					return;
				}
				if (e.u.installed.phase == 'p' ||
				    (absent && record.vmid != 0)) {
					/* Replay only the journal's exact token and bytes. A
					 * missing spool or revoked source stays fenced. An
					 * absent answer lacks proof of the original VM epoch. */
					int present = s->outbounddir->verify_pending_outbound(
					    record);
					int revoked = present > 0 ?
					    s->outbounddir->source_revoked(
					    record.source_id.data()) : 0;
					if (present < 0 || revoked < 0) {
						ERR("cannot validate outbound replay: %m");
						broadcast_shutdown(*s);
						return;
					}
					if (present > 0 && revoked == 0 &&
					    e.u.installed.revoked == 0) {
						int queued = s->outbounddir->
						    queue_recovered_outbound(record,
						    e.u.installed.vmid,
						    e.u.installed.epoch);
						if (queued < 0) {
							ERR("cannot queue outbound replay: %m");
							broadcast_shutdown(*s);
							return;
						}
						if (queued == 0) {
							outbound_waiting = false;
							outbound_retry = true;
							outbound_retry_at =
							    dtraced_io_deadline_after(1000);
							if (outbound_retry_at < 0) {
								broadcast_shutdown(*s);
								return;
							}
							break;
						}
					}
				}
				++outbound_index;
				if (!send_next_outbound_ingress_query(s,
				    outbound_pending, outbound_index,
				    outbound_waiting, outbound_deadline,
				    outbound_query_id, query_counter)) {
					ERR("cannot query next outbound delivery: %m");
					broadcast_shutdown(*s);
					return;
				}
			}
			break;

		case DTT_VM_IDENTITY:
			{
				std::lock_guard identity(s->vm_identity_mtx);
				if (s->vm_identity_query_id == 0 ||
				    e.u.installed.query_id !=
				    s->vm_identity_query_id)
					break;
				const uint8_t zero_id[16] = {};
				const uint8_t zero_digest[32] = {};
				if (e.u.installed.delivery_id != 0 ||
				    e.u.installed.vmid == 0 ||
				    e.u.installed.vmid >= HYPERTRACE_MAX_VMS ||
				    e.u.installed.epoch == 0 ||
				    memcmp(e.u.installed.program_id, zero_id, 16) != 0 ||
				    memcmp(e.u.installed.source_id, zero_id, 16) != 0 ||
				    e.u.installed.phase != 0 ||
				    e.u.installed.revoked != 0 ||
				    e.u.installed.replay != 0 ||
				    memcmp(e.u.installed.digest,
				    zero_digest, 32) != 0) {
					errno = EPROTO;
					ERR("invalid VM identity reply: %m");
					broadcast_shutdown(*s);
					return;
				}
				s->vm_identity_vmid = e.u.installed.vmid;
				s->vm_identity_epoch = e.u.installed.epoch;
				s->vm_identity_ready = true;
				s->vm_identity_cv.notify_all();
			}
			break;

		case DTT_VM_REKEY:
			/* Drop the old daemon's volatile state and traced children.
			 * The fresh process must reconcile durable source receipts and
			 * finish the fenced rekey before starting normal threads. */
			WARN("VM identity changed; restarting for journal rekey");
			dtt_cleanup(s);
			return;

		default:
			ERR("got unknown event (%d) from dttransport",
			    e.event_kind);
			break;
		}
	}

	return;
}

/* Release the receipt slot this bridge claimed for a frame it abandons, so
 * the next frame on a new connection is not refused as busy.  A late
 * receipt for the abandoned delivery is ignored by dtt_host_elf(). */
static void
dtt_bridge_release_receipt(state *s, uint64_t delivery_id)
{
	std::lock_guard lock(s->host_elf_mtx);
	if (delivery_id != 0 && s->host_elf_waiting == delivery_id) {
		s->host_elf_waiting = 0;
		s->host_elf_accepted = false;
	}
}

/*
 * Serve one bridge connection: read identified ELF frames from the local
 * daemon, write them to /dev/dttransport, wait for bhyve's receipt and ACK.
 * Returns how the session ended; *delivered counts acknowledged frames.
 */
static dtt_bridge_result
dtt_bridge_session(state *s, int sockfd, unsigned *delivered)
{
	dtt_entry_t e;
	dtraced_hdr_t header;
	size_t transferred, length, offset, fragment;
	uint32_t identifier;
	dtraced_delivery_ack_t ack;
	int64_t deadline;
	ssize_t written;
	uint64_t claimed;

	while (!dtt_bridge_stopping(s)) {
		/* Wait idle in short slices so shutdown is noticed promptly; a
		 * frame, once started, keeps the full 10 s deadline. */
		struct pollfd idle = { .fd = sockfd, .events = POLLIN, .revents = 0 };
		int ready = poll(&idle, 1, 1000);
		if (ready == 0 || (ready < 0 && errno == EINTR))
			continue;
		deadline = dtraced_io_deadline_after(10000);
		if (deadline < 0)
			return (DTT_BRIDGE_FATAL);
		unsigned char header_wire[DTRACED_MSGHDRSIZE];
		if (dtraced_io_transfer(sockfd, header_wire, sizeof(header_wire), false,
		    deadline, &transferred) != 0) {
			if (errno == ETIMEDOUT && transferred == 0)
				continue;
			/* The local daemon closes the bridge when a job to it
			 * fails (state::kill_socket). */
			ERR("guest bridge: connection closed before a complete "
			    "daemon ELF header: %m; reconnecting");
			return (DTT_BRIDGE_RECONNECT);
		}
		if (dtraced_wire_decode_header(&header, header_wire) != 0) {
			ERR("guest bridge: invalid daemon ELF header: %m; "
			    "protocol violation, stopping");
			return (DTT_BRIDGE_FATAL);
		}
		length = header.elf.len;
		if (header.msg_type != DTRACED_MSG_ELF ||
		    header.elf.delivery_id == 0 || length < 4 ||
		    length > HYPERTRACE_ELF_MAX ||
		    header.elf.filter_by_vmid != 0 ||
		    header.elf.vmid == 0 ||
		    header.elf.vmid >= HYPERTRACE_MAX_VMS ||
		    header.elf.epoch == 0) {
			ERR("guest bridge: invalid daemon ELF frame; "
			    "protocol violation, stopping");
			return (DTT_BRIDGE_FATAL);
		}
		const uint8_t zero_id[DTRACED_PROGRAM_ID_LEN] = {};
		if (memcmp(header.elf.program_id, zero_id, sizeof(zero_id)) == 0 ||
		    memcmp(header.elf.source_id, zero_id, sizeof(zero_id)) == 0) {
			ERR("guest bridge: daemon ELF has no program or source "
			    "identity; protocol violation, stopping");
			return (DTT_BRIDGE_FATAL);
		}
		std::unique_ptr<unsigned char[]> data(new (std::nothrow) unsigned char[length]);
		if (!data) {
			errno = ENOMEM;
			ERR("guest bridge: cannot allocate daemon ELF frame: %m; "
			    "reconnecting");
			return (DTT_BRIDGE_RECONNECT);
		}
		if (dtraced_io_transfer(sockfd, data.get(), length, false,
		    deadline, &transferred) != 0) {
			ERR("guest bridge: cannot receive complete daemon ELF: "
			    "%m; reconnecting");
			return (DTT_BRIDGE_RECONNECT);
		}
		if (memcmp(data.get(), "\177ELF", 4) != 0) {
			ERR("guest bridge: daemon payload is not ELF; "
			    "protocol violation, stopping");
			return (DTT_BRIDGE_FATAL);
		}
		uint8_t expected_digest[SHA256_DIGEST_LENGTH];
		if (SHA256(data.get(), length, expected_digest) == NULL) {
			ERR("guest bridge: cannot hash daemon ELF frame");
			return (DTT_BRIDGE_FATAL);
		}
		{
			std::lock_guard lock(s->host_elf_mtx);
			if (s->host_elf_waiting != 0) {
				/* Only this thread claims the slot and it
				 * releases it on every exit from a frame. */
				ERR("guest bridge: host receipt slot is held by "
				    "delivery %ju", (uintmax_t)s->host_elf_waiting);
				return (DTT_BRIDGE_FATAL);
			}
			s->host_elf_waiting = header.elf.delivery_id;
			memcpy(s->host_elf_program.data(), header.elf.program_id, 16);
			memcpy(s->host_elf_source.data(), header.elf.source_id, 16);
			memcpy(s->host_elf_digest.data(), expected_digest, 32);
			s->host_elf_accepted = false;
		}
		claimed = header.elf.delivery_id;
		identifier = arc4random();
		deadline = dtraced_io_deadline_after(10000);
		if (deadline < 0) {
			dtt_bridge_release_receipt(s, claimed);
			return (DTT_BRIDGE_FATAL);
		}
		for (offset = 0; offset < length; offset += fragment) {
			fragment = MIN(length - offset, DTT_MAXDATALEN);
			memset(&e, 0, sizeof(e));
			e.event_kind = DTT_ELF;
			e.u.elf.identifier = identifier;
			e.u.elf.delivery_id = header.elf.delivery_id;
			e.u.elf.vmid = header.elf.vmid;
			e.u.elf.epoch = header.elf.epoch;
			memcpy(e.u.elf.program_id, header.elf.program_id, 16);
			memcpy(e.u.elf.source_id, header.elf.source_id, 16);
			e.u.elf.hasmore = offset + fragment < length;
			e.u.elf.len = fragment;
			e.u.elf.totallen = length;
			memcpy(e.u.elf.data, data.get() + offset, fragment);
			for (;;) {
				if (dtt_bridge_stopping(s)) {
					dtt_bridge_release_receipt(s, claimed);
					return (DTT_BRIDGE_STOP);
				}
				int64_t now = dtraced_io_milliseconds();
				if (now < 0) {
					dtt_bridge_release_receipt(s, claimed);
					return (DTT_BRIDGE_FATAL);
				}
				if (now >= deadline && offset == 0) {
					/* The device kept refusing for lack of
					 * queue space: fail this job only. */
					ERR("guest bridge: dttransport stayed full "
					    "for delivery %ju; reconnecting",
					    (uintmax_t)claimed);
					dtt_bridge_release_receipt(s, claimed);
					return (DTT_BRIDGE_RECONNECT);
				}
				if (now >= deadline) {
					/* bhyve holds the accepted fragments and
					 * accepts only their continuation (same
					 * identifier and delivery); any other
					 * frame resets the transport. */
					ERR("guest bridge: dttransport stayed full "
					    "after %zu of %zu bytes of delivery "
					    "%ju; the partial ELF cannot be "
					    "abandoned, stopping", offset, length,
					    (uintmax_t)claimed);
					dtt_bridge_release_receipt(s, claimed);
					return (DTT_BRIDGE_FATAL);
				}
				written = write(s->dtt_fd, &e, sizeof(e));
				if (written == (ssize_t)sizeof(e))
					break;
				if (written < 0 && errno == EINTR)
					continue;
				if (written < 0 && (errno == EAGAIN || errno == ENOBUFS)) {
					usleep(DTRACED_SLEEPTIME);
					continue;
				}
				/* Device writes are complete records.  A gone
				 * device (ENXIO, ENODEV, EBADF), revoked
				 * transport ownership (EBUSY, EPERM, EACCES), a
				 * partial record or another device error cannot
				 * be repaired by reconnecting to the daemon. */
				if (written >= 0)
					ERR("guest bridge: dttransport accepted a "
					    "partial record (%zd of %zu bytes); "
					    "stopping", written, sizeof(e));
				else if (errno == ENXIO || errno == ENODEV ||
				    errno == EBADF)
					ERR("guest bridge: dttransport device is "
					    "gone: %m; stopping");
				else if (errno == EBUSY || errno == EPERM ||
				    errno == EACCES)
					ERR("guest bridge: dttransport ownership "
					    "was revoked: %m; stopping");
				else
					ERR("guest bridge: dttransport write "
					    "failed: %m; stopping");
				dtt_bridge_release_receipt(s, claimed);
				return (DTT_BRIDGE_FATAL);
			}
		}
		/* A device write is only queue acceptance. Wait for bhyve's receipt
		 * after the host daemon has accepted the complete identified ELF. */
		{
			std::unique_lock lock(s->host_elf_mtx);
			bool received = s->host_elf_cv.wait_for(lock,
			    std::chrono::seconds(20), [&] {
				return s->host_elf_accepted || dtt_bridge_stopping(s);
			    });
			bool accepted = received && s->host_elf_accepted;
			s->host_elf_waiting = 0;
			s->host_elf_accepted = false;
			if (dtt_bridge_stopping(s))
				return (DTT_BRIDGE_STOP);
			if (!accepted) {
				/* No ACK: the daemon fails the job and keeps the
				 * token pending; host ingress status settles it. */
				ERR("guest bridge: no host receipt for delivery "
				    "%ju; reconnecting", (uintmax_t)claimed);
				return (DTT_BRIDGE_RECONNECT);
			}
		}
		ack.delivery_id = header.elf.delivery_id;
		deadline = dtraced_io_deadline_after(10000);
		if (deadline < 0)
			return (DTT_BRIDGE_FATAL);
		if (dtraced_wire_write_ack(sockfd, &ack,
		    deadline, &transferred) != 0) {
			ERR("guest bridge: cannot acknowledge delivery %ju: %m; "
			    "reconnecting", (uintmax_t)claimed);
			return (DTT_BRIDGE_RECONNECT);
		}
		++*delivered;
	}
	return (DTT_BRIDGE_STOP);
}

/* Sleep for the reconnect backoff in short slices; false on shutdown. */
static bool
dtt_bridge_backoff(state *s, int64_t delay_ms)
{
	int64_t deadline = dtraced_io_deadline_after(delay_ms);

	if (deadline < 0)
		return (false);
	while (!dtt_bridge_stopping(s)) {
		int64_t now = dtraced_io_milliseconds();
		if (now < 0)
			return (false);
		if (now >= deadline)
			return (true);
		usleep((useconds_t)MIN(deadline - now, (int64_t)50) * 1000);
	}
	return (false);
}

/*
 * The guest's local forwarder: a client of this daemon's own socket that
 * moves identified ELF frames to the host through /dev/dttransport.  One
 * failed job or a closed connection is logged and the bridge re-registers
 * with bounded exponential backoff.  It stops the guest daemon on a fatal
 * device or protocol condition, or after DTT_BRIDGE_SETUP_ATTEMPTS
 * consecutive connection attempts fail.  Sessions that end without a
 * delivery are not counted: a stalled host fails each job (no receipt, a
 * full device) for as long as it stalls, and the pending token is replayed
 * once it drains.  A frame the bridge can never accept is a protocol
 * violation, which is already fatal.
 */
void
write_dttransport(void *_s)
{
	state *s = (state *)_s;
	dtt_bridge_result result = DTT_BRIDGE_STOP;
	unsigned setup_failures = 0;
	int64_t backoff = DTT_BRIDGE_BACKOFF_MIN_MS;
	bool wait_ready = true;

	while (!dtt_bridge_stopping(s)) {
		dtt_bridge_result failure;
		int sockfd = setup_connection(s, &wait_ready, &failure);
		if (sockfd < 0) {
			if (failure != DTT_BRIDGE_RECONNECT) {
				result = failure;
				break;
			}
			if (++setup_failures >= DTT_BRIDGE_SETUP_ATTEMPTS) {
				ERR("guest bridge: %u consecutive connection "
				    "attempts to the local daemon failed; "
				    "stopping", setup_failures);
				result = DTT_BRIDGE_FATAL;
				break;
			}
		} else {
			setup_failures = 0;
			unsigned delivered = 0;
			result = dtt_bridge_session(s, sockfd, &delivered);
			close(sockfd);
			if (result != DTT_BRIDGE_RECONNECT)
				break;
			if (delivered != 0)
				backoff = DTT_BRIDGE_BACKOFF_MIN_MS;
		}
		WARN("guest bridge: re-registering with the local daemon in "
		    "%jd ms", (intmax_t)backoff);
		if (!dtt_bridge_backoff(s, backoff)) {
			result = DTT_BRIDGE_STOP;
			break;
		}
		backoff = MIN(backoff * 2, DTT_BRIDGE_BACKOFF_MAX_MS);
	}
	if (result == DTT_BRIDGE_FATAL && !s->cleanup_in_progress.load())
		broadcast_shutdown(*s);
}

}
