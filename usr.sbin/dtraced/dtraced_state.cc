/*-
 * Copyright (c) 2020 Domagoj Stolfa
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
#include <sys/procdesc.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/hypertrace.h>
#include <sys/ioctl.h>
#include <dttransport.h>
#if defined(__amd64__)
#include <amd64/include/vmm_dev.h>
#elif defined(__aarch64__)
#include <arm64/include/vmm_dev.h>
#elif defined(__riscv)
#include <riscv/include/vmm_dev.h>
#endif
#if defined(__amd64__) || defined(__aarch64__) || defined(__riscv)
#define DTRACED_HAS_VM_ATTESTATION 1
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <algorithm>
#include <chrono>
#include <memory>
#include <new>
#include <system_error>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced_connection.h"
#include "dtraced_child_ledger.h"
#include "dtraced_io.h"
#include "dtraced_wire.h"
#include "dtraced_socket.h"
#include "dtraced_directory.h"
#include "dtraced_dttransport.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_misc.h"
#include "dtraced_process.h"
#include "dtraced_state.h"

namespace dtraced {

const static int DTRACED_BACKLOG_SIZE = 10000;

static bool
validate_guest_recovery_identity(int fd,
    const std::vector<durable_delivery_state> &outbound,
    const std::vector<durable_delivery_state> &inbound,
    const std::vector<durable_kill> &kills,
    ::dtt_vm_identity *rekey_out = nullptr, bool fresh_namespace = false)
{
	/* The listener cannot receive an asynchronous identity reply until its
	 * journals have been recovered. Read the driver's current identity before
	 * any old journal is retired or replayed. */
	struct dtt_vm_identity identity{};
	int64_t deadline = dtraced_io_deadline_after(30000);
	if (deadline < 0)
		return (false);
	int64_t now;
	for (;;) {
		if (ioctl(fd, DTT_GET_VM_IDENTITY, &identity) == 0)
			break;
		if (errno != EAGAIN && errno != ENXIO)
			return (false);
		now = dtraced_io_milliseconds();
		if (now < 0)
			return (false);
		if (now >= deadline) {
			errno = ETIMEDOUT;
			return (false);
		}
		usleep(10000);
	}
	if (identity.vmid == 0 || identity.vmid >= HYPERTRACE_MAX_VMS ||
	    identity.epoch == 0 ||
	    (identity.flags != 0 && identity.flags != DTT_IDENTITY_REKEY_PENDING &&
	    identity.flags != DTT_IDENTITY_REKEY_LOCAL_COMMITTED &&
	    identity.flags != DTT_IDENTITY_FRESH_PENDING &&
	    identity.flags != DTT_IDENTITY_FRESH_READY &&
	    identity.flags != DTT_IDENTITY_FRESH_ACTIVE) ||
	    (identity.flags == 0 &&
	    (identity.old_vmid != 0 || identity.old_epoch != 0)) ||
	    (identity.flags != 0 &&
	    (identity.old_vmid == 0 ||
	    identity.old_vmid >= HYPERTRACE_MAX_VMS ||
	    identity.old_epoch == 0 ||
	    (identity.old_vmid == identity.vmid &&
	    identity.old_epoch == identity.epoch)))) {
		errno = EPROTO;
		return (false);
	}
	/* A previous daemon may have died before consuming the priority
	 * notice or after local commit but before host acknowledgement. Neither
	 * phase authorizes ordinary journal recovery or replay. */
	if (identity.flags != 0 && !(fresh_namespace &&
	    identity.flags == DTT_IDENTITY_FRESH_ACTIVE)) {
		if (rekey_out == nullptr) {
			errno = ESTALE;
			return (false);
		}
		*rekey_out = identity;
		return (true);
	}
	for (const auto &entry : outbound) {
		/* A pending guest outbound token may be deliberately unbound.
		 * It cannot be replayed after rekey: the driver fences its
		 * identity-free ingress status query. */
		if (entry.record.scope == 2 &&
		    entry.record.vmid == 0 && entry.record.epoch == 0)
			continue;
		if (entry.record.vmid != identity.vmid ||
		    entry.record.epoch != identity.epoch) {
			errno = ESTALE;
			return (false);
		}
	}
	for (const auto &entry : inbound)
		if (entry.record.vmid != identity.vmid ||
		    entry.record.epoch != identity.epoch) {
			errno = ESTALE;
			return (false);
		}
	for (const auto &record : kills)
		if (record.vmid != identity.vmid ||
		    record.epoch != identity.epoch) {
			errno = ESTALE;
			return (false);
		}
	return (true);
}

static bool
validate_guest_cleanup_recovery_state(int fd, int child_directory,
    dtt_cleanup_state *stopped_out = nullptr)
{
	struct dtt_cleanup_state cleanup{};
	struct dtt_vm_identity identity{};

	if (ioctl(fd, DTT_GET_CLEANUP_STATE, &cleanup) != 0 ||
	    ioctl(fd, DTT_GET_VM_IDENTITY, &identity) != 0)
		return (false);
	/* The selected active namespace owns this identity's child ledger. */
	if (identity.flags == DTT_IDENTITY_FRESH_ACTIVE) {
		identity.flags = 0;
		identity.old_vmid = 0;
		identity.old_epoch = 0;
	}
	if (cleanup.reserved != 0 ||
	    (cleanup.flags & ~(DTT_CLEANUP_STATE_PENDING |
	    DTT_CLEANUP_STATE_APPLIED | DTT_CLEANUP_STATE_SESSION_STOP)) != 0 ||
	    ((cleanup.flags & DTT_CLEANUP_STATE_PENDING) == 0 &&
	    (cleanup.flags != 0 || cleanup.delivery_id != 0 ||
	    cleanup.vmid != 0 || cleanup.epoch != 0)) ||
	    ((cleanup.flags & DTT_CLEANUP_STATE_PENDING) != 0 &&
	    (cleanup.delivery_id == 0 || cleanup.vmid == 0 ||
	    cleanup.vmid >= HYPERTRACE_MAX_VMS || cleanup.epoch == 0 ||
	    cleanup.vmid != identity.vmid ||
	    cleanup.epoch != identity.epoch))) {
		errno = EPROTO;
		return (false);
	}
	const bool stopped =
	    (cleanup.flags & DTT_CLEANUP_STATE_SESSION_STOP) != 0;
	const bool unapplied = (cleanup.flags & DTT_CLEANUP_STATE_PENDING) != 0 &&
	    (cleanup.flags & DTT_CLEANUP_STATE_APPLIED) == 0;
	if (stopped && (identity.flags != 0 || identity.old_vmid != 0 ||
	    identity.old_epoch != 0)) {
		errno = EPROTO;
		return (false);
	}
	/* All guest tracing children are held behind the durable birth-record
	 * gate before exec. Reopen and verify exact children from the old owner,
	 * then wait for exit before claiming its pending CLEANUP was applied. */
	if (!recover_guest_children(child_directory,
	    unapplied || stopped))
		return (false);
	if (unapplied || stopped) {
		dtt_entry_t applied{};
		applied.event_kind = stopped ? DTT_SESSION_STOPPED : DTT_CLEANUP_APPLIED;
		applied.u.cleanup.delivery_id = cleanup.delivery_id;
		applied.u.cleanup.vmid = cleanup.vmid;
		applied.u.cleanup.epoch = cleanup.epoch;
		int64_t deadline = dtraced_io_deadline_after(10000);
		if (deadline < 0)
			return (false);
		ssize_t sent;
		for (;;) {
			int64_t now = dtraced_io_milliseconds();
			if (now < 0)
				return (false);
			if (now >= deadline) {
				errno = ETIMEDOUT;
				return (false);
			}
			sent = write(fd, &applied, sizeof(applied));
			if (sent >= 0 || errno != EINTR)
				break;
		}
		if (sent != (ssize_t)sizeof(applied)) {
			if (sent >= 0) errno = EIO;
			return (false);
		}
	}
	if (stopped) {
		if (stopped_out != nullptr)
			*stopped_out = cleanup;
		/* Finish an interrupted stop, but never admit journal replay or
		 * new launches under this retired session. Fresh attach is separate. */
		errno = ESHUTDOWN;
		return (false);
	}
	return (true);
}

/* Called only after all three fresh directories have been opened empty and
 * synchronized. No worker or directory watcher may run before activation. */
static bool
activate_guest_fresh_session(int fd, const dtt_vm_identity &identity)
{
	dtt_cleanup_state stop{};
	if ((identity.flags != DTT_IDENTITY_FRESH_PENDING &&
	    identity.flags != DTT_IDENTITY_FRESH_READY) ||
	    ioctl(fd, DTT_GET_CLEANUP_STATE, &stop) != 0)
		return (false);
	if (stop.reserved != 0 || stop.flags != (DTT_CLEANUP_STATE_PENDING |
	    DTT_CLEANUP_STATE_APPLIED | DTT_CLEANUP_STATE_SESSION_STOP) ||
	    stop.delivery_id == 0 || stop.vmid != identity.old_vmid ||
	    stop.epoch != identity.old_epoch) {
		errno = EPROTO;
		return (false);
	}
	int64_t deadline = dtraced_io_deadline_after(30000);
	if (deadline < 0)
		return (false);
	dtt_entry_t ready{};
	ready.event_kind = DTT_SESSION_READY;
	ready.u.cleanup.vmid = identity.vmid;
	ready.u.cleanup.epoch = identity.epoch;
	ready.u.cleanup.delivery_id = stop.delivery_id;
	bool sent = false;
	for (;;) {
		int64_t now = dtraced_io_milliseconds();
		if (now < 0)
			return (false);
		if (now >= deadline) {
			errno = ETIMEDOUT;
			return (false);
		}
		dtt_vm_identity current{};
		if (ioctl(fd, DTT_GET_VM_IDENTITY, &current) != 0)
			return (false);
		if (current.vmid != identity.vmid || current.epoch != identity.epoch ||
		    current.old_vmid != identity.old_vmid ||
		    current.old_epoch != identity.old_epoch ||
		    (current.flags != DTT_IDENTITY_FRESH_PENDING &&
		    current.flags != DTT_IDENTITY_FRESH_READY &&
		    current.flags != DTT_IDENTITY_FRESH_ACTIVE)) {
			errno = ESTALE;
			return (false);
		}
		if (current.flags == DTT_IDENTITY_FRESH_ACTIVE)
			return (true);
		if (!sent) {
			ssize_t result = write(fd, &ready, sizeof(ready));
			if (result == (ssize_t)sizeof(ready))
				sent = true;
			else if (result >= 0 || (errno != EINTR && errno != EAGAIN)) {
				if (result >= 0) errno = EIO;
				return (false);
			}
		}
		usleep(10000);
	}
}

bool
state::setup_threads(void)
{
	if (sem_init(&this->socksema, 0, 0) != 0)
		return (false);

	this->socksema_initialized = true;
	{
		std::lock_guard start(this->socket_start_mtx);
		this->socket_start_done = false;
		this->socket_start_error = 0;
		this->directory_start_done = 0;
		this->directory_start_error = 0;
	}
	try {
		this->workers.resize(this->threadpool_size);
		for (size_t i = 0; i < this->threadpool_size; i++)
			this->workers[i] = std::thread(&state::process_joblist, this);

		if (this->ctrlmachine == 0) {
			this->dtt_listentd = std::thread(&dtraced::listen_dttransport, this);
			this->dtt_writetd = std::thread(&dtraced::write_dttransport, this);
		}

		this->socktd = std::thread(&state::process_consumers, this);
		this->inboundtd = std::thread(&dir::listen, this->inbounddir);
		this->basetd = std::thread(&dir::listen, this->basedir);
		this->killtd = std::thread(&state::manage_children, this);
		this->reaptd = std::thread(&state::reap_children, this);
		this->closetd = std::thread(&state::close_filedescs, this);
		this->jobcleantd = std::thread(&state::clean_jobs, this);
	} catch (const std::bad_alloc &) {
		broadcast_shutdown(*this);
		errno = ENOMEM;
		return (false);
	} catch (const std::system_error &e) {
		broadcast_shutdown(*this);
		errno = e.code().value();
		return (false);
	}

	std::unique_lock start(this->socket_start_mtx);
	bool reported = this->socket_start_cv.wait_for(start,
	    std::chrono::seconds(10), [this] {
		return this->socket_start_error != 0 ||
		    this->directory_start_error != 0 ||
		    (this->socket_start_done && this->directory_start_done == 2) ||
		    this->shutdown.load();
	});
	if (!reported) {
		start.unlock();
		broadcast_shutdown(*this);
		errno = ETIMEDOUT;
		return (false);
	}
	if (!this->socket_start_done || this->directory_start_done != 2 ||
	    this->socket_start_error != 0 ||
	    this->directory_start_error != 0 || this->shutdown.load()) {
		int error = this->directory_start_error != 0 &&
		    this->directory_start_error != ECANCELED ?
		    this->directory_start_error :
		    this->socket_start_error != 0 ?
		    this->socket_start_error :
		    this->directory_start_error != 0 ?
		    this->directory_start_error : ECANCELED;
		start.unlock();
		broadcast_shutdown(*this);
		errno = error;
		return (false);
	}
	return (true);
}

void
state::report_directory_start(int error)
{
	{
		std::lock_guard start(this->socket_start_mtx);
		this->directory_start_done++;
		if (error != 0 && this->directory_start_error == 0)
			this->directory_start_error = error;
	}
	this->socket_start_cv.notify_all();
}

bool
state::setup_socket(void)
{
	int err;
	struct sockaddr_un addr;
	size_t l;

	this->sockfd = ::socket(PF_UNIX, SOCK_STREAM, 0);
	if (this->sockfd == -1) {
		ERR("Failed to create unix: %m");
		return (false);
	}

	memset(&addr, 0, sizeof(addr));

	addr.sun_family = PF_UNIX;
	l = strlcpy(addr.sun_path, DTRACED_SOCKPATH, sizeof(addr.sun_path));
	if (l >= sizeof(addr.sun_path)) {
		ERR("failed to copy %s into sockaddr (%zu)", DTRACED_SOCKPATH,
		    l);
		close(this->sockfd);
		this->sockfd = -1;

		return (false);
	}

	if (remove(DTRACED_SOCKPATH) != 0) {
		if (errno != ENOENT) {
			ERR("failed to remove %s: %m", DTRACED_SOCKPATH);
			close(this->sockfd);
			this->sockfd = -1;
			return (false);
		}
	}

	err = bind(this->sockfd, (struct sockaddr *)&addr, sizeof(addr));
	if (err != 0) {
		ERR("failed to bind to %d: %m", this->sockfd);
		close(this->sockfd);
		this->sockfd = -1;

		return (false);
	}

	return (true);
}

bool
state::initialize(int ctrlmachine, int nosha, int n_threads, const char **argv,
    const char *release_private_path, const char *release_peer_path)
{
	bool socket_ready = false;
	bool directories_ready = false;
	bool fresh_namespace = false;
	this->sockfd = -1;
	this->dtt_fd = -1;
	this->kq_hdl = -1;
	this->ctrlmachine = ctrlmachine;
	this->argv = argv;
	this->nosha = nosha;
	this->threadpool_size = n_threads;
	if ((release_private_path == nullptr) !=
	    (release_peer_path == nullptr) ||
	    ((release_private_path != nullptr || release_peer_path != nullptr) &&
	    ctrlmachine == 0)) {
		errno = EINVAL;
		return (false);
	}
	if (release_private_path != nullptr &&
	    !this->handoff_keys.load(release_private_path, release_peer_path)) {
		ERR("failed to load HyperTrace host keys: %m");
		return (false);
	}

	if (this->ctrlmachine == 0) {
		this->dtt_fd = open("/dev/dttransport",
		    O_RDWR | O_CLOEXEC | O_NONBLOCK);
		if (this->dtt_fd == -1) {
			ERR("failed to open /dev/dttransport: %m");
			return (false);
		}
	}

	try {
		auto outbound = std::make_unique<dir>(OUTBOUNDDIR,
		    &process_outbound);
		auto inbound = std::make_unique<dir>(INBOUNDDIR,
		    &process_inbound);
		auto base = std::make_unique<dir>(BASEDIR, &process_base);
		if (this->ctrlmachine == 0) {
			dtt_vm_identity startup{};
			if (!validate_guest_recovery_identity(this->dtt_fd,
			    {}, {}, {}, &startup))
				throw std::system_error(errno, std::generic_category(),
				    "guest startup identity");
			if (startup.flags == DTT_IDENTITY_FRESH_PENDING ||
			    startup.flags == DTT_IDENTITY_FRESH_READY ||
			    startup.flags == DTT_IDENTITY_FRESH_ACTIVE) {
				const bool active = startup.flags == DTT_IDENTITY_FRESH_ACTIVE;
				auto select = [&](dir &root) {
					return (active ? root.existing_session(startup.vmid,
					    startup.epoch) : root.fresh_empty_session(startup.vmid,
					    startup.epoch));
				};
				auto fresh_out = select(*outbound);
				if (!fresh_out)
					throw std::system_error(errno, std::generic_category(),
					    "fresh outbound directory");
				auto fresh_in = select(*inbound);
				if (!fresh_in)
					throw std::system_error(errno, std::generic_category(),
					    "fresh inbound directory");
				auto fresh_base = select(*base);
				if (!fresh_base || (!active &&
				    !activate_guest_fresh_session(this->dtt_fd, startup)))
					throw std::system_error(errno, std::generic_category(),
					    "fresh session activation");
				outbound = std::move(fresh_out);
				inbound = std::move(fresh_in);
				base = std::move(fresh_base);
				fresh_namespace = true;
			}
		}
		this->outbounddir = outbound.get();
		this->inbounddir = inbound.get();
		this->basedir = base.get();
		outbound->state = this;
		inbound->state = this;
		base->state = this;
		if (this->setup_socket()) {
			socket_ready = true;
			std::vector<durable_delivery_state> recovered;
			std::vector<durable_delivery_state> guest_records;
			std::vector<durable_consumer_receipt_state> host_receipts;
			std::vector<durable_derived_claim> host_claims;
			std::vector<durable_kill> guest_kills;
			bool outbound_ready = outbound->populate_existing() &&
			    outbound->list_deliveries(recovered);
			if (this->ctrlmachine != 0 && outbound_ready) {
				outbound_ready =
				    outbound->list_derived_claims(host_claims);
				/* A spool no record names was never queued to a
				 * forwarder (records precede memorization). */
				outbound->forget_unrecorded_host_spools(recovered);
			}
			bool inbound_ready = inbound->populate_existing() &&
			    inbound->list_deliveries(guest_records);
			if (this->ctrlmachine != 0 && inbound_ready)
				inbound_ready =
				    inbound->recover_consumer_cohorts(guest_records) &&
				    inbound->list_consumer_receipts(host_receipts) &&
				    inbound->recover_consumer_executions(host_receipts) &&
				    inbound->list_consumer_receipts(host_receipts) &&
				    this->recover_collector_owners(host_receipts) &&
				    inbound->forget_unassigned_ingress(guest_records);
			if (this->ctrlmachine != 0 && outbound_ready &&
			    inbound_ready)
				inbound_ready = inbound->audit_derived_claims(
				    *outbound, host_claims, host_receipts, guest_records,
				    true);
			if (this->ctrlmachine != 0 && outbound_ready && inbound_ready &&
			    outbound->retire_completed_fresh_session_acks() != 1)
				ERR("completed fresh-session ACK cleanup deferred: %m");
			if (this->ctrlmachine == 0 && inbound_ready)
				inbound_ready = inbound->list_kills(guest_kills);
			::dtt_vm_identity pending_rekey{};
			if (outbound_ready && inbound_ready && this->ctrlmachine == 0 &&
			    !validate_guest_recovery_identity(this->dtt_fd, recovered,
			    guest_records, guest_kills, &pending_rekey, fresh_namespace)) {
				ERR("guest journal does not match current VM identity: %m");
				outbound_ready = inbound_ready = false;
			}
			if (outbound_ready && inbound_ready &&
			    pending_rekey.flags != 0) {
				if (!recover_guest_rekey(this, pending_rekey)) {
					ERR("cannot reconcile restored guest journals: %m");
					outbound_ready = inbound_ready = false;
				} else {
					recovered.clear();
					guest_records.clear();
					guest_kills.clear();
					outbound_ready = outbound->list_deliveries(recovered);
					inbound_ready = inbound->list_deliveries(guest_records) &&
					    inbound->list_kills(guest_kills);
					if (outbound_ready && inbound_ready &&
					    !validate_guest_recovery_identity(this->dtt_fd,
					    recovered, guest_records, guest_kills))
						outbound_ready = inbound_ready = false;
				}
			}
			dtt_cleanup_state stopped_session{};
			if (outbound_ready && inbound_ready &&
			    this->ctrlmachine == 0 &&
			    !validate_guest_cleanup_recovery_state(this->dtt_fd,
			    inbound->dirfd, &stopped_session)) {
				if (errno == ESHUTDOWN &&
				    wait_guest_fresh_prepare(this, stopped_session))
					this->re_exec();
				ERR("guest cleanup is not safely recovered: %m");
				outbound_ready = inbound_ready = false;
			}
			if (outbound_ready)
				for (const auto &entry : recovered) {
					if (entry.record.scope !=
					    (this->ctrlmachine == 0 ? 2 : 0) ||
					    (entry.record.scope == 2 &&
					    entry.phase != delivery_phase::pending &&
					    entry.phase != delivery_phase::accepted)) {
						errno = EPROTO;
						outbound_ready = false;
						break;
					}
					if (entry.record.scope == 2 &&
					    entry.phase == delivery_phase::pending &&
					    entry.record.journal_version == 4) {
						/* Absence stays unresolved; a mismatch is fatal. */
						if (outbound->verify_pending_outbound(
						    entry.record) < 0) {
							outbound_ready = false;
							break;
						}
					}
					if (entry.record.scope == 2 &&
					    entry.phase == delivery_phase::accepted &&
					    !outbound->retire_accepted_outbound(
					    entry.record)) {
						outbound_ready = false;
						break;
					}
				}
			if (!outbound_ready)
				ERR("failed to recover delivery ledger: %m");
			if (inbound_ready)
				for (const auto &entry : guest_records) {
					if (this->ctrlmachine != 0 &&
					    entry.record.scope == 3 &&
					    (entry.phase == delivery_phase::pending ||
					    entry.phase == delivery_phase::accepted))
						continue;
					if (this->ctrlmachine != 0 ||
					    entry.record.scope != 1) {
						errno = EPROTO;
						inbound_ready = false;
						break;
					}
					if (entry.phase == delivery_phase::terminal) {
						if (!inbound->retire_terminal_delivery(
						    entry.record)) {
							inbound_ready = false;
							break;
						}
						continue;
					}
					guest_delivery delivery{};
					delivery.delivery_id = entry.record.delivery_id;
					delivery.vmid = entry.record.vmid;
					delivery.epoch = entry.record.epoch;
					delivery.program_id = entry.record.program_id;
					delivery.source_id = entry.record.source_id;
					delivery.journal_session_id =
					    entry.record.session_id;
					delivery.journal_version =
					    entry.record.journal_version;
					delivery.payload_digest =
					    entry.record.payload_digest;
					delivery.terminal_sent =
					    entry.phase == delivery_phase::exited;
					delivery.authorized_current = false;
					this->guest_deliveries.push_back(delivery);
				}
			if (!inbound_ready)
				ERR("failed to recover guest delivery ledger: %m");
			if (outbound_ready && inbound_ready &&
			    base->populate_existing()) {
				(void)outbound.release();
				(void)inbound.release();
				(void)base.release();
				directories_ready = true;
			}
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		ERR("failed to allocate daemon directories: %m");
	} catch (const std::system_error &e) {
		errno = e.code().value();
		ERR("failed to open daemon directories: %m");
	}
	if (!directories_ready) {
		this->outbounddir = nullptr;
		this->inbounddir = nullptr;
		this->basedir = nullptr;
		if (socket_ready)
			(void)this->destroy_socket();
		if (this->dtt_fd != -1) {
			close(this->dtt_fd);
			this->dtt_fd = -1;
		}
		return (false);
	}

	if (!this->setup_threads()) {
		ERR("failed to set up threads: %m");
		broadcast_shutdown(*this);
		(void)this->finalize();
		return (false);
	}

	return (true);
}

bool
state::destroy_socket(void)
{
	if (close(this->sockfd) != 0) {
		ERR("failed to close %d: %m", this->sockfd);
		return (false);
	}

	this->sockfd = -1;

	if (remove(DTRACED_SOCKPATH) != 0) {
		ERR("failed to remove %s: %m", DTRACED_SOCKPATH);
		return (false);
	}

	return (true);
}

bool
state::finalize(void)
{
	size_t i;

	/*
	 * Give all the threads a chance to stop.
	 */
	if (this->socktd.joinable())
		this->socktd.join();
	if (this->ctrlmachine == 0) {
		if (this->dtt_listentd.joinable())
		this->dtt_listentd.join();
		if (this->dtt_writetd.joinable())
		this->dtt_writetd.join();
	}

	if (this->inboundtd.joinable())
		this->inboundtd.join();
	if (this->basetd.joinable())
		this->basetd.join();

	{
		std::lock_guard lk(this->dispatched_jobsmtx);
		this->dispatched_jobscv.notify_all();
	}

	for (i = 0; i < this->workers.size(); i++) {
		if (this->workers[i].joinable())
			this->workers[i].join();
	}

	if (this->killtd.joinable())
		this->killtd.join();
	if (this->reaptd.joinable())
		this->reaptd.join();
	{
		std::lock_guard children(this->pidlistmtx);
		for (const auto &[pid, fd] : this->pidfds)
			(void)close(fd);
		this->pidfds.clear();
		this->pid_sources.clear();
		this->pid_deliveries.clear();
		this->pidlist.clear();
	}
	if (this->closetd.joinable())
		this->closetd.join();
	if (this->jobcleantd.joinable())
		this->jobcleantd.join();

	{
		std::lock_guard lk(this->joblistmtx);
		for (; !this->joblist.empty(); this->joblist.pop_front())
			delete this->joblist.front();
	}

	{
		std::lock_guard lk(this->dispatched_jobsmtx);
		for (; !this->dispatched_jobs.empty();
		     this->dispatched_jobs.pop_front())
			delete this->dispatched_jobs.front();
	}

	for (client_fd *client : this->sockfds) {
		this->client_events.remove(client->event_cookie);
		delete client;
	}
	this->sockfds.clear();
	for (client_fd *client : this->deadfds)
		delete client;
	this->deadfds.clear();
	bool kqueue_closed = true;
	if (this->kq_hdl >= 0) {
		kqueue_closed = close(this->kq_hdl) == 0;
		this->kq_hdl = -1;
	}

	delete this->outbounddir;
	delete this->inbounddir;
	delete this->basedir;
	this->outbounddir = nullptr;
	this->inbounddir = nullptr;
	this->basedir = nullptr;

	if (this->socksema_initialized) {
		sem_destroy(&this->socksema);
		this->socksema_initialized = false;
	}

	bool socket_closed = this->destroy_socket();

	if (this->ctrlmachine == 0) {
		close(this->dtt_fd);
		this->dtt_fd = -1;
	}

	return (socket_closed && kqueue_closed);
}

void
_broadcast_shutdown(state &s, const char *errfile, int errline)
{
	fprintf(stderr, "%s (line %d): broadcasting shutdown\n", errfile,
	    errline);
	s.shutdown.store(1);

	{
		std::lock_guard lk(s.dispatched_jobsmtx);
		s.dispatched_jobscv.notify_all();
	}

	{
		std::lock_guard lk(s.killmtx);
		s.killcv.notify_all();
	}

	{
		std::lock_guard lk(s.deadfdsmtx);
		s.jobcleancv.notify_all();
		s.deadfdscv.notify_all();
	}
	s.socket_start_cv.notify_all();
	s.host_elf_cv.notify_all();
	s.vm_identity_cv.notify_all();
}

bool
state::accept_new_connection(void)
{
	int connsockfd;
	__cleanup(closefd_generic) int attest_fd = -1;
	int on = 1;
	dtd_initmsg_t initmsg;
	unsigned char init_wire[DTRACED_INIT_WIRE_SIZE];
	struct hypertrace_vm_attestation attestation = {};

	memset(&initmsg, 0, sizeof(initmsg));

	connsockfd = accept4(this->sockfd, NULL, NULL, SOCK_CLOEXEC);
	if (connsockfd == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
			ERR("accept() failed: %m");
		return (false);
	}

	if (setsockopt(connsockfd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on))) {
		close(connsockfd);
		ERR("setsockopt() failed: %m");
		return (false);
	}

	memset(&initmsg, 0, sizeof(initmsg));
	initmsg.protocol_version = DTRACED_PROTOCOL_VERSION;
	initmsg.kind = DTRACED_KIND_DTRACED;
	dtraced_wire_encode_init(init_wire, &initmsg);
	if (!socket_transfer(connsockfd, init_wire, sizeof(init_wire), true,
	    std::chrono::seconds(2))) {
		close(connsockfd);
		ERR("send() initmsg to connsockfd failed: %m");
		return (false);
	}

	if (!socket_transfer(connsockfd, init_wire, sizeof(init_wire), false,
	    std::chrono::seconds(2))) {
		close(connsockfd);
		ERR("recv() get initmsg failed: %m");
		return (false);
	}
	dtraced_wire_decode_init(&initmsg, init_wire);
	if (!valid_initmsg(initmsg)) {
		close(connsockfd);
		errno = EPROTO;
		ERR("refused client hello (kind %d, subscriptions 0x%jx): %m",
		    (int)initmsg.kind, (uintmax_t)initmsg.subs);
		return (false);
	}
	if (this->ctrlmachine == 1 &&
	    initmsg.kind == DTRACED_KIND_FORWARDER) {
#ifdef DTRACED_HAS_VM_ATTESTATION
		int64_t attest_deadline = dtraced_io_deadline_after(2000);
		if (attest_deadline < 0) {
			close(connsockfd);
			return (false);
		}
		attest_fd = dtraced_io_recv_fd(connsockfd, attest_deadline);
		if (attest_fd < 0 ||
		    ioctl(attest_fd, VM_GET_ATTESTATION, &attestation) != 0 ||
		    attestation.vmid == 0 ||
		    attestation.vmid >= HYPERTRACE_MAX_VMS ||
		    attestation.epoch == 0 ||
		    memchr(attestation.name, '\0', sizeof(attestation.name)) == NULL ||
		    strcmp(attestation.name, initmsg.ident) != 0) {
			close(connsockfd);
			errno = EPERM;
			return (false);
		}
#else
		close(connsockfd);
		errno = EOPNOTSUPP;
		return (false);
#endif
	}

	std::unique_ptr<client_fd> owned;
	std::unique_lock<std::mutex> admission_output;
	std::vector<durable_kill> replay_manifest;
	uintptr_t cookie = 0;
	client_fd *dfdp;
	try {
		owned.reset(new client_fd(this->kq_hdl, connsockfd, initmsg));
		if (owned->kind == DTRACED_KIND_FORWARDER &&
		    (owned->peer_pid <= 0 || owned->peer_uid == (uid_t)-1)) {
			errno = EPERM;
			return (false);
		}
		if (owned->kind == DTRACED_KIND_RELEASE_RECOVERY &&
		    (!this->is_control_machine() || owned->peer_pid <= 1 ||
		    owned->peer_uid != 0 || geteuid() != 0 ||
		    !this->handoff_keys.configured())) {
			/* HT-C BEGIN: disabled trace continuity. */
			errno = EPERM;
			return (false);
			/* HT-C END */
		}
		if (owned->kind == DTRACED_KIND_CONSUMER &&
		    owned->is_subscribed(DTD_SUB_ELFWRITE) &&
		    (owned->peer_pid <= 1 || owned->peer_uid == (uid_t)-1 ||
		    !owned->consumer_birth_valid)) {
			errno = EPERM;
			return (false);
		}
		if (attest_fd >= 0) {
			owned->vm_attestation_fd = attest_fd;
			owned->vmid = attestation.vmid;
			owned->vm_epoch = attestation.epoch;
			attest_fd = -1;
		}
		if (owned->is_subscribed(DTD_SUB_SOURCE_RELEASE)) {
			/* HT-C BEGIN: disabled trace continuity. */
			if (!this->is_control_machine() || owned->vmid == 0) {
				errno = EPERM;
				return (false);
			}
			hypertrace_epoch_query query{};
			query.vmid = owned->vmid;
			query.epoch = owned->vm_epoch;
			owned->vm_epoch_query_fd = open("/dev/dtrace/hypertrace",
			    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
			if (owned->vm_epoch_query_fd < 0 ||
			    ioctl(owned->vm_epoch_query_fd,
			    HYPERTRACE_IOC_EPOCH_QUERY, &query) != 0)
				return (false);
			if (query.live != 1) {
				errno = ESTALE;
				return (false);
			}
			/* HT-C END */
		}
		/* Only the host persists outbound VM ownership for recovery. */
		if (this->ctrlmachine == 1 &&
		    owned->kind == DTRACED_KIND_FORWARDER &&
		    owned->is_subscribed(DTD_SUB_ELFWRITE) &&
		    !this->recover_outbound_deliveries(owned.get()))
			return (false);
		/* Hold the output stream before enabling events.  Replayed KILL
		 * jobs and other workers must not write ahead of the admission ACK. */
		if (owned->is_subscribed(DTD_SUB_ADMISSION_ACK))
			admission_output =
			    std::unique_lock<std::mutex>(owned->output_mtx);
		{
			std::lock_guard gate(this->admission_register_mtx);
			cookie = this->client_events.add(owned.get());
			owned->event_cookie = cookie;
			if (cookie == 0 ||
			    !owned->enable_rw(reinterpret_cast<void *>(cookie))) {
				int saved = errno;
				this->client_events.remove(cookie);
				errno = saved;
				return (false);
			}
			bool duplicate_consumer = false;
			try {
				std::lock_guard lk(this->sockfdsmtx);
				if (owned->kind == DTRACED_KIND_CONSUMER &&
				    owned->is_subscribed(DTD_SUB_ELFWRITE))
					for (client_fd *current : this->sockfds)
						if (!current->retired.load() &&
						    current->kind == DTRACED_KIND_CONSUMER &&
						    current->is_subscribed(DTD_SUB_ELFWRITE) &&
						    current->session_id == owned->session_id) {
							duplicate_consumer = true;
							break;
						}
				if (!duplicate_consumer) {
					owned->consumer_replay_pending =
					    this->ctrlmachine != 0 &&
					    owned->kind == DTRACED_KIND_CONSUMER &&
					    owned->is_subscribed(DTD_SUB_ELFWRITE) &&
					    this->inbounddir != nullptr;
					this->sockfds.insert(owned.get());
				}
			} catch (...) {
				this->client_events.remove(cookie);
				cookie = 0;
				throw;
			}
			if (duplicate_consumer) {
				this->client_events.remove(cookie);
				cookie = 0;
				errno = EEXIST;
				return (false);
			}
			LOG("accept(%d, %x, 0x%jx, %s)", owned->fd, owned->kind,
			    (uintmax_t)owned->subs, owned->ident);
			dfdp = owned.release();
			dfdp->acquire(); /* Admission continues after dispatch resumes. */
		}
	} catch (const std::bad_alloc &) {
		if (!owned)
			close(connsockfd);
		errno = ENOMEM;
		return (false);
	}
	bool ready = true;
	if (dfdp->kind == DTRACED_KIND_FORWARDER &&
	    dfdp->is_subscribed(DTD_SUB_REPLAY_MANIFEST) &&
	    !this->collect_replay_kills(dfdp, replay_manifest)) {
		this->kill_socket(dfdp);
		ready = false;
	} else if (dfdp->kind == DTRACED_KIND_FORWARDER &&
	    dfdp->is_subscribed(DTD_SUB_KILL) &&
	    !dfdp->is_subscribed(DTD_SUB_REPLAY_MANIFEST) &&
	    !this->queue_replay_kills(dfdp)) {
		this->kill_socket(dfdp);
		ready = false;
	}
	if (ready && this->is_control_machine() &&
	    dfdp->kind == DTRACED_KIND_FORWARDER &&
	    dfdp->is_subscribed(DTD_SUB_CLEANUP) &&
	    !this->queue_replay_cleanups(dfdp)) {
		this->kill_socket(dfdp);
		ready = false;
	}
	if (ready && dfdp->is_subscribed(DTD_SUB_INFO) &&
	    !this->send_info_async(dfdp)) {
		this->kill_socket(dfdp);
		ready = false;
	}
	if (ready && dfdp->is_subscribed(DTD_SUB_ADMISSION_ACK)) {
		unsigned char ack = 1;

		if (dfdp->retired.load() || !dfdp->send(&ack, sizeof(ack))) {
			this->kill_socket(dfdp);
			ready = false;
		}
	}
	if (ready && dfdp->is_subscribed(DTD_SUB_REPLAY_MANIFEST)) {
		unsigned char count_wire[4];
		dtraced_wire_put_u32(count_wire,
		    (uint32_t)replay_manifest.size());
		ready = dfdp->send(count_wire, sizeof(count_wire));
		for (const durable_kill &record : replay_manifest) {
			if (!ready)
				break;
			dtraced_replay_kill_t kill{};
			kill.pid = record.pid;
			kill.vmid = record.vmid;
			kill.epoch = record.epoch;
			memcpy(kill.source_id, record.source_id.data(), 16);
			unsigned char wire[DTRACED_REPLAY_KILL_WIRE_SIZE];
			dtraced_wire_encode_replay_kill(wire, &kill);
			ready = dfdp->send(wire, sizeof(wire));
		}
		if (!ready)
			this->kill_socket(dfdp);
	}
	if (admission_output.owns_lock())
		admission_output.unlock();
	/* Resend this channel's pending host deliveries: their first send
	 * failed or the daemon restarted before the guest accepted them. */
	if (ready && this->is_control_machine() &&
	    dfdp->kind == DTRACED_KIND_FORWARDER &&
	    dfdp->is_subscribed(DTD_SUB_ELFWRITE) &&
	    this->outbounddir != nullptr && dfdp->vmid != 0 &&
	    this->outbounddir->queue_pending_host_outbound(dfdp) < 0) {
		ERR("cannot queue pending deliveries: %m");
		this->kill_socket(dfdp);
		ready = false;
	}
	if (ready && dfdp->kind == DTRACED_KIND_FORWARDER &&
	    dfdp->is_subscribed(DTD_SUB_ELFWRITE) && this->outbounddir != nullptr)
		this->outbounddir->request_scan();
	if (ready && this->is_control_machine() &&
	    dfdp->kind == DTRACED_KIND_FORWARDER &&
	    dfdp->is_subscribed(DTD_SUB_ELFWRITE) &&
	    !this->queue_claimed_source_journal_replays(dfdp)) {
		/* HT-C BEGIN: disabled trace continuity. */
		this->kill_socket(dfdp);
		ready = false;
		/* HT-C END */
	}
	if (ready && dfdp->consumer_replay_pending &&
	    this->inbounddir->queue_recovered_consumer(dfdp) < 0) {
		this->kill_socket(dfdp);
		ready = false;
	}
	bool queue_imports = false;
	if (ready && dfdp->consumer_replay_pending) {
		std::lock_guard clients(this->sockfdsmtx);
		dfdp->consumer_replay_pending = false;
		/* HPI1 can arrive while admission replays ordinary HCR1 work.
		 * The registration handler then defers imported HCR2 work; take
		 * that obligation here after the replay gate opens. Both paths
		 * inspect the flag and program identity under sockfdsmtx. */
		if (dfdp->consumer_program_valid &&
		    !dfdp->consumer_import_scan_done &&
		    !dfdp->consumer_import_scan_active) {
			dfdp->consumer_import_scan_active = true;
			queue_imports = true;
		}
	}
	if (ready && queue_imports) {
		int queued = 0;
		if (dfdp->consumer_replay_registration_pending.load())
			queued = this->inbounddir->queue_recovered_consumer(dfdp);
		if (queued >= 0)
			queued = this->inbounddir->queue_activated_import_consumer(dfdp);
		{
			std::lock_guard clients(this->sockfdsmtx);
			dfdp->consumer_import_scan_active = false;
			if (queued >= 0)
				dfdp->consumer_import_scan_done = true;
		}
		if (queued < 0) {
			this->kill_socket(dfdp);
			ready = false;
		}
	}
	if (ready && dfdp->kind == DTRACED_KIND_CONSUMER &&
	    dfdp->is_subscribed(DTD_SUB_ELFWRITE) && this->inbounddir != nullptr)
		this->inbounddir->request_scan();
	dfdp->release();
	return (ready);
}

bool
state::recover_outbound_deliveries(client_fd *client) try
{
	if (client == nullptr || client->kind != DTRACED_KIND_FORWARDER ||
	    !client->is_subscribed(DTD_SUB_ELFWRITE) ||
	    !client->outbound_deliveries.empty() || this->outbounddir == nullptr ||
	    client->vmid == 0 || client->vm_epoch == 0 ||
	    client->peer_pid <= 0 || client->peer_uid == (uid_t)-1 ||
	    !client->current_vm_attestation()) {
		errno = EPROTO;
		return (false);
	}
	std::lock_guard revocations(this->revocationmtx);
	std::vector<durable_delivery_state> records;
	if (!this->outbounddir->list_deliveries(records))
		return (false);
	std::vector<outbound_delivery> restored;
	for (const durable_delivery_state &entry : records) {
		const durable_delivery &record = entry.record;
		if (record.scope != 0 ||
		    (entry.phase != delivery_phase::accepted &&
		    entry.phase != delivery_phase::installed) ||
		    record.session_id != client->session_id ||
		    record.peer_uid != (uint32_t)client->peer_uid ||
		    record.peer_pid != (uint32_t)client->peer_pid ||
		    record.vmid != client->vmid ||
		    record.epoch != client->vm_epoch)
			continue;
		int revoked = this->outbounddir->source_revoked_for_vm(
		    record.source_id.data(), record.vmid, record.epoch);
		if (revoked < 0)
			return (false);
		if (revoked != 0)
			continue;
		if (record.journal_version == 5) {
			/* HT-C BEGIN: disabled trace continuity. */
			bool source_revoked = false;
			int ready = this->outbounddir->bound_handoff_status(record,
			    source_revoked);
			if (ready < 0)
				return (false);
			if (ready == 0 || source_revoked)
				continue;
			/* HT-C END */
		}
		outbound_delivery delivery{};
		delivery.delivery_id = record.delivery_id;
		delivery.program_id = record.program_id;
		delivery.source_id = record.source_id;
		delivery.target_vmid = record.vmid;
		delivery.target_epoch = record.epoch;
		delivery.accepted = true;
		restored.push_back(delivery);
	}
	client->outbound_deliveries.swap(restored);
	return (true);
} catch (const std::bad_alloc &) {
	errno = ENOMEM;
	return (false);
}

/* An imported source receipt may remain pending across a daemon restart or
 * a lost guest queue ACK. Only a claimed, signed HJB1 can replay it, and
 * the job rechecks that authority again before any ELF bytes leave. */
bool
state::queue_claimed_source_journal_replays(client_fd *client) try
{
	if (!this->is_control_machine() || this->outbounddir == nullptr ||
	    client == nullptr || client->retired.load() ||
	    client->kind != DTRACED_KIND_FORWARDER ||
	    !client->is_subscribed(DTD_SUB_ELFWRITE) ||
	    client->vmid == 0 || client->vm_epoch == 0 ||
	    client->peer_pid <= 1 || client->peer_uid == (uid_t)-1 ||
	    !client->current_vm_attestation()) {
		errno = EINVAL;
		return (false);
	}
	std::vector<durable_delivery_state> records;
	if (!this->outbounddir->list_deliveries(records))
		return (false);
	for (const auto &entry : records) {
		const durable_delivery &record = entry.record;
		if (record.scope != 0 || record.journal_version != 5 ||
		    entry.phase != delivery_phase::pending ||
		    record.session_id != client->session_id ||
		    record.peer_uid != (uint32_t)client->peer_uid ||
		    record.peer_pid != (uint32_t)client->peer_pid ||
		    record.vmid != client->vmid ||
		    record.epoch != client->vm_epoch)
			continue;
		/* HT-C BEGIN: disabled trace continuity. */
		durable_handoff ticket{};
		int phase = this->outbounddir->handoff_status(
		    record.handoff_token, ticket);
		if (phase < 0)
			return (false);
		if (phase == (int)handoff_phase::reserved ||
		    phase == (int)handoff_phase::mutating)
			continue;
		if (phase != (int)handoff_phase::claimed ||
		    ticket.destination_vmid != record.vmid ||
		    ticket.destination_epoch != record.epoch ||
		    ticket.source_session != record.source_session) {
			errno = EPROTO;
			return (false);
		}
		int queued = this->outbounddir->
		    queue_claimed_source_journal_replay(record);
		if (queued != 1) {
			if (queued == 0)
				errno = ESTALE;
			return (false);
		}
		/* HT-C END */
	}
	return (true);
} catch (const std::bad_alloc &) {
	errno = ENOMEM;
	return (false);
}

bool
state::collect_replay_kills(client_fd *client,
    std::vector<durable_kill> &records) try
{
	/* The admission output lock is already held. A KILL committed after
	 * this scan is queued as a live job and cannot overtake the manifest. */
	std::lock_guard revocations(this->revocationmtx);
	if (client == nullptr || this->outbounddir == nullptr ||
	    client->kind != DTRACED_KIND_FORWARDER || client->vmid == 0 ||
	    client->vm_epoch == 0 || !client->current_vm_attestation()) {
		errno = EINVAL;
		return (false);
	}
	if (!this->outbounddir->list_kills(records))
		return (false);
	records.erase(std::remove_if(records.begin(), records.end(),
	    [client](const durable_kill &record) {
		return (record.vmid != client->vmid ||
		    record.epoch != client->vm_epoch);
	}), records.end());
	if (records.size() > DTRACED_REPLAY_KILL_MAX) {
		errno = E2BIG;
		return (false);
	}
	/* The device binds a digest of the ordered admission manifest.  A
	 * directory scan is not a stable order across daemon restarts, so exact
	 * reconnects must sort the same durable KILL set identically. */
	std::sort(records.begin(), records.end(),
	    [](const durable_kill &a, const durable_kill &b) {
		if (a.vmid != b.vmid)
			return (a.vmid < b.vmid);
		if (a.epoch != b.epoch)
			return (a.epoch < b.epoch);
		if (a.pid != b.pid)
			return (a.pid < b.pid);
		return (a.source_id < b.source_id);
	    });
	return (true);
} catch (const std::bad_alloc &) {
	errno = ENOMEM;
	return (false);
}

bool
state::queue_replay_kills(client_fd *client) try
{
	/* Serialize the scan with live kill subscriber selection/publication. */
	std::lock_guard revocations(this->revocationmtx);
	if (this->outbounddir == nullptr) {
		errno = EINVAL;
		return (false);
	}
	std::vector<durable_kill> records;
	if (!this->outbounddir->list_kills(records))
		return (false);
	if (records.empty())
		return (true);
	std::vector<std::unique_ptr<job>> owned;
	std::list<job *> staged;
	std::lock_guard clients(this->sockfdsmtx);
	if (client->retired.load()) {
		errno = ENOTCONN;
		return (false);
	}
	auto matches_vm = [client](const durable_kill &record) {
		return (client->vmid == 0 ||
		    (client->vmid == record.vmid &&
		    client->vm_epoch == record.epoch));
	};
	size_t matching = std::count_if(records.begin(), records.end(),
	    matches_vm);
	if (matching == 0)
		return (true);
	owned.reserve(matching);
	for (const durable_kill &record : records) {
		if (!matches_vm(record))
			continue;
		auto pending = std::make_unique<job>(KILL, client);
		kill_job &target = pending->kill_get();
		target.pid = record.pid;
		target.vmid = record.vmid;
		target.epoch = record.epoch;
		memcpy(target.source_id, record.source_id.data(), 16);
		owned.push_back(std::move(pending));
		staged.push_back(owned.back().get());
	}
	{
		std::lock_guard jobs(this->joblistmtx);
		this->joblist.splice(this->joblist.end(), staged);
	}
	for (auto &pending : owned)
		(void)pending.release();
	return (client->re_enable_write());
} catch (const std::bad_alloc &) {
	errno = ENOMEM;
	return (false);
}

bool
state::queue_replay_cleanups(client_fd *client) try
{
	if (client == nullptr || this->outbounddir == nullptr ||
	    client->kind != DTRACED_KIND_FORWARDER || client->vmid == 0 ||
	    client->vm_epoch == 0 || !client->current_vm_attestation()) {
		errno = EINVAL;
		return (false);
	}
	std::vector<durable_cleanup> records;
	if (!this->outbounddir->list_pending_cleanups(records))
		return (false);
	std::vector<std::unique_ptr<job>> owned;
	std::list<job *> staged;
	std::lock_guard clients(this->sockfdsmtx);
	if (client->retired.load()) {
		errno = ENOTCONN;
		return (false);
	}
	for (const durable_cleanup &record : records) {
		if (record.vmid != client->vmid ||
		    record.epoch != client->vm_epoch)
			continue;
		auto replay = std::make_unique<job>(CLEANUP, client);
		replay->cleanup_get() = new cleanup_job;
		replay->cleanup_delivery_id = record.delivery_id;
		replay->cleanup_journaled = true;
		owned.push_back(std::move(replay));
		staged.push_back(owned.back().get());
	}
	if (staged.empty())
		return (true);
	{
		std::lock_guard jobs(this->joblistmtx);
		this->joblist.splice(this->joblist.end(), staged);
	}
	for (auto &replay : owned)
		(void)replay.release();
	return (client->re_enable_write());
} catch (const std::bad_alloc &) {
	errno = ENOMEM;
	return (false);
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
bool
state::wake_handoff_source(const client_fd &source)
{
	std::vector<client_fd *> targets;
	try {
		std::lock_guard clients(this->sockfdsmtx);
		targets.reserve(this->sockfds.size());
		for (client_fd *candidate : this->sockfds) {
			bool matching_forwarder =
			    candidate->kind == DTRACED_KIND_FORWARDER &&
			    candidate->is_subscribed(DTD_SUB_ELFWRITE | DTD_SUB_KILL) &&
			    candidate->same_forwarder(source);
			bool host_consumer =
			    candidate->kind == DTRACED_KIND_CONSUMER &&
			    candidate->is_subscribed(DTD_SUB_ELFWRITE);
			if (candidate->retired.load() ||
			    (!matching_forwarder && !host_consumer))
				continue;
			candidate->acquire();
			targets.push_back(candidate);
		}
	} catch (const std::bad_alloc &) {
		for (client_fd *candidate : targets)
			candidate->release();
		errno = ENOMEM;
		return (false);
	}
	bool ready = true;
	for (client_fd *candidate : targets) {
		if (!candidate->retired.load() &&
		    !candidate->re_enable_write()) {
			ready = false;
			this->kill_socket(candidate);
		}
		candidate->release();
	}
	/* A source-fenced host ingress spool stays unmemorized during PREPARE.
	 * Revisit it after ABORT even if no directory write follows the cut. */
	if (this->inbounddir != nullptr)
		this->inbounddir->request_scan();
	return (ready);
}
/* HT-C END */

/* Startup inventory is already validated before any consumer worker starts.
 * Unavailable historical ownership stays unproven; it never becomes a stop.
 * Storage corruption and resource exhaustion must not silently skip recovery. */
bool
state::recover_collector_owners(
    const std::vector<durable_consumer_receipt_state> &receipts)
{
	if (!this->is_control_machine() || this->inbounddir == nullptr) {
		errno = EINVAL;
		return (false);
	}
	auto unresolved = [](int error) {
		return (error == EAGAIN || error == ESRCH || error == ESTALE ||
		    error == ENOTTY || error == EOPNOTSUPP);
	};
	for (const auto &entry : receipts) {
		int saved = this->inbounddir->checkpoint_consumer_process_exit(
		    entry.record, this->collector_owners);
		if (saved >= 0)
			continue; // Already durable, or already pinned and still live.
		if (!unresolved(errno))
			return (false);
		int recovered = this->inbounddir->recover_consumer_process(
		    entry.record, this->collector_owners);
		if (recovered != 1) {
			if (!unresolved(errno))
				return (false);
			continue;
		}
		/* Cover exit racing the successful live pin; the periodic worker
		 * retains and checks a still-live process after startup. */
		saved = this->inbounddir->checkpoint_consumer_process_exit(
		    entry.record, this->collector_owners);
		if (saved < 0 && !unresolved(errno))
			return (false);
	}
	return (true);
}

int
state::stop_fresh_session_step(const durable_session_stop &stop)
{
	if (!is_control_machine() || this->inbounddir == nullptr ||
	    this->outbounddir == nullptr) {
		errno = EINVAL;
		return (-1);
	}
	int completed = this->outbounddir->fresh_session_stop_completed(stop);
	if (completed != 0)
		return (completed == 1 ? 0 : -1);
	std::vector<host_ingress_program_evidence> recipients;
	if (this->inbounddir->fresh_session_consumers(*this->outbounddir,
	    stop, recipients) < 0)
		return (-1);
	bool missing_proof = false;
	for (const auto &proof : recipients) {
		int recorded = this->inbounddir->fresh_consumer_stop_receipt(
		    *this->outbounddir, stop, proof, false);
		if (recorded < 0)
			return (-1);
		if (recorded == 1)
			continue;
		client_fd *consumer = nullptr;
		{
			std::lock_guard clients(this->sockfdsmtx);
			for (client_fd *candidate : this->sockfds) {
				if (candidate->retired.load() ||
				    candidate->kind != DTRACED_KIND_CONSUMER ||
				    !candidate->is_subscribed(DTD_SUB_ELFWRITE) ||
				    candidate->consumer_replay_pending ||
				    !candidate->consumer_birth_valid ||
				    !candidate->consumer_program_valid ||
				    candidate->session_id != proof.recipient.consumer_session ||
				    candidate->peer_uid != (uid_t)proof.recipient.consumer_uid ||
				    candidate->peer_pid != (pid_t)proof.recipient.consumer_pid ||
				    memcmp(candidate->consumer_birth.data(),
				    proof.owner_wire.data() + 28, 16) != 0 ||
				    candidate->consumer_program_digest != proof.program_digest)
					continue;
				candidate->acquire();
				consumer = candidate;
				break;
			}
		}
		if (consumer == nullptr) {
			/* Retain an exact live pin across a daemon restart when HPB1
			 * permits it. This is not a stop receipt: even successful pin
			 * recovery cannot prove output workers have stopped. */
			int process_exit = this->inbounddir->checkpoint_consumer_process_exit(
			    proof.recipient, this->collector_owners);
			if (process_exit < 0 && errno == EAGAIN &&
			    this->inbounddir->recover_consumer_process(
			    proof.recipient, this->collector_owners) == 1)
				process_exit = this->inbounddir->checkpoint_consumer_process_exit(
				    proof.recipient, this->collector_owners);
			/* All three facts bind to the immutable registered collector:
			 * durable exit, no descendants at exit, and destruction of its
			 * exact kernel handle. No single fact authorizes a stop. The
			 * receipt publisher rechecks the exact source fence and owner. */
			if (process_exit == 1 &&
			    this->inbounddir->consumer_reaper_exit_status(proof.recipient) == 1 &&
			    this->inbounddir->consumer_kernel_handle_retired(proof.recipient) == 1) {
				if (this->inbounddir->fresh_consumer_stop_receipt(
				    *this->outbounddir, stop, proof, true) != 1)
					return (-1);
				continue;
			}
			/* A missing socket is not proof that its process or inherited
			 * handles stopped. Keep the epoch fenced, but still stop later
			 * connected recipients rather than starving them behind a crash. */
			missing_proof = true;
			continue;
		}
		dtraced_consumer_stop_t challenge{};
		memcpy(challenge.token, stop.token.data(), 16);
		memcpy(challenge.source_session, stop.source_session.data(), 16);
		memcpy(challenge.consumer_session, proof.recipient.consumer_session.data(), 16);
		memcpy(challenge.program_digest, proof.program_digest.data(), 32);
		challenge.vmid = stop.vmid;
		challenge.epoch = stop.epoch;
		bool stopped = consumer->request_consumer_stop(challenge);
		int error = stopped ? 0 : (errno != 0 ? errno : EIO);
		/* The collector also commits on a separate authenticated connection.
		 * Resolve a lost reply if that durable proof is already available;
		 * otherwise a later coordinator retry must establish completion. */
		if (!stopped) {
			int recorded = this->inbounddir->fresh_consumer_stop_receipt(
			    *this->outbounddir, stop, proof, false);
			if (recorded == 1)
				error = 0;
			else if (recorded < 0)
				error = errno != 0 ? errno : EIO;
			else if (error == EPIPE || error == ECONNRESET ||
			    error == ENOTCONN || error == ETIMEDOUT)
				error = EAGAIN;
		}
		if (stopped && this->inbounddir->fresh_consumer_stop_receipt(
		    *this->outbounddir, stop, proof, true) != 1)
			error = errno != 0 ? errno : EIO;
		if (error == 0 || error == EAGAIN)
			this->kill_socket(consumer);
		consumer->release();
		if (error != 0)
			errno = error;
		return (error == 0 ? 1 : -1);
	}
	if (missing_proof) {
		errno = EAGAIN;
		return (-1);
	}
	return (this->inbounddir->complete_fresh_session_stop(
	    *this->outbounddir, stop) == 1 ? 0 : -1);
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
void
state::retire_handoff_consumers(uint16_t vmid, uint64_t epoch)
{
	std::lock_guard jobs(this->joblistmtx);
	for (auto it = this->joblist.begin(); it != this->joblist.end();) {
		job *pending = *it;
		if (pending->kind != NOTIFY_ELFWRITE ||
		    pending->connsockfd->kind != DTRACED_KIND_CONSUMER ||
		    pending->handoff_vmid != vmid ||
		    pending->handoff_epoch != epoch) {
			++it;
			continue;
		}
		it = this->joblist.erase(it);
		delete pending;
	}
}
/* HT-C END */

void
state::kill_socket(client_fd *dfdp)
{
	client_fd &dfd = *dfdp;
	bool out_of_memory = false;
	{
		std::lock_guard lk(this->sockfdsmtx);
		if (dfd.retired.exchange(true))
			return;
		if (dfd.kind == DTRACED_KIND_FORWARDER &&
		    dfd.is_subscribed(DTD_SUB_READDATA)) {
			for (client_fd *peer : this->sockfds) {
				if (peer == dfdp || peer->retired.load() ||
				    peer->kind != DTRACED_KIND_FORWARDER ||
				    !peer->is_subscribed(DTD_SUB_ELFWRITE) ||
				    !peer->same_forwarder(dfd))
					continue;
				std::lock_guard deliveries(peer->installed_mtx);
				for (outbound_delivery &item : peer->outbound_deliveries)
					if (item.observer_connection == dfd.id) {
						item.observed = false;
						item.observer_connection = 0;
						item.observation = {};
					}
			}
		}
		this->client_events.remove(dfd.event_cookie);

		/* EV_ENABLE without EV_ADD cannot resurrect retired filters. */
		for (int filter : {EVFILT_READ, EVFILT_WRITE}) {
			struct kevent change;
			EV_SET(&change, dfd.fd, filter, EV_DELETE, 0, 0,
			    nullptr);
			if (kevent(this->kq_hdl, &change, 1, nullptr, 0,
			    nullptr) == -1 && errno != ENOENT && errno != EBADF)
				ERR("retire socket event failed: %m");
		}
		dfd.shutdown();
		std::unique_lock dead_lock(this->deadfdsmtx);
		try {
			this->deadfds.insert(dfdp);
			this->sockfds.erase(dfdp);
			this->deadfds_generation++;
			this->jobcleancv.notify_all();
			this->deadfdscv.notify_all();
		} catch (const std::bad_alloc &) {
			/* sockfds retains ownership until finalization. */
			out_of_memory = true;
		}
	}
	if (out_of_memory) {
		errno = ENOMEM;
		broadcast_shutdown(*this);
	}
}

bool
state::send_info_async(client_fd *dfdp)
{
	try {
		auto item = std::make_unique<job>(SEND_INFO, dfdp);
		std::unique_lock lk(this->joblistmtx);
		this->joblist.push_back(item.get());
		item.release();
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
	/* Admission armed EVFILT_WRITE before this job existed; a write event
	 * consumed meanwhile disabled it with nothing to dispatch. Re-arm it,
	 * as every other job producer does, so the queued job is delivered. */
	return (dfdp->re_enable_write());
}

int
state::socket(void)
{

	return (this->sockfd);
}

bool
state::is_control_machine(void)
{

	return (this->ctrlmachine != 0);
}

[[noreturn]] void
state::re_exec(void)
{

	execve(this->argv[0], (char *const *)this->argv, NULL);
	abort();
}

bool
state::handle_event(struct kevent &event)
{
	int efd = event.ident;

	client_fd *dfdp = this->client_events.lookup(
	    reinterpret_cast<uintptr_t>(event.udata), efd);
	if (dfdp == nullptr)
		return (true); /* Stale event from a retired connection. */
	std::unique_ptr<client_fd, void (*)(client_fd *)> reference(dfdp,
	    [](client_fd *client) { client->release(); });
	if (event.flags & (EV_ERROR | EV_EOF)) {
		this->kill_socket(dfdp);
		return (true);
	}
	/* Dispatch retains its own job reference before this guard is released. */
	struct kevent dispatch = event;
	dispatch.udata = dfdp;
	bool ok;
	if (event.filter == EVFILT_READ)
		ok = this->dispatch_read(dfdp, dispatch);
	else if (event.filter == EVFILT_WRITE)
		ok = this->dispatch_write(dfdp, dispatch);
	else
		ok = false;
	if (!ok)
		this->kill_socket(dfdp);
	return (ok);
}

void
state::process_consumers(void)
{
	int new_events, err, sockfd, flags;
	__cleanup(closefd_generic) int kq = -1;
	struct timespec ts;
	struct kevent event[1] = { {} };
	std::array<std::thread, 4> admissions;
	auto report_start = [this](int error) {
		{
			std::lock_guard start(this->socket_start_mtx);
			this->socket_start_error = error;
			this->socket_start_done = true;
		}
		this->socket_start_cv.notify_all();
	};

	sockfd = this->sockfd;
	if (sockfd == -1) {
		report_start(EBADF);
		broadcast_shutdown(*this);
		return;
	}

	err = listen(sockfd, DTRACED_BACKLOG_SIZE);
	if (err != 0) {
		int error = errno;
		ERR("failed to listen on %d: %m", sockfd);
		report_start(error);
		broadcast_shutdown(*this);
		return;
	}
	flags = fcntl(sockfd, F_GETFL);
	if (flags < 0 || fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) != 0) {
		int error = errno;
		ERR("failed to make listening socket nonblocking: %m");
		report_start(error);
		broadcast_shutdown(*this);
		return;
	}

	kq = kqueue();
	if (kq == -1) {
		int error = errno;
		ERR("failed to create dtraced socket kqueue: %m");
		report_start(error);
		broadcast_shutdown(*this);
		return;
	}

	this->kq_hdl = kq;
	kq = -1; /* finalize owns the kqueue after worker startup. */
	int admission_error = 0;
	try {
		for (std::thread &worker : admissions)
			worker = std::thread([this, sockfd] {
				while (!this->shutdown.load()) {
					struct pollfd watch = { sockfd, POLLIN, 0 };
					int ready = poll(&watch, 1, 100);
					if (ready < 0 && errno == EINTR)
						continue;
					if (ready < 0 ||
					    (ready > 0 &&
					    (watch.revents & (POLLERR | POLLHUP | POLLNVAL)))) {
						if (!this->shutdown.load())
							broadcast_shutdown(*this);
						return;
					}
					if (ready > 0 && (watch.revents & POLLIN) &&
					    !this->accept_new_connection() &&
					    errno != EAGAIN && errno != EWOULDBLOCK &&
					    errno != EINTR)
						ERR("failed to admit connection: %m");
				}
			});
	} catch (const std::system_error &e) {
		admission_error = e.code().value();
	} catch (const std::bad_alloc &) {
		admission_error = ENOMEM;
	}
	if (admission_error != 0) {
		report_start(admission_error);
		broadcast_shutdown(*this);
	}
	if (this->shutdown.load()) {
		if (admission_error == 0)
			report_start(ECANCELED);
		for (std::thread &worker : admissions)
			if (worker.joinable())
				worker.join();
		return;
	}
	if (sem_post(&this->socksema) != 0) {
		int error = errno;
		report_start(error);
		broadcast_shutdown(*this);
		for (std::thread &worker : admissions)
			if (worker.joinable())
				worker.join();
		return;
	}
	report_start(0);

	ts.tv_sec = DTRACED_EVENTSLEEPTIME;
	ts.tv_nsec = 0;
	for (;;) {
		new_events = dtraced::event(*this, this->kq_hdl, NULL, 0,
		    event, 1, &ts);

		if (this->shutdown.load())
			break;

		if (new_events == -1) {
			ERR("dtraced::event failed: %m");
			broadcast_shutdown(*this);
			break;
		}

		for (int i = 0; i < new_events; i++) {
			std::lock_guard gate(this->admission_register_mtx);
			if (!this->handle_event(event[i]))
				ERR("failed to handle event");
		}
	}
	for (std::thread &worker : admissions)
		if (worker.joinable())
			worker.join();

	return;
}

bool
state::dispatch_read(client_fd *dfdp, struct kevent &event)
{
	/*
	 * Disable the EVFILT_READ event so we don't get spammed by it.
	 */
	if (disable_fd(this->kq_hdl, dfdp->fd, EVFILT_READ)) {
		ERR("disable_fd() failed with: %m");
		return (false);
	}

	/*
	 * If the file descriptor did not state it ever wants READDATA to work
	 * on dtraced, we will simply ignore it and report a warning.
	 */
	if (!dfdp->is_subscribed(DTD_SUB_READDATA) &&
	    !dfdp->is_subscribed(DTD_SUB_SOURCE_RELEASE) &&
	    !dfdp->is_subscribed(DTD_SUB_RELEASE_RECOVERY)) {
		/* An identified host consumer registers its program (HPI1/HPI2)
		 * on its ELF receiver before any delivery can reach it; that
		 * frame needs a reader, or dtrace -E waits for its status until
		 * it times out. read_data() accepts only the registration here. */
		if (dfdp->kind == DTRACED_KIND_CONSUMER &&
		    dfdp->is_subscribed(DTD_SUB_ELFWRITE) &&
		    dfdp->consumer_birth_valid &&
		    !dfdp->consumer_registration_acked.load()) {
			if (!this->dispatch_event(event)) {
				ERR("dispatch_event() failed");
				return (false);
			}
			return (true);
		}
		/* ELF forwarders and registered host consumers return their
		 * acknowledgments to the sending worker on this socket. */
		if (!((dfdp->kind == DTRACED_KIND_FORWARDER ||
		    dfdp->kind == DTRACED_KIND_CONSUMER) &&
		    dfdp->is_subscribed(DTD_SUB_ELFWRITE)))
			WARN("socket %d sent unexpected data (%lx)",
			    dfdp->fd, dfdp->subs);
		return (true);
	}

	if (!this->dispatch_event(event)) {
		ERR("dispatch_event() failed");
		return (false);
	}

	return (true);
}

bool
state::dispatch_write(client_fd *dfdp, struct kevent &event)
{
	client_fd &dfd = *dfdp;

	if (disable_fd(this->kq_hdl, dfd.fd, EVFILT_WRITE)) {
		ERR("disable_fd() failed with: %m");
		return (false);
	}

	bool dispatch = false;

	std::unique_lock lk(this->joblistmtx);
	for (job *job : this->joblist) {
		if (job->connsockfd == dfdp)
			dispatch = true;
	}

	/*
	 * If we have a job to dispatch to the socket, we tell a worker thread
	 * to actually do the action.
	 */
	if (dispatch && !this->dispatch_event(event)) {
		ERR("dispatch_event() failed");
		/*
		 * Necessary because broadcast_shutdown acquires a few locks.
		 */
		lk.unlock();
		return (false);
	}

	return (true);
}

bool
state::dispatch_event(struct kevent &event)
{
	client_fd *dfdp;
	job *j;
	int efd;

	efd = (int)event.ident;

	if (event.filter == EVFILT_READ) {
		dfdp = (client_fd *)event.udata;

		/*
		 * Read is a little bit more complicated than write, because we
		 * have to read in the actual event and put it in the
		 * /var/ddtrace/base directory for the directory monitoring
		 * kqueues to wake up and process it further.
		 */
		try {
			auto pending = std::make_unique<job>(READ_DATA, dfdp);
			std::lock_guard lk(this->dispatched_jobsmtx);
			this->dispatched_jobs.push_front(pending.get());
			pending.release();
			this->dispatched_jobscv.notify_all();
		} catch (const std::bad_alloc &) {
			errno = ENOMEM;
			return (false);
		}

	} else if (event.filter == EVFILT_WRITE) {
		/*
		 * Go through the joblist, and if we find a job which has our
		 * file descriptor as the destination, we put it in the dispatch
		 * list.
		 */

		/* The caller holds joblistmtx.  Splice keeps the existing node. */
		for (auto it = this->joblist.begin();
		     it != this->joblist.end();) {
			j = *it;
			client_fd &dfd = *j->connsockfd;
			if (dfd.fd == efd) {
				std::lock_guard lk(this->dispatched_jobsmtx);
				auto current = it++;
				this->dispatched_jobs.splice(
				    this->dispatched_jobs.end(), this->joblist, current);
				this->dispatched_jobscv.notify_all();
			} else
				++it;
		}

	} else {
		ERR("Unexpected event flags: %d", event.flags);
		return (false);
	}

	return (true);
}

void
state::close_filedescs(void)
{
	std::unique_lock lk(this->deadfdsmtx);
	uint64_t observed = 0;
	collector_owner_key collector_cursor{};
	std::array<collector_owner_key, 32> collector_batch{};
	while (this->shutdown.load() == 0) {
		/* A timeout also catches references released after job cleanup. */
		this->deadfdscv.wait_for(lk,
		    std::chrono::seconds(DTRACED_CLOSEFD_SLEEPTIME), [this, &observed] {
			return (this->shutdown.load() != 0 ||
			    this->deadfds_generation != observed);
		});
		if (this->shutdown.load() != 0)
			break;
		observed = this->deadfds_generation;
		for (auto it = this->deadfds.begin();
		     it != this->deadfds.end();) {
			client_fd *dfdp = *it;

			/* Jobs must be removed and all active users must release. */
			if (!dfdp->can_reap()) {
				++it;
				continue;
			}

			it = this->deadfds.erase(it);
			delete dfdp;
		}
		/* Journal I/O must never hold the socket-retirement mutex. */
		lk.unlock();
		if (this->is_control_machine() && this->inbounddir != nullptr) {
			size_t count = this->collector_owners.batch_after(
			    collector_cursor, collector_batch);
			for (size_t i = 0; i < count && !this->shutdown.load(); i++)
				if (this->inbounddir->checkpoint_collector_exit(
				    collector_batch[i], this->collector_owners) < 0)
					ERR("collector exit checkpoint retained for retry: %m");
		}
		lk.lock();
	}
}

void
state::manage_children(void)
{
	pending_kill request;

	while (1) {
		/*
		 * Wait for a notification that we need to kill a process
		 */
		std::unique_lock lk(this->killmtx);
		this->killcv.wait(lk, [this] {
			return (!this->pids_to_kill.empty() ||
			    this->shutdown.load());
		});

		/*
		 * No need to unlock here due to RAII.
		 */
		if (unlikely(this->shutdown.load()))
			return;

		request = this->pids_to_kill.front();
		this->pids_to_kill.pop();
		lk.unlock();

		/* A durable source revocation outlives the PID named by the sender. */
		std::lock_guard child_lock(this->pidlistmtx);
		if (request.pid <= 1 ||
		    this->revoked_sources.find(request.source_id) ==
		    this->revoked_sources.end())
			continue;
		for (const auto &[pid, source] : this->pid_sources) {
			if (pid <= 1 || source != request.source_id ||
			    this->pidlist.find(pid) == this->pidlist.end())
				continue;
			LOG("kill %d", pid);
			auto fd = this->pidfds.find(pid);
			int error = fd == this->pidfds.end() ? kill(pid, SIGTERM) :
			    pdkill(fd->second, SIGTERM);
			if (error != 0 && errno != ESRCH)
				ERR("cannot terminate child %d: %m", pid);
		}
		/* Keep ownership until waitpid() reaps it, including repeat requests. */
	}
}

void
state::reap_children(void)
{
	int status, rv;

	for (;;) {
		usleep(DTRACED_SLEEPTIME * 100);
		for (;;) {
			bool reaped = false, notify = false, failed = false;
			guest_delivery delivery{};
			{
				/* Preserve install-before-exit order even for short children. */
				std::lock_guard events(this->install_event_mtx);
				{
					std::lock_guard child_lock(this->pidlistmtx);
					for (auto it = this->pidlist.begin();
					    it != this->pidlist.end(); ++it) {
						auto fd = this->pidfds.find(*it);
						if (fd != this->pidfds.end())
							rv = pdwait(fd->second, &status,
							    WEXITED | WNOHANG, nullptr, nullptr);
						else
							rv = waitpid(*it, &status, WNOHANG);
						if (!((fd != this->pidfds.end() &&
						    (rv == 0 || (rv == -1 && errno == ESRCH))) ||
						    (fd == this->pidfds.end() &&
						    (rv > 0 || (rv == -1 && errno == ECHILD)))))
							continue;
						if (!this->is_control_machine() &&
						    this->inbounddir != nullptr &&
						    !retire_guest_child(this->inbounddir->dirfd,
						    *it)) {
							failed = true;
							break;
						}
						auto known = this->pid_deliveries.find(*it);
						if (known != this->pid_deliveries.end()) {
							delivery = known->second;
							this->pid_deliveries.erase(known);
							notify = true;
						}
						if (fd != this->pidfds.end()) {
							(void)waitpid(*it, &status, WNOHANG);
							(void)close(fd->second);
							this->pidfds.erase(fd);
						}
						this->pid_sources.erase(*it);
						this->pidlist.erase(it);
						reaped = true;
						break;
					}
				}
				if (notify && !finish_guest_delivery(*this, delivery))
					failed = true;
			}
			if (failed) {
				ERR("cannot report tracing child exit: %m");
				broadcast_shutdown(*this);
				return;
			}
			if (!reaped)
				break;
		}

		if (this->shutdown.load() != 0)
			return;
	}
}

void
state::clean_jobs(void)
{
	int woken;

	while (1) {
		woken = 0;
		std::unique_lock lk(this->deadfdsmtx);
		while (this->shutdown.load() == 0 &&
		    (this->deadfds.empty() || woken == 0)) {
			this->jobcleancv.wait(lk);
			woken = 1;
		}

		if (unlikely(this->shutdown.load() != 0))
			return;

		/*
		 * Delete any jobs that our dead file descriptors have started.
		 * We don't need to do anything with them, as the initiating
		 * process is gone.
		 */
		for (client_fd *dfdp : this->deadfds) {
			client_fd &dfd = *dfdp;

			std::lock_guard lk(this->joblistmtx);
			for (auto it = this->joblist.begin();
			     it != this->joblist.end();) {
				job *j = *it;
				if (j->initiator() == dfd.id || j->connsockfd == dfdp) {
					it = this->joblist.erase(it);
					delete j;
				} else
					++it;
			}
			dfd.cleaned_up = true;
		}
		this->deadfds_generation++;
		this->deadfdscv.notify_all();
	}
}

bool
state::handle_job(job *j)
{
	switch (j->kind) {
	case READ_DATA:
		return (j->read_data(*this));

	case KILL:
		return (j->send_kill(*this));

	case NOTIFY_ELFWRITE:
		return (j->send_elf());

	case CLEANUP:
		return (j->send_cleanup(*this));

	case SEND_INFO:
		return (j->send_info(*this));

	default:
		ERR("unknown job: %d", j->kind);
		abort();
	}

	// XXX: Waiting for C++23.
	// std::unreachable();
	return (false);
}

void
state::process_joblist(void)
{
	job *curjob;

	while (1) {
		std::unique_lock lk(this->dispatched_jobsmtx);
		this->dispatched_jobscv.wait(lk, [this] {
			return (!this->dispatched_jobs.empty() ||
			    this->shutdown.load() != 0);
		});

		if (unlikely(this->shutdown.load() != 0))
			break;

		curjob = this->dispatched_jobs.front();
		this->dispatched_jobs.pop_front();
		lk.unlock();

		if (!curjob->connsockfd->retired.load() &&
		    !this->handle_job(curjob)) {
			if (curjob->handoff_deferred &&
			    !curjob->connsockfd->retired.load()) {
				/* HT-C BEGIN: disabled trace continuity. */
				client_fd *client = curjob->connsockfd;
				uint16_t vmid = curjob->handoff_vmid != 0 ?
				    curjob->handoff_vmid : client->vmid;
				uint64_t epoch = curjob->handoff_vmid != 0 ?
				    curjob->handoff_epoch : client->vm_epoch;
				bool consumer = curjob->handoff_vmid != 0;
				/* The handoff lock makes the phase check and requeue
				 * atomic with COMMIT retirement and ABORT wakeup. */
				client->acquire();
				bool queued = false;
				int phase = -1;
				int phase_error = 0;
				try {
					if (this->outbounddir != nullptr)
						phase = this->outbounddir->
						    with_source_handoff_phase(vmid, epoch,
						    [&](int current) {
							if (consumer && current > 0 &&
							    current !=
							    (int)handoff_phase::prepared)
								return;
							std::lock_guard jobs(
							    this->joblistmtx);
							this->joblist.push_back(curjob);
							queued = true;
						    });
					phase_error = errno;
				} catch (const std::bad_alloc &) {
					errno = ENOMEM;
				}
				if (queued) {
					if (phase > 0) {
						client->release();
						continue;
					}
					if (phase == 0 && !client->retired.load() &&
					    client->re_enable_write()) {
						client->release();
						continue;
					}
					this->kill_socket(client);
					client->release();
					continue;
				}
				if (consumer && phase < 0 && phase_error == ECANCELED) {
					/* Retire queued old work without losing the socket
					 * needed to prove this collector has stopped. */
					if (!client->re_enable_write())
						this->kill_socket(client);
					client->release();
					delete curjob;
					continue;
				}
				client->release();
				if (consumer && phase > 0 &&
				    phase != (int)handoff_phase::prepared) {
					delete curjob;
					continue;
				}
				/* HT-C END */
			}
			ERR("failed to handle job kind %d", curjob->kind);
			/* The job's reference pins the client through retirement. */
			this->kill_socket(curjob->connsockfd);
		}
		delete curjob;
	}
}

}
