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

#include <algorithm>
#include <sys/ioctl.h>
#include <sys/hypertrace.h>
#include <sys/hypertrace_wire.h>
#include <openssl/sha.h>

#include <list>
#include <algorithm>
#include <memory>
#include <new>
#include <vector>

#include "dtraced.h"
#include "dtraced_wire.h"
#include "dtraced_transfer_wire.h"
#include "dtraced_derived.h"
#include "dtraced_protocol.h"
#include "dtraced_clientrequest.h"
#include "dtraced_connection.h"

#include "dtraced_directory.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_state.h"
#include "dtraced_process.h"

static_assert(DTRACED_WIRE_MAX_VMS == HYPERTRACE_MAX_VMS,
    "dtraced wire VM-ID limit must match HyperTrace");
static_assert(DTRACED_MSGHDRSIZE + DTRACED_HANDOFF_IMPORT_BINDING_SIZE +
    DTRACED_TRANSFER_MAX_SIZE <=
    dtraced::max_request_bytes, "HTX1 import must fit one control frame");

namespace dtraced {

/* A refusal names its check for the reader's log (job::read_data()). */
#define	REFUSE(error, check)	this->refuse((error), (check), __LINE__)

static durable_delivery
delivery_from_observation(const client_fd &sender, const dtraced_hdr_t &header)
{
	/* The wire carries an owner/key, not the journal version or payload
	 * digest. Resolve the stored record before changing a durable phase. */
	durable_delivery record{};
	record.session_id = sender.session_id;
	record.delivery_id = header.installed.delivery_id;
	record.vmid = header.installed.vmid;
	record.epoch = header.installed.epoch;
	memcpy(record.program_id.data(), header.installed.program_id, 16);
	memcpy(record.source_id.data(), header.installed.source_id, 16);
	record.peer_uid = sender.peer_uid;
	record.peer_pid = sender.peer_pid;
	return (record);
}

client_request::client_request(state &_s, dtraced_hdr_t &h, uchar *b,
    size_t size, client_fd *sender)
    : s(_s)
    , buf(b)
    , buf_size(size)
    , hdr(h)
    , origin(sender)
{
}

bool
client_request::refuse(int error, const char *check, int line)
{
	this->refused_check = check;
	this->refused_line = line;
	errno = error;
	return (false);
}

bool
client_request::handle_installedmsg(void)
{
	const uint8_t zero_id[DTRACED_PROGRAM_ID_LEN] = {};
	if (this->buf_size != 0 || this->origin == nullptr ||
	    this->origin->kind != DTRACED_KIND_FORWARDER ||
	    !this->origin->is_subscribed(DTD_SUB_READDATA) ||
	    this->origin->retired.load() ||
	    this->hdr.installed.delivery_id == 0 ||
	    this->hdr.installed.vmid == 0 ||
	    this->hdr.installed.vmid >= HYPERTRACE_MAX_VMS ||
	    this->hdr.installed.epoch == 0 ||
	    memcmp(this->hdr.installed.program_id, zero_id,
	    sizeof(zero_id)) == 0 ||
	    memcmp(this->hdr.installed.source_id, zero_id,
	    sizeof(zero_id)) == 0 ||
	    memchr(this->hdr.installed.name, '\0',
	    sizeof(this->hdr.installed.name)) == nullptr ||
	    strcmp(this->hdr.installed.name, this->origin->ident) != 0) {
		return (REFUSE(EPROTO,
		    "INSTALLED from an unexpected peer or VM name"));
	}
	installed_receipt receipt{};
	receipt.delivery_id = this->hdr.installed.delivery_id;
	receipt.vmid = this->hdr.installed.vmid;
	receipt.epoch = this->hdr.installed.epoch;
	memcpy(receipt.program_id.data(), this->hdr.installed.program_id,
	    receipt.program_id.size());
	memcpy(receipt.source_id.data(), this->hdr.installed.source_id,
	    receipt.source_id.size());
	/* The observer cannot name a different VM than its VMM descriptor. */
	if (this->s.is_control_machine() &&
	    (this->origin->vmid != receipt.vmid ||
	    this->origin->vm_epoch != receipt.epoch ||
	    !this->origin->current_vm_attestation())) {
		return (REFUSE(EPROTO, "INSTALLED for another VM lifetime"));
	}
	std::lock_guard revocations(this->s.revocationmtx);
	if (this->s.outbounddir == nullptr) {
		return (REFUSE(EINVAL, "no outbound directory"));
	}
	int revoked = this->s.outbounddir->source_revoked_for_vm(
	    receipt.source_id.data(), receipt.vmid, receipt.epoch);
	if (revoked != 0) {
		if (revoked > 0)
			errno = ECANCELED;
		return (false);
	}
	durable_delivery durable = delivery_from_observation(
	    *this->origin, this->hdr);
	durable_delivery_state stored{};
	int resolved = this->s.outbounddir->resolve_host_delivery(durable,
	    stored);
	int recorded = resolved > 0 ? (int)stored.phase : resolved;
	if (recorded <= 0) {
		if (recorded == 0) errno = ENOENT;
		return (false);
	}
	durable = stored.record;
	if (durable.journal_version == 5) {
		/* HT-C BEGIN: disabled trace continuity. */
		bool source_revoked = false;
		int ready = this->s.outbounddir->bound_handoff_status(durable,
		    source_revoked);
		if (ready != 1 || source_revoked) {
			if (ready == 0) errno = EBUSY;
			if (source_revoked) errno = ECANCELED;
			return (false);
		}
		/* HT-C END */
	}
	std::lock_guard peers(this->s.sockfdsmtx);
	for (client_fd *candidate : this->s.sockfds) {
		if (candidate == this->origin || candidate->retired.load() ||
		    candidate->kind != DTRACED_KIND_FORWARDER ||
		    !candidate->is_subscribed(DTD_SUB_ELFWRITE))
			continue;
		std::lock_guard deliveries(candidate->installed_mtx);
		if (!candidate->same_forwarder(*this->origin)) {
			if (std::any_of(candidate->outbound_deliveries.begin(),
			    candidate->outbound_deliveries.end(),
			    [&](const outbound_delivery &sent) {
				return sent.delivery_id == receipt.delivery_id;
			    })) {
				errno = ENOENT;
				return (false);
			}
			continue;
		}
		for (outbound_delivery &sent : candidate->outbound_deliveries) {
			if (sent.delivery_id != receipt.delivery_id)
				continue;
			if (sent.revoked || sent.retired ||
			    sent.program_id != receipt.program_id ||
			    sent.source_id != receipt.source_id ||
			    (sent.target_vmid != 0 &&
			    (sent.target_vmid != receipt.vmid ||
			    sent.target_epoch != receipt.epoch)) ||
			    (sent.observed &&
			    (sent.observation.vmid != receipt.vmid ||
			    sent.observation.epoch != receipt.epoch))) {
				return (REFUSE(EPROTO,
				    "INSTALLED names another delivery"));
			}
			/* The disk transition must complete before bhyve gets an ACK. */
			if (!this->s.outbounddir->record_delivery(durable,
			    delivery_phase::installed))
				return (false);
			sent.observation = receipt;
			sent.observed = true;
			sent.observer_connection = this->origin->id;
			if (sent.target_vmid == 0) {
				sent.target_vmid = receipt.vmid;
				sent.target_epoch = receipt.epoch;
			}
			return (true);
		}
	}
	/* Repeated observation after a daemon restart uses the durable token. */
	return (this->s.outbounddir->record_delivery(durable,
	    delivery_phase::installed));
}

bool
client_request::handle_uninstalledmsg(void)
{
	const uint8_t zero_id[DTRACED_PROGRAM_ID_LEN] = {};
	if (this->buf_size != 0 || this->origin == nullptr ||
	    this->origin->kind != DTRACED_KIND_FORWARDER ||
	    !this->origin->is_subscribed(DTD_SUB_READDATA) ||
	    this->origin->retired.load() ||
	    this->hdr.installed.delivery_id == 0 ||
	    this->hdr.installed.vmid == 0 ||
	    this->hdr.installed.vmid >= HYPERTRACE_MAX_VMS ||
	    this->hdr.installed.epoch == 0 ||
	    memcmp(this->hdr.installed.program_id, zero_id,
	    sizeof(zero_id)) == 0 ||
	    memcmp(this->hdr.installed.source_id, zero_id,
	    sizeof(zero_id)) == 0 ||
	    memchr(this->hdr.installed.name, '\0',
	    sizeof(this->hdr.installed.name)) == nullptr ||
	    strcmp(this->hdr.installed.name, this->origin->ident) != 0) {
		return (REFUSE(EPROTO,
		    "UNINSTALLED from an unexpected peer or VM name"));
	}
	if (this->s.is_control_machine() &&
	    (this->origin->vmid != this->hdr.installed.vmid ||
	    this->origin->vm_epoch != this->hdr.installed.epoch ||
	    !this->origin->current_vm_attestation())) {
		return (REFUSE(EPROTO, "UNINSTALLED for another VM lifetime"));
	}
	std::lock_guard revocations(this->s.revocationmtx);
	if (this->s.outbounddir == nullptr) {
		return (REFUSE(EINVAL, "no outbound directory"));
	}
	durable_delivery durable = delivery_from_observation(
	    *this->origin, this->hdr);
	durable_delivery_state stored{};
	int resolved = this->s.outbounddir->resolve_host_delivery(durable,
	    stored);
	if (resolved <= 0) {
		if (resolved == 0) errno = ENOENT;
		return (false);
	}
	durable = stored.record;
	if (durable.journal_version == 5) {
		/* HT-C BEGIN: disabled trace continuity. */
		bool source_revoked = false;
		int ready = this->s.outbounddir->bound_handoff_status(durable,
		    source_revoked);
		if (ready != 1) {
			if (ready == 0) errno = EBUSY;
			return (false);
		}
		/* HT-C END */
	}
	if (!this->s.outbounddir->record_delivery(durable,
	    delivery_phase::terminal))
		return (false);
	std::lock_guard peers(this->s.sockfdsmtx);
	for (client_fd *candidate : this->s.sockfds) {
		if (candidate == this->origin || candidate->retired.load() ||
		    candidate->kind != DTRACED_KIND_FORWARDER ||
		    !candidate->is_subscribed(DTD_SUB_ELFWRITE) ||
		    !candidate->same_forwarder(*this->origin))
			continue;
		std::lock_guard deliveries(candidate->installed_mtx);
		for (auto it = candidate->outbound_deliveries.begin();
		    it != candidate->outbound_deliveries.end(); ++it) {
			if (it->delivery_id != this->hdr.installed.delivery_id)
				continue;
			if (memcmp(it->program_id.data(),
			    this->hdr.installed.program_id, 16) != 0 ||
			    memcmp(it->source_id.data(),
			    this->hdr.installed.source_id, 16) != 0 ||
			    (it->target_vmid != 0 &&
			    (it->target_vmid != this->hdr.installed.vmid ||
			    it->target_epoch != this->hdr.installed.epoch)) ||
			    (it->observed &&
			    (it->observation.vmid != this->hdr.installed.vmid ||
			    it->observation.epoch != this->hdr.installed.epoch))) {
				return (REFUSE(EPROTO,
				    "UNINSTALLED names another delivery"));
			}
			if (it->accepted)
				candidate->outbound_deliveries.erase(it);
			else {
				it->retired = true;
				it->observed = false;
				it->observer_connection = 0;
				it->observation = {};
			}
			return (true);
		}
	}
	return (true); /* An already retired delivery is idempotent. */
}

bool
client_request::handle_statusmsg(void)
{
	const uint8_t zero_id[DTRACED_PROGRAM_ID_LEN] = {};
	if (this->buf_size != 0 || this->origin == nullptr ||
	    !this->s.is_control_machine() ||
	    this->origin->kind != DTRACED_KIND_FORWARDER ||
	    !this->origin->is_subscribed(DTD_SUB_READDATA) ||
	    this->origin->retired.load() ||
	    this->hdr.installed.delivery_id == 0 ||
	    this->hdr.installed.vmid == 0 ||
	    this->hdr.installed.vmid >= HYPERTRACE_MAX_VMS ||
	    this->hdr.installed.epoch == 0 ||
	    memcmp(this->hdr.installed.program_id, zero_id, 16) == 0 ||
	    memcmp(this->hdr.installed.source_id, zero_id, 16) == 0 ||
	    memchr(this->hdr.installed.name, '\0',
	    sizeof(this->hdr.installed.name)) == nullptr ||
	    strcmp(this->hdr.installed.name, this->origin->ident) != 0 ||
	    this->origin->vmid != this->hdr.installed.vmid ||
	    this->origin->vm_epoch != this->hdr.installed.epoch ||
	    !this->origin->current_vm_attestation() ||
	    this->s.outbounddir == nullptr) {
		return (REFUSE(EPROTO, "STATUS from an unattested peer"));
	}
	durable_delivery durable = delivery_from_observation(
	    *this->origin, this->hdr);
	std::lock_guard revocations(this->s.revocationmtx);
	durable_delivery_state stored{};
	int resolved = this->s.outbounddir->resolve_host_delivery(durable,
	    stored);
	if (resolved < 0)
		return (false);
	int phase = resolved == 0 ? 0 : (int)stored.phase;
	if (resolved != 0)
		durable = stored.record;
	int revoked = this->s.outbounddir->source_revoked_for_vm(
	    durable.source_id.data(), durable.vmid, durable.epoch);
	if (revoked < 0)
		return (false);
	if (resolved != 0 && durable.journal_version == 5) {
		/* HT-C BEGIN: disabled trace continuity. */
		bool source_revoked = false;
		int ready = this->s.outbounddir->bound_handoff_status(durable,
		    source_revoked);
		if (ready < 0)
			return (false);
		if (ready == 0) {
			this->status_reply.delivery_id = durable.delivery_id;
			this->status_reply.phase = 'u';
			this->status_ready = true;
			return (true);
		}
		revoked |= source_revoked;
		/* HT-C END */
	}
	this->status_reply.delivery_id = durable.delivery_id;
	this->status_reply.phase = (uint8_t)phase;
	this->status_reply.revoked = (uint8_t)(revoked != 0);
	if (revoked == 0 &&
	    (phase == (int)delivery_phase::accepted ||
	    phase == (int)delivery_phase::installed)) {
		bool eligible = false;
		{
		std::lock_guard peers(this->s.sockfdsmtx);
		for (client_fd *candidate : this->s.sockfds) {
			if (candidate == this->origin || candidate->retired.load() ||
			    candidate->kind != DTRACED_KIND_FORWARDER ||
			    !candidate->is_subscribed(DTD_SUB_ELFWRITE) ||
			    !candidate->same_forwarder(*this->origin))
				continue;
			std::lock_guard deliveries(candidate->installed_mtx);
			for (const outbound_delivery &sent :
			    candidate->outbound_deliveries)
				if (sent.delivery_id == durable.delivery_id &&
				    sent.program_id == durable.program_id &&
				    sent.source_id == durable.source_id &&
				    sent.target_vmid == durable.vmid &&
				    sent.target_epoch == durable.epoch &&
				    sent.accepted && !sent.revoked && !sent.retired)
					eligible = true;
		}
		}
		if (!eligible) {
			/* The receive channel may reconnect after this query channel. */
			this->status_reply.phase = 'u';
			this->status_ready = true;
			return (true);
		}
		if (eligible && durable.journal_version >= 4) {
			int verified = this->s.outbounddir->
			    verify_host_delivery_payload(durable);
			if (verified < 0)
				return (false);
			if (verified != 0) {
				memcpy(this->status_reply.digest,
				    durable.payload_digest.data(),
				    sizeof(this->status_reply.digest));
				this->status_reply.replay = 1;
			}
		} else if (eligible &&
		    this->s.outbounddir->hash_identified_data(
		    durable.program_id.data(), durable.source_id.data(),
		    this->status_reply.digest))
			this->status_reply.replay = 1;
	}
	this->status_ready = true;
	return (true);
}

bool
client_request::handle_ingress_statusmsg(void)
{
	const uint8_t zero_id[DTRACED_PROGRAM_ID_LEN] = {};
	if (this->buf_size != 0 || this->origin == nullptr ||
	    !this->s.is_control_machine() ||
	    this->origin->kind != DTRACED_KIND_FORWARDER ||
	    !this->origin->is_subscribed(DTD_SUB_READDATA) ||
	    this->origin->retired.load() ||
	    this->hdr.installed.delivery_id == 0 ||
	    this->hdr.installed.vmid == 0 ||
	    this->hdr.installed.vmid >= HYPERTRACE_MAX_VMS ||
	    this->hdr.installed.epoch == 0 ||
	    memcmp(this->hdr.installed.program_id, zero_id, 16) == 0 ||
	    memcmp(this->hdr.installed.source_id, zero_id, 16) == 0 ||
	    memchr(this->hdr.installed.name, '\0',
	    sizeof(this->hdr.installed.name)) == nullptr ||
	    strcmp(this->hdr.installed.name, this->origin->ident) != 0 ||
	    this->origin->vmid != this->hdr.installed.vmid ||
	    this->origin->vm_epoch != this->hdr.installed.epoch ||
	    !this->origin->current_vm_attestation() ||
	    this->s.inbounddir == nullptr ||
	    this->s.outbounddir == nullptr) {
		return (REFUSE(EPROTO,
		    "INGRESS_STATUS from an unexpected peer"));
	}
	durable_delivery key{};
	key.session_id = this->origin->session_id;
	key.delivery_id = this->hdr.installed.delivery_id;
	key.vmid = this->origin->vmid;
	key.epoch = this->origin->vm_epoch;
	memcpy(key.program_id.data(), this->hdr.installed.program_id, 16);
	memcpy(key.source_id.data(), this->hdr.installed.source_id, 16);
	key.peer_uid = this->origin->peer_uid;
	key.peer_pid = this->origin->peer_pid;
	key.scope = 3;
	/* Hold the outbound KILL snapshot through the inbound receipt lookup.
	 * A second daemon process cannot commit KILL between those two reads. */
	std::lock_guard revocations(this->s.revocationmtx);
	std::lock_guard ingress(this->s.host_ingress_mtx);
	auto source = this->s.outbounddir->lock_source_snapshot(
	    key.source_id.data(), key.vmid, key.epoch);
	if (!source)
		return (false);
	int killed = source->source_revoked() ? 1 : 0;
	durable_delivery_state entry{};
	int found = this->s.inbounddir->lookup_host_ingress(key, entry);
	if (found < 0)
		return (false);
	int revoked = this->s.inbounddir->source_revoked(key.source_id.data());
	if (revoked < 0)
		return (false);
	this->status_reply.delivery_id = key.delivery_id;
	this->status_reply.revoked = (uint8_t)(revoked != 0 || killed != 0);
	if (found != 0) {
		this->status_reply.phase = (uint8_t)entry.phase;
		memcpy(this->status_reply.digest,
		    entry.record.payload_digest.data(), 32);
	}
	this->status_ready = true;
	return (true);
}

bool
client_request::handle_elfmsg(void)
{
	dir *dir;
	durable_delivery host_ingress{};
	dtraced_derived_parent_t derived_parent{};
	durable_derived_claim derived_claim{};
	durable_committed_import_result_state imported_parent{};
	bool derived_outbound = false;
	bool imported_derived_parent = false;
	bool host_guest_elf = this->s.is_control_machine() &&
	    this->origin != nullptr &&
	    this->origin->kind == DTRACED_KIND_FORWARDER;
	std::unique_lock<std::mutex> revocations(
	    this->s.revocationmtx, std::defer_lock);
	std::unique_lock<std::mutex> host_ingress_lock(
	    this->s.host_ingress_mtx, std::defer_lock);
	std::unique_ptr<consumer_outcome_lock> derived_outcome_lock;
	std::unique_ptr<dir::source_transaction> source_live;
	size_t guest_elf_offset = 0;
	const char *location = DTRACED_MSG_LOC(this->hdr);
	if (memchr(location, '\0', DTRACED_LOCSIZE) == nullptr ||
	    DTRACED_MSG_LEN(this->hdr) != this->buf_size)
		return (false);
	std::string loc { location };

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
	const dtraced_hdr_t empty_header{};
	bool has_parent = memcmp(&this->hdr.installed,
	    &empty_header.installed, sizeof(this->hdr.installed)) != 0;
	if (has_parent) {
		if (!this->s.is_control_machine() || loc != "outbound" ||
		    this->origin == nullptr ||
		    this->origin->kind != DTRACED_KIND_CONSUMER ||
		    !this->origin->is_subscribed(DTD_SUB_READDATA) ||
		    this->origin->retired.load() ||
		    this->origin->peer_uid == (uid_t)-1 ||
		    this->origin->peer_pid <= 1 ||
		    this->s.inbounddir == nullptr || this->s.outbounddir == nullptr ||
		    dtraced_derived_parent_from_header(&derived_parent,
		    &this->hdr) != 0 || this->hdr.elf.delivery_id != 0 ||
		    this->hdr.elf.vmid != 0 || this->hdr.elf.epoch != 0 ||
		    this->hdr.elf.ident_present != 0 ||
		    this->hdr.elf.filter_by_vmid != 0 ||
		    memcmp(this->hdr.elf.source_id,
		    derived_parent.source_id, 16) != 0) {
			return (REFUSE(EPROTO,
			    "derived ELF sender, IDs or source"));
		}
		struct hypertrace_vm_envelope target{};
		if (this->buf_size < HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 4) {
			return (REFUSE(EPROTO,
			    "derived ELF shorter than its VM target"));
		}
		hypertrace_envelope_decode(&target, this->buf);
		if (target.magic != HYPERTRACE_TARGET_MAGIC ||
		    target.version != HYPERTRACE_ENVELOPE_VERSION ||
		    target.vmid == 0 || target.vmid >= HYPERTRACE_MAX_VMS ||
		    target.epoch == 0 || target.name_length != 0 ||
		    memcmp(this->buf + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
		    "\177ELF", 4) != 0) {
			return (REFUSE(EPROTO, "derived ELF VM target"));
		}
		uint8_t expected_id[16];
		if (dtraced_derived_program_id(&derived_parent, this->buf,
		    this->buf_size, expected_id) != 0 ||
		    memcmp(this->hdr.elf.program_id, expected_id, 16) != 0) {
			return (REFUSE(EPROTO, "derived ELF program ID"));
		}
		derived_outcome_lock.reset(new (std::nothrow)
		    consumer_outcome_lock(this->s.inbounddir->dirfd));
		if (!derived_outcome_lock) {
			errno = ENOMEM;
			return (false);
		}
		if (!derived_outcome_lock->held())
			return (false);
		/* The parent header has no ingress journal session. The identified
		 * spool name must resolve to exactly one accepted HTD record before
		 * selecting either the local HCR1 or imported HCR2 authority. */
		durable_delivery_state parent_ingress{};
		int parent_phase = this->s.inbounddir->host_ingress_phase(
		    derived_parent.program_id, derived_parent.source_id,
		    &parent_ingress);
		if (parent_phase != (int)delivery_phase::accepted)
			return (parent_phase < 0 ? false : REFUSE(EPROTO,
			    "derived ELF parent ingress not accepted"));
		if (parent_ingress.record.delivery_id !=
		    derived_parent.delivery_id ||
		    parent_ingress.record.vmid != derived_parent.vmid ||
		    parent_ingress.record.epoch != derived_parent.epoch) {
			return (REFUSE(EPROTO,
			    "derived ELF parent delivery, VM or epoch"));
		}
		if (parent_ingress.record.journal_version == 5) {
			/* HT-C BEGIN: disabled trace continuity. */
			int found = this->s.inbounddir->
			    load_activated_import_recipient(
			    parent_ingress.record.handoff_token,
			    parent_ingress.record.session_id,
			    parent_ingress.record.delivery_id,
			    this->origin->session_id,
			    (uint32_t)this->origin->peer_uid,
			    (uint32_t)this->origin->peer_pid,
			    imported_parent);
			if (found != 1) {
				if (found == 0)
					errno = EBUSY;
				return (false);
			}
			if (imported_parent.recipient.ingress.session_id !=
			    parent_ingress.record.session_id ||
			    imported_parent.recipient.ingress.delivery_id !=
			    parent_ingress.record.delivery_id ||
			    imported_parent.recipient.ingress.vmid !=
			    parent_ingress.record.vmid ||
			    imported_parent.recipient.ingress.epoch !=
			    parent_ingress.record.epoch ||
			    imported_parent.recipient.ingress.program_id !=
			    parent_ingress.record.program_id ||
			    imported_parent.recipient.ingress.source_id !=
			    parent_ingress.record.source_id ||
			    imported_parent.recipient.ingress.payload_digest !=
			    parent_ingress.record.payload_digest ||
			    consumer_receipt_no_derived(imported_parent.outcome.phase)) {
				return (REFUSE(EPROTO,
				    "imported derived parent"));
			}
			bool exact_receiver = false;
			{
				std::lock_guard clients(this->s.sockfdsmtx);
				for (client_fd *candidate : this->s.sockfds) {
					if (candidate->retired.load() ||
					    candidate->kind != DTRACED_KIND_CONSUMER ||
					    !candidate->is_subscribed(DTD_SUB_ELFWRITE) ||
					    candidate->consumer_replay_pending ||
					    candidate->session_id !=
					    this->origin->session_id ||
					    candidate->peer_uid !=
					    this->origin->peer_uid ||
					    candidate->peer_pid !=
					    this->origin->peer_pid ||
					    !candidate->consumer_birth_valid ||
					    !candidate->consumer_program_valid ||
					    memcmp(imported_parent.recipient.owner_wire.data()
					    + 28, candidate->consumer_birth.data(), 16) != 0 ||
					    imported_parent.recipient.program_digest !=
					    candidate->consumer_program_digest)
						continue;
					exact_receiver = true;
					break;
				}
			}
			if (!exact_receiver) {
				errno = EAGAIN;
				return (false);
			}
			imported_derived_parent = true;
			/* HT-C END */
		} else if (parent_ingress.record.journal_version != 4) {
			return (REFUSE(EPROTO,
			    "derived ELF parent journal version"));
		}
		/* The write socket has a separate session. Match the exact
		 * accepted ingress through the receiver's durable receipt and
		 * both Unix peer credentials. Ambiguity is a hard failure. */
		std::vector<durable_consumer_receipt_state> receipts;
		if (!imported_derived_parent &&
		    !this->s.inbounddir->list_consumer_receipts(receipts))
			return (false);
		const durable_consumer_receipt_state *matched = nullptr;
		for (const auto &receipt : receipts) {
			const auto &ingress = receipt.record.ingress;
			if (ingress.delivery_id != derived_parent.delivery_id ||
			    ingress.vmid != derived_parent.vmid ||
			    ingress.epoch != derived_parent.epoch ||
			    memcmp(ingress.program_id.data(),
			    derived_parent.program_id, 16) != 0 ||
			    memcmp(ingress.source_id.data(),
			    derived_parent.source_id, 16) != 0 ||
			    memcmp(receipt.record.consumer_session.data(),
			    derived_parent.consumer_session, 16) != 0 ||
			    receipt.record.consumer_uid !=
			    (uint32_t)this->origin->peer_uid ||
			    receipt.record.consumer_pid !=
			    (uint32_t)this->origin->peer_pid)
				continue;
			if (matched != nullptr)
				return (REFUSE(EEXIST,
				    "derived ELF parent has two receipts"));
			matched = &receipt;
		}
		if (!imported_derived_parent && matched == nullptr)
			return (REFUSE(EPERM,
			    "derived ELF parent not received here"));
		if (!imported_derived_parent &&
		    consumer_receipt_no_derived(matched->phase)) {
			return (REFUSE(EPROTO,
			    "derived ELF parent has no derived result"));
		}
		memcpy(derived_claim.consumer_session.data(),
		    derived_parent.consumer_session, 16);
		derived_claim.ingress_delivery_id = derived_parent.delivery_id;
		derived_claim.ingress_vmid = derived_parent.vmid;
		derived_claim.ingress_epoch = derived_parent.epoch;
		memcpy(derived_claim.ingress_program_id.data(),
		    derived_parent.program_id, 16);
		memcpy(derived_claim.ingress_source_id.data(),
		    derived_parent.source_id, 16);
		derived_claim.target_vmid = target.vmid;
		derived_claim.target_epoch = target.epoch;
		memcpy(derived_claim.derived_program_id.data(),
		    this->hdr.elf.program_id, 16);
		if (SHA256(this->buf, this->buf_size,
		    derived_claim.payload_digest.data()) == nullptr)
			return (false);
		if (SHA256(this->buf + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
		    this->buf_size - HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
		    derived_claim.bare_elf_digest.data()) == nullptr)
			return (false);
		durable_delivery_state accepted{};
		if (this->s.inbounddir->lookup_host_ingress(
		    imported_derived_parent ? imported_parent.recipient.ingress :
		    matched->record.ingress, accepted) != 1 ||
		    accepted.phase != delivery_phase::accepted) {
			return (REFUSE(EPROTO,
			    "derived ELF parent ingress not accepted"));
		}
		revocations.lock();
		host_ingress_lock.lock();
		int revoked = this->s.outbounddir->source_revoked_for_vm(
		    derived_parent.source_id, derived_parent.vmid,
		    derived_parent.epoch);
		if (revoked < 0)
			return (false);
		if (revoked != 0)
			return (REFUSE(ECANCELED,
			    "derived ELF source revoked"));
		source_live = this->s.outbounddir->lock_live_source(
		    derived_parent.source_id, derived_parent.vmid,
		    derived_parent.epoch);
		if (!source_live)
			return (false);
		derived_outbound = true;
	}
	if (host_guest_elf) {
		const uint8_t zero_id[DTRACED_PROGRAM_ID_LEN] = {};
		if (loc != "inbound" ||
		    !this->origin->is_subscribed(DTD_SUB_READDATA) ||
		    this->origin->retired.load() ||
		    !this->origin->current_vm_attestation() ||
		    this->hdr.elf.delivery_id == 0 ||
		    memcmp(this->hdr.elf.program_id, zero_id,
		    sizeof(zero_id)) == 0 ||
		    memcmp(this->hdr.elf.source_id, zero_id,
		    sizeof(zero_id)) == 0 ||
		    this->hdr.elf.ident_present != 0 ||
		    this->hdr.elf.filter_by_vmid != 0 ||
		    this->hdr.elf.vmid != 0 ||
		    this->hdr.elf.epoch != 0 ||
		    !parse_guest_elf_envelope(this->buf, this->buf_size,
		    this->origin->vmid, this->origin->vm_epoch,
		    this->origin->ident, guest_elf_offset)) {
			return (REFUSE(EPROTO,
			    "guest ELF header or VM envelope"));
		}
		if (this->s.outbounddir == nullptr) {
			return (REFUSE(EINVAL, "no outbound directory"));
		}
		/* Match the KILL publisher's lock order and keep the source live
		 * through the accepted journal commit. */
		revocations.lock();
		host_ingress_lock.lock();
		host_ingress.session_id = this->origin->session_id;
		host_ingress.delivery_id = this->hdr.elf.delivery_id;
		host_ingress.vmid = this->origin->vmid;
		host_ingress.epoch = this->origin->vm_epoch;
		memcpy(host_ingress.program_id.data(),
		    this->hdr.elf.program_id, 16);
		memcpy(host_ingress.source_id.data(),
		    this->hdr.elf.source_id, 16);
		host_ingress.peer_uid = this->origin->peer_uid;
		host_ingress.peer_pid = this->origin->peer_pid;
		host_ingress.scope = 3;
		host_ingress.journal_version = 4;
		if (SHA256(this->buf + guest_elf_offset,
		    this->buf_size - guest_elf_offset,
		    host_ingress.payload_digest.data()) == nullptr)
			return (false);
		/* Keep KILL publication in every daemon process behind the full
		 * host-ingress transaction, through its accepted journal fsync. */
		source_live = this->s.outbounddir->lock_live_source(
		    host_ingress.source_id.data(), host_ingress.vmid,
		    host_ingress.epoch);
		if (!source_live)
			return (false);
		int revoked = dir->source_revoked(host_ingress.source_id.data());
		if (revoked < 0)
			return (false);
		if (revoked > 0) {
			errno = ECANCELED;
			return (false);
		}
		durable_delivery_state prior{};
		int found = dir->lookup_host_ingress(host_ingress, prior);
		if (found < 0)
			return (false);
		if (found != 0) {
			/* Imported pending ingress has a separate destination
			 * execution lease; a normal ELF retry cannot promote it. */
			if (prior.record.journal_version == 5) {
				/* HT-C BEGIN: disabled trace continuity. */
				errno = EBUSY;
				return (false);
				/* HT-C END */
			}
			if (prior.record.payload_digest !=
			    host_ingress.payload_digest) {
				return (REFUSE(EPROTO,
				    "guest ELF retry with another payload"));
			}
			/* A new attested socket completes the original journal
			 * transaction. It must not create a second ledger entry. */
			host_ingress = prior.record;
		}
		int phase = found != 0 ? (int)prior.phase : 0;
		int related = dir->host_ingress_phase(
		    host_ingress.program_id.data(),
		    host_ingress.source_id.data());
		if (related < 0)
			return (false);
		if ((phase == 0 && related != 0) ||
		    (phase != 0 && related != phase)) {
			errno = EEXIST;
			return (false);
		}
		if (phase == 0) {
			uint8_t orphan_digest[32];
			if (dir->hash_identified_data(
			    host_ingress.program_id.data(),
			    host_ingress.source_id.data(), orphan_digest, true)) {
				/* An artifact without a matching transaction may have
				 * already launched. Never replay it as a new ingest. */
				errno = EEXIST;
				return (false);
			}
			if (errno != ENOENT)
				return (false);
		}
		if (phase == (int)delivery_phase::accepted) {
			/* An exact retry cannot publish a second spool artifact. */
			uint8_t expected[32], actual[32];
			if (SHA256(this->buf, this->buf_size, expected) == nullptr)
				return (false);
			if (!dir->hash_identified_data(
			    host_ingress.program_id.data(),
			    host_ingress.source_id.data(), actual, true)) {
				if (errno != ENOENT)
					return (false);
			} else if (memcmp(actual, expected, sizeof(actual)) != 0) {
				return (REFUSE(EPROTO,
				    "guest ELF retry differs from its spool"));
			}
			return (true);
		}
		if (phase == 0 && !dir->record_delivery(host_ingress,
		    delivery_phase::pending, true))
			return (false);
	}
	/* Prepare the list node before I/O; commit it after durable publication. */
	std::list<state::listed_ident> pending_ident;
	if (!this->s.is_control_machine() &&
	    DTRACED_MSG_IDENT_PRESENT(this->hdr)) {
		state::listed_ident listed;
		std::copy_n(std::begin(DTRACED_MSG_IDENT(this->hdr)),
		    DTRACED_PROGIDENTLEN, std::begin(listed.ident));
		std::copy_n(this->hdr.elf.source_id, listed.source_id.size(),
		    listed.source_id.begin());
		pending_ident.push_back(std::move(listed));
	}

	/* The directory watcher may launch this file as soon as it appears. */
	std::unique_lock ident_guard(this->s.identlistmtx, std::defer_lock);
	bool guest_upload = !this->s.is_control_machine() &&
	    loc == "outbound" && this->s.inbounddir != nullptr;
	if (!pending_ident.empty() || guest_upload)
		ident_guard.lock();
	/* dtt_kill() revokes a source before it stops the guest's processes:
	 * nothing leaves the guest under a revoked source.  dtrace -Y uploads a
	 * derived program's response under the spool's source, its parent's.
	 * dtt_kill() revokes and drops the source's listed identifiers under
	 * identlistmtx, held here from this check through publication and the
	 * splice: the upload and its identifier precede the KILL or are
	 * refused. */
	if (guest_upload) {
		const uint8_t zero_id[DTRACED_PROGRAM_ID_LEN] = {};
		int revoked = memcmp(this->hdr.elf.source_id, zero_id,
		    sizeof(zero_id)) == 0 ? 0 :
		    this->s.inbounddir->source_revoked(this->hdr.elf.source_id);
		if (revoked < 0)
			return (false);
		if (revoked > 0)
			return (REFUSE(ECANCELED, "guest ELF source revoked"));
	}
	DEBUG("write_data(%s, [buf], %zu)", dir->full_path().c_str(), buf_size);
	const uint8_t zero_id[DTRACED_PROGRAM_ID_LEN] = {};
	bool identified = (loc == "inbound" || derived_outbound) &&
	    memcmp(this->hdr.elf.program_id, zero_id, sizeof(zero_id)) != 0;
	const uint8_t *source_id =
	    memcmp(this->hdr.elf.source_id, zero_id, sizeof(zero_id)) == 0 ?
	    nullptr : this->hdr.elf.source_id;
	/* On the host, "elf.<id>.<source>" in inbound names a journaled guest
	 * upload; the watcher drops such a name without an accepted record. A
	 * local consumer's linked result (dtrace -Y <base>,host) carries no
	 * program ID, so publish it without the lineage suffix: it is delivered
	 * to registered host consumers like any host-local inbound program. */
	if (!identified && loc == "inbound" && this->s.is_control_machine() &&
	    !host_guest_elf)
		source_id = nullptr;
	bool created = true;
	if (!(derived_outbound ? source_live->publish_derived(derived_claim,
	    buf, buf_size, &created) :
	    identified ? dir->write_identified_data(buf, buf_size,
	    this->hdr.elf.program_id, &created, source_id,
	    loc == "inbound" && this->s.is_control_machine()) :
	    source_id != nullptr ? dir->write_data_with_source(buf, buf_size,
	    source_id) : dir->write_data(buf, buf_size))) {
		int publish_error = errno;
		ERR("write_data() failed");
		errno = publish_error;
		return (false);
	}
	if (host_guest_elf) {
		uint8_t expected[32];
		if (SHA256(this->buf, this->buf_size, expected) == nullptr ||
		    !dir->request_reprocess(host_ingress.program_id.data(),
		    host_ingress.source_id.data(), expected, true))
			return (false);
		/* Drop the recovered file's memorization while the pending
		 * journal still fences the watcher. */
		if (!dir->record_delivery(host_ingress,
		    delivery_phase::accepted))
			return (false);
		dir->request_scan();
	}
	if (created && !pending_ident.empty()) {
		this->s.identlist.splice(this->s.identlist.end(), pending_ident);
	}

	return (true);
}

bool
client_request::handle_killmsg(void)
{
	const uint8_t zero_id[DTRACED_PROGRAM_ID_LEN] = {};
	/* Only a local tracing consumer may revoke a source. */
	if (this->buf_size != 0 || this->origin == nullptr ||
	    this->origin->kind != DTRACED_KIND_CONSUMER ||
	    !this->origin->is_subscribed(DTD_SUB_READDATA) ||
	    this->origin->retired.load() ||
	    this->hdr.kill.pid <= 1 || this->hdr.kill.vmid == 0 ||
	    this->hdr.kill.vmid >= HYPERTRACE_MAX_VMS ||
	    this->hdr.kill.epoch == 0 ||
	    memcmp(this->hdr.kill.source_id, zero_id, sizeof(zero_id)) == 0) {
		return (REFUSE(EPROTO,
		    "KILL from a non-consumer or with no target"));
	}
	/* Prepare every subscriber before making the revocation durable. */
	std::list<job *> staged;
	std::vector<std::unique_ptr<job>> owned;
	std::vector<client_fd *> recipients, failed;
	/*
	 * Admission scans the durable kill log under this same lock.  Keep it
	 * across subscriber selection and publication: a new subscriber must
	 * receive either the live job or the replayed record.
	 */
	std::unique_lock revocations(this->s.revocationmtx);
	durable_kill record{};
	record.pid = this->hdr.kill.pid;
	record.vmid = this->hdr.kill.vmid;
	record.epoch = this->hdr.kill.epoch;
	memcpy(record.source_id.data(), this->hdr.kill.source_id, 16);
	std::vector<durable_kill> lineage;
	bool prepared = false;
	if (this->s.outbounddir == nullptr) {
		return (REFUSE(EINVAL, "no outbound directory"));
	}
	bool persisted = this->s.outbounddir->record_kill(record,
	    [&](const std::vector<durable_kill> &records) {
		lineage = records;
		std::lock_guard clients(this->s.sockfdsmtx);
		owned.reserve(this->s.sockfds.size());
		recipients.reserve(this->s.sockfds.size());
		failed.reserve(this->s.sockfds.size());
		for (client_fd *dfdp : this->s.sockfds) {
			client_fd &dfd = *dfdp;
			if (dfd.kind != DTRACED_KIND_FORWARDER ||
			    !dfd.is_subscribed(uint32_t(DTD_SUB_KILL)))
				continue;
			bool matched = false;
			for (const durable_kill &target : records) {
				if (dfd.vmid != 0 &&
				    (dfd.vmid != target.vmid ||
				    dfd.vm_epoch != target.epoch))
					continue;
				auto j = std::make_unique<job>(KILL, dfdp);
				kill_job &k = j->kill_get();
				k.pid = target.pid;
				k.vmid = target.vmid;
				k.epoch = target.epoch;
				memcpy(k.source_id, target.source_id.data(),
				    sizeof(k.source_id));
				owned.push_back(std::move(j));
				staged.push_back(owned.back().get());
				matched = true;
			}
			if (matched)
				recipients.push_back(dfdp);
		}
		prepared = true;
		return (true);
	    });
	int journal_error = persisted ? 0 : errno;
	/* A partially written lineage is fail closed: deliver every prepared
	 * KILL even when the source cannot receive a durable success reply. */
	if (!persisted && !prepared)
		return (false);
	{
		std::lock_guard clients(this->s.sockfdsmtx);
		for (client_fd *dfdp : this->s.sockfds) {
			if (dfdp->kind != DTRACED_KIND_FORWARDER ||
			    !dfdp->is_subscribed(DTD_SUB_ELFWRITE))
				continue;
			std::lock_guard deliveries(dfdp->installed_mtx);
			for (auto it = dfdp->outbound_deliveries.begin();
			    it != dfdp->outbound_deliveries.end();) {
				outbound_delivery &sent = *it;
				bool revoked = std::any_of(lineage.begin(),
				    lineage.end(), [&](const durable_kill &target) {
					return (sent.source_id == target.source_id &&
					    (sent.target_vmid != 0 ?
					    (sent.target_vmid == target.vmid &&
					    sent.target_epoch == target.epoch) :
					    (sent.observed &&
					    sent.observation.vmid == target.vmid &&
					    sent.observation.epoch == target.epoch)));
				});
				if (!revoked) {
					++it;
					continue;
				}
				if (sent.accepted) {
					it = dfdp->outbound_deliveries.erase(it);
					continue;
				}
				sent.revoked = true;
				sent.observed = false;
				sent.observer_connection = 0;
				sent.observation = {};
				++it;
			}
		}
	}
	{
		std::lock_guard clients(this->s.sockfdsmtx);
		std::lock_guard jobs(this->s.joblistmtx);
		this->s.joblist.splice(this->s.joblist.end(), staged);
		for (client_fd *dfdp : recipients) {
			if (!dfdp->retired.load() && !dfdp->re_enable_write()) {
				ERR("re_enable_write() failed with: %m");
				dfdp->acquire();
				failed.push_back(dfdp);
			}
		}
		for (auto &pending : owned)
			(void)pending.release();
	}
	revocations.unlock();
	for (client_fd *dfdp : failed) {
		this->s.kill_socket(dfdp);
		dfdp->release();
	}
	if (!persisted)
		errno = journal_error;
	return (persisted && failed.empty());
}

bool
client_request::handle_kill_appliedmsg(void)
{
	const uint8_t zero_id[DTRACED_PROGRAM_ID_LEN] = {};
	if (this->buf_size != 0 || !this->s.is_control_machine() ||
	    this->origin == nullptr ||
	    this->origin->kind != DTRACED_KIND_FORWARDER ||
	    !this->origin->is_subscribed(DTD_SUB_READDATA) ||
	    this->origin->retired.load() ||
	    this->hdr.kill.pid <= 1 || this->hdr.kill.vmid == 0 ||
	    this->hdr.kill.vmid >= HYPERTRACE_MAX_VMS ||
	    this->hdr.kill.epoch == 0 ||
	    memcmp(this->hdr.kill.source_id, zero_id, sizeof(zero_id)) == 0 ||
	    this->origin->vmid != this->hdr.kill.vmid ||
	    this->origin->vm_epoch != this->hdr.kill.epoch ||
	    !this->origin->current_vm_attestation()) {
		return (REFUSE(EPROTO,
		    "KILL_APPLIED from an unexpected peer or VM"));
	}
	durable_kill record{};
	record.pid = this->hdr.kill.pid;
	record.vmid = this->hdr.kill.vmid;
	record.epoch = this->hdr.kill.epoch;
	memcpy(record.source_id.data(), this->hdr.kill.source_id, 16);
	std::lock_guard revocations(this->s.revocationmtx);
	if (this->s.outbounddir == nullptr) {
		return (REFUSE(EINVAL, "no outbound directory"));
	}
	return (this->s.outbounddir->record_kill_applied(record));
}

bool
client_request::handle_cleanup_appliedmsg(void)
{
	if (this->buf_size != 0 || !this->s.is_control_machine() ||
	    this->origin == nullptr ||
	    this->origin->kind != DTRACED_KIND_FORWARDER ||
	    !this->origin->is_subscribed(DTD_SUB_READDATA) ||
	    this->origin->retired.load() ||
	    this->hdr.cleanup.num_entries != 0 ||
	    this->hdr.cleanup.vmid == 0 ||
	    this->hdr.cleanup.vmid >= HYPERTRACE_MAX_VMS ||
	    this->hdr.cleanup.epoch == 0 ||
	    DTRACED_MSG_CLEANUP_DELIVERY_ID(this->hdr) == 0 ||
	    this->origin->vmid != this->hdr.cleanup.vmid ||
	    this->origin->vm_epoch != this->hdr.cleanup.epoch ||
	    !this->origin->current_vm_attestation() ||
	    this->s.outbounddir == nullptr) {
		return (REFUSE(EPROTO,
		    "CLEANUP_APPLIED from an unexpected peer"));
	}
	durable_cleanup record{};
	record.vmid = this->hdr.cleanup.vmid;
	record.epoch = this->hdr.cleanup.epoch;
	record.delivery_id = DTRACED_MSG_CLEANUP_DELIVERY_ID(this->hdr);
	return (this->s.outbounddir->record_cleanup_applied(record));
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
bool
client_request::handle_release_recovery(void)
{
	if (this->buf == nullptr ||
	    this->buf_size != DTRACED_HANDOFF_WIRE_SIZE ||
	    this->origin == nullptr ||
	    this->origin->kind != DTRACED_KIND_RELEASE_RECOVERY ||
	    this->origin->retired.load() ||
	    this->origin->peer_uid != 0 || this->origin->peer_pid <= 1 ||
	    !this->s.is_control_machine() || this->s.outbounddir == nullptr ||
	    !this->s.handoff_keys.configured()) {
		errno = EPERM;
		return (false);
	}
	dtraced_handoff_request_t request{};
	if (dtraced_wire_decode_handoff(&request, this->buf) != 0 ||
	    request.op != DTRACED_HANDOFF_RELEASE_RECOVER) {
		errno = EPROTO;
		return (false);
	}
	std::array<uint8_t, 16> token{};
	memcpy(token.data(), request.token, token.size());
	durable_handoff ticket{};
	int phase = this->s.outbounddir->handoff_status(token, ticket);
	if (phase < 0)
		return (false);
	if (phase == 0 || phase == (int)handoff_phase::prepared) {
		errno = phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	if (memcmp(ticket.checkpoint_digest.data(), request.digest,
	    ticket.checkpoint_digest.size()) != 0) {
		errno = EPROTO;
		return (false);
	}
	ticket.destination_vmid = 0;
	ticket.destination_epoch = 0;
	if (!this->s.outbounddir->read_source_release_attestation(ticket,
	    this->s.handoff_keys.own_public().data(),
	    this->s.handoff_keys.peer_public().data(), this->release_reply))
		return (false);
	this->release_signed = true;
	this->release_ready = true;
	return (true);
}
/* HT-C END */

bool
client_request::handle_session_stopmsg(bool release)
{
	const std::array<uint8_t, 16> zero{};
	if (this->buf == nullptr ||
	    this->buf_size != DTRACED_SESSION_STOP_WIRE_SIZE ||
	    !this->s.is_control_machine() || this->s.outbounddir == nullptr ||
	    this->s.inbounddir == nullptr || this->origin == nullptr ||
	    this->origin->kind != DTRACED_KIND_FORWARDER ||
	    !this->origin->is_subscribed(DTD_SUB_READDATA) ||
	    this->origin->retired.load() || this->origin->peer_pid <= 1 ||
	    this->origin->peer_uid == (uid_t)-1 ||
	    this->origin->vmid == 0 || this->origin->vmid >= HYPERTRACE_MAX_VMS ||
	    this->origin->vm_epoch == 0 || this->origin->session_id == zero ||
	    !this->origin->current_vm_attestation()) {
		errno = EPERM;
		return (false);
	}
	durable_session_stop stop{};
	if ((release ? dtraced_wire_decode_session_release(stop.token.data(), this->buf) :
	    dtraced_wire_decode_session_stop(stop.token.data(), this->buf)) != 0)
		return (false);
	stop.vmid = this->origin->vmid;
	stop.epoch = this->origin->vm_epoch;
	stop.source_session = this->origin->session_id;
	if (release) {
		if (!this->s.outbounddir->release_fresh_session_gate(stop) ||
		    !this->origin->current_vm_attestation())
			return (false);
		this->drain_step_reply = 0;
		this->drain_step_ready = true;
		return (true);
	}
	/* This verifies gate ownership before creating the durable admission cut.
	 * Retries must retain the same source session and token. */
	if (!this->s.outbounddir->begin_fresh_session_stop(stop))
		return (false);
	int step = this->s.stop_fresh_session_step(stop);
	/* A missing/disconnected collector may be committing proof on another
	 * connection. Yield this worker and report pending, never completion. */
	if (step < 0 && errno == EAGAIN)
		step = 1;
	if (step < 0 || !this->origin->current_vm_attestation())
		return (false);
	/* Completion is already durable. Cleanup failures retain that proof and
	 * are retried by the next exact stop request, never treated as rollback. */
	if (step == 0 && this->s.outbounddir->retire_fresh_session_acks(stop) != 1)
		ERR("fresh-session acknowledgment retirement deferred: %m");
	this->drain_step_reply = (uint8_t)step;
	this->drain_step_ready = true;
	return (true);
}

bool
client_request::handle_consumer_stop_commit(void)
{
	if (this->buf == nullptr ||
	    this->buf_size != DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE ||
	    !this->s.is_control_machine() || this->s.outbounddir == nullptr ||
	    this->s.inbounddir == nullptr || this->origin == nullptr ||
	    this->origin->kind != DTRACED_KIND_CONSUMER ||
	    !this->origin->is_subscribed(DTD_SUB_READDATA) ||
	    this->origin->retired.load() || !this->origin->consumer_birth_valid ||
	    this->origin->peer_uid == (uid_t)-1 || this->origin->peer_pid <= 1) {
		errno = EPERM;
		return (false);
	}
	dtraced_consumer_stop_t proof{};
	if (dtraced_wire_decode_consumer_stop_ack(&proof, this->buf) != 0)
		return (false);
	if (proof.result != 1 || memcmp(proof.consumer_session,
	    this->origin->session_id.data(), 16) != 0) {
		return (REFUSE(EPROTO, "consumer stop proof"));
	}
	durable_session_stop stop{};
	int present = this->s.outbounddir->fresh_session_stop_for_vm(
	    proof.vmid, proof.epoch, stop);
	if (present != 1) {
		if (present == 0)
			errno = ENOENT;
		return (false);
	}
	if (memcmp(proof.token, stop.token.data(), 16) != 0 ||
	    memcmp(proof.source_session, stop.source_session.data(), 16) != 0) {
		errno = ESTALE;
		return (false);
	}
	std::vector<host_ingress_program_evidence> recipients;
	if (this->s.inbounddir->fresh_session_consumers(*this->s.outbounddir,
	    stop, recipients) < 0)
		return (false);
	for (const auto &candidate : recipients) {
		if (candidate.recipient.consumer_session != this->origin->session_id ||
		    candidate.recipient.consumer_uid != (uint32_t)this->origin->peer_uid ||
		    candidate.recipient.consumer_pid != (uint32_t)this->origin->peer_pid ||
		    memcmp(candidate.owner_wire.data() + 28,
		    this->origin->consumer_birth.data(), 16) != 0 ||
		    memcmp(candidate.program_digest.data(), proof.program_digest, 32) != 0)
			continue;
		/* Publish before replying. A disconnected caller can repeat this
		 * exact assertion without a live ELF subscription or buffer replay. */
		return (this->s.inbounddir->fresh_consumer_stop_receipt(
		    *this->s.outbounddir, stop, candidate, true) == 1);
	}
	errno = ESTALE;
	return (false);
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
bool
client_request::handle_handoffmsg(void)
{
	const std::array<uint8_t, 16> zero16{};
	const std::array<uint8_t, 32> zero32{};
	if (this->buf == nullptr ||
	    this->buf_size != DTRACED_HANDOFF_WIRE_SIZE ||
	    !this->s.is_control_machine() || this->s.outbounddir == nullptr ||
	    this->origin == nullptr ||
	    this->origin->kind != DTRACED_KIND_FORWARDER ||
	    !(this->origin->is_subscribed(DTD_SUB_READDATA) ||
	    this->origin->is_subscribed(DTD_SUB_SOURCE_RELEASE)) ||
	    this->origin->retired.load() ||
	    this->origin->peer_pid <= 1 ||
	    this->origin->peer_uid == (uid_t)-1 ||
	    this->origin->vmid == 0 ||
	    this->origin->vmid >= HYPERTRACE_MAX_VMS ||
	    this->origin->vm_epoch == 0 ||
	    this->origin->session_id == zero16) {
		errno = EPROTO;
		return (false);
	}
	dtraced_handoff_request_t request{};
	if (dtraced_wire_decode_handoff(&request, this->buf) != 0)
		return (false);
	if ((request.op == DTRACED_HANDOFF_SOURCE_RELEASE) !=
	    this->origin->is_subscribed(DTD_SUB_SOURCE_RELEASE)) {
		errno = EPROTO;
		return (false);
	}
	/* The only request allowed after VMM destruction is the source's
	 * release witness on a channel authenticated before that destruction. */
	if (request.op != DTRACED_HANDOFF_SOURCE_RELEASE &&
	    !this->origin->current_vm_attestation()) {
		errno = EPROTO;
		return (false);
	}
	durable_handoff ticket{};
	memcpy(ticket.token.data(), request.token, ticket.token.size());
	bool empty_digest = memcmp(request.digest, zero32.data(),
	    zero32.size()) == 0;
	bool source_op = request.op == DTRACED_HANDOFF_PREPARE ||
	    request.op == DTRACED_HANDOFF_COMMIT ||
	    request.op == DTRACED_HANDOFF_ABORT ||
	    request.op == DTRACED_HANDOFF_SOURCE_STATUS ||
	    request.op == DTRACED_HANDOFF_EXPORT ||
	    request.op == DTRACED_HANDOFF_SOURCE_GATE_BEGIN ||
	    request.op == DTRACED_HANDOFF_SOURCE_GATE_ABORT ||
	    request.op == DTRACED_HANDOFF_SOURCE_DRAIN_STEP ||
	    request.op == DTRACED_HANDOFF_SOURCE_RELEASE;
	bool destination_op = request.op == DTRACED_HANDOFF_RESERVE ||
	    request.op == DTRACED_HANDOFF_CANCEL ||
	    request.op == DTRACED_HANDOFF_MUTATE ||
	    request.op == DTRACED_HANDOFF_CLAIM ||
	    request.op == DTRACED_HANDOFF_BIND_KILLS_ALL ||
	    request.op == DTRACED_HANDOFF_REKEY_APPLIED ||
	    request.op == DTRACED_HANDOFF_EXECUTION_START ||
	    request.op == DTRACED_HANDOFF_PROMOTE_IMPORT ||
	    request.op == DTRACED_HANDOFF_ACTIVATE_IMPORT ||
	    request.op == DTRACED_HANDOFF_REPLAY_READY;
	bool destination_status =
	    request.op == DTRACED_HANDOFF_DESTINATION_STATUS;
	bool reset_mutation = request.op == DTRACED_HANDOFF_RESET_MUTATION;
	bool rebind_begin = request.op == DTRACED_HANDOFF_REBIND_BEGIN ||
	    request.op == DTRACED_HANDOFF_REBIND_STAGE ||
	    request.op == DTRACED_HANDOFF_REBIND_PENDING ||
	    request.op == DTRACED_HANDOFF_REBIND_CANCEL_PENDING ||
	    request.op == DTRACED_HANDOFF_REBIND_COMMIT_EMPTY ||
	    request.op == DTRACED_HANDOFF_REBIND_EMPTY_READY ||
	    request.op == DTRACED_HANDOFF_REBIND_NONEMPTY_PREFLIGHT;
	if (ticket.token == zero16 ||
	    (!source_op && !destination_op && !destination_status &&
	    !rebind_begin && !reset_mutation) ||
	    ((request.op == DTRACED_HANDOFF_ABORT ||
	    request.op == DTRACED_HANDOFF_SOURCE_STATUS ||
	    request.op == DTRACED_HANDOFF_EXPORT) && !empty_digest) ||
	    ((request.op == DTRACED_HANDOFF_SOURCE_GATE_BEGIN ||
	    request.op == DTRACED_HANDOFF_SOURCE_GATE_ABORT) && !empty_digest) ||
	    ((request.op == DTRACED_HANDOFF_PREPARE ||
	    request.op == DTRACED_HANDOFF_COMMIT ||
	    request.op == DTRACED_HANDOFF_SOURCE_DRAIN_STEP ||
	    request.op == DTRACED_HANDOFF_SOURCE_RELEASE || destination_op ||
	    destination_status || rebind_begin || reset_mutation) &&
	    empty_digest)) {
		errno = EPROTO;
		return (false);
	}
	if (request.op == DTRACED_HANDOFF_SOURCE_GATE_BEGIN ||
	    request.op == DTRACED_HANDOFF_SOURCE_GATE_ABORT) {
		ticket.source_session = this->origin->session_id;
		ticket.source_vmid = this->origin->vmid;
		ticket.source_epoch = this->origin->vm_epoch;
		return (request.op == DTRACED_HANDOFF_SOURCE_GATE_BEGIN ?
		    this->s.outbounddir->source_gate_begin(ticket) :
		    this->s.outbounddir->source_gate_abort(ticket));
	}
	if (request.op == DTRACED_HANDOFF_EXPORT) {
		ticket.source_session = this->origin->session_id;
		ticket.source_vmid = this->origin->vmid;
		ticket.source_epoch = this->origin->vm_epoch;
		if (!this->s.outbounddir->source_journal_transfer_wire_export(
		    ticket, this->transfer_reply, true))
			return (false);
		this->transfer_ready = true;
		return (true);
	}
	if (request.op == DTRACED_HANDOFF_PREPARE) {
		ticket.source_session = this->origin->session_id;
		ticket.source_vmid = this->origin->vmid;
		ticket.source_epoch = this->origin->vm_epoch;
		memcpy(ticket.transfer_digest.data(), request.digest,
		    ticket.transfer_digest.size());
		return (this->s.outbounddir->prepare_handoff(ticket, true));
	}
	if (reset_mutation) {
		memcpy(ticket.checkpoint_digest.data(), request.digest,
		    ticket.checkpoint_digest.size());
		return (this->s.outbounddir->reset_handoff_mutation(ticket.token,
		    ticket.checkpoint_digest, this->origin->vmid,
		    this->origin->vm_epoch));
	}
	if (request.op == DTRACED_HANDOFF_SOURCE_DRAIN_STEP) {
		ticket.source_session = this->origin->session_id;
		ticket.source_vmid = this->origin->vmid;
		ticket.source_epoch = this->origin->vm_epoch;
		memcpy(ticket.transfer_digest.data(), request.digest,
		    ticket.transfer_digest.size());
		this->drain_step_ready = true;
		int step = this->s.outbounddir->
		    drain_source_consumer_step(ticket);
		if (step < 0)
			return (false);
		this->drain_step_reply = (uint8_t)step;
		return (true);
	}
	int phase = this->s.outbounddir->handoff_status(ticket.token, ticket);
	if (phase < 0)
		return (false);
	if (phase == 0 && request.op == DTRACED_HANDOFF_RESERVE) {
		/* A foreign source has no local phase journal. Adopt only its
		 * pinned-key HSA1 release as a committed source ticket; the
		 * ordinary reservation still checks destination availability. */
		if (!this->s.outbounddir->adopt_imported_source_release(
		    ticket.token, request.digest))
			return (false);
		phase = this->s.outbounddir->handoff_status(ticket.token,
		    ticket);
		if (phase < 0)
			return (false);
	}
	if (phase == 0) {
		if (request.op == DTRACED_HANDOFF_SOURCE_STATUS) {
			this->status_ready = true;
			return (true);
		}
		if (request.op == DTRACED_HANDOFF_ABORT)
			return (this->s.wake_handoff_source(*this->origin));
		errno = ENOENT;
		return (false);
	}
	if (destination_status) {
		if (phase != (int)handoff_phase::committed &&
		    phase != (int)handoff_phase::reserved &&
		    phase != (int)handoff_phase::mutating &&
		    phase != (int)handoff_phase::claimed) {
			errno = EBUSY;
			return (false);
		}
		if (memcmp(ticket.checkpoint_digest.data(), request.digest,
		    ticket.checkpoint_digest.size()) != 0) {
			errno = EPROTO;
			return (false);
		}
		if (phase != (int)handoff_phase::committed &&
		    (ticket.destination_vmid != this->origin->vmid ||
		    ticket.destination_epoch != this->origin->vm_epoch)) {
			errno = EPERM;
			return (false);
		}
		this->status_reply.phase = (uint8_t)phase;
		memcpy(this->status_reply.digest,
		    ticket.checkpoint_digest.data(),
		    sizeof(this->status_reply.digest));
		this->status_ready = true;
		return (true);
	}
	if (rebind_begin) {
		if (request.op == DTRACED_HANDOFF_REBIND_COMMIT_EMPTY &&
		    phase == (int)handoff_phase::claimed &&
		    ticket.destination_vmid == this->origin->vmid &&
		    ticket.destination_epoch == this->origin->vm_epoch &&
		    memcmp(ticket.checkpoint_digest.data(), request.digest,
		    ticket.checkpoint_digest.size()) == 0)
			return (this->s.outbounddir->handoff_rebind_empty_done(
			    ticket, this->origin->session_id,
			    (uint32_t)this->origin->peer_uid,
			    (uint32_t)this->origin->peer_pid));
		if (phase != (int)handoff_phase::claimed) {
			errno = EBUSY;
			return (false);
		}
		if (memcmp(ticket.checkpoint_digest.data(), request.digest,
		    ticket.checkpoint_digest.size()) != 0) {
			errno = EPROTO;
			return (false);
		}
		if (ticket.destination_vmid == this->origin->vmid &&
		    ticket.destination_epoch == this->origin->vm_epoch) {
			errno = EALREADY;
			return (false);
		}
		if (request.op == DTRACED_HANDOFF_REBIND_BEGIN)
			return (this->s.outbounddir->begin_handoff_rebind(ticket,
			    this->origin->vmid, this->origin->vm_epoch,
			    this->origin->session_id,
			    (uint32_t)this->origin->peer_uid,
			    (uint32_t)this->origin->peer_pid));
		if (request.op == DTRACED_HANDOFF_REBIND_STAGE)
			return (this->s.outbounddir->stage_handoff_rebind(ticket,
			    this->origin->vmid, this->origin->vm_epoch,
			    this->origin->session_id,
			    (uint32_t)this->origin->peer_uid,
			    (uint32_t)this->origin->peer_pid));
		if (request.op == DTRACED_HANDOFF_REBIND_CANCEL_PENDING)
			return (this->s.outbounddir->
			    cancel_handoff_rebind_pending(ticket));
		if (request.op == DTRACED_HANDOFF_REBIND_COMMIT_EMPTY)
			return (this->s.outbounddir->
			    commit_handoff_rebind_empty(ticket,
			    this->origin->vmid, this->origin->vm_epoch,
			    this->origin->session_id,
			    (uint32_t)this->origin->peer_uid,
			    (uint32_t)this->origin->peer_pid));
		if (request.op == DTRACED_HANDOFF_REBIND_EMPTY_READY)
			return (this->s.outbounddir->
			    handoff_rebind_empty_plan_ready(ticket,
			    this->origin->vmid, this->origin->vm_epoch,
			    this->origin->session_id,
			    (uint32_t)this->origin->peer_uid,
			    (uint32_t)this->origin->peer_pid));
		if (request.op == DTRACED_HANDOFF_REBIND_NONEMPTY_PREFLIGHT)
			return (this->s.outbounddir->
			    handoff_rebind_nonempty_preflight(ticket,
			    this->origin->vmid, this->origin->vm_epoch,
			    this->origin->session_id,
			    (uint32_t)this->origin->peer_uid,
			    (uint32_t)this->origin->peer_pid));
		return (this->s.outbounddir->publish_handoff_rebind_pending(
		    ticket, this->origin->vmid, this->origin->vm_epoch,
		    this->origin->session_id,
		    (uint32_t)this->origin->peer_uid,
		    (uint32_t)this->origin->peer_pid));
	}
	if (destination_op) {
		bool phase_allowed =
		    ((request.op == DTRACED_HANDOFF_RESERVE ||
		    request.op == DTRACED_HANDOFF_CANCEL) &&
		    (phase == (int)handoff_phase::committed ||
		    phase == (int)handoff_phase::reserved)) ||
		    (request.op == DTRACED_HANDOFF_MUTATE &&
		    (phase == (int)handoff_phase::reserved ||
		    phase == (int)handoff_phase::mutating)) ||
		    (request.op == DTRACED_HANDOFF_CLAIM &&
		    (phase == (int)handoff_phase::mutating ||
		    phase == (int)handoff_phase::claimed)) ||
	    (request.op == DTRACED_HANDOFF_BIND_KILLS_ALL &&
	    phase == (int)handoff_phase::claimed) ||
	    (request.op == DTRACED_HANDOFF_PROMOTE_IMPORT &&
	    phase == (int)handoff_phase::claimed) ||
	    (request.op == DTRACED_HANDOFF_ACTIVATE_IMPORT &&
	    phase == (int)handoff_phase::claimed) ||
	    (request.op == DTRACED_HANDOFF_REPLAY_READY &&
	    phase == (int)handoff_phase::claimed) ||
	    (request.op == DTRACED_HANDOFF_REKEY_APPLIED &&
		    phase == (int)handoff_phase::claimed) ||
	    (request.op == DTRACED_HANDOFF_EXECUTION_START &&
	    phase == (int)handoff_phase::claimed);
		if (!phase_allowed) {
			errno = EBUSY;
			return (false);
		}
		if (memcmp(ticket.checkpoint_digest.data(), request.digest,
		    ticket.checkpoint_digest.size()) != 0) {
			errno = EPROTO;
			return (false);
		}
		if ((phase == (int)handoff_phase::reserved ||
		    phase == (int)handoff_phase::mutating ||
		    phase == (int)handoff_phase::claimed) &&
		    (ticket.destination_vmid != this->origin->vmid ||
		    ticket.destination_epoch != this->origin->vm_epoch)) {
			errno = EPERM;
			return (false);
		}
		ticket.destination_vmid = this->origin->vmid;
		ticket.destination_epoch = this->origin->vm_epoch;
		switch (request.op) {
		case DTRACED_HANDOFF_RESERVE:
			return (this->s.outbounddir->reserve_handoff(ticket));
		case DTRACED_HANDOFF_CANCEL:
			return (this->s.outbounddir->cancel_handoff_reservation(ticket));
		case DTRACED_HANDOFF_MUTATE:
			return (this->s.outbounddir->begin_handoff_mutation(ticket));
		case DTRACED_HANDOFF_CLAIM:
			return (this->s.outbounddir->claim_handoff(ticket));
		case DTRACED_HANDOFF_BIND_KILLS_ALL: {
			std::lock_guard revocations(this->s.revocationmtx);
			return (this->s.outbounddir->bind_handoff_kills_all(ticket));
		}
		case DTRACED_HANDOFF_REKEY_APPLIED:
			return (this->s.outbounddir->mark_handoff_rekey_applied(ticket));
		case DTRACED_HANDOFF_EXECUTION_START:
			return (this->s.outbounddir->mark_handoff_execution_start(ticket));
		case DTRACED_HANDOFF_PROMOTE_IMPORT: {
			if (this->s.inbounddir == nullptr) {
				errno = EINVAL;
				return (false);
			}
			/* Keep the same KILL publication order as the restore
			 * barrier. The bind is idempotent after a lost reply. */
			std::lock_guard revocations(this->s.revocationmtx);
			if (!this->s.outbounddir->bind_handoff_kills_all(ticket))
				return (false);
			host_ingress_destination_plan plan;
			int present = this->s.inbounddir->
			    load_host_ingress_destination_stage(ticket,
			    this->origin->session_id,
			    (uint32_t)this->origin->peer_uid,
			    (uint32_t)this->origin->peer_pid,
			    this->origin->ident, plan);
			if (present < 0)
				return (false);
			if (present == 0) {
				int journal = this->s.outbounddir->
				    claimed_source_journal_status(ticket,
				    this->origin->session_id,
				    (uint32_t)this->origin->peer_uid,
				    (uint32_t)this->origin->peer_pid);
				if (journal < 0)
					return (false);
				if (journal == 1)
					return (true);
				std::vector<uint8_t> empty_wire;
				if (!dtraced_transfer_wire_build(ticket.token.data(),
				    {}, {}, empty_wire))
					return (false);
				if (memcmp(ticket.transfer_digest.data(),
				    empty_wire.data() + empty_wire.size() - 32, 32) != 0) {
					errno = EPROTO;
					return (false);
				}
				return (true);
			}
			return (this->s.inbounddir->promote_import_host_ingress(
			    ticket, this->origin->session_id,
			    (uint32_t)this->origin->peer_uid,
			    (uint32_t)this->origin->peer_pid,
			    this->origin->ident));
		}
		case DTRACED_HANDOFF_REPLAY_READY: {
			std::lock_guard revocations(this->s.revocationmtx);
			if (!this->s.outbounddir->bind_handoff_kills_all(ticket))
				return (false);
			int journal = this->s.outbounddir->
			    claimed_source_journal_status(ticket,
			    this->origin->session_id,
			    (uint32_t)this->origin->peer_uid,
			    (uint32_t)this->origin->peer_pid, true);
			if (journal < 0)
				return (false);
			if (journal == 1) {
				errno = EBUSY;
				return (false);
			}
			if (journal == 2)
				return (true);
			std::vector<uint8_t> empty_wire;
			if (!dtraced_transfer_wire_build(ticket.token.data(),
			    {}, {}, empty_wire))
				return (false);
			if (memcmp(ticket.transfer_digest.data(),
			    empty_wire.data() + empty_wire.size() - 32, 32) != 0) {
				errno = EPROTO;
				return (false);
			}
			return (true);
		}
		case DTRACED_HANDOFF_ACTIVATE_IMPORT: {
			if (this->s.inbounddir == nullptr) {
				errno = EINVAL;
				return (false);
			}
			std::lock_guard revocations(this->s.revocationmtx);
			if (!this->s.outbounddir->bind_handoff_kills_all(ticket))
				return (false);
			int applied = this->s.outbounddir->
			    handoff_rekey_applied_status(ticket);
			if (applied != 1) {
				if (applied == 0)
					errno = EBUSY;
				return (false);
			}
			host_ingress_destination_plan plan;
			int present = this->s.inbounddir->
			    load_host_ingress_destination_stage(ticket,
			    this->origin->session_id,
			    (uint32_t)this->origin->peer_uid,
			    (uint32_t)this->origin->peer_pid,
			    this->origin->ident, plan);
			if (present < 0)
				return (false);
			if (present == 0) {
				int journal = this->s.outbounddir->
				    claimed_source_journal_status(ticket,
				    this->origin->session_id,
				    (uint32_t)this->origin->peer_uid,
				    (uint32_t)this->origin->peer_pid);
				if (journal < 0)
					return (false);
				if (journal == 1)
					return (true);
				std::vector<uint8_t> empty_wire;
				if (!dtraced_transfer_wire_build(ticket.token.data(),
				    {}, {}, empty_wire))
					return (false);
				if (memcmp(ticket.transfer_digest.data(),
				    empty_wire.data() + empty_wire.size() - 32, 32) != 0) {
					errno = EPROTO;
					return (false);
				}
				return (true);
			}
			if (!this->s.inbounddir->activate_import_host_ingress(
			    ticket, this->origin->session_id,
			    (uint32_t)this->origin->peer_uid,
			    (uint32_t)this->origin->peer_pid,
			    this->origin->ident))
				return (false);
			struct retained_receivers {
				std::vector<client_fd *> clients;
				~retained_receivers()
				{
					for (client_fd *client : clients)
						client->release();
				}
			} receivers;
			try {
				{
					std::lock_guard clients(this->s.sockfdsmtx);
					receivers.clients.reserve(this->s.sockfds.size());
					for (client_fd *client : this->s.sockfds) {
						if (client->retired.load() ||
						    client->kind != DTRACED_KIND_CONSUMER ||
						    !client->is_subscribed(
						    DTD_SUB_ELFWRITE) ||
						    client->consumer_replay_pending ||
						    !client->consumer_program_valid)
							continue;
						client->acquire();
						receivers.clients.push_back(client);
					}
				}
				for (client_fd *client : receivers.clients)
					if (!client->retired.load() &&
					    this->s.inbounddir->
					    queue_activated_import_consumer(client,
					    &ticket.token) < 0)
						return (false);
			} catch (const std::bad_alloc &) {
				errno = ENOMEM;
				return (false);
			}
			return (true);
		}
		}
		errno = EPROTO;
		return (false);
	}
	if (ticket.source_session != this->origin->session_id ||
	    ticket.source_vmid != this->origin->vmid ||
	    ticket.source_epoch != this->origin->vm_epoch) {
		errno = EPERM;
		return (false);
	}
	if (request.op == DTRACED_HANDOFF_SOURCE_RELEASE) {
		if (phase != (int)handoff_phase::committed ||
		    memcmp(ticket.checkpoint_digest.data(), request.digest,
		    ticket.checkpoint_digest.size()) != 0) {
			errno = EPROTO;
			return (false);
		}
		/* The HTH2 journal bound this exact attested VM lifetime while
		 * it was live. The kernel clears its epoch only after ECB drain. */
		hypertrace_epoch_query query{};
		query.vmid = ticket.source_vmid;
		query.epoch = ticket.source_epoch;
		if (this->origin->vm_epoch_query_fd < 0) {
			errno = EPROTO;
			return (false);
		}
		if (ioctl(this->origin->vm_epoch_query_fd,
		    HYPERTRACE_IOC_EPOCH_QUERY, &query) != 0)
			return (false);
		if (query.live != 0) {
			errno = EBUSY;
			return (false);
		}
		if (!this->s.outbounddir->record_source_release(ticket))
			return (false);
		if (this->s.handoff_keys.configured()) {
			if (!this->s.outbounddir->attest_source_release(ticket,
			    this->s.handoff_keys.private_key(),
			    this->s.handoff_keys.peer_public().data(),
			    this->release_reply))
				return (false);
			this->release_signed = true;
		}
		this->release_ready = true;
		return (true);
	}
	if (request.op == DTRACED_HANDOFF_SOURCE_STATUS) {
		this->status_reply.phase = (uint8_t)phase;
		if (phase == (int)handoff_phase::prepared)
			memcpy(this->status_reply.digest,
			    ticket.transfer_digest.data(),
			    sizeof(this->status_reply.digest));
		else
			memcpy(this->status_reply.digest,
			    ticket.checkpoint_digest.data(),
			    sizeof(this->status_reply.digest));
		this->status_ready = true;
		return (true);
	}
	if (request.op == DTRACED_HANDOFF_ABORT) {
		if (phase != (int)handoff_phase::prepared) {
			errno = EBUSY;
			return (false);
		}
		if (!this->s.outbounddir->abort_handoff(ticket))
			return (false);
		return (this->s.wake_handoff_source(*this->origin));
	}
	if (phase != (int)handoff_phase::prepared &&
	    phase != (int)handoff_phase::committed) {
		errno = EBUSY;
		return (false);
	}
	memcpy(ticket.checkpoint_digest.data(), request.digest,
	    ticket.checkpoint_digest.size());
	if (!this->s.outbounddir->commit_handoff(ticket))
		return (false);
	this->s.retire_handoff_consumers(ticket.source_vmid,
	    ticket.source_epoch);
	return (true);
}

/* The 48-byte prefix binds the saved HTX1 bytes to a reserved checkpoint.
 * The peer's VM identity comes only from its live VMM attestation. The
 * imported journal and owner/recipient sidecars remain inert until a
 * separate destination execution lease is committed. */
bool
client_request::handle_handoff_importmsg(void)
{
	const std::array<uint8_t, 16> zero16{};
	const std::array<uint8_t, 32> zero32{};
	if (this->buf == nullptr || this->buf_size <
	    DTRACED_HANDOFF_IMPORT_BINDING_SIZE +
	    DTRACED_TRANSFER_HEADER_SIZE + DTRACED_TRANSFER_DIGEST_SIZE ||
	    this->buf_size > DTRACED_HANDOFF_IMPORT_BINDING_SIZE +
	    DTRACED_TRANSFER_MAX_SIZE ||
	    !this->s.is_control_machine() || this->s.outbounddir == nullptr ||
	    this->s.inbounddir == nullptr || this->origin == nullptr ||
	    this->origin->kind != DTRACED_KIND_FORWARDER ||
	    !this->origin->is_subscribed(DTD_SUB_READDATA) ||
	    this->origin->retired.load() ||
	    this->origin->peer_pid <= 1 ||
	    this->origin->peer_uid == (uid_t)-1 ||
	    this->origin->vmid == 0 ||
	    this->origin->vmid >= HYPERTRACE_MAX_VMS ||
	    this->origin->vm_epoch == 0 ||
	    this->origin->session_id == zero16 ||
	    !this->origin->current_vm_attestation()) {
		errno = EPROTO;
		return (false);
	}
	durable_handoff ticket{};
	memcpy(ticket.token.data(), this->buf, ticket.token.size());
	if (ticket.token == zero16 ||
	    memcmp(this->buf + 16, zero32.data(), zero32.size()) == 0 ||
	    !dtraced_transfer_wire_valid(this->buf +
	    DTRACED_HANDOFF_IMPORT_BINDING_SIZE,
	    this->buf_size - DTRACED_HANDOFF_IMPORT_BINDING_SIZE,
	    ticket.token.data())) {
		errno = EPROTO;
		return (false);
	}
	int phase = this->s.outbounddir->handoff_status(ticket.token, ticket);
	if (phase != (int)handoff_phase::reserved) {
		if (phase >= 0)
			errno = phase == 0 ? ENOENT : EBUSY;
		return (false);
	}
	if (memcmp(ticket.checkpoint_digest.data(), this->buf + 16,
	    ticket.checkpoint_digest.size()) != 0 ||
	    ticket.destination_vmid != this->origin->vmid ||
	    ticket.destination_epoch != this->origin->vm_epoch) {
		errno = EPERM;
		return (false);
	}
	if (memcmp(ticket.transfer_digest.data(),
	    this->buf + this->buf_size - DTRACED_TRANSFER_DIGEST_SIZE,
	    ticket.transfer_digest.size()) != 0) {
		errno = EPROTO;
		return (false);
	}
	std::vector<uint8_t> wire(this->buf +
	    DTRACED_HANDOFF_IMPORT_BINDING_SIZE,
	    this->buf + this->buf_size);
	host_ingress_destination_plan plan;
	int staged = this->s.inbounddir->
	    stage_host_ingress_destination_wire_reserved(
	    ticket, wire, this->origin->session_id,
	    (uint32_t)this->origin->peer_uid,
	    (uint32_t)this->origin->peer_pid, this->origin->ident, plan);
	if (staged < 0)
		return (false);
	if (staged == 0)
		return (true);
	if (staged == 2) {
		/* Complete the outbound HJB1/HJR1 import, then the nested inbound
		 * pending upload. The reply acknowledges durable preparation only;
		 * MUTATE and CLAIM still fence execution until a separate lease.
		 * CANCEL can unwind both prefixes before mutation. */
		if (!this->s.outbounddir->import_source_journal_pending(ticket,
		    this->origin->session_id,
		    (uint32_t)this->origin->peer_uid,
		    (uint32_t)this->origin->peer_pid))
			return (false);
		std::vector<uint8_t> outer_manifest, ingress_manifest, archive;
		std::vector<std::vector<uint8_t>> outer_frames, ingress_frames;
		if (!dtraced_transfer_wire_unpack(wire.data(), wire.size(),
		    ticket.token.data(), outer_manifest, outer_frames) ||
		    !dtraced_transfer_journal_split(ticket.token.data(),
		    outer_manifest, outer_frames, ingress_manifest, ingress_frames,
		    archive))
			return (false);
		if (archive.empty()) {
			errno = EPROTO;
			return (false);
		}
		if (!ingress_manifest.empty()) {
			host_ingress_destination_plan nested;
			if (!dir::plan_host_ingress_destination(ticket,
			    ingress_manifest, ingress_frames,
			    this->origin->session_id,
			    (uint32_t)this->origin->peer_uid,
			    (uint32_t)this->origin->peer_pid,
			    this->origin->ident, nested))
				return (false);
			if (nested.source_programs.empty()) {
				errno = EOPNOTSUPP;
				return (false);
			}
			if (!this->s.inbounddir->stage_host_ingress_destination(
			    ticket, ingress_manifest, ingress_frames,
			    this->origin->session_id,
			    (uint32_t)this->origin->peer_uid,
			    (uint32_t)this->origin->peer_pid,
			    this->origin->ident, nested) ||
			    !this->s.inbounddir->import_host_ingress_pending(ticket,
			    this->origin->session_id,
			    (uint32_t)this->origin->peer_uid,
			    (uint32_t)this->origin->peer_pid,
			    this->origin->ident))
				return (false);
			/* Freeze the exact live consumer incarnation and program image
			 * before an eventual execution lease can promote these HTD5s.
			 * A missing consumer is retryable; the pending import stays inert. */
			if (!this->s.inbounddir->
			    reserve_host_ingress_consumer_owners(ticket,
			    this->origin->session_id,
			    (uint32_t)this->origin->peer_uid,
			    (uint32_t)this->origin->peer_pid,
			    this->origin->ident))
				return (false);
		}
		return (true);
	}
	/* A legacy HTM1 transfer lacks the HCP1 program-image evidence needed
	 * to bind a destination consumer. Refuse its import before returning an
	 * ACK that a later promotion could mistake for a complete reservation. */
	if (plan.source_programs.empty()) {
		errno = EOPNOTSUPP;
		return (false);
	}
	if (!this->s.inbounddir->import_host_ingress_pending(ticket,
	    this->origin->session_id, (uint32_t)this->origin->peer_uid,
	    (uint32_t)this->origin->peer_pid, this->origin->ident))
		return (false);
	return (this->s.inbounddir->reserve_host_ingress_consumer_owners(
	    ticket, this->origin->session_id,
	    (uint32_t)this->origin->peer_uid,
	    (uint32_t)this->origin->peer_pid, this->origin->ident));
}

/* A destination's live VMM-attested forwarder may stage a source-host
 * signature. This is inert evidence: no phase, reservation, or guest lease
 * is created by accepting the frame. */
bool
client_request::handle_handoff_release_importmsg(void)
{
	const std::array<uint8_t, 16> zero16{};
	if (this->buf == nullptr ||
	    this->buf_size != DTRACED_HANDOFF_RELEASE_IMPORT_SIZE ||
	    !this->s.is_control_machine() || this->s.outbounddir == nullptr ||
	    !this->s.handoff_keys.configured() || this->origin == nullptr ||
	    this->origin->kind != DTRACED_KIND_FORWARDER ||
	    !this->origin->is_subscribed(DTD_SUB_READDATA) ||
	    this->origin->retired.load() ||
	    this->origin->peer_pid <= 1 ||
	    this->origin->peer_uid == (uid_t)-1 ||
	    this->origin->vmid == 0 ||
	    this->origin->vmid >= HYPERTRACE_MAX_VMS ||
	    this->origin->vm_epoch == 0 ||
	    this->origin->session_id == zero16 ||
	    !this->origin->current_vm_attestation()) {
		errno = EPROTO;
		return (false);
	}
	/* A source and restore on this daemon already share the local HSL1
	 * journal. Validate its HSA1 in the source-key direction; the foreign
	 * slot is only for a ticket absent from this daemon's phase journal. */
	durable_handoff local{};
	std::array<uint8_t, 16> token{};
	memcpy(token.data(), this->buf, token.size());
	int phase = this->s.outbounddir->handoff_status(token, local);
	if (phase < 0)
		return (false);
	if (phase != 0) {
		local.destination_vmid = 0;
		local.destination_epoch = 0;
		if (phase == (int)handoff_phase::prepared ||
		    memcmp(local.checkpoint_digest.data(), this->buf + 16,
		    local.checkpoint_digest.size()) != 0 ||
		    !dir::verify_source_release_attestation(local,
		    this->s.handoff_keys.own_public().data(),
		    this->s.handoff_keys.peer_public().data(),
		    this->buf + 48) ||
		    this->s.outbounddir->source_release_status(local) != 1) {
			errno = EPROTO;
			return (false);
		}
		return (true);
	}
	return (this->s.outbounddir->stage_imported_source_release(
	    this->buf + 48, this->s.handoff_keys.peer_public().data(),
	    this->s.handoff_keys.own_public().data(), this->buf,
	    this->buf + 16));
}

bool
client_request::handle_handoff_deliverymsg(bool bind)
{
	const std::array<uint8_t, 16> zero16{};
	const std::array<uint8_t, 32> zero32{};
	const std::array<uint8_t, 7> zero7{};
	if (this->buf == nullptr ||
	    this->buf_size != (bind ?
	    DTRACED_HANDOFF_BIND_DELIVERY_WIRE_SIZE :
	    DTRACED_HANDOFF_DELIVERY_WIRE_SIZE) ||
	    !this->s.is_control_machine() || this->s.outbounddir == nullptr ||
	    this->origin == nullptr ||
	    this->origin->kind != DTRACED_KIND_FORWARDER ||
	    !this->origin->is_subscribed(DTD_SUB_READDATA) ||
	    this->origin->retired.load() ||
	    this->origin->peer_pid <= 1 ||
	    this->origin->peer_uid == (uid_t)-1 ||
	    this->origin->vmid == 0 ||
	    this->origin->vmid >= HYPERTRACE_MAX_VMS ||
	    this->origin->vm_epoch == 0 ||
	    this->origin->session_id == zero16 ||
	    !this->origin->current_vm_attestation()) {
		errno = EPROTO;
		return (false);
	}
	dtraced_handoff_delivery_request_t request{};
	dtraced_handoff_bind_delivery_request_t bound_request{};
	if (bind) {
		if (dtraced_wire_decode_handoff_bind_delivery(&bound_request,
		    (const unsigned char *)this->buf) != 0)
			return (false);
		request = bound_request.delivery;
	} else if (dtraced_wire_decode_handoff_delivery(&request,
	    (const unsigned char *)this->buf) != 0)
		return (false);
	durable_handoff claim{};
	memcpy(claim.token.data(), request.token, claim.token.size());
	memcpy(claim.checkpoint_digest.data(), request.digest,
	    claim.checkpoint_digest.size());
	claim.destination_vmid = this->origin->vmid;
	claim.destination_epoch = this->origin->vm_epoch;
	std::array<uint8_t, 16> program_id{}, source_id{};
	memcpy(program_id.data(), request.program_id, program_id.size());
	memcpy(source_id.data(), request.source_id, source_id.size());
	if (claim.token == zero16 || claim.checkpoint_digest == zero32 ||
	    request.delivery_id == 0 ||
	    (request.scope != 0 && (bind || request.scope != 3 ||
	    this->s.inbounddir == nullptr)) ||
	    program_id == zero16 || source_id == zero16 ||
	    memcmp(request.reserved, zero7.data(), zero7.size()) != 0) {
		errno = EPROTO;
		return (false);
	}
	durable_delivery_state found{};
	bool revoked = false;
	bool payload_available = false;
	std::lock_guard revocations(this->s.revocationmtx);
	if (bind) {
		if (!this->s.outbounddir->bind_handoff_delivery(claim,
		    request.delivery_id, program_id, source_id,
		    bound_request.payload_digest,
		    this->origin->session_id, this->origin->peer_uid,
		    this->origin->peer_pid, found))
			return (false);
		this->status_reply.delivery_id = request.delivery_id;
		this->status_reply.phase = (uint8_t)found.phase;
		memcpy(this->status_reply.digest,
		    found.record.payload_digest.data(),
		    sizeof(this->status_reply.digest));
		this->status_ready = true;
		return (true);
	}
	/* A queued HOST_ELF is a guest upload accepted by host inbound,
	 * while the ticket and KILL authority remain in host outbound. */
	int status = this->s.outbounddir->handoff_delivery_status(claim,
	    request.scope, request.delivery_id, program_id, source_id,
	    found, revoked, payload_available, this->s.inbounddir);
	if (status < 0)
		return (false);
	this->status_reply.delivery_id = request.delivery_id;
	if (status != 0) {
		this->status_reply.phase = (uint8_t)found.phase;
		this->status_reply.revoked = revoked ? 1 : 0;
		if (payload_available)
			memcpy(this->status_reply.digest,
			    found.record.payload_digest.data(),
			    sizeof(this->status_reply.digest));
	}
	/* The read-only lookup does not create a destination receipt. */
	this->status_ready = true;
	return (true);
}

bool
client_request::handle_handoff_killmsg(bool bind)
{
	const std::array<uint8_t, 16> zero16{};
	const std::array<uint8_t, 32> zero32{};
	const std::array<uint8_t, 4> zero4{};
	if (this->buf == nullptr ||
	    this->buf_size != DTRACED_HANDOFF_KILL_WIRE_SIZE ||
	    !this->s.is_control_machine() || this->s.outbounddir == nullptr ||
	    this->origin == nullptr ||
	    this->origin->kind != DTRACED_KIND_FORWARDER ||
	    !this->origin->is_subscribed(DTD_SUB_READDATA) ||
	    this->origin->retired.load() ||
	    this->origin->peer_pid <= 1 ||
	    this->origin->peer_uid == (uid_t)-1 ||
	    this->origin->vmid == 0 ||
	    this->origin->vmid >= HYPERTRACE_MAX_VMS ||
	    this->origin->vm_epoch == 0 ||
	    this->origin->session_id == zero16 ||
	    !this->origin->current_vm_attestation()) {
		errno = EPROTO;
		return (false);
	}
	dtraced_handoff_kill_request_t request{};
	if (dtraced_wire_decode_handoff_kill(&request,
	    (const unsigned char *)this->buf) != 0)
		return (false);
	durable_handoff claim{};
	memcpy(claim.token.data(), request.token, claim.token.size());
	memcpy(claim.checkpoint_digest.data(), request.digest,
	    claim.checkpoint_digest.size());
	claim.destination_vmid = this->origin->vmid;
	claim.destination_epoch = this->origin->vm_epoch;
	std::array<uint8_t, 16> source_id{};
	memcpy(source_id.data(), request.source_id, source_id.size());
	if (claim.token == zero16 || claim.checkpoint_digest == zero32 ||
	    request.pid <= 1 || source_id == zero16 ||
	    memcmp(request.reserved, zero4.data(), zero4.size()) != 0) {
		errno = EPROTO;
		return (false);
	}
	std::lock_guard revocations(this->s.revocationmtx);
	if (bind) {
		int phase = this->s.outbounddir->bind_handoff_kill(claim,
		    request.pid, source_id);
		if (phase < 0)
			return (false);
		this->status_reply.delivery_id = (uint32_t)request.pid;
		this->status_reply.phase = (uint8_t)phase;
		this->status_reply.revoked = 1;
		this->status_ready = true;
		return (true);
	}
	bool revoked = false;
	int phase = this->s.outbounddir->handoff_kill_status(claim,
	    request.pid, source_id, revoked);
	if (phase < 0)
		return (false);
	this->status_reply.delivery_id = (uint32_t)request.pid;
	this->status_reply.phase = (uint8_t)phase;
	this->status_reply.revoked = revoked ? 1 : 0;
	/* A journal observation cannot authorize replay in a new VM epoch. */
	this->status_ready = true;
	return (true);
}

bool
client_request::handle_handoff_cleanupmsg(void)
{
	const std::array<uint8_t, 16> zero16{};
	if (this->buf == nullptr ||
	    this->buf_size != DTRACED_HANDOFF_CLEANUP_WIRE_SIZE ||
	    !this->s.is_control_machine() || this->s.outbounddir == nullptr ||
	    this->origin == nullptr ||
	    this->origin->kind != DTRACED_KIND_FORWARDER ||
	    !this->origin->is_subscribed(DTD_SUB_READDATA) ||
	    this->origin->retired.load() ||
	    this->origin->peer_pid <= 1 ||
	    this->origin->peer_uid == (uid_t)-1 ||
	    this->origin->vmid == 0 ||
	    this->origin->vmid >= HYPERTRACE_MAX_VMS ||
	    this->origin->vm_epoch == 0 ||
	    this->origin->session_id == zero16 ||
	    !this->origin->current_vm_attestation()) {
		errno = EPROTO;
		return (false);
	}
	dtraced_handoff_cleanup_request_t request{};
	if (dtraced_wire_decode_handoff_cleanup(&request,
	    (const unsigned char *)this->buf) != 0)
		return (false);
	durable_handoff claim{};
	memcpy(claim.token.data(), request.token, claim.token.size());
	memcpy(claim.checkpoint_digest.data(), request.digest,
	    claim.checkpoint_digest.size());
	claim.destination_vmid = this->origin->vmid;
	claim.destination_epoch = this->origin->vm_epoch;
	int phase = this->s.outbounddir->handoff_cleanup_status(claim,
	    request.delivery_id);
	if (phase < 0)
		return (false);
	this->status_reply.delivery_id = request.delivery_id;
	this->status_reply.phase = (uint8_t)phase;
	this->status_ready = true;
	return (true);
}
/* HT-C END */

bool
client_request::handle_cleanupmsg(void)
{
	using vecstr = std::vector<std::string>;
	/* A cleanup affects tracing state in every selected VM. */
	if (this->origin == nullptr ||
	    this->origin->kind != DTRACED_KIND_CONSUMER ||
	    this->origin->peer_uid != 0 || this->origin->peer_pid <= 0 ||
	    this->origin->retired.load()) {
		errno = EPERM;
		return (false);
	}
	if (this->hdr.cleanup.vmid != 0 || this->hdr.cleanup.epoch != 0 ||
	    DTRACED_MSG_CLEANUP_DELIVERY_ID(this->hdr) != 0) {
		return (REFUSE(EPROTO, "CLEANUP names a VM"));
	}

	vecstr entries;
	if (!parse_cleanup(this->buf, this->buf_size,
	    DTRACED_MSG_NUMENTRIES(this->hdr), entries))
		return (false);

	std::lock_guard lk(this->s.sockfdsmtx);
	for (client_fd *dfdp : this->s.sockfds) {
		client_fd &dfd = *dfdp;

		if (dfd.kind != DTRACED_KIND_FORWARDER)
			continue;

		if (!dfd.is_subscribed(uint32_t(DTD_SUB_CLEANUP)))
			continue;

		/* An empty list explicitly selects all VMs; names match exactly. */
		if (!entries.empty() && std::find(entries.begin(), entries.end(),
		    dfd.ident) == entries.end())
			continue;

		auto j = std::make_unique<job>(CLEANUP, dfdp);

		// XXX: ugly.
		cleanup_job *&c = j->cleanup_get();
		c = new vecstr(entries);
		std::list<job *> staged;
		staged.push_back(j.get()); /* allocate before durable publication */
		if (this->s.is_control_machine()) {
			if (this->s.outbounddir == nullptr || dfd.vmid == 0 ||
			    dfd.vm_epoch == 0 || !dfd.current_vm_attestation()) {
				errno = ESTALE;
				return (false);
			}
			do {
				arc4random_buf(&j->cleanup_delivery_id,
				    sizeof(j->cleanup_delivery_id));
			} while (j->cleanup_delivery_id == 0);
			durable_cleanup pending{};
			pending.vmid = dfd.vmid;
			pending.epoch = dfd.vm_epoch;
			pending.delivery_id = j->cleanup_delivery_id;
			if (!this->s.outbounddir->record_cleanup_pending(pending))
				return (false);
			j->cleanup_journaled = true;
		}
		{
			std::lock_guard _lk(this->s.joblistmtx);
			this->s.joblist.splice(this->s.joblist.end(), staged);
			(void)j.release();
		}

		if (!dfd.re_enable_write()) {
			ERR("re_enable_write() failed with: %m");
			return (false);
		}
	}

	return (true);
}

bool
client_request::handle_statsmsg(void)
{
	/* The empty selector reports every active forwarder channel. */
	if (this->origin == nullptr ||
	    this->origin->kind != DTRACED_KIND_CONSUMER ||
	    this->origin->peer_uid != 0 || this->origin->peer_pid <= 0 ||
	    this->origin->retired.load()) {
		errno = EPERM;
		return (false);
	}
	if (this->hdr.cleanup.vmid != 0 || this->hdr.cleanup.epoch != 0) {
		return (REFUSE(EPROTO, "STATS names a VM"));
	}
	std::vector<std::string> names;
	if (!parse_cleanup(this->buf, this->buf_size,
	    DTRACED_MSG_NUMENTRIES(this->hdr), names)) {
		return (REFUSE(EPROTO, "STATS name list"));
	}
	std::lock_guard connections(this->s.sockfdsmtx);
	for (client_fd *fd : this->s.sockfds) {
		if (fd->kind != DTRACED_KIND_FORWARDER || fd->retired.load() ||
		    (!names.empty() && std::find(names.begin(), names.end(),
		    fd->ident) == names.end()))
			continue;
		++this->stats_reply.forwarder_channels;
		std::lock_guard deliveries(fd->installed_mtx);
		for (const outbound_delivery &delivery : fd->outbound_deliveries) {
			++this->stats_reply.outbound_deliveries;
			this->stats_reply.installed_deliveries +=
			    delivery.observed ? 1 : 0;
			this->stats_reply.revoked_deliveries +=
			    delivery.revoked ? 1 : 0;
		}
	}
	this->stats_ready = true;
	return (true);
}

bool
client_request::handle_consumer_programmsg(void)
{
	if (this->origin == nullptr ||
	    this->origin->kind != DTRACED_KIND_CONSUMER ||
	    !this->origin->is_subscribed(DTD_SUB_ELFWRITE) ||
	    !this->origin->consumer_birth_valid ||
	    this->origin->peer_pid <= 1 ||
	    this->origin->peer_uid == (uid_t)-1 ||
	    !this->s.is_control_machine() ||
	    (this->hdr.elf.len != 32 && this->hdr.elf.len != 64) ||
	    this->buf == nullptr || this->buf_size != this->hdr.elf.len) {
		return (REFUSE(EPROTO, "program registration frame"));
	}
	std::array<uint8_t, 32> digest{};
	std::array<uint8_t, 24> lifetime{};
	if (this->buf_size == 64) {
		if (dtraced_wire_decode_consumer_program_v2(
		    (const unsigned char *)this->buf, this->buf_size,
		    digest.data(), lifetime.data()) != 0) {
			return (REFUSE(EPROTO, "program registration body"));
		}
	} else
		memcpy(digest.data(), this->buf, digest.size());
	if (digest == std::array<uint8_t, 32>{}) {
		return (REFUSE(EPROTO, "program registration digest is zero"));
	}
	{
		std::lock_guard clients(this->s.sockfdsmtx);
		if (this->origin->retired.load() ||
		    this->s.sockfds.find(this->origin) == this->s.sockfds.end()) {
			errno = EBUSY;
			return (false);
		}
		if (this->origin->consumer_program_valid) {
			if (this->origin->consumer_program_digest != digest ||
			    this->origin->consumer_handle_lifetime != lifetime) {
				errno = EEXIST;
				return (false);
			}
		} else {
			if (this->buf_size == 64) {
				pd_birth_identity birth{};
				birth.pid = this->origin->peer_pid;
				birth.start_sec = dtraced_wire_get_u64(this->origin->consumer_birth.data());
				birth.start_usec = dtraced_wire_get_u64(this->origin->consumer_birth.data() + 8);
				int process_fd = -1;
				if (collector_process_pin(this->origin->peer_pid, birth,
				    &process_fd) != 0)
					return (false);
				auto key = collector_owner_identity(this->origin->session_id,
				    this->origin->consumer_birth, (uint32_t)this->origin->peer_uid,
				    (uint32_t)this->origin->peer_pid, digest, lifetime);
				if (this->s.collector_owners.retain(key, process_fd) != 0) {
					int error = errno;
					close(process_fd);
					errno = error;
					return (false);
				}
				this->origin->consumer_process_fd = process_fd;
			}
			this->origin->consumer_program_digest = digest;
			this->origin->consumer_handle_lifetime = lifetime;
			this->origin->consumer_program_valid = true;
		}
		/* Admission replay takes over if HPI1 arrives before its gate
		 * opens. Once a census succeeds, exact retries must not append
		 * another copy of every pending HCR2 job. */
		if (this->s.inbounddir == nullptr ||
		    this->origin->consumer_replay_pending ||
		    this->origin->consumer_import_scan_done)
			return (true);
		if (this->origin->consumer_import_scan_active) {
			errno = EBUSY;
			return (false);
		}
		this->origin->consumer_import_scan_active = true;
	}
	/* The program is bound: a failed census ends registration on this
	 * connection (job::read_data()); the client registers again on a new
	 * one. */
	int queued = 0;
	if (this->origin->consumer_replay_registration_pending.load())
		queued = this->s.inbounddir->queue_recovered_consumer(this->origin);
	if (queued >= 0)
		queued = this->s.inbounddir->queue_activated_import_consumer(
		    this->origin);
	{
		std::lock_guard clients(this->s.sockfdsmtx);
		this->origin->consumer_import_scan_active = false;
		if (queued >= 0)
			this->origin->consumer_import_scan_done = true;
	}
	/* Files skipped by the watcher while registration was deferred need a
	 * new scan once ordinary and imported recovery have both completed. */
	if (queued >= 0)
		this->s.inbounddir->request_scan();
	return (queued >= 0);
}

bool
client_request::handle_consumer_executionmsg(void)
{
	const uint8_t zero_id[16] = {};
	dtraced_consumer_ack_t execution{};
	if (this->origin == nullptr ||
	    this->origin->kind != DTRACED_KIND_CONSUMER ||
	    !this->origin->is_subscribed(DTD_SUB_READDATA) ||
	    this->origin->retired.load() ||
	    this->origin->peer_pid <= 1 ||
	    this->origin->peer_uid == (uid_t)-1 ||
	    !this->s.is_control_machine() || this->s.inbounddir == nullptr ||
	    this->hdr.elf.len != DTRACED_CONSUMER_EXECUTION_WIRE_SIZE ||
	    this->buf == nullptr ||
	    this->buf_size != DTRACED_CONSUMER_EXECUTION_WIRE_SIZE ||
	    dtraced_wire_decode_consumer_execution(&execution, this->buf) != 0 ||
	    execution.delivery_id == 0 || execution.vmid == 0 ||
	    execution.vmid >= HYPERTRACE_MAX_VMS || execution.epoch == 0 ||
	    memcmp(execution.program_id, zero_id, sizeof(zero_id)) == 0 ||
	    memcmp(execution.source_id, zero_id, sizeof(zero_id)) == 0 ||
	    (execution.outcome != DTRACED_CONSUMER_ACK_NO_DERIVED &&
	    execution.outcome != DTRACED_CONSUMER_ACK_DERIVED)) {
		return (REFUSE(EPROTO, "execution report frame"));
	}
	/* The one-shot result socket is only a reporting channel.  Keep its
	 * authority tied to the consumer's live ELF receiver; a stale session
	 * or a different process must not settle a receipt after receiver loss.
	 * A reconnect can retry the idempotent result after replay admission. */
	bool live_receiver = false;
	{
		std::lock_guard clients(this->s.sockfdsmtx);
		for (client_fd *candidate : this->s.sockfds) {
			if (candidate->retired.load() ||
			    candidate->kind != DTRACED_KIND_CONSUMER ||
			    !candidate->is_subscribed(DTD_SUB_ELFWRITE) ||
			    candidate->consumer_replay_pending ||
			    candidate->session_id != this->origin->session_id ||
			    candidate->peer_uid != this->origin->peer_uid ||
			    candidate->peer_pid != this->origin->peer_pid)
				continue;
			live_receiver = true;
			break;
		}
	}
	if (!live_receiver) {
		errno = EAGAIN;
		return (false);
	}
	std::array<uint8_t, 16> ingress_session{};
	memcpy(ingress_session.data(), execution.ingress_session, 16);
	durable_consumer_receipt_state matched{};
	int located = this->s.inbounddir->consumer_receipt_exact(
	    ingress_session, execution.delivery_id,
	    this->origin->session_id, (uint32_t)this->origin->peer_uid,
	    (uint32_t)this->origin->peer_pid, matched);
	if (located < 0)
		return (false);
	if (located == 2) {
		/* HT-C BEGIN: disabled trace continuity. */
		const auto &ingress = matched.record.ingress;
		if (ingress.journal_version != 5 ||
		    ingress.handoff_token == std::array<uint8_t, 16>{}) {
			errno = EPROTO;
			return (false);
		}
		if (ingress.session_id != ingress_session ||
		    ingress.delivery_id != execution.delivery_id ||
		    ingress.vmid != execution.vmid ||
		    ingress.epoch != execution.epoch ||
		    memcmp(ingress.program_id.data(), execution.program_id,
		    16) != 0 ||
		    memcmp(ingress.source_id.data(), execution.source_id,
		    16) != 0) {
			return (REFUSE(EPROTO, "execution report ingress"));
		}
		durable_committed_import_result_state result{};
		int found = this->s.inbounddir->load_activated_import_recipient(
		    ingress.handoff_token, ingress_session,
		    execution.delivery_id, this->origin->session_id,
		    (uint32_t)this->origin->peer_uid,
		    (uint32_t)this->origin->peer_pid, result);
		if (found != 1) {
			if (found == 0)
				errno = ENOENT;
			return (false);
		}
		/* The report socket has the right OS process identity, but only
		 * the original HCO1/HPI1 receiver may settle this imported HCR2. */
		bool exact_receiver = false;
		{
			std::lock_guard clients(this->s.sockfdsmtx);
			for (client_fd *candidate : this->s.sockfds) {
				if (candidate->retired.load() ||
				    candidate->kind != DTRACED_KIND_CONSUMER ||
				    !candidate->is_subscribed(DTD_SUB_ELFWRITE) ||
				    candidate->consumer_replay_pending ||
				    candidate->session_id != this->origin->session_id ||
				    candidate->peer_uid != this->origin->peer_uid ||
				    candidate->peer_pid != this->origin->peer_pid ||
				    !candidate->consumer_birth_valid ||
				    !candidate->consumer_program_valid ||
				    memcmp(result.recipient.owner_wire.data() + 28,
				    candidate->consumer_birth.data(), 16) != 0 ||
				    result.recipient.program_digest !=
				    candidate->consumer_program_digest)
					continue;
				exact_receiver = true;
				break;
			}
		}
		if (!exact_receiver) {
			errno = EAGAIN;
			return (false);
		}
		consumer_receipt_phase target =
		    execution.outcome == DTRACED_CONSUMER_ACK_DERIVED ?
		    consumer_receipt_phase::executed_derived :
		    consumer_receipt_phase::executed_no_derived;
		return (this->s.inbounddir->record_activated_import_execution(
		    ingress.handoff_token, ingress_session,
		    execution.delivery_id, this->origin->session_id,
		    (uint32_t)this->origin->peer_uid,
		    (uint32_t)this->origin->peer_pid, target) == (int)target);
		/* HT-C END */
	}
	if (located == 0) {
		errno = ENOENT;
		return (false);
	}
	const auto &ingress = matched.record.ingress;
	if (ingress.vmid != execution.vmid ||
	    ingress.epoch != execution.epoch ||
	    memcmp(ingress.program_id.data(), execution.program_id, 16) != 0 ||
	    memcmp(ingress.source_id.data(), execution.source_id, 16) != 0) {
		return (REFUSE(EPROTO, "execution report ingress"));
	}
	/* HCR1 predates process births. Where HCP1 exists, its frozen owner
	 * and program must identify this live receiver before its separate
	 * report socket can turn processing into execution. A PID-reused
	 * consumer may share the HCS1 session but cannot inherit that proof. */
	std::array<uint8_t, 76> proof_owner{};
	std::array<uint8_t, 32> proof_program{};
	int proof = this->s.inbounddir->consumer_program_status(
	    matched.record, proof_owner, proof_program);
	if (proof < 0)
		return (false);
	if (proof == 1) {
		bool exact_receiver = false;
		std::lock_guard clients(this->s.sockfdsmtx);
		for (client_fd *candidate : this->s.sockfds) {
			if (candidate->retired.load() ||
			    candidate->kind != DTRACED_KIND_CONSUMER ||
			    !candidate->is_subscribed(DTD_SUB_ELFWRITE) ||
			    candidate->consumer_replay_pending ||
			    candidate->session_id != this->origin->session_id ||
			    candidate->peer_uid != this->origin->peer_uid ||
			    candidate->peer_pid != this->origin->peer_pid ||
			    !candidate->consumer_birth_valid ||
			    !candidate->consumer_program_valid ||
			    memcmp(proof_owner.data() + 28,
			    candidate->consumer_birth.data(), 16) != 0 ||
			    proof_program != candidate->consumer_program_digest)
				continue;
			exact_receiver = true;
			break;
		}
		if (!exact_receiver) {
			errno = EAGAIN;
			return (false);
		}
	}
	consumer_receipt_phase target =
	    execution.outcome == DTRACED_CONSUMER_ACK_DERIVED ?
	    consumer_receipt_phase::executed_derived :
	    consumer_receipt_phase::executed_no_derived;
	if (proof == 1)
		return (this->s.inbounddir->record_consumer_execution(
		    matched.record, target) == (int)target);
	if (matched.phase == consumer_receipt_phase::pending) {
		errno = EAGAIN;
		return (false);
	}
	if (target == consumer_receipt_phase::executed_derived ?
	    !consumer_receipt_derived(matched.phase) :
	    !consumer_receipt_no_derived(matched.phase)) {
		return (REFUSE(EPROTO, "execution report outcome"));
	}
	return (this->s.inbounddir->record_consumer_receipt(
	    matched.record, target) == (int)target);
}

bool
client_request::handle(void) try
{
	if (this->origin != nullptr &&
	    this->origin->kind == DTRACED_KIND_RELEASE_RECOVERY &&
	    (DTRACED_MSG_TYPE(this->hdr) != DTRACED_MSG_HANDOFF ||
	    this->buf == nullptr ||
	    this->buf_size != DTRACED_HANDOFF_WIRE_SIZE ||
	    this->buf[0] != DTRACED_HANDOFF_RELEASE_RECOVER)) {
		/* HT-C BEGIN: disabled trace continuity. */
		errno = EPROTO;
		return (false);
		/* HT-C END */
	}
	if (this->origin != nullptr &&
	    this->origin->is_subscribed(DTD_SUB_SOURCE_RELEASE) &&
	    (DTRACED_MSG_TYPE(this->hdr) != DTRACED_MSG_HANDOFF ||
	    this->buf == nullptr ||
	    this->buf_size != DTRACED_HANDOFF_WIRE_SIZE ||
	    this->buf[0] != DTRACED_HANDOFF_SOURCE_RELEASE)) {
		/* HT-C BEGIN: disabled trace continuity. */
		errno = EPROTO;
		return (false);
		/* HT-C END */
	}
	switch (DTRACED_MSG_TYPE(this->hdr)) {
	case DTRACED_MSG_SESSION_STOP:
		return (this->handle_session_stopmsg(false));
	case DTRACED_MSG_SESSION_RELEASE:
		return (this->handle_session_stopmsg(true));
	case DTRACED_MSG_CONSUMER_STOP_COMMIT:
		return (this->handle_consumer_stop_commit());
	case DTRACED_MSG_ELF:
		return (this->handle_elfmsg());

	case DTRACED_MSG_KILL:
		return (this->handle_killmsg());

	case DTRACED_MSG_KILL_APPLIED:
		return (this->handle_kill_appliedmsg());

	case DTRACED_MSG_CLEANUP_APPLIED:
		return (this->handle_cleanup_appliedmsg());

	case DTRACED_MSG_HANDOFF:
		return (this->origin != nullptr &&
		    this->origin->kind == DTRACED_KIND_RELEASE_RECOVERY ?
		    this->handle_release_recovery() : this->handle_handoffmsg());

	case DTRACED_MSG_HANDOFF_IMPORT:
		return (this->handle_handoff_importmsg());

	case DTRACED_MSG_HANDOFF_RELEASE_IMPORT:
		return (this->handle_handoff_release_importmsg());

	case DTRACED_MSG_HANDOFF_DELIVERY:
		return (this->handle_handoff_deliverymsg(false));

	case DTRACED_MSG_HANDOFF_BIND_DELIVERY:
		return (this->handle_handoff_deliverymsg(true));

	case DTRACED_MSG_HANDOFF_KILL:
		return (this->handle_handoff_killmsg(false));

	case DTRACED_MSG_HANDOFF_BIND_KILL:
		return (this->handle_handoff_killmsg(true));

	case DTRACED_MSG_HANDOFF_CLEANUP:
		return (this->handle_handoff_cleanupmsg());

	case DTRACED_MSG_CLEANUP:
		return (this->handle_cleanupmsg());

	case DTRACED_MSG_STATS:
		return (this->handle_statsmsg());

	case DTRACED_MSG_INSTALLED:
		return (this->handle_installedmsg());

	case DTRACED_MSG_UNINSTALLED:
		return (this->handle_uninstalledmsg());

	case DTRACED_MSG_STATUS:
		return (this->handle_statusmsg());

	case DTRACED_MSG_INGRESS_STATUS:
		return (this->handle_ingress_statusmsg());

	case DTRACED_MSG_CONSUMER_EXECUTION:
		return (this->handle_consumer_executionmsg());

	case DTRACED_MSG_CONSUMER_PROGRAM:
		return (this->handle_consumer_programmsg());

	default:
		ERR("unknown message: %ju",
		    (uintmax_t)DTRACED_MSG_TYPE(this->hdr));
	}

	return (false);
} catch (const std::bad_alloc &) {
	errno = ENOMEM;
	return (false);
}
}
