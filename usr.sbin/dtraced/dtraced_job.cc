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
#include <sys/hypertrace.h>

#include <assert.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <algorithm>
#include <new>

#include "dtraced_clientrequest.h"
#include "dtraced_protocol.h"
#include "dtraced_connection.h"
#include "dtraced_errmsg.h"
#include "dtraced_id.h"
#include "dtraced_job.h"
#include "dtraced_io.h"
#include "dtraced_transfer_wire.h"
#include "dtraced_wire.h"
#include "dtraced_state.h"

namespace dtraced {

static bool
send_header(client_fd &fd, const dtraced_hdr_t &header, int64_t deadline)
{
	unsigned char wire[DTRACED_MSGHDRSIZE];
	dtraced_wire_encode_header(wire, &header);
	return (fd.send(wire, sizeof(wire), deadline));
}

/* A consumer can publish its derived spool and then lose the ACK socket.
 * Durable HDU2 plus spool/outbound proof resolves that one HCR1 without
 * trusting the missing ACK or waiting for a daemon restart. A claim with no
 * published result remains pending for exact-session replay. */
static bool
reconcile_lost_consumer_ack(dir &inbound,
    const durable_consumer_receipt &processing)
{
	if (inbound.state == nullptr || inbound.state->outbounddir == nullptr) {
		errno = EINVAL;
		return (false);
	}
	consumer_outcome_lock outcome_lock(inbound.dirfd);
	if (!outcome_lock.held())
		return (false);
	dir &outbound = *inbound.state->outbounddir;
	std::vector<durable_derived_claim> claims;
	if (!outbound.list_derived_claims(claims))
		return (false);
	const durable_derived_claim *matched = nullptr;
	for (const auto &claim : claims) {
		if (claim.consumer_session != processing.consumer_session ||
		    claim.ingress_delivery_id != processing.ingress.delivery_id ||
		    claim.ingress_vmid != processing.ingress.vmid ||
		    claim.ingress_epoch != processing.ingress.epoch ||
		    claim.ingress_program_id != processing.ingress.program_id ||
		    claim.ingress_source_id != processing.ingress.source_id)
			continue;
		if (matched != nullptr) {
			errno = EPROTO;
			return (false);
		}
		matched = &claim;
	}
	if (matched == nullptr)
		return (true);
	durable_consumer_receipt_state resolved{};
	int status = inbound.resolve_derived_outbound(outbound,
	    matched->derived_program_id.data(),
	    matched->ingress_source_id.data(), resolved);
	if (status < 0)
		return (false);
	if (status == 0)
		return (true);
	if (resolved.record.consumer_session != processing.consumer_session ||
	    resolved.record.consumer_uid != processing.consumer_uid ||
	    resolved.record.consumer_pid != processing.consumer_pid ||
	    resolved.record.ingress.session_id != processing.ingress.session_id ||
	    resolved.record.ingress.delivery_id != processing.ingress.delivery_id ||
	    resolved.record.ingress.vmid != processing.ingress.vmid ||
	    resolved.record.ingress.epoch != processing.ingress.epoch ||
	    resolved.record.ingress.program_id != processing.ingress.program_id ||
	    resolved.record.ingress.source_id != processing.ingress.source_id ||
	    resolved.record.ingress.peer_uid != processing.ingress.peer_uid ||
	    resolved.record.ingress.peer_pid != processing.ingress.peer_pid ||
	    resolved.record.ingress.scope != processing.ingress.scope ||
	    resolved.record.ingress.journal_version !=
	    processing.ingress.journal_version ||
	    resolved.record.ingress.payload_digest !=
	    processing.ingress.payload_digest ||
	    resolved.record.ingress.handoff_token !=
	    processing.ingress.handoff_token ||
	    resolved.record.ingress.source_session !=
	    processing.ingress.source_session ||
	    resolved.record.ingress.payload_vmid !=
	    processing.ingress.payload_vmid ||
	    resolved.record.ingress.payload_epoch !=
	    processing.ingress.payload_epoch) {
		errno = EPROTO;
		return (false);
	}
	return (consumer_receipt_derived((consumer_receipt_phase)
	    inbound.record_consumer_receipt(processing,
	    consumer_receipt_phase::derived)));
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
/* A lost imported ACK can settle only a provably published HDU2 result.
 * An absent or incomplete claim leaves the exact HCR2 slot pending for replay. */
static bool
reconcile_lost_import_ack(dir &inbound,
    const durable_committed_import_result_state &processing)
{
	if (inbound.state == nullptr || inbound.state->outbounddir == nullptr) {
		errno = EINVAL;
		return (false);
	}
	consumer_outcome_lock outcome_lock(inbound.dirfd);
	if (!outcome_lock.held())
		return (false);
	std::vector<durable_derived_claim> claims;
	if (!inbound.state->outbounddir->list_derived_claims(claims))
		return (false);
	const auto &ingress = processing.recipient.ingress;
	const durable_derived_claim *matched = nullptr;
	for (const auto &claim : claims) {
		if (memcmp(processing.recipient.owner_wire.data() + 4,
		    claim.consumer_session.data(), 16) != 0 ||
		    claim.ingress_delivery_id != ingress.delivery_id ||
		    claim.ingress_vmid != ingress.vmid ||
		    claim.ingress_epoch != ingress.epoch ||
		    claim.ingress_program_id != ingress.program_id ||
		    claim.ingress_source_id != ingress.source_id)
			continue;
		if (matched != nullptr) {
			errno = EPROTO;
			return (false);
		}
		matched = &claim;
	}
	if (matched == nullptr)
		return (true);
	std::array<uint8_t, 32> claim_digest{};
	int proven = inbound.resolve_import_derived_outbound(
	    *inbound.state->outbounddir, processing, *matched, claim_digest);
	if (proven < 0)
		return (false);
	if (proven == 0)
		return (true);
	return (consumer_receipt_derived((consumer_receipt_phase)
	    inbound.record_activated_import_processing(processing,
	    consumer_receipt_phase::derived, claim_digest)));
}
/* HT-C END */

struct pending_delivery_guard {
	client_fd &client;
	uint64_t id = 0;
	bool armed = false;
	~pending_delivery_guard()
	{
		if (!armed)
			return;
		std::lock_guard lock(client.installed_mtx);
		auto &deliveries = client.outbound_deliveries;
		deliveries.erase(std::remove_if(deliveries.begin(), deliveries.end(),
		    [this](const outbound_delivery &item) {
			return item.delivery_id == id;
		    }), deliveries.end());
	}
};

/* Outbound spool names are durable 128-bit identities, unlike delivery IDs. */
static bool
spool_program_id(const char *name, uint8_t id[DTRACED_PROGRAM_ID_LEN],
    uint8_t source_id[DTRACED_PROGRAM_ID_LEN])
{
	size_t length = strlen(name);
	if (length != 69 ||
	    strncmp(name, "elf.", 4) != 0 ||
	    name[36] != '.')
		return (false);
	for (size_t field = 0; field < 2; field++) {
		uint8_t *output = field == 0 ? id : source_id;
		size_t start = field == 0 ? 4 : 37;
		for (size_t i = 0; i < DTRACED_PROGRAM_ID_LEN; i++) {
			unsigned value = 0;
			for (size_t digit = 0; digit < 2; digit++) {
				char c = name[start + i * 2 + digit];
				if (c >= '0' && c <= '9')
					value = value * 16 + (unsigned)(c - '0');
				else if (c >= 'a' && c <= 'f')
					value = value * 16 + (unsigned)(c - 'a' + 10);
				else
					return (false);
			}
			output[i] = (uint8_t)value;
		}
		const uint8_t zero[DTRACED_PROGRAM_ID_LEN] = {};
		if (memcmp(output, zero, sizeof(zero)) == 0)
			return (false);
	}
	return (true);
}

void
job::tag(void)
{

	this->init_id = this->connsockfd->id;
	this->id = dtraced_genid();
}

job::job(job_kind job_kind, client_fd *dfdp)
    : j{}
    , kind(job_kind)
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
		delete ne.replay;
		delete ne.recorded;
		this->connsockfd->release();
		break;
	}

	case CLEANUP:
		delete this->cleanup_get();
		this->connsockfd->release();
		break;

	case KILL:
	case READ_DATA:
		this->connsockfd->release();
		break;

	case SEND_INFO:
		this->connsockfd->release();
		break;

	default:
		break;
	}
}

bool
job::send_elf(void)
{
	std::lock_guard output(this->connsockfd->output_mtx);
	this->handoff_deferred = false;
	this->handoff_vmid = 0;
	this->handoff_epoch = 0;
	int64_t deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0)
		return (false);
	using uchar = unsigned char;

	__cleanup(closefd_generic) int elffd = -1;
	dtraced_hdr_t header{};

	client_fd &dfd = *this->connsockfd;
	pending_delivery_guard pending{dfd};
	notify_elfwrite_job &ne = this->notify_elfwrite_get();
	durable_delivery durable{};
	uint16_t target_vmid = 0;
	uint64_t target_epoch = 0;
	size_t host_elf_offset = 0;
	const bool host_forwarder = dfd.kind == DTRACED_KIND_FORWARDER &&
	    ne.dir->state != nullptr && ne.dir->state->is_control_machine();
	const bool guest_forwarder = dfd.kind == DTRACED_KIND_FORWARDER &&
	    ne.dir->state != nullptr && !host_forwarder;
	const bool replay_host = ne.replay != nullptr && host_forwarder &&
	    ne.replay->scope == 0 && ne.replay->journal_version == 5;
	const bool replay_guest = ne.replay != nullptr && guest_forwarder &&
	    ne.replay->scope == 2 && ne.replay->journal_version == 4;
	if (host_forwarder && !dfd.current_vm_attestation()) {
		errno = ESTALE;
		return (false);
	}
	if (ne.replay != nullptr && !replay_host && !replay_guest) {
		errno = EPROTO;
		return (false);
	}
	/* A host delivery recorded before the send (queue time or admission
	 * recovery) is sent with its recorded identity, never re-recorded. */
	const durable_delivery *recorded = ne.recorded;
	if (recorded != nullptr && (!host_forwarder || ne.replay != nullptr ||
	    recorded->scope != 0 || recorded->journal_version != 4 ||
	    recorded->session_id != dfd.session_id ||
	    recorded->peer_uid != (uint32_t)dfd.peer_uid || dfd.peer_pid <= 1 ||
	    recorded->peer_pid != (uint32_t)dfd.peer_pid ||
	    recorded->vmid != dfd.vmid || recorded->epoch != dfd.vm_epoch)) {
		errno = EPROTO;
		return (false);
	}
	if (replay_host && (ne.dir != ne.dir->state->outbounddir ||
	    dfd.session_id != ne.replay->session_id ||
	    dfd.peer_uid != ne.replay->peer_uid ||
	    dfd.peer_pid <= 1 ||
	    (uint32_t)dfd.peer_pid != ne.replay->peer_pid ||
	    dfd.vmid != ne.replay->vmid ||
	    dfd.vm_epoch != ne.replay->epoch)) {
		/* HT-C BEGIN: disabled trace continuity. */
		errno = ESTALE;
		return (false);
		/* HT-C END */
	}
	if (guest_forwarder)
		deadline += 35000; /* Device and host acceptance follow socket writes. */

	struct stat stat{};
	std::vector<uchar> replay_payload;

	DEBUG("%s%s to %d-%s", ne.dir->full_path().c_str(), ne.path,
	    dfd.get_fd(), dfd.ident);

	/*
	 * Sanity assertions.
	 */
	assert(ne.path != NULL);
	assert(ne.pathlen <= MAXPATHLEN);
	assert(ne.dir->dirfd != -1);

	if (replay_host) {
		/* HT-C BEGIN: disabled trace continuity. */
		if (ne.dir->claimed_source_journal_replay_payload(*ne.replay,
		    replay_payload) != 1)
			return (false);
		/* HT-C END */
	} else {
		elffd = openat(ne.dir->dirfd, ne.path,
		    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
		const durable_delivery *token = recorded != nullptr ? recorded :
		    replay_guest ? ne.replay : nullptr;
		if (elffd == -1 && errno == ENOENT && token != nullptr &&
		    ne.dir->state != nullptr &&
		    ne.dir->state->outbounddir == ne.dir) {
			/* The publication that created this spool was refused
			 * and removed it; withdraw the token recorded for it. */
			if (!ne.dir->withdraw_pending_delivery(*token))
				return (false);
			return (dfd.re_enable_write());
		}
		if (elffd == -1) {
			ERR("failed to open %s: %m", ne.path);
			return (false);
		}
		if (fstat(elffd, &stat) != 0) {
			ERR("failed to fstat %s: %m", ne.path);
			return (false);
		}
	}

	/* The guest device consumes a bare ELF; only host peers use SHA framing. */
	const size_t prefix = ne.nosha || guest_forwarder ? 0 :
	    SHA256_DIGEST_LENGTH;
	if ((!replay_host && (!S_ISREG(stat.st_mode) || stat.st_size <= 0 ||
	    (uint64_t)stat.st_size > max_request_bytes - prefix)) ||
	    (replay_host && (replay_payload.empty() ||
	    replay_payload.size() > max_request_bytes - prefix))) {
		ERR("invalid ELF spool file size or type");
		return (false);
	}
	size_t elflen = replay_host ? replay_payload.size() : (size_t)stat.st_size;
	size_t msglen = elflen + prefix;
	std::vector<uchar> msg;
	try {
		msg.resize(msglen);
	} catch (const std::bad_alloc &) {
		ERR("cannot allocate ELF forwarding buffer");
		return (false);
	}

	DTRACED_MSG_TYPE(header) = DTRACED_MSG_ELF;
	DTRACED_MSG_LEN(header) = msglen;
	if (dfd.kind == DTRACED_KIND_FORWARDER) {
		if (!spool_program_id(ne.path, header.elf.program_id,
		    header.elf.source_id)) {
			errno = EPROTO;
			return (false);
		}
		if (replay_guest || replay_host) {
			if (memcmp(header.elf.program_id,
			    ne.replay->program_id.data(), 16) != 0 ||
			    memcmp(header.elf.source_id,
			    ne.replay->source_id.data(), 16) != 0) {
				errno = EPROTO;
				return (false);
			}
			header.elf.delivery_id = ne.replay->delivery_id;
		} else if (recorded != nullptr) {
			if (memcmp(header.elf.program_id,
			    recorded->program_id.data(), 16) != 0 ||
			    memcmp(header.elf.source_id,
			    recorded->source_id.data(), 16) != 0) {
				errno = EPROTO;
				return (false);
			}
			header.elf.delivery_id = recorded->delivery_id;
		} else {
			do {
				arc4random_buf(&header.elf.delivery_id,
				    sizeof(header.elf.delivery_id));
			} while (header.elf.delivery_id == 0);
		}
	}

	uchar *contents = &msg[0] + prefix;

	if (replay_host)
		/* HT-C BEGIN: disabled trace continuity. */
		memcpy(contents, replay_payload.data(), elflen);
		/* HT-C END */
	else for (size_t offset = 0; offset < elflen;) {
		ssize_t n = read(elffd, contents + offset, elflen - offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			ERR("incomplete ELF spool file");
			return (false);
		}
		offset += (size_t)n;
	}
	if (host_forwarder) {
		/* A source can be active in another VM or a later VM lifetime. */
		if (elflen < 4) {
			errno = EPROTO;
			return (false);
		}
		if (memcmp(contents, "\177ELF", 4) != 0) {
			struct hypertrace_vm_envelope target;
			if (elflen < HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 4) {
				errno = EPROTO;
				return (false);
			}
			hypertrace_envelope_decode(&target, contents);
			if (target.magic != HYPERTRACE_TARGET_MAGIC ||
			    target.version != HYPERTRACE_ENVELOPE_VERSION ||
			    target.vmid == 0 || target.vmid >= HYPERTRACE_MAX_VMS ||
			    target.epoch == 0 || target.name_length != 0 ||
			    memcmp(contents + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
			    "\177ELF", 4) != 0) {
				errno = EPROTO;
				return (false);
			}
			host_elf_offset = HYPERTRACE_VM_ENVELOPE_WIRE_SIZE;
			target_vmid = target.vmid;
			target_epoch = target.epoch;
			/* A targeted program belongs only to this attested VM. */
			if (dfd.vmid != 0 &&
			    (dfd.vmid != target.vmid ||
			    dfd.vm_epoch != target.epoch))
				return (true);
		}
		if (target_vmid == 0 && dfd.vmid != 0) {
			if (dfd.vm_epoch == 0 || !dfd.current_vm_attestation()) {
				errno = ESTALE;
				return (false);
			}
			target_vmid = dfd.vmid;
			target_epoch = dfd.vm_epoch;
		}
	}
	if (dfd.kind == DTRACED_KIND_FORWARDER && !host_forwarder &&
	    (ne.dir->state == nullptr || elflen < 4 ||
	    memcmp(contents, "\177ELF", 4) != 0)) {
		/* The host stamps guest origin after receiving the bare ELF. */
		errno = EPROTO;
		return (false);
	}

	if (prefix != 0 && SHA256(contents, elflen, &msg[0]) == NULL) {
		ERR("failed to create a SHA256 of the file");
		return (false);
	}
	if (host_forwarder) {
		if (target_vmid == 0 || target_epoch == 0 ||
		    ne.dir->state == nullptr ||
		    ne.dir->state->outbounddir == nullptr) {
			errno = EPROTO;
			return (false);
		}
		/* Publish the pending token atomically with the final kill check. */
		std::lock_guard revocations(ne.dir->state->revocationmtx);
		int revoked = ne.dir->source_revoked_for_vm(
		    header.elf.source_id, target_vmid, target_epoch);
		if (revoked < 0)
			return (false);
		if (revoked > 0)
			return (true);
		outbound_delivery delivery{};
		delivery.program_id = {};
		memcpy(delivery.program_id.data(), header.elf.program_id, 16);
		memcpy(delivery.source_id.data(), header.elf.source_id, 16);
		delivery.target_vmid = target_vmid;
		delivery.target_epoch = target_epoch;
		std::lock_guard lock(dfd.installed_mtx);
		if (dfd.outbound_deliveries.size() >= 16384) {
			errno = ENOSPC;
			return (false);
		}
		if (recorded != nullptr) {
			if (std::any_of(dfd.outbound_deliveries.begin(),
			    dfd.outbound_deliveries.end(),
			    [&](const outbound_delivery &item) {
				return item.delivery_id == header.elf.delivery_id;
			    })) {
				errno = EBUSY;
				return (false);
			}
		} else if (replay_host) {
			/* HT-C BEGIN: disabled trace continuity. */
			if (std::any_of(dfd.outbound_deliveries.begin(),
			    dfd.outbound_deliveries.end(),
			    [&](const outbound_delivery &item) {
				return item.delivery_id == header.elf.delivery_id;
			    })) {
				errno = EBUSY;
				return (false);
			}
			/* HT-C END */
		} else {
			while (std::any_of(dfd.outbound_deliveries.begin(),
			    dfd.outbound_deliveries.end(),
			    [&](const outbound_delivery &item) {
				return item.delivery_id == header.elf.delivery_id;
			    }))
				arc4random_buf(&header.elf.delivery_id,
				    sizeof(header.elf.delivery_id));
		}
		if (header.elf.delivery_id == 0)
			return (false);
		delivery.delivery_id = header.elf.delivery_id;
		std::array<uint8_t, SHA256_DIGEST_LENGTH> actual_digest{};
		if (SHA256(contents + host_elf_offset,
		    elflen - host_elf_offset, actual_digest.data()) == NULL)
			return (false);
		if (replay_host) {
			/* HT-C BEGIN: disabled trace continuity. */
			durable = *ne.replay;
			if (durable.payload_digest != actual_digest ||
			    durable.session_id != dfd.session_id ||
			    durable.delivery_id != delivery.delivery_id ||
			    durable.vmid != target_vmid ||
			    durable.epoch != target_epoch ||
			    durable.program_id != delivery.program_id ||
			    durable.source_id != delivery.source_id ||
			    durable.peer_uid != dfd.peer_uid ||
			    dfd.peer_pid <= 1 ||
			    durable.peer_pid != (uint32_t)dfd.peer_pid) {
				errno = EPROTO;
				return (false);
			}
			/* HT-C END */
		} else if (recorded != nullptr) {
			durable = *recorded;
			if (durable.payload_digest != actual_digest ||
			    durable.delivery_id != delivery.delivery_id ||
			    durable.vmid != target_vmid ||
			    durable.epoch != target_epoch) {
				errno = EPROTO;
				return (false);
			}
			int phase = ne.dir->state->outbounddir->delivery_status(
			    durable);
			if (phase < 0)
				return (false);
			if (phase != (int)delivery_phase::pending) {
				if (phase == 0) {
					errno = EPROTO;
					return (false);
				}
				/* Already accepted by this VM lifetime. */
				return (dfd.re_enable_write());
			}
		} else {
			durable.session_id = dfd.session_id;
			durable.delivery_id = delivery.delivery_id;
			durable.vmid = target_vmid;
			durable.epoch = target_epoch;
			durable.program_id = delivery.program_id;
			durable.source_id = delivery.source_id;
			durable.peer_uid = dfd.peer_uid;
			durable.peer_pid = dfd.peer_pid;
			/* The optional VM target envelope is not part of the
			 * portable ELF identity. */
			durable.journal_version = 4;
			durable.payload_digest = actual_digest;
		}
		try {
			dfd.outbound_deliveries.push_back(delivery);
		} catch (const std::bad_alloc &) {
			errno = ENOMEM;
			return (false);
		}
		pending.id = delivery.delivery_id;
		pending.armed = true;
		/* The token must survive a crash before any ELF bytes leave. */
		if (!replay_host && recorded == nullptr &&
		    !ne.dir->state->outbounddir->record_delivery(durable,
		    delivery_phase::pending, true)) {
			int saved = errno;
			if (saved == EBUSY) {
				durable_handoff active{};
				this->handoff_deferred =
				    ne.dir->state->outbounddir->source_handoff_for_vm(
				    target_vmid, target_epoch, active) > 0;
			}
			errno = saved;
			return (false);
		}
	}
	if (guest_forwarder) {
		if (ne.dir->state->outbounddir == nullptr) {
			errno = EPROTO;
			return (false);
		}
		std::array<uint8_t, 32> actual_digest{};
		if (SHA256(contents, elflen, actual_digest.data()) == NULL)
			return (false);
		if (replay_guest) {
			durable = *ne.replay;
			if (durable.delivery_id == 0 ||
			    durable.payload_digest != actual_digest ||
			    ne.dir->state->outbounddir->delivery_status(durable) !=
			    (int)delivery_phase::pending) {
				errno = EPROTO;
				return (false);
			}
		}
		uint16_t current_vmid = 0;
		uint64_t current_epoch = 0;
		if (!ne.dir->state->query_vm_identity(current_vmid,
		    current_epoch))
			return (false);
		header.elf.vmid = current_vmid;
		header.elf.epoch = current_epoch;
		if (replay_guest) {
			if (current_vmid != ne.replay_vmid ||
			    current_epoch != ne.replay_epoch ||
			    (durable.vmid != 0 &&
			    (durable.vmid != current_vmid ||
			    durable.epoch != current_epoch))) {
				errno = ESTALE;
				return (false);
			}
		} else {
			durable.session_id = dfd.session_id;
			durable.delivery_id = header.elf.delivery_id;
			durable.vmid = current_vmid;
			durable.epoch = current_epoch;
			memcpy(durable.program_id.data(), header.elf.program_id, 16);
			memcpy(durable.source_id.data(), header.elf.source_id, 16);
			durable.peer_uid = dfd.peer_uid;
			durable.peer_pid = dfd.peer_pid;
			durable.scope = 2;
			durable.journal_version = 4;
			durable.payload_digest = actual_digest;
			bool recorded = false;
			for (unsigned attempt = 0; attempt < 8; attempt++) {
				if (ne.dir->state->outbounddir->record_delivery(durable,
				    delivery_phase::pending, true)) {
					recorded = true;
					break;
				}
				if (errno != EEXIST)
					return (false);
				do {
					arc4random_buf(&durable.delivery_id,
					    sizeof(durable.delivery_id));
				} while (durable.delivery_id == 0);
				header.elf.delivery_id = durable.delivery_id;
			}
			if (!recorded) {
				errno = EEXIST;
				return (false);
			}
		}
	}

	std::unique_lock<std::mutex> host_consumer_revocations;
	std::unique_ptr<dir::source_transaction> host_consumer_source;
	durable_consumer_receipt processing_receipt{};
	durable_committed_import_result_state imported_processing{};
	bool imported_consumer = false;
	if (dfd.kind == DTRACED_KIND_CONSUMER && ne.dir->state != nullptr &&
	    ne.dir->state->is_control_machine() &&
	    ne.dir == ne.dir->state->inbounddir) {
		{
			std::lock_guard clients(ne.dir->state->sockfdsmtx);
			if (!dfd.consumer_program_valid ||
			    dfd.consumer_replay_pending ||
			    dfd.consumer_replay_registration_pending.load()) {
				errno = EAGAIN;
				return (false); // No frame bytes before registration.
			}
		}
		uint8_t program_id[16], source_id[16];
		if (spool_program_id(ne.path, program_id, source_id)) {
			state *s = ne.dir->state;
			durable_delivery_state accepted{};
			int phase = ne.dir->host_ingress_phase(program_id,
			    source_id, &accepted);
			if (phase < 0)
				return (false);
			if (phase != (int)delivery_phase::accepted)
				return (dfd.re_enable_write());
			/* The watcher may queue an accepted artifact before a local
			 * spool replacement. Revalidate the guest identity and the
			 * durable bare-ELF digest from the bytes actually being sent. */
			hypertrace_vm_envelope envelope{};
			char vm_name[HYPERTRACE_VM_ATTEST_NAME_LEN] = {};
			size_t elf_offset = 0;
			uint8_t actual_digest[SHA256_DIGEST_LENGTH];
			if ((accepted.record.journal_version != 4 &&
			    accepted.record.journal_version != 5) ||
			    elflen < HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 4) {
				errno = EPROTO;
				return (false);
			}
			hypertrace_envelope_decode(&envelope, contents);
			if (envelope.name_length == 0 ||
			    envelope.name_length >= sizeof(vm_name) ||
			    envelope.name_length > elflen -
			    HYPERTRACE_VM_ENVELOPE_WIRE_SIZE - 4) {
				errno = EPROTO;
				return (false);
			}
			memcpy(vm_name, contents + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
			    envelope.name_length);
			if (!parse_guest_elf_envelope(contents, elflen,
			    accepted.record.vmid, accepted.record.epoch, vm_name,
			    elf_offset) || SHA256(contents + elf_offset,
			    elflen - elf_offset, actual_digest) == NULL ||
			    memcmp(actual_digest,
			    accepted.record.payload_digest.data(),
			    sizeof(actual_digest)) != 0) {
				errno = EPROTO;
				return (false);
			}
			if (s->outbounddir == nullptr) {
				errno = EINVAL;
				return (false);
			}
			if (accepted.record.journal_version == 5) {
				/* HT-C BEGIN: disabled trace continuity. */
				int found = ne.dir->load_activated_import_recipient(
				    accepted.record.handoff_token,
				    accepted.record.session_id,
				    accepted.record.delivery_id, dfd.session_id,
				    (uint32_t)dfd.peer_uid,
				    (uint32_t)dfd.peer_pid, imported_processing);
				if (found != 1) {
					if (found == 0)
						errno = EBUSY;
					return (false);
				}
				const auto &fixed = imported_processing.recipient;
				if (fixed.ingress.session_id !=
				    accepted.record.session_id ||
				    fixed.ingress.delivery_id !=
				    accepted.record.delivery_id ||
				    fixed.ingress.vmid != accepted.record.vmid ||
				    fixed.ingress.epoch != accepted.record.epoch ||
				    fixed.ingress.program_id !=
				    accepted.record.program_id ||
				    fixed.ingress.source_id !=
				    accepted.record.source_id ||
				    fixed.ingress.peer_uid !=
				    accepted.record.peer_uid ||
				    fixed.ingress.peer_pid !=
				    accepted.record.peer_pid ||
				    fixed.ingress.handoff_token !=
				    accepted.record.handoff_token ||
				    fixed.ingress.source_session !=
				    accepted.record.source_session ||
				    fixed.ingress.payload_vmid !=
				    accepted.record.payload_vmid ||
				    fixed.ingress.payload_epoch !=
				    accepted.record.payload_epoch ||
				    fixed.ingress.payload_digest !=
				    accepted.record.payload_digest ||
				    dfd.retired.load() ||
				    dfd.consumer_replay_pending ||
				    !dfd.consumer_birth_valid ||
				    !dfd.consumer_program_valid ||
				    memcmp(fixed.owner_wire.data() + 28,
				    dfd.consumer_birth.data(), 16) != 0 ||
				    fixed.program_digest !=
				    dfd.consumer_program_digest) {
					errno = EPROTO;
					return (false);
				}
				if (imported_processing.outcome.phase !=
				    consumer_receipt_phase::pending)
					return (dfd.re_enable_write());
				imported_consumer = true;
				/* HT-C END */
			}
			/* Hash outside the KILL lock; take it only for the final
			 * revocation check and socket publication. */
			host_consumer_revocations =
			    std::unique_lock(s->revocationmtx);
			int revoked = s->outbounddir->source_revoked_for_vm(
			    source_id, accepted.record.vmid, accepted.record.epoch);
			if (revoked < 0)
				return (false);
			if (revoked > 0)
				return (dfd.re_enable_write());
			/* Serialize the entire local consumer send with PREPARE. An
			 * accepted upload may be pending in the daemon job queue even
			 * after guest ingress itself has been fenced. */
			host_consumer_source = s->outbounddir->lock_live_source(
			    source_id, accepted.record.vmid, accepted.record.epoch);
			if (!host_consumer_source) {
				if (errno == ECANCELED) {
					durable_session_stop stopped{};
					int closed = s->outbounddir->fresh_session_stop_for_vm(
					    accepted.record.vmid, accepted.record.epoch,
					    stopped);
					if (closed == 1)
						/* Drop the old delivery but retain the connection
						 * for its explicit collector-stop exchange. */
						return (dfd.re_enable_write());
					if (closed == 0)
						errno = ECANCELED;
				}
				if (errno == EBUSY) {
					this->handoff_vmid = accepted.record.vmid;
					this->handoff_epoch = accepted.record.epoch;
					this->handoff_deferred = true;
				}
				return (false);
			}
			/* Carry the authenticated ingress identity to the consumer.
			 * A later processing receipt must name this exact delivery,
			 * rather than infer it from mutable spool or VM names. */
			memcpy(header.elf.program_id, program_id,
			    sizeof(header.elf.program_id));
			memcpy(header.elf.source_id, source_id,
			    sizeof(header.elf.source_id));
			header.elf.delivery_id = accepted.record.delivery_id;
			header.elf.vmid = accepted.record.vmid;
			header.elf.epoch = accepted.record.epoch;
			/* The source journal session disambiguates equal delivery IDs
			 * from separate ingress owners.  On daemon-to-consumer ELF
			 * frames the parent slot mirrors this ingress and carries its
			 * 16-byte session; derived uploads use their own parent slot. */
			header.installed.delivery_id = accepted.record.delivery_id;
			header.installed.vmid = accepted.record.vmid;
			header.installed.epoch = accepted.record.epoch;
			memcpy(header.installed.program_id,
			    accepted.record.program_id.data(), 16);
			memcpy(header.installed.source_id,
			    accepted.record.source_id.data(), 16);
			memcpy(header.installed.name,
			    accepted.record.session_id.data(), 16);
			processing_receipt.ingress = accepted.record;
			processing_receipt.consumer_session = dfd.session_id;
			processing_receipt.consumer_uid = (uint32_t)dfd.peer_uid;
			processing_receipt.consumer_pid = (uint32_t)dfd.peer_pid;
			if (!imported_consumer) {
				std::array<uint8_t, 24> lifetime{};
				int modern = ne.dir->consumer_handle_status(
				    processing_receipt, lifetime);
				if (modern < 0)
					return (false);
				if (modern == 1) {
					std::lock_guard clients(s->sockfdsmtx);
					if (!dfd.consumer_program_valid ||
					    dfd.consumer_process_fd < 0 ||
					    dfd.consumer_replay_registration_pending.load() ||
					    dfd.consumer_handle_lifetime != lifetime) {
						errno = EAGAIN;
						return (false); // No frame header has been sent.
					}
				}
			}
			/* Recheck the immutable handle binding at send time as well as
			 * initial queueing: reconnect replay may bypass the latter. */
			if (!imported_consumer && dfd.consumer_program_valid &&
			    ne.dir->record_consumer_program(processing_receipt, dfd) != 1)
				return (false);
		}
	}

	if (!send_header(dfd, header, deadline)) {
		ERR("failed to write to %s (%s, %zu): %m", dfd.ident, ne.path,
		    ne.pathlen);
		return (false);
	}

	if (!dfd.send(&msg[0], msglen, deadline)) {
		ERR("failed to write to %s (%s, %zu): %m", dfd.ident, ne.path,
		    ne.pathlen);
		return (false);
	}
	if (host_consumer_source) {
		/* The complete frame is now on the consumer socket. Its derived
		 * publication needs the same source and revocation locks, so release
		 * them before waiting for its ACK. PREPARE still rejects this accepted
		 * ingress until a durable handoff can reconcile its outcome. */
		host_consumer_source.reset();
		host_consumer_revocations.unlock();
		unsigned char ack_wire[DTRACED_CONSUMER_ACK_WIRE_SIZE];
		dtraced_consumer_ack_t ack{};
		int64_t processed_deadline = dtraced_io_deadline_after(60000);
		if (processed_deadline < 0)
			return (false);
		if (!dfd.recv(ack_wire, sizeof(ack_wire), processed_deadline)) {
			int receive_error = errno != 0 ? errno : ECONNRESET;
			if (!(imported_consumer ?
			    reconcile_lost_import_ack(*ne.dir,
			    imported_processing) :
			    reconcile_lost_consumer_ack(*ne.dir,
			    processing_receipt)))
				return (false);
			errno = receive_error;
			return (false);
		}
		if (dtraced_wire_decode_consumer_ack(&ack, ack_wire) != 0 ||
		    (ack.outcome != DTRACED_CONSUMER_ACK_NO_DERIVED &&
		    ack.outcome != DTRACED_CONSUMER_ACK_DERIVED) ||
		    ack.delivery_id != header.elf.delivery_id ||
		    ack.vmid != header.elf.vmid ||
		    ack.epoch != header.elf.epoch ||
		    memcmp(ack.program_id, header.elf.program_id, 16) != 0 ||
		    memcmp(ack.source_id, header.elf.source_id, 16) != 0) {
			/* A failure or malformed ACK cannot certify processing, but
			 * an independently durable derived result still can. */
			if (!(imported_consumer ?
			    reconcile_lost_import_ack(*ne.dir,
			    imported_processing) :
			    reconcile_lost_consumer_ack(*ne.dir,
			    processing_receipt)))
				return (false);
			errno = EPROTO;
			return (false);
		}
		/* A replay can find the consumer program already valid and ACK
		 * without emitting a second ELF. The durable HDU2 claim, not that
		 * process-local decision, determines whether this ingress derived a
		 * program. Conversely an ACK claiming a derived program must have a
		 * complete spool or an accepted outbound receipt. Serialize this
		 * decision with a competing derived publication, across processes. */
		consumer_outcome_lock outcome_lock(ne.dir->dirfd);
		if (!outcome_lock.held())
			return (false);
		std::vector<durable_derived_claim> claims;
		if (!ne.dir->state->outbounddir->list_derived_claims(claims))
			return (false);
		const durable_derived_claim *derived = nullptr;
		std::array<uint8_t, 32> derived_digest{};
		for (const auto &claim : claims) {
			if (claim.consumer_session !=
			    processing_receipt.consumer_session ||
			    claim.ingress_delivery_id != ack.delivery_id ||
			    claim.ingress_vmid != ack.vmid ||
			    claim.ingress_epoch != ack.epoch ||
			    memcmp(claim.ingress_program_id.data(), ack.program_id,
			    16) != 0 ||
			    memcmp(claim.ingress_source_id.data(), ack.source_id,
			    16) != 0)
				continue;
			if (derived != nullptr) {
				errno = EPROTO;
				return (false);
			}
			derived = &claim;
		}
		if (derived != nullptr) {
			if (imported_consumer) {
				/* HT-C BEGIN: disabled trace continuity. */
				int status = ne.dir->resolve_import_derived_outbound(
				    *ne.dir->state->outbounddir,
				    imported_processing, *derived, derived_digest);
				if (status != 1) {
					if (status == 0)
						errno = EAGAIN;
					return (false);
				}
				/* HT-C END */
			} else {
				durable_consumer_receipt_state resolved{};
				int status = ne.dir->resolve_derived_outbound(
				    *ne.dir->state->outbounddir,
				    derived->derived_program_id.data(), ack.source_id,
				    resolved);
				if (status != 1) {
					if (status == 0)
						errno = EAGAIN;
					return (false);
				}
				if (resolved.record.consumer_session !=
				    processing_receipt.consumer_session ||
				    resolved.record.ingress.delivery_id != ack.delivery_id ||
				    resolved.record.ingress.vmid != ack.vmid ||
				    resolved.record.ingress.epoch != ack.epoch ||
				    memcmp(resolved.record.ingress.program_id.data(),
				    ack.program_id, 16) != 0 ||
				    memcmp(resolved.record.ingress.source_id.data(),
				    ack.source_id, 16) != 0) {
					errno = EPROTO;
					return (false);
				}
			}
		} else if (ack.outcome == DTRACED_CONSUMER_ACK_DERIVED) {
			errno = EPROTO;
			return (false);
		}
		consumer_receipt_phase outcome = derived != nullptr ?
		    consumer_receipt_phase::derived :
		    consumer_receipt_phase::no_derived;
		int recorded = imported_consumer ?
		    ne.dir->record_activated_import_processing(
		    imported_processing, outcome, derived_digest) :
		    ne.dir->record_consumer_receipt(processing_receipt, outcome);
		if (recorded < 0 || (derived != nullptr ?
		    !consumer_receipt_derived((consumer_receipt_phase)recorded) :
		    !consumer_receipt_no_derived((consumer_receipt_phase)recorded)))
			return (false);
	}
	/* The ACK confirms guest queueing for host forwarders and host-daemon
	 * acceptance for the guest's local forwarder. A socket write proves neither. */
	if (dfd.kind == DTRACED_KIND_FORWARDER) {
		dtraced_delivery_ack_t ack;
		unsigned char ack_wire[DTRACED_ACK_WIRE_SIZE];
		if (!dfd.recv(ack_wire, sizeof(ack_wire), deadline))
			return (false);
		dtraced_wire_decode_ack(&ack, ack_wire);
		if (ack.delivery_id != header.elf.delivery_id) {
			errno = EPROTO;
			return (false);
		}
		if (host_forwarder) {
			std::lock_guard lock(dfd.installed_mtx);
			/* Guest queue acceptance precedes a durable accepted transition. */
			bool recorded = replay_host ?
			    ne.dir->state->outbounddir->
			    accept_claimed_source_journal_replay(durable) :
			    ne.dir->state->outbounddir->record_delivery(durable,
			    delivery_phase::accepted);
			if (!recorded && errno != ECANCELED)
				return (false);
			for (outbound_delivery &delivery : dfd.outbound_deliveries)
				if (delivery.delivery_id == ack.delivery_id) {
					delivery.accepted = true;
					break;
				}
		} else if (guest_forwarder &&
		    (!ne.dir->state->outbounddir->record_delivery(durable,
		    delivery_phase::accepted) ||
		    !ne.dir->state->outbounddir->retire_accepted_outbound(durable))) {
			return (false);
		}
	}

	if (!dfd.re_enable_write()) {
		ERR("re_enable_write() failed with: %m");
		return (false);
	}
	if (host_forwarder) {
		std::lock_guard lock(dfd.installed_mtx);
		for (const outbound_delivery &delivery : dfd.outbound_deliveries)
			if (delivery.delivery_id == pending.id &&
			    (delivery.revoked || delivery.retired))
				return (true); /* Guard retires the closed delivery. */
	}
	pending.armed = false;

	return (true);
}

bool
job::send_kill(state &s)
{
	std::lock_guard output(this->connsockfd->output_mtx);
	this->handoff_deferred = false;
	int64_t deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0)
		return (false);
	dtraced_hdr_t header{};
	client_fd &dfd = *this->connsockfd;
	kill_job &k = this->kill_get();

	if (k.pid <= 1 || k.vmid == 0 || k.epoch == 0) {
		ERR("unexpected pid: %d", k.pid);
		return (false);
	}
	const uint8_t zero_source[DTRACED_PROGRAM_ID_LEN] = {};
	if (memcmp(k.source_id, zero_source, sizeof(zero_source)) == 0) {
		errno = EPROTO;
		return (false);
	}
	if (dfd.kind == DTRACED_KIND_FORWARDER && dfd.vmid != 0 &&
	    (dfd.vmid != k.vmid || dfd.vm_epoch != k.epoch ||
	    !dfd.current_vm_attestation())) {
		errno = ESTALE;
		return (false);
	}
	if (s.is_control_machine() && dfd.kind == DTRACED_KIND_FORWARDER) {
		if (s.outbounddir == nullptr) {
			errno = EINVAL;
			return (false);
		}
		durable_handoff active{};
		int phase = s.outbounddir->source_handoff_for_vm(
		    k.vmid, k.epoch, active);
		if (phase < 0)
			return (false);
		if (phase != 0) {
			this->handoff_deferred = true;
			errno = EBUSY;
			return (false);
		}
	}

	/* Preserve the durable revocation's exact VM lifetime on the wire. */
	DTRACED_MSG_TYPE(header) = DTRACED_MSG_KILL;
	DTRACED_MSG_KILLPID(header) = k.pid;
	DTRACED_MSG_KILLVMID(header) = k.vmid;
	DTRACED_MSG_KILLEPOCH(header) = k.epoch;
	memcpy(header.kill.source_id, k.source_id,
	    sizeof(header.kill.source_id));

	if (!send_header(dfd, header, deadline)) {
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
job::send_info(state &s) try
{
	std::lock_guard output(this->connsockfd->output_mtx);
	const int64_t deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0)
		return (false);
	dtraced_hdr_t hdr{};
	client_fd &dfd = *this->connsockfd;
	std::vector<dtraced_infomsg_t> imsgs;

	size_t i = 0;
	{
		std::lock_guard lk(s.sockfdsmtx);
		imsgs.resize(s.sockfds.size(), {0, {0}});
		for (client_fd *cp : s.sockfds) {
			imsgs[i].client_kind = cp->kind;
			memcpy(imsgs[i++].client_name, cp->ident,
			    DTRACED_FDIDENTLEN);
		}
	}

	hdr.msg_type = DTRACED_MSG_INFO;
	hdr.info.count = imsgs.size();
	std::vector<unsigned char> wire(imsgs.size() * DTRACED_INFO_WIRE_SIZE);
	for (size_t item = 0; item < imsgs.size(); ++item)
		dtraced_wire_encode_info(wire.data() +
		    item * DTRACED_INFO_WIRE_SIZE, &imsgs[item]);

	if (!send_header(dfd, hdr, deadline))
		return (false);
	return (wire.empty() || dfd.send(wire.data(), wire.size(), deadline));
} catch (const std::bad_alloc &) {
	errno = ENOMEM;
	return (false);
}

bool
job::read_data(state &s) try
{
	int64_t deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0)
		return (false);
	using uchar = unsigned char;

	client_fd &dfd = *this->connsockfd;
	dtraced_hdr_t header{};

	unsigned char size_wire[8];
	if (!dfd.recv(size_wire, sizeof(size_wire), deadline))
		return (false);
	uint64_t frame_size = dtraced_wire_get_u64(size_wire);

	if (frame_size < DTRACED_MSGHDRSIZE ||
	    frame_size > max_request_bytes) {
		ERR("invalid frame size (%ju), header size (%zu)",
		    (uintmax_t)frame_size, (size_t)DTRACED_MSGHDRSIZE);
		return (false);
	}
	if (dfd.is_subscribed(DTD_SUB_SOURCE_RELEASE) &&
	    frame_size != DTRACED_MSGHDRSIZE + DTRACED_HANDOFF_WIRE_SIZE) {
		/* HT-C BEGIN: disabled trace continuity. */
		errno = EPROTO;
		return (false);
		/* HT-C END */
	}
	size_t totalbytes = (size_t)frame_size;
	unsigned char header_wire[DTRACED_MSGHDRSIZE];
	if (!dfd.recv(header_wire, sizeof(header_wire), deadline) ||
	    dtraced_wire_decode_header(&header, header_wire) != 0)
		return (false);
	if (dfd.is_subscribed(DTD_SUB_SOURCE_RELEASE) &&
	    header.msg_type != DTRACED_MSG_HANDOFF) {
		/* HT-C BEGIN: disabled trace continuity. */
		errno = EPROTO;
		return (false);
		/* HT-C END */
	}
	if (header.msg_type == DTRACED_MSG_HANDOFF_IMPORT &&
	    totalbytes > DTRACED_MSGHDRSIZE +
	    DTRACED_HANDOFF_IMPORT_BINDING_SIZE +
	    DTRACED_TRANSFER_MAX_SIZE) {
		/* HT-C BEGIN: disabled trace continuity. */
		errno = E2BIG;
		return (false);
		/* HT-C END */
	}
	if ((header.msg_type == DTRACED_MSG_SESSION_STOP ||
	    header.msg_type == DTRACED_MSG_SESSION_RELEASE) &&
	    frame_size != DTRACED_MSGHDRSIZE + DTRACED_SESSION_STOP_WIRE_SIZE) {
		errno = EPROTO;
		return (false);
	}
	if (header.msg_type == DTRACED_MSG_CONSUMER_STOP_COMMIT &&
	    frame_size != DTRACED_MSGHDRSIZE + DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE) {
		errno = EPROTO;
		return (false);
	}
	if (header.msg_type == DTRACED_MSG_HANDOFF_IMPORT &&
	    frame_size > 1024 * 1024) {
		/* HT-C BEGIN: disabled trace continuity. */
		deadline = dtraced_io_deadline_after(60000);
		if (deadline < 0)
			return (false);
		/* HT-C END */
	}

	std::vector<uchar> buf(totalbytes, 0);
	memcpy(buf.data(), header_wire, sizeof(header_wire));

	if (totalbytes != sizeof(header_wire) &&
	    !dfd.recv(buf.data() + sizeof(header_wire),
	    totalbytes - sizeof(header_wire), deadline)) {
		/* recv() already shut the stream down (a partial frame is never
		 * reused), so no status byte can follow: the peer sees EOF. */
		if (!dfd.re_enable_read())
			ERR("re_enable_read() failed on %s with: %m",
			    dfd.ident);
		return (false);
	}

	/* The canonical header was checked before allocating the body. */
	client_request cr(s, header, buf.data() + DTRACED_MSGHDRSIZE,
	    totalbytes - DTRACED_MSGHDRSIZE, &dfd);
	if (header.msg_type == DTRACED_MSG_CONSUMER_PROGRAM) {
		/* Registration can release replayed or imported ELF jobs for this
		 * same socket while the client waits for its one-byte status. An
		 * ELF frame begins with the same byte as an ACK, so hold the output
		 * stream from registration through the status: no job frame may
		 * precede it. Registration takes no output lock of its own. */
		std::unique_lock output(dfd.output_mtx);
		unsigned char status = cr.handle() ? 1 : 0;
		if (!dfd.send(&status, sizeof(status), deadline)) {
			ERR("sending response failed on %s with: %m", dfd.ident);
			return (false);
		}
		output.unlock();
		if (!dfd.re_enable_read()) {
			ERR("re_enable_read() failed with: %m");
			return (false);
		}
		return (true);
	}
	bool accepted = cr.handle();
	int64_t response_deadline = cr.transfer_response() != nullptr ?
	    dtraced_io_deadline_after(60000) :
	    (header.msg_type == DTRACED_MSG_SESSION_STOP ||
	    header.msg_type == DTRACED_MSG_SESSION_RELEASE ||
	    header.msg_type == DTRACED_MSG_CONSUMER_STOP_COMMIT ||
	    cr.drain_step_response() != nullptr ||
	    cr.release_response() != nullptr) ?
	    dtraced_io_deadline_after(10000) : deadline;
	if (response_deadline < 0 ||
	    !(cr.transfer_response() != nullptr ?
	    dfd.respond_with_transfer(accepted, cr.transfer_response(),
	    response_deadline) : cr.drain_step_response() != nullptr ?
	    dfd.respond_with_drain_step(accepted,
	    cr.drain_step_response(), response_deadline) :
	    cr.release_response() != nullptr ?
	    dfd.respond_with_release(accepted, cr.release_response(),
	    cr.release_response_signed(), response_deadline) :
	    cr.stats_response() != nullptr ?
	    dfd.respond_with_stats(accepted, cr.stats_response(), deadline) :
	    dfd.respond_with_status(accepted, cr.status_response(), response_deadline))) {
		ERR("sending response failed on %s with: %m", dfd.ident);
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
} catch (const std::bad_alloc &) {
	/* The frame has not been consumed; the worker retires this connection. */
	errno = ENOMEM;
	return (false);
}

bool
job::send_cleanup(state &s)
{
	std::lock_guard output(this->connsockfd->output_mtx);
	this->handoff_deferred = false;
	const int64_t deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0)
		return (false);
	dtraced_hdr_t header{};
	size_t buflen;
	client_fd &dfd = *this->connsockfd;
	cleanup_job &c = *this->cleanup_get();

	DEBUG("CLEANUP to %d-%s", dfd.get_fd(), dfd.ident);
	if (dfd.kind == DTRACED_KIND_FORWARDER &&
	    !dfd.current_vm_attestation()) {
		errno = ESTALE;
		return (false);
	}
	const bool host_forwarder = s.is_control_machine() &&
	    dfd.kind == DTRACED_KIND_FORWARDER;
	if (host_forwarder && (!this->cleanup_journaled ||
	    this->cleanup_delivery_id == 0)) {
		errno = EPROTO;
		return (false);
	}

	DTRACED_MSG_TYPE(header) = DTRACED_MSG_CLEANUP;
	DTRACED_MSG_NUMENTRIES(header) = c.size();
	header.cleanup.vmid = dfd.vmid;
	header.cleanup.epoch = dfd.vm_epoch;
	DTRACED_MSG_CLEANUP_DELIVERY_ID(header) = this->cleanup_delivery_id;

	auto send_frame = [&]() {
		if (!send_header(dfd, header, deadline)) {
			if (errno != EPIPE)
				ERR("failed to write to %s: %m", dfd.ident);
			return (false);
		}

		for (std::string &entry : c) {
			buflen = entry.length() + 1;
			unsigned char size_wire[8];
			dtraced_wire_put_u64(size_wire, buflen);
			if (!dfd.send(size_wire, sizeof(size_wire), deadline) ||
			    !dfd.send(&entry[0], buflen, deadline)) {
				if (errno != EPIPE)
					ERR("failed to write to %s: %m", dfd.ident);
				return (false);
			}
		}
		if (host_forwarder) {
			unsigned char ack_wire[DTRACED_ACK_WIRE_SIZE];
			dtraced_delivery_ack_t ack{};
			if (!dfd.recv(ack_wire, sizeof(ack_wire), deadline))
				return (false);
			dtraced_wire_decode_ack(&ack, ack_wire);
			if (ack.delivery_id != this->cleanup_delivery_id) {
				errno = EPROTO;
				return (false);
			}
		}
		return (true);
	};

	if (host_forwarder) {
		if (s.outbounddir == nullptr) {
			errno = EINVAL;
			return (false);
		}
		bool sent = false;
		int phase = s.outbounddir->with_source_handoff_phase(
		    dfd.vmid, dfd.vm_epoch, [&](int current) {
			if (current == 0)
				sent = send_frame();
		});
		if (phase < 0)
			return (false);
		if (phase != 0) {
			this->handoff_deferred = true;
			errno = EBUSY;
			return (false);
		}
		if (!sent)
			return (false);
		durable_cleanup pending{};
		pending.vmid = dfd.vmid;
		pending.epoch = dfd.vm_epoch;
		pending.delivery_id = this->cleanup_delivery_id;
		/* The pending file keeps PREPARE closed after the queue ACK and
		 * across a daemon crash until this directory fsync settles it. */
		if (!s.outbounddir->record_cleanup_queued(pending))
			return (false);
	} else if (!send_frame()) {
		return (false);
	}

	if (!dfd.re_enable_write()) {
		ERR("re_enable_write() failed with: %m");
		return (false);
	}

	return (true);
}

}
