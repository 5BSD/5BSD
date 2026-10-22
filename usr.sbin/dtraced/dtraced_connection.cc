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
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ucred.h>
#include <sys/hypertrace.h>
#include <sys/ioctl.h>
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atomic>

#include "dtraced.h"
#include "dtraced_socket.h"
#include "dtraced_io.h"
#include "dtraced_wire.h"
#include "dtraced_transfer_wire.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_errmsg.h"
#include "dtraced_id.h"
#include "dtraced_job.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

namespace dtraced {

client_fd::client_fd(int _kq, int _fd, dtd_initmsg_t initmsg)
    : kq(_kq)
    , fd(_fd)
    , subs(initmsg.subs)
    , cleaned_up(false)
    , id(0)
    , kind(initmsg.kind)
{
	memcpy(this->ident, initmsg.ident, DTRACED_FDIDENTLEN);
	this->ident[DTRACED_FDIDENTLEN - 1] = '\0';
	memcpy(this->session_id.data(), initmsg.session_id,
	    this->session_id.size());
	struct xucred cred = {};
	socklen_t len = sizeof(cred);
	if (getsockopt(this->fd, SOL_LOCAL, LOCAL_PEERCRED, &cred,
	    &len) == 0 && len == sizeof(cred) &&
	    cred.cr_version == XUCRED_VERSION && cred.cr_pid > 0) {
		this->peer_uid = cred.cr_uid;
		this->peer_pid = cred.cr_pid;
	}
	uint32_t claimed_pid = 0;
	this->consumer_birth_valid = this->kind == DTRACED_KIND_CONSUMER &&
	    parse_consumer_birth(this->ident, claimed_pid,
	    this->consumer_birth) && claimed_pid == (uint32_t)this->peer_pid;
	this->id = dtraced_genid();
}

bool
client_fd::current_vm_attestation(void) const
{
	if (this->vm_attestation_fd < 0)
		return (this->vmid == 0 && this->vm_epoch == 0);
#ifdef DTRACED_HAS_VM_ATTESTATION
	struct hypertrace_vm_attestation identity = {};
	return (ioctl(this->vm_attestation_fd, VM_GET_ATTESTATION,
	    &identity) == 0 && identity.vmid == this->vmid &&
	    identity.epoch == this->vm_epoch &&
	    memchr(identity.name, '\0', sizeof(identity.name)) != NULL &&
	    strcmp(identity.name, this->ident) == 0);
#else
	return (false);
#endif
}

bool
client_fd::same_forwarder(const client_fd &other) const
{
	return (this->kind == DTRACED_KIND_FORWARDER &&
	    other.kind == DTRACED_KIND_FORWARDER &&
	    this->peer_pid > 0 && this->peer_pid == other.peer_pid &&
	    this->peer_uid != (uid_t)-1 && this->peer_uid == other.peer_uid &&
	    this->vmid == other.vmid && this->vm_epoch == other.vm_epoch &&
	    this->current_vm_attestation() && other.current_vm_attestation() &&
	    this->session_id == other.session_id &&
	    strcmp(this->ident, other.ident) == 0);
}

bool
client_fd::enable_read(void *data)
{
	struct kevent change_event[1];

	EV_SET(change_event, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, data);
	return (kevent(this->kq, change_event, 1, NULL, 0, NULL) != -1);
}

bool
client_fd::enable_write(void *data)
{
	struct kevent change_event[1];

	EV_SET(change_event, fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, data);
	return (kevent(this->kq, change_event, 1, NULL, 0, NULL) != -1);
}

bool
client_fd::enable_rw(void *data)
{

	return (this->enable_read(data) && this->enable_write(data));
}

bool
client_fd::re_enable_read(void)
{
	if (this->retired.load()) {
		errno = ENOTCONN;
		return (false);
	}

	struct kevent change_event[1];

	EV_SET(change_event, this->fd, EVFILT_READ,
	    EV_ENABLE | EV_KEEPUDATA, 0, 0, 0);
	return (kevent(this->kq, change_event, 1, NULL, 0, NULL) != -1);
}

bool
client_fd::re_enable_write(void)
{
	if (this->retired.load()) {
		errno = ENOTCONN;
		return (false);
	}

	struct kevent change_event[1];

	EV_SET(change_event, this->fd, EVFILT_WRITE,
	    EV_ENABLE | EV_KEEPUDATA, 0, 0, 0);
	return (kevent(this->kq, change_event, 1, NULL, 0, NULL) != -1);
}

void
client_fd::close(void)
{

	if (this->fd != -1) {
		LOG("close(%d-%s)", this->fd, this->ident);
		::close(this->fd);
		this->fd = -1;
	}
}

void
client_fd::shutdown(void)
{

	::shutdown(this->fd, SHUT_RDWR);
}

client_fd::operator std::string(void) const
{

	return (std::to_string(this->fd) + "-" + std::string(this->ident));
}

client_fd::~client_fd()
{
	if (this->consumer_process_fd >= 0)
		::close(this->consumer_process_fd);
	if (this->vm_epoch_query_fd >= 0)
		::close(this->vm_epoch_query_fd);
	if (this->vm_attestation_fd >= 0)
		::close(this->vm_attestation_fd);
	this->close();
}

ssize_t
client_fd::send_ack(void)
{

	std::lock_guard lk(this->output_mtx);
	unsigned char ack = 1;
	return (this->send(&ack, sizeof(ack)) ? 0 : -1);
}

ssize_t
client_fd::send_nak(void)
{

	std::lock_guard lk(this->output_mtx);
	unsigned char ack = 0;
	return (this->send(&ack, sizeof(ack)) ? 0 : -1);
}

bool
client_fd::respond(bool accepted)
{

	/* Exactly one status byte for each complete request. */
	return ((accepted ? this->send_ack() : this->send_nak()) == 0);
}

bool
client_fd::respond_with_status(bool accepted,
    const dtraced_delivery_status_t *status, int64_t deadline)
{
	std::lock_guard lk(this->output_mtx);
	unsigned char ack = accepted ? 1 : 0;
	unsigned char wire[DTRACED_STATUS_WIRE_SIZE];
	if (accepted && status != nullptr)
		dtraced_wire_encode_status(wire, status);
	return (this->send(&ack, sizeof(ack), deadline) &&
	    (!accepted || status == nullptr ||
	    this->send(wire, sizeof(wire), deadline)));
}

bool
client_fd::respond_with_stats(bool accepted, const dtraced_stats_t *stats,
    int64_t deadline)
{
	std::lock_guard lk(this->output_mtx);
	unsigned char ack = accepted ? 1 : 0;
	unsigned char wire[DTRACED_STATS_WIRE_SIZE];
	if (accepted && stats != nullptr)
		dtraced_wire_encode_stats(wire, stats);
	return (this->send(&ack, sizeof(ack), deadline) &&
	    (!accepted || stats == nullptr ||
	    this->send(wire, sizeof(wire), deadline)));
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
bool
client_fd::respond_with_transfer(bool accepted,
    std::vector<uint8_t> *transfer, int64_t deadline)
{
	std::lock_guard lk(this->output_mtx);
	unsigned char ack = accepted ? 1 : 0;
	unsigned char length[8];
	if (accepted && (transfer == nullptr || transfer->empty() ||
	    transfer->size() > DTRACED_TRANSFER_MAX_SIZE)) {
		errno = EPROTO;
		return (false);
	}
	if (accepted)
		dtraced_wire_put_u64(length, transfer->size());
	return (this->send(&ack, sizeof(ack), deadline) &&
	    (!accepted || (this->send(length, sizeof(length), deadline) &&
	    this->send(transfer->data(), transfer->size(), deadline))));
}
/* HT-C END */

bool
client_fd::respond_with_drain_step(bool accepted, const uint8_t *remaining,
    int64_t deadline)
{
	std::lock_guard lk(this->output_mtx);
	unsigned char ack = accepted ? 1 : 0;
	if (accepted && (remaining == nullptr || *remaining > 1)) {
		errno = EPROTO;
		return (false);
	}
	unsigned char value = accepted ? *remaining : 0;
	return (this->send(&ack, sizeof(ack), deadline) &&
	    (!accepted || this->send(&value, sizeof(value), deadline)));
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
bool
client_fd::respond_with_release(bool accepted, const uint8_t *attestation,
    bool signed_release, int64_t deadline)
{
	std::lock_guard lk(this->output_mtx);
	uint8_t ack = accepted ? 1 : 0;
	uint8_t mode = signed_release ? DTRACED_RELEASE_MODE_SIGNED :
	    DTRACED_RELEASE_MODE_LOCAL;
	if (accepted && attestation == nullptr) {
		errno = EPROTO;
		return (false);
	}
	return (this->send(&ack, sizeof(ack), deadline) &&
	    (!accepted || (this->send(&mode, sizeof(mode), deadline) &&
	    (!signed_release || this->send((void *)attestation,
	    DTRACED_RELEASE_ATTESTED_SIZE, deadline)))));
}
/* HT-C END */

bool
client_fd::send(void *b, size_t len, int64_t deadline)
{
	size_t transferred;
	if (this->kind == DTRACED_KIND_FORWARDER &&
	    !this->is_subscribed(DTD_SUB_SOURCE_RELEASE) &&
	    !this->current_vm_attestation()) {
		errno = ESTALE;
		this->shutdown();
		return (false);
	}
	if (deadline == 0)
		deadline = dtraced_io_deadline_after(10000);
	bool ok = deadline >= 0 &&
	    dtraced_io_transfer(this->fd, b, len, true, deadline,
	    &transferred) == 0;
	if (ok && this->kind == DTRACED_KIND_FORWARDER &&
	    !this->is_subscribed(DTD_SUB_SOURCE_RELEASE) &&
	    !this->current_vm_attestation()) {
		errno = ESTALE;
		ok = false;
	}
	if (!ok) {
		/* A partial frame must never be reused as a fresh request. */
		int error = errno;
		this->shutdown();
		errno = error;
	}
	return (ok);
}

bool
client_fd::recv(void *b, size_t len, int64_t deadline)
{
	size_t transferred;
	if (this->kind == DTRACED_KIND_FORWARDER &&
	    !this->is_subscribed(DTD_SUB_SOURCE_RELEASE) &&
	    !this->current_vm_attestation()) {
		errno = ESTALE;
		this->shutdown();
		return (false);
	}
	if (deadline == 0)
		deadline = dtraced_io_deadline_after(10000);
	bool ok = deadline >= 0 &&
	    dtraced_io_transfer(this->fd, b, len, false, deadline,
	    &transferred) == 0;
	if (ok && this->kind == DTRACED_KIND_FORWARDER &&
	    !this->is_subscribed(DTD_SUB_SOURCE_RELEASE) &&
	    !this->current_vm_attestation()) {
		errno = ESTALE;
		ok = false;
	}
	if (!ok) {
		/* A partial frame must never be reused as a fresh request. */
		int error = errno;
		this->shutdown();
		errno = error;
	}
	return (ok);
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
bool
client_fd::request_consumer_drain(const dtraced_consumer_drain_t &challenge)
{
	unsigned char header_wire[DTRACED_MSGHDRSIZE];
	unsigned char body_wire[DTRACED_CONSUMER_DRAIN_WIRE_SIZE];
	unsigned char ack_wire[DTRACED_CONSUMER_DRAIN_ACK_WIRE_SIZE];
	dtraced_consumer_drain_t canonical{}, ack{};
	dtraced_hdr_t header{};
	int64_t send_deadline, reply_deadline;

	if (this->kind != DTRACED_KIND_CONSUMER ||
	    !this->is_subscribed(DTD_SUB_ELFWRITE) ||
	    this->retired.load() ||
	    memcmp(challenge.consumer_session, this->session_id.data(),
	    this->session_id.size()) != 0) {
		errno = EPROTO;
		return (false);
	}
	dtraced_wire_encode_consumer_drain(body_wire, &challenge);
	if (dtraced_wire_decode_consumer_drain(&canonical, body_wire) != 0)
		return (false);
	header.msg_type = DTRACED_MSG_CONSUMER_DRAIN;
	header.elf.len = sizeof(body_wire);
	dtraced_wire_encode_header(header_wire, &header);
	std::lock_guard output(this->output_mtx);
	if (this->retired.load()) {
		errno = ESTALE;
		return (false);
	}
	send_deadline = dtraced_io_deadline_after(10000);
	if (send_deadline < 0)
		return (false);
	if (!this->send(header_wire, sizeof(header_wire), send_deadline) ||
	    !this->send(body_wire, sizeof(body_wire), send_deadline))
		return (false);
	reply_deadline = dtraced_io_deadline_after(60000);
	if (reply_deadline < 0 ||
	    !this->recv(ack_wire, sizeof(ack_wire), reply_deadline))
		return (false);
	if (dtraced_wire_decode_consumer_drain_ack(&ack, ack_wire) != 0 ||
	    memcmp(ack.token, canonical.token, sizeof(ack.token)) != 0 ||
	    memcmp(ack.source_session, canonical.source_session,
	    sizeof(ack.source_session)) != 0 ||
	    memcmp(ack.consumer_session, canonical.consumer_session,
	    sizeof(ack.consumer_session)) != 0 ||
	    memcmp(ack.program_digest, canonical.program_digest,
	    sizeof(ack.program_digest)) != 0 ||
	    ack.vmid != canonical.vmid || ack.epoch != canonical.epoch) {
		this->shutdown();
		errno = EPROTO;
		return (false);
	}
	if (ack.result != 1 || this->retired.load()) {
		errno = ack.result != 1 ? EOPNOTSUPP : ESTALE;
		return (false);
	}
	return (true);
}
/* HT-C END */

/* A lost or malformed stop reply leaves the result unknown. Retire the
 * stream so an old reply cannot satisfy a subsequent request. The caller
 * must keep checkpoint admission closed until retirement is proven. */
bool
client_fd::request_consumer_stop(const dtraced_consumer_stop_t &challenge)
{
	unsigned char header_wire[DTRACED_MSGHDRSIZE];
	unsigned char body_wire[DTRACED_CONSUMER_STOP_WIRE_SIZE];
	unsigned char ack_wire[DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE];
	dtraced_consumer_stop_t canonical{}, ack{};
	dtraced_hdr_t header{};
	int64_t deadline;

	if (this->kind != DTRACED_KIND_CONSUMER ||
	    !this->is_subscribed(DTD_SUB_ELFWRITE) || this->retired.load() ||
	    memcmp(challenge.consumer_session, this->session_id.data(), 16) != 0) {
		errno = EPROTO;
		return (false);
	}
	dtraced_wire_encode_consumer_stop(body_wire, &challenge);
	if (dtraced_wire_decode_consumer_stop(&canonical, body_wire) != 0)
		return (false);
	header.msg_type = DTRACED_MSG_CONSUMER_STOP;
	header.elf.len = sizeof(body_wire);
	dtraced_wire_encode_header(header_wire, &header);
	std::lock_guard output(this->output_mtx);
	if (this->retired.load()) {
		errno = ESTALE;
		return (false);
	}
	deadline = dtraced_io_deadline_after(60000);
	if (deadline < 0)
		return (false);
	if (!this->send(header_wire, sizeof(header_wire), deadline) ||
	    !this->send(body_wire, sizeof(body_wire), deadline) ||
	    !this->recv(ack_wire, sizeof(ack_wire), deadline)) {
		int error = errno;
		this->shutdown();
		errno = error;
		return (false);
	}
	if (dtraced_wire_decode_consumer_stop_ack(&ack, ack_wire) != 0 ||
	    memcmp(ack.token, canonical.token, 16) != 0 ||
	    memcmp(ack.source_session, canonical.source_session, 16) != 0 ||
	    memcmp(ack.consumer_session, canonical.consumer_session, 16) != 0 ||
	    memcmp(ack.program_digest, canonical.program_digest, 32) != 0 ||
	    ack.vmid != canonical.vmid || ack.epoch != canonical.epoch) {
		this->shutdown();
		errno = EPROTO;
		return (false);
	}
	if (ack.result != 1 || this->retired.load()) {
		errno = ack.result != 1 ? EOPNOTSUPP : ESTALE;
		return (false);
	}
	return (true);
}

int
disable_fd(int kq, int fd, int filt)
{
	struct kevent change_event[1];

	EV_SET(change_event, fd, filt, EV_DISABLE | EV_KEEPUDATA, 0, 0, 0);
	return (kevent(kq, change_event, 1, NULL, 0, NULL));
}

}
