/*-
 * Copyright (c) 2017 Domagoj Stolfa <domagoj.stolfa@gmail.com>
 * All rights reserved.
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
 *
 * $FreeBSD$
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <machine/vmm.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#include <capsicum_helpers.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vmmapi.h>
#include <sys/hypertrace_wire.h>
#include <dev/virtio/dtrace/virtio_dtrace_wire.h>
#include "hypertrace.h"
#include "dtraced_io.h"
#include "dtraced_wire.h"
#include "dtraced_transfer_wire.h"

#define HT_MAX_FRAME (64U * 1024U * 1024U)
#define HT_MAX_CLEANUP 4096U

_Static_assert(HYPERTRACE_TRANSFER_MIN_BYTES ==
    DTRACED_TRANSFER_HEADER_SIZE + DTRACED_TRANSFER_DIGEST_SIZE,
    "HyperTrace transfer minimum must match HTX1");
_Static_assert(HYPERTRACE_TRANSFER_MAX_BYTES == DTRACED_TRANSFER_MAX_SIZE,
    "HyperTrace transfer maximum must match HTX1");
_Static_assert(DTRACED_HANDOFF_IMPORT_BINDING_SIZE == 16 + 32,
    "HTX1 import binding must hold token and checkpoint digest");

int
hypertrace_transfer_inspect(const void *wire, size_t length,
    const uint8_t token[16], bool *has_state)
{
	int requires_import = 0;
	if (has_state == NULL ||
	    !dtraced_transfer_wire_requires_import(wire, length, token,
	    &requires_import))
		return (-1);
	*has_state = requires_import != 0;
	return (0);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
int
hypertrace_transfer_replay_controls(const void *wire, size_t length,
    const uint8_t token[16], size_t *controls)
{
	return (dtraced_transfer_wire_replay_controls(wire, length, token,
	    HYPERTRACE_VM_ENVELOPE_WIRE_SIZE, VTDTR_WIRE_MAXELFLEN,
	    controls) ? 0 : -1);
}

/* Each lock owns its descriptor for a complete frame or replacement. */
struct ht_channel {
	pthread_mutex_t mutex;
	int fd;
	atomic_bool configured;
	uint64_t generation; /* VirtIO reset generation. */
	uint64_t connection_generation; /* Changes whenever this fd retires. */
	uint64_t pending_delivery_id;
	dtraced_replay_kill_t *replay_kills;
	size_t replay_count;
	uint16_t replay_vmid;
	uint64_t replay_epoch;
	bool replay_ready;
};
static struct ht_channel rx = { .mutex = PTHREAD_MUTEX_INITIALIZER, .fd = -1 };
static struct ht_channel wx = { .mutex = PTHREAD_MUTEX_INITIALIZER, .fd = -1 };
static int inbound_dirfd = -1, sockdir = -1;
/* Optional for ordinary tracing; required for a fresh-session stop. Retain
 * this capability before cap_enter(), with no authority to resume a gate. */
static int session_gate_fd = -1, session_gate_error = ENXIO;
static pthread_t connector;
static pthread_mutex_t lifecycle = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t reconnect = PTHREAD_COND_INITIALIZER;
static bool stopping, prepared, started;
static atomic_bool restore_mode;
static uint8_t forwarder_session_id[16];

/* Caller holds the channel mutex. */
static void
ht_disconnect(struct ht_channel *channel)
{
	int error = errno;
	atomic_store(&channel->configured, false);
	channel->pending_delivery_id = 0;
	free(channel->replay_kills);
	channel->replay_kills = NULL;
	channel->replay_count = 0;
	channel->replay_vmid = 0;
	channel->replay_epoch = 0;
	channel->replay_ready = false;
	if (channel->fd != -1) {
		channel->connection_generation++;
		close(channel->fd);
		channel->fd = -1;
	}
	errno = error;
}

static int
ht_connect(struct ht_channel *channel, struct vmctx *ctx, uint64_t subs)
{
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	dtd_initmsg_t hello = { 0 };
	int fd, error;
	int identity_fd = -1;
	dtraced_replay_kill_t *replay = NULL;
	uint32_t replay_count = 0;
	uint16_t replay_vmid = 0;
	uint64_t replay_epoch = 0;
	size_t transferred;
	int64_t deadline;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
#endif

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd == -1)
		return (-1);
	strlcpy(address.sun_path, "sub.sock", sizeof(address.sun_path));
	address.sun_len = SUN_LEN(&address);
	deadline = dtraced_io_deadline_after(2000);
	if (deadline < 0)
		goto fail;
	if (connectat(sockdir, fd, (struct sockaddr *)&address,
	    address.sun_len) != 0) {
		if (errno != EINPROGRESS && errno != EALREADY && errno != EINTR)
			goto fail;
		if (dtraced_io_complete_connect(fd, deadline) != 0)
			goto fail;
	}
#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_RECV, CAP_SEND, CAP_EVENT);
	if (caph_rights_limit(fd, &rights) != 0)
		goto fail;
#endif
	if (dtraced_wire_read_init(fd, &hello, deadline,
	    &transferred) != 0)
		goto fail;
	if (!dtraced_wire_valid_server_init(&hello)) {
		errno = EPROTO;
		goto fail;
	}
	memset(&hello, 0, sizeof(hello));
	if (strlcpy(hello.ident, vm_get_name(ctx), sizeof(hello.ident)) >=
	    sizeof(hello.ident)) {
		errno = ENAMETOOLONG;
		goto fail;
	}
	hello.protocol_version = DTRACED_PROTOCOL_VERSION;
	hello.kind = DTRACED_KIND_FORWARDER;
	hello.subs = subs;
	memcpy(hello.session_id, forwarder_session_id,
	    sizeof(hello.session_id));
	if (dtraced_wire_write_init(fd, &hello, deadline,
	    &transferred) != 0)
		goto fail;
	identity_fd = vm_export_attestation_fd(ctx);
	if (identity_fd < 0 ||
	    dtraced_io_send_fd(fd, identity_fd, deadline) != 0)
		goto fail;
	close(identity_fd);
	identity_fd = -1;
	if ((subs & DTD_SUB_ADMISSION_ACK) != 0) {
		uint8_t accepted;

		/* The daemon acknowledges only after admission and KILL replay
		 * staging.  A connected socket alone is not a ready session. */
		deadline = dtraced_io_deadline_after(10000);
		if (deadline < 0)
			goto fail;
		if (dtraced_io_transfer(fd, &accepted, sizeof(accepted), false,
		    deadline, &transferred) != 0)
			goto fail;
		if (accepted != 1) {
			errno = EPROTO;
			goto fail;
		}
	}
	if ((subs & DTD_SUB_REPLAY_MANIFEST) != 0) {
		unsigned char count_wire[4], kill_wire[DTRACED_REPLAY_KILL_WIRE_SIZE];

		if (dtraced_io_transfer(fd, count_wire, sizeof(count_wire),
		    false, deadline, &transferred) != 0)
			goto fail;
		replay_count = dtraced_wire_get_u32(count_wire);
		if (replay_count > DTRACED_REPLAY_KILL_MAX ||
		    vm_get_identity(ctx, &replay_vmid, &replay_epoch) != 0 ||
		    replay_vmid == 0 || replay_epoch == 0) {
			errno = EPROTO;
			goto fail;
		}
		if (replay_count != 0) {
			replay = calloc(replay_count, sizeof(*replay));
			if (replay == NULL)
				goto fail;
		}
		for (uint32_t i = 0; i < replay_count; i++) {
			if (dtraced_io_transfer(fd, kill_wire,
			    sizeof(kill_wire), false, deadline, &transferred) != 0 ||
			    dtraced_wire_decode_replay_kill(&replay[i],
			    kill_wire) != 0)
				goto fail;
			if (replay[i].vmid != replay_vmid ||
			    replay[i].epoch != replay_epoch) {
				errno = EPROTO;
				goto fail;
			}
			/* The manifest digest binds this order. Reject a reordered or
			 * duplicate entry before the device can attach its ticket. */
			if (i != 0 &&
			    (replay[i - 1].pid > replay[i].pid ||
			    (replay[i - 1].pid == replay[i].pid &&
			    memcmp(replay[i - 1].source_id,
			    replay[i].source_id, 16) >= 0))) {
				errno = EPROTO;
				goto fail;
			}
		}
	}
	channel->fd = fd;
	channel->replay_kills = replay;
	channel->replay_count = replay_count;
	channel->replay_vmid = replay_vmid;
	channel->replay_epoch = replay_epoch;
	channel->replay_ready =
	    (subs & DTD_SUB_REPLAY_MANIFEST) != 0;
	atomic_store(&channel->configured, true);
	return (0);
fail:
	error = errno;
	free(replay);
	if (identity_fd >= 0)
		close(identity_fd);
	close(fd);
	errno = error;
	return (-1);
}

static void *
ht_connector(void *arg)
{
	struct vmctx *ctx = arg;
	struct timespec wake;

	pthread_mutex_lock(&lifecycle);
	while (!stopping) {
		pthread_mutex_unlock(&lifecycle);
		if (!atomic_load(&rx.configured)) {
			pthread_mutex_lock(&rx.mutex);
			if (!atomic_load(&rx.configured))
				(void)ht_connect(&rx, ctx, DTD_SUB_ELFWRITE |
				    DTD_SUB_KILL | DTD_SUB_CLEANUP |
				    DTD_SUB_ADMISSION_ACK |
				    (atomic_load(&restore_mode) ?
				    DTD_SUB_REPLAY_MANIFEST : 0));
			pthread_mutex_unlock(&rx.mutex);
		}
		if (!atomic_load(&wx.configured)) {
			pthread_mutex_lock(&wx.mutex);
			if (!atomic_load(&wx.configured))
				(void)ht_connect(&wx, ctx, DTD_SUB_READDATA |
				    DTD_SUB_ADMISSION_ACK);
			pthread_mutex_unlock(&wx.mutex);
		}
		pthread_mutex_lock(&lifecycle);
		if (hypertrace_configured())
			pthread_cond_broadcast(&reconnect);
		clock_gettime(CLOCK_REALTIME, &wake);
		wake.tv_sec += 5;
		if (!stopping)
			(void)pthread_cond_timedwait(&reconnect, &lifecycle, &wake);
	}
	pthread_mutex_unlock(&lifecycle);
	return (NULL);
}

/* Initialization and destruction are called by the bhyve control thread. */
int
hypertrace_init(struct vmctx *ctx)
{
	int error;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
#endif
	if (prepared) {
		errno = EALREADY;
		return (-1);
	}
	if (vm_get_vmid(ctx) == 0) {
		errno = ENOTSUP;
		return (-1);
	}
	do {
		arc4random_buf(forwarder_session_id,
		    sizeof(forwarder_session_id));
	} while (memcmp(forwarder_session_id,
	    (const uint8_t[16]){0}, sizeof(forwarder_session_id)) == 0);
	sockdir = open("/var/ddtrace", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (sockdir == -1)
		return (-1);
#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_CONNECTAT);
	if (caph_rights_limit(sockdir, &rights) != 0)
		goto fail;
#endif
	inbound_dirfd = open("/var/ddtrace/inbound",
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (inbound_dirfd == -1)
		goto fail;
	session_gate_fd = open("/dev/dtrace/hypertrace",
	    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
	session_gate_error = session_gate_fd < 0 ? errno : 0;
#ifndef WITHOUT_CAPSICUM
	if (session_gate_fd >= 0) {
		const unsigned long commands[] = {
		    HYPERTRACE_IOC_EPOCH_GATE_QUERY, HYPERTRACE_IOC_EPOCH_SUSPEND,
		    HYPERTRACE_IOC_EPOCH_QUERY };
		cap_rights_init(&rights, CAP_IOCTL);
		if (caph_rights_limit(session_gate_fd, &rights) != 0 ||
		    cap_ioctls_limit(session_gate_fd, commands,
		    sizeof(commands) / sizeof(commands[0])) != 0) {
			session_gate_error = errno;
			close(session_gate_fd);
			session_gate_fd = -1;
		}
	}
#endif
	prepared = true;
	/* PCI device shutdown handlers registered later run first. */
	if (atexit(hypertrace_destroy) != 0) {
		hypertrace_destroy();
		errno = ENOMEM;
		return (-1);
	}
	return (0);
fail:
	error = errno;
	if (inbound_dirfd != -1)
		close(inbound_dirfd);
	close(sockdir);
	inbound_dirfd = sockdir = -1;
	errno = error;
	return (-1);
}

/* Called only after the VM's device state is ready to receive messages. */
int
hypertrace_start(struct vmctx *ctx)
{
	int error;

	pthread_mutex_lock(&lifecycle);
	if (!prepared || ctx == NULL) {
		errno = EINVAL;
		goto fail;
	}
	if (started) {
		errno = EALREADY;
		goto fail;
	}
	stopping = false;
	error = pthread_create(&connector, NULL, ht_connector, ctx);
	if (error != 0) {
		errno = error;
		goto fail;
	}
	started = true;
	pthread_mutex_unlock(&lifecycle);
	return (0);
fail:
	pthread_mutex_unlock(&lifecycle);
	return (-1);
}

/* Restore keeps every vCPU fenced until both attested channels have been
 * admitted by the daemon and their durable replay has been staged. */
int
hypertrace_start_ready(struct vmctx *ctx, int timeout_ms)
{
	struct timespec deadline;
	int error = 0;

	if (timeout_ms <= 0) {
		errno = EINVAL;
		return (-1);
	}
	if (clock_gettime(CLOCK_REALTIME, &deadline) != 0)
		return (-1);
	deadline.tv_sec += timeout_ms / 1000;
	deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000L;
	}
	atomic_store(&restore_mode, true);
	if (hypertrace_start(ctx) != 0) {
		atomic_store(&restore_mode, false);
		return (-1);
	}
	pthread_mutex_lock(&lifecycle);
	while (!stopping && !hypertrace_configured()) {
		error = pthread_cond_timedwait(&reconnect, &lifecycle,
		    &deadline);
		if (error != 0)
			break;
	}
	if (stopping)
		error = ECANCELED;
	else if (error == 0 && !hypertrace_configured())
		error = ENOTCONN;
	pthread_mutex_unlock(&lifecycle);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

/* The exact admitted journal cut is consumed once by the restored device
 * before it may release NODE_REKEY. Caller owns and frees the returned list. */
int
hypertrace_take_replay_kills(struct vmctx *ctx,
    dtraced_replay_kill_t **kills, size_t *count)
{
	uint16_t vmid;
	uint64_t epoch;
	int error = 0;

	if (ctx == NULL || kills == NULL || count == NULL)
		return (EINVAL);
	*kills = NULL;
	*count = 0;
	pthread_mutex_lock(&rx.mutex);
	if (!atomic_load(&restore_mode) ||
	    !atomic_load(&rx.configured) || !rx.replay_ready)
		error = ENOTCONN;
	else if (vm_get_identity(ctx, &vmid, &epoch) != 0 ||
	    vmid != rx.replay_vmid || epoch != rx.replay_epoch)
		error = ESTALE;
	else {
		*kills = rx.replay_kills;
		*count = rx.replay_count;
		rx.replay_kills = NULL;
		rx.replay_count = 0;
		rx.replay_ready = false;
		atomic_store(&restore_mode, false);
	}
	pthread_mutex_unlock(&rx.mutex);
	return (error);
}

/* Called by the bhyve control thread during device initialization. */
int
hypertrace_initialized(void)
{
	return (prepared);
}

int
hypertrace_configured(void)
{
	return (atomic_load(&rx.configured) && atomic_load(&wx.configured));
}

int
hypertrace_read_epoch(void **buf, dtraced_hdr_t *hdr, uint64_t *epoch,
    uint64_t *connection)
{
	int error;
	int64_t deadline;
	size_t transferred, length;
	char entry[4096];

	if (buf == NULL || hdr == NULL || epoch == NULL || connection == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*buf = NULL;
	pthread_mutex_lock(&rx.mutex);
	*epoch = rx.generation;
	*connection = rx.connection_generation;
	if (!atomic_load(&rx.configured)) {
		errno = ENOTCONN;
		goto fail;
	}
	/* A complete ELF must be acknowledged before accepting another frame. */
	if (rx.pending_delivery_id != 0) {
		pthread_mutex_unlock(&rx.mutex);
		errno = EBUSY;
		return (-1);
	}
	deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0)
		goto fail;
	unsigned char header_wire[DTRACED_MSGHDRSIZE];
	if (dtraced_io_transfer(rx.fd, header_wire, sizeof(header_wire), false, deadline,
	    &transferred) != 0) {
		/* Idle is harmless; a partial frame must retire the stream. */
		if (errno == ETIMEDOUT && transferred == 0) {
			pthread_mutex_unlock(&rx.mutex);
			errno = EAGAIN;
			return (-1);
		}
		goto fail;
	}
	if (dtraced_wire_decode_header(hdr, header_wire) != 0)
		goto fail;
	switch (hdr->msg_type) {
	case DTRACED_MSG_ELF:
		length = hdr->elf.len;
		if (length == 0 || length > HT_MAX_FRAME) {
			errno = EMSGSIZE;
			goto fail;
		}
		const uint8_t zero_id[DTRACED_PROGRAM_ID_LEN] = { 0 };
		if (hdr->elf.delivery_id == 0 ||
		    memcmp(hdr->elf.program_id, zero_id, sizeof(zero_id)) == 0 ||
		    memcmp(hdr->elf.source_id, zero_id, sizeof(zero_id)) == 0) {
			errno = EPROTO;
			goto fail;
		}
		*buf = malloc(length);
		if (*buf == NULL)
			goto fail;
		if (dtraced_io_transfer(rx.fd, *buf, length, false, deadline,
		    &transferred) != 0)
			goto fail;
		break;
	case DTRACED_MSG_KILL:
		{
			const uint8_t zero_source[DTRACED_PROGRAM_ID_LEN] = { 0 };
			if (memcmp(hdr->kill.source_id, zero_source,
			    sizeof(zero_source)) == 0) {
				errno = EPROTO;
				goto fail;
			}
		}
		break;
	case DTRACED_MSG_CLEANUP:
		/* The guest uses a global cleanup event; still consume the frame. */
		if (DTRACED_MSG_CLEANUP_DELIVERY_ID(*hdr) == 0 ||
		    hdr->cleanup.num_entries > HT_MAX_CLEANUP) {
			errno = EMSGSIZE;
			goto fail;
		}
		for (size_t i = 0; i < hdr->cleanup.num_entries; i++) {
			if (dtraced_io_read_size(rx.fd, &length, deadline,
			    &transferred) != 0)
				goto fail;
			if (length == 0 || length > sizeof(entry)) {
				errno = EMSGSIZE;
				goto fail;
			}
			if (dtraced_io_transfer(rx.fd, entry, length, false, deadline,
			    &transferred) != 0)
				goto fail;
			if (entry[length - 1] != '\0' ||
			    memchr(entry, '\0', length - 1) != NULL) {
				errno = EPROTO;
				goto fail;
			}
		}
		break;
	default:
		errno = EPROTO;
		goto fail;
	}
	if (hdr->msg_type == DTRACED_MSG_ELF)
		rx.pending_delivery_id = hdr->elf.delivery_id;
	else if (hdr->msg_type == DTRACED_MSG_CLEANUP)
		rx.pending_delivery_id = DTRACED_MSG_CLEANUP_DELIVERY_ID(*hdr);
	pthread_mutex_unlock(&rx.mutex);
	return (0);
fail:
	error = errno;
	free(*buf);
	*buf = NULL;
	ht_disconnect(&rx);
	pthread_mutex_unlock(&rx.mutex);
	errno = error;
	return (-1);
}

/* Acknowledge only a complete frame from the still-current receive stream. */
int
hypertrace_ack_epoch(uint64_t epoch, uint64_t connection,
    uint64_t delivery_id)
{
	dtraced_delivery_ack_t ack = { .delivery_id = delivery_id };
	size_t transferred;
	int error;
	int64_t deadline;

	pthread_mutex_lock(&rx.mutex);
	if (delivery_id == 0 || delivery_id != rx.pending_delivery_id ||
	    epoch != rx.generation || connection != rx.connection_generation ||
	    !atomic_load(&rx.configured)) {
		pthread_mutex_unlock(&rx.mutex);
		errno = ESTALE;
		return (-1);
	}
	deadline = dtraced_io_deadline_after(2000);
	if (deadline < 0 || dtraced_wire_write_ack(rx.fd, &ack,
	    deadline, &transferred) != 0) {
		error = errno;
		ht_disconnect(&rx);
		pthread_mutex_unlock(&rx.mutex);
		errno = error;
		return (-1);
	}
	rx.pending_delivery_id = 0;
	pthread_mutex_unlock(&rx.mutex);
	return (0);
}

/*
 * Reset owns both complete-frame locks before retiring the old session.
 * A read already in progress finishes within its deadline and returns its
 * original generation; the device discards it after reset.  A fresh read
 * obtains the new generation while owning the new connection, so it cannot
 * be mistaken for a pre-reset frame merely because its worker started early.
 */
uint64_t
hypertrace_reset(void)
{
	uint64_t epoch;

	pthread_mutex_lock(&rx.mutex);
	pthread_mutex_lock(&wx.mutex);
	epoch = ++rx.generation;
	ht_disconnect(&rx);
	ht_disconnect(&wx);
	pthread_mutex_unlock(&wx.mutex);
	pthread_mutex_unlock(&rx.mutex);
	pthread_mutex_lock(&lifecycle);
	pthread_cond_signal(&reconnect);
	pthread_mutex_unlock(&lifecycle);
	return (epoch);
}

/* One-shot recovery runs before normal initialization and needs only the
 * retirement witness. Do not open daemon journals, attach a VM, or start threads.
 * Capsicum restricts this descriptor to the retirement query alone. */
int
hypertrace_session_recovery_open(void)
{
	int fd;
#ifndef WITHOUT_CAPSICUM
	int error;
	cap_rights_t rights;
	const unsigned long command = HYPERTRACE_IOC_EPOCH_QUERY;
#endif

	if (prepared || session_gate_fd >= 0)
		return (EBUSY);
	fd = open("/dev/dtrace/hypertrace",
	    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return (errno);
#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_IOCTL);
	if (caph_rights_limit(fd, &rights) != 0 ||
	    cap_ioctls_limit(fd, &command, 1) != 0) {
		error = errno;
		close(fd);
		return (error);
	}
#endif
	session_gate_fd = fd;
	session_gate_error = 0;
	return (0);
}

void
hypertrace_session_recovery_close(void)
{
	/* Only the single-threaded recovery command owns this descriptor. */
	if (!prepared && session_gate_fd >= 0) {
		close(session_gate_fd);
		session_gate_fd = -1;
		session_gate_error = ENXIO;
	}
}

/* The caller must have bound this lifetime to its stopped source; absence
 * alone is not proof for an arbitrary caller-supplied historical identity. */
int
hypertrace_session_retired(uint16_t vmid, uint64_t epoch)
{
	struct hypertrace_epoch_query query = { .vmid = vmid, .epoch = epoch };
	if (vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0) {
		errno = EINVAL;
		return (-1);
	}
	if (session_gate_fd < 0) {
		errno = session_gate_error;
		return (-1);
	}
	if (ioctl(session_gate_fd, HYPERTRACE_IOC_EPOCH_QUERY, &query) != 0)
		return (-1);
	if (query.vmid != vmid || query.epoch != epoch || query.live > 1 ||
	    query.reserved[0] != 0 || query.reserved[1] != 0 ||
	    query.reserved[2] != 0 || query.reserved2 != 0) {
		errno = EPROTO;
		return (-1);
	}
	if (query.live != 0) {
		errno = EBUSY;
		return (-1);
	}
	return (0);
}

static int
ht_session_gate_query(uint16_t vmid, uint64_t epoch,
    struct hypertrace_epoch_gate *gate)
{
	memset(gate, 0, sizeof(*gate));
	gate->vmid = vmid;
	gate->epoch = epoch;
	if (ioctl(session_gate_fd, HYPERTRACE_IOC_EPOCH_GATE_QUERY, gate) != 0)
		return (-1);
	if (gate->vmid != vmid || gate->epoch != epoch || gate->suspended > 1 ||
	    gate->reserved[0] != 0 || gate->reserved[1] != 0 ||
	    gate->reserved[2] != 0 || gate->reserved2 != 0 ||
	    memcmp(gate->previous_token, (const uint8_t[16]){0}, 16) != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

/* Both callers serialize with the device lifecycle. A failed readback must
 * leave the same token available for retry; never resume this old session. */
static int
ht_session_host_gate_state(struct vmctx *ctx, const uint8_t token[16],
    uint32_t suspended)
{
	struct hypertrace_epoch_gate gate;
	uint16_t vmid, current_vmid;
	uint64_t epoch, current_epoch;

	if (ctx == NULL || token == NULL ||
	    memcmp(token, (const uint8_t[16]){0}, 16) == 0) {
		errno = EINVAL;
		return (-1);
	}
	if (session_gate_fd < 0) {
		errno = session_gate_error;
		return (-1);
	}
	if (vm_get_identity(ctx, &vmid, &epoch) != 0)
		return (-1);
	if (vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0) {
		errno = EPROTO;
		return (-1);
	}
	if (ht_session_gate_query(vmid, epoch, &gate) != 0)
		return (-1);
	if (gate.suspended != suspended || memcmp(gate.token, token, 16) != 0) {
		errno = EBUSY;
		return (-1);
	}
	if (vm_get_identity(ctx, &current_vmid, &current_epoch) != 0)
		return (-1);
	if (current_vmid != vmid || current_epoch != epoch) {
		errno = ESTALE;
		return (-1);
	}
	return (0);
}

int
hypertrace_session_host_stopped(struct vmctx *ctx, const uint8_t token[16])
{
	return (ht_session_host_gate_state(ctx, token, 1));
}

int
hypertrace_session_host_released(struct vmctx *ctx, const uint8_t token[16])
{
	return (ht_session_host_gate_state(ctx, token, 0));
}

int
hypertrace_session_host_stop(struct vmctx *ctx, const uint8_t token[16])
{
	struct hypertrace_epoch_gate gate, suspend = {0};
	uint16_t vmid, current_vmid;
	uint64_t epoch, current_epoch;

	if (ctx == NULL || token == NULL ||
	    memcmp(token, (const uint8_t[16]){0}, 16) == 0) {
		errno = EINVAL;
		return (-1);
	}
	if (session_gate_fd < 0) {
		errno = session_gate_error;
		return (-1);
	}
	if (vm_get_identity(ctx, &vmid, &epoch) != 0)
		return (-1);
	if (vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0) {
		errno = EPROTO;
		return (-1);
	}
	if (ht_session_gate_query(vmid, epoch, &gate) != 0)
		return (-1);
	if (gate.suspended != 0) {
		if (memcmp(gate.token, token, 16) != 0) {
			errno = EBUSY;
			return (-1);
		}
	} else {
		suspend.vmid = vmid;
		suspend.epoch = epoch;
		memcpy(suspend.token, token, 16);
		memcpy(suspend.previous_token, gate.token, 16);
		if (ioctl(session_gate_fd, HYPERTRACE_IOC_EPOCH_SUSPEND,
		    &suspend) != 0)
			return (-1);
	}
	if (hypertrace_session_host_stopped(ctx, token) != 0 ||
	    vm_get_identity(ctx, &current_vmid, &current_epoch) != 0)
		return (-1);
	if (vmid != current_vmid || epoch != current_epoch) {
		errno = ESTALE;
		return (-1);
	}
	return (0);
}

int
hypertrace_write(const dtraced_hdr_t *header, void *payload,
    size_t payload_len)
{
	unsigned char ack;
	unsigned char header_wire[DTRACED_MSGHDRSIZE];
	size_t transferred;
	int error;
	int64_t deadline;

	if (header == NULL || payload_len > HT_MAX_FRAME - DTRACED_MSGHDRSIZE ||
	    (payload_len != 0 && payload == NULL) ||
	    (header->msg_type == DTRACED_MSG_ELF &&
	    header->elf.len != payload_len) ||
	    (header->msg_type != DTRACED_MSG_ELF && payload_len != 0)) {
		errno = EINVAL;
		return (-1);
	}
	dtraced_wire_encode_header(header_wire, header);
	pthread_mutex_lock(&wx.mutex);
	if (!atomic_load(&wx.configured)) {
		errno = ENOTCONN;
		goto fail;
	}
	deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0)
		goto fail;
	if (dtraced_io_write_size(wx.fd,
	    DTRACED_MSGHDRSIZE + payload_len, deadline,
	    &transferred) != 0 ||
	    dtraced_io_transfer(wx.fd, header_wire, sizeof(header_wire), true,
	    deadline, &transferred) != 0 ||
	    (payload_len != 0 &&
	    dtraced_io_transfer(wx.fd, payload, payload_len, true,
	    deadline, &transferred) != 0) ||
	    dtraced_io_transfer(wx.fd, &ack, sizeof(ack), false, deadline,
	    &transferred) != 0)
		goto fail;
	if (ack != 1) {
		errno = EPROTO;
		goto fail;
	}
	pthread_mutex_unlock(&wx.mutex);
	return (0);
fail:
	error = errno;
	ht_disconnect(&wx);
	pthread_mutex_unlock(&wx.mutex);
	errno = error;
	return (-1);
}

static int
ht_handoff_frame(uint8_t op, const uint8_t token[16],
    const uint8_t digest[32], uint8_t frame[DTRACED_MSGHDRSIZE +
    DTRACED_HANDOFF_WIRE_SIZE])
{
	const uint8_t zero16[16] = {}, zero32[32] = {};
	dtraced_hdr_t header = { .msg_type = DTRACED_MSG_HANDOFF };
	dtraced_handoff_request_t request = { .op = op };
	bool empty_digest;

	if (token == NULL || digest == NULL) {
		errno = EINVAL;
		return (-1);
	}
	empty_digest = memcmp(digest, zero32, sizeof(zero32)) == 0;
	if (memcmp(token, zero16, sizeof(zero16)) == 0 ||
	    (op != DTRACED_HANDOFF_PREPARE &&
	    op != DTRACED_HANDOFF_COMMIT &&
	    op != DTRACED_HANDOFF_ABORT &&
	    op != DTRACED_HANDOFF_SOURCE_STATUS &&
	    op != DTRACED_HANDOFF_EXPORT &&
	    op != DTRACED_HANDOFF_SOURCE_GATE_BEGIN &&
	    op != DTRACED_HANDOFF_SOURCE_GATE_ABORT &&
	    op != DTRACED_HANDOFF_SOURCE_DRAIN_STEP &&
	    op != DTRACED_HANDOFF_DESTINATION_STATUS &&
	    op != DTRACED_HANDOFF_RESERVE &&
	    op != DTRACED_HANDOFF_CANCEL &&
	    op != DTRACED_HANDOFF_MUTATE &&
	    op != DTRACED_HANDOFF_CLAIM &&
	    op != DTRACED_HANDOFF_BIND_KILLS_ALL &&
	    op != DTRACED_HANDOFF_REKEY_APPLIED &&
	    op != DTRACED_HANDOFF_EXECUTION_START &&
	    op != DTRACED_HANDOFF_REBIND_BEGIN &&
	    op != DTRACED_HANDOFF_REBIND_STAGE &&
	    op != DTRACED_HANDOFF_REBIND_PENDING &&
	    op != DTRACED_HANDOFF_REBIND_CANCEL_PENDING &&
	    op != DTRACED_HANDOFF_REBIND_COMMIT_EMPTY &&
	    op != DTRACED_HANDOFF_REBIND_EMPTY_READY &&
	    op != DTRACED_HANDOFF_REBIND_NONEMPTY_PREFLIGHT &&
	    op != DTRACED_HANDOFF_RESET_MUTATION &&
	    op != DTRACED_HANDOFF_PROMOTE_IMPORT &&
	    op != DTRACED_HANDOFF_ACTIVATE_IMPORT &&
	    op != DTRACED_HANDOFF_REPLAY_READY &&
	    op != DTRACED_HANDOFF_SOURCE_RELEASE &&
	    op != DTRACED_HANDOFF_RELEASE_RECOVER) ||
	    ((op == DTRACED_HANDOFF_ABORT ||
	    op == DTRACED_HANDOFF_SOURCE_STATUS ||
	    op == DTRACED_HANDOFF_EXPORT) && !empty_digest) ||
	    ((op == DTRACED_HANDOFF_SOURCE_GATE_BEGIN ||
	    op == DTRACED_HANDOFF_SOURCE_GATE_ABORT) && !empty_digest) ||
	    ((op == DTRACED_HANDOFF_PREPARE ||
	    op == DTRACED_HANDOFF_COMMIT ||
	    op == DTRACED_HANDOFF_SOURCE_DRAIN_STEP ||
	    op == DTRACED_HANDOFF_DESTINATION_STATUS ||
	    op == DTRACED_HANDOFF_RESERVE ||
	    op == DTRACED_HANDOFF_CANCEL ||
	    op == DTRACED_HANDOFF_MUTATE ||
	    op == DTRACED_HANDOFF_CLAIM ||
	    op == DTRACED_HANDOFF_BIND_KILLS_ALL ||
	    op == DTRACED_HANDOFF_REKEY_APPLIED ||
	    op == DTRACED_HANDOFF_EXECUTION_START ||
	    op == DTRACED_HANDOFF_REBIND_BEGIN ||
	    op == DTRACED_HANDOFF_REBIND_STAGE ||
	    op == DTRACED_HANDOFF_REBIND_PENDING ||
	    op == DTRACED_HANDOFF_REBIND_CANCEL_PENDING ||
	    op == DTRACED_HANDOFF_REBIND_COMMIT_EMPTY ||
	    op == DTRACED_HANDOFF_REBIND_EMPTY_READY ||
	    op == DTRACED_HANDOFF_REBIND_NONEMPTY_PREFLIGHT ||
	    op == DTRACED_HANDOFF_RESET_MUTATION ||
	    op == DTRACED_HANDOFF_PROMOTE_IMPORT ||
	    op == DTRACED_HANDOFF_ACTIVATE_IMPORT ||
	    op == DTRACED_HANDOFF_REPLAY_READY ||
	    op == DTRACED_HANDOFF_SOURCE_RELEASE ||
	    op == DTRACED_HANDOFF_RELEASE_RECOVER) && empty_digest)) {
		errno = EINVAL;
		return (-1);
	}
	memcpy(request.token, token, sizeof(request.token));
	memcpy(request.digest, digest, sizeof(request.digest));
	dtraced_wire_encode_header(frame, &header);
	dtraced_wire_encode_handoff(frame + DTRACED_MSGHDRSIZE, &request);
	return (0);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Called only by the uncalled hypertrace_handoff_source()
 * and hypertrace_handoff_destination(): this
 * is intentionally unreachable until enabled. */
static int
ht_handoff_request(uint8_t op, const uint8_t token[16],
    const uint8_t digest[32])
{
	uint8_t frame[DTRACED_MSGHDRSIZE +
    DTRACED_HANDOFF_WIRE_SIZE] = {};
	uint8_t ack;
	size_t length = sizeof(frame), transferred;
	int64_t deadline;
	int error;

	if (ht_handoff_frame(op, token, digest, frame) != 0)
		return (-1);
	pthread_mutex_lock(&wx.mutex);
	if (!atomic_load(&wx.configured)) {
		pthread_mutex_unlock(&wx.mutex);
		errno = ENOTCONN;
		return (-1);
	}
	deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0)
		goto broken;
	if (dtraced_io_write_size(wx.fd, length,
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(wx.fd, frame, sizeof(frame), true,
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(wx.fd, &ack, sizeof(ack), false,
	    deadline, &transferred) != 0)
		goto broken;
	if (ack == 0) {
		/* The daemon consumed this frame and sends no reply body on NAK.
		 * Keep the channel and its queued device work intact. */
		pthread_mutex_unlock(&wx.mutex);
		errno = EPROTO;
		return (-1);
	}
	if (ack != 1) {
		errno = EPROTO;
		goto broken;
	}
	pthread_mutex_unlock(&wx.mutex);
	return (0);
broken:
	error = errno;
	ht_disconnect(&wx);
	pthread_mutex_unlock(&wx.mutex);
	errno = error;
	return (-1);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  No caller: this
 * is intentionally unreachable until enabled. */
int
hypertrace_handoff_source(uint8_t op, const uint8_t token[16],
    const uint8_t digest[32])
{
	if (op != DTRACED_HANDOFF_PREPARE &&
	    op != DTRACED_HANDOFF_COMMIT &&
	    op != DTRACED_HANDOFF_ABORT) {
		errno = EINVAL;
		return (-1);
	}
	return (ht_handoff_request(op, token, digest));
}

static int ht_handoff_fresh(struct vmctx *, uint8_t, const uint8_t[16],
    const uint8_t[32], dtraced_delivery_status_t *, bool *);

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* The connector is admitted before this barrier. The restored device reader
 * has resumed, but guest vCPUs remain fenced while claimed HJB1 ELF jobs
 * reach their exact durable queue ACKs. */
int
hypertrace_handoff_replay_drain(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32], int timeout_ms)
{
	if (ctx == NULL || !prepared || timeout_ms <= 0) {
		errno = EINVAL;
		return (-1);
	}
	int64_t deadline = dtraced_io_deadline_after(timeout_ms);
	if (deadline < 0)
		return (-1);
	for (;;) {
		bool rejected = false;
		if (ht_handoff_fresh(ctx, DTRACED_HANDOFF_REPLAY_READY,
		    token, digest, NULL, &rejected) == 0)
			return (0);
		if (!rejected)
			return (-1);
		int remaining;
		if (dtraced_io_remaining_timeout(deadline,
		    &remaining) != 0)
			return (-1);
		struct timespec delay = { .tv_sec = 0,
		    .tv_nsec = (remaining < 100 ? remaining : 100) * 1000000L };
		while (nanosleep(&delay, &delay) != 0) {
			if (errno != EINTR)
				return (-1);
		}
	}
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  No caller: this
 * is intentionally unreachable until enabled. */
int
hypertrace_handoff_destination(uint8_t op, const uint8_t token[16],
    const uint8_t digest[32])
{
	if (op != DTRACED_HANDOFF_RESERVE &&
	    op != DTRACED_HANDOFF_CANCEL &&
	    op != DTRACED_HANDOFF_MUTATE &&
	    op != DTRACED_HANDOFF_CLAIM &&
	    op != DTRACED_HANDOFF_BIND_KILLS_ALL &&
	    op != DTRACED_HANDOFF_PROMOTE_IMPORT &&
	    op != DTRACED_HANDOFF_ACTIVATE_IMPORT) {
		errno = EINVAL;
		return (-1);
	}
	return (ht_handoff_request(op, token, digest));
}

/* REKEY_APPLIED comes from the paused guest-control path after the normal
 * connector is live. Use a separate attested channel: a lost reply can be
 * retried against the daemon's durable exact-identity record without
 * depending on the data connector's state. */
int
hypertrace_handoff_rekey_applied(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32])
{
	bool rejected = false;

	if (ht_handoff_fresh(ctx, DTRACED_HANDOFF_REKEY_APPLIED,
	    token, digest, NULL, &rejected) != 0) {
		if (rejected || ht_handoff_fresh(ctx,
		    DTRACED_HANDOFF_REKEY_APPLIED, token, digest, NULL, NULL) != 0)
			return (-1);
	}
	/* The guest-applied fact precedes the durable import activation gate.
	 * Both requests are idempotent after an ACK is lost. */
	rejected = false;
	if (ht_handoff_fresh(ctx, DTRACED_HANDOFF_ACTIVATE_IMPORT,
	    token, digest, NULL, &rejected) == 0)
		return (0);
	if (rejected)
		return (-1);
	return (ht_handoff_fresh(ctx, DTRACED_HANDOFF_ACTIVATE_IMPORT,
	    token, digest, NULL, NULL));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* The daemon fsyncs this exact claimed-incarnation marker before bhyve may
 * release a restored vCPU. A lost reply is an idempotent retry; an explicit
 * NAK keeps the startup fence closed. */
int
hypertrace_handoff_execution_start(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32])
{
	bool rejected = false;

	if (ht_handoff_fresh(ctx, DTRACED_HANDOFF_EXECUTION_START,
	    token, digest, NULL, &rejected) == 0)
		return (0);
	if (rejected)
		return (-1);
	return (ht_handoff_fresh(ctx, DTRACED_HANDOFF_EXECUTION_START,
	    token, digest, NULL, NULL));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  No caller: this
 * is intentionally unreachable until enabled. */
/* This records only a proposed replacement owner. The daemon proves the
 * original VMM epoch is retired and publishes HRI1; no VM lease changes. */
int
hypertrace_handoff_rebind_begin(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32])
{
	bool rejected = false;

	if (ht_handoff_fresh(ctx, DTRACED_HANDOFF_REBIND_BEGIN,
	    token, digest, NULL, &rejected) == 0)
		return (0);
	if (rejected)
		return (-1);
	return (ht_handoff_fresh(ctx, DTRACED_HANDOFF_REBIND_BEGIN,
	    token, digest, NULL, NULL));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* A normal first restore has a committed rather than claimed ticket, so
 * BEGIN is expected to receive an explicit NAK. Distinguish that answer
 * from a lost response before the restore coordinator chooses RESERVE. */
int
hypertrace_handoff_rebind_begin_optional(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32], bool *rebind)
{
	dtraced_delivery_status_t status;
	bool rejected = false;

	if (rebind == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*rebind = false;
	if (ht_handoff_fresh(ctx, DTRACED_HANDOFF_REBIND_BEGIN,
	    token, digest, NULL, &rejected) == 0) {
		*rebind = true;
		return (0);
	}
	if (rejected) {
		/* BEGIN refuses an ordinary committed ticket, but a NAK can
		 * also mean an unsafe claimed or mutating state. Classify only
		 * after a read-only exact-digest phase query proves COMMITTED.
		 * A second explicit NAK means this VMM cannot read the old
		 * destination phase; only then try the retired-MUTATE reset. */
		bool status_rejected = false;
		if (ht_handoff_fresh(ctx,
		    DTRACED_HANDOFF_DESTINATION_STATUS, token, digest,
		    &status, &status_rejected) != 0) {
			if (!status_rejected)
				return (-1);
			return (ht_handoff_fresh(ctx,
			    DTRACED_HANDOFF_RESET_MUTATION, token, digest,
			    NULL, NULL));
		}
		if (memcmp(status.digest, digest, sizeof(status.digest)) != 0 ||
		    (status.phase != 'c' && status.phase != 'v' &&
		    status.phase != 'm' && status.phase != 'r')) {
			errno = EPROTO;
			return (-1);
		}
		if (status.phase != 'c') {
			errno = EBUSY;
			return (-1);
		}
		return (0);
	}
	if (errno == EPROTO)
		return (-1);
	/* The first BEGIN may already have published HRI1. A later NAK
	 * cannot prove that this is a fresh, reservable ticket. */
	if (ht_handoff_fresh(ctx, DTRACED_HANDOFF_REBIND_BEGIN,
	    token, digest, NULL, &rejected) == 0) {
		*rebind = true;
		return (0);
	}
	return (-1);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  No caller: this
 * is intentionally unreachable until enabled. */
/* A failed restore may have published MUTATE before its VMM retired. The
 * daemon proves retirement and replays its durable reset; an uncertain reply
 * is left for a later exact retry, never treated as a clean reservation. */
int
hypertrace_handoff_mutation_reset(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32])
{
	return (ht_handoff_fresh(ctx, DTRACED_HANDOFF_RESET_MUTATION,
	    token, digest, NULL, NULL));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* Freeze the exact replacement journal inventory before any remap. */
int
hypertrace_handoff_rebind_stage(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32])
{
	bool rejected = false;

	if (ht_handoff_fresh(ctx, DTRACED_HANDOFF_REBIND_STAGE,
	    token, digest, NULL, &rejected) == 0)
		return (0);
	if (rejected)
		return (-1);
	return (ht_handoff_fresh(ctx, DTRACED_HANDOFF_REBIND_STAGE,
	    token, digest, NULL, NULL));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
int
hypertrace_handoff_rebind_pending(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32])
{
	bool rejected = false;

	if (ht_handoff_fresh(ctx, DTRACED_HANDOFF_REBIND_PENDING,
	    token, digest, NULL, &rejected) == 0)
		return (0);
	if (rejected)
		return (-1);
	return (ht_handoff_fresh(ctx, DTRACED_HANDOFF_REBIND_PENDING,
	    token, digest, NULL, NULL));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  No caller: this
 * is intentionally unreachable until enabled. */
int
hypertrace_handoff_rebind_cancel_pending(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32])
{
	bool rejected = false;

	if (ht_handoff_fresh(ctx, DTRACED_HANDOFF_REBIND_CANCEL_PENDING,
	    token, digest, NULL, &rejected) == 0)
		return (0);
	if (rejected)
		return (-1);
	return (ht_handoff_fresh(ctx,
	    DTRACED_HANDOFF_REBIND_CANCEL_PENDING,
	    token, digest, NULL, NULL));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* Commit only a verified empty local journal. The daemon persists HRC1
 * before changing the claimed ticket and completes an interrupted switch
 * under its handoff lock on retry or restart. */
int
hypertrace_handoff_rebind_commit_empty(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32])
{
	bool rejected = false;

	if (ht_handoff_fresh(ctx, DTRACED_HANDOFF_REBIND_COMMIT_EMPTY,
	    token, digest, NULL, &rejected) == 0)
		return (0);
	if (rejected)
		return (-1);
	return (ht_handoff_fresh(ctx,
	    DTRACED_HANDOFF_REBIND_COMMIT_EMPTY,
	    token, digest, NULL, NULL));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* Require a durable, exactly empty HRP1 before touching the destination
 * kernel restore session. An uncertain reply is safe to retry: this query
 * publishes no new handoff authority. */
int
hypertrace_handoff_rebind_empty_ready(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32])
{
	bool rejected = false;

	if (ht_handoff_fresh(ctx, DTRACED_HANDOFF_REBIND_EMPTY_READY,
	    token, digest, NULL, &rejected) == 0)
		return (0);
	if (rejected)
		return (-1);
	return (ht_handoff_fresh(ctx,
	    DTRACED_HANDOFF_REBIND_EMPTY_READY,
	    token, digest, NULL, NULL));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* Read-only census after PENDING. This does not grant a replacement lease;
 * the restore coordinator still refuses nonempty mutation. */
int
hypertrace_handoff_rebind_nonempty_preflight(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32])
{
	bool rejected = false;

	if (ht_handoff_fresh(ctx,
	    DTRACED_HANDOFF_REBIND_NONEMPTY_PREFLIGHT,
	    token, digest, NULL, &rejected) == 0)
		return (0);
	if (rejected)
		return (-1);
	return (ht_handoff_fresh(ctx,
	    DTRACED_HANDOFF_REBIND_NONEMPTY_PREFLIGHT,
	    token, digest, NULL, NULL));
}

/* A short-lived attested control channel is independent of the normal
 * connector.  Source ABORT can therefore be retried after its write socket
 * fails; destination reservation can run before its connector starts. */
static int
ht_session_control_step(struct vmctx *ctx, const uint8_t token[16], bool release)
{
	struct ht_channel channel = { .fd = -1 };
	uint8_t frame[DTRACED_MSGHDRSIZE + DTRACED_SESSION_STOP_WIRE_SIZE] = {};
	dtraced_hdr_t header = {};
	uint8_t checked[16], ack, remaining;
	size_t transferred;
	int64_t deadline;
	int error;

	if (ctx == NULL || token == NULL || !prepared) {
		errno = EINVAL;
		return (-1);
	}
	header.msg_type = release ? DTRACED_MSG_SESSION_RELEASE : DTRACED_MSG_SESSION_STOP;
	dtraced_wire_encode_header(frame, &header);
	if (release)
		dtraced_wire_encode_session_release(frame + DTRACED_MSGHDRSIZE, token);
	else
		dtraced_wire_encode_session_stop(frame + DTRACED_MSGHDRSIZE, token);
	if ((release ? dtraced_wire_decode_session_release(checked,
	    frame + DTRACED_MSGHDRSIZE) : dtraced_wire_decode_session_stop(checked,
	    frame + DTRACED_MSGHDRSIZE)) != 0 ||
	    (hypertrace_session_host_stopped(ctx, token) != 0 &&
	    (!release || hypertrace_session_host_released(ctx, token) != 0)) ||
	    ht_connect(&channel, ctx, DTD_SUB_READDATA) != 0)
		return (-1);
	/* One collector RPC has a 60-second budget. Allow its response and
	 * journal commit without holding the device mutex or a tracing channel. */
	deadline = dtraced_io_deadline_after(75000);
	if (deadline < 0 ||
	    dtraced_io_write_size(channel.fd, sizeof(frame), deadline,
	    &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, frame, sizeof(frame), true,
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, &ack, sizeof(ack), false,
	    deadline, &transferred) != 0)
		goto fail;
	if (ack != 1) {
		errno = ack == 0 ? EBUSY : EPROTO;
		goto fail;
	}
	if (dtraced_io_transfer(channel.fd, &remaining, sizeof(remaining), false,
	    deadline, &transferred) != 0)
		goto fail;
	if (remaining > 1 || (release && remaining != 0)) {
		errno = EPROTO;
		goto fail;
	}
	if ((release ? hypertrace_session_host_released(ctx, token) :
	    hypertrace_session_host_stopped(ctx, token)) != 0)
		goto fail;
	ht_disconnect(&channel);
	return (remaining);
fail:
	error = errno;
	ht_disconnect(&channel);
	errno = error;
	return (-1);
}

int
hypertrace_session_collectors_stop_step(struct vmctx *ctx, const uint8_t token[16])
{
	return (ht_session_control_step(ctx, token, false));
}

int
hypertrace_session_release(struct vmctx *ctx, const uint8_t token[16])
{
	return (ht_session_control_step(ctx, token, true));
}

static int
ht_handoff_fresh(struct vmctx *ctx, uint8_t op,
    const uint8_t token[16], const uint8_t digest[32],
    dtraced_delivery_status_t *status, bool *rejected)
{
	struct ht_channel channel = { .fd = -1 };
	uint8_t frame[DTRACED_MSGHDRSIZE +
	    DTRACED_HANDOFF_WIRE_SIZE] = {};
	uint8_t ack;
	size_t length = sizeof(frame), transferred;
	int64_t deadline;
	int error;

	if (status != NULL)
		memset(status, 0, sizeof(*status));
	if (rejected != NULL)
		*rejected = false;
	if (ctx == NULL || !prepared) {
		errno = EINVAL;
		return (-1);
	}
	if (ht_handoff_frame(op, token, digest, frame) != 0)
		return (-1);
	if (ht_connect(&channel, ctx, DTD_SUB_READDATA) != 0)
		return (-1);
	deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0)
		goto fail;
	if (dtraced_io_write_size(channel.fd, length,
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, frame, sizeof(frame), true,
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, &ack, sizeof(ack), false,
	    deadline, &transferred) != 0)
		goto fail;
	if (ack != 1) {
		if (ack == 0 && rejected != NULL)
			*rejected = true;
		errno = EPROTO;
		goto fail;
	}
	if (status != NULL) {
		const uint8_t zero5[5] = {}, zero32[32] = {};
		if (dtraced_wire_read_status(channel.fd, status,
		    deadline, &transferred) != 0)
			goto fail;
		bool has_digest = status->phase == 'p' ||
		    status->phase == 'c' ||
		    status->phase == 'v' || status->phase == 'm' ||
		    status->phase == 'r';
		if (status->delivery_id != 0 || status->revoked != 0 ||
		    status->replay != 0 ||
		    memcmp(status->reserved, zero5, sizeof(zero5)) != 0 ||
		    (status->phase != 0 && status->phase != 'p' &&
		    !has_digest) ||
		    (memcmp(status->digest, zero32, sizeof(zero32)) == 0) !=
		    !has_digest) {
			errno = EPROTO;
			goto fail;
		}
	}
	ht_disconnect(&channel);
	return (0);
fail:
	error = errno;
	if (status != NULL)
		memset(status, 0, sizeof(*status));
	ht_disconnect(&channel);
	errno = error;
	return (-1);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Source-side
 * handoff: called only under vm_checkpoint()'s handoff_enabled, so this is
 * intentionally unreachable until enabled. */
/* Keep an independently attested channel open across VirtIO shutdown and
 * VM destruction. No new VMM attestation can be minted after that cut. */
int
hypertrace_handoff_source_release_open(struct vmctx *ctx)
{
	struct ht_channel channel = { .fd = -1 };
	int fd;

	if (ctx == NULL || !prepared) {
		errno = EINVAL;
		return (-1);
	}
	if (ht_connect(&channel, ctx,
	    DTD_SUB_SOURCE_RELEASE | DTD_SUB_ADMISSION_ACK) != 0)
		return (-1);
	fd = channel.fd;
	channel.fd = -1;
	return (fd);
}

/* This consumes fd even when the daemon rejects or the reply is lost. A
 * failed acknowledgment cannot be promoted into a source-release claim. */
static bool
ht_release_reply_valid(const uint8_t wire[DTRACED_RELEASE_ATTESTED_SIZE],
    const uint8_t token[16], const uint8_t checkpoint_digest[32])
{
	const uint8_t zero3[3] = {}, zero10[10] = {}, zero32[32] = {};
	uint8_t hash[32];

	if (memcmp(wire, "HSA1", 4) != 0 || wire[4] != 1 ||
	    memcmp(wire + 5, zero3, sizeof(zero3)) != 0 ||
	    memcmp(wire + 8, zero32, sizeof(zero32)) == 0 ||
	    memcmp(wire + 40, zero32, sizeof(zero32)) == 0 ||
	    memcmp(wire + 72, "HSL1HTH2", 8) != 0 ||
	    memcmp(wire + 80, token, 16) != 0 ||
	    memcmp(wire + 122, checkpoint_digest, 32) != 0 ||
	    memcmp(wire + 154, zero10, sizeof(zero10)) != 0)
		return (false);
	if (SHA256(wire + 76, 120, hash) == NULL)
		return (false);
	if (memcmp(hash, wire + 196, sizeof(hash)) != 0)
		return (false);
	if (SHA256(wire + 72, 156, hash) == NULL)
		return (false);
	return (memcmp(hash, wire + 228, sizeof(hash)) == 0);
}

int
hypertrace_release_attestation_inspect(
    const uint8_t wire[DTRACED_RELEASE_ATTESTED_SIZE],
    const uint8_t token[16], const uint8_t checkpoint_digest[32])
{
	if (wire == NULL || token == NULL || checkpoint_digest == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (!ht_release_reply_valid(wire, token, checkpoint_digest)) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

/* The manifest authenticates the copied HTX1 member by hash, and HSA1
 * signs its internal digest. Require both views to name the same transfer
 * before submitting the release to a destination daemon. */
int
hypertrace_release_transfer_inspect(
    const uint8_t release[DTRACED_RELEASE_ATTESTED_SIZE],
    const uint8_t token[16], const uint8_t checkpoint_digest[32],
    const void *transfer, size_t transfer_length)
{
	if (release == NULL || token == NULL || checkpoint_digest == NULL ||
	    transfer == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (hypertrace_release_attestation_inspect(release, token,
	    checkpoint_digest) != 0 ||
	    !dtraced_transfer_wire_valid(transfer, transfer_length, token) ||
	    memcmp(release + 164,
	    (const uint8_t *)transfer + transfer_length -
	    DTRACED_TRANSFER_DIGEST_SIZE,
	    DTRACED_TRANSFER_DIGEST_SIZE) != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* Read only an already-durable source release. This local root channel does
 * not recreate a VMM attestation or advance any handoff phase. */
int
hypertrace_release_recover(const uint8_t token[16], const uint8_t digest[32],
    uint8_t attestation[DTRACED_RELEASE_ATTESTED_SIZE])
{
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	dtd_initmsg_t hello = {};
	uint8_t frame[DTRACED_MSGHDRSIZE + DTRACED_HANDOFF_WIRE_SIZE] = {};
	uint8_t candidate[DTRACED_RELEASE_ATTESTED_SIZE] = {};
	uint8_t ack, mode;
	size_t transferred;
	int dirfd = -1, fd = -1, error;
	int64_t deadline;

	if (token == NULL || digest == NULL || attestation == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(attestation, 0, DTRACED_RELEASE_ATTESTED_SIZE);
	if (ht_handoff_frame(DTRACED_HANDOFF_RELEASE_RECOVER,
	    token, digest, frame) != 0)
		return (-1);
	dirfd = open("/var/ddtrace", O_RDONLY | O_DIRECTORY |
	    O_NOFOLLOW | O_CLOEXEC);
	if (dirfd < 0)
		return (-1);
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0)
		goto fail;
	strlcpy(address.sun_path, "sub.sock", sizeof(address.sun_path));
	address.sun_len = SUN_LEN(&address);
	deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0)
		goto fail;
	if (connectat(dirfd, fd, (struct sockaddr *)&address,
	    address.sun_len) != 0) {
		if (errno != EINPROGRESS && errno != EALREADY && errno != EINTR)
			goto fail;
		if (dtraced_io_complete_connect(fd, deadline) != 0)
			goto fail;
	}
	if (dtraced_wire_read_init(fd, &hello, deadline,
	    &transferred) != 0)
		goto fail;
	if (!dtraced_wire_valid_server_init(&hello)) {
		errno = EPROTO;
		goto fail;
	}
	memset(&hello, 0, sizeof(hello));
	hello.protocol_version = DTRACED_PROTOCOL_VERSION;
	hello.kind = DTRACED_KIND_RELEASE_RECOVERY;
	hello.subs = DTD_SUB_RELEASE_RECOVERY;
	strlcpy(hello.ident, "hypertrace-release-recovery",
	    sizeof(hello.ident));
	if (dtraced_wire_write_init(fd, &hello, deadline,
	    &transferred) != 0 ||
	    dtraced_io_write_size(fd, sizeof(frame), deadline,
	    &transferred) != 0 ||
	    dtraced_io_transfer(fd, frame, sizeof(frame), true,
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(fd, &ack, sizeof(ack), false,
	    deadline, &transferred) != 0)
		goto fail;
	if (ack != 1) {
		errno = ENOENT;
		goto fail;
	}
	if (dtraced_io_transfer(fd, &mode, sizeof(mode), false,
	    deadline, &transferred) != 0)
		goto fail;
	if (mode != DTRACED_RELEASE_MODE_SIGNED) {
		errno = EPROTO;
		goto fail;
	}
	if (dtraced_io_transfer(fd, candidate, sizeof(candidate), false,
	    deadline, &transferred) != 0) {
		goto fail;
	}
	if (hypertrace_release_attestation_inspect(candidate,
	    token, digest) != 0)
		goto fail;
	memcpy(attestation, candidate, sizeof(candidate));
	close(fd);
	close(dirfd);
	return (0);
fail:
	error = errno != 0 ? errno : EIO;
	if (fd >= 0)
		close(fd);
	close(dirfd);
	errno = error;
	return (-1);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Source-side
 * handoff: called only under vm_checkpoint()'s handoff_enabled, so this is
 * intentionally unreachable until enabled. */
int
hypertrace_handoff_source_release_finish(int fd, const uint8_t token[16],
    const uint8_t digest[32],
    uint8_t attestation[DTRACED_RELEASE_ATTESTED_SIZE], bool *signed_release)
{
	uint8_t frame[DTRACED_MSGHDRSIZE + DTRACED_HANDOFF_WIRE_SIZE] = {};
	uint8_t ack, mode, candidate[DTRACED_RELEASE_ATTESTED_SIZE] = {};
	size_t transferred;
	int64_t deadline;
	int error = 0;

	if (attestation == NULL || signed_release == NULL || token == NULL ||
	    digest == NULL || fd < 0) {
		error = EINVAL;
		goto done;
	}
	memset(attestation, 0, DTRACED_RELEASE_ATTESTED_SIZE);
	*signed_release = false;
	if (ht_handoff_frame(DTRACED_HANDOFF_SOURCE_RELEASE,
	    token, digest, frame) != 0) {
		error = errno;
		goto done;
	}
	deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0 ||
	    dtraced_io_write_size(fd, sizeof(frame), deadline,
	    &transferred) != 0 ||
	    dtraced_io_transfer(fd, frame, sizeof(frame), true,
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(fd, &ack, sizeof(ack), false,
	    deadline, &transferred) != 0)
		error = errno != 0 ? errno : EIO;
	else if (ack != 1)
		error = EPROTO;
	else if (dtraced_io_transfer(fd, &mode, sizeof(mode), false,
	    deadline, &transferred) != 0)
		error = errno != 0 ? errno : EIO;
	else if (mode == DTRACED_RELEASE_MODE_SIGNED) {
		if (dtraced_io_transfer(fd, candidate, sizeof(candidate), false,
		    deadline, &transferred) != 0)
			error = errno != 0 ? errno : EIO;
		else if (hypertrace_release_attestation_inspect(candidate, token,
		    digest) != 0)
			error = EPROTO;
		else {
			memcpy(attestation, candidate, sizeof(candidate));
			*signed_release = true;
		}
	} else if (mode != DTRACED_RELEASE_MODE_LOCAL)
		error = EPROTO;
done:
	if (fd >= 0 && close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  No caller: this
 * is intentionally unreachable until enabled. */
int
hypertrace_handoff_source_fresh(struct vmctx *ctx, uint8_t op,
    const uint8_t token[16], const uint8_t digest[32])
{
	if (op != DTRACED_HANDOFF_PREPARE &&
	    op != DTRACED_HANDOFF_COMMIT &&
	    op != DTRACED_HANDOFF_ABORT &&
	    op != DTRACED_HANDOFF_SOURCE_GATE_BEGIN &&
	    op != DTRACED_HANDOFF_SOURCE_GATE_ABORT) {
		errno = EINVAL;
		return (-1);
	}
	return (ht_handoff_fresh(ctx, op, token, digest, NULL, NULL));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Source-side
 * handoff: called only under vm_checkpoint()'s handoff_enabled, so this is
 * intentionally unreachable until enabled. */
/* HGI1 begin and abort are exact-ticket idempotent. A second attested
 * connection may settle a lost ACK, but an explicit refusal is final.
 * A late abort cannot resume a newer gate owner. */
int
hypertrace_handoff_source_gate_ensure(struct vmctx *ctx, uint8_t op,
    const uint8_t token[16])
{
	const uint8_t zero_digest[32] = {};

	if (op != DTRACED_HANDOFF_SOURCE_GATE_BEGIN &&
	    op != DTRACED_HANDOFF_SOURCE_GATE_ABORT) {
		errno = EINVAL;
		return (-1);
	}
	for (unsigned attempt = 0; attempt < 2; attempt++) {
		bool rejected = false;
		if (ht_handoff_fresh(ctx, op, token, zero_digest,
		    NULL, &rejected) == 0)
			return (0);
		if (rejected || errno == EPROTO)
			return (-1);
	}
	return (-1);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Source-side
 * handoff: called only under vm_checkpoint()'s handoff_enabled, so this is
 * intentionally unreachable until enabled. */
/* One request can wait for at most one consumer's bounded drain. The daemon
 * fsyncs HGD1 before replying "more"; an uncertain reply is retried with
 * the same ticket and HTX1 digest, and may either replay or advance a step. */
static int
ht_handoff_source_drain_once(struct vmctx *ctx, const uint8_t token[16],
    const uint8_t digest[32], uint8_t *more, bool *rejected)
{
	struct ht_channel channel = { .fd = -1 };
	uint8_t frame[DTRACED_MSGHDRSIZE + DTRACED_HANDOFF_WIRE_SIZE] = {};
	uint8_t ack = 0, remaining = 0;
	size_t transferred;
	int64_t deadline;
	int error;

	*more = 0;
	*rejected = false;
	if (ctx == NULL || !prepared ||
	    ht_handoff_frame(DTRACED_HANDOFF_SOURCE_DRAIN_STEP,
	    token, digest, frame) != 0)
		return (-1);
	if (ht_connect(&channel, ctx, DTD_SUB_READDATA) != 0)
		return (-1);
	deadline = dtraced_io_deadline_after(120000);
	if (deadline < 0 ||
	    dtraced_io_write_size(channel.fd, sizeof(frame),
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, frame, sizeof(frame), true,
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, &ack, sizeof(ack), false,
	    deadline, &transferred) != 0)
		goto fail;
	if (ack != 1) {
		*rejected = ack == 0;
		errno = ack == 0 ? EAGAIN : EPROTO;
		goto fail;
	}
	if (dtraced_io_transfer(channel.fd, &remaining,
	    sizeof(remaining), false, deadline, &transferred) != 0)
		goto fail;
	if (remaining > 1) {
		errno = EPROTO;
		goto fail;
	}
	*more = remaining;
	ht_disconnect(&channel);
	return (0);
fail:
	error = errno != 0 ? errno : EIO;
	ht_disconnect(&channel);
	errno = error;
	return (-1);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Source-side
 * handoff: called only under vm_checkpoint()'s handoff_enabled, so this is
 * intentionally unreachable until enabled. */
int
hypertrace_handoff_source_drain(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32])
{
	for (uint32_t i = 0; i <= DTRACED_CONSUMER_RECEIPT_LIMIT; i++) {
		uint8_t more = 0;
		bool rejected = false;
		if (ht_handoff_source_drain_once(ctx, token, digest,
		    &more, &rejected) != 0) {
			if (rejected || ht_handoff_source_drain_once(ctx,
			    token, digest, &more, &rejected) != 0)
				return (-1);
		}
		if (more == 0)
			return (0);
	}
	errno = E2BIG;
	return (-1);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Source-side
 * handoff: called only under vm_checkpoint()'s handoff_enabled, so this is
 * intentionally unreachable until enabled. */
int
hypertrace_handoff_source_status_fresh(struct vmctx *ctx,
    const uint8_t token[16], dtraced_delivery_status_t *status)
{
	const uint8_t zero_digest[32] = {};

	if (status == NULL) {
		errno = EINVAL;
		return (-1);
	}
	return (ht_handoff_fresh(ctx, DTRACED_HANDOFF_SOURCE_STATUS,
	    token, zero_digest, status, NULL));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Source-side
 * handoff: called only under vm_checkpoint()'s handoff_enabled, so this is
 * intentionally unreachable until enabled. */
/* The caller owns *bundle only after the complete, token-bound HTX1 frame
 * passes its checksum and canonical-length checks.  A rejected or partial
 * reply never exposes bytes to the checkpoint writer. */
int
hypertrace_handoff_source_bundle_fresh(struct vmctx *ctx,
    const uint8_t token[16], void **bundle, size_t *bundle_length)
{
	const uint8_t zero_digest[32] = {};
	struct ht_channel channel = { .fd = -1 };
	uint8_t frame[DTRACED_MSGHDRSIZE + DTRACED_HANDOFF_WIRE_SIZE] = {};
	uint8_t ack;
	void *bytes = NULL;
	size_t length, transferred;
	int64_t deadline;
	int error;

	if (bundle == NULL || bundle_length == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*bundle = NULL;
	*bundle_length = 0;
	if (ctx == NULL || !prepared || token == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (ht_handoff_frame(DTRACED_HANDOFF_EXPORT, token, zero_digest,
	    frame) != 0)
		return (-1);
	if (ht_connect(&channel, ctx, DTD_SUB_READDATA) != 0)
		return (-1);
	deadline = dtraced_io_deadline_after(60000);
	if (deadline < 0 || dtraced_io_write_size(channel.fd, sizeof(frame),
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, frame, sizeof(frame), true,
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, &ack, sizeof(ack), false,
	    deadline, &transferred) != 0)
		goto fail;
	if (ack != 1) {
		errno = EPROTO;
		goto fail;
	}
	if (dtraced_io_read_size(channel.fd, &length, deadline,
	    &transferred) != 0)
		goto fail;
	if (length < DTRACED_TRANSFER_HEADER_SIZE +
	    DTRACED_TRANSFER_DIGEST_SIZE ||
	    length > DTRACED_TRANSFER_MAX_SIZE) {
		errno = EPROTO;
		goto fail;
	}
	bytes = malloc(length);
	if (bytes == NULL)
		goto fail;
	if (dtraced_io_transfer(channel.fd, bytes, length, false,
	    deadline, &transferred) != 0 ||
	    !dtraced_transfer_wire_valid(bytes, length, token))
		goto fail;
	*bundle = bytes;
	*bundle_length = length;
	ht_disconnect(&channel);
	return (0);
fail:
	error = errno;
	free(bytes);
	ht_disconnect(&channel);
	errno = error;
	return (-1);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* Stage the signed source release before reservation. The daemon checks
 * its pinned keys; this fresh VMM-attested channel does not grant a lease. */
static int
ht_stage_release_once(struct vmctx *ctx, const uint8_t token[16],
    const uint8_t digest[32],
    const uint8_t release[DTRACED_RELEASE_ATTESTED_SIZE], bool *rejected)
{
	struct ht_channel channel = { .fd = -1 };
	dtraced_hdr_t header = { .msg_type =
	    DTRACED_MSG_HANDOFF_RELEASE_IMPORT };
	uint8_t frame[DTRACED_MSGHDRSIZE +
	    DTRACED_HANDOFF_RELEASE_IMPORT_SIZE] = {};
	uint8_t ack;
	size_t transferred;
	int64_t deadline;
	int error;

	if (rejected != NULL)
		*rejected = false;
	if (ctx == NULL || !prepared || started || token == NULL ||
	    digest == NULL || release == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (hypertrace_release_attestation_inspect(release, token,
	    digest) != 0)
		return (-1);
	dtraced_wire_encode_header(frame, &header);
	memcpy(frame + DTRACED_MSGHDRSIZE, token, 16);
	memcpy(frame + DTRACED_MSGHDRSIZE + 16, digest, 32);
	memcpy(frame + DTRACED_MSGHDRSIZE + 48, release,
	    DTRACED_RELEASE_ATTESTED_SIZE);
	if (ht_connect(&channel, ctx, DTD_SUB_READDATA) != 0)
		return (-1);
	deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0 || dtraced_io_write_size(channel.fd,
	    sizeof(frame), deadline, &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, frame, sizeof(frame), true,
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, &ack, sizeof(ack), false,
	    deadline, &transferred) != 0)
		goto fail;
	if (ack != 1) {
		if (rejected != NULL)
			*rejected = true;
		errno = EPROTO;
		goto fail;
	}
	ht_disconnect(&channel);
	return (0);
fail:
	error = errno;
	ht_disconnect(&channel);
	errno = error;
	return (-1);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
int
hypertrace_handoff_destination_stage_release_prestart(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32],
    const uint8_t release[DTRACED_RELEASE_ATTESTED_SIZE])
{
	bool rejected = false;

	if (ht_stage_release_once(ctx, token, digest, release, &rejected) == 0)
		return (0);
	if (rejected || (errno != ECONNRESET && errno != EPIPE &&
	    errno != ETIMEDOUT && errno != ENOTCONN && errno != EIO))
		return (-1);
	return (ht_stage_release_once(ctx, token, digest, release, NULL));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* Import only after the destination ticket is reserved. The daemon
 * authenticates this fresh channel against the live VMM descriptor and
 * publishes pending records only after an exact durable HTB1 stage. */
static int
ht_handoff_import_once(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32],
    const void *bundle, size_t bundle_length, bool *rejected)
{
	struct ht_channel channel = { .fd = -1 };
	dtraced_hdr_t header = { 0 };
	uint8_t frame[DTRACED_MSGHDRSIZE] = { 0 };
	uint8_t ack, binding[DTRACED_HANDOFF_IMPORT_BINDING_SIZE];
	size_t transferred;
	int64_t deadline;
	int error;

	if (rejected != NULL)
		*rejected = false;
	if (ctx == NULL || !prepared || started || token == NULL || digest == NULL ||
	    bundle == NULL || bundle_length < HYPERTRACE_TRANSFER_MIN_BYTES ||
	    bundle_length > HYPERTRACE_TRANSFER_MAX_BYTES ||
	    !dtraced_transfer_wire_valid(bundle, bundle_length, token) ||
	    bundle_length > HT_MAX_FRAME - sizeof(frame) - sizeof(binding)) {
		errno = EINVAL;
		return (-1);
	}
	memcpy(binding, token, 16);
	memcpy(binding + 16, digest, 32);
	header.msg_type = DTRACED_MSG_HANDOFF_IMPORT;
	dtraced_wire_encode_header(frame, &header);
	if (ht_connect(&channel, ctx, DTD_SUB_READDATA) != 0)
		return (-1);
	deadline = dtraced_io_deadline_after(60000);
	if (deadline < 0 || dtraced_io_write_size(channel.fd,
	    sizeof(frame) + sizeof(binding) + bundle_length,
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, frame, sizeof(frame), true,
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, binding, sizeof(binding), true,
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, (void *)(uintptr_t)bundle,
	    bundle_length, true, deadline, &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, &ack, sizeof(ack), false,
	    deadline, &transferred) != 0)
		goto fail;
	if (ack != 1) {
		if (rejected != NULL)
			*rejected = true;
		errno = EPROTO;
		goto fail;
	}
	ht_disconnect(&channel);
	return (0);
fail:
	error = errno;
	ht_disconnect(&channel);
	errno = error;
	return (-1);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* The daemon's reserved HTB1/HTD5/HTL1 import is exact-retry safe. Retry
 * once if the frame or ACK was lost, but never after a NAK, malformed ACK,
 * or protocol rejection. The caller still owns the pre-MUTATE cancel path. */
int
hypertrace_handoff_destination_import_prestart(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32],
    const void *bundle, size_t bundle_length)
{
	bool rejected = false;

	if (ht_handoff_import_once(ctx, token, digest, bundle, bundle_length,
	    &rejected) == 0)
		return (0);
	if (rejected || (errno != ECONNRESET && errno != EPIPE &&
	    errno != ETIMEDOUT && errno != ENOTCONN && errno != EIO))
		return (-1);
	return (ht_handoff_import_once(ctx, token, digest, bundle,
	    bundle_length, NULL));
}

int
hypertrace_handoff_destination_status_prestart(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32],
    dtraced_delivery_status_t *status)
{
	int error;

	if (status == NULL || digest == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (ht_handoff_fresh(ctx, DTRACED_HANDOFF_DESTINATION_STATUS,
	    token, digest, status, NULL) != 0)
		return (-1);
	if ((status->phase != 'c' && status->phase != 'v' &&
	    status->phase != 'm' && status->phase != 'r') ||
	    memcmp(status->digest, digest, sizeof(status->digest)) != 0) {
		error = EPROTO;
		memset(status, 0, sizeof(*status));
		errno = error;
		return (-1);
	}
	return (0);
}

static int ht_handoff_destination_prestart_once(struct vmctx *, uint8_t,
    const uint8_t [16], const uint8_t [32], bool *);

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* A RESERVE with an uncertain reply is never resent: the original could
 * publish after a status query and re-reserve a ticket following CANCEL.
 * The later destination transitions are idempotent while their caller holds
 * the VM stopped and advances only after this helper confirms each phase. */
int
hypertrace_handoff_destination_ensure(struct vmctx *ctx, uint8_t op,
    const uint8_t token[16], const uint8_t digest[32])
{
	dtraced_delivery_status_t status;
	uint8_t done_phase, retry_phase;

	switch (op) {
	case DTRACED_HANDOFF_RESERVE:
		done_phase = 'v';
		retry_phase = 'c';
		break;
	case DTRACED_HANDOFF_CANCEL:
		done_phase = 'c';
		retry_phase = 'v';
		break;
	case DTRACED_HANDOFF_MUTATE:
		done_phase = 'm';
		retry_phase = 'v';
		break;
	case DTRACED_HANDOFF_CLAIM:
		done_phase = 'r';
		retry_phase = 'm';
		break;
	default:
		errno = EINVAL;
		return (-1);
	}
	for (int attempt = 0; attempt < 2; attempt++) {
		bool rejected = false;
		if (ht_handoff_destination_prestart_once(ctx, op, token,
		    digest, &rejected) == 0)
			return (0);
		if (rejected || errno == EPROTO)
			return (-1);
		if (hypertrace_handoff_destination_status_prestart(ctx,
		    token, digest, &status) != 0)
			return (-1);
		if (status.phase == done_phase)
			return (0);
		if (status.phase != retry_phase || attempt != 0 ||
		    op == DTRACED_HANDOFF_RESERVE) {
			errno = EBUSY;
			return (-1);
		}
	}
	errno = EBUSY;
	return (-1);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Source-side
 * handoff: called only under vm_checkpoint()'s handoff_enabled, so this is
 * intentionally unreachable until enabled. */
/* Resolve a lost ACK against the durable source ticket.  A failed PREPARE
 * permits the caller to resume only when the exact ticket is proved absent.
 * COMMIT/ABORT retry once while the ticket is still prepared. */
int
hypertrace_handoff_source_ensure(struct vmctx *ctx, uint8_t op,
    const uint8_t token[16], const uint8_t digest[32], bool *absent)
{
	dtraced_delivery_status_t status;
	bool rejected;
	int request_error;

	if (absent == NULL || (op != DTRACED_HANDOFF_PREPARE &&
	    op != DTRACED_HANDOFF_COMMIT && op != DTRACED_HANDOFF_ABORT)) {
		errno = EINVAL;
		return (-1);
	}
	*absent = false;
	for (int attempt = 0; attempt < 2; attempt++) {
		if (ht_handoff_fresh(ctx, op, token, digest, NULL,
		    &rejected) == 0)
			return (0);
		request_error = errno;
		if (hypertrace_handoff_source_status_fresh(ctx, token,
		    &status) != 0) {
			/* A timed-out PREPARE may still be queued on its original
			 * connection.  Sending another can create a late new ticket
			 * after a later ABORT, so only settled transitions retry. */
			if (op != DTRACED_HANDOFF_PREPARE && attempt == 0)
				continue;
			return (-1);
		}
		if (op == DTRACED_HANDOFF_PREPARE) {
			if (status.phase == 'p' &&
			    memcmp(status.digest, digest, sizeof(status.digest)) == 0)
				return (0);
			/* Only an explicit rejection of the first request has
			 * no older in-flight PREPARE that could publish later. */
			if (status.phase == 0 && rejected && attempt == 0) {
				*absent = true;
				errno = request_error;
				return (-1);
			}
			if (status.phase == 0) {
				errno = EBUSY;
				return (-1);
			}
		} else if (op == DTRACED_HANDOFF_ABORT) {
			if (status.phase == 0)
				return (0);
			if (status.phase == 'p' && attempt == 0)
				continue;
		} else {
			if ((status.phase == 'c' || status.phase == 'v' ||
			    status.phase == 'm' || status.phase == 'r') &&
			    memcmp(status.digest, digest, sizeof(status.digest)) == 0)
				return (0);
			if (status.phase == 'p' && attempt == 0)
				continue;
		}
		errno = EBUSY;
		return (-1);
	}
	errno = EIO;
	return (-1);
}

/* Restore keeps the normal rx/wx connector stopped until device and journal
 * state can be rebound.  Reservation must precede destination mutation. */
static int
ht_handoff_destination_prestart_once(struct vmctx *ctx, uint8_t op,
    const uint8_t token[16], const uint8_t digest[32], bool *rejected)
{
	if (ctx == NULL || !prepared || started) {
		errno = EINVAL;
		return (-1);
	}
	if (op != DTRACED_HANDOFF_RESERVE &&
	    op != DTRACED_HANDOFF_CANCEL &&
	    op != DTRACED_HANDOFF_MUTATE &&
	    op != DTRACED_HANDOFF_CLAIM &&
	    op != DTRACED_HANDOFF_BIND_KILLS_ALL &&
	    op != DTRACED_HANDOFF_PROMOTE_IMPORT &&
	    op != DTRACED_HANDOFF_ACTIVATE_IMPORT) {
		errno = EINVAL;
		return (-1);
	}
	return (ht_handoff_fresh(ctx, op, token, digest, NULL, rejected));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
int
hypertrace_handoff_destination_prestart(struct vmctx *ctx, uint8_t op,
    const uint8_t token[16], const uint8_t digest[32])
{
	return (ht_handoff_destination_prestart_once(ctx, op, token, digest,
	    NULL));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* PROMOTE_IMPORT is idempotent after a lost reply. An explicit NAK is a
 * settled refusal, so it must not be retried as an uncertain write. This
 * barrier runs after CLAIM/binding and before connector or vCPU release. */
int
hypertrace_handoff_destination_promote_prestart(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32])
{
	bool rejected = false;

	if (ctx == NULL || !prepared || started) {
		errno = EINVAL;
		return (-1);
	}
	if (ht_handoff_fresh(ctx, DTRACED_HANDOFF_PROMOTE_IMPORT,
	    token, digest, NULL, &rejected) == 0)
		return (0);
	if (rejected || errno == EPROTO)
		return (-1);
	return (ht_handoff_fresh(ctx, DTRACED_HANDOFF_PROMOTE_IMPORT,
	    token, digest, NULL, NULL));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* Query or durably bind a source receipt through the attested destination.
 * Neither reply alone permits replay before the ticket is CLAIMED. */
static int
ht_handoff_delivery_lookup(struct vmctx *ctx,
    const dtraced_handoff_delivery_request_t *request,
    const uint8_t *payload_digest, dtraced_delivery_status_t *status,
    bool bind_delivery,
    bool require_started)
{
	const uint8_t zero16[16] = {}, zero32[32] = {}, zero7[7] = {};
	struct ht_channel channel = { .fd = -1 };
	dtraced_hdr_t header = { .msg_type = bind_delivery ?
	    DTRACED_MSG_HANDOFF_BIND_DELIVERY : DTRACED_MSG_HANDOFF_DELIVERY };
	uint8_t frame[DTRACED_MSGHDRSIZE +
	    DTRACED_HANDOFF_BIND_DELIVERY_WIRE_SIZE] = {};
	uint8_t ack;
	size_t length = DTRACED_MSGHDRSIZE + (bind_delivery ?
	    DTRACED_HANDOFF_BIND_DELIVERY_WIRE_SIZE :
	    DTRACED_HANDOFF_DELIVERY_WIRE_SIZE), transferred;
	int64_t deadline;
	int error;

	if (ctx == NULL || request == NULL || status == NULL || !prepared ||
	    started != require_started ||
	    (require_started && bind_delivery) ||
	    memcmp(request->token, zero16, sizeof(zero16)) == 0 ||
	    memcmp(request->digest, zero32, sizeof(zero32)) == 0 ||
	    request->delivery_id == 0 ||
	    (request->scope != 0 &&
	    (bind_delivery || request->scope != 3)) ||
	    memcmp(request->program_id, zero16, sizeof(zero16)) == 0 ||
	    memcmp(request->source_id, zero16, sizeof(zero16)) == 0 ||
	    memcmp(request->reserved, zero7, sizeof(zero7)) != 0 ||
	    (bind_delivery ? (payload_digest == NULL ||
	    memcmp(payload_digest, zero32, sizeof(zero32)) == 0) :
	    payload_digest != NULL)) {
		errno = EINVAL;
		return (-1);
	}
	memset(status, 0, sizeof(*status));
	dtraced_wire_encode_header(frame, &header);
	if (bind_delivery) {
		dtraced_handoff_bind_delivery_request_t bound = {0};
		bound.delivery = *request;
		memcpy(bound.payload_digest, payload_digest, 32);
		dtraced_wire_encode_handoff_bind_delivery(
		    frame + DTRACED_MSGHDRSIZE, &bound);
	} else {
		dtraced_wire_encode_handoff_delivery(
		    frame + DTRACED_MSGHDRSIZE, request);
	}
	if (ht_connect(&channel, ctx, DTD_SUB_READDATA) != 0)
		return (-1);
	deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0)
		goto fail;
	if (dtraced_io_write_size(channel.fd, length,
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, frame, length, true,
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, &ack, sizeof(ack), false,
	    deadline, &transferred) != 0)
		goto fail;
	if (ack != 1) {
		errno = EPROTO;
		goto fail;
	}
	if (dtraced_wire_read_status(channel.fd, status,
	    deadline, &transferred) != 0)
		goto fail;
	if (status->delivery_id != request->delivery_id ||
	    (status->phase != 0 && status->phase != 'p' &&
	    status->phase != 'a' && status->phase != 'i' &&
	    status->phase != 't') || status->revoked > 1 ||
	    (status->phase == 0 && status->revoked != 0) ||
	    status->replay != 0 ||
	    memcmp(status->reserved, (const uint8_t[5]){0}, 5) != 0 ||
	    (bind_delivery && ((status->phase != 'a' &&
	    status->phase != 'i') || status->revoked != 0 ||
	    memcmp(status->digest, zero32, sizeof(zero32)) == 0)) ||
	    ((status->phase == 0 || status->phase == 'p' ||
	    status->phase == 't' || status->revoked != 0) &&
	    memcmp(status->digest, zero32, sizeof(zero32)) != 0)) {
		errno = EPROTO;
		goto fail;
	}
	ht_disconnect(&channel);
	return (0);
fail:
	error = errno;
	memset(status, 0, sizeof(*status));
	ht_disconnect(&channel);
	errno = error;
	return (-1);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
int
hypertrace_handoff_delivery_prestart(struct vmctx *ctx,
    const dtraced_handoff_delivery_request_t *request,
    dtraced_delivery_status_t *status)
{
	return (ht_handoff_delivery_lookup(ctx, request, NULL, status, false,
	    false));
}

int
hypertrace_handoff_delivery_live(struct vmctx *ctx,
    const dtraced_handoff_delivery_request_t *request,
    dtraced_delivery_status_t *status)
{
	return (ht_handoff_delivery_lookup(ctx, request, NULL, status, false,
	    true));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
int
hypertrace_handoff_bind_delivery_prestart(struct vmctx *ctx,
    const dtraced_handoff_bind_delivery_request_t *request,
    dtraced_delivery_status_t *status)
{
	return (ht_handoff_delivery_lookup(ctx,
	    request != NULL ? &request->delivery : NULL,
	    request != NULL ? request->payload_digest : NULL, status, true,
	    false));
}

/* Query source KILL state or bind it durably after destination CLAIM. */
static int
ht_handoff_kill_lookup(struct vmctx *ctx,
    const dtraced_handoff_kill_request_t *request,
    dtraced_delivery_status_t *status, bool bind_kill,
    bool require_started)
{
	const uint8_t zero16[16] = {}, zero32[32] = {}, zero4[4] = {};
	struct ht_channel channel = { .fd = -1 };
	dtraced_hdr_t header = { .msg_type = bind_kill ?
	    DTRACED_MSG_HANDOFF_BIND_KILL : DTRACED_MSG_HANDOFF_KILL };
	uint8_t frame[DTRACED_MSGHDRSIZE + DTRACED_HANDOFF_KILL_WIRE_SIZE] = {};
	uint8_t ack;
	size_t length = sizeof(frame), transferred;
	int64_t deadline;
	int error;

	if (ctx == NULL || request == NULL || status == NULL || !prepared ||
	    started != require_started || (require_started && bind_kill) ||
	    memcmp(request->token, zero16, sizeof(zero16)) == 0 ||
	    memcmp(request->digest, zero32, sizeof(zero32)) == 0 ||
	    request->pid <= 1 ||
	    memcmp(request->source_id, zero16, sizeof(zero16)) == 0 ||
	    memcmp(request->reserved, zero4, sizeof(zero4)) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(status, 0, sizeof(*status));
	dtraced_wire_encode_header(frame, &header);
	dtraced_wire_encode_handoff_kill(frame + DTRACED_MSGHDRSIZE, request);
	if (ht_connect(&channel, ctx, DTD_SUB_READDATA) != 0)
		return (-1);
	deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0)
		goto fail;
	if (dtraced_io_write_size(channel.fd, length,
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, frame, sizeof(frame), true,
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, &ack, sizeof(ack), false,
	    deadline, &transferred) != 0)
		goto fail;
	if (ack != 1) {
		errno = EPROTO;
		goto fail;
	}
	if (dtraced_wire_read_status(channel.fd, status,
	    deadline, &transferred) != 0)
		goto fail;
	if (status->delivery_id != (uint32_t)request->pid ||
	    (status->phase != 0 && status->phase != 'p' &&
	    status->phase != 'a') ||
	    status->revoked > 1 ||
	    (status->phase != 0 && status->revoked == 0) ||
	    (bind_kill && (status->phase == 0 || status->revoked == 0)) ||
	    status->replay != 0 ||
	    memcmp(status->reserved, (const uint8_t[5]){0}, 5) != 0 ||
	    memcmp(status->digest, zero32, sizeof(zero32)) != 0) {
		errno = EPROTO;
		goto fail;
	}
	ht_disconnect(&channel);
	return (0);
fail:
	error = errno;
	memset(status, 0, sizeof(*status));
	ht_disconnect(&channel);
	errno = error;
	return (-1);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
int
hypertrace_handoff_kill_prestart(struct vmctx *ctx,
    const dtraced_handoff_kill_request_t *request,
    dtraced_delivery_status_t *status)
{
	return (ht_handoff_kill_lookup(ctx, request, status, false, false));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
int
hypertrace_handoff_cleanup_prestart(struct vmctx *ctx,
    const dtraced_handoff_cleanup_request_t *request,
    dtraced_delivery_status_t *status)
{
	const uint8_t zero16[16] = {}, zero32[32] = {};
	struct ht_channel channel = { .fd = -1 };
	dtraced_hdr_t header = { .msg_type = DTRACED_MSG_HANDOFF_CLEANUP };
	uint8_t frame[DTRACED_MSGHDRSIZE +
	    DTRACED_HANDOFF_CLEANUP_WIRE_SIZE] = {};
	uint8_t ack;
	size_t transferred;
	int64_t deadline;
	int error;

	if (ctx == NULL || request == NULL || status == NULL || !prepared ||
	    started || request->delivery_id == 0 ||
	    memcmp(request->token, zero16, 16) == 0 ||
	    memcmp(request->digest, zero32, 32) == 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(status, 0, sizeof(*status));
	dtraced_wire_encode_header(frame, &header);
	dtraced_wire_encode_handoff_cleanup(frame + DTRACED_MSGHDRSIZE,
	    request);
	if (ht_connect(&channel, ctx, DTD_SUB_READDATA) != 0)
		return (-1);
	deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0)
		goto fail;
	if (dtraced_io_write_size(channel.fd, sizeof(frame), deadline,
	    &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, frame, sizeof(frame), true,
	    deadline, &transferred) != 0 ||
	    dtraced_io_transfer(channel.fd, &ack, sizeof(ack), false,
	    deadline, &transferred) != 0)
		goto fail;
	if (ack != 1) {
		errno = EPROTO;
		goto fail;
	}
	if (dtraced_wire_read_status(channel.fd, status,
	    deadline, &transferred) != 0)
		goto fail;
	if (status->delivery_id != request->delivery_id ||
	    (status->phase != 0 && status->phase != 'a') ||
	    status->revoked != 0 || status->replay != 0 ||
	    memcmp(status->digest, zero32, 32) != 0) {
		errno = EPROTO;
		goto fail;
	}
	ht_disconnect(&channel);
	return (0);
fail:
	error = errno;
	memset(status, 0, sizeof(*status));
	ht_disconnect(&channel);
	errno = error;
	return (-1);
}

int
hypertrace_handoff_kill_live(struct vmctx *ctx,
    const dtraced_handoff_kill_request_t *request,
    dtraced_delivery_status_t *status)
{
	return (ht_handoff_kill_lookup(ctx, request, status, false, true));
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  No caller: this
 * is intentionally unreachable until enabled. */
int
hypertrace_handoff_bind_kill_prestart(struct vmctx *ctx,
    const dtraced_handoff_kill_request_t *request,
    dtraced_delivery_status_t *status)
{
	return (ht_handoff_kill_lookup(ctx, request, status, true, false));
}

static int
ht_query_status(const dtraced_hdr_t *request,
    dtraced_delivery_status_t *status, uint64_t message_type)
{
	const uint8_t zero_id[16] = { 0 };
	unsigned char ack;
	unsigned char header_wire[DTRACED_MSGHDRSIZE];
	size_t transferred, len = DTRACED_MSGHDRSIZE;
	int error;
	int64_t deadline;

	if (request == NULL || status == NULL ||
	    request->msg_type != message_type ||
	    request->installed.delivery_id == 0 ||
	    request->installed.vmid == 0 ||
	    request->installed.epoch == 0 ||
	    memcmp(request->installed.program_id, zero_id, 16) == 0 ||
	    memcmp(request->installed.source_id, zero_id, 16) == 0) {
		errno = EINVAL;
		return (-1);
	}
	dtraced_wire_encode_header(header_wire, request);
	memset(status, 0, sizeof(*status));
	pthread_mutex_lock(&wx.mutex);
	if (!atomic_load(&wx.configured)) {
		errno = ENOTCONN;
		goto fail;
	}
	deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0)
		goto fail;
	if (dtraced_io_write_size(wx.fd, len, deadline,
	    &transferred) != 0 ||
	    dtraced_io_transfer(wx.fd, header_wire, len, true, deadline,
	    &transferred) != 0 ||
	    dtraced_io_transfer(wx.fd, &ack, sizeof(ack), false, deadline,
	    &transferred) != 0)
		goto fail;
	if (ack != 1) {
		errno = EPROTO;
		goto fail;
	}
	if (dtraced_wire_read_status(wx.fd, status,
	    deadline, &transferred) != 0)
		goto fail;
	bool ingress = message_type == DTRACED_MSG_INGRESS_STATUS;
	bool valid = status->delivery_id == request->installed.delivery_id &&
	    status->revoked <= 1 &&
	    memcmp(status->reserved, (const uint8_t[5]){0}, 5) == 0;
	if (ingress)
		valid = valid && status->replay == 0 &&
		    (status->phase == 0 || status->phase == 'p' ||
		    status->phase == 'a') &&
		    ((status->phase == 0) ==
		    (memcmp(status->digest, (const uint8_t[32]){0}, 32) == 0));
	else
		valid = valid &&
		    (status->phase == 0 || status->phase == 'p' ||
		    status->phase == 'a' || status->phase == 'i' ||
		    status->phase == 't' || status->phase == 'u') &&
		    status->replay <= 1 &&
		    (status->replay == 0 ||
		    (status->revoked == 0 &&
		    (status->phase == 'a' || status->phase == 'i'))) &&
		    (status->phase != 'u' || status->revoked == 0) &&
	    /* A replay grant must identify the exact ELF bytes to replay. */
	    ((status->replay == 0) ==
	    (memcmp(status->digest, (const uint8_t[32]){0}, 32) == 0));
	if (!valid) {
		errno = EPROTO;
		goto fail;
	}
	pthread_mutex_unlock(&wx.mutex);
	return (0);
fail:
	error = errno;
	memset(status, 0, sizeof(*status));
	ht_disconnect(&wx);
	pthread_mutex_unlock(&wx.mutex);
	errno = error;
	return (-1);
}

int
hypertrace_delivery_status(const dtraced_hdr_t *request,
    dtraced_delivery_status_t *status)
{
	return (ht_query_status(request, status, DTRACED_MSG_STATUS));
}

int
hypertrace_ingress_status(const dtraced_hdr_t *request,
    dtraced_delivery_status_t *status)
{
	return (ht_query_status(request, status,
	    DTRACED_MSG_INGRESS_STATUS));
}

/* Device workers must already be stopped. Join the connector before its VM
 * context can be freed, but retain the epoch-query capability for retirement
 * proof and recovery after destruction. Safe to retry after a failed join. */
int
hypertrace_retire_transport(void)
{
	int error;

	pthread_mutex_lock(&lifecycle);
	prepared = false;
	stopping = true;
	atomic_store(&restore_mode, false);
	pthread_cond_broadcast(&reconnect);
	pthread_mutex_unlock(&lifecycle);
	if (started) {
		error = pthread_join(connector, NULL);
		if (error != 0)
			return (error);
		started = false;
	}
	pthread_mutex_lock(&rx.mutex);
	ht_disconnect(&rx);
	pthread_mutex_unlock(&rx.mutex);
	pthread_mutex_lock(&wx.mutex);
	ht_disconnect(&wx);
	pthread_mutex_unlock(&wx.mutex);
	if (inbound_dirfd != -1)
		close(inbound_dirfd);
	if (sockdir != -1)
		close(sockdir);
	inbound_dirfd = sockdir = -1;
	return (0);
}

void
hypertrace_destroy(void)
{
	if (hypertrace_retire_transport() != 0)
		return;
	if (session_gate_fd != -1)
		close(session_gate_fd);
	session_gate_fd = -1;
	session_gate_error = ENXIO;
}

