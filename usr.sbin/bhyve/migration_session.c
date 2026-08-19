/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Live-migration control plane: wire codec, capability/topology negotiation,
 * an injectable transport (with a thin fd/stream adapter), and the source and
 * destination session state machines.
 *
 * Everything in this file above the BHYVE_SNAPSHOT guard is pure: it has no
 * dependency on a running VM, the kernel, a socket, or root, so it compiles in
 * both build modes and is exercised in-process by the rootless session test.
 * The production adapter that binds the source ops to migration_precopy, guest
 * RAM, and the device snapshot codecs lives under the guard at the end.
 */

#include <sys/endian.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "migration_session.h"

/* ------------------------------------------------------------------------- */
/* Small helpers								     */
/* ------------------------------------------------------------------------- */

/*
 * A fixed-width string field is canonical when it is NUL-terminated within its
 * capacity and every byte after the first NUL is also NUL.  This rejects both
 * unterminated fields and non-zeroed padding used to smuggle bytes past the
 * terminator.
 */
static bool
migration_string_canonical(const char *string, size_t capacity)
{
	const char *terminator;
	size_t used;

	terminator = memchr(string, '\0', capacity);
	if (terminator == NULL)
		return (false);
	used = (size_t)(terminator - string) + 1;
	for (size_t i = used; i < capacity; i++) {
		if (string[i] != '\0')
			return (false);
	}
	return (true);
}

static uint32_t
migration_crc32(const void *payload, size_t payload_len)
{
	const uint8_t *cursor;
	uLong checksum;

	if (payload_len == 0)
		return (0);
	cursor = payload;
	checksum = crc32(0L, Z_NULL, 0);
	while (payload_len != 0) {
		uInt chunk;

		chunk = payload_len > UINT_MAX ? UINT_MAX : (uInt)payload_len;
		checksum = crc32(checksum, cursor, chunk);
		cursor += chunk;
		payload_len -= chunk;
	}
	return ((uint32_t)checksum);
}

static bool
migration_message_type_valid(uint16_t type)
{

	return (type >= MIGRATION_MSG_HELLO && type <= MIGRATION_MSG_ABORT);
}

static bool
migration_frame_flags_valid(uint16_t type, uint32_t flags)
{

	if (flags == 0)
		return (true);
	return (flags == MIGRATION_FFLAG_CHUNK &&
	    (type == MIGRATION_MSG_MEM_GEN || type == MIGRATION_MSG_DEV_STATE));
}

/*
 * Memory-generation records are a canonical, page-ordered representation of
 * backed guest RAM.  Keep this validation in the wire/core portion of the
 * file so malformed streams can be tested without a VM or root privileges.
 */
int
migration_memory_record_validate(uint64_t gpa, uint32_t length,
    uint64_t lowmem, uint64_t highmem_base, uint64_t highmem,
    uint64_t previous_end)
{
	uint64_t end, highmem_end;
	bool backed;

	if (length != MIGRATION_DIRTY_GRANULARITY ||
	    (gpa & (MIGRATION_DIRTY_GRANULARITY - 1)) != 0 ||
	    gpa < previous_end || gpa > UINT64_MAX - length)
		return (EBADMSG);
	end = gpa + length;
	backed = gpa < lowmem && end <= lowmem;
	if (highmem != 0 && highmem_base <= UINT64_MAX - highmem) {
		highmem_end = highmem_base + highmem;
		backed = backed || (gpa >= highmem_base && end <= highmem_end);
	}
	return (backed ? 0 : EBADMSG);
}

/* ------------------------------------------------------------------------- */
/* Frame codec								     */
/* ------------------------------------------------------------------------- */

int
migration_frame_encode(uint16_t version, uint16_t type, uint32_t seq,
    uint32_t flags, const void *payload, size_t payload_len, uint8_t *out,
    size_t out_cap, size_t *written)
{

	if (out == NULL || written == NULL ||
	    (payload == NULL && payload_len != 0))
		return (EINVAL);
	if (version < MIGRATION_PROTO_VERSION_MIN ||
	    version > MIGRATION_PROTO_VERSION || !migration_message_type_valid(type) ||
	    !migration_frame_flags_valid(type, flags))
		return (EINVAL);
	if (payload_len > MIGRATION_MAX_PAYLOAD)
		return (EMSGSIZE);
	if (out_cap < (size_t)MIGRATION_FRAME_HDR_SIZE + payload_len)
		return (EMSGSIZE);
	le32enc(out + 0, MIGRATION_PROTO_MAGIC);
	le16enc(out + 4, version);
	le16enc(out + 6, type);
	le32enc(out + 8, flags);
	le32enc(out + 12, seq);
	le32enc(out + 16, (uint32_t)payload_len);
	le32enc(out + 20, migration_crc32(payload, payload_len));
	if (payload_len != 0)
		memcpy(out + MIGRATION_FRAME_HDR_SIZE, payload, payload_len);
	*written = (size_t)MIGRATION_FRAME_HDR_SIZE + payload_len;
	return (0);
}

int
migration_frame_decode_header(const uint8_t *buf, size_t len,
    struct migration_frame_header *hdr)
{

	if (buf == NULL || hdr == NULL || len < MIGRATION_FRAME_HDR_SIZE)
		return (EINVAL);
	hdr->magic = le32dec(buf + 0);
	hdr->version = le16dec(buf + 4);
	hdr->type = le16dec(buf + 6);
	hdr->flags = le32dec(buf + 8);
	hdr->seq = le32dec(buf + 12);
	hdr->length = le32dec(buf + 16);
	hdr->crc32 = le32dec(buf + 20);
	if (hdr->magic != MIGRATION_PROTO_MAGIC)
		return (EINVAL);
	if (hdr->version < MIGRATION_PROTO_VERSION_MIN ||
	    hdr->version > MIGRATION_PROTO_VERSION ||
	    !migration_message_type_valid(hdr->type) ||
	    !migration_frame_flags_valid(hdr->type, hdr->flags))
		return (EPROTO);
	if (hdr->length > MIGRATION_MAX_PAYLOAD)
		return (EMSGSIZE);
	return (0);
}

int
migration_frame_verify_payload(const struct migration_frame_header *hdr,
    const void *payload, size_t payload_len)
{

	if (hdr == NULL || (payload == NULL && payload_len != 0))
		return (EINVAL);
	if (payload_len != hdr->length)
		return (EBADMSG);
	if (migration_crc32(payload, payload_len) != hdr->crc32)
		return (EBADMSG);
	return (0);
}

/* ------------------------------------------------------------------------- */
/* Typed message codecs							     */
/* ------------------------------------------------------------------------- */

int
migration_hello_encode(const struct migration_hello *hello, uint8_t *out,
    size_t cap)
{

	if (hello == NULL || out == NULL || cap < MIGRATION_HELLO_SIZE)
		return (EINVAL);
	if (hello->role != MIGRATION_ROLE_SOURCE &&
	    hello->role != MIGRATION_ROLE_DEST)
		return (EINVAL);
	if (!migration_string_canonical(hello->machine_abi,
	    sizeof(hello->machine_abi)))
		return (EINVAL);
	memset(out, 0, MIGRATION_HELLO_SIZE);
	le16enc(out + 0, hello->version_max);
	le16enc(out + 2, hello->version_min);
	out[4] = hello->role;
	le32enc(out + 8, hello->arch_id);
	le32enc(out + 12, hello->page_size);
	le32enc(out + 16, hello->cpu_family);
	le32enc(out + 20, hello->cpu_model);
	le32enc(out + 24, hello->cpu_stepping);
	le64enc(out + 32, hello->cpu_feature_hash);
	le32enc(out + 40, hello->intr_controller);
	le64enc(out + 48, hello->capability_flags);
	memcpy(out + 56, hello->machine_abi, sizeof(hello->machine_abi));
	return (0);
}

int
migration_hello_decode(const uint8_t *buf, size_t len,
    struct migration_hello *hello)
{
	struct migration_hello candidate;

	if (buf == NULL || hello == NULL || len != MIGRATION_HELLO_SIZE)
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.version_max = le16dec(buf + 0);
	candidate.version_min = le16dec(buf + 2);
	candidate.role = buf[4];
	candidate.arch_id = le32dec(buf + 8);
	candidate.page_size = le32dec(buf + 12);
	candidate.cpu_family = le32dec(buf + 16);
	candidate.cpu_model = le32dec(buf + 20);
	candidate.cpu_stepping = le32dec(buf + 24);
	candidate.cpu_feature_hash = le64dec(buf + 32);
	candidate.intr_controller = le32dec(buf + 40);
	candidate.capability_flags = le64dec(buf + 48);
	memcpy(candidate.machine_abi, buf + 56, sizeof(candidate.machine_abi));
	if (candidate.role != MIGRATION_ROLE_SOURCE &&
	    candidate.role != MIGRATION_ROLE_DEST)
		return (EBADMSG);
	if (!migration_string_canonical(candidate.machine_abi,
	    sizeof(candidate.machine_abi)))
		return (EBADMSG);
	*hello = candidate;
	return (0);
}

int
migration_caps_accept_encode(const struct migration_caps_accept *caps,
    uint8_t *out, size_t cap)
{

	if (caps == NULL || out == NULL || cap < MIGRATION_CAPS_ACCEPT_SIZE)
		return (EINVAL);
	memset(out, 0, MIGRATION_CAPS_ACCEPT_SIZE);
	le16enc(out + 0, caps->negotiated_version);
	le64enc(out + 4, caps->capability_flags);
	return (0);
}

int
migration_caps_accept_decode(const uint8_t *buf, size_t len,
    struct migration_caps_accept *caps)
{

	if (buf == NULL || caps == NULL || len != MIGRATION_CAPS_ACCEPT_SIZE)
		return (EINVAL);
	memset(caps, 0, sizeof(*caps));
	caps->negotiated_version = le16dec(buf + 0);
	caps->capability_flags = le64dec(buf + 4);
	return (0);
}

int
migration_reason_encode(const struct migration_reason_msg *reason,
    uint8_t *out, size_t cap)
{

	if (reason == NULL || out == NULL || cap < MIGRATION_REASON_SIZE)
		return (EINVAL);
	le32enc(out + 0, reason->reason_code);
	le32enc(out + 4, reason->detail);
	return (0);
}

int
migration_reason_decode(const uint8_t *buf, size_t len,
    struct migration_reason_msg *reason)
{

	if (buf == NULL || reason == NULL || len != MIGRATION_REASON_SIZE)
		return (EINVAL);
	reason->reason_code = le32dec(buf + 0);
	reason->detail = le32dec(buf + 4);
	return (0);
}

size_t
migration_topology_wire_size(const struct migration_topology *topology)
{

	if (topology == NULL || topology->device_count > MIGRATION_MAX_DEVICES)
		return (0);
	return ((size_t)MIGRATION_TOPOLOGY_HDR_SIZE +
	    (size_t)topology->device_count * MIGRATION_DEVREC_SIZE);
}

int
migration_topology_encode(const struct migration_topology *topology,
    uint8_t *out, size_t cap, size_t *written)
{
	size_t size;
	uint8_t *record;

	if (topology == NULL || out == NULL || written == NULL ||
	    topology->device_count > MIGRATION_MAX_DEVICES)
		return (EINVAL);
	size = migration_topology_wire_size(topology);
	if (cap < size)
		return (EMSGSIZE);
	for (uint32_t i = 0; i < topology->device_count; i++) {
		if (!migration_string_canonical(topology->devices[i].name,
		    sizeof(topology->devices[i].name)))
			return (EINVAL);
	}
	memset(out, 0, size);
	le64enc(out + 0, topology->mem_size);
	le64enc(out + 8, topology->lowmem);
	le64enc(out + 16, topology->highmem);
	le32enc(out + 24, topology->ncpus);
	le16enc(out + 28, topology->sockets);
	le16enc(out + 30, topology->cores);
	le16enc(out + 32, topology->threads);
	le32enc(out + 36, topology->device_count);
	record = out + MIGRATION_TOPOLOGY_HDR_SIZE;
	for (uint32_t i = 0; i < topology->device_count; i++) {
		const struct migration_device_record *dev;

		dev = &topology->devices[i];
		memcpy(record + 0, dev->name, sizeof(dev->name));
		le32enc(record + 40, dev->migration_flags);
		le32enc(record + 44, dev->compat_schema);
		le32enc(record + 48, dev->compat_crc32);
		le32enc(record + 52, dev->bar_hash);
		record += MIGRATION_DEVREC_SIZE;
	}
	*written = size;
	return (0);
}

int
migration_topology_decode(const uint8_t *buf, size_t len,
    struct migration_topology *topology)
{
	struct migration_topology *candidate;
	const uint8_t *record;
	uint32_t device_count;
	size_t size;
	int error;

	if (buf == NULL || topology == NULL || len < MIGRATION_TOPOLOGY_HDR_SIZE)
		return (EINVAL);
	device_count = le32dec(buf + 36);
	if (device_count > MIGRATION_MAX_DEVICES)
		return (EBADMSG);
	size = (size_t)MIGRATION_TOPOLOGY_HDR_SIZE +
	    (size_t)device_count * MIGRATION_DEVREC_SIZE;
	if (len != size)
		return (EBADMSG);
	candidate = calloc(1, sizeof(*candidate));
	if (candidate == NULL)
		return (ENOMEM);
	candidate->mem_size = le64dec(buf + 0);
	candidate->lowmem = le64dec(buf + 8);
	candidate->highmem = le64dec(buf + 16);
	candidate->ncpus = le32dec(buf + 24);
	candidate->sockets = le16dec(buf + 28);
	candidate->cores = le16dec(buf + 30);
	candidate->threads = le16dec(buf + 32);
	candidate->device_count = device_count;
	record = buf + MIGRATION_TOPOLOGY_HDR_SIZE;
	error = 0;
	for (uint32_t i = 0; i < device_count; i++) {
		struct migration_device_record *dev;

		dev = &candidate->devices[i];
		memcpy(dev->name, record + 0, sizeof(dev->name));
		dev->migration_flags = le32dec(record + 40);
		dev->compat_schema = le32dec(record + 44);
		dev->compat_crc32 = le32dec(record + 48);
		dev->bar_hash = le32dec(record + 52);
		if (!migration_string_canonical(dev->name, sizeof(dev->name))) {
			error = EBADMSG;
			break;
		}
		record += MIGRATION_DEVREC_SIZE;
	}
	if (error == 0)
		*topology = *candidate;
	free(candidate);
	return (error);
}

int
migration_memgen_encode(const struct migration_memgen *gen, uint8_t *out,
    size_t cap)
{

	if (gen == NULL || out == NULL || cap < MIGRATION_MEMGEN_HDR_SIZE)
		return (EINVAL);
	le32enc(out + 0, gen->round);
	le32enc(out + 4, gen->mode);
	le64enc(out + 8, gen->gpa);
	le64enc(out + 16, gen->length);
	le64enc(out + 24, gen->cpu_identity);
	le64enc(out + 32, gen->cpu_map_generation);
	le64enc(out + 40, gen->cpu_dirty_generation);
	le64enc(out + 48, gen->device_identity);
	le64enc(out + 56, gen->device_dirty_generation);
	le32enc(out + 64, gen->page_count);
	le32enc(out + 68, gen->final);
	return (0);
}

int
migration_memgen_decode(const uint8_t *buf, size_t len,
    struct migration_memgen *gen)
{

	if (buf == NULL || gen == NULL || len < MIGRATION_MEMGEN_HDR_SIZE)
		return (EINVAL);
	gen->round = le32dec(buf + 0);
	gen->mode = le32dec(buf + 4);
	gen->gpa = le64dec(buf + 8);
	gen->length = le64dec(buf + 16);
	gen->cpu_identity = le64dec(buf + 24);
	gen->cpu_map_generation = le64dec(buf + 32);
	gen->cpu_dirty_generation = le64dec(buf + 40);
	gen->device_identity = le64dec(buf + 48);
	gen->device_dirty_generation = le64dec(buf + 56);
	gen->page_count = le32dec(buf + 64);
	gen->final = le32dec(buf + 68);
	return (0);
}

int
migration_chunk_encode(const struct migration_chunk *chunk, uint8_t *out,
    size_t cap)
{

	if (chunk == NULL || out == NULL || cap < MIGRATION_CHUNK_HDR_SIZE)
		return (EINVAL);
	le64enc(out + 0, chunk->total_length);
	le64enc(out + 8, chunk->offset);
	le32enc(out + 16, chunk->chunk_length);
	le32enc(out + 20, chunk->final);
	return (0);
}

int
migration_chunk_decode(const uint8_t *buf, size_t len,
    struct migration_chunk *chunk)
{

	if (buf == NULL || chunk == NULL || len != MIGRATION_CHUNK_HDR_SIZE)
		return (EINVAL);
	chunk->total_length = le64dec(buf + 0);
	chunk->offset = le64dec(buf + 8);
	chunk->chunk_length = le32dec(buf + 16);
	chunk->final = le32dec(buf + 20);
	return (0);
}

int
migration_chunk_validate(uint64_t expect_offset, uint64_t total_or_zero,
    const struct migration_chunk *chunk, size_t chunk_max, size_t reasm_cap)
{

	if (chunk == NULL)
		return (EINVAL);
	/* Oversize single chunk, or a total larger than we will ever buffer. */
	if (chunk->chunk_length > chunk_max)
		return (EMSGSIZE);
	if (chunk->total_length > reasm_cap)
		return (EMSGSIZE);
	/* Strict in-order contiguity: no gaps, no duplicates, no reordering. */
	if (chunk->offset != expect_offset)
		return (EBADMSG);
	if (chunk->total_length != 0) {
		/* A latched total must not change mid-stream. */
		if (total_or_zero != 0 && chunk->total_length != total_or_zero)
			return (EBADMSG);
		/* Chunk must lie within the declared total (overflow-safe). */
		if (chunk->offset > chunk->total_length ||
		    (uint64_t)chunk->chunk_length >
		    chunk->total_length - chunk->offset)
			return (EBADMSG);
		/* final must be set exactly when the total is reached. */
		if ((chunk->offset + chunk->chunk_length ==
		    chunk->total_length) != (chunk->final != 0))
			return (EBADMSG);
	} else {
		/* Streaming producer: termination is carried by final only. */
		if (chunk->final != 0 && chunk->chunk_length == 0 &&
		    chunk->offset == 0)
			return (0);
	}
	return (0);
}

/* ------------------------------------------------------------------------- */
/* Negotiation and validation						     */
/* ------------------------------------------------------------------------- */

int
migration_negotiate_version(uint16_t local_max, uint16_t local_min,
    uint16_t remote_max, uint16_t remote_min, uint16_t *negotiated)
{
	uint16_t high, low;

	if (negotiated == NULL || local_min > local_max || remote_min > remote_max)
		return (EINVAL);
	high = local_max < remote_max ? local_max : remote_max;
	low = local_min > remote_min ? local_min : remote_min;
	if (high < low)
		return (EPROTONOSUPPORT);
	*negotiated = high;
	return (0);
}

bool
migration_device_flags_eligible(uint32_t flags)
{

	if ((flags & ~MIGRATION_DEVF_ALL) != 0)
		return (false);
	if ((flags & MIGRATION_DEVF_STATE_CODEC) == 0)
		return (false);
	if (!!(flags & MIGRATION_DEVF_COMPAT_FIXED) +
	    !!(flags & MIGRATION_DEVF_COMPAT_CALLBACK) != 1)
		return (false);
	if (!!(flags & MIGRATION_DEVF_DMA_NONE) +
	    !!(flags & MIGRATION_DEVF_DMA_TRACKED) != 1)
		return (false);
	if (!!(flags & MIGRATION_DEVF_QUIESCE_NONE) +
	    !!(flags & MIGRATION_DEVF_QUIESCE_CALLBACK) != 1)
		return (false);
	return (true);
}

static void
migration_set_reason(uint32_t *reason, uint32_t value)
{

	if (reason != NULL)
		*reason = value;
}

int
migration_hello_validate(const struct migration_hello *local,
    const struct migration_hello *remote, uint16_t *negotiated,
    uint32_t *reason)
{
	uint16_t chosen;
	int error;

	migration_set_reason(reason, MIGRATION_REASON_NONE);
	if (local == NULL || remote == NULL || negotiated == NULL)
		return (EINVAL);
	error = migration_negotiate_version(local->version_max,
	    local->version_min, remote->version_max, remote->version_min,
	    &chosen);
	if (error != 0) {
		migration_set_reason(reason, MIGRATION_REASON_VERSION);
		return (error);
	}
	if (remote->arch_id != local->arch_id) {
		migration_set_reason(reason, MIGRATION_REASON_ARCH);
		return (EINVAL);
	}
	if (remote->page_size != local->page_size) {
		migration_set_reason(reason, MIGRATION_REASON_PAGESIZE);
		return (EINVAL);
	}
	if (memcmp(remote->machine_abi, local->machine_abi,
	    sizeof(local->machine_abi)) != 0) {
		migration_set_reason(reason, MIGRATION_REASON_MACHINE_ABI);
		return (EINVAL);
	}
	if (remote->intr_controller != local->intr_controller) {
		migration_set_reason(reason, MIGRATION_REASON_INTR);
		return (EINVAL);
	}
	/*
	 * CPU architectural state is not assumed portable: the destination
	 * must present the same CPU family/model and the same capability
	 * signature as the source, or the restored guest could execute against
	 * a silently different ISA surface.
	 */
	if (remote->cpu_family != local->cpu_family ||
	    remote->cpu_model != local->cpu_model ||
	    remote->cpu_feature_hash != local->cpu_feature_hash) {
		migration_set_reason(reason, MIGRATION_REASON_CPU);
		return (EINVAL);
	}
	/* The migration itself requires pre-copy support on both ends. */
	if (((remote->capability_flags & local->capability_flags) &
	    MIGRATION_CAP_PRECOPY) == 0) {
		migration_set_reason(reason, MIGRATION_REASON_CAPS);
		return (EINVAL);
	}
	*negotiated = chosen;
	return (0);
}

int
migration_topology_validate(const struct migration_topology *local,
    const struct migration_topology *remote, uint32_t *reason)
{

	migration_set_reason(reason, MIGRATION_REASON_NONE);
	if (local == NULL || remote == NULL)
		return (EINVAL);
	if (remote->device_count > MIGRATION_MAX_DEVICES) {
		migration_set_reason(reason, MIGRATION_REASON_TOPOLOGY);
		return (EINVAL);
	}
	/* Guest-visible memory geometry must be identical on both hosts. */
	if (remote->mem_size != local->mem_size ||
	    remote->lowmem != local->lowmem ||
	    remote->highmem != local->highmem) {
		migration_set_reason(reason, MIGRATION_REASON_MEMSIZE);
		return (EINVAL);
	}
	if (remote->ncpus != local->ncpus ||
	    remote->sockets != local->sockets ||
	    remote->cores != local->cores ||
	    remote->threads != local->threads) {
		migration_set_reason(reason, MIGRATION_REASON_CPUCOUNT);
		return (EINVAL);
	}
	/*
	 * Every source device must advertise a real external-state contract
	 * (step 10).  A device whose migration flags do not encode exactly one
	 * compatibility/DMA/quiesce policy plus the portable state codec is
	 * refused here, before the source quiesces.
	 */
	for (uint32_t i = 0; i < remote->device_count; i++) {
		if (!migration_device_flags_eligible(
		    remote->devices[i].migration_flags)) {
			migration_set_reason(reason, MIGRATION_REASON_DEVICE);
			return (EOPNOTSUPP);
		}
	}
	/*
	 * The destination must host the same set of devices with matching
	 * identity (name, compat schema, compat envelope crc, and BAR-layout
	 * hash).  Order is significant so restore consumes records in the same
	 * order they were produced.
	 */
	if (remote->device_count != local->device_count) {
		migration_set_reason(reason, MIGRATION_REASON_DEVICE);
		return (EINVAL);
	}
	for (uint32_t i = 0; i < remote->device_count; i++) {
		const struct migration_device_record *r, *l;

		r = &remote->devices[i];
		l = &local->devices[i];
		if (memcmp(r->name, l->name, sizeof(r->name)) != 0 ||
		    r->migration_flags != l->migration_flags ||
		    r->compat_schema != l->compat_schema ||
		    r->compat_crc32 != l->compat_crc32 ||
		    r->bar_hash != l->bar_hash) {
			migration_set_reason(reason, MIGRATION_REASON_DEVICE);
			return (EINVAL);
		}
	}
	return (0);
}

/* ------------------------------------------------------------------------- */
/* File-descriptor transport (the thin, separately identified stream layer)  */
/* ------------------------------------------------------------------------- */

#include <poll.h>
#include <unistd.h>

static int
migration_fd_wait(int fd, int timeout_ms)
{
	struct pollfd pfd;
	int rc;

	if (timeout_ms <= 0)
		return (0);
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN;
	rc = poll(&pfd, 1, timeout_ms);
	if (rc < 0)
		return (errno != 0 ? errno : EIO);
	if (rc == 0)
		return (ETIMEDOUT);
	return (0);
}

static int
migration_fd_send(void *cookie, const void *buf, size_t len)
{
	struct migration_transport_fd *fdx;
	const uint8_t *cursor;

	fdx = cookie;
	cursor = buf;
	while (len != 0) {
		ssize_t n;

		n = write(fdx->fd, cursor, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return (errno != 0 ? errno : EIO);
		}
		if (n == 0)
			return (EPIPE);
		cursor += (size_t)n;
		len -= (size_t)n;
	}
	return (0);
}

static int
migration_fd_recv(void *cookie, void *buf, size_t len)
{
	struct migration_transport_fd *fdx;
	uint8_t *cursor;

	fdx = cookie;
	cursor = buf;
	while (len != 0) {
		ssize_t n;
		int error;

		error = migration_fd_wait(fdx->fd, fdx->recv_timeout_ms);
		if (error != 0)
			return (error);
		n = read(fdx->fd, cursor, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return (errno != 0 ? errno : EIO);
		}
		if (n == 0)
			return (ECONNRESET);
		cursor += (size_t)n;
		len -= (size_t)n;
	}
	return (0);
}

void
migration_transport_fd_init(struct migration_transport *xp,
    struct migration_transport_fd *fdx, int fd, int recv_timeout_ms)
{

	fdx->fd = fd;
	fdx->recv_timeout_ms = recv_timeout_ms;
	xp->xp_send = migration_fd_send;
	xp->xp_recv = migration_fd_recv;
	xp->xp_cookie = fdx;
}

/* ------------------------------------------------------------------------- */
/* Session framing helpers						     */
/* ------------------------------------------------------------------------- */

struct migration_session {
	const struct migration_transport *xp;
	const struct migration_session_config *config;
	uint16_t version;		/* negotiated (0 until handshake) */
	uint32_t send_seq;
	uint32_t recv_seq;
};

static void
migration_progress_report(const struct migration_session *sess, uint32_t phase,
    uint32_t round, uint64_t bytes, uint64_t dirty_pages, bool converged)
{
	struct migration_stat stat;
	const struct migration_progress *progress;

	if (sess->config == NULL || sess->config->progress == NULL)
		return;
	progress = sess->config->progress;
	if (progress->mp_update == NULL)
		return;
	memset(&stat, 0, sizeof(stat));
	stat.phase = phase;
	stat.round = round;
	stat.bytes_sent = bytes;
	stat.last_dirty_pages = dirty_pages;
	stat.converged = converged;
	progress->mp_update(progress->mp_cookie, &stat);
}

/*
 * Frame and send one message.  version is the negotiated protocol version once
 * the handshake completes, or MIGRATION_PROTO_VERSION for the opening HELLO.
 */
static int
migration_send(struct migration_session *sess, uint16_t type, uint32_t flags,
    const void *payload, size_t payload_len)
{
	uint8_t *frame;
	size_t frame_len, written;
	uint16_t version;
	int error;

	if (payload_len > MIGRATION_MAX_PAYLOAD)
		return (EMSGSIZE);
	version = sess->version != 0 ? sess->version : MIGRATION_PROTO_VERSION;
	frame_len = (size_t)MIGRATION_FRAME_HDR_SIZE + payload_len;
	frame = malloc(frame_len);
	if (frame == NULL)
		return (ENOMEM);
	error = migration_frame_encode(version, type, sess->send_seq + 1, flags,
	    payload, payload_len, frame, frame_len, &written);
	if (error == 0) {
		error = sess->xp->xp_send(sess->xp->xp_cookie, frame, written);
		if (error == 0)
			sess->send_seq++;
	}
	free(frame);
	return (error);
}

static int
migration_send_reason(struct migration_session *sess, uint16_t type,
    uint32_t reason, uint32_t detail)
{
	struct migration_reason_msg msg;
	uint8_t payload[MIGRATION_REASON_SIZE];
	int error;

	memset(&msg, 0, sizeof(msg));
	msg.reason_code = reason;
	msg.detail = detail;
	error = migration_reason_encode(&msg, payload, sizeof(payload));
	if (error != 0)
		return (error);
	return (migration_send(sess, type, 0, payload, sizeof(payload)));
}

/*
 * Receive one framed message.  On success returns 0 with the decoded header,
 * an allocated payload buffer (caller frees), and its length.  Enforces strict
 * per-peer sequence monotonicity so a replayed or reordered generation is
 * rejected rather than applied out of order.
 */
static int
migration_recv(struct migration_session *sess,
    struct migration_frame_header *hdr, uint8_t **payload, size_t *payload_len)
{
	uint8_t header[MIGRATION_FRAME_HDR_SIZE];
	uint8_t *buf;
	int error;

	*payload = NULL;
	*payload_len = 0;
	error = sess->xp->xp_recv(sess->xp->xp_cookie, header, sizeof(header));
	if (error != 0)
		return (error);
	error = migration_frame_decode_header(header, sizeof(header), hdr);
	if (error != 0)
		return (error);
	if (hdr->seq != sess->recv_seq + 1)
		return (EBADMSG);
	if (sess->version != 0 && hdr->version != sess->version)
		return (EPROTO);
	buf = NULL;
	if (hdr->length != 0) {
		buf = malloc(hdr->length);
		if (buf == NULL)
			return (ENOMEM);
		error = sess->xp->xp_recv(sess->xp->xp_cookie, buf,
		    hdr->length);
		if (error != 0) {
			free(buf);
			return (error);
		}
	}
	error = migration_frame_verify_payload(hdr, buf, hdr->length);
	if (error != 0) {
		free(buf);
		return (error);
	}
	sess->recv_seq++;
	*payload = buf;
	*payload_len = hdr->length;
	return (0);
}

static bool
migration_cancelled(const struct migration_session *sess)
{

	return (sess->config != NULL && sess->config->cancel != NULL &&
	    *sess->config->cancel != 0);
}

/*
 * Send one whole memory generation, transparently split across as many frames
 * as its page records require.  A generation that fits in a single frame is
 * emitted in the legacy [memgen][page records] layout with flags == 0; a larger
 * generation is emitted as ordered [memgen][chunk hdr][page records] chunks,
 * each acknowledged with MEM_ACK.  scratch must hold MIGRATION_MAX_PAYLOAD
 * bytes.  On the final chunk *converged_out carries the source op's convergence
 * verdict and *dirty_pages_out the generation's total page count.
 */
static int
migration_source_send_generation(struct migration_session *sess,
    const struct migration_source_ops *ops, void *arg, bool final,
    uint32_t round, uint32_t final_flag, uint8_t *scratch, uint64_t *bytes_sent,
    uint64_t *dirty_pages_out, bool *converged_out, uint32_t *reason)
{
	const size_t datacap = MIGRATION_MAX_PAYLOAD -
	    MIGRATION_MEMGEN_HDR_SIZE - MIGRATION_CHUNK_HDR_SIZE;
	struct migration_frame_header hdr;
	struct migration_reason_msg reason_msg;
	uint8_t *payload;
	size_t payload_len;
	uint64_t offset, total_dirty;
	bool more, converged;
	int error;

	offset = 0;
	total_dirty = 0;
	converged = false;
	for (;;) {
		struct migration_memgen gen;
		uint64_t dirty_pages;
		size_t page_bytes, frame_len;

		memset(&gen, 0, sizeof(gen));
		dirty_pages = 0;
		page_bytes = 0;
		more = false;
		converged = false;
		error = ops->so_precopy_round(arg, final, &gen,
		    scratch + MIGRATION_MEMGEN_HDR_SIZE, datacap, &page_bytes,
		    &dirty_pages, &converged, &more);
		if (error != 0)
			return (error);
		gen.round = round;
		gen.final = final_flag;
		total_dirty += dirty_pages;
		if (offset == 0 && !more) {
			/* One frame: unchunked, byte-identical to legacy. */
			error = migration_memgen_encode(&gen, scratch,
			    MIGRATION_MEMGEN_HDR_SIZE);
			if (error != 0)
				return (error);
			frame_len = MIGRATION_MEMGEN_HDR_SIZE + page_bytes;
			error = migration_send(sess, MIGRATION_MSG_MEM_GEN, 0,
			    scratch, frame_len);
		} else {
			struct migration_chunk chunk;

			/* [memgen][chunk hdr][page records]; records are shifted
			 * up by the chunk header the op did not reserve for. */
			memmove(scratch + MIGRATION_MEMGEN_HDR_SIZE +
			    MIGRATION_CHUNK_HDR_SIZE,
			    scratch + MIGRATION_MEMGEN_HDR_SIZE, page_bytes);
			error = migration_memgen_encode(&gen, scratch,
			    MIGRATION_MEMGEN_HDR_SIZE);
			if (error != 0)
				return (error);
			memset(&chunk, 0, sizeof(chunk));
			chunk.total_length = 0;		/* streaming */
			chunk.offset = offset;
			chunk.chunk_length = (uint32_t)page_bytes;
			chunk.final = more ? 0 : 1;
			error = migration_chunk_encode(&chunk,
			    scratch + MIGRATION_MEMGEN_HDR_SIZE,
			    MIGRATION_CHUNK_HDR_SIZE);
			if (error != 0)
				return (error);
			frame_len = MIGRATION_MEMGEN_HDR_SIZE +
			    MIGRATION_CHUNK_HDR_SIZE + page_bytes;
			error = migration_send(sess, MIGRATION_MSG_MEM_GEN,
			    MIGRATION_FFLAG_CHUNK, scratch, frame_len);
		}
		if (error != 0)
			return (error);
		*bytes_sent += frame_len;
		offset += page_bytes;
		error = migration_recv(sess, &hdr, &payload, &payload_len);
		if (error != 0)
			return (error);
		if (hdr.type == MIGRATION_MSG_ABORT) {
			if (migration_reason_decode(payload, payload_len,
			    &reason_msg) == 0 && reason != NULL)
				*reason = reason_msg.reason_code;
			free(payload);
			return (ECONNRESET);
		}
		if (hdr.type != MIGRATION_MSG_MEM_ACK) {
			free(payload);
			if (reason != NULL)
				*reason = MIGRATION_REASON_PROTOCOL;
			return (EPROTO);
		}
		free(payload);
		if (!more)
			break;
	}
	*dirty_pages_out = total_dirty;
	*converged_out = converged;
	return (0);
}

/*
 * Serialize the source device/CPU/kernel-state blob and stream it as one or
 * more DEV_STATE frames.  A blob within one frame is sent unchunked (legacy
 * format); a larger blob is split into ordered, total/offset-tagged chunks that
 * the destination reassembles before restore.  DEV_STATE frames are not
 * individually acknowledged; the FINAL fence that follows orders them.
 */
static int
migration_source_send_dev_state(struct migration_session *sess,
    const struct migration_source_ops *ops, void *arg, uint64_t *bytes_sent)
{
	const size_t chunkmax = MIGRATION_MAX_PAYLOAD - MIGRATION_CHUNK_HDR_SIZE;
	uint8_t *blob, *frame;
	size_t len, offset;
	int error;

	blob = NULL;
	len = 0;
	error = ops->so_dev_state(arg, &blob, &len);
	if (error != 0)
		return (error);
	if (blob == NULL && len != 0)
		return (EINVAL);
	if (len > MIGRATION_MAX_DEV_STATE) {
		free(blob);
		return (EMSGSIZE);
	}
	if (len <= MIGRATION_MAX_PAYLOAD) {
		error = migration_send(sess, MIGRATION_MSG_DEV_STATE, 0, blob,
		    len);
		if (error == 0)
			*bytes_sent += len;
		free(blob);
		return (error);
	}
	frame = malloc(MIGRATION_MAX_PAYLOAD);
	if (frame == NULL) {
		free(blob);
		return (ENOMEM);
	}
	offset = 0;
	error = 0;
	while (offset < len) {
		struct migration_chunk chunk;
		size_t this;

		this = len - offset;
		if (this > chunkmax)
			this = chunkmax;
		memset(&chunk, 0, sizeof(chunk));
		chunk.total_length = len;
		chunk.offset = offset;
		chunk.chunk_length = (uint32_t)this;
		chunk.final = (offset + this == len) ? 1 : 0;
		error = migration_chunk_encode(&chunk, frame,
		    MIGRATION_CHUNK_HDR_SIZE);
		if (error != 0)
			break;
		memcpy(frame + MIGRATION_CHUNK_HDR_SIZE, blob + offset, this);
		error = migration_send(sess, MIGRATION_MSG_DEV_STATE,
		    MIGRATION_FFLAG_CHUNK, frame,
		    MIGRATION_CHUNK_HDR_SIZE + this);
		if (error != 0)
			break;
		*bytes_sent += MIGRATION_CHUNK_HDR_SIZE + this;
		offset += this;
	}
	free(frame);
	free(blob);
	return (error);
}

/* ------------------------------------------------------------------------- */
/* Source state machine							     */
/* ------------------------------------------------------------------------- */

int
migration_source_run(const struct migration_transport *xp,
    const struct migration_source_ops *ops, void *arg,
    const struct migration_session_config *config,
    struct migration_source_result *result)
{
	struct migration_session sess;
	struct migration_source_result out;
	struct migration_frame_header hdr;
	struct migration_hello hello;
	struct migration_topology *topology;
	struct migration_caps_accept caps;
	struct migration_reason_msg reason_msg;
	uint8_t *payload, *frame_payload;
	uint8_t hello_wire[MIGRATION_HELLO_SIZE];
	uint8_t *topo_wire;
	size_t payload_len, topo_len, wrote;
	uint32_t max_rounds, round;
	bool quiesced, precopy_enabled, cutover_ready;
	int error;

	if (xp == NULL || xp->xp_send == NULL || xp->xp_recv == NULL ||
	    ops == NULL || config == NULL || result == NULL)
		return (EINVAL);

	memset(&out, 0, sizeof(out));
	out.phase = MIGRATION_PHASE_INIT;
	out.source_runnable = true;
	out.reason = MIGRATION_REASON_NONE;

	memset(&sess, 0, sizeof(sess));
	sess.xp = xp;
	sess.config = config;
	max_rounds = config->max_rounds != 0 ? config->max_rounds : 8;

	payload = NULL;
	topology = NULL;
	frame_payload = NULL;
	quiesced = false;
	precopy_enabled = false;
	cutover_ready = false;

	/* ---- Handshake ---- */
	out.phase = MIGRATION_PHASE_HANDSHAKE;
	memset(&hello, 0, sizeof(hello));
	error = ops->so_local_hello(arg, &hello);
	if (error != 0)
		goto fail_runnable;
	hello.role = MIGRATION_ROLE_SOURCE;
	hello.version_max = config->version_max != 0 ? config->version_max :
	    MIGRATION_PROTO_VERSION;
	hello.version_min = config->version_min != 0 ? config->version_min :
	    MIGRATION_PROTO_VERSION_MIN;
	error = migration_hello_encode(&hello, hello_wire, sizeof(hello_wire));
	if (error != 0)
		goto fail_runnable;
	error = migration_send(&sess, MIGRATION_MSG_HELLO, 0, hello_wire,
	    sizeof(hello_wire));
	if (error != 0)
		goto fail_runnable;
	error = migration_recv(&sess, &hdr, &payload, &payload_len);
	if (error != 0)
		goto fail_runnable;
	if (hdr.type == MIGRATION_MSG_CAPS_REJECT) {
		if (migration_reason_decode(payload, payload_len,
		    &reason_msg) == 0)
			out.reason = reason_msg.reason_code;
		else
			out.reason = MIGRATION_REASON_PROTOCOL;
		error = ECONNREFUSED;
		goto fail_runnable;
	}
	if (hdr.type != MIGRATION_MSG_CAPS_ACCEPT) {
		out.reason = MIGRATION_REASON_PROTOCOL;
		error = EPROTO;
		goto fail_runnable;
	}
	error = migration_caps_accept_decode(payload, payload_len, &caps);
	if (error != 0) {
		out.reason = MIGRATION_REASON_PROTOCOL;
		goto fail_runnable;
	}
	free(payload);
	payload = NULL;
	/* The destination must have chosen a version inside our own window. */
	if (caps.negotiated_version > hello.version_max ||
	    caps.negotiated_version < hello.version_min) {
		out.reason = MIGRATION_REASON_VERSION;
		error = EPROTONOSUPPORT;
		goto fail_runnable;
	}
	sess.version = caps.negotiated_version;
	out.negotiated_version = caps.negotiated_version;

	/* ---- Topology exchange + pre-quiesce validation ---- */
	out.phase = MIGRATION_PHASE_VALIDATE;
	topology = calloc(1, sizeof(*topology));
	if (topology == NULL) {
		error = ENOMEM;
		goto fail_runnable;
	}
	error = ops->so_local_topology(arg, topology);
	if (error != 0)
		goto fail_runnable;
	topo_len = migration_topology_wire_size(topology);
	if (topo_len == 0) {
		error = EINVAL;
		goto fail_runnable;
	}
	topo_wire = malloc(topo_len);
	if (topo_wire == NULL) {
		error = ENOMEM;
		goto fail_runnable;
	}
	error = migration_topology_encode(topology, topo_wire, topo_len, &wrote);
	if (error != 0) {
		free(topo_wire);
		goto fail_runnable;
	}
	error = migration_send(&sess, MIGRATION_MSG_TOPOLOGY, 0, topo_wire,
	    wrote);
	free(topo_wire);
	if (error != 0)
		goto fail_runnable;
	error = migration_recv(&sess, &hdr, &payload, &payload_len);
	if (error != 0)
		goto fail_runnable;
	if (hdr.type == MIGRATION_MSG_TOPO_REJECT) {
		if (migration_reason_decode(payload, payload_len,
		    &reason_msg) == 0)
			out.reason = reason_msg.reason_code;
		else
			out.reason = MIGRATION_REASON_PROTOCOL;
		error = ECONNREFUSED;
		goto fail_runnable;
	}
	if (hdr.type != MIGRATION_MSG_TOPO_ACCEPT) {
		out.reason = MIGRATION_REASON_PROTOCOL;
		error = EPROTO;
		goto fail_runnable;
	}
	free(payload);
	payload = NULL;
	free(topology);
	topology = NULL;

	/* ---- Iterative pre-copy ---- */
	out.phase = MIGRATION_PHASE_PRECOPY;
	error = ops->so_precopy_enable(arg);
	if (error != 0)
		goto fail_runnable;
	precopy_enabled = true;

	frame_payload = malloc(MIGRATION_MAX_PAYLOAD);
	if (frame_payload == NULL) {
		error = ENOMEM;
		goto fail_runnable;
	}

	for (round = 1; round <= max_rounds; round++) {
		uint64_t dirty_pages;
		bool converged;

		if (migration_cancelled(&sess)) {
			out.reason = MIGRATION_REASON_CANCELLED;
			error = ECANCELED;
			goto fail_runnable;
		}
		dirty_pages = 0;
		converged = false;
		error = migration_source_send_generation(&sess, ops, arg, false,
		    round, 0, frame_payload, &out.bytes_sent, &dirty_pages,
		    &converged, &out.reason);
		if (error != 0)
			goto fail_runnable;
		out.rounds = round;
		migration_progress_report(&sess, MIGRATION_PHASE_PRECOPY, round,
		    out.bytes_sent, dirty_pages, converged);
		if (converged ||
		    (config->converge_pages != 0 &&
		    dirty_pages <= config->converge_pages)) {
			cutover_ready = true;
			break;
		}
	}
	/*
	 * If the working set never fell under the convergence ceiling within
	 * max_rounds, the operator policy decides: either abort and keep the
	 * source running (abort_if_unconverged), or proceed to the final,
	 * guest-quiesced stop-and-copy round, which is bounded because no new
	 * writes occur once quiesced.
	 */
	if (!cutover_ready && config->abort_if_unconverged) {
		out.reason = MIGRATION_REASON_CONVERGENCE;
		error = EBUSY;
		goto fail_runnable;
	}

	/* ---- Event-fenced stop-and-copy ---- */
	out.phase = MIGRATION_PHASE_STOPCOPY;
	if (migration_cancelled(&sess)) {
		out.reason = MIGRATION_REASON_CANCELLED;
		error = ECANCELED;
		goto fail_runnable;
	}
	error = ops->so_quiesce(arg);
	if (error != 0) {
		/* Contract: a failed quiesce leaves the source runnable. */
		out.reason = MIGRATION_REASON_STATE;
		goto fail_runnable;
	}
	quiesced = true;

	{
		uint64_t dirty_pages;
		bool converged;

		dirty_pages = 0;
		converged = true;
		error = migration_source_send_generation(&sess, ops, arg, true,
		    out.rounds + 1, 1, frame_payload, &out.bytes_sent,
		    &dirty_pages, &converged, &out.reason);
		if (error != 0)
			goto fail_rollback;
	}

	/* Device/backend/CPU/kernel state, then the final ordering fence. */
	error = migration_source_send_dev_state(&sess, ops, arg, &out.bytes_sent);
	if (error != 0)
		goto fail_rollback;
	error = migration_send_reason(&sess, MIGRATION_MSG_FINAL,
	    MIGRATION_REASON_NONE, 0);
	if (error != 0)
		goto fail_rollback;

	/* Pre-copy dirty logging is retired only after the cut. */
	(void)ops->so_precopy_disable(arg);
	precopy_enabled = false;

	/* ---- Commit / cutover ---- */
	out.phase = MIGRATION_PHASE_COMMIT;
	error = migration_recv(&sess, &hdr, &payload, &payload_len);
	if (error != 0)
		goto fail_rollback;
	if (hdr.type == MIGRATION_MSG_ABORT) {
		if (migration_reason_decode(payload, payload_len,
		    &reason_msg) == 0)
			out.reason = reason_msg.reason_code;
		error = ECONNRESET;
		goto fail_rollback;
	}
	if (hdr.type != MIGRATION_MSG_COMMIT) {
		out.reason = MIGRATION_REASON_PROTOCOL;
		error = EPROTO;
		goto fail_rollback;
	}
	free(payload);
	payload = NULL;

	/*
	 * The destination has committed all state but will not run the guest
	 * until it receives RELEASE.  Only after RELEASE is successfully sent do
	 * we relinquish the source: this keeps exactly one runnable copy.  If
	 * RELEASE cannot be sent, the destination never resumes and we roll the
	 * source back.
	 */
	error = migration_send_reason(&sess, MIGRATION_MSG_RELEASE,
	    MIGRATION_REASON_NONE, 0);
	if (error != 0)
		goto fail_rollback;

	ops->so_defunct(arg);
	out.source_runnable = false;
	out.phase = MIGRATION_PHASE_COMPLETED;
	migration_progress_report(&sess, MIGRATION_PHASE_COMPLETED, out.rounds,
	    out.bytes_sent, 0, true);
	free(frame_payload);
	*result = out;
	return (0);

fail_rollback:
	/*
	 * Failure after the source quiesced but before an acknowledged
	 * destination commit: resume the source so it remains the running copy.
	 */
	if (quiesced) {
		int resume_error;

		resume_error = ops->so_resume(arg);
		if (resume_error != 0) {
			/*
			 * Do not claim the source rolled back when its device fabric
			 * could not be resumed.  In particular, a production source
			 * must keep vCPUs stopped in this state.
			 */
			if (error == 0)
				error = resume_error;
			out.source_runnable = false;
			out.phase = MIGRATION_PHASE_FAILED;
			if (out.reason == MIGRATION_REASON_NONE)
				out.reason = MIGRATION_REASON_STATE;
		}
	}
	if (precopy_enabled)
		(void)ops->so_precopy_disable(arg);
	if (out.phase != MIGRATION_PHASE_FAILED) {
		out.source_runnable = true;
		out.phase = MIGRATION_PHASE_ROLLED_BACK;
	}
	if (out.reason == MIGRATION_REASON_NONE)
		out.reason = MIGRATION_REASON_TRANSPORT;
	(void)migration_send_reason(&sess, MIGRATION_MSG_ABORT, out.reason, 0);
	free(payload);
	free(frame_payload);
	free(topology);
	if (error == 0)
		error = EPROTO;
	*result = out;
	return (error);

fail_runnable:
	/*
	 * Failure before the source ever quiesced: nothing destructive has
	 * happened, so the source keeps running.
	 */
	if (precopy_enabled)
		(void)ops->so_precopy_disable(arg);
	out.source_runnable = true;
	out.phase = MIGRATION_PHASE_FAILED;
	if (out.reason == MIGRATION_REASON_NONE)
		out.reason = MIGRATION_REASON_TRANSPORT;
	(void)migration_send_reason(&sess, MIGRATION_MSG_ABORT, out.reason, 0);
	free(payload);
	free(frame_payload);
	free(topology);
	if (error == 0)
		error = EPROTO;
	*result = out;
	return (error);
}

/* ------------------------------------------------------------------------- */
/* Destination state machine						     */
/* ------------------------------------------------------------------------- */

int
migration_dest_run(const struct migration_transport *xp,
    const struct migration_dest_ops *ops, void *arg,
    const struct migration_session_config *config,
    struct migration_dest_result *result)
{
	struct migration_session sess;
	struct migration_dest_result out;
	struct migration_frame_header hdr;
	struct migration_hello local_hello, remote_hello;
	struct migration_topology *local_topo, *remote_topo;
	struct migration_caps_accept caps;
	struct migration_reason_msg reason_msg;
	uint8_t *payload;
	uint8_t caps_wire[MIGRATION_CAPS_ACCEPT_SIZE];
	uint8_t *dev_reasm;		/* chunked DEV_STATE reassembly buffer */
	size_t payload_len;
	uint64_t mem_offset;		/* next contiguous byte in a chunked gen */
	uint64_t dev_total, dev_offset;	/* chunked DEV_STATE reassembly cursor */
	uint16_t negotiated;
	uint32_t reason;
	bool committed, staged, dev_state_seen, dev_state_started;
	int error;

	if (xp == NULL || xp->xp_send == NULL || xp->xp_recv == NULL ||
	    ops == NULL || config == NULL || result == NULL)
		return (EINVAL);

	memset(&out, 0, sizeof(out));
	out.phase = MIGRATION_PHASE_INIT;
	out.reason = MIGRATION_REASON_NONE;

	memset(&sess, 0, sizeof(sess));
	sess.xp = xp;
	sess.config = config;

	payload = NULL;
	local_topo = NULL;
	remote_topo = NULL;
	dev_reasm = NULL;
	mem_offset = 0;
	dev_total = 0;
	dev_offset = 0;
	committed = false;
	staged = false;
	dev_state_seen = false;
	dev_state_started = false;

	/* ---- Handshake ---- */
	out.phase = MIGRATION_PHASE_HANDSHAKE;
	error = migration_recv(&sess, &hdr, &payload, &payload_len);
	if (error != 0)
		goto fail;
	if (hdr.type != MIGRATION_MSG_HELLO) {
		out.reason = MIGRATION_REASON_PROTOCOL;
		error = EPROTO;
		goto fail;
	}
	error = migration_hello_decode(payload, payload_len, &remote_hello);
	if (error != 0) {
		out.reason = MIGRATION_REASON_PROTOCOL;
		goto fail;
	}
	free(payload);
	payload = NULL;
	if (remote_hello.role != MIGRATION_ROLE_SOURCE) {
		out.reason = MIGRATION_REASON_PROTOCOL;
		error = EPROTO;
		goto fail;
	}
	memset(&local_hello, 0, sizeof(local_hello));
	error = ops->do_local_hello(arg, &local_hello);
	if (error != 0)
		goto fail;
	local_hello.role = MIGRATION_ROLE_DEST;
	if (config->version_max != 0)
		local_hello.version_max = config->version_max;
	if (config->version_min != 0)
		local_hello.version_min = config->version_min;
	reason = MIGRATION_REASON_NONE;
	error = migration_hello_validate(&local_hello, &remote_hello,
	    &negotiated, &reason);
	if (error != 0) {
		out.reason = reason;
		(void)migration_send_reason(&sess, MIGRATION_MSG_CAPS_REJECT,
		    reason, 0);
		goto fail;
	}
	sess.version = negotiated;
	out.negotiated_version = negotiated;
	memset(&caps, 0, sizeof(caps));
	caps.negotiated_version = negotiated;
	caps.capability_flags = local_hello.capability_flags &
	    remote_hello.capability_flags;
	error = migration_caps_accept_encode(&caps, caps_wire, sizeof(caps_wire));
	if (error != 0)
		goto fail;
	error = migration_send(&sess, MIGRATION_MSG_CAPS_ACCEPT, 0, caps_wire,
	    sizeof(caps_wire));
	if (error != 0)
		goto fail;

	/* ---- Topology validation (before the source quiesces) ---- */
	out.phase = MIGRATION_PHASE_VALIDATE;
	error = migration_recv(&sess, &hdr, &payload, &payload_len);
	if (error != 0)
		goto fail;
	if (hdr.type != MIGRATION_MSG_TOPOLOGY) {
		out.reason = MIGRATION_REASON_PROTOCOL;
		error = EPROTO;
		goto fail;
	}
	remote_topo = calloc(1, sizeof(*remote_topo));
	local_topo = calloc(1, sizeof(*local_topo));
	if (remote_topo == NULL || local_topo == NULL) {
		error = ENOMEM;
		goto fail;
	}
	error = migration_topology_decode(payload, payload_len, remote_topo);
	if (error != 0) {
		out.reason = MIGRATION_REASON_PROTOCOL;
		goto fail;
	}
	free(payload);
	payload = NULL;
	error = ops->do_local_topology(arg, local_topo);
	if (error != 0)
		goto fail;
	reason = MIGRATION_REASON_NONE;
	error = migration_topology_validate(local_topo, remote_topo, &reason);
	if (error != 0) {
		out.reason = reason;
		(void)migration_send_reason(&sess, MIGRATION_MSG_TOPO_REJECT,
		    reason, 0);
		goto fail;
	}
	error = migration_send(&sess, MIGRATION_MSG_TOPO_ACCEPT, 0, NULL, 0);
	if (error != 0)
		goto fail;
	free(remote_topo);
	free(local_topo);
	remote_topo = NULL;
	local_topo = NULL;

	/* ---- Staging: memory generations + device state ---- */
	out.phase = MIGRATION_PHASE_PRECOPY;
	staged = true;
	for (;;) {
		if (migration_cancelled(&sess)) {
			out.reason = MIGRATION_REASON_CANCELLED;
			(void)migration_send_reason(&sess, MIGRATION_MSG_ABORT,
			    MIGRATION_REASON_CANCELLED, 0);
			error = ECANCELED;
			goto fail;
		}
		error = migration_recv(&sess, &hdr, &payload, &payload_len);
		if (error != 0)
			goto fail;
		if (hdr.type == MIGRATION_MSG_MEM_GEN) {
			struct migration_memgen gen;
			const uint8_t *data;
			size_t data_len;

			if (dev_state_started ||
			    payload_len < MIGRATION_MEMGEN_HDR_SIZE) {
				out.reason = MIGRATION_REASON_PROTOCOL;
				error = EBADMSG;
				goto fail;
			}
			error = migration_memgen_decode(payload, payload_len,
			    &gen);
			if (error != 0)
				goto fail;
			if ((hdr.flags & MIGRATION_FFLAG_CHUNK) != 0) {
				struct migration_chunk chunk;
				const size_t chunkmax = MIGRATION_MAX_PAYLOAD -
				    MIGRATION_MEMGEN_HDR_SIZE -
				    MIGRATION_CHUNK_HDR_SIZE;

				if (payload_len < MIGRATION_MEMGEN_HDR_SIZE +
				    MIGRATION_CHUNK_HDR_SIZE) {
					out.reason = MIGRATION_REASON_PROTOCOL;
					error = EBADMSG;
					goto fail;
				}
				error = migration_chunk_decode(payload +
				    MIGRATION_MEMGEN_HDR_SIZE,
				    MIGRATION_CHUNK_HDR_SIZE, &chunk);
				if (error != 0)
					goto fail;
				data = payload + MIGRATION_MEMGEN_HDR_SIZE +
				    MIGRATION_CHUNK_HDR_SIZE;
				data_len = payload_len -
				    MIGRATION_MEMGEN_HDR_SIZE -
				    MIGRATION_CHUNK_HDR_SIZE;
				if (chunk.chunk_length != data_len) {
					out.reason = MIGRATION_REASON_PROTOCOL;
					error = EBADMSG;
					goto fail;
				}
				/* Streaming: total 0, ordered by offset only. */
				error = migration_chunk_validate(mem_offset, 0,
				    &chunk, chunkmax, MIGRATION_MAX_DEV_STATE);
				if (error != 0) {
					out.reason = MIGRATION_REASON_PROTOCOL;
					goto fail;
				}
				error = ops->do_stage_mem(arg, &gen, data,
				    data_len);
				if (error != 0) {
					out.reason = MIGRATION_REASON_STATE;
					goto fail;
				}
				mem_offset += data_len;
				if (chunk.final != 0) {
					mem_offset = 0;
					out.rounds++;
				}
			} else {
				error = ops->do_stage_mem(arg, &gen,
				    payload + MIGRATION_MEMGEN_HDR_SIZE,
				    payload_len - MIGRATION_MEMGEN_HDR_SIZE);
				if (error != 0) {
					out.reason = MIGRATION_REASON_STATE;
					goto fail;
				}
				out.rounds++;
			}
			out.bytes_received += payload_len;
			free(payload);
			payload = NULL;
			error = migration_send(&sess, MIGRATION_MSG_MEM_ACK, 0,
			    NULL, 0);
			if (error != 0)
				goto fail;
			continue;
		}
		if (hdr.type == MIGRATION_MSG_DEV_STATE) {
			if ((hdr.flags & MIGRATION_FFLAG_CHUNK) != 0) {
				struct migration_chunk chunk;
				const size_t chunkmax = MIGRATION_MAX_PAYLOAD -
				    MIGRATION_CHUNK_HDR_SIZE;

				if (dev_state_seen ||
				    (dev_state_started && dev_reasm == NULL) ||
				    payload_len < MIGRATION_CHUNK_HDR_SIZE) {
					out.reason = MIGRATION_REASON_PROTOCOL;
					error = EBADMSG;
					goto fail;
				}
				error = migration_chunk_decode(payload,
				    MIGRATION_CHUNK_HDR_SIZE, &chunk);
				if (error != 0)
					goto fail;
				if (chunk.chunk_length !=
				    payload_len - MIGRATION_CHUNK_HDR_SIZE) {
					out.reason = MIGRATION_REASON_PROTOCOL;
					error = EBADMSG;
					goto fail;
				}
				/*
				 * DEV_STATE is reassembled into a total-sized
				 * buffer, so it must declare a non-zero total.
				 * The streaming (total==0) form is legal only for
				 * MEM_GEN, which is staged chunk-by-chunk and
				 * never buffered.  Reject total==0 here before
				 * chunk_validate (which permits total==0 for the
				 * streaming case) so a peer cannot drive a
				 * 1-byte allocation followed by a large copy.
				 */
				if (chunk.total_length == 0) {
					out.reason = MIGRATION_REASON_PROTOCOL;
					error = EBADMSG;
					goto fail;
				}
				error = migration_chunk_validate(dev_offset,
				    dev_total, &chunk, chunkmax,
				    MIGRATION_MAX_DEV_STATE);
				if (error != 0) {
					out.reason = MIGRATION_REASON_PROTOCOL;
					goto fail;
				}
				if (dev_reasm == NULL) {
					dev_state_started = true;
					dev_total = chunk.total_length;
					dev_reasm = malloc(dev_total != 0 ?
					    dev_total : 1);
					if (dev_reasm == NULL) {
						error = ENOMEM;
						goto fail;
					}
				}
				memcpy(dev_reasm + chunk.offset,
				    payload + MIGRATION_CHUNK_HDR_SIZE,
				    chunk.chunk_length);
				dev_offset += chunk.chunk_length;
				if (chunk.final != 0) {
					error = ops->do_stage_dev(arg, dev_reasm,
					    dev_total);
					free(dev_reasm);
					dev_reasm = NULL;
					dev_offset = 0;
					dev_total = 0;
					if (error != 0) {
						out.reason =
						    MIGRATION_REASON_STATE;
						goto fail;
					}
					dev_state_seen = true;
				}
			} else {
				if (dev_state_started) {
					out.reason = MIGRATION_REASON_PROTOCOL;
					error = EBADMSG;
					goto fail;
				}
				dev_state_started = true;
				error = ops->do_stage_dev(arg, payload,
				    payload_len);
				if (error != 0) {
					out.reason = MIGRATION_REASON_STATE;
					goto fail;
				}
				dev_state_seen = true;
			}
			out.bytes_received += payload_len;
			free(payload);
			payload = NULL;
			continue;
		}
		if (hdr.type == MIGRATION_MSG_FINAL) {
			free(payload);
			payload = NULL;
			/*
			 * A DEV_STATE reassembly still in progress at the
			 * ordering fence means the device blob is incomplete;
			 * committing it would replay truncated state.  Reject
			 * (the fail path frees dev_reasm).
			 */
			if (dev_reasm != NULL || !dev_state_seen) {
				out.reason = MIGRATION_REASON_PROTOCOL;
				error = EBADMSG;
				goto fail;
			}
			break;
		}
		if (hdr.type == MIGRATION_MSG_ABORT) {
			if (migration_reason_decode(payload, payload_len,
			    &reason_msg) == 0)
				out.reason = reason_msg.reason_code;
			error = ECONNRESET;
			goto fail;
		}
		out.reason = MIGRATION_REASON_PROTOCOL;
		error = EPROTO;
		goto fail;
	}

	/* ---- Commit ---- */
	out.phase = MIGRATION_PHASE_COMMIT;
	error = ops->do_commit(arg);
	if (error != 0) {
		out.reason = MIGRATION_REASON_STATE;
		(void)migration_send_reason(&sess, MIGRATION_MSG_ABORT,
		    MIGRATION_REASON_STATE, 0);
		goto fail;
	}
	committed = true;
	error = migration_send(&sess, MIGRATION_MSG_COMMIT, 0, NULL, 0);
	if (error != 0)
		goto fail;

	/*
	 * The source resumes exactly one copy: we run the guest only after the
	 * source has released it.  A source abort here means the source will
	 * keep running, so we must not resume.
	 */
	error = migration_recv(&sess, &hdr, &payload, &payload_len);
	if (error != 0)
		goto fail;
	if (hdr.type != MIGRATION_MSG_RELEASE) {
		if (hdr.type == MIGRATION_MSG_ABORT &&
		    migration_reason_decode(payload, payload_len,
		    &reason_msg) == 0)
			out.reason = reason_msg.reason_code;
		else
			out.reason = MIGRATION_REASON_PROTOCOL;
		error = ECONNRESET;
		goto fail;
	}
	free(payload);
	payload = NULL;
	error = ops->do_resume(arg);
	if (error != 0) {
		out.reason = MIGRATION_REASON_STATE;
		goto fail;
	}
	out.resumed = true;
	out.phase = MIGRATION_PHASE_COMPLETED;
	migration_progress_report(&sess, MIGRATION_PHASE_COMPLETED, out.rounds,
	    out.bytes_received, 0, true);
	*result = out;
	return (0);

fail:
	/*
	 * Any destination failure discards all staged (and even committed but
	 * not-yet-resumed) state: nothing was published to a running guest, and
	 * the source remains authoritative.
	 */
	if (staged || committed)
		ops->do_discard(arg);
	if (out.phase != MIGRATION_PHASE_COMPLETED)
		out.phase = MIGRATION_PHASE_FAILED;
	out.resumed = false;
	if (out.reason == MIGRATION_REASON_NONE)
		out.reason = MIGRATION_REASON_TRANSPORT;
	free(payload);
	free(remote_topo);
	free(local_topo);
	free(dev_reasm);
	if (error == 0)
		error = EPROTO;
	*result = out;
	return (error);
}

/* ------------------------------------------------------------------------- */
/* Production adapter (BHYVE_SNAPSHOT only)				     */
/*									     */
/* Binds the source session ops to the live VM: capability/identity and	     */
/* topology come from the running machine and its PCI bus, iterative pre-copy */
/* is driven through migration_precopy over both guest-RAM regions (lowmem and */
/* highmem across the MMIO hole), and quiesce/resume use the existing	     */
/* checkpoint pause helpers.  The final device+CPU/vCPU/kernel state stream    */
/* (steps 6-7 of the handoff) reuses the whole-machine checkpoint save path    */
/* via vm_snapshot_dev_state_to_mem(); the destination adapter reassembles it  */
/* and replays it through the restore steps at COMMIT.  A pre-commit failure   */
/* still rolls the source back through prod_resume().			     */
/* ------------------------------------------------------------------------- */

#ifdef BHYVE_SNAPSHOT

#include <sys/param.h>

#include <err.h>
#include <machine/cpufunc.h>

#include <vmmapi.h>

#include "bhyverun.h"
#include "checkpoint_compat.h"
#include "checkpoint_manifest.h"
#include "ipc.h"
#include "migration_dirty.h"
#include "migration_precopy.h"
#include "pci_emul.h"
#include "qemu_fwcfg.h"
#include "qemu_fwcfg_snapshot.h"
#include "snapshot.h"
#include "tpm_device.h"

/* The pure core mirrors pci_emul.h's flag values; prove they stay identical. */
_Static_assert(MIGRATION_DEVF_STATE_CODEC == PCI_MIGRATION_F_STATE_CODEC,
    "migration device flag mirror drift");
_Static_assert(MIGRATION_DEVF_COMPAT_FIXED == PCI_MIGRATION_F_COMPAT_FIXED,
    "migration device flag mirror drift");
_Static_assert(MIGRATION_DEVF_COMPAT_CALLBACK == PCI_MIGRATION_F_COMPAT_CALLBACK,
    "migration device flag mirror drift");
_Static_assert(MIGRATION_DEVF_DMA_NONE == PCI_MIGRATION_F_DMA_NONE,
    "migration device flag mirror drift");
_Static_assert(MIGRATION_DEVF_DMA_TRACKED == PCI_MIGRATION_F_DMA_TRACKED,
    "migration device flag mirror drift");
_Static_assert(MIGRATION_DEVF_QUIESCE_NONE == PCI_MIGRATION_F_QUIESCE_NONE,
    "migration device flag mirror drift");
_Static_assert(MIGRATION_DEVF_QUIESCE_CALLBACK == PCI_MIGRATION_F_QUIESCE_CALLBACK,
    "migration device flag mirror drift");
_Static_assert(MIGRATION_DEVF_ALL == PCI_MIGRATION_F_ALL,
    "migration device flag mirror drift");

struct migration_prod_source {
	struct vmctx *ctx;
	uint64_t track_gpa;	/* tracked range base (0) */
	uint64_t track_len;	/* tracked range length (spans the MMIO hole) */
	uint64_t lowmem_len;	/* [0, lowmem_len) backed */
	uint64_t highmem_base;	/* highmem region base (>= 4 GiB on amd64) */
	uint64_t highmem_len;	/* [highmem_base, highmem_base+highmem_len) */
	/* Chunked-generation cursor (multi-frame pre-copy round state). */
	uint8_t *bitmap;
	size_t bitmap_bytes;
	uint64_t cursor;	/* next GPA to examine within the round */
	uint64_t gen_total;	/* dirty pages emitted so far this generation */
	bool gen_active;
	bool quiesced;
};

/* Advance a page-aligned GPA to the next backed guest-RAM page, or track_len. */
static uint64_t
prod_next_backed(const struct migration_prod_source *src, uint64_t gpa)
{

	if (gpa < src->lowmem_len)
		return (gpa);
	if (src->highmem_len != 0) {
		if (gpa < src->highmem_base)
			return (src->highmem_base);
		if (gpa < src->highmem_base + src->highmem_len)
			return (gpa);
	}
	return (src->track_len);
}

int
migration_prod_fill_hello(struct vmctx *ctx, struct migration_hello *hello)
{

	if (ctx == NULL || hello == NULL)
		return (EINVAL);
	memset(hello, 0, sizeof(*hello));
	hello->version_max = MIGRATION_PROTO_VERSION;
	hello->version_min = MIGRATION_PROTO_VERSION_MIN;
	hello->page_size = MIGRATION_DIRTY_GRANULARITY;
	hello->capability_flags = MIGRATION_CAP_PRECOPY |
	    MIGRATION_CAP_DEVICE_DIRTY;
	strlcpy(hello->machine_abi, CHECKPOINT_MACHINE_ABI,
	    sizeof(hello->machine_abi));
#ifdef __amd64__
	{
		u_int regs[4];
		uint32_t feats[5];

		hello->arch_id = 0x8664;
		hello->intr_controller = 1;	/* xAPIC */
		do_cpuid(1, regs);
		hello->cpu_family = ((regs[0] >> 8) & 0xf) +
		    ((regs[0] >> 20) & 0xff);
		hello->cpu_model = ((regs[0] >> 4) & 0xf) |
		    (((regs[0] >> 16) & 0xf) << 4);
		hello->cpu_stepping = regs[0] & 0xf;
		feats[0] = regs[2];
		feats[1] = regs[3];
		cpuid_count(7, 0, regs);
		feats[2] = regs[1];
		feats[3] = regs[2];
		feats[4] = regs[3];
		hello->cpu_feature_hash = migration_crc32(feats, sizeof(feats));
	}
#else
	hello->arch_id = 0;
	hello->intr_controller = 0;
#endif
	return (0);
}

int
migration_prod_fill_topology(struct vmctx *ctx, struct migration_topology *topo)
{
	struct pci_devinst *pdi;
	uint16_t sockets, cores, threads, maxcpus;
	uint64_t lowmem, highmem;

	if (ctx == NULL || topo == NULL)
		return (EINVAL);
	/* TPM state has no portable backend/interface checkpoint contract yet. */
	if (tpm_device_present())
		return (ENOTSUP);
	memset(topo, 0, sizeof(*topo));
	lowmem = vm_get_lowmem_size(ctx);
	highmem = vm_get_highmem_size(ctx);
	topo->lowmem = lowmem;
	topo->highmem = highmem;
	topo->mem_size = lowmem + highmem;
	topo->ncpus = (uint32_t)guest_ncpus;
	if (vm_get_topology(ctx, &sockets, &cores, &threads, &maxcpus) == 0) {
		topo->sockets = sockets;
		topo->cores = cores;
		topo->threads = threads;
	}
	pdi = NULL;
	while ((pdi = pci_next(pdi)) != NULL) {
		struct migration_device_record *rec;

		if (topo->device_count >= MIGRATION_MAX_DEVICES)
			return (E2BIG);
		rec = &topo->devices[topo->device_count];
		strlcpy(rec->name, pdi->pi_name, sizeof(rec->name));
		rec->migration_flags = pdi->pi_d->pe_migration_flags;
		rec->compat_schema = PCI_SNAPSHOT_COMPAT_SCHEMA;
		if ((rec->migration_flags & PCI_MIGRATION_F_COMPAT_CALLBACK) != 0) {
			struct pci_snapshot_compat compat;
			uint8_t wire[CHECKPOINT_COMPAT_ENVELOPE_SIZE];
			int error;

			error = pci_snapshot_compat(pdi, &compat);
			if (error != 0)
				return (error);
			/*
			 * Negotiation and payload state belong to the streamed checkpoint,
			 * not the pre-quiesce destination shape.  Hash the canonical,
			 * immutable compatibility envelope and require both endpoints to
			 * instantiate that same device contract.
			 */
			compat.negotiated_features = 0;
			compat.payload_crc32 = 0;
			error = checkpoint_compat_encode(&compat, wire, sizeof(wire));
			if (error != 0)
				return (error);
			rec->compat_crc32 = migration_crc32(wire, sizeof(wire));
		} else {
			rec->compat_crc32 = 0;
		}
		/*
		 * BAR-layout identity: a host-independent hash over each BAR's
		 * type and size (never its host-assigned address).  Two hosts
		 * that instantiate the same device with a different BAR layout
		 * produce different hashes, so migration_topology_validate()
		 * refuses the transfer before the source quiesces rather than
		 * replaying BAR-relative device state onto a mismatched layout.
		 */
		{
			uint8_t barbuf[(PCI_BARMAX_WITH_ROM + 1) * 12];
			size_t bo = 0;
			int b;

			for (b = 0; b <= PCI_BARMAX_WITH_ROM; b++) {
				le32enc(barbuf + bo,
				    (uint32_t)pdi->pi_bar[b].type);
				le64enc(barbuf + bo + 4, pdi->pi_bar[b].size);
				bo += 12;
			}
			rec->bar_hash = migration_crc32(barbuf, bo);
		}
		topo->device_count++;
	}
	if (qemu_fwcfg_enabled()) {
		struct migration_device_record *rec;
		int error;

		if (topo->device_count >= MIGRATION_MAX_DEVICES)
			return (E2BIG);
		rec = &topo->devices[topo->device_count];
		strlcpy(rec->name, QEMU_FWCFG_SNAPSHOT_NAME,
		    sizeof(rec->name));
		rec->migration_flags = PCI_MIGRATION_F_STATE_CODEC |
		    PCI_MIGRATION_F_COMPAT_FIXED | PCI_MIGRATION_F_DMA_NONE |
		    PCI_MIGRATION_F_QUIESCE_NONE;
		rec->compat_schema = QEMU_FWCFG_SNAPSHOT_VERSION;
		error = qemu_fwcfg_migration_identity(&rec->compat_crc32);
		if (error != 0)
			return (error);
		rec->bar_hash = 0;
		topo->device_count++;
	}
	return (0);
}

static int
prod_local_hello(void *arg, struct migration_hello *hello)
{
	struct migration_prod_source *src = arg;

	return (migration_prod_fill_hello(src->ctx, hello));
}

static int
prod_local_topology(void *arg, struct migration_topology *topo)
{
	struct migration_prod_source *src = arg;

	return (migration_prod_fill_topology(src->ctx, topo));
}

static int
prod_precopy_enable(void *arg)
{
	struct migration_prod_source *src = arg;
	uint64_t lowmem, highmem, highbase, track_len;
	int error;

	/*
	 * Cover both guest-RAM regions.  A guest larger than the 32-bit MMIO
	 * hole has memory below the hole (lowmem) and above it (highmem); the
	 * dirty tracker manages a single range, so we arm it over the union
	 * [0, highmem_base + highmem_len) that spans the hole and walk only the
	 * two backed sub-regions when serializing.  Hole pages are never backed
	 * and thus never appear dirty.
	 */
	lowmem = vm_get_lowmem_size(src->ctx);
	if (lowmem == 0)
		return (ENXIO);
	highmem = vm_get_highmem_size(src->ctx);
	highbase = vm_get_highmem_base(src->ctx);
	track_len = highmem != 0 ? highbase + highmem : lowmem;
	src->track_gpa = 0;
	src->track_len = track_len;
	src->lowmem_len = lowmem;
	src->highmem_base = highbase;
	src->highmem_len = highmem;
	src->bitmap = NULL;
	src->bitmap_bytes = 0;
	src->gen_active = false;
	src->cursor = 0;
	src->gen_total = 0;
	error = migration_precopy_enable(src->ctx, src->track_gpa,
	    src->track_len);
	return (error);
}

static int
prod_precopy_round(void *arg, bool final, struct migration_memgen *gen,
    uint8_t *buf, size_t cap, size_t *written, uint64_t *dirty_pages,
    bool *converged, bool *more)
{
	struct migration_prod_source *src = arg;
	struct migration_precopy_generation pc;
	size_t off;
	uint64_t count, gpa;
	int error;

	(void)final;
	*more = false;
	/*
	 * A generation begins on the first call after the previous one finished.
	 * Collect the dirty bitmap once for the whole tracked range, then emit
	 * page records chunk by chunk across the two backed sub-regions.
	 */
	if (!src->gen_active) {
		error = migration_dirty_range_bitmap_bytes(src->track_gpa,
		    src->track_len, &src->bitmap_bytes);
		if (error != 0)
			return (error);
		src->bitmap = calloc(src->bitmap_bytes, 1);
		if (src->bitmap == NULL)
			return (ENOMEM);
		memset(&pc, 0, sizeof(pc));
		error = migration_precopy_collect(src->ctx, src->track_gpa,
		    src->track_len, MIGRATION_DIRTY_CLEAR, src->bitmap,
		    src->bitmap_bytes, &pc);
		if (error != 0) {
			free(src->bitmap);
			src->bitmap = NULL;
			return (error);
		}
		src->gen_active = true;
		src->cursor = 0;
		src->gen_total = 0;
	}

	off = 0;
	count = 0;
	gpa = prod_next_backed(src, src->cursor);
	while (gpa < src->track_len) {
		uint64_t p;
		void *host;

		p = gpa / MIGRATION_DIRTY_GRANULARITY;
		if ((src->bitmap[p / NBBY] & (UINT8_C(1) << (p % NBBY))) == 0) {
			gpa = prod_next_backed(src,
			    gpa + MIGRATION_DIRTY_GRANULARITY);
			continue;
		}
		if (off + 12 + MIGRATION_DIRTY_GRANULARITY > cap) {
			/* Chunk full: resume here on the next call. */
			src->cursor = gpa;
			*more = true;
			break;
		}
		host = vm_map_gpa(src->ctx, gpa, MIGRATION_DIRTY_GRANULARITY);
		if (host == NULL) {
			free(src->bitmap);
			src->bitmap = NULL;
			src->gen_active = false;
			return (EFAULT);
		}
		le64enc(buf + off, gpa);
		le32enc(buf + off + 8, (uint32_t)MIGRATION_DIRTY_GRANULARITY);
		memcpy(buf + off + 12, host, MIGRATION_DIRTY_GRANULARITY);
		off += 12 + MIGRATION_DIRTY_GRANULARITY;
		count++;
		gpa = prod_next_backed(src, gpa + MIGRATION_DIRTY_GRANULARITY);
	}
	src->gen_total += count;
	if (!*more) {
		/* Generation complete: retire the bitmap. */
		free(src->bitmap);
		src->bitmap = NULL;
		src->gen_active = false;
	}
	gen->mode = MIGRATION_DIRTY_CLEAR;
	gen->gpa = src->track_gpa;
	gen->length = src->track_len;
	gen->page_count = (uint32_t)count;
	*written = off;
	*dirty_pages = count;
	*converged = (!*more && src->gen_total == 0);
	return (0);
}

static int
prod_precopy_disable(void *arg)
{
	struct migration_prod_source *src = arg;

	free(src->bitmap);
	src->bitmap = NULL;
	src->gen_active = false;
	return (migration_precopy_disable(src->ctx));
}

static int
prod_quiesce(void *arg)
{
	struct migration_prod_source *src = arg;
	int error;

	error = vm_suspend_all_cpus(src->ctx);
	if (error != 0)
		return (errno != 0 ? errno : EIO);
	error = vm_pause_devices();
	if (error != 0) {
		int resume_error;

		/*
		 * vm_pause_devices() may report that its own rollback could not
		 * resume a fabric.  Never restart vCPUs in that state.
		 */
		resume_error = vm_resume_devices();
		if (resume_error != 0) {
			src->quiesced = true;
			return (resume_error);
		}
		(void)vm_resume_all_cpus(src->ctx);
		return (error);
	}
	src->quiesced = true;
	return (0);
}

static int
prod_resume(void *arg)
{
	struct migration_prod_source *src = arg;
	int error;

	error = vm_resume_devices();
	if (error != 0)
		return (error);
	error = vm_resume_all_cpus(src->ctx);
	if (error != 0)
		return (errno != 0 ? errno : EIO);
	src->quiesced = false;
	return (0);
}

static int
prod_dev_state(void *arg, uint8_t **buf, size_t *len)
{
	struct migration_prod_source *src = arg;

	/*
	 * Serialize device + CPU/vCPU/kernel structure state at the cutover by
	 * reusing the whole-machine checkpoint save serializers, packaged into
	 * a single in-memory blob (guest RAM is excluded; it was streamed as
	 * memory generations).  The session chunks the blob across as many
	 * DEV_STATE frames as it needs.  On any error the source rolls back via
	 * prod_resume() and keeps running.
	 */
	return (vm_snapshot_dev_state_to_mem(src->ctx, buf, len));
}

static void
prod_defunct(void *arg)
{
	struct migration_prod_source *src = arg;

	/*
	 * RELEASE is the irreversible handoff.  Leaving this VM merely paused
	 * lets an independent controller resurrect a second runnable copy.
	 */
	vm_destroy(src->ctx);
	exit(BHYVE_EXIT_SUSPEND);
}

static const struct migration_source_ops migration_prod_source_ops = {
	.so_local_hello = prod_local_hello,
	.so_local_topology = prod_local_topology,
	.so_precopy_enable = prod_precopy_enable,
	.so_precopy_round = prod_precopy_round,
	.so_precopy_disable = prod_precopy_disable,
	.so_quiesce = prod_quiesce,
	.so_resume = prod_resume,
	.so_dev_state = prod_dev_state,
	.so_defunct = prod_defunct,
};

/*
 * Operator entry: drive a source migration over an already-connected stream
 * descriptor (an nvlist descriptor received over the per-VM IPC control
 * socket as "fd").  This performs the live handshake, capability/topology
 * validation, device eligibility check, and iterative pre-copy against a
 * destination bhyve, streams the device/CPU cutover state (see
 * prod_dev_state) through COMMIT/RELEASE; a pre-commit failure rolls back
 * and resumes the source, while a committed handoff makes it defunct.
 */
static int
vm_do_migrate(struct vmctx *ctx, const nvlist_t *nvl)
{
	struct migration_prod_source src;
	struct migration_transport xp;
	struct migration_transport_fd fdx;
	struct migration_session_config config;
	struct migration_source_result result;
	int fd, error;

	if (!nvlist_exists_descriptor(nvl, "fd"))
		return (EINVAL);
	fd = nvlist_get_descriptor(nvl, "fd");

	memset(&src, 0, sizeof(src));
	src.ctx = ctx;
	migration_transport_fd_init(&xp, &fdx, fd, 30000);

	memset(&config, 0, sizeof(config));
	config.version_max = MIGRATION_PROTO_VERSION;
	config.version_min = MIGRATION_PROTO_VERSION_MIN;
	config.max_rounds = 8;
	if (nvlist_exists_number(nvl, "max_rounds"))
		config.max_rounds = (uint32_t)nvlist_get_number(nvl,
		    "max_rounds");
	if (nvlist_exists_number(nvl, "converge_pages"))
		config.converge_pages = nvlist_get_number(nvl, "converge_pages");

	memset(&result, 0, sizeof(result));
	error = migration_source_run(&xp, &migration_prod_source_ops, &src,
	    &config, &result);
	if (error != 0) {
		warnx("migration failed at phase %u (reason %u); source %s",
		    result.phase, result.reason,
		    result.source_runnable ? "still running" : "DEFUNCT");
	} else {
		warnx("migration committed; source relinquished");
	}
	return (error);
}
IPC_COMMAND(ipc_cmd_set, migrate, vm_do_migrate);

/* ------------------------------------------------------------------------- */
/* Production destination adapter + listener				     */
/*									     */
/* The destination is an otherwise normally-configured bhyve whose vCPU	     */
/* threads are held at the restore startup fence (exactly as --restore holds  */
/* them).  Received memory generations are written straight into guest RAM;   */
/* the chunked device/CPU blob is reassembled by the session and, at COMMIT,  */
/* replayed through the existing restore steps (vm_migrate_commit_state).     */
/* The guest is resumed only after RELEASE (vm_migrate_resume), preserving    */
/* the one-copy invariant on the live path.				     */
/* ------------------------------------------------------------------------- */

struct migration_prod_dest {
	struct vmctx *ctx;
	uint8_t *dev_blob;	/* reassembled device/CPU blob (owned) */
	size_t dev_len;
	uint64_t mem_last_end;
	uint32_t mem_round;
	bool mem_round_active;
	bool committed;
};

static int
prod_dest_local_hello(void *arg, struct migration_hello *hello)
{
	struct migration_prod_dest *dst = arg;

	return (migration_prod_fill_hello(dst->ctx, hello));
}

static int
prod_dest_local_topology(void *arg, struct migration_topology *topo)
{
	struct migration_prod_dest *dst = arg;

	return (migration_prod_fill_topology(dst->ctx, topo));
}

/*
 * Stage one (possibly chunked) memory generation directly into guest RAM.  The
 * record format matches the source: [gpa u64][len u32][page bytes]*.  Nothing
 * is "published" separately: writing guest RAM before COMMIT is safe because
 * the destination vCPUs are fenced and cannot observe it until resume.
 */
static int
prod_dest_stage_mem(void *arg, const struct migration_memgen *gen,
    const uint8_t *buf, size_t len)
{
	struct migration_prod_dest *dst = arg;
	uint64_t expected_length, highmem, highmem_base;
	size_t off;
	uint32_t page_count;

	highmem = vm_get_highmem_size(dst->ctx);
	highmem_base = vm_get_highmem_base(dst->ctx);
	expected_length = highmem != 0 ?
	    highmem_base + highmem :
	    vm_get_lowmem_size(dst->ctx);
	if (gen == NULL || gen->mode != MIGRATION_DIRTY_CLEAR ||
	    gen->final > 1 || gen->gpa != 0 ||
	    gen->length != expected_length)
		return (EBADMSG);
	if (!dst->mem_round_active || gen->round != dst->mem_round) {
		if (dst->mem_round_active && gen->round <= dst->mem_round)
			return (EBADMSG);
		dst->mem_round = gen->round;
		dst->mem_last_end = 0;
		dst->mem_round_active = true;
	}
	off = 0;
	page_count = 0;
	while (off + 12 <= len) {
		uint64_t gpa;
		uint32_t plen;
		void *host;

		gpa = le64dec(buf + off);
		plen = le32dec(buf + off + 8);
		off += 12;
		if (off + plen > len || migration_memory_record_validate(gpa, plen,
		    vm_get_lowmem_size(dst->ctx), highmem_base, highmem,
		    dst->mem_last_end) != 0)
			return (EBADMSG);
		host = vm_map_gpa(dst->ctx, gpa, plen);
		if (host == NULL)
			return (EFAULT);
		memcpy(host, buf + off, plen);
		dst->mem_last_end = gpa + plen;
		off += plen;
		page_count++;
	}
	return (off == len && page_count == gen->page_count ? 0 : EBADMSG);
}

static int
prod_dest_stage_dev(void *arg, const uint8_t *buf, size_t len)
{
	struct migration_prod_dest *dst = arg;
	uint8_t *copy;

	copy = malloc(len != 0 ? len : 1);
	if (copy == NULL)
		return (ENOMEM);
	memcpy(copy, buf, len);
	free(dst->dev_blob);
	dst->dev_blob = copy;
	dst->dev_len = len;
	return (0);
}

static int
prod_dest_commit(void *arg)
{
	struct migration_prod_dest *dst = arg;
	int error;

	/*
	 * Replay device + CPU/vCPU/kernel state.  Guest RAM is already present.
	 * Devices are left paused and the startup fence held: the guest does not
	 * run until RELEASE drives prod_dest_resume().
	 */
	error = vm_migrate_commit_state(dst->ctx, dst->dev_blob, dst->dev_len);
	if (error == 0)
		dst->committed = true;
	return (error);
}

static int
prod_dest_resume(void *arg)
{
	struct migration_prod_dest *dst = arg;

	return (vm_migrate_resume(dst->ctx));
}

static void
prod_dest_discard(void *arg)
{
	struct migration_prod_dest *dst = arg;

	free(dst->dev_blob);
	dst->dev_blob = NULL;
	dst->dev_len = 0;
	/*
	 * The destination is torn down by the caller on discard; staged guest
	 * RAM and any partially committed device state die with the process.
	 */
}

static const struct migration_dest_ops migration_prod_dest_ops = {
	.do_local_hello = prod_dest_local_hello,
	.do_local_topology = prod_dest_local_topology,
	.do_stage_mem = prod_dest_stage_mem,
	.do_stage_dev = prod_dest_stage_dev,
	.do_commit = prod_dest_commit,
	.do_resume = prod_dest_resume,
	.do_discard = prod_dest_discard,
};

int
migration_prod_dest_serve(struct vmctx *ctx, int fd,
    const struct migration_session_config *config,
    struct migration_dest_result *result)
{
	struct migration_prod_dest dst;
	struct migration_transport xp;
	struct migration_transport_fd fdx;
	int error;

	if (ctx == NULL || result == NULL)
		return (EINVAL);
	memset(&dst, 0, sizeof(dst));
	dst.ctx = ctx;
	migration_transport_fd_init(&xp, &fdx, fd, 30000);
	error = migration_dest_run(&xp, &migration_prod_dest_ops, &dst, config,
	    result);
	free(dst.dev_blob);
	return (error);
}

#endif /* BHYVE_SNAPSHOT */
