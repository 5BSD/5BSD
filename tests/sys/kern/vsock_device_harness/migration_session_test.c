/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Rootless ATF coverage for the bhyve live-migration control plane:
 *
 *   - the fixed-width little-endian wire codec (round-trip, truncation, crc,
 *     magic/version rejection);
 *   - capability and topology negotiation/validation; and
 *   - the source and destination session state machines driven in-process, one
 *     party per thread, over a real socketpair using the fd transport, plus an
 *     injectable model of the source/destination ops.
 *
 * There is no VM, kernel, network, or privilege here.  A completed loopback
 * migration is model evidence for the control logic only; it is not a live
 * two-host migration claim.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../../../usr.sbin/bhyve/migration_session.c"

/* ------------------------------------------------------------------------- */
/* Codec tests								     */
/* ------------------------------------------------------------------------- */

static struct migration_hello
sample_hello(void)
{
	struct migration_hello h;

	memset(&h, 0, sizeof(h));
	h.version_max = 3;
	h.version_min = 1;
	h.role = MIGRATION_ROLE_SOURCE;
	h.arch_id = 0x8664;
	h.page_size = 4096;
	h.cpu_family = 6;
	h.cpu_model = 0x9e;
	h.cpu_stepping = 10;
	h.cpu_feature_hash = 0x0123456789abcdefull;
	h.intr_controller = 2;
	h.capability_flags = MIGRATION_CAP_PRECOPY | MIGRATION_CAP_DEVICE_DIRTY;
	strlcpy(h.machine_abi, "bhyve-virtio-v2", sizeof(h.machine_abi));
	return (h);
}

ATF_TC_WITHOUT_HEAD(hello_roundtrip);
ATF_TC_BODY(hello_roundtrip, tc)
{
	struct migration_hello in, out;
	uint8_t wire[MIGRATION_HELLO_SIZE];

	(void)tc;
	in = sample_hello();
	ATF_REQUIRE_EQ(migration_hello_encode(&in, wire, sizeof(wire)), 0);
	ATF_REQUIRE_EQ(migration_hello_decode(wire, sizeof(wire), &out), 0);
	ATF_CHECK_EQ(memcmp(&in, &out, sizeof(in)), 0);
}

ATF_TC_WITHOUT_HEAD(hello_rejects_uncanonical_abi_and_truncation);
ATF_TC_BODY(hello_rejects_uncanonical_abi_and_truncation, tc)
{
	struct migration_hello in, out;
	uint8_t wire[MIGRATION_HELLO_SIZE];
	const size_t offsets[] = {5, 28, 44};

	(void)tc;
	in = sample_hello();
	/* Non-NUL padding after the terminator is not canonical. */
	memset(in.machine_abi, 'x', sizeof(in.machine_abi));
	ATF_CHECK_EQ(migration_hello_encode(&in, wire, sizeof(wire)), EINVAL);

	in = sample_hello();
	ATF_REQUIRE_EQ(migration_hello_encode(&in, wire, sizeof(wire)), 0);
	/* Corrupt the abi terminator region on the wire; decode must reject. */
	memset(wire + 56, 'y', MIGRATION_MACHINE_ABI_MAX);
	ATF_CHECK_EQ(migration_hello_decode(wire, sizeof(wire), &out), EBADMSG);

	/* Truncated buffers are rejected by both directions. */
	in = sample_hello();
	ATF_CHECK_EQ(migration_hello_encode(&in, wire, MIGRATION_HELLO_SIZE - 1),
	    EINVAL);
	ATF_REQUIRE_EQ(migration_hello_encode(&in, wire, sizeof(wire)), 0);
	ATF_CHECK_EQ(migration_hello_decode(wire, MIGRATION_HELLO_SIZE - 1,
	    &out), EINVAL);
	/* Every reserved field must remain zero and a failed decode is atomic. */
	for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
		out.role = 0x7f;
		wire[offsets[i]] = 1;
		ATF_CHECK_EQ(migration_hello_decode(wire, sizeof(wire), &out),
		    EBADMSG);
		ATF_CHECK_EQ(out.role, 0x7f);
		wire[offsets[i]] = 0;
	}
	in.capability_flags |= 1ull << 40;
	ATF_CHECK_EQ(migration_hello_encode(&in, wire, sizeof(wire)), EINVAL);
	le64enc(wire + 48, in.capability_flags);
	out.role = 0x7f;
	ATF_CHECK_EQ(migration_hello_decode(wire, sizeof(wire), &out),
	    EBADMSG);
	ATF_CHECK_EQ(out.role, 0x7f);
}

ATF_TC_WITHOUT_HEAD(caps_accept_requires_canonical_offered_capabilities);
ATF_TC_BODY(caps_accept_requires_canonical_offered_capabilities, tc)
{
	struct migration_hello offered;
	struct migration_hello remote;
	struct migration_caps_accept accepted, decoded;
	uint8_t wire[MIGRATION_CAPS_ACCEPT_SIZE];
	uint32_t reason;
	uint16_t negotiated;

	(void)tc;
	offered = sample_hello();
	accepted.negotiated_version = 2;
	accepted.capability_flags = MIGRATION_CAP_PRECOPY;
	ATF_REQUIRE_EQ(migration_caps_accept_encode(&accepted, wire,
	    sizeof(wire)), 0);
	decoded.negotiated_version = 99;
	wire[2] = 1;
	ATF_CHECK_EQ(migration_caps_accept_decode(wire, sizeof(wire), &decoded),
	    EBADMSG);
	ATF_CHECK_EQ(decoded.negotiated_version, 99);
	wire[2] = 0;
	ATF_REQUIRE_EQ(migration_caps_accept_decode(wire, sizeof(wire),
	    &decoded), 0);
	ATF_CHECK_EQ(migration_source_caps_validate(&offered, &decoded,
	    &reason), 0);
	le64enc(wire + 4, MIGRATION_CAP_PRECOPY | (1ull << 40));
	decoded.negotiated_version = 99;
	ATF_CHECK_EQ(migration_caps_accept_decode(wire, sizeof(wire), &decoded),
	    EBADMSG);
	ATF_CHECK_EQ(decoded.negotiated_version, 99);
	accepted.capability_flags = 0;
	ATF_CHECK_EQ(migration_source_caps_validate(&offered, &accepted,
	    &reason), EPROTO);
	ATF_CHECK_EQ(reason, MIGRATION_REASON_CAPS);
	accepted.capability_flags = MIGRATION_CAP_PRECOPY | (1ull << 40);
	ATF_CHECK_EQ(migration_caps_accept_encode(&accepted, wire,
	    sizeof(wire)), EINVAL);
	ATF_CHECK_EQ(migration_source_caps_validate(&offered, &accepted,
	    &reason), EPROTO);
	offered.capability_flags = MIGRATION_CAP_PRECOPY;
	accepted.capability_flags = MIGRATION_CAP_ALL;
	ATF_CHECK_EQ(migration_source_caps_validate(&offered, &accepted,
	    &reason), EPROTO);
	accepted.capability_flags = MIGRATION_CAP_PRECOPY;
	accepted.negotiated_version = offered.version_max + 1;
	ATF_CHECK_EQ(migration_source_caps_validate(&offered, &accepted,
	    &reason), EPROTONOSUPPORT);
	ATF_CHECK_EQ(reason, MIGRATION_REASON_VERSION);
	remote = sample_hello();
	remote.capability_flags |= 1ull << 40;
	negotiated = 99;
	ATF_CHECK_EQ(migration_hello_validate(&offered, &remote,
	    &negotiated, &reason), EINVAL);
	ATF_CHECK_EQ(reason, MIGRATION_REASON_CAPS);
	ATF_CHECK_EQ(negotiated, 99);
}

ATF_TC_WITHOUT_HEAD(fresh_tracing_requires_matching_capabilities);
ATF_TC_BODY(fresh_tracing_requires_matching_capabilities, tc)
{
	struct migration_hello source = sample_hello(), destination = sample_hello();
	struct migration_caps_accept accepted = {0}, decoded;
	uint8_t wire[MIGRATION_CAPS_ACCEPT_SIZE];
	uint16_t version = 99;
	uint32_t reason;

	(void)tc;
	source.capability_flags |= MIGRATION_CAP_HYPERTRACE_FRESH;
	ATF_CHECK_EQ(migration_hello_validate(&destination, &source, &version,
	    &reason), EPROTONOSUPPORT);
	ATF_CHECK_EQ(reason, MIGRATION_REASON_CAPS);
	ATF_CHECK_EQ(version, 99);
	ATF_CHECK_EQ(migration_hello_validate(&source, &destination, &version,
	    &reason), EPROTONOSUPPORT);
	destination.capability_flags |= MIGRATION_CAP_HYPERTRACE_FRESH;
	ATF_REQUIRE_EQ(migration_hello_validate(&destination, &source, &version,
	    &reason), 0);
	accepted.negotiated_version = version;
	accepted.capability_flags = source.capability_flags;
	ATF_REQUIRE_EQ(migration_caps_accept_encode(&accepted, wire, sizeof(wire)), 0);
	ATF_REQUIRE_EQ(migration_caps_accept_decode(wire, sizeof(wire), &decoded), 0);
	ATF_CHECK_EQ(migration_source_caps_validate(&source, &decoded, &reason), 0);
	decoded.capability_flags &= ~MIGRATION_CAP_HYPERTRACE_FRESH;
	ATF_CHECK_EQ(migration_source_caps_validate(&source, &decoded, &reason), EPROTO);
	ATF_CHECK_EQ(reason, MIGRATION_REASON_CAPS);
}

ATF_TC_WITHOUT_HEAD(frame_roundtrip_and_crc);
ATF_TC_BODY(frame_roundtrip_and_crc, tc)
{
	struct migration_frame_header hdr;
	uint8_t payload[64], frame[MIGRATION_FRAME_HDR_SIZE + 64];
	size_t written;

	(void)tc;
	for (size_t i = 0; i < sizeof(payload); i++)
		payload[i] = (uint8_t)(i * 7 + 1);
	ATF_REQUIRE_EQ(migration_frame_encode(MIGRATION_PROTO_VERSION, MIGRATION_MSG_DEV_STATE, 5,
	    0, payload, sizeof(payload), frame, sizeof(frame), &written), 0);
	ATF_CHECK_EQ(written, MIGRATION_FRAME_HDR_SIZE + sizeof(payload));
	ATF_REQUIRE_EQ(migration_frame_decode_header(frame, written, &hdr), 0);
	ATF_CHECK_EQ(hdr.magic, MIGRATION_PROTO_MAGIC);
	ATF_CHECK_EQ(hdr.type, MIGRATION_MSG_DEV_STATE);
	ATF_CHECK_EQ(hdr.seq, 5u);
	ATF_CHECK_EQ(hdr.length, sizeof(payload));
	ATF_REQUIRE_EQ(migration_frame_verify_payload(&hdr,
	    frame + MIGRATION_FRAME_HDR_SIZE, hdr.length), 0);

	/* Flip a payload byte: crc verification must fail. */
	frame[MIGRATION_FRAME_HDR_SIZE + 3] ^= 0x40;
	ATF_CHECK_EQ(migration_frame_verify_payload(&hdr,
	    frame + MIGRATION_FRAME_HDR_SIZE, hdr.length), EBADMSG);

	/* Corrupt magic: header decode must fail. */
	struct migration_frame_header prior = hdr;
	frame[0] ^= 0xff;
	ATF_CHECK_EQ(migration_frame_decode_header(frame, written, &hdr),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&hdr, &prior, sizeof(hdr)), 0);
	frame[0] ^= 0xff;
	le16enc(frame + 4, MIGRATION_PROTO_VERSION + 1);
	ATF_CHECK_EQ(migration_frame_decode_header(frame, written, &hdr),
	    EPROTO);
	ATF_CHECK_EQ(memcmp(&hdr, &prior, sizeof(hdr)), 0);
	le16enc(frame + 4, MIGRATION_PROTO_VERSION);
	le32enc(frame + 8, MIGRATION_FFLAG_CHUNK << 1);
	ATF_CHECK_EQ(migration_frame_decode_header(frame, written, &hdr),
	    EPROTO);
	ATF_CHECK_EQ(memcmp(&hdr, &prior, sizeof(hdr)), 0);
}

ATF_TC_WITHOUT_HEAD(frame_rejects_oversize_and_short_header);
ATF_TC_BODY(frame_rejects_oversize_and_short_header, tc)
{
	struct migration_frame_header hdr;
	uint8_t frame[MIGRATION_FRAME_HDR_SIZE];
	size_t written;

	(void)tc;
	/* Oversize payload is rejected (non-NULL pointer, size check hits). */
	ATF_CHECK_EQ(migration_frame_encode(MIGRATION_PROTO_VERSION, MIGRATION_MSG_HELLO, 1, 0,
	    frame, (size_t)MIGRATION_MAX_PAYLOAD + 1, frame, sizeof(frame),
	    &written), EMSGSIZE);
	/* NULL payload with nonzero length is a caller error. */
	ATF_CHECK_EQ(migration_frame_encode(MIGRATION_PROTO_VERSION, MIGRATION_MSG_HELLO, 1, 0,
	    NULL, 8, frame, sizeof(frame), &written), EINVAL);
	ATF_CHECK_EQ(migration_frame_decode_header(frame,
	    MIGRATION_FRAME_HDR_SIZE - 1, &hdr), EINVAL);
	/* A header claiming an oversize length is rejected. */
	memset(frame, 0, sizeof(frame));
	le32enc(frame + 0, MIGRATION_PROTO_MAGIC);
	le16enc(frame + 4, MIGRATION_PROTO_VERSION);
	le16enc(frame + 6, MIGRATION_MSG_HELLO);
	le32enc(frame + 16, MIGRATION_MAX_PAYLOAD + 1);
	ATF_CHECK_EQ(migration_frame_decode_header(frame, sizeof(frame), &hdr),
	    EMSGSIZE);
}

ATF_TC_WITHOUT_HEAD(memory_record_validation);
ATF_TC_BODY(memory_record_validation, tc)
{
	const uint64_t lowmem = 2 * MIGRATION_DIRTY_GRANULARITY;
	const uint64_t highbase = UINT64_C(0x100000000);
	const uint64_t highmem = 2 * MIGRATION_DIRTY_GRANULARITY;

	(void)tc;
	ATF_CHECK_EQ(migration_memory_record_validate(0,
	    MIGRATION_DIRTY_GRANULARITY, lowmem, highbase, highmem, 0), 0);
	ATF_CHECK_EQ(migration_memory_record_validate(
	    MIGRATION_DIRTY_GRANULARITY, MIGRATION_DIRTY_GRANULARITY,
	    lowmem, highbase, highmem, MIGRATION_DIRTY_GRANULARITY), 0);
	ATF_CHECK_EQ(migration_memory_record_validate(highbase,
	    MIGRATION_DIRTY_GRANULARITY, lowmem, highbase, highmem, lowmem), 0);

	ATF_CHECK_EQ(migration_memory_record_validate(1,
	    MIGRATION_DIRTY_GRANULARITY, lowmem, highbase, highmem, 0), EBADMSG);
	ATF_CHECK_EQ(migration_memory_record_validate(0,
	    MIGRATION_DIRTY_GRANULARITY / 2, lowmem, highbase, highmem, 0),
	    EBADMSG);
	ATF_CHECK_EQ(migration_memory_record_validate(0,
	    MIGRATION_DIRTY_GRANULARITY, lowmem, highbase, highmem,
	    MIGRATION_DIRTY_GRANULARITY), EBADMSG);
	ATF_CHECK_EQ(migration_memory_record_validate(lowmem,
	    MIGRATION_DIRTY_GRANULARITY, lowmem, highbase, highmem, lowmem),
	    EBADMSG);
	ATF_CHECK_EQ(migration_memory_record_validate(highbase + highmem,
	    MIGRATION_DIRTY_GRANULARITY, lowmem, highbase, highmem, highbase),
	    EBADMSG);
}

ATF_TC_WITHOUT_HEAD(frame_rejects_unknown_version_type_and_flags);
ATF_TC_BODY(frame_rejects_unknown_version_type_and_flags, tc)
{
	struct migration_frame_header hdr;
	uint8_t frame[MIGRATION_FRAME_HDR_SIZE];
	size_t written;

	(void)tc;
	ATF_CHECK_EQ(migration_frame_encode(0, MIGRATION_MSG_HELLO, 1, 0,
	    NULL, 0, frame, sizeof(frame), &written), EINVAL);
	ATF_CHECK_EQ(migration_frame_encode(MIGRATION_PROTO_VERSION,
	    MIGRATION_MSG_HELLO, 1, MIGRATION_FFLAG_CHUNK, NULL, 0, frame,
	    sizeof(frame), &written), EINVAL);

	memset(frame, 0, sizeof(frame));
	le32enc(frame + 0, MIGRATION_PROTO_MAGIC);
	le16enc(frame + 4, MIGRATION_PROTO_VERSION + 1);
	le16enc(frame + 6, MIGRATION_MSG_HELLO);
	ATF_CHECK_EQ(migration_frame_decode_header(frame, sizeof(frame), &hdr),
	    EPROTO);
	le16enc(frame + 4, MIGRATION_PROTO_VERSION);
	le16enc(frame + 6, MIGRATION_MSG_RELEASE_ACK + 1);
	ATF_CHECK_EQ(migration_frame_decode_header(frame, sizeof(frame), &hdr),
	    EPROTO);
	le16enc(frame + 6, MIGRATION_MSG_HELLO);
	le32enc(frame + 8, MIGRATION_FFLAG_CHUNK);
	ATF_CHECK_EQ(migration_frame_decode_header(frame, sizeof(frame), &hdr),
	    EPROTO);
}

ATF_TC_WITHOUT_HEAD(topology_roundtrip_and_bounds);
ATF_TC_BODY(topology_roundtrip_and_bounds, tc)
{
	struct migration_topology *in, *out;
	uint8_t *wire;
	size_t size, written;

	(void)tc;
	in = calloc(1, sizeof(*in));
	out = calloc(1, sizeof(*out));
	ATF_REQUIRE(in != NULL && out != NULL);
	in->mem_size = 4ull << 30;
	in->lowmem = 3ull << 30;
	in->highmem = 1ull << 30;
	in->ncpus = 4;
	in->sockets = 1;
	in->cores = 4;
	in->threads = 1;
	in->device_count = 2;
	strlcpy(in->devices[0].name, "virtio-net", MIGRATION_DEVICE_NAME_MAX);
	in->devices[0].migration_flags = MIGRATION_DEVF_STATE_CODEC |
	    MIGRATION_DEVF_COMPAT_CALLBACK | MIGRATION_DEVF_DMA_TRACKED |
	    MIGRATION_DEVF_QUIESCE_CALLBACK;
	in->devices[0].compat_schema = 7;
	in->devices[0].compat_crc32 = 0xdeadbeef;
	strlcpy(in->devices[1].name, "hostbridge", MIGRATION_DEVICE_NAME_MAX);
	in->devices[1].migration_flags = MIGRATION_DEVF_STATE_CODEC |
	    MIGRATION_DEVF_COMPAT_FIXED | MIGRATION_DEVF_DMA_NONE |
	    MIGRATION_DEVF_QUIESCE_NONE;

	size = migration_topology_wire_size(in);
	ATF_CHECK_EQ(size, (size_t)MIGRATION_TOPOLOGY_HDR_SIZE +
	    2 * MIGRATION_DEVREC_SIZE);
	wire = malloc(size);
	ATF_REQUIRE(wire != NULL);
	ATF_REQUIRE_EQ(migration_topology_encode(in, wire, size, &written), 0);
	ATF_CHECK_EQ(written, size);
	ATF_REQUIRE_EQ(migration_topology_decode(wire, size, out), 0);
	ATF_CHECK_EQ(memcmp(in, out, sizeof(*in)), 0);

	/* Truncated device array is rejected. */
	ATF_CHECK_EQ(migration_topology_decode(wire, size - 1, out), EBADMSG);
	/* Fixed-version topology records do not admit silently ignored trailers. */
	ATF_CHECK_EQ(migration_topology_decode(wire, size + 1, out), EBADMSG);
	/* Reject an inconsistent memory total before accepting a peer layout. */
	le64enc(wire, in->mem_size - 1);
	ATF_CHECK_EQ(migration_topology_decode(wire, size, out), EBADMSG);
	ATF_CHECK_EQ(out->mem_size, in->mem_size);
	le64enc(wire, in->mem_size);
	in->mem_size--;
	ATF_CHECK_EQ(migration_topology_encode(in, wire, size, &written), EINVAL);
	in->mem_size++;
	/* A wrapped low+high sum must not be mistaken for a valid total. */
	le64enc(wire + 8, UINT64_MAX);
	le64enc(wire + 16, 1);
	le64enc(wire, 0);
	ATF_CHECK_EQ(migration_topology_decode(wire, size, out), EBADMSG);
	ATF_CHECK_EQ(out->mem_size, in->mem_size);
	ATF_REQUIRE_EQ(migration_topology_encode(in, wire, size, &written), 0);

	/* An over-large device_count in the header is rejected. */
	le32enc(wire + 36, MIGRATION_MAX_DEVICES + 1);
	ATF_CHECK_EQ(migration_topology_decode(wire, size, out), EBADMSG);

	free(wire);
	free(in);
	free(out);
}

ATF_TC_WITHOUT_HEAD(version_negotiation_downgrade_and_reject);
ATF_TC_BODY(version_negotiation_downgrade_and_reject, tc)
{
	uint16_t v;

	(void)tc;
	/* Overlapping windows pick the highest common version. */
	ATF_REQUIRE_EQ(migration_negotiate_version(3, 1, 2, 1, &v), 0);
	ATF_CHECK_EQ(v, 2);
	ATF_REQUIRE_EQ(migration_negotiate_version(2, 2, 4, 1, &v), 0);
	ATF_CHECK_EQ(v, 2);
	/* Disjoint windows fail closed. */
	ATF_CHECK_EQ(migration_negotiate_version(1, 1, 3, 2, &v),
	    EPROTONOSUPPORT);
	ATF_CHECK_EQ(migration_negotiate_version(4, 3, 2, 1, &v),
	    EPROTONOSUPPORT);
}

ATF_TC_WITHOUT_HEAD(hello_validate_rejects_mismatch);
ATF_TC_BODY(hello_validate_rejects_mismatch, tc)
{
	struct migration_hello local, remote;
	uint16_t negotiated;
	uint32_t reason;

	(void)tc;
	local = sample_hello();
	local.role = MIGRATION_ROLE_DEST;

	remote = sample_hello();
	ATF_REQUIRE_EQ(migration_hello_validate(&local, &remote, &negotiated,
	    &reason), 0);
	ATF_CHECK_EQ(reason, (uint32_t)MIGRATION_REASON_NONE);

	remote = sample_hello();
	remote.arch_id = 0xaa64;
	ATF_CHECK(migration_hello_validate(&local, &remote, &negotiated,
	    &reason) != 0);
	ATF_CHECK_EQ(reason, (uint32_t)MIGRATION_REASON_ARCH);

	remote = sample_hello();
	remote.page_size = 16384;
	ATF_CHECK(migration_hello_validate(&local, &remote, &negotiated,
	    &reason) != 0);
	ATF_CHECK_EQ(reason, (uint32_t)MIGRATION_REASON_PAGESIZE);

	remote = sample_hello();
	remote.cpu_feature_hash ^= 1;
	ATF_CHECK(migration_hello_validate(&local, &remote, &negotiated,
	    &reason) != 0);
	ATF_CHECK_EQ(reason, (uint32_t)MIGRATION_REASON_CPU);

	remote = sample_hello();
	strlcpy(remote.machine_abi, "mismatched-machine-abi",
	    sizeof(remote.machine_abi));
	ATF_CHECK(migration_hello_validate(&local, &remote, &negotiated,
	    &reason) != 0);
	ATF_CHECK_EQ(reason, (uint32_t)MIGRATION_REASON_MACHINE_ABI);

	remote = sample_hello();
	remote.capability_flags = 0;
	ATF_CHECK(migration_hello_validate(&local, &remote, &negotiated,
	    &reason) != 0);
	ATF_CHECK_EQ(reason, (uint32_t)MIGRATION_REASON_CAPS);
}

ATF_TC_WITHOUT_HEAD(device_flags_eligibility);
ATF_TC_BODY(device_flags_eligibility, tc)
{

	(void)tc;
	/* Exactly one of each policy plus the mandatory state codec. */
	ATF_CHECK(migration_device_flags_eligible(MIGRATION_DEVF_STATE_CODEC |
	    MIGRATION_DEVF_COMPAT_CALLBACK | MIGRATION_DEVF_DMA_TRACKED |
	    MIGRATION_DEVF_QUIESCE_CALLBACK));
	/* Missing the state codec: ineligible. */
	ATF_CHECK(!migration_device_flags_eligible(MIGRATION_DEVF_COMPAT_FIXED |
	    MIGRATION_DEVF_DMA_NONE | MIGRATION_DEVF_QUIESCE_NONE));
	/* Two compat policies at once: ineligible. */
	ATF_CHECK(!migration_device_flags_eligible(MIGRATION_DEVF_STATE_CODEC |
	    MIGRATION_DEVF_COMPAT_FIXED | MIGRATION_DEVF_COMPAT_CALLBACK |
	    MIGRATION_DEVF_DMA_NONE | MIGRATION_DEVF_QUIESCE_NONE));
	/* Unknown bit: ineligible. */
	ATF_CHECK(!migration_device_flags_eligible(MIGRATION_DEVF_ALL |
	    (1u << 20)));
	/* No DMA policy declared: ineligible. */
	ATF_CHECK(!migration_device_flags_eligible(MIGRATION_DEVF_STATE_CODEC |
	    MIGRATION_DEVF_COMPAT_FIXED | MIGRATION_DEVF_QUIESCE_NONE));
}

ATF_TC_WITHOUT_HEAD(topology_validate_enforces_device_identity);
ATF_TC_BODY(topology_validate_enforces_device_identity, tc)
{
	struct migration_topology local, remote;
	uint32_t reason;

	(void)tc;

	/* Two structurally identical single-device topologies. */
	memset(&local, 0, sizeof(local));
	local.mem_size = 0x10000;
	local.lowmem = 0x10000;
	local.highmem = 0;
	local.ncpus = 2;
	local.sockets = 1;
	local.cores = 2;
	local.threads = 1;
	local.device_count = 1;
	strlcpy(local.devices[0].name, "virtio-blk",
	    MIGRATION_DEVICE_NAME_MAX);
	local.devices[0].migration_flags = MIGRATION_DEVF_STATE_CODEC |
	    MIGRATION_DEVF_COMPAT_CALLBACK | MIGRATION_DEVF_DMA_TRACKED |
	    MIGRATION_DEVF_QUIESCE_CALLBACK;
	local.devices[0].compat_schema = 1;
	local.devices[0].compat_crc32 = 0x11223344;
	local.devices[0].bar_hash = 0xaabbccdd;
	remote = local;

	/* Identical hosts validate clean. */
	reason = 0xffffffff;
	ATF_CHECK_EQ(migration_topology_validate(&local, &remote, &reason), 0);
	ATF_CHECK_EQ(reason, MIGRATION_REASON_NONE);
	remote.mem_size--;
	ATF_CHECK_EQ(migration_topology_validate(&local, &remote, &reason),
	    EINVAL);
	ATF_CHECK_EQ(reason, MIGRATION_REASON_MEMSIZE);
	remote.mem_size++;

	/*
	 * A differing BAR-layout hash means the destination instantiated the
	 * same device with a different BAR layout; restoring BAR-relative state
	 * onto it would corrupt, so the transfer must be refused before the
	 * source quiesces.
	 */
	remote.devices[0].bar_hash = local.devices[0].bar_hash ^ 0x1u;
	reason = MIGRATION_REASON_NONE;
	ATF_CHECK_EQ(migration_topology_validate(&local, &remote, &reason),
	    EINVAL);
	ATF_CHECK_EQ(reason, MIGRATION_REASON_DEVICE);
	remote.devices[0].bar_hash = local.devices[0].bar_hash;

	/* Regression guard: a differing compat CRC is still refused. */
	remote.devices[0].compat_crc32 ^= 0x1u;
	reason = MIGRATION_REASON_NONE;
	ATF_CHECK_EQ(migration_topology_validate(&local, &remote, &reason),
	    EINVAL);
	ATF_CHECK_EQ(reason, MIGRATION_REASON_DEVICE);
	remote.devices[0].compat_crc32 = local.devices[0].compat_crc32;

	/* And an identical pair still validates after the mutations are undone. */
	reason = 0xffffffff;
	ATF_CHECK_EQ(migration_topology_validate(&local, &remote, &reason), 0);
	ATF_CHECK_EQ(reason, MIGRATION_REASON_NONE);
}

/* ------------------------------------------------------------------------- */
/* Session model								     */
/* ------------------------------------------------------------------------- */

#define	MODEL_PAGES		16
#define	MODEL_PAGE_SIZE		4096
#define	MODEL_MEM		(MODEL_PAGES * MODEL_PAGE_SIZE)

/*
 * A tiny in-memory "guest": MODEL_PAGES pages, a dirty bitmap, and a device
 * state blob.  The source model dirties pages between rounds; the destination
 * model stages received pages into its own copy and only publishes on commit.
 */
struct model_guest {
	uint8_t pages[MODEL_PAGES][MODEL_PAGE_SIZE];
	uint8_t dirty[MODEL_PAGES];
	uint8_t dev_state[128];
	size_t dev_state_len;
};

struct source_model {
	struct model_guest guest;
	int round;
	int chunk_cursor;	/* page index a chunked generation resumes from */
	int converge_after;	/* declare converged at this round (<=0 never) */
	int fail_dev_state;	/* errno to fail so_dev_state with */
	int fail_resume;	/* errno to fail source rollback resume with */
	int fail_quiesce;	/* errno to fail so_quiesce with */
	bool quiesce_wedged;	/* if failing quiesce, source is unrecoverable */
	const uint8_t *dev_override;	/* large dev-state blob (else guest.dev_state) */
	size_t dev_override_len;
	bool quiesced;
	bool defunct;
	bool resumed_after_rollback;
	bool retired;
	int fail_retire;
	int fail_record, recorded, fail_binding;
	uint8_t challenge[32];
};

struct dest_model {
	struct model_guest staged;	/* not published until commit */
	struct model_guest published;
	int fail_commit;		/* errno to fail do_commit with */
	int fail_resume, resume_attempts;
	bool committed;
	bool resumed;
	bool discarded;
	int fail_record, recorded, fail_binding;
	bool retained;
	uint8_t challenge[32];
	int fail_preserve, preserved;	/* optional durable image hook */
};

/* ---- source ops ---- */

static int
src_hello(void *arg, struct migration_hello *h)
{

	(void)arg;
	*h = sample_hello();
	h->role = MIGRATION_ROLE_SOURCE;
	return (0);
}

static void
model_fill_topology(struct migration_topology *t)
{

	memset(t, 0, sizeof(*t));
	t->mem_size = MODEL_MEM;
	t->lowmem = MODEL_MEM;
	t->highmem = 0;
	t->ncpus = 2;
	t->sockets = 1;
	t->cores = 2;
	t->threads = 1;
	t->device_count = 1;
	strlcpy(t->devices[0].name, "virtio-blk", MIGRATION_DEVICE_NAME_MAX);
	t->devices[0].migration_flags = MIGRATION_DEVF_STATE_CODEC |
	    MIGRATION_DEVF_COMPAT_CALLBACK | MIGRATION_DEVF_DMA_TRACKED |
	    MIGRATION_DEVF_QUIESCE_CALLBACK;
	t->devices[0].compat_schema = 1;
	t->devices[0].compat_crc32 = 0x11223344;
}

static int
src_fresh_hello(void *arg, struct migration_hello *hello)
{
	int error = src_hello(arg, hello);
	hello->capability_flags |= MIGRATION_CAP_HYPERTRACE_FRESH;
	return (error);
}

static int
src_topology(void *arg, struct migration_topology *t)
{

	(void)arg;
	model_fill_topology(t);
	return (0);
}

static int
src_precopy_enable(void *arg)
{
	struct source_model *m = arg;

	/* Dirty every page initially. */
	memset(m->guest.dirty, 1, sizeof(m->guest.dirty));
	return (0);
}

static int
src_precopy_round(void *arg, bool final, struct migration_memgen *gen,
    uint8_t *buf, size_t cap, size_t *written, uint64_t *dirty_pages,
    bool *converged, bool *more)
{
	struct source_model *m = arg;
	size_t off;
	uint64_t count;

	/*
	 * A fresh generation begins whenever the previous one finished (cursor
	 * at 0).  The model emits whole page records until this frame's data
	 * capacity is reached, then reports *more so the session continues the
	 * same generation in a further chunk.
	 */
	if (m->chunk_cursor == 0)
		m->round++;
	off = 0;
	count = 0;
	*more = false;
	for (int p = m->chunk_cursor; p < MODEL_PAGES; p++) {
		if (!m->guest.dirty[p])
			continue;
		if (off + 8 + MODEL_PAGE_SIZE > cap) {
			/* Ran out of frame room: resume here next call. */
			m->chunk_cursor = p;
			*more = true;
			break;
		}
		le64enc(buf + off, (uint64_t)p * MODEL_PAGE_SIZE);
		off += 8;
		memcpy(buf + off, m->guest.pages[p], MODEL_PAGE_SIZE);
		off += MODEL_PAGE_SIZE;
		m->guest.dirty[p] = 0;
		count++;
	}
	if (*more) {
		/* Mid-generation chunk: report only this chunk's pages. */
		gen->mode = MIGRATION_DIRTY_CLEAR;
		gen->gpa = 0;
		gen->length = MODEL_MEM;
		gen->cpu_identity = 1;
		gen->cpu_map_generation = 1;
		gen->cpu_dirty_generation = (uint64_t)m->round;
		gen->device_identity = 2;
		gen->device_dirty_generation = (uint64_t)m->round;
		gen->page_count = (uint32_t)count;
		*written = off;
		*dirty_pages = count;
		*converged = false;
		return (0);
	}
	m->chunk_cursor = 0;
	gen->mode = final ? MIGRATION_DIRTY_CLEAR : MIGRATION_DIRTY_CLEAR;
	gen->gpa = 0;
	gen->length = MODEL_MEM;
	gen->cpu_identity = 1;
	gen->cpu_map_generation = 1;
	gen->cpu_dirty_generation = (uint64_t)m->round;
	gen->device_identity = 2;
	gen->device_dirty_generation = (uint64_t)m->round;
	gen->page_count = (uint32_t)count;
	*written = off;
	*dirty_pages = count;
	if (final) {
		*converged = true;
	} else {
		/* Re-dirty one page to model a working set until convergence. */
		if (m->converge_after > 0 && m->round >= m->converge_after)
			*converged = true;
		else {
			m->guest.pages[0][0]++;
			m->guest.dirty[0] = 1;
			*converged = false;
		}
	}
	return (0);
}

static int
src_precopy_disable(void *arg)
{

	(void)arg;
	return (0);
}

static int
src_quiesce(void *arg, bool *source_runnable)
{
	struct source_model *m = arg;

	if (m->fail_quiesce != 0) {
		/*
		 * A wedged quiesce leaves the source stopped; a clean quiesce
		 * failure rolled back and kept it running.
		 */
		m->quiesced = m->quiesce_wedged;
		*source_runnable = !m->quiesce_wedged;
		return (m->fail_quiesce);
	}
	m->quiesced = true;
	return (0);
}

static int
src_resume(void *arg)
{
	struct source_model *m = arg;

	if (m->fail_resume != 0)
		return (m->fail_resume);
	m->quiesced = false;
	m->resumed_after_rollback = true;
	return (0);
}

static int
src_dev_state(void *arg, uint8_t **buf, size_t *len)
{
	struct source_model *m = arg;
	uint8_t *out;

	if (m->fail_dev_state != 0)
		return (m->fail_dev_state);
	if (m->dev_override != NULL) {
		out = malloc(m->dev_override_len != 0 ? m->dev_override_len : 1);
		if (out == NULL)
			return (ENOMEM);
		memcpy(out, m->dev_override, m->dev_override_len);
		*buf = out;
		*len = m->dev_override_len;
		return (0);
	}
	out = malloc(m->guest.dev_state_len != 0 ? m->guest.dev_state_len : 1);
	if (out == NULL)
		return (ENOMEM);
	memcpy(out, m->guest.dev_state, m->guest.dev_state_len);
	*buf = out;
	*len = m->guest.dev_state_len;
	return (0);
}

static void
src_defunct(void *arg)
{
	struct source_model *m = arg;

	m->defunct = true;
}

/* Protocol 2: every migration retires the source after a bound COMMIT and
 * retains, never discards, a committed destination (defined below). */
static int model_retire(void *);
static int model_accept_commit(void *, const struct migration_commit_binding *);
static int model_prepare_commit(void *, struct migration_commit_binding *);
static void model_dest_retain(void *, const struct migration_commit_binding *);
static int model_source_record(void *, enum migration_recovery_phase, const uint8_t[32]);
static int model_dest_record(void *, enum migration_recovery_phase, const uint8_t[32]);

/* Journal records are written for every migration; models without a
 * journal accept them. */
static int
noop_record(void *arg, enum migration_recovery_phase phase, const uint8_t challenge[32])
{
	(void)arg;
	(void)phase;
	(void)challenge;
	return (0);
}

static const struct migration_source_ops source_ops = {
	.so_local_hello = src_hello,
	.so_local_topology = src_topology,
	.so_precopy_enable = src_precopy_enable,
	.so_precopy_round = src_precopy_round,
	.so_precopy_disable = src_precopy_disable,
	.so_quiesce = src_quiesce,
	.so_resume = src_resume,
	.so_dev_state = src_dev_state,
	.so_defunct = src_defunct,
	.so_retire = model_retire,
	.so_accept_commit = model_accept_commit,
	.so_record = model_source_record,
};

/* ---- dest ops ---- */

static int
dst_hello(void *arg, struct migration_hello *h)
{

	(void)arg;
	*h = sample_hello();
	h->role = MIGRATION_ROLE_DEST;
	return (0);
}

static int
dst_topology(void *arg, struct migration_topology *t)
{

	(void)arg;
	model_fill_topology(t);
	return (0);
}

static int
dst_fresh_hello(void *arg, struct migration_hello *hello)
{
	int error = dst_hello(arg, hello);
	hello->capability_flags |= MIGRATION_CAP_HYPERTRACE_FRESH;
	return (error);
}

/* A topology model that mismatches memory, forcing a pre-quiesce rejection. */
static int
dst_topology_mismatch(void *arg, struct migration_topology *t)
{

	(void)arg;
	model_fill_topology(t);
	t->mem_size += MODEL_PAGE_SIZE;
	return (0);
}

static int
dst_stage_mem(void *arg, const struct migration_memgen *gen,
    const uint8_t *buf, size_t len)
{
	struct dest_model *m = arg;
	size_t off;

	(void)gen;
	off = 0;
	while (off + 8 <= len) {
		uint64_t gpa;
		int p;

		gpa = le64dec(buf + off);
		off += 8;
		p = (int)(gpa / MODEL_PAGE_SIZE);
		if (p < 0 || p >= MODEL_PAGES || off + MODEL_PAGE_SIZE > len)
			return (EBADMSG);
		memcpy(m->staged.pages[p], buf + off, MODEL_PAGE_SIZE);
		off += MODEL_PAGE_SIZE;
	}
	return (off == len ? 0 : EBADMSG);
}

static int
dst_stage_dev(void *arg, const uint8_t *buf, size_t len)
{
	struct dest_model *m = arg;

	if (len > sizeof(m->staged.dev_state))
		return (ENOSPC);
	memcpy(m->staged.dev_state, buf, len);
	m->staged.dev_state_len = len;
	return (0);
}

static int
dst_commit(void *arg)
{
	struct dest_model *m = arg;

	if (m->fail_commit != 0)
		return (m->fail_commit);
	m->published = m->staged;
	m->committed = true;
	return (0);
}

static int
dst_resume(void *arg)
{
	struct dest_model *m = arg;

	m->resume_attempts++;
	if (m->fail_resume != 0)
		return (m->fail_resume);
	m->resumed = true;
	return (0);
}

static void
dst_discard(void *arg)
{
	struct dest_model *m = arg;

	m->discarded = true;
	memset(&m->staged, 0, sizeof(m->staged));
}

static const struct migration_dest_ops dest_ops = {
	.do_local_hello = dst_hello,
	.do_local_topology = dst_topology,
	.do_stage_mem = dst_stage_mem,
	.do_stage_dev = dst_stage_dev,
	.do_commit = dst_commit,
	.do_resume = dst_resume,
	.do_discard = dst_discard,
	.do_prepare_commit = model_prepare_commit,
	.do_retain = model_dest_retain,
	.do_record = model_dest_record,
};

/* ---- loopback harness ---- */

struct party_arg {
	struct migration_transport xp;
	struct migration_transport_fd fdx;
	const struct migration_dest_ops *ops;
	const struct migration_session_config *config;
	void *ops_arg;
	int error;
	struct migration_dest_result result;
};

static void *
dest_thread(void *v)
{
	struct party_arg *a = v;

	a->error = migration_dest_run(&a->xp, a->ops, a->ops_arg, a->config,
	    &a->result);
	return (NULL);
}

/*
 * Drive one full in-process migration: the destination runs in a thread, the
 * source runs on the caller, connected by a socketpair through the real fd
 * transport.  dops selects the destination behaviour (default or a rejecting
 * variant).
 */
static void
run_loopback_ops(struct source_model *src, struct dest_model *dst,
    const struct migration_dest_ops *dops,
    const struct migration_session_config *src_cfg,
    const struct migration_session_config *dst_cfg,
    struct migration_source_result *src_res,
    struct dest_model **dst_out, int *src_err, int *dst_err)
{
	struct party_arg dparg;
	struct migration_transport src_xp;
	struct migration_transport_fd src_fdx;
	pthread_t dtid;
	int sv[2];

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

	memset(&dparg, 0, sizeof(dparg));
	migration_transport_fd_init(&dparg.xp, &dparg.fdx, sv[1], 5000);
	dparg.ops = dops;
	dparg.config = dst_cfg;
	dparg.ops_arg = dst;
	ATF_REQUIRE_EQ(pthread_create(&dtid, NULL, dest_thread, &dparg), 0);

	migration_transport_fd_init(&src_xp, &src_fdx, sv[0], 5000);
	*src_err = migration_source_run(&src_xp, &source_ops, src, src_cfg,
	    src_res);

	ATF_REQUIRE_EQ(pthread_join(dtid, NULL), 0);
	*dst_err = dparg.error;
	if (dst_out != NULL)
		*dst_out = dst;
	close(sv[0]);
	close(sv[1]);
}

static void
run_loopback(struct source_model *src, struct dest_model *dst,
    const struct migration_session_config *src_cfg,
    const struct migration_session_config *dst_cfg,
    struct migration_source_result *src_res,
    struct dest_model **dst_out, int *src_err, int *dst_err)
{

	run_loopback_ops(src, dst, &dest_ops, src_cfg, dst_cfg, src_res,
	    dst_out, src_err, dst_err);
}

static struct migration_session_config
base_config(void)
{
	struct migration_session_config c;

	memset(&c, 0, sizeof(c));
	c.version_max = MIGRATION_PROTO_VERSION;
	c.version_min = MIGRATION_PROTO_VERSION_MIN;
	c.max_rounds = 8;
	return (c);
}

ATF_TC_WITHOUT_HEAD(source_rejects_wrapping_round_limit);
ATF_TC_BODY(source_rejects_wrapping_round_limit, tc)
{
	struct migration_session_config cfg;
	struct migration_source_result result;
	struct source_model source;
	struct migration_transport transport;

	(void)tc;
	ATF_CHECK(migration_max_rounds_valid(0));
	ATF_CHECK(migration_max_rounds_valid(UINT32_MAX - 1));
	ATF_CHECK(!migration_max_rounds_valid(UINT32_MAX));
	ATF_CHECK(!migration_max_rounds_valid(UINT64_MAX));
	cfg = base_config();
	cfg.max_rounds = UINT32_MAX;
	memset(&source, 0, sizeof(source));
	memset(&transport, 0, sizeof(transport));
	transport.xp_send = migration_fd_send;
	transport.xp_recv = migration_fd_recv;
	memset(&result, 0, sizeof(result));
	ATF_CHECK_EQ(migration_source_run(&transport, &source_ops, &source,
	    &cfg, &result), EINVAL);
	ATF_CHECK_EQ(result.phase, (uint32_t)MIGRATION_PHASE_FAILED);
	ATF_CHECK_EQ(result.reason, (uint32_t)MIGRATION_REASON_STATE);
	ATF_CHECK(result.source_runnable);
	ATF_CHECK(!source.quiesced);
}

ATF_TC_WITHOUT_HEAD(loopback_migration_succeeds);
ATF_TC_BODY(loopback_migration_succeeds, tc)
{
	struct source_model src;
	struct dest_model dst;
	struct migration_source_result sres;
	struct migration_session_config cfg;
	struct dest_model *dstate;
	int serr, derr;

	(void)tc;
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	/* Distinct page + device content the destination must reproduce. */
	for (int p = 0; p < MODEL_PAGES; p++)
		memset(src.guest.pages[p], 0x40 + p, MODEL_PAGE_SIZE);
	memset(src.guest.dev_state, 0xab, 64);
	src.guest.dev_state_len = 64;
	src.converge_after = 3;
	cfg = base_config();

	run_loopback(&src, &dst, &cfg, &cfg, &sres, &dstate, &serr, &derr);

	ATF_CHECK_EQ(serr, 0);
	ATF_CHECK_EQ(derr, 0);
	ATF_CHECK_EQ(sres.phase, (uint32_t)MIGRATION_PHASE_COMPLETED);
	ATF_CHECK_EQ(sres.negotiated_version, (uint16_t)MIGRATION_PROTO_VERSION);
	ATF_CHECK(!sres.source_runnable);
	ATF_CHECK(src.defunct);
	ATF_CHECK(dstate->committed);
	ATF_CHECK(dstate->resumed);
	/* On the committed path the destination must not have discarded state. */
	ATF_CHECK(!dstate->discarded);
	/* The published destination image matches the source page-for-page. */
	for (int p = 0; p < MODEL_PAGES; p++) {
		ATF_CHECK_EQ(memcmp(dstate->published.pages[p],
		    src.guest.pages[p], MODEL_PAGE_SIZE), 0);
	}
	ATF_CHECK_EQ(dstate->published.dev_state_len, 64u);
	ATF_CHECK_EQ(memcmp(dstate->published.dev_state, src.guest.dev_state,
	    64), 0);
}

ATF_TC_WITHOUT_HEAD(destination_rejects_topology_before_quiesce);
ATF_TC_BODY(destination_rejects_topology_before_quiesce, tc)
{
	struct source_model src;
	struct dest_model dst;
	struct migration_source_result sres;
	struct migration_session_config cfg;
	struct migration_dest_ops rej_ops;
	struct dest_model *dstate;
	int serr, derr;

	(void)tc;
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	src.converge_after = 1;
	cfg = base_config();
	/* A destination whose topology model mismatches the source memory. */
	rej_ops = dest_ops;
	rej_ops.do_local_topology = dst_topology_mismatch;

	run_loopback_ops(&src, &dst, &rej_ops, &cfg, &cfg, &sres, &dstate,
	    &serr, &derr);

	/* Source stays runnable; it never quiesced. */
	ATF_CHECK(serr != 0);
	ATF_CHECK(sres.source_runnable);
	ATF_CHECK(!src.quiesced);
	ATF_CHECK(!src.defunct);
	ATF_CHECK_EQ(sres.reason, (uint32_t)MIGRATION_REASON_MEMSIZE);
	/* Destination rejected and published nothing. */
	ATF_CHECK(derr != 0);
	ATF_CHECK(!dstate->committed);
	ATF_CHECK(!dstate->resumed);
}

ATF_TC_WITHOUT_HEAD(source_rolls_back_when_destination_commit_fails);
ATF_TC_BODY(source_rolls_back_when_destination_commit_fails, tc)
{
	struct source_model src;
	struct dest_model dst;
	struct migration_source_result sres;
	struct migration_session_config cfg;
	struct dest_model *dstate;
	int serr, derr;

	(void)tc;
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	src.converge_after = 2;
	dst.fail_commit = EIO;		/* destination cannot commit */
	cfg = base_config();

	run_loopback(&src, &dst, &cfg, &cfg, &sres, &dstate, &serr, &derr);

	/* Source quiesced for the cut, then rolled back to runnable. */
	ATF_CHECK(serr != 0);
	ATF_CHECK(sres.source_runnable);
	ATF_CHECK(src.resumed_after_rollback);
	ATF_CHECK(!src.defunct);
	ATF_CHECK_EQ(sres.phase, (uint32_t)MIGRATION_PHASE_ROLLED_BACK);
	/* Destination did not resume and discarded staged state. */
	ATF_CHECK(derr != 0);
	ATF_CHECK(!dstate->resumed);
	ATF_CHECK(dstate->discarded);
}

ATF_TC_WITHOUT_HEAD(convergence_limit_aborts_and_keeps_source);
ATF_TC_BODY(convergence_limit_aborts_and_keeps_source, tc)
{
	struct source_model src;
	struct dest_model dst;
	struct migration_source_result sres;
	struct migration_session_config cfg;
	struct dest_model *dstate;
	int serr, derr;

	(void)tc;
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	src.converge_after = 0;		/* never converges */
	cfg = base_config();
	cfg.max_rounds = 3;
	cfg.abort_if_unconverged = true;

	run_loopback(&src, &dst, &cfg, &cfg, &sres, &dstate, &serr, &derr);

	ATF_CHECK(serr != 0);
	ATF_CHECK_EQ(sres.reason, (uint32_t)MIGRATION_REASON_CONVERGENCE);
	ATF_CHECK(sres.source_runnable);
	ATF_CHECK(!src.quiesced);
	ATF_CHECK(!src.defunct);
	ATF_CHECK_EQ(sres.rounds, 3u);
	/* Destination saw an abort and never resumed. */
	ATF_CHECK(!dstate->resumed);
}

ATF_TC_WITHOUT_HEAD(cancellation_midcopy_keeps_source);
ATF_TC_BODY(cancellation_midcopy_keeps_source, tc)
{
	struct source_model src;
	struct dest_model dst;
	struct migration_source_result sres;
	struct migration_session_config cfg;
	struct dest_model *dstate;
	int serr, derr;
	static volatile int cancel;

	(void)tc;
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	src.converge_after = 0;		/* keep pre-copying */
	cancel = 1;			/* operator cancels immediately */
	cfg = base_config();
	cfg.max_rounds = 8;
	cfg.cancel = &cancel;

	run_loopback(&src, &dst, &cfg, &cfg, &sres, &dstate, &serr, &derr);

	ATF_CHECK_EQ(serr, ECANCELED);
	ATF_CHECK_EQ(sres.reason, (uint32_t)MIGRATION_REASON_CANCELLED);
	ATF_CHECK(sres.source_runnable);
	ATF_CHECK(!src.quiesced);
	ATF_CHECK(!src.defunct);
	ATF_CHECK(!dstate->resumed);
}

/*
 * The receive path enforces strict per-sender sequence monotonicity: the next
 * frame must carry exactly recv_seq + 1.  A skipped or replayed sequence number
 * is rejected rather than applied, so a malicious/reordered peer cannot inject
 * an out-of-order generation.  All frames here are payload-free so a rejected
 * header leaves nothing unconsumed on the stream.
 */
ATF_TC_WITHOUT_HEAD(recv_enforces_sequence_monotonicity);
ATF_TC_BODY(recv_enforces_sequence_monotonicity, tc)
{
	struct migration_session sess;
	struct migration_transport xp;
	struct migration_transport_fd fdx;
	struct migration_frame_header hdr;
	uint8_t frame[MIGRATION_FRAME_HDR_SIZE + 1], byte = 0x5a;
	uint8_t *payload;
	size_t payload_len, written;
	int sv[2];

	(void)tc;
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	migration_transport_fd_init(&xp, &fdx, sv[0], 5000);
	memset(&sess, 0, sizeof(sess));
	sess.xp = &xp;
	memset(&hdr, 0xa5, sizeof(hdr));

	/* A frame that skips ahead (seq 2 when 1 is expected) is rejected. */
	ATF_REQUIRE_EQ(migration_frame_encode(MIGRATION_PROTO_VERSION,
	    MIGRATION_MSG_MEM_ACK, 2, 0, NULL, 0, frame, sizeof(frame),
	    &written), 0);
	ATF_REQUIRE_EQ(write(sv[1], frame, written), (ssize_t)written);
	ATF_CHECK_EQ(migration_recv(&sess, &hdr, &payload, &payload_len),
	    EBADMSG);
	ATF_CHECK_EQ(hdr.magic, UINT32_C(0xa5a5a5a5));
	ATF_CHECK_EQ(payload, NULL);
	ATF_CHECK_EQ(payload_len, 0u);

	/* The correctly-sequenced frame (seq 1) is accepted. */
	ATF_REQUIRE_EQ(migration_frame_encode(MIGRATION_PROTO_VERSION,
	    MIGRATION_MSG_MEM_ACK, 1, 0, NULL, 0, frame, sizeof(frame),
	    &written), 0);
	ATF_REQUIRE_EQ(write(sv[1], frame, written), (ssize_t)written);
	ATF_CHECK_EQ(migration_recv(&sess, &hdr, &payload, &payload_len), 0);

	/* A replay of seq 1 (now expecting seq 2) is rejected. */
	ATF_REQUIRE_EQ(write(sv[1], frame, written), (ssize_t)written);
	ATF_CHECK_EQ(migration_recv(&sess, &hdr, &payload, &payload_len),
	    EBADMSG);
	ATF_CHECK_EQ(hdr.seq, 1u);

	/* The next in-order frame (seq 2) is accepted. */
	ATF_REQUIRE_EQ(migration_frame_encode(MIGRATION_PROTO_VERSION,
	    MIGRATION_MSG_MEM_ACK, 2, 0, NULL, 0, frame, sizeof(frame),
	    &written), 0);
	ATF_REQUIRE_EQ(write(sv[1], frame, written), (ssize_t)written);
	ATF_CHECK_EQ(migration_recv(&sess, &hdr, &payload, &payload_len), 0);
	ATF_CHECK_EQ(hdr.seq, 2u);

	/* A matching sequence with a bad CRC cannot publish its header. */
	ATF_REQUIRE_EQ(migration_frame_encode(MIGRATION_PROTO_VERSION,
	    MIGRATION_MSG_MEM_ACK, 3, 0, &byte, sizeof(byte), frame,
	    sizeof(frame),
	    &written), 0);
	frame[MIGRATION_FRAME_HDR_SIZE] ^= 1;
	ATF_REQUIRE_EQ(write(sv[1], frame, written), (ssize_t)written);
	ATF_CHECK_EQ(migration_recv(&sess, &hdr, &payload, &payload_len),
	    EBADMSG);
	ATF_CHECK_EQ(hdr.seq, 2u);
	ATF_CHECK_EQ(sess.recv_seq, 2u);
	ATF_CHECK_EQ(payload, NULL);
	ATF_CHECK_EQ(payload_len, 0u);
	frame[MIGRATION_FRAME_HDR_SIZE] ^= 1;
	ATF_REQUIRE_EQ(write(sv[1], frame, written), (ssize_t)written);
	ATF_CHECK_EQ(migration_recv(&sess, &hdr, &payload, &payload_len), 0);
	ATF_CHECK_EQ(hdr.seq, 3u);
	ATF_CHECK_EQ(payload_len, sizeof(byte));
	ATF_CHECK_EQ(payload[0], byte);
	free(payload);

	/* Sequence exhaustion is terminal; zero must never be accepted next. */
	sess.recv_seq = UINT32_MAX;
	ATF_REQUIRE_EQ(migration_frame_encode(MIGRATION_PROTO_VERSION,
	    MIGRATION_MSG_MEM_ACK, 0, 0, NULL, 0, frame, sizeof(frame),
	    &written), 0);
	ATF_REQUIRE_EQ(write(sv[1], frame, written), (ssize_t)written);
	ATF_CHECK_EQ(migration_recv(&sess, &hdr, &payload, &payload_len),
	    EOVERFLOW);
	ATF_CHECK_EQ(hdr.seq, 3u);
	sess.send_seq = UINT32_MAX;
	ATF_CHECK_EQ(migration_send(&sess, MIGRATION_MSG_MEM_ACK, 0,
	    NULL, 0), EOVERFLOW);
	ATF_CHECK_EQ(sess.send_seq, UINT32_MAX);

	close(sv[0]);
	close(sv[1]);
}

/*
 * A hand-rolled source that speaks the wire protocol all the way through the
 * destination's COMMIT, then ABORTs instead of sending RELEASE.  Used to prove
 * the central one-copy invariant on the destination: even after a successful
 * commit it will not run the guest without RELEASE.
 */
static void
fake_source_commit_then_finish(int fd, int mode)
{
	struct migration_session s;
	struct migration_transport xp;
	struct migration_transport_fd fdx;
	struct migration_frame_header hdr;
	struct migration_hello h;
	struct migration_topology *t;
	struct migration_caps_accept caps;
	struct migration_memgen gen;
	uint8_t hello_wire[MIGRATION_HELLO_SIZE];
	uint8_t dev[64];
	uint8_t *topo_wire, *mem, *payload;
	size_t topo_len, wrote, payload_len, off;

	migration_transport_fd_init(&xp, &fdx, fd, 5000);
	memset(&s, 0, sizeof(s));
	s.xp = &xp;

	/* HELLO -> CAPS_ACCEPT */
	h = sample_hello();
	h.role = MIGRATION_ROLE_SOURCE;
	h.version_max = MIGRATION_PROTO_VERSION;
	h.version_min = MIGRATION_PROTO_VERSION_MIN;
	ATF_REQUIRE_EQ(migration_hello_encode(&h, hello_wire,
	    sizeof(hello_wire)), 0);
	ATF_REQUIRE_EQ(migration_send(&s, MIGRATION_MSG_HELLO, 0, hello_wire,
	    sizeof(hello_wire)), 0);
	ATF_REQUIRE_EQ(migration_recv(&s, &hdr, &payload, &payload_len), 0);
	ATF_REQUIRE_EQ(hdr.type, MIGRATION_MSG_CAPS_ACCEPT);
	ATF_REQUIRE_EQ(migration_caps_accept_decode(payload, payload_len,
	    &caps), 0);
	free(payload);
	s.version = caps.negotiated_version;

	/* TOPOLOGY -> TOPO_ACCEPT */
	t = calloc(1, sizeof(*t));
	ATF_REQUIRE(t != NULL);
	model_fill_topology(t);
	topo_len = migration_topology_wire_size(t);
	topo_wire = malloc(topo_len);
	ATF_REQUIRE(topo_wire != NULL);
	ATF_REQUIRE_EQ(migration_topology_encode(t, topo_wire, topo_len,
	    &wrote), 0);
	ATF_REQUIRE_EQ(migration_send(&s, MIGRATION_MSG_TOPOLOGY, 0, topo_wire,
	    wrote), 0);
	free(topo_wire);
	free(t);
	ATF_REQUIRE_EQ(migration_recv(&s, &hdr, &payload, &payload_len), 0);
	ATF_REQUIRE_EQ(hdr.type, MIGRATION_MSG_TOPO_ACCEPT);
	free(payload);

	/* One MEM_GEN carrying every page (model page format) -> MEM_ACK. */
	mem = malloc(MIGRATION_MEMGEN_HDR_SIZE +
	    MODEL_PAGES * (8 + MODEL_PAGE_SIZE));
	ATF_REQUIRE(mem != NULL);
	memset(&gen, 0, sizeof(gen));
	gen.round = 1;
	gen.final = 1;
	gen.length = MODEL_MEM;
	ATF_REQUIRE_EQ(migration_memgen_encode(&gen, mem,
	    MIGRATION_MEMGEN_HDR_SIZE), 0);
	off = MIGRATION_MEMGEN_HDR_SIZE;
	for (int p = 0; p < MODEL_PAGES; p++) {
		le64enc(mem + off, (uint64_t)p * MODEL_PAGE_SIZE);
		off += 8;
		memset(mem + off, 0x5a, MODEL_PAGE_SIZE);
		off += MODEL_PAGE_SIZE;
	}
	ATF_REQUIRE_EQ(migration_send(&s, MIGRATION_MSG_MEM_GEN, 0, mem, off), 0);
	free(mem);
	ATF_REQUIRE_EQ(migration_recv(&s, &hdr, &payload, &payload_len), 0);
	ATF_REQUIRE_EQ(hdr.type, MIGRATION_MSG_MEM_ACK);
	free(payload);

	/* DEV_STATE + FINAL -> COMMIT */
	memset(dev, 0xcd, sizeof(dev));
	ATF_REQUIRE_EQ(migration_send(&s, MIGRATION_MSG_DEV_STATE, 0, dev,
	    sizeof(dev)), 0);
	ATF_REQUIRE_EQ(migration_send_reason(&s, MIGRATION_MSG_FINAL,
	    MIGRATION_REASON_NONE, 0), 0);
	ATF_REQUIRE_EQ(migration_recv(&s, &hdr, &payload, &payload_len), 0);
	ATF_REQUIRE_EQ(hdr.type, MIGRATION_MSG_COMMIT);
	/* Protocol 2: COMMIT is the 80-byte FMC1 binding with the challenge. */
	ATF_REQUIRE_EQ(payload_len, MIGRATION_FRESH_COMMIT_SIZE);
	ATF_REQUIRE(memcmp(payload, "FMC1", 4) == 0);
	uint8_t release[MIGRATION_FRESH_RELEASE_SIZE] = {0};
	memcpy(release + MIGRATION_REASON_SIZE, payload + 16,
	    MIGRATION_FRESH_CHALLENGE_SIZE);
	free(payload);

	if (mode == 0)
		(void)migration_send_reason(&s, MIGRATION_MSG_ABORT,
		    MIGRATION_REASON_CANCELLED, 0);
	else if (mode == 1)
		(void)migration_send(&s, MIGRATION_MSG_RELEASE, 0, NULL, 0);
	else if (mode == 2)
		(void)migration_send_reason(&s, MIGRATION_MSG_RELEASE,
		    MIGRATION_REASON_STATE, 0);
	else if (mode == 3)
		(void)migration_send_reason(&s, MIGRATION_MSG_RELEASE,
		    MIGRATION_REASON_NONE, 1);
	else if (mode == 4) {
		uint8_t extended[MIGRATION_REASON_SIZE + 1] = {0};
		(void)migration_send(&s, MIGRATION_MSG_RELEASE, 0, extended,
		    sizeof(extended));
	} else if (mode == 6) {
		/* A protocol 1 success RELEASE: no challenge. */
		(void)migration_send_reason(&s, MIGRATION_MSG_RELEASE,
		    MIGRATION_REASON_NONE, 0);
	} else if (mode == 7) {
		release[MIGRATION_REASON_SIZE] ^= 1;	/* another challenge */
		(void)migration_send(&s, MIGRATION_MSG_RELEASE, 0, release,
		    sizeof(release));
	} else {
		/* Success: zero reason/detail and the exact challenge; the
		 * destination acknowledges after resuming. */
		ATF_REQUIRE_EQ(migration_send(&s, MIGRATION_MSG_RELEASE, 0, release,
		    sizeof(release)), 0);
		ATF_REQUIRE_EQ(migration_recv(&s, &hdr, &payload, &payload_len), 0);
		ATF_REQUIRE_EQ(hdr.type, MIGRATION_MSG_RELEASE_ACK);
		free(payload);
	}
}

ATF_TC_WITHOUT_HEAD(destination_without_release_does_not_run);
ATF_TC_BODY(destination_without_release_does_not_run, tc)
{
	struct dest_model dst;
	struct migration_session_config cfg;
	struct party_arg dparg;
	pthread_t dtid;
	int sv[2];

	(void)tc;
	memset(&dst, 0, sizeof(dst));
	cfg = base_config();

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	memset(&dparg, 0, sizeof(dparg));
	migration_transport_fd_init(&dparg.xp, &dparg.fdx, sv[1], 5000);
	dparg.ops = &dest_ops;
	dparg.config = &cfg;
	dparg.ops_arg = &dst;
	ATF_REQUIRE_EQ(pthread_create(&dtid, NULL, dest_thread, &dparg), 0);

	fake_source_commit_then_finish(sv[0], 0);

	ATF_REQUIRE_EQ(pthread_join(dtid, NULL), 0);
	close(sv[0]);
	close(sv[1]);

	/*
	 * The destination committed all state but never received RELEASE.  It
	 * must NOT resume (one copy), and since protocol 2 it must not discard
	 * either: after COMMIT the source may already be retired, so the
	 * committed image is retained for operator resolution.
	 */
	ATF_CHECK(dparg.error != 0);
	ATF_CHECK(dst.committed);
	ATF_CHECK(!dst.resumed);
	ATF_CHECK(!dst.discarded);
	ATF_CHECK(dst.retained);
}

ATF_TC_WITHOUT_HEAD(destination_requires_successful_release);
ATF_TC_BODY(destination_requires_successful_release, tc)
{
	(void)tc;
	/* 1-4 malformed results, 5 success, 6 a protocol 1 RELEASE without the
	 * challenge, 7 another challenge. */
	for (int mode = 1; mode <= 7; mode++) {
		struct dest_model dst = {0};
		struct migration_session_config cfg = base_config();
		struct party_arg dparg = {0};
		pthread_t dtid;
		int sv[2];

		ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
		migration_transport_fd_init(&dparg.xp, &dparg.fdx, sv[1], 5000);
		dparg.ops = &dest_ops;
		dparg.config = &cfg;
		dparg.ops_arg = &dst;
		ATF_REQUIRE_EQ(pthread_create(&dtid, NULL, dest_thread, &dparg), 0);
		fake_source_commit_then_finish(sv[0], mode);
		ATF_REQUIRE_EQ(pthread_join(dtid, NULL), 0);
		close(sv[0]);
		close(sv[1]);
		ATF_CHECK(dst.committed);
		ATF_CHECK_EQ(dst.resumed, mode == 5);
		ATF_CHECK(!dst.discarded);
		ATF_CHECK_EQ(dst.retained, mode != 5);
		ATF_CHECK_EQ(dparg.error, mode == 5 ? 0 : EPROTO);
	}
}

/*
 * The source fails to serialize device/backend state at cutover, after it has
 * already quiesced.  This is the exact shape of the production fail-closed
 * boundary (prod_dev_state returns EOPNOTSUPP): the source must roll back to
 * runnable and the destination must discard, never resuming.
 */
ATF_TC_WITHOUT_HEAD(source_rolls_back_when_dev_state_fails);
ATF_TC_BODY(source_rolls_back_when_dev_state_fails, tc)
{
	struct source_model src;
	struct dest_model dst;
	struct migration_source_result sres;
	struct migration_session_config cfg;
	struct dest_model *dstate;
	int serr, derr;

	(void)tc;
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	src.converge_after = 2;
	src.fail_dev_state = EOPNOTSUPP;	/* fail-closed cutover boundary */
	cfg = base_config();

	run_loopback(&src, &dst, &cfg, &cfg, &sres, &dstate, &serr, &derr);

	/* Source quiesced for the cut, then rolled back to runnable. */
	ATF_CHECK(serr != 0);
	ATF_CHECK(sres.source_runnable);
	ATF_CHECK(!src.quiesced);
	ATF_CHECK(src.resumed_after_rollback);
	ATF_CHECK(!src.defunct);
	ATF_CHECK_EQ(sres.phase, (uint32_t)MIGRATION_PHASE_ROLLED_BACK);
	/* Destination never committed and discarded staged state. */
	ATF_CHECK(derr != 0);
	ATF_CHECK(!dstate->committed);
	ATF_CHECK(!dstate->resumed);
	ATF_CHECK(dstate->discarded);
}

/*
 * A rollback is only successful if the quiesced source can actually resume.
 * If the device fabric resume fails, it must remain stopped rather than being
 * reported as a runnable source after a failed handoff.
 */
ATF_TC_WITHOUT_HEAD(source_resume_failure_stays_fail_closed);
ATF_TC_BODY(source_resume_failure_stays_fail_closed, tc)
{
	struct source_model src;
	struct dest_model dst;
	struct migration_source_result sres;
	struct migration_session_config cfg;
	struct dest_model *dstate;
	int serr, derr;

	(void)tc;
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	src.converge_after = 2;
	src.fail_dev_state = EOPNOTSUPP;
	src.fail_resume = EIO;
	cfg = base_config();

	run_loopback(&src, &dst, &cfg, &cfg, &sres, &dstate, &serr, &derr);

	/* Keep the original cutover failure while recording failed rollback. */
	ATF_CHECK_EQ(serr, EOPNOTSUPP);
	ATF_CHECK(!sres.source_runnable);
	ATF_CHECK(src.quiesced);
	ATF_CHECK(!src.resumed_after_rollback);
	ATF_CHECK(!src.defunct);
	ATF_CHECK_EQ(sres.phase, (uint32_t)MIGRATION_PHASE_FAILED);
	ATF_CHECK_EQ(sres.reason, (uint32_t)MIGRATION_REASON_STATE);
	ATF_CHECK(derr != 0);
	ATF_CHECK(!dstate->committed);
	ATF_CHECK(!dstate->resumed);
	ATF_CHECK(dstate->discarded);
}

/*
 * A quiesce that fails but cleanly rolls back leaves the source running: it
 * must be reported runnable and never marked quiesced.
 */
ATF_TC_WITHOUT_HEAD(source_quiesce_failure_rolls_back_runnable);
ATF_TC_BODY(source_quiesce_failure_rolls_back_runnable, tc)
{
	struct source_model src;
	struct dest_model dst;
	struct migration_source_result sres;
	struct migration_session_config cfg;
	struct dest_model *dstate;
	int serr, derr;

	(void)tc;
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	src.converge_after = 2;
	src.fail_quiesce = EBUSY;
	src.quiesce_wedged = false;	/* rolled back cleanly */
	cfg = base_config();

	run_loopback(&src, &dst, &cfg, &cfg, &sres, &dstate, &serr, &derr);

	ATF_CHECK_EQ(serr, EBUSY);
	ATF_CHECK(sres.source_runnable);
	ATF_CHECK(!src.quiesced);
	ATF_CHECK(!src.defunct);
	ATF_CHECK_EQ(sres.phase, (uint32_t)MIGRATION_PHASE_FAILED);
	ATF_CHECK_EQ(sres.reason, (uint32_t)MIGRATION_REASON_STATE);
	ATF_CHECK(!dstate->committed);
	ATF_CHECK(!dstate->resumed);
}

/*
 * A quiesce that fails AND cannot roll back leaves the source wedged (vCPUs and
 * devices stopped, unrecoverable).  The session MUST report the source as NOT
 * runnable so the control plane never resumes a second copy elsewhere -- the
 * split-brain guard.
 */
ATF_TC_WITHOUT_HEAD(source_quiesce_wedged_reports_not_runnable);
ATF_TC_BODY(source_quiesce_wedged_reports_not_runnable, tc)
{
	struct source_model src;
	struct dest_model dst;
	struct migration_source_result sres;
	struct migration_session_config cfg;
	struct dest_model *dstate;
	int serr, derr;

	(void)tc;
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	src.converge_after = 2;
	src.fail_quiesce = EIO;
	src.quiesce_wedged = true;	/* rollback failed: source stopped */
	cfg = base_config();

	run_loopback(&src, &dst, &cfg, &cfg, &sres, &dstate, &serr, &derr);

	ATF_CHECK_EQ(serr, EIO);
	ATF_CHECK(!sres.source_runnable);	/* the split-brain guard */
	ATF_CHECK(src.quiesced);
	ATF_CHECK(!src.defunct);
	ATF_CHECK_EQ(sres.phase, (uint32_t)MIGRATION_PHASE_FAILED);
	ATF_CHECK_EQ(sres.reason, (uint32_t)MIGRATION_REASON_STATE);
	/* Destination must not have committed or resumed. */
	ATF_CHECK(!dstate->committed);
	ATF_CHECK(!dstate->resumed);
}

/* ------------------------------------------------------------------------- */
/* Multi-frame chunking coverage						     */
/* ------------------------------------------------------------------------- */

/*
 * migration_chunk_validate is the gate every reassembled chunk passes before a
 * single byte is copied.  It must accept only strictly in-order, contiguous,
 * size-bounded chunks and reject gaps, duplicates, oversize chunks, a shifting
 * total, and an inconsistent final flag.
 */
ATF_TC_WITHOUT_HEAD(chunk_validate_rejects_gap_dup_oversize);
ATF_TC_BODY(chunk_validate_rejects_gap_dup_oversize, tc)
{
	struct migration_chunk c;
	const size_t chunkmax = 4096;
	const size_t cap = 1u << 20;

	(void)tc;
	/* First in-order chunk of a 3000-byte total. */
	memset(&c, 0, sizeof(c));
	c.total_length = 3000;
	c.offset = 0;
	c.chunk_length = 2000;
	c.final = 0;
	ATF_CHECK_EQ(migration_chunk_validate(0, 0, &c, chunkmax, cap), 0);
	/* Contiguous continuation that reaches the total must set final. */
	c.offset = 2000;
	c.chunk_length = 1000;
	c.final = 1;
	ATF_CHECK_EQ(migration_chunk_validate(2000, 3000, &c, chunkmax, cap), 0);
	/* Same continuation without final is inconsistent. */
	c.final = 0;
	ATF_CHECK_EQ(migration_chunk_validate(2000, 3000, &c, chunkmax, cap),
	    EBADMSG);
	/* A gap (offset skips ahead) is rejected. */
	c.offset = 2500;
	c.chunk_length = 500;
	c.final = 1;
	ATF_CHECK_EQ(migration_chunk_validate(2000, 3000, &c, chunkmax, cap),
	    EBADMSG);
	/* A duplicate (offset behind the cursor) is rejected. */
	c.offset = 0;
	c.chunk_length = 2000;
	c.final = 0;
	ATF_CHECK_EQ(migration_chunk_validate(2000, 3000, &c, chunkmax, cap),
	    EBADMSG);
	/* A shifting total is rejected. */
	c.offset = 2000;
	c.total_length = 4000;
	c.chunk_length = 1000;
	c.final = 0;
	ATF_CHECK_EQ(migration_chunk_validate(2000, 3000, &c, chunkmax, cap),
	    EBADMSG);
	/* An oversize single chunk is rejected. */
	memset(&c, 0, sizeof(c));
	c.total_length = 8192;
	c.offset = 0;
	c.chunk_length = 8192;		/* > chunkmax */
	ATF_CHECK_EQ(migration_chunk_validate(0, 0, &c, chunkmax, cap),
	    EMSGSIZE);
	/* A total larger than the reassembly cap is rejected. */
	memset(&c, 0, sizeof(c));
	c.total_length = cap + 1;
	c.offset = 0;
	c.chunk_length = 100;
	ATF_CHECK_EQ(migration_chunk_validate(0, 0, &c, chunkmax, cap),
	    EMSGSIZE);
	/* A chunk overrunning the declared total is rejected. */
	memset(&c, 0, sizeof(c));
	c.total_length = 1000;
	c.offset = 900;
	c.chunk_length = 200;		/* 900 + 200 > 1000 */
	ATF_CHECK_EQ(migration_chunk_validate(900, 1000, &c, chunkmax, cap),
	    EBADMSG);
}

static int
bad_source_round(void *arg, bool final, struct migration_memgen *gen,
    uint8_t *buf, size_t cap, size_t *written, uint64_t *dirty_pages,
    bool *converged, bool *more)
{
	int variant = *(int *)arg;

	(void)final;
	(void)gen;
	(void)buf;
	*written = variant == 0 ? cap + 1 : 0;
	*dirty_pages = 0;
	*converged = false;
	*more = variant != 0;
	return (0);
}

ATF_TC_WITHOUT_HEAD(source_rejects_invalid_memory_chunk_contract);
ATF_TC_BODY(source_rejects_invalid_memory_chunk_contract, tc)
{
	struct migration_session sess;
	struct migration_source_ops ops;
	uint8_t *scratch;
	uint64_t sent, dirty;
	uint32_t reason;
	bool converged;

	(void)tc;
	memset(&sess, 0, sizeof(sess));
	memset(&ops, 0, sizeof(ops));
	ops.so_precopy_round = bad_source_round;
	scratch = malloc(MIGRATION_MAX_PAYLOAD);
	ATF_REQUIRE(scratch != NULL);
	for (int variant = 0; variant < 2; variant++) {
		sent = 0;
		dirty = 0;
		reason = MIGRATION_REASON_NONE;
		converged = false;
		ATF_CHECK_EQ(migration_source_send_generation(&sess, &ops,
		    &variant, false, 1, 0, scratch, &sent, &dirty,
		    &converged, &reason), EPROTO);
		ATF_CHECK_EQ(reason, MIGRATION_REASON_PROTOCOL);
		ATF_CHECK_EQ(sent, (uint64_t)0);
	}
	free(scratch);
}

/* ---- large-device-state dest ops (heap staging, no 128-byte cap) ---- */

struct big_dest_model {
	uint8_t *dev;
	size_t dev_len;
	struct model_guest ram;
	bool committed;
	bool resumed;
	bool discarded;
	bool retained;
};

static int
big_dst_stage_mem(void *arg, const struct migration_memgen *gen,
    const uint8_t *buf, size_t len)
{
	struct big_dest_model *m = arg;
	size_t off;

	(void)gen;
	off = 0;
	while (off + 8 <= len) {
		uint64_t gpa;
		int p;

		gpa = le64dec(buf + off);
		off += 8;
		p = (int)(gpa / MODEL_PAGE_SIZE);
		if (p < 0 || p >= MODEL_PAGES || off + MODEL_PAGE_SIZE > len)
			return (EBADMSG);
		memcpy(m->ram.pages[p], buf + off, MODEL_PAGE_SIZE);
		off += MODEL_PAGE_SIZE;
	}
	return (off == len ? 0 : EBADMSG);
}

static int
big_dst_stage_dev(void *arg, const uint8_t *buf, size_t len)
{
	struct big_dest_model *m = arg;
	uint8_t *copy;

	copy = malloc(len != 0 ? len : 1);
	if (copy == NULL)
		return (ENOMEM);
	memcpy(copy, buf, len);
	free(m->dev);
	m->dev = copy;
	m->dev_len = len;
	return (0);
}

static int
big_dst_hello(void *arg, struct migration_hello *h)
{

	(void)arg;
	*h = sample_hello();
	h->role = MIGRATION_ROLE_DEST;
	return (0);
}

static int
big_dst_topology(void *arg, struct migration_topology *t)
{

	(void)arg;
	model_fill_topology(t);
	return (0);
}

static int
big_dst_commit(void *arg)
{
	struct big_dest_model *m = arg;

	m->committed = true;
	return (0);
}

static int
big_dst_resume(void *arg)
{
	struct big_dest_model *m = arg;

	m->resumed = true;
	return (0);
}

static void
big_dst_discard(void *arg)
{
	struct big_dest_model *m = arg;

	m->discarded = true;
}

/* Protocol 2 binding for models without a journal: fixed identity and a
 * digest the matching source hook checks. */
static int
big_dst_prepare(void *arg, struct migration_commit_binding *binding)
{
	struct big_dest_model *m = arg;

	ATF_REQUIRE(m->committed && !m->resumed);
	binding->destination_vmid = 8;
	binding->destination_epoch = 10;
	memset(binding->state_digest, 0x5a, 32);
	return (0);
}

static void
big_dst_retain(void *arg, const struct migration_commit_binding *binding)
{
	struct big_dest_model *m = arg;

	(void)binding;
	ATF_REQUIRE(m->committed && !m->discarded);
	m->retained = true;
}

static const struct migration_dest_ops big_dest_ops = {
	.do_local_hello = big_dst_hello,
	.do_local_topology = big_dst_topology,
	.do_stage_mem = big_dst_stage_mem,
	.do_stage_dev = big_dst_stage_dev,
	.do_commit = big_dst_commit,
	.do_resume = big_dst_resume,
	.do_discard = big_dst_discard,
	.do_prepare_commit = big_dst_prepare,
	.do_retain = big_dst_retain,
	.do_record = noop_record,
};

struct big_party {
	struct migration_transport xp;
	struct migration_transport_fd fdx;
	struct big_dest_model *dst;
	const struct migration_session_config *config;
	int error;
	struct migration_dest_result result;
};

static void *
big_dest_thread(void *v)
{
	struct big_party *a = v;

	a->error = migration_dest_run(&a->xp, &big_dest_ops, a->dst, a->config,
	    &a->result);
	return (NULL);
}

#define	BIG_DEV_STATE	(34u * 1024u * 1024u)	/* > 2 frames -> 3 chunks */

static uint8_t
big_dev_byte(size_t i)
{

	return ((uint8_t)((i * 31u + 7u) & 0xffu));
}

/*
 * A full loopback migration whose device/CPU-state blob is larger than the
 * 16 MiB frame cap.  This exercises the real dev_state bridge end to end: the
 * source serializes a >16 MiB blob, the session splits it into ordered
 * total/offset-tagged DEV_STATE chunks, and the destination reassembles it,
 * commits, and resumes only after RELEASE.  Model evidence for the cutover
 * control+data path, not a live two-host claim.
 */
ATF_TC_WITHOUT_HEAD(loopback_multiframe_dev_state_reassembles);
ATF_TC_BODY(loopback_multiframe_dev_state_reassembles, tc)
{
	struct source_model src;
	struct big_dest_model dst;
	struct big_party dparg;
	struct migration_transport src_xp;
	struct migration_transport_fd src_fdx;
	struct migration_session_config cfg;
	struct migration_source_result sres;
	uint8_t *big;
	pthread_t dtid;
	int sv[2], serr;

	(void)tc;
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	for (int p = 0; p < MODEL_PAGES; p++)
		memset(src.guest.pages[p], 0x40 + p, MODEL_PAGE_SIZE);
	big = malloc(BIG_DEV_STATE);
	ATF_REQUIRE(big != NULL);
	for (size_t i = 0; i < BIG_DEV_STATE; i++)
		big[i] = big_dev_byte(i);
	src.dev_override = big;
	src.dev_override_len = BIG_DEV_STATE;
	src.converge_after = 1;
	cfg = base_config();

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	memset(&dparg, 0, sizeof(dparg));
	migration_transport_fd_init(&dparg.xp, &dparg.fdx, sv[1], 10000);
	dparg.dst = &dst;
	dparg.config = &cfg;
	ATF_REQUIRE_EQ(pthread_create(&dtid, NULL, big_dest_thread, &dparg), 0);

	migration_transport_fd_init(&src_xp, &src_fdx, sv[0], 10000);
	serr = migration_source_run(&src_xp, &source_ops, &src, &cfg, &sres);
	ATF_REQUIRE_EQ(pthread_join(dtid, NULL), 0);

	ATF_CHECK_EQ(serr, 0);
	ATF_CHECK_EQ(dparg.error, 0);
	ATF_CHECK(!sres.source_runnable);
	ATF_CHECK(src.defunct);
	ATF_CHECK(dst.committed);
	ATF_CHECK(dst.resumed);
	ATF_CHECK(!dst.discarded);
	/* The multi-frame blob reassembled byte-for-byte. */
	ATF_CHECK_EQ(dst.dev_len, (size_t)BIG_DEV_STATE);
	if (dst.dev_len == BIG_DEV_STATE) {
		bool ok = true;
		for (size_t i = 0; i < BIG_DEV_STATE; i++) {
			if (dst.dev[i] != big_dev_byte(i)) {
				ok = false;
				break;
			}
		}
		ATF_CHECK(ok);
	}
	/* Guest RAM still round-tripped alongside the chunked device state. */
	for (int p = 0; p < MODEL_PAGES; p++)
		ATF_CHECK_EQ(memcmp(dst.ram.pages[p], src.guest.pages[p],
		    MODEL_PAGE_SIZE), 0);
	free(dst.dev);
	free(big);
	close(sv[0]);
	close(sv[1]);
}

/* A retirement-aware adapter must never roll back after an ambiguous RELEASE.
 * This model hook is deliberately not wired into the production adapter. */
static int
model_retire(void *arg)
{
	struct source_model *src = arg;

	ATF_REQUIRE(src->quiesced);
	src->retired = true;
	return (src->fail_retire);
}

static int
model_source_record(void *arg, enum migration_recovery_phase phase,
    const uint8_t challenge[32])
{
	struct source_model *src = arg;
	ATF_REQUIRE(src->quiesced);
	ATF_REQUIRE_EQ((int)phase, src->recorded + 1);
	ATF_REQUIRE_EQ(src->retired, phase != MIGRATION_REC_SOURCE_INTENT);
	if (src->recorded == 0)
		memcpy(src->challenge, challenge, 32);
	ATF_REQUIRE(memcmp(src->challenge, challenge, 32) == 0);
	src->recorded = phase;
	return (src->fail_record == (int)phase ? EIO : 0);
}

static int
model_accept_commit(void *arg, const struct migration_commit_binding *binding)
{
	struct source_model *src = arg;
	ATF_REQUIRE(src->quiesced && !src->retired);
	ATF_REQUIRE_EQ(binding->destination_vmid, 8);
	ATF_REQUIRE_EQ(binding->destination_epoch, 10);
	for (size_t i = 0; i < 32; i++) ATF_REQUIRE_EQ(binding->state_digest[i], 0x5a);
	return (src->fail_binding);
}

static int
model_prepare_commit(void *arg, struct migration_commit_binding *binding)
{
	struct dest_model *dst = arg;
	ATF_REQUIRE(dst->committed && !dst->resumed);
	/* Ordinary mode keeps no journal record; the challenge is bound here. */
	if (dst->recorded == 0)
		memcpy(dst->challenge, binding->challenge, 32);
	binding->destination_vmid = 8;
	binding->destination_epoch = 10;
	memset(binding->state_digest, 0x5a, 32);
	return (dst->fail_binding);
}

static int
model_dest_record(void *arg, enum migration_recovery_phase phase,
    const uint8_t challenge[32])
{
	struct dest_model *dst = arg;
	ATF_REQUIRE(dst->committed);
	ATF_REQUIRE_EQ((int)phase, dst->recorded == 0 ?
	    MIGRATION_REC_DEST_STAGED : dst->recorded + 1);
	ATF_REQUIRE_EQ(dst->resumed, phase == MIGRATION_REC_DEST_RUNNING);
	if (dst->recorded == 0)
		memcpy(dst->challenge, challenge, 32);
	ATF_REQUIRE(memcmp(dst->challenge, challenge, 32) == 0);
	dst->recorded = phase;
	return (dst->fail_record == (int)phase ? EIO : 0);
}

/* The durable image must follow the complete binding and precede STAGED. */
static int
model_dest_preserve(void *arg, const struct migration_commit_binding *binding)
{
	struct dest_model *dst = arg;
	ATF_REQUIRE(dst->committed && !dst->resumed && !dst->retained);
	ATF_REQUIRE_EQ(dst->recorded, 0);
	ATF_REQUIRE_EQ(binding->destination_vmid, 8);
	ATF_REQUIRE_EQ(binding->destination_epoch, 10);
	ATF_REQUIRE(memcmp(binding->challenge, (const uint8_t[32]){0}, 32) != 0);
	dst->preserved++;
	memcpy(dst->challenge, binding->challenge, 32);
	return (dst->fail_preserve);
}

static void
model_dest_retain(void *arg, const struct migration_commit_binding *binding)
{
	struct dest_model *dst = arg;
	ATF_REQUIRE(dst->committed && !dst->resumed && !dst->discarded && !dst->retained);
	ATF_REQUIRE(memcmp(binding->challenge, dst->challenge, 32) == 0);
	ATF_REQUIRE_EQ(binding->destination_vmid, 8);
	ATF_REQUIRE_EQ(binding->destination_epoch, 10);
	dst->retained = true;
}

struct retirement_xp {
	struct migration_transport_fd fd;
	struct source_model *source;
	int mode;
	bool release_sent;
};

static int
retirement_send(void *arg, const void *buf, size_t len)
{
	struct retirement_xp *xp = arg;
	const uint8_t *wire = buf;
	bool release = len >= MIGRATION_FRAME_HDR_SIZE &&
	    le16dec(wire + 6) == MIGRATION_MSG_RELEASE;
	int error;

	if (len >= MIGRATION_FRAME_HDR_SIZE &&
	    le16dec(wire + 6) == MIGRATION_MSG_COMMIT && xp->mode >= 8) {
		if (xp->mode == 8)
			return (EPIPE);
		error = migration_fd_send(&xp->fd, buf, len);
		return (error == 0 ? EPIPE : error);
	}
	if (len >= MIGRATION_FRAME_HDR_SIZE &&
	    le16dec(wire + 6) == MIGRATION_MSG_RELEASE_ACK) {
		if (xp->mode == 6)
			return (EPIPE);
		if (xp->mode == 7) {
			error = migration_fd_send(&xp->fd, buf, len);
			return (error == 0 ? EPIPE : error);
		}
	}
	if (release) {
		ATF_REQUIRE(xp->source->retired);
		if (xp->mode == 2)
			return (EPIPE);
		if (xp->mode == 4 || xp->mode == 5) {
			uint8_t altered[MIGRATION_FRAME_HDR_SIZE + MIGRATION_FRESH_RELEASE_SIZE];
			size_t send_length = sizeof(altered);
			ATF_REQUIRE_EQ(len, sizeof(altered));
			memcpy(altered, buf, len);
			if (xp->mode == 4)
				altered[MIGRATION_FRAME_HDR_SIZE + MIGRATION_REASON_SIZE] ^= 1;
			else {
				/* Attempt to downgrade fresh RELEASE to the legacy result. */
				le32enc(altered + 16, MIGRATION_REASON_SIZE);
				send_length = MIGRATION_FRAME_HDR_SIZE + MIGRATION_REASON_SIZE;
			}
			le32enc(altered + 20, migration_crc32(altered +
			    MIGRATION_FRAME_HDR_SIZE, send_length - MIGRATION_FRAME_HDR_SIZE));
			error = migration_fd_send(&xp->fd, altered, send_length);
			xp->release_sent = error == 0;
			return (error);
		}
	}
	error = migration_fd_send(&xp->fd, buf, len);
	if (release && error == 0) {
		xp->release_sent = true;
		if (xp->mode == 3)
			return (EPIPE); /* Delivered, but sender observes failure. */
	}
	return (error);
}

static int
retirement_recv(void *arg, void *buf, size_t len)
{
	struct retirement_xp *xp = arg;
	return (migration_fd_recv(&xp->fd, buf, len));
}

ATF_TC_WITHOUT_HEAD(source_retirement_precedes_release);
ATF_TC_BODY(source_retirement_precedes_release, tc)
{
	(void)tc;
	{
		struct source_model src = {0};
		struct dest_model dst = {0};
		struct migration_dest_ops dops = dest_ops;
		struct migration_session_config cfg = base_config();
		struct migration_source_result result;
		int source_error, destination_error;
		dops.do_local_hello = dst_fresh_hello;
		dops.do_record = model_dest_record;
		dops.do_prepare_commit = model_prepare_commit;
		dops.do_retain = NULL;	/* the hook under test */
		run_loopback_ops(&src, &dst, &dops, &cfg, &cfg, &result,
		    NULL, &source_error, &destination_error);
		ATF_CHECK(source_error != 0);
		ATF_CHECK_EQ(destination_error, EOPNOTSUPP);
		ATF_CHECK(!src.quiesced && !dst.committed && !dst.retained);
	}
	{
		struct source_model src = {0};
		struct migration_source_ops ops = source_ops;
		struct migration_session_config cfg = base_config();
		struct migration_source_result result;
		struct migration_transport transport;
		struct migration_transport_fd fd;
		migration_transport_fd_init(&transport, &fd, -1, 100);
		ops.so_local_hello = src_fresh_hello;
		ops.so_retire = NULL;	/* the hook under test */
		ATF_CHECK_EQ(migration_source_run(&transport, &ops, &src, &cfg,
		    &result), EOPNOTSUPP);
		ATF_CHECK_EQ(result.reason, MIGRATION_REASON_CAPS);
		ATF_CHECK(result.source_runnable && !src.quiesced && !src.retired);
	}
	for (int variant = 0; variant < 14; variant++) {
		bool fresh = variant >= 4;
		int mode = fresh ? variant - 4 : variant;
		struct source_model src = {0};
		struct dest_model dst = {0};
		struct party_arg dest = {0};
		struct migration_source_ops ops = source_ops;
		struct migration_dest_ops dops = dest_ops;
		struct migration_session_config cfg = base_config();
		struct migration_source_result result;
		struct migration_transport transport;
		struct retirement_xp xp = {0};
		struct retirement_xp dest_xp = {0};
		pthread_t thread;
		int sockets[2], error;

		src.converge_after = 1;
		src.fail_retire = mode == 1 ? EIO : 0;
		ops.so_retire = model_retire;
		if (fresh) {
			ops.so_local_hello = src_fresh_hello;
			ops.so_record = model_source_record;
			ops.so_accept_commit = model_accept_commit;
			dops.do_local_hello = dst_fresh_hello;
			dops.do_record = model_dest_record;
			dops.do_prepare_commit = model_prepare_commit;
			dops.do_retain = model_dest_retain;
		}
		ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);
		migration_transport_fd_init(&dest.xp, &dest.fdx, sockets[1], 2000);
		if (mode >= 6) {
			dest_xp.fd.fd = sockets[1];
			dest_xp.fd.recv_timeout_ms = 2000;
			dest_xp.mode = mode;
			dest.xp = (struct migration_transport){
			    .xp_send = retirement_send, .xp_recv = retirement_recv,
			    .xp_cookie = &dest_xp };
		}
		dest.ops = &dops;
		dest.config = &cfg;
		dest.ops_arg = &dst;
		ATF_REQUIRE_EQ(pthread_create(&thread, NULL, dest_thread, &dest), 0);
		xp.fd.fd = sockets[0];
		xp.fd.recv_timeout_ms = 2000;
		xp.source = &src;
		xp.mode = mode;
		transport = (struct migration_transport){
		    .xp_send = retirement_send, .xp_recv = retirement_recv,
		    .xp_cookie = &xp };
		error = migration_source_run(&transport, &ops, &src, &cfg, &result);
		ATF_REQUIRE_EQ(pthread_join(thread, NULL), 0);
		ATF_CHECK_EQ(src.retired, mode != 8);
		ATF_CHECK_EQ(src.resumed_after_rollback, mode == 8);
		ATF_CHECK_EQ(result.source_runnable, mode == 8);
		ATF_CHECK_EQ(error, mode == 0 || mode == 7 ? 0 : mode >= 4 ? ETIMEDOUT :
		    mode == 1 ? EIO : EPIPE);
		ATF_CHECK_EQ(src.defunct, mode == 0 || mode == 7);
		ATF_CHECK_EQ(xp.release_sent, mode == 0 || (mode >= 3 && mode != 8));
		ATF_CHECK_EQ(dst.resumed, mode == 0 || mode == 3 || mode == 6 || mode == 7);
		/* Protocol 2: ordinary destinations retain exactly as fresh ones. */
		ATF_CHECK_EQ(dst.retained, mode == 1 || mode == 2 ||
		    mode == 4 || mode == 5 || mode >= 8);
		ATF_CHECK_EQ(dest.result.retained, dst.retained);
		if (dst.retained) {
			ATF_CHECK(!dst.discarded);
			ATF_CHECK_EQ(dest.result.phase, MIGRATION_PHASE_RECOVERY);
		}
		if (mode == 4 || mode == 5)
			ATF_CHECK_EQ(dest.error, EPROTO);
		if (mode == 6 || mode == 7) {
			ATF_CHECK_EQ(dest.error, 0);
			ATF_CHECK(!dst.discarded && !dest.result.release_ack_sent);
		}
		if (mode >= 8)
			ATF_CHECK_EQ(dest.error, EPIPE);
		ATF_CHECK_EQ(result.phase, (uint32_t)(mode == 0 || mode == 7 ?
		    MIGRATION_PHASE_COMPLETED : mode == 8 ? MIGRATION_PHASE_ROLLED_BACK :
		    MIGRATION_PHASE_FAILED));
		close(sockets[0]);
		close(sockets[1]);
	}
}

/* ---- fault-injecting transport for mid-DEV_STATE failure ---- */

ATF_TC_WITHOUT_HEAD(fresh_recovery_persistence_boundaries);
ATF_TC_BODY(fresh_recovery_persistence_boundaries, tc)
{
	(void)tc;
	for (int failure = 0; failure < 9; failure++) {
		struct source_model src = { .converge_after = 1 };
		struct dest_model dst = {0};
		struct migration_source_ops sops = source_ops;
		struct migration_dest_ops dops = dest_ops;
		struct migration_session_config cfg = base_config();
		struct migration_source_result result;
		struct migration_transport xp;
		struct migration_transport_fd fd;
		struct party_arg dest = {0};
		pthread_t thread;
		int sockets[2], error;

		sops.so_local_hello = src_fresh_hello;
		sops.so_retire = model_retire;
		sops.so_record = model_source_record;
		sops.so_accept_commit = model_accept_commit;
		dops.do_local_hello = dst_fresh_hello;
		dops.do_record = model_dest_record;
		dops.do_prepare_commit = model_prepare_commit;
		dops.do_retain = model_dest_retain;
		if (failure < 4) src.fail_record = failure + 1;
		else if (failure < 7) dst.fail_record = MIGRATION_REC_DEST_STAGED + failure - 4;
		else if (failure == 7) src.fail_binding = EPROTO;
		else dst.fail_binding = EIO;
		ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);
		migration_transport_fd_init(&xp, &fd, sockets[0], 1000);
		migration_transport_fd_init(&dest.xp, &dest.fdx, sockets[1], 1000);
		dest.ops = &dops; dest.config = &cfg; dest.ops_arg = &dst;
		ATF_REQUIRE_EQ(pthread_create(&thread, NULL, dest_thread, &dest), 0);
		error = migration_source_run(&xp, &sops, &src, &cfg, &result);
		ATF_REQUIRE_EQ(pthread_join(thread, NULL), 0);
		ATF_CHECK_EQ(error, failure < 4 ? EIO : failure == 4 || failure == 8 ?
		    ECONNRESET : failure == 7 ? EPROTO : ETIMEDOUT);
		ATF_CHECK_EQ(src.retired, failure != 0 && failure != 4 && failure < 7);
		ATF_CHECK_EQ(src.resumed_after_rollback, failure == 4 || failure >= 7);
		ATF_CHECK_EQ(result.source_runnable, failure == 4 || failure >= 7);
		ATF_CHECK(!src.defunct);
		ATF_CHECK_EQ(dst.resumed, failure == 3 || failure == 6);
		ATF_CHECK_EQ(dst.discarded, failure == 4 || failure == 8);
		ATF_CHECK_EQ(dst.retained, failure < 3 || failure == 5 || failure == 7);
		ATF_CHECK_EQ(dest.result.retained, dst.retained);
		if (dst.retained)
			ATF_CHECK_EQ(dest.result.phase, MIGRATION_PHASE_RECOVERY);
		if (failure == 6) {
			ATF_CHECK_EQ(dest.error, 0);
			ATF_CHECK(!dest.result.release_ack_sent);
			ATF_CHECK_EQ(dest.result.reason, MIGRATION_REASON_STATE);
		}
		close(sockets[0]); close(sockets[1]);
	}
}

/* A failed image preservation aborts before STAGED and COMMIT: the source
 * never begins retirement and rolls back; the destination discards. */
ATF_TC_WITHOUT_HEAD(fresh_preserve_precedes_staged);
ATF_TC_BODY(fresh_preserve_precedes_staged, tc)
{
	(void)tc;
	for (int failure = 0; failure < 2; failure++) {
		struct source_model src = { .converge_after = 1 };
		struct dest_model dst = { .fail_preserve = failure ? EIO : 0 };
		struct migration_source_ops sops = source_ops;
		struct migration_dest_ops dops = dest_ops;
		struct migration_session_config cfg = base_config();
		struct migration_source_result result;
		struct migration_transport xp;
		struct migration_transport_fd fd;
		struct party_arg dest = {0};
		pthread_t thread;
		int sockets[2], error;

		sops.so_local_hello = src_fresh_hello;
		sops.so_retire = model_retire;
		sops.so_record = model_source_record;
		sops.so_accept_commit = model_accept_commit;
		dops.do_local_hello = dst_fresh_hello;
		dops.do_record = model_dest_record;
		dops.do_prepare_commit = model_prepare_commit;
		dops.do_retain = model_dest_retain;
		dops.do_preserve = model_dest_preserve;
		ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);
		migration_transport_fd_init(&xp, &fd, sockets[0], 1000);
		migration_transport_fd_init(&dest.xp, &dest.fdx, sockets[1], 1000);
		dest.ops = &dops; dest.config = &cfg; dest.ops_arg = &dst;
		ATF_REQUIRE_EQ(pthread_create(&thread, NULL, dest_thread, &dest), 0);
		error = migration_source_run(&xp, &sops, &src, &cfg, &result);
		ATF_REQUIRE_EQ(pthread_join(thread, NULL), 0);
		ATF_CHECK_EQ(dst.preserved, 1);
		if (failure == 0) {
			ATF_CHECK_EQ(error, 0);
			ATF_CHECK(src.retired && dst.resumed && !dst.discarded);
			ATF_CHECK_EQ(dst.recorded, MIGRATION_REC_DEST_RUNNING);
		} else {
			ATF_CHECK(error != 0);
			ATF_CHECK(!src.retired && src.resumed_after_rollback);
			ATF_CHECK(result.source_runnable);
			ATF_CHECK_EQ(dst.recorded, 0);
			ATF_CHECK(dst.discarded && !dst.retained && !dst.resumed);
			ATF_CHECK_EQ(dest.error, EIO);
			ATF_CHECK_EQ(dest.result.phase, MIGRATION_PHASE_FAILED);
		}
		close(sockets[0]); close(sockets[1]);
	}
}

ATF_TC_WITHOUT_HEAD(fresh_initial_resume_failure_retains_owner);
ATF_TC_BODY(fresh_initial_resume_failure_retains_owner, tc)
{
	(void)tc;
	struct source_model src = { .converge_after = 1 };
	struct dest_model dst = { .fail_resume = EIO };
	struct migration_source_ops sops = source_ops;
	struct migration_dest_ops dops = dest_ops;
	struct migration_session_config cfg = base_config();
	struct migration_source_result result;
	struct migration_transport xp;
	struct migration_transport_fd fd;
	struct party_arg dest = {0};
	pthread_t thread;
	int sockets[2];

	sops.so_local_hello = src_fresh_hello;
	sops.so_retire = model_retire;
	sops.so_record = model_source_record;
	sops.so_accept_commit = model_accept_commit;
	dops.do_local_hello = dst_fresh_hello;
	dops.do_record = model_dest_record;
	dops.do_prepare_commit = model_prepare_commit;
	dops.do_retain = model_dest_retain;
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);
	migration_transport_fd_init(&xp, &fd, sockets[0], 1000);
	migration_transport_fd_init(&dest.xp, &dest.fdx, sockets[1], 1000);
	dest.ops = &dops; dest.config = &cfg; dest.ops_arg = &dst;
	ATF_REQUIRE_EQ(pthread_create(&thread, NULL, dest_thread, &dest), 0);
	ATF_CHECK(migration_source_run(&xp, &sops, &src, &cfg, &result) != 0);
	ATF_REQUIRE_EQ(pthread_join(thread, NULL), 0);
	ATF_CHECK(src.retired && !src.resumed_after_rollback && !result.source_runnable);
	ATF_CHECK(dst.committed && dst.retained && !dst.discarded && !dst.resumed);
	ATF_CHECK_EQ(dst.resume_attempts, 1);
	ATF_CHECK_EQ(dest.error, EIO);
	ATF_CHECK(dest.result.retained && !dest.result.release_ack_sent);
	ATF_CHECK_EQ(dest.result.phase, MIGRATION_PHASE_RECOVERY);
	close(sockets[0]); close(sockets[1]);
}

struct fault_xp {
	struct migration_transport_fd fdx;
	int fail_after_sends;	/* fail once this many sends have succeeded */
	int sends;
};

static int
fault_send(void *cookie, const void *buf, size_t len)
{
	struct fault_xp *f = cookie;

	if (f->sends >= f->fail_after_sends)
		return (EPIPE);
	f->sends++;
	return (migration_fd_send(&f->fdx, buf, len));
}

static int
fault_recv(void *cookie, void *buf, size_t len)
{
	struct fault_xp *f = cookie;

	return (migration_fd_recv(&f->fdx, buf, len));
}

/*
 * A transport failure part-way through the multi-frame DEV_STATE stream, after
 * the source has already quiesced.  The first device-state chunk reaches the
 * destination; the next send fails.  The source must roll back to runnable
 * (resume the guest) and the destination must discard and never resume: the
 * one-copy invariant holds through a mid-cutover data-plane fault.
 */
ATF_TC_WITHOUT_HEAD(source_rolls_back_on_midchunk_dev_state_failure);
ATF_TC_BODY(source_rolls_back_on_midchunk_dev_state_failure, tc)
{
	struct source_model src;
	struct big_dest_model dst;
	struct big_party dparg;
	struct migration_transport src_xp;
	struct fault_xp fx;
	struct migration_session_config cfg;
	struct migration_source_result sres;
	uint8_t *big;
	pthread_t dtid;
	int sv[2], serr;

	(void)tc;
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	big = malloc(BIG_DEV_STATE);
	ATF_REQUIRE(big != NULL);
	memset(big, 0xa5, BIG_DEV_STATE);
	src.dev_override = big;
	src.dev_override_len = BIG_DEV_STATE;
	src.converge_after = 1;
	cfg = base_config();

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	memset(&dparg, 0, sizeof(dparg));
	migration_transport_fd_init(&dparg.xp, &dparg.fdx, sv[1], 2000);
	dparg.dst = &dst;
	dparg.config = &cfg;
	ATF_REQUIRE_EQ(pthread_create(&dtid, NULL, big_dest_thread, &dparg), 0);

	/*
	 * Sends in order: HELLO(1), TOPOLOGY(2), precopy MEM_GEN(3), stop-copy
	 * MEM_GEN(4), DEV_STATE chunk0(5), DEV_STATE chunk1(6)...  Allow the
	 * first device-state chunk through, then fail the second.
	 */
	memset(&fx, 0, sizeof(fx));
	fx.fdx.fd = sv[0];
	fx.fdx.recv_timeout_ms = 2000;
	fx.fail_after_sends = 5;
	src_xp.xp_send = fault_send;
	src_xp.xp_recv = fault_recv;
	src_xp.xp_cookie = &fx;

	serr = migration_source_run(&src_xp, &source_ops, &src, &cfg, &sres);
	/* Unblock the destination's pending recv promptly. */
	shutdown(sv[0], SHUT_RDWR);
	ATF_REQUIRE_EQ(pthread_join(dtid, NULL), 0);

	ATF_CHECK(serr != 0);
	ATF_CHECK(sres.source_runnable);
	ATF_CHECK(src.resumed_after_rollback);
	ATF_CHECK(!src.defunct);
	ATF_CHECK_EQ(sres.phase, (uint32_t)MIGRATION_PHASE_ROLLED_BACK);
	ATF_CHECK(dparg.error != 0);
	ATF_CHECK(!dst.committed);
	ATF_CHECK(!dst.resumed);
	ATF_CHECK(dst.discarded);

	free(dst.dev);
	free(big);
	close(sv[0]);
	close(sv[1]);
}

/*
 * A malicious/buggy source that drives the wire protocol through the
 * destination's staging phase and then emits a chunked DEV_STATE frame whose
 * chunk sub-header declares total_length == 0 (the streaming sentinel, legal
 * only for the chunk-by-chunk-staged MEM_GEN) while carrying a large data
 * chunk.  DEV_STATE is reassembled into a total-sized buffer, so honouring the
 * sentinel here would size the buffer at one byte and then copy the whole chunk
 * into it.  The destination must reject the frame before any copy, stage no
 * device blob, and discard.
 */
#define	EVIL_DEV_CHUNK	(1u << 20)	/* 1 MiB into a would-be 1-byte buffer */

static void
fake_source_zero_total_dev_state(int fd)
{
	struct migration_session s;
	struct migration_transport xp;
	struct migration_transport_fd fdx;
	struct migration_frame_header hdr;
	struct migration_hello h;
	struct migration_topology *t;
	struct migration_caps_accept caps;
	struct migration_memgen gen;
	struct migration_chunk chunk;
	uint8_t hello_wire[MIGRATION_HELLO_SIZE];
	uint8_t *topo_wire, *mem, *evil, *payload;
	size_t topo_len, wrote, payload_len, off;

	migration_transport_fd_init(&xp, &fdx, fd, 5000);
	memset(&s, 0, sizeof(s));
	s.xp = &xp;

	/* HELLO -> CAPS_ACCEPT */
	h = sample_hello();
	h.role = MIGRATION_ROLE_SOURCE;
	h.version_max = MIGRATION_PROTO_VERSION;
	h.version_min = MIGRATION_PROTO_VERSION_MIN;
	ATF_REQUIRE_EQ(migration_hello_encode(&h, hello_wire,
	    sizeof(hello_wire)), 0);
	ATF_REQUIRE_EQ(migration_send(&s, MIGRATION_MSG_HELLO, 0, hello_wire,
	    sizeof(hello_wire)), 0);
	ATF_REQUIRE_EQ(migration_recv(&s, &hdr, &payload, &payload_len), 0);
	ATF_REQUIRE_EQ(hdr.type, MIGRATION_MSG_CAPS_ACCEPT);
	ATF_REQUIRE_EQ(migration_caps_accept_decode(payload, payload_len,
	    &caps), 0);
	free(payload);
	s.version = caps.negotiated_version;

	/* TOPOLOGY -> TOPO_ACCEPT */
	t = calloc(1, sizeof(*t));
	ATF_REQUIRE(t != NULL);
	model_fill_topology(t);
	topo_len = migration_topology_wire_size(t);
	topo_wire = malloc(topo_len);
	ATF_REQUIRE(topo_wire != NULL);
	ATF_REQUIRE_EQ(migration_topology_encode(t, topo_wire, topo_len,
	    &wrote), 0);
	ATF_REQUIRE_EQ(migration_send(&s, MIGRATION_MSG_TOPOLOGY, 0, topo_wire,
	    wrote), 0);
	free(topo_wire);
	free(t);
	ATF_REQUIRE_EQ(migration_recv(&s, &hdr, &payload, &payload_len), 0);
	ATF_REQUIRE_EQ(hdr.type, MIGRATION_MSG_TOPO_ACCEPT);
	free(payload);

	/* One MEM_GEN (final) so the destination is in the staging loop. */
	mem = malloc(MIGRATION_MEMGEN_HDR_SIZE +
	    MODEL_PAGES * (8 + MODEL_PAGE_SIZE));
	ATF_REQUIRE(mem != NULL);
	memset(&gen, 0, sizeof(gen));
	gen.round = 1;
	gen.final = 1;
	gen.length = MODEL_MEM;
	ATF_REQUIRE_EQ(migration_memgen_encode(&gen, mem,
	    MIGRATION_MEMGEN_HDR_SIZE), 0);
	off = MIGRATION_MEMGEN_HDR_SIZE;
	for (int p = 0; p < MODEL_PAGES; p++) {
		le64enc(mem + off, (uint64_t)p * MODEL_PAGE_SIZE);
		off += 8;
		memset(mem + off, 0x5a, MODEL_PAGE_SIZE);
		off += MODEL_PAGE_SIZE;
	}
	ATF_REQUIRE_EQ(migration_send(&s, MIGRATION_MSG_MEM_GEN, 0, mem, off), 0);
	free(mem);
	ATF_REQUIRE_EQ(migration_recv(&s, &hdr, &payload, &payload_len), 0);
	ATF_REQUIRE_EQ(hdr.type, MIGRATION_MSG_MEM_ACK);
	free(payload);

	/*
	 * Chunked DEV_STATE with total_length == 0 and a 1 MiB data chunk.  A
	 * destination honouring the streaming sentinel would malloc(1) and then
	 * memcpy 1 MiB into it.
	 */
	evil = malloc(MIGRATION_CHUNK_HDR_SIZE + EVIL_DEV_CHUNK);
	ATF_REQUIRE(evil != NULL);
	memset(&chunk, 0, sizeof(chunk));
	chunk.total_length = 0;		/* illegal for DEV_STATE */
	chunk.offset = 0;
	chunk.chunk_length = EVIL_DEV_CHUNK;
	chunk.final = 0;
	ATF_REQUIRE_EQ(migration_chunk_encode(&chunk, evil,
	    MIGRATION_CHUNK_HDR_SIZE), 0);
	memset(evil + MIGRATION_CHUNK_HDR_SIZE, 0xee, EVIL_DEV_CHUNK);
	(void)migration_send(&s, MIGRATION_MSG_DEV_STATE, MIGRATION_FFLAG_CHUNK,
	    evil, MIGRATION_CHUNK_HDR_SIZE + EVIL_DEV_CHUNK);
	free(evil);
}

ATF_TC_WITHOUT_HEAD(destination_rejects_zero_total_dev_state);
ATF_TC_BODY(destination_rejects_zero_total_dev_state, tc)
{
	struct big_dest_model dst;
	struct big_party dparg;
	struct migration_session_config cfg;
	pthread_t dtid;
	int sv[2];

	(void)tc;
	memset(&dst, 0, sizeof(dst));
	cfg = base_config();

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	memset(&dparg, 0, sizeof(dparg));
	migration_transport_fd_init(&dparg.xp, &dparg.fdx, sv[1], 5000);
	dparg.dst = &dst;
	dparg.config = &cfg;
	ATF_REQUIRE_EQ(pthread_create(&dtid, NULL, big_dest_thread, &dparg), 0);

	fake_source_zero_total_dev_state(sv[0]);
	shutdown(sv[0], SHUT_RDWR);
	ATF_REQUIRE_EQ(pthread_join(dtid, NULL), 0);

	/*
	 * The destination rejects the streaming-sentinel DEV_STATE before
	 * reassembling it: no device blob is staged, no commit, no resume, and
	 * staged state is discarded.  (Before the fix this overflowed a 1-byte
	 * allocation with 1 MiB of attacker data.)
	 */
	ATF_CHECK(dparg.error != 0);
	ATF_CHECK(!dst.committed);
	ATF_CHECK(!dst.resumed);
	ATF_CHECK_EQ(dst.dev_len, (size_t)0);
	ATF_CHECK(dst.dev == NULL);
	ATF_CHECK(dst.discarded);

	free(dst.dev);
	close(sv[0]);
	close(sv[1]);
}

/*
 * A source that opens a chunked DEV_STATE reassembly (a valid first chunk of a
 * larger declared total, final == 0) and then jumps straight to the FINAL
 * ordering fence, leaving the device blob truncated.  Committing that would
 * replay incomplete device/CPU state (the missing tail reads back as whatever
 * the reassembly buffer held), so the destination must reject at the fence,
 * stage no device blob, and discard.
 */
#define	TRUNC_DEV_TOTAL		2000u	/* two-chunk blob... */
#define	TRUNC_DEV_CHUNK0	1000u	/* ...of which only half is delivered */

static void
fake_source_truncated_dev_state(int fd)
{
	struct migration_session s;
	struct migration_transport xp;
	struct migration_transport_fd fdx;
	struct migration_frame_header hdr;
	struct migration_hello h;
	struct migration_topology *t;
	struct migration_caps_accept caps;
	struct migration_memgen gen;
	struct migration_chunk chunk;
	uint8_t hello_wire[MIGRATION_HELLO_SIZE];
	uint8_t *topo_wire, *mem, *frame, *payload;
	size_t topo_len, wrote, payload_len, off;

	migration_transport_fd_init(&xp, &fdx, fd, 5000);
	memset(&s, 0, sizeof(s));
	s.xp = &xp;

	/* HELLO -> CAPS_ACCEPT */
	h = sample_hello();
	h.role = MIGRATION_ROLE_SOURCE;
	h.version_max = MIGRATION_PROTO_VERSION;
	h.version_min = MIGRATION_PROTO_VERSION_MIN;
	ATF_REQUIRE_EQ(migration_hello_encode(&h, hello_wire,
	    sizeof(hello_wire)), 0);
	ATF_REQUIRE_EQ(migration_send(&s, MIGRATION_MSG_HELLO, 0, hello_wire,
	    sizeof(hello_wire)), 0);
	ATF_REQUIRE_EQ(migration_recv(&s, &hdr, &payload, &payload_len), 0);
	ATF_REQUIRE_EQ(hdr.type, MIGRATION_MSG_CAPS_ACCEPT);
	ATF_REQUIRE_EQ(migration_caps_accept_decode(payload, payload_len,
	    &caps), 0);
	free(payload);
	s.version = caps.negotiated_version;

	/* TOPOLOGY -> TOPO_ACCEPT */
	t = calloc(1, sizeof(*t));
	ATF_REQUIRE(t != NULL);
	model_fill_topology(t);
	topo_len = migration_topology_wire_size(t);
	topo_wire = malloc(topo_len);
	ATF_REQUIRE(topo_wire != NULL);
	ATF_REQUIRE_EQ(migration_topology_encode(t, topo_wire, topo_len,
	    &wrote), 0);
	ATF_REQUIRE_EQ(migration_send(&s, MIGRATION_MSG_TOPOLOGY, 0, topo_wire,
	    wrote), 0);
	free(topo_wire);
	free(t);
	ATF_REQUIRE_EQ(migration_recv(&s, &hdr, &payload, &payload_len), 0);
	ATF_REQUIRE_EQ(hdr.type, MIGRATION_MSG_TOPO_ACCEPT);
	free(payload);

	/* One MEM_GEN (final) so the destination is in the staging loop. */
	mem = malloc(MIGRATION_MEMGEN_HDR_SIZE +
	    MODEL_PAGES * (8 + MODEL_PAGE_SIZE));
	ATF_REQUIRE(mem != NULL);
	memset(&gen, 0, sizeof(gen));
	gen.round = 1;
	gen.final = 1;
	gen.length = MODEL_MEM;
	ATF_REQUIRE_EQ(migration_memgen_encode(&gen, mem,
	    MIGRATION_MEMGEN_HDR_SIZE), 0);
	off = MIGRATION_MEMGEN_HDR_SIZE;
	for (int p = 0; p < MODEL_PAGES; p++) {
		le64enc(mem + off, (uint64_t)p * MODEL_PAGE_SIZE);
		off += 8;
		memset(mem + off, 0x5a, MODEL_PAGE_SIZE);
		off += MODEL_PAGE_SIZE;
	}
	ATF_REQUIRE_EQ(migration_send(&s, MIGRATION_MSG_MEM_GEN, 0, mem, off), 0);
	free(mem);
	ATF_REQUIRE_EQ(migration_recv(&s, &hdr, &payload, &payload_len), 0);
	ATF_REQUIRE_EQ(hdr.type, MIGRATION_MSG_MEM_ACK);
	free(payload);

	/*
	 * Valid first chunk of a two-chunk DEV_STATE blob (total 2000, this
	 * chunk 1000, final == 0), which the destination accepts and buffers.
	 */
	frame = malloc(MIGRATION_CHUNK_HDR_SIZE + TRUNC_DEV_CHUNK0);
	ATF_REQUIRE(frame != NULL);
	memset(&chunk, 0, sizeof(chunk));
	chunk.total_length = TRUNC_DEV_TOTAL;
	chunk.offset = 0;
	chunk.chunk_length = TRUNC_DEV_CHUNK0;
	chunk.final = 0;
	ATF_REQUIRE_EQ(migration_chunk_encode(&chunk, frame,
	    MIGRATION_CHUNK_HDR_SIZE), 0);
	memset(frame + MIGRATION_CHUNK_HDR_SIZE, 0xc7, TRUNC_DEV_CHUNK0);
	ATF_REQUIRE_EQ(migration_send(&s, MIGRATION_MSG_DEV_STATE,
	    MIGRATION_FFLAG_CHUNK, frame,
	    MIGRATION_CHUNK_HDR_SIZE + TRUNC_DEV_CHUNK0), 0);
	free(frame);

	/*
	 * Jump to the ordering fence with the tail still outstanding.  A correct
	 * destination rejects here; a broken one commits the truncated blob.
	 */
	(void)migration_send_reason(&s, MIGRATION_MSG_FINAL,
	    MIGRATION_REASON_NONE, 0);
}

ATF_TC_WITHOUT_HEAD(destination_rejects_truncated_dev_state);
ATF_TC_BODY(destination_rejects_truncated_dev_state, tc)
{
	struct big_dest_model dst;
	struct big_party dparg;
	struct migration_session_config cfg;
	pthread_t dtid;
	int sv[2];

	(void)tc;
	memset(&dst, 0, sizeof(dst));
	cfg = base_config();

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	memset(&dparg, 0, sizeof(dparg));
	migration_transport_fd_init(&dparg.xp, &dparg.fdx, sv[1], 5000);
	dparg.dst = &dst;
	dparg.config = &cfg;
	ATF_REQUIRE_EQ(pthread_create(&dtid, NULL, big_dest_thread, &dparg), 0);

	fake_source_truncated_dev_state(sv[0]);
	shutdown(sv[0], SHUT_RDWR);
	ATF_REQUIRE_EQ(pthread_join(dtid, NULL), 0);

	/*
	 * The reassembly was still open at the FINAL fence, so the destination
	 * refuses to commit a truncated device blob: no stage completes, no
	 * commit, no resume, and staged state is discarded.  The mutation-
	 * sensitive assertion is !committed: dropping the fence check lets the
	 * destination commit with the missing tail silently lost.
	 */
	ATF_CHECK(dparg.error != 0);
	ATF_CHECK(!dst.committed);
	ATF_CHECK(!dst.resumed);
	ATF_CHECK(dst.discarded);
	ATF_CHECK(dst.dev == NULL);
	ATF_CHECK_EQ(dst.dev_len, (size_t)0);

	free(dst.dev);
	close(sv[0]);
	close(sv[1]);
}

/* A memory generation must finish before device state, and every chunk of
 * that generation must carry the same CPU/memory identity. */
static void
fake_source_bad_mem_generation(int fd, int variant)
{
	struct migration_session s;
	struct migration_transport xp;
	struct migration_transport_fd fdx;
	struct migration_frame_header hdr;
	struct migration_hello h;
	struct migration_topology *topology;
	struct migration_caps_accept caps;
	struct migration_memgen gen;
	struct migration_chunk chunk;
	uint8_t hello_wire[MIGRATION_HELLO_SIZE];
	uint8_t *topo_wire, *payload;
	uint8_t frame[MIGRATION_MEMGEN_HDR_SIZE + MIGRATION_CHUNK_HDR_SIZE +
	    8 + MODEL_PAGE_SIZE];
	size_t topo_len, written, payload_len;

	migration_transport_fd_init(&xp, &fdx, fd, 5000);
	memset(&s, 0, sizeof(s));
	s.xp = &xp;
	h = sample_hello();
	h.role = MIGRATION_ROLE_SOURCE;
	h.version_max = MIGRATION_PROTO_VERSION;
	h.version_min = MIGRATION_PROTO_VERSION_MIN;
	ATF_REQUIRE_EQ(migration_hello_encode(&h, hello_wire,
	    sizeof(hello_wire)), 0);
	ATF_REQUIRE_EQ(migration_send(&s, MIGRATION_MSG_HELLO, 0, hello_wire,
	    sizeof(hello_wire)), 0);
	ATF_REQUIRE_EQ(migration_recv(&s, &hdr, &payload, &payload_len), 0);
	ATF_REQUIRE_EQ(hdr.type, MIGRATION_MSG_CAPS_ACCEPT);
	ATF_REQUIRE_EQ(migration_caps_accept_decode(payload, payload_len,
	    &caps), 0);
	free(payload);
	s.version = caps.negotiated_version;
	topology = calloc(1, sizeof(*topology));
	ATF_REQUIRE(topology != NULL);
	model_fill_topology(topology);
	topo_len = migration_topology_wire_size(topology);
	topo_wire = malloc(topo_len);
	ATF_REQUIRE(topo_wire != NULL);
	ATF_REQUIRE_EQ(migration_topology_encode(topology, topo_wire,
	    topo_len, &written), 0);
	ATF_REQUIRE_EQ(migration_send(&s, MIGRATION_MSG_TOPOLOGY, 0,
	    topo_wire, written), 0);
	free(topo_wire);
	free(topology);
	ATF_REQUIRE_EQ(migration_recv(&s, &hdr, &payload, &payload_len), 0);
	ATF_REQUIRE_EQ(hdr.type, MIGRATION_MSG_TOPO_ACCEPT);
	free(payload);

	memset(&gen, 0, sizeof(gen));
	gen.round = 1;
	gen.length = MODEL_MEM;
	gen.cpu_identity = 1;
	gen.page_count = 1;
	memset(&chunk, 0, sizeof(chunk));
	chunk.chunk_length = 8 + MODEL_PAGE_SIZE;
	ATF_REQUIRE_EQ(migration_memgen_encode(&gen, frame,
	    MIGRATION_MEMGEN_HDR_SIZE), 0);
	ATF_REQUIRE_EQ(migration_chunk_encode(&chunk,
	    frame + MIGRATION_MEMGEN_HDR_SIZE,
	    MIGRATION_CHUNK_HDR_SIZE), 0);
	le64enc(frame + MIGRATION_MEMGEN_HDR_SIZE +
	    MIGRATION_CHUNK_HDR_SIZE, 0);
	memset(frame + MIGRATION_MEMGEN_HDR_SIZE +
	    MIGRATION_CHUNK_HDR_SIZE + 8, 0x5a, MODEL_PAGE_SIZE);
	ATF_REQUIRE_EQ(migration_send(&s, MIGRATION_MSG_MEM_GEN,
	    MIGRATION_FFLAG_CHUNK, frame, sizeof(frame)), 0);
	ATF_REQUIRE_EQ(migration_recv(&s, &hdr, &payload, &payload_len), 0);
	ATF_REQUIRE_EQ(hdr.type, MIGRATION_MSG_MEM_ACK);
	free(payload);

	if (variant == 0) {
		const uint8_t device[] = { 1, 2, 3, 4 };
		(void)migration_send(&s, MIGRATION_MSG_DEV_STATE, 0,
		    device, sizeof(device));
		return;
	}
	if (variant == 1)
		gen.cpu_identity++;
	chunk.offset = 8 + MODEL_PAGE_SIZE;
	chunk.final = 1;
	ATF_REQUIRE_EQ(migration_memgen_encode(&gen, frame,
	    MIGRATION_MEMGEN_HDR_SIZE), 0);
	ATF_REQUIRE_EQ(migration_chunk_encode(&chunk,
	    frame + MIGRATION_MEMGEN_HDR_SIZE,
	    MIGRATION_CHUNK_HDR_SIZE), 0);
	le64enc(frame + MIGRATION_MEMGEN_HDR_SIZE +
	    MIGRATION_CHUNK_HDR_SIZE, MODEL_PAGE_SIZE);
	memset(frame + MIGRATION_MEMGEN_HDR_SIZE +
	    MIGRATION_CHUNK_HDR_SIZE + 8, 0x7b, MODEL_PAGE_SIZE);
	if (variant == 2) {
		memmove(frame + MIGRATION_MEMGEN_HDR_SIZE,
		    frame + MIGRATION_MEMGEN_HDR_SIZE + MIGRATION_CHUNK_HDR_SIZE,
		    8 + MODEL_PAGE_SIZE);
		(void)migration_send(&s, MIGRATION_MSG_MEM_GEN, 0, frame,
		    MIGRATION_MEMGEN_HDR_SIZE + 8 + MODEL_PAGE_SIZE);
	} else
		(void)migration_send(&s, MIGRATION_MSG_MEM_GEN,
		    MIGRATION_FFLAG_CHUNK, frame, sizeof(frame));
}

ATF_TC_WITHOUT_HEAD(destination_rejects_incomplete_memory_generation);
ATF_TC_BODY(destination_rejects_incomplete_memory_generation, tc)
{
	struct big_dest_model dst;
	struct big_party dparg;
	struct migration_session_config cfg;
	pthread_t dtid;
	int sv[2];

	(void)tc;
	cfg = base_config();
	for (int variant = 0; variant < 3; variant++) {
		memset(&dst, 0, sizeof(dst));
		ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
		memset(&dparg, 0, sizeof(dparg));
		migration_transport_fd_init(&dparg.xp, &dparg.fdx, sv[1],
		    5000);
		dparg.dst = &dst;
		dparg.config = &cfg;
		ATF_REQUIRE_EQ(pthread_create(&dtid, NULL, big_dest_thread,
		    &dparg), 0);
		fake_source_bad_mem_generation(sv[0], variant);
		shutdown(sv[0], SHUT_RDWR);
		ATF_REQUIRE_EQ(pthread_join(dtid, NULL), 0);
		ATF_CHECK(dparg.error != 0);
		ATF_CHECK(!dst.committed && !dst.resumed && dst.discarded);
		ATF_CHECK(dst.dev == NULL && dst.dev_len == 0);
		ATF_CHECK(dst.ram.pages[0][0] == 0x5a);
		ATF_CHECK(dst.ram.pages[1][0] == 0);
		close(sv[0]);
		close(sv[1]);
	}
}

/* ------------------------------------------------------------------------- */
/* High-memory + low-memory dirty coverage across the MMIO hole		     */
/* ------------------------------------------------------------------------- */

#define	HM_LOWMEM	(2ull * 1024 * 1024 * 1024)	/* 2 GiB below hole */
#define	HM_HIGHBASE	(4ull * 1024 * 1024 * 1024)	/* hole base at 4 GiB */
#define	HM_HIGHMEM	(1ull * 1024 * 1024 * 1024)	/* 1 GiB above hole */
#define	HM_NSAMPLES	4

struct hm_sample {
	uint64_t gpa;
	uint8_t byte;
	bool seen;
};

struct hm_source {
	bool mem_sent;
	bool quiesced;
	bool defunct;
	bool resumed_after_rollback;
	bool retired;
};

struct hm_dest {
	struct hm_sample samples[HM_NSAMPLES];
	bool committed;
	bool resumed;
	bool retained;
};

static const uint64_t hm_gpas[HM_NSAMPLES] = {
	0,					/* bottom of lowmem */
	HM_LOWMEM - MODEL_PAGE_SIZE,		/* top of lowmem */
	HM_HIGHBASE,				/* bottom of highmem (>4 GiB) */
	HM_HIGHBASE + HM_HIGHMEM - MODEL_PAGE_SIZE,	/* top of highmem */
};

static uint8_t
hm_gpa_byte(uint64_t gpa)
{

	return ((uint8_t)((gpa >> 12) ^ (gpa >> 32)) ^ 0x5a);
}

static void
hm_fill_topology(struct migration_topology *t)
{

	memset(t, 0, sizeof(*t));
	t->lowmem = HM_LOWMEM;
	t->highmem = HM_HIGHMEM;
	t->mem_size = HM_LOWMEM + HM_HIGHMEM;
	t->ncpus = 2;
	t->sockets = 1;
	t->cores = 2;
	t->threads = 1;
	t->device_count = 1;
	strlcpy(t->devices[0].name, "virtio-blk", MIGRATION_DEVICE_NAME_MAX);
	t->devices[0].migration_flags = MIGRATION_DEVF_STATE_CODEC |
	    MIGRATION_DEVF_COMPAT_CALLBACK | MIGRATION_DEVF_DMA_TRACKED |
	    MIGRATION_DEVF_QUIESCE_CALLBACK;
	t->devices[0].compat_schema = 1;
	t->devices[0].compat_crc32 = 0x11223344;
}

static int
hm_src_hello(void *arg, struct migration_hello *h)
{

	(void)arg;
	*h = sample_hello();
	h->role = MIGRATION_ROLE_SOURCE;
	return (0);
}

static int
hm_src_topology(void *arg, struct migration_topology *t)
{

	(void)arg;
	hm_fill_topology(t);
	return (0);
}

static int
hm_src_precopy_enable(void *arg)
{

	(void)arg;
	return (0);
}

static int
hm_src_precopy_round(void *arg, bool final, struct migration_memgen *gen,
    uint8_t *buf, size_t cap, size_t *written, uint64_t *dirty_pages,
    bool *converged, bool *more)
{
	struct hm_source *m = arg;
	size_t off;
	uint64_t count;

	(void)final;
	off = 0;
	count = 0;
	*more = false;
	if (!m->mem_sent) {
		for (int i = 0; i < HM_NSAMPLES; i++) {
			ATF_REQUIRE(off + 8 + MODEL_PAGE_SIZE <= cap);
			le64enc(buf + off, hm_gpas[i]);
			off += 8;
			memset(buf + off, hm_gpa_byte(hm_gpas[i]), MODEL_PAGE_SIZE);
			off += MODEL_PAGE_SIZE;
			count++;
		}
		m->mem_sent = true;
	}
	memset(gen, 0, sizeof(*gen));
	gen->mode = MIGRATION_DIRTY_CLEAR;
	gen->length = HM_LOWMEM + HM_HIGHMEM;
	gen->page_count = (uint32_t)count;
	*written = off;
	*dirty_pages = count;
	*converged = true;
	return (0);
}

static int
hm_src_precopy_disable(void *arg)
{

	(void)arg;
	return (0);
}

static int
hm_src_quiesce(void *arg, bool *source_runnable)
{
	struct hm_source *m = arg;

	(void)source_runnable;
	m->quiesced = true;
	return (0);
}

static int
hm_src_resume(void *arg)
{
	struct hm_source *m = arg;

	m->quiesced = false;
	m->resumed_after_rollback = true;
	return (0);
}

static int
hm_src_dev_state(void *arg, uint8_t **buf, size_t *len)
{
	uint8_t *out;

	(void)arg;
	out = malloc(16);
	if (out == NULL)
		return (ENOMEM);
	memset(out, 0xd7, 16);
	*buf = out;
	*len = 16;
	return (0);
}

static void
hm_src_defunct(void *arg)
{
	struct hm_source *m = arg;

	m->defunct = true;
}

static int
hm_src_retire(void *arg)
{
	struct hm_source *m = arg;

	ATF_REQUIRE(m->quiesced);
	m->retired = true;
	return (0);
}

static int
hm_src_accept(void *arg, const struct migration_commit_binding *binding)
{
	(void)arg;
	ATF_REQUIRE_EQ(binding->destination_vmid, 8);
	ATF_REQUIRE_EQ(binding->destination_epoch, 10);
	return (0);
}

static const struct migration_source_ops hm_source_ops = {
	.so_local_hello = hm_src_hello,
	.so_local_topology = hm_src_topology,
	.so_precopy_enable = hm_src_precopy_enable,
	.so_precopy_round = hm_src_precopy_round,
	.so_precopy_disable = hm_src_precopy_disable,
	.so_quiesce = hm_src_quiesce,
	.so_resume = hm_src_resume,
	.so_dev_state = hm_src_dev_state,
	.so_defunct = hm_src_defunct,
	.so_retire = hm_src_retire,
	.so_accept_commit = hm_src_accept,
	.so_record = noop_record,
};

static int
hm_dst_hello(void *arg, struct migration_hello *h)
{

	(void)arg;
	*h = sample_hello();
	h->role = MIGRATION_ROLE_DEST;
	return (0);
}

static int
hm_dst_topology(void *arg, struct migration_topology *t)
{

	(void)arg;
	hm_fill_topology(t);
	return (0);
}

static int
hm_dst_stage_mem(void *arg, const struct migration_memgen *gen,
    const uint8_t *buf, size_t len)
{
	struct hm_dest *m = arg;
	size_t off;

	(void)gen;
	off = 0;
	while (off + 8 <= len) {
		uint64_t gpa;

		gpa = le64dec(buf + off);
		off += 8;
		if (off + MODEL_PAGE_SIZE > len)
			return (EBADMSG);
		for (int i = 0; i < HM_NSAMPLES; i++) {
			if (m->samples[i].gpa == gpa) {
				m->samples[i].byte = buf[off];
				m->samples[i].seen = true;
			}
		}
		off += MODEL_PAGE_SIZE;
	}
	return (off == len ? 0 : EBADMSG);
}

static int
hm_dst_stage_dev(void *arg, const uint8_t *buf, size_t len)
{

	(void)arg;
	(void)buf;
	(void)len;
	return (0);
}

static int
hm_dst_commit(void *arg)
{
	struct hm_dest *m = arg;

	m->committed = true;
	return (0);
}

static int
hm_dst_resume(void *arg)
{
	struct hm_dest *m = arg;

	m->resumed = true;
	return (0);
}

static void
hm_dst_discard(void *arg)
{

	(void)arg;
}

static int
hm_dst_prepare(void *arg, struct migration_commit_binding *binding)
{
	struct hm_dest *m = arg;

	ATF_REQUIRE(m->committed && !m->resumed);
	binding->destination_vmid = 8;
	binding->destination_epoch = 10;
	memset(binding->state_digest, 0x5a, 32);
	return (0);
}

static void
hm_dst_retain(void *arg, const struct migration_commit_binding *binding)
{
	struct hm_dest *m = arg;

	(void)binding;
	m->retained = true;
}

static const struct migration_dest_ops hm_dest_ops = {
	.do_local_hello = hm_dst_hello,
	.do_local_topology = hm_dst_topology,
	.do_stage_mem = hm_dst_stage_mem,
	.do_stage_dev = hm_dst_stage_dev,
	.do_commit = hm_dst_commit,
	.do_resume = hm_dst_resume,
	.do_discard = hm_dst_discard,
	.do_prepare_commit = hm_dst_prepare,
	.do_retain = hm_dst_retain,
	.do_record = noop_record,
};

struct hm_party {
	struct migration_transport xp;
	struct migration_transport_fd fdx;
	struct hm_dest *dst;
	const struct migration_session_config *config;
	int error;
	struct migration_dest_result result;
};

static void *
hm_dest_thread(void *v)
{
	struct hm_party *a = v;

	a->error = migration_dest_run(&a->xp, &hm_dest_ops, a->dst, a->config,
	    &a->result);
	return (NULL);
}

/*
 * A guest larger than the 32-bit MMIO hole migrates correctly: dirty page
 * records are produced and staged for both the low-memory region below 4 GiB
 * and the high-memory region above it.  This proves the session and staging
 * path carry 64-bit guest-physical addresses across the hole; the production
 * adapter additionally arms dirty logging over both ranges (compile-verified).
 */
ATF_TC_WITHOUT_HEAD(highmem_lowmem_dirty_coverage);
ATF_TC_BODY(highmem_lowmem_dirty_coverage, tc)
{
	struct hm_source src;
	struct hm_dest dst;
	struct hm_party dparg;
	struct migration_transport src_xp;
	struct migration_transport_fd src_fdx;
	struct migration_session_config cfg;
	struct migration_source_result sres;
	pthread_t dtid;
	int sv[2], serr;

	(void)tc;
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	for (int i = 0; i < HM_NSAMPLES; i++)
		dst.samples[i].gpa = hm_gpas[i];
	cfg = base_config();

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	memset(&dparg, 0, sizeof(dparg));
	migration_transport_fd_init(&dparg.xp, &dparg.fdx, sv[1], 5000);
	dparg.dst = &dst;
	dparg.config = &cfg;
	ATF_REQUIRE_EQ(pthread_create(&dtid, NULL, hm_dest_thread, &dparg), 0);

	migration_transport_fd_init(&src_xp, &src_fdx, sv[0], 5000);
	serr = migration_source_run(&src_xp, &hm_source_ops, &src, &cfg, &sres);
	ATF_REQUIRE_EQ(pthread_join(dtid, NULL), 0);

	ATF_CHECK_EQ(serr, 0);
	ATF_CHECK_EQ(dparg.error, 0);
	ATF_CHECK(dst.committed);
	ATF_CHECK(dst.resumed);
	/* Every sample - low and high, including the >4 GiB pages - arrived. */
	for (int i = 0; i < HM_NSAMPLES; i++) {
		ATF_CHECK(dst.samples[i].seen);
		ATF_CHECK_EQ(dst.samples[i].byte, hm_gpa_byte(hm_gpas[i]));
	}
	/* At least one staged page lived above the 4 GiB hole. */
	ATF_CHECK(dst.samples[2].gpa >= HM_HIGHBASE && dst.samples[2].seen);

	close(sv[0]);
	close(sv[1]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, hello_roundtrip);
	ATF_TP_ADD_TC(tp, hello_rejects_uncanonical_abi_and_truncation);
	ATF_TP_ADD_TC(tp, caps_accept_requires_canonical_offered_capabilities);
	ATF_TP_ADD_TC(tp, frame_roundtrip_and_crc);
	ATF_TP_ADD_TC(tp, frame_rejects_oversize_and_short_header);
	ATF_TP_ADD_TC(tp, frame_rejects_unknown_version_type_and_flags);
	ATF_TP_ADD_TC(tp, memory_record_validation);
	ATF_TP_ADD_TC(tp, topology_roundtrip_and_bounds);
	ATF_TP_ADD_TC(tp, version_negotiation_downgrade_and_reject);
	ATF_TP_ADD_TC(tp, hello_validate_rejects_mismatch);
	ATF_TP_ADD_TC(tp, device_flags_eligibility);
	ATF_TP_ADD_TC(tp, topology_validate_enforces_device_identity);
	ATF_TP_ADD_TC(tp, loopback_migration_succeeds);
	ATF_TP_ADD_TC(tp, fresh_tracing_requires_matching_capabilities);
	ATF_TP_ADD_TC(tp, source_retirement_precedes_release);
	ATF_TP_ADD_TC(tp, fresh_recovery_persistence_boundaries);
	ATF_TP_ADD_TC(tp, fresh_initial_resume_failure_retains_owner);
	ATF_TP_ADD_TC(tp, fresh_preserve_precedes_staged);
	ATF_TP_ADD_TC(tp, source_rejects_wrapping_round_limit);
	ATF_TP_ADD_TC(tp, destination_rejects_topology_before_quiesce);
	ATF_TP_ADD_TC(tp, source_rolls_back_when_destination_commit_fails);
	ATF_TP_ADD_TC(tp, convergence_limit_aborts_and_keeps_source);
	ATF_TP_ADD_TC(tp, cancellation_midcopy_keeps_source);
	ATF_TP_ADD_TC(tp, recv_enforces_sequence_monotonicity);
	ATF_TP_ADD_TC(tp, destination_without_release_does_not_run);
	ATF_TP_ADD_TC(tp, destination_requires_successful_release);
	ATF_TP_ADD_TC(tp, source_rolls_back_when_dev_state_fails);
	ATF_TP_ADD_TC(tp, source_resume_failure_stays_fail_closed);
	ATF_TP_ADD_TC(tp, source_quiesce_failure_rolls_back_runnable);
	ATF_TP_ADD_TC(tp, source_quiesce_wedged_reports_not_runnable);
	ATF_TP_ADD_TC(tp, chunk_validate_rejects_gap_dup_oversize);
	ATF_TP_ADD_TC(tp, source_rejects_invalid_memory_chunk_contract);
	ATF_TP_ADD_TC(tp, loopback_multiframe_dev_state_reassembles);
	ATF_TP_ADD_TC(tp, source_rolls_back_on_midchunk_dev_state_failure);
	ATF_TP_ADD_TC(tp, destination_rejects_zero_total_dev_state);
	ATF_TP_ADD_TC(tp, destination_rejects_truncated_dev_state);
	ATF_TP_ADD_TC(tp, destination_rejects_incomplete_memory_generation);
	ATF_TP_ADD_TC(tp, highmem_lowmem_dirty_coverage);
	return (atf_no_error());
}
