/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef DTRACED_TRANSFER_WIRE_H
#define DTRACED_TRANSFER_WIRE_H

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include "dtraced_wire.h"

/* HTX1 is a read-only source export.  Its digest detects torn or corrupted
 * transport; the checkpoint must separately bind these bytes to its ticket. */
/* Leave space for the canonical request header and ticket binding when
 * importing an HTX1 bundle through the 64 MiB local control frame. */
/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
#define DTRACED_TRANSFER_MAX_SIZE (63U * 1024U * 1024U)
#define DTRACED_TRANSFER_HEADER_SIZE 32U
#define DTRACED_TRANSFER_DIGEST_SIZE SHA256_DIGEST_LENGTH
#define DTRACED_TRANSFER_MAX_FRAMES 65536U

static inline int
dtraced_transfer_wire_valid(const uint8_t *wire, size_t length,
    const uint8_t token[16])
{
	uint8_t digest[SHA256_DIGEST_LENGTH];
	const uint8_t zero_token[16] = { 0 };
	size_t end, offset;
	uint32_t count, manifest_length;

	if (wire == NULL || token == NULL ||
	    CRYPTO_memcmp(token, zero_token, sizeof(zero_token)) == 0 ||
	    length < DTRACED_TRANSFER_HEADER_SIZE + SHA256_DIGEST_LENGTH ||
	    length > DTRACED_TRANSFER_MAX_SIZE ||
	    memcmp(wire, "HTX1", 4) != 0 ||
	    memcmp(wire + 4, token, 16) != 0 ||
	    dtraced_wire_get_u32(wire + 28) != 0) {
		errno = EPROTO;
		return (0);
	}
	manifest_length = dtraced_wire_get_u32(wire + 20);
	count = dtraced_wire_get_u32(wire + 24);
	end = length - SHA256_DIGEST_LENGTH;
	offset = DTRACED_TRANSFER_HEADER_SIZE;
	if (manifest_length > end - offset ||
	    (manifest_length == 0 && count != 0)) {
		errno = EPROTO;
		return (0);
	}
	offset += manifest_length;
	/* Every frame consumes at least a four-byte length field. */
	if (count > DTRACED_TRANSFER_MAX_FRAMES ||
	    count > (end - offset) / 4) {
		errno = EPROTO;
		return (0);
	}
	for (uint32_t i = 0; i < count; i++) {
		uint32_t frame_length = dtraced_wire_get_u32(wire + offset);
		offset += 4;
		if (frame_length == 0 || frame_length > end - offset) {
			errno = EPROTO;
			return (0);
		}
		offset += frame_length;
	}
	if (offset != end || SHA256(wire, end, digest) == NULL ||
	    CRYPTO_memcmp(digest, wire + end, sizeof(digest)) != 0) {
		errno = EPROTO;
		return (0);
	}
	return (1);
}

/* HJM1 wraps the ingress manifest and appends one HJX1 source journal.
 * The HTX1 digest, later signed through HSA1, binds both parts. */
#define DTRACED_TRANSFER_JOURNAL_HEADER_SIZE 64U
static inline int
dtraced_transfer_journal_archive_valid(const uint8_t token[16],
    const uint8_t *archive, size_t length, uint8_t digest[SHA256_DIGEST_LENGTH])
{
	const uint8_t zero6[6] = {};
	if (token == NULL || archive == NULL || digest == NULL ||
	    length < DTRACED_TRANSFER_JOURNAL_HEADER_SIZE +
	    SHA256_DIGEST_LENGTH ||
	    memcmp(archive, "HJX1", 4) != 0 ||
	    dtraced_wire_get_u32(archive + 4) != 1 ||
	    memcmp(archive + 8, token, 16) != 0 ||
	    memcmp(archive + 42, zero6, sizeof(zero6)) != 0 ||
	    archive[62] != 0 || archive[63] != 0 ||
	    SHA256(archive, length - SHA256_DIGEST_LENGTH, digest) == NULL ||
	    CRYPTO_memcmp(digest, archive + length - SHA256_DIGEST_LENGTH,
	    SHA256_DIGEST_LENGTH) != 0) {
		errno = EPROTO;
		return (0);
	}
	return (1);
}

static inline int
dtraced_transfer_wire_inspect(const uint8_t *wire, size_t length,
    const uint8_t token[16], int *has_ingress, int *has_journal)
{
	if (has_ingress == NULL || has_journal == NULL ||
	    !dtraced_transfer_wire_valid(wire, length, token))
		return (0);
	*has_ingress = 0;
	*has_journal = 0;
	uint32_t manifest_length = dtraced_wire_get_u32(wire + 20);
	uint32_t frame_count = dtraced_wire_get_u32(wire + 24);
	const uint8_t *manifest = wire + DTRACED_TRANSFER_HEADER_SIZE;
	if (manifest_length < 4 || memcmp(manifest, "HJM1", 4) != 0) {
		*has_ingress = manifest_length != 0;
		return (1);
	}
	if (manifest_length < DTRACED_TRANSFER_JOURNAL_HEADER_SIZE ||
	    dtraced_wire_get_u32(manifest + 4) != 1 ||
	    memcmp(manifest + 8, token, 16) != 0 ||
	    dtraced_wire_get_u32(manifest + 24) != manifest_length -
	    DTRACED_TRANSFER_JOURNAL_HEADER_SIZE ||
	    frame_count == 0 ||
	    dtraced_wire_get_u32(manifest + 28) != frame_count - 1 ||
	    ((dtraced_wire_get_u32(manifest + 24) == 0) !=
	    (dtraced_wire_get_u32(manifest + 28) == 0))) {
		errno = EPROTO;
		return (0);
	}
	size_t offset = DTRACED_TRANSFER_HEADER_SIZE + manifest_length;
	const uint8_t *archive = NULL;
	size_t archive_length = 0;
	for (uint32_t i = 0; i < frame_count; i++) {
		uint32_t frame_length = dtraced_wire_get_u32(wire + offset);
		offset += 4;
		if (i == frame_count - 1) {
			archive = wire + offset;
			archive_length = frame_length;
		}
		offset += frame_length;
	}
	uint8_t digest[SHA256_DIGEST_LENGTH];
	if (!dtraced_transfer_journal_archive_valid(token, archive,
	    archive_length, digest) ||
	    CRYPTO_memcmp(digest, manifest + 32, sizeof(digest)) != 0) {
		errno = EPROTO;
		return (0);
	}
	*has_ingress = dtraced_wire_get_u32(manifest + 28) != 0;
	*has_journal = 1;
	return (1);
}

/* Restore needs an import transaction for either guest ingress or source
 * journal state. A journal-only HJM1 bundle is not an empty checkpoint. */
static inline int
dtraced_transfer_wire_requires_import(const uint8_t *wire, size_t length,
    const uint8_t token[16], int *requires_import)
{
	int ingress = 0, journal = 0;

	if (requires_import == NULL) {
		errno = EINVAL;
		return (0);
	}
	if (!dtraced_transfer_wire_inspect(wire, length, token,
	    &ingress, &journal))
		return (0);
	*requires_import = ingress != 0 || journal != 0;
	return (1);
}

/* Conservative source-side queue budget for the authenticated HJX1 cut.
 * Count every nonrevoked bare ELF in VirtIO chunks, plus KILL and queued
 * CLEANUP controls. A saved control may already cover an imported receipt;
 * counting it twice errs toward refusing the source cut before release. */
static inline int
dtraced_transfer_wire_replay_controls(const uint8_t *wire, size_t length,
    const uint8_t token[16], size_t envelope_bytes, size_t chunk_bytes,
    size_t *controls)
{
	int ingress = 0, journal = 0;
	if (controls == NULL || envelope_bytes == 0 || chunk_bytes == 0) {
		errno = EINVAL;
		return (0);
	}
	*controls = 0;
	if (!dtraced_transfer_wire_inspect(wire, length, token,
	    &ingress, &journal))
		return (0);
	if (!journal)
		return (1);
	uint32_t manifest_length = dtraced_wire_get_u32(wire + 20);
	uint32_t frame_count = dtraced_wire_get_u32(wire + 24);
	size_t offset = DTRACED_TRANSFER_HEADER_SIZE + manifest_length;
	const uint8_t *archive = NULL;
	size_t archive_length = 0;
	for (uint32_t i = 0; i < frame_count; i++) {
		uint32_t frame_length = dtraced_wire_get_u32(wire + offset);
		offset += 4;
		if (i == frame_count - 1) {
			archive = wire + offset;
			archive_length = frame_length;
		}
		offset += frame_length;
	}
	/* inspect() already checked the outer frame, nested HJX1 digest, and
	 * minimum archive length. Check each inner length before using it. */
	size_t end = archive_length - SHA256_DIGEST_LENGTH;
	size_t pos = DTRACED_TRANSFER_JOURNAL_HEADER_SIZE;
	size_t total = 0;
	uint32_t previous_pid = 0;
	uint8_t previous_source[16] = {};
	uint64_t previous_cleanup = 0;
	const uint8_t zero6[6] = {};
	const uint8_t zero16[16] = {};
	uint16_t deliveries = dtraced_wire_get_u16(archive + 56);
	uint16_t kills = dtraced_wire_get_u16(archive + 58);
	uint16_t cleanups = dtraced_wire_get_u16(archive + 60);
	for (uint16_t i = 0; i < deliveries; i++) {
		if (pos > end || end - pos < 12 || archive[pos] != 1 ||
		    (archive[pos + 1] != 'a' && archive[pos + 1] != 'i') ||
		    archive[pos + 2] > 1 || archive[pos + 3] != 0 ||
		    archive[pos + 6] != 0 || archive[pos + 7] != 0) {
			errno = EPROTO;
			return (0);
		}
		size_t record_bytes = dtraced_wire_get_u16(archive + pos + 4);
		size_t payload_bytes = dtraced_wire_get_u32(archive + pos + 8);
		bool revoked = archive[pos + 2] != 0;
		pos += 12;
		if ((record_bytes != 143 && record_bytes != 185) ||
		    record_bytes > end - pos ||
		    payload_bytes > end - pos - record_bytes ||
		    (record_bytes == 143 &&
		    memcmp(archive + pos, "HTD4", 4) != 0) ||
		    (record_bytes == 185 &&
		    memcmp(archive + pos, "HTD5", 4) != 0)) {
			errno = EPROTO;
			return (0);
		}
		if (revoked) {
			if (payload_bytes != 0) {
				errno = EPROTO;
				return (0);
			}
		} else {
			size_t bare = payload_bytes;
			const uint8_t *payload = archive + pos + record_bytes;
			if (payload_bytes < 4) {
				errno = EPROTO;
				return (0);
			}
			if (memcmp(payload, "\177ELF", 4) != 0) {
				if (payload_bytes < envelope_bytes + 4 ||
				    memcmp(payload + envelope_bytes, "\177ELF", 4) != 0) {
					errno = EPROTO;
					return (0);
				}
				bare -= envelope_bytes;
			}
			size_t chunks = bare / chunk_bytes +
			    (bare % chunk_bytes != 0);
			if (chunks > SIZE_MAX - total) {
				errno = EOVERFLOW;
				return (0);
			}
			total += chunks;
		}
		pos += record_bytes + payload_bytes;
	}
	for (uint16_t i = 0; i < kills; i++) {
		uint32_t pid;
		if (pos > end || end - pos < 24 || archive[pos] != 2 ||
		    archive[pos + 1] != 1 || archive[pos + 2] != 0 ||
		    archive[pos + 3] != 0) {
			errno = EPROTO;
			return (0);
		}
		pid = dtraced_wire_get_u32(archive + pos + 4);
		if (pid <= 1 || pid > INT32_MAX ||
		    memcmp(archive + pos + 8, zero16, sizeof(zero16)) == 0 ||
		    (i != 0 && (pid < previous_pid ||
		    (pid == previous_pid && memcmp(archive + pos + 8,
		    previous_source, sizeof(previous_source)) <= 0)))) {
			errno = EPROTO;
			return (0);
		}
		if (total == SIZE_MAX) {
			errno = EOVERFLOW;
			return (0);
		}
		previous_pid = pid;
		memcpy(previous_source, archive + pos + 8,
		    sizeof(previous_source));
		pos += 24;
		total++;
	}
	for (uint16_t i = 0; i < cleanups; i++) {
		uint64_t delivery_id;
		if (pos > end || end - pos < 16 || archive[pos] != 3 ||
		    (archive[pos + 1] != 'a' && archive[pos + 1] != 'g') ||
		    memcmp(archive + pos + 2, zero6, sizeof(zero6)) != 0) {
			errno = EPROTO;
			return (0);
		}
		delivery_id = dtraced_wire_get_u64(archive + pos + 8);
		if (delivery_id == 0 ||
		    (i != 0 && delivery_id <= previous_cleanup)) {
			errno = EPROTO;
			return (0);
		}
		previous_cleanup = delivery_id;
		if (archive[pos + 1] == 'a') {
			if (total == SIZE_MAX) {
				errno = EOVERFLOW;
				return (0);
			}
			total++;
		}
		pos += 16;
	}
	if (pos != end) {
		errno = EPROTO;
		return (0);
	}
	*controls = total;
	return (1);
}

#ifdef __cplusplus
#include <new>
#include <vector>

static inline bool dtraced_transfer_wire_build(const uint8_t[16],
    const std::vector<uint8_t> &, const std::vector<std::vector<uint8_t>> &,
    std::vector<uint8_t> &);

static inline bool
dtraced_transfer_journal_wrap(const uint8_t token[16],
    const std::vector<uint8_t> &ingress_manifest,
    const std::vector<std::vector<uint8_t>> &ingress_frames,
    const std::vector<uint8_t> &archive,
    std::vector<uint8_t> &manifest,
    std::vector<std::vector<uint8_t>> &frames)
{
	manifest.clear();
	frames.clear();
	uint8_t digest[SHA256_DIGEST_LENGTH];
	if (!dtraced_transfer_journal_archive_valid(token, archive.data(),
	    archive.size(), digest) ||
	    (ingress_manifest.empty() != ingress_frames.empty()) ||
	    ingress_manifest.size() > DTRACED_TRANSFER_MAX_SIZE -
	    DTRACED_TRANSFER_JOURNAL_HEADER_SIZE ||
	    ingress_frames.size() >= DTRACED_TRANSFER_MAX_FRAMES) {
		errno = EPROTO;
		return (false);
	}
	try {
		std::vector<uint8_t> wrapped(
		    DTRACED_TRANSFER_JOURNAL_HEADER_SIZE +
		    ingress_manifest.size(), 0);
		memcpy(wrapped.data(), "HJM1", 4);
		dtraced_wire_put_u32(wrapped.data() + 4, 1);
		memcpy(wrapped.data() + 8, token, 16);
		dtraced_wire_put_u32(wrapped.data() + 24,
		    (uint32_t)ingress_manifest.size());
		dtraced_wire_put_u32(wrapped.data() + 28,
		    (uint32_t)ingress_frames.size());
		memcpy(wrapped.data() + 32, digest, sizeof(digest));
		if (!ingress_manifest.empty())
			memcpy(wrapped.data() +
			    DTRACED_TRANSFER_JOURNAL_HEADER_SIZE,
			    ingress_manifest.data(), ingress_manifest.size());
		std::vector<std::vector<uint8_t>> copied = ingress_frames;
		copied.push_back(archive);
		std::vector<uint8_t> checked;
		if (!dtraced_transfer_wire_build(token, wrapped, copied,
		    checked))
			return (false);
		manifest.swap(wrapped);
		frames.swap(copied);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

static inline bool
dtraced_transfer_journal_split(const uint8_t token[16],
    const std::vector<uint8_t> &manifest,
    const std::vector<std::vector<uint8_t>> &frames,
    std::vector<uint8_t> &ingress_manifest,
    std::vector<std::vector<uint8_t>> &ingress_frames,
    std::vector<uint8_t> &archive)
{
	ingress_manifest.clear();
	ingress_frames.clear();
	archive.clear();
	if (token == nullptr) {
		errno = EINVAL;
		return (false);
	}
	if (manifest.size() < 4 || memcmp(manifest.data(), "HJM1", 4) != 0) {
		try {
			ingress_manifest = manifest;
			ingress_frames = frames;
			return (true);
		} catch (const std::bad_alloc &) {
			errno = ENOMEM;
			return (false);
		}
	}
	const size_t header = DTRACED_TRANSFER_JOURNAL_HEADER_SIZE;
	if (manifest.size() < header || frames.empty() ||
	    dtraced_wire_get_u32(manifest.data() + 4) != 1 ||
	    memcmp(manifest.data() + 8, token, 16) != 0 ||
	    dtraced_wire_get_u32(manifest.data() + 24) !=
	    manifest.size() - header ||
	    dtraced_wire_get_u32(manifest.data() + 28) != frames.size() - 1 ||
	    ((manifest.size() == header) != (frames.size() == 1))) {
		errno = EPROTO;
		return (false);
	}
	const auto &last = frames.back();
	uint8_t digest[SHA256_DIGEST_LENGTH];
	if (!dtraced_transfer_journal_archive_valid(token, last.data(),
	    last.size(), digest) ||
	    CRYPTO_memcmp(digest, manifest.data() + 32,
	    sizeof(digest)) != 0) {
		errno = EPROTO;
		return (false);
	}
	try {
		std::vector<uint8_t> nested(manifest.begin() + header,
		    manifest.end());
		std::vector<std::vector<uint8_t>> nested_frames(
		    frames.begin(), frames.end() - 1);
		std::vector<uint8_t> journal = last;
		ingress_manifest.swap(nested);
		ingress_frames.swap(nested_frames);
		archive.swap(journal);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

static inline bool
dtraced_transfer_wire_build(const uint8_t token[16],
    const std::vector<uint8_t> &manifest,
    const std::vector<std::vector<uint8_t>> &frames,
    std::vector<uint8_t> &result)
{
	result.clear();
	const uint8_t zero[16] = {};
	size_t length = DTRACED_TRANSFER_HEADER_SIZE +
	    DTRACED_TRANSFER_DIGEST_SIZE;
	if (token == nullptr || memcmp(token, zero, sizeof(zero)) == 0 ||
	    (manifest.empty() && !frames.empty()) ||
	    manifest.size() > DTRACED_TRANSFER_MAX_SIZE - length ||
	    frames.size() > DTRACED_TRANSFER_MAX_FRAMES) {
		errno = EPROTO;
		return (false);
	}
	length += manifest.size();
	for (const auto &frame : frames) {
		if (frame.empty() || length > DTRACED_TRANSFER_MAX_SIZE - 4 ||
		    frame.size() > DTRACED_TRANSFER_MAX_SIZE - length - 4) {
			errno = E2BIG;
			return (false);
		}
		length += 4 + frame.size();
	}
	try {
		std::vector<uint8_t> candidate(length, 0);
		uint8_t *wire = candidate.data();
		memcpy(wire, "HTX1", 4);
		memcpy(wire + 4, token, 16);
		dtraced_wire_put_u32(wire + 20, (uint32_t)manifest.size());
		dtraced_wire_put_u32(wire + 24, (uint32_t)frames.size());
		size_t offset = DTRACED_TRANSFER_HEADER_SIZE;
		if (!manifest.empty()) {
			memcpy(wire + offset, manifest.data(), manifest.size());
			offset += manifest.size();
		}
		for (const auto &frame : frames) {
			dtraced_wire_put_u32(wire + offset,
			    (uint32_t)frame.size());
			offset += 4;
			memcpy(wire + offset, frame.data(), frame.size());
			offset += frame.size();
		}
		if (SHA256(wire, offset, wire + offset) == nullptr) {
			errno = EIO;
			return (false);
		}
		result.swap(candidate);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}

static inline bool
dtraced_transfer_wire_unpack(const uint8_t *wire, size_t length,
    const uint8_t token[16], std::vector<uint8_t> &manifest,
    std::vector<std::vector<uint8_t>> &frames)
{
	manifest.clear();
	frames.clear();
	if (!dtraced_transfer_wire_valid(wire, length, token))
		return (false);
	try {
		std::vector<uint8_t> decoded_manifest;
		std::vector<std::vector<uint8_t>> decoded_frames;
		size_t offset = DTRACED_TRANSFER_HEADER_SIZE;
		uint32_t manifest_length = dtraced_wire_get_u32(wire + 20);
		uint32_t count = dtraced_wire_get_u32(wire + 24);
		decoded_manifest.assign(wire + offset,
		    wire + offset + manifest_length);
		offset += manifest_length;
		decoded_frames.reserve(count);
		for (uint32_t i = 0; i < count; i++) {
			uint32_t frame_length = dtraced_wire_get_u32(wire + offset);
			offset += 4;
			decoded_frames.emplace_back(wire + offset,
			    wire + offset + frame_length);
			offset += frame_length;
		}
		manifest.swap(decoded_manifest);
		frames.swap(decoded_frames);
		return (true);
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return (false);
	}
}
#endif

/* HT-C END */
#endif
