/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _GEOM_VERITY_TRANSITION_H_
#define _GEOM_VERITY_TRANSITION_H_
#include <sys/types.h>
/*
 * Bounded root-transition wire format, version 1. All integers are big-endian.
 * This format conveys no authority by itself: the loader must authenticate and
 * retain the exact bytes, and bind them at final handoff before kernel use.
 * No consumer or disk-root admission is enabled by defining this contract.
 *
 * offset size field
 *      0    8 magic "5BSDBOOT"
 *      8    4 version (1)
 *     12    4 complete wire length (2192)
 *     16   32 SHA256 of the selected root descriptor
 *     48    4 worker count
 *     52    4 transport filesystem (1=UFS, 2=ZFS)
 *     56    8 cache entries per worker
 *     64    8 read window bytes per worker
 *     72    8 total provider buffer budget
 *     80 1024 transport device/dataset
 *   1104 1024 image pathname on the transport filesystem
 *   2128   64 verifier provider name
 *
 * Strings are ASCII, NUL-terminated and zero-padded. No mount options, scripts
 * or directives are accepted. Target limits and allocation arithmetic must be
 * validated by the consumer before any storage operation. Layout limits bound
 * parsing/storage; they are not inferred device names or resource defaults.
 */
#define G_VERITY_TRANSITION_BYTES 2192
#define G_VERITY_TRANSITION_VERSION 1
#define G_VERITY_TRANSITION_TYPE "bip_root_transition"
struct g_verity_transition {
	uint8_t descriptor_sha256[32];
	uint32_t workers, transport_fs;
	uint64_t cache_blocks, window_bytes, buffer_bytes;
	char transport_device[1024], image[1024], provider[64];
};
/* Structural validation only. Output is unchanged on error; no I/O or trust. */
int g_verity_transition_decode(const void *, size_t, struct g_verity_transition *);
#ifdef _KERNEL
struct g_verity_root;
/* Snapshot/decode a unique bound pair and check target provider resources.
 * Not signer authentication or root admission. Outputs unchanged on error. */
int g_verity_preload_transition(struct g_verity_transition *, struct g_verity_root *);
#endif
#endif
