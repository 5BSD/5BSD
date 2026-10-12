/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _SYS_CAPIMAGE_H_
#define _SYS_CAPIMAGE_H_
#include <sys/types.h>
#include <sys/stdint.h>

#define CAPIMAGE_DOMAIN "org.5bsd.signed-elf.v1"
/* On-disk fields are little endian, independent of the ELF byte order. */
#define CAPIMAGE_NOTE_TYPE UINT32_C(0x35425344)
#define CAPIMAGE_VERSION 1U
#define CAPIMAGE_POLICY_MAX (1024U * 1024U)
#define CAPIMAGE_FILE_MAX (512ULL * 1024ULL * 1024ULL)
#define CAPIMAGE_KEY_SIZE 32U
#define CAPIMAGE_SIGNATURE_SIZE 64U
struct capimage_header {
	uint8_t magic[8];
	uint32_t version;
	uint32_t policy_size;
	uint8_t key[CAPIMAGE_KEY_SIZE];
	uint8_t signature[CAPIMAGE_SIGNATURE_SIZE];
};
_Static_assert(sizeof(struct capimage_header) == 112, "capimage disk ABI");
/* Post-link embedding preserves all existing ELF offsets. The footer and
 * appended policy are included in the whole-file signature. This is the only
 * final signature representation; .5bsd.policy is unsigned build input. */
struct capimage_footer {
	uint8_t magic[8]; /* 5BSDEND followed by NUL */
	uint32_t version;
	uint32_t reserved;
	uint64_t offset;
	uint64_t size;
};
_Static_assert(sizeof(struct capimage_footer) == 32, "capimage footer ABI");

/* Integrity-only pinned handles. No field confers publisher or platform trust. */
#define CAPIMAGE_HANDLE_VERSION 1U
#define CAPIMAGE_MAC_POLICY "mac_veriexec"
#define CAPIMAGE_PREPARE_SYSCALL 6
#define CAPIMAGE_HANDLE_INFO_SYSCALL 7
#define CAPIMAGE_PREPARE_REQUIRED 0x01U
#define CAPIMAGE_PREPARE_RAW_DIGEST 0x02U
#define CAPIMAGE_PREPARE_VVERIFY 0x04U
#define CAPIMAGE_INFO_RAW_DIGEST 0x01U
struct capimage_prepare {
	uint32_t version;
	uint32_t struct_size;
	int32_t source_fd;
	uint32_t flags;
	uint64_t reserved[4];
};
struct capimage_info {
	uint32_t version;
	uint32_t struct_size;
	uint32_t available;
	uint32_t container_version;
	uint64_t file_size;
	uint64_t policy_offset;
	uint64_t policy_size;
	uint8_t image_digest[32];
	uint8_t key[CAPIMAGE_KEY_SIZE];
	uint8_t policy_digest[32];
	uint8_t raw_digest[32];
	uint64_t reserved[4];
};
_Static_assert(sizeof(struct capimage_prepare) == 48, "prepare image ABI");
_Static_assert(sizeof(struct capimage_info) == 200, "image handle ABI");
/* Kernel validates the exact descriptor type before returning metadata. */
struct capimage_info_request {
	uint32_t version;
	uint32_t struct_size;
	int32_t handle_fd;
	uint32_t reserved;
	struct capimage_info info;
};
_Static_assert(sizeof(struct capimage_info_request) == 216, "handle info ABI");

#endif /* _SYS_CAPIMAGE_H_ */
