/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _SYS_CAPIMAGE_H_
#define _SYS_CAPIMAGE_H_
#include <sys/types.h>
#include <sys/stdint.h>

#define CAPIMAGE_DOMAIN "org.5bsd.signed-elf.v1"
/* On-disk fields are little endian, independent of the ELF byte order. */
#define CAPIMAGE_NOTE_TYPE UINT32_C(0x35425344)
#define CAPIMAGE_VERSION 1U
#define CAPIMAGE_SEAL_VERSION 1U
#define CAPIMAGE_ELF_NOTE_TYPE UINT32_C(0x35425345)
#define CAPIMAGE_ELF_SECTION ".note.5bsd.signature"
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
/* The signature appends a non-allocated ELF note and replacement section/name tables.
 * Only e_sh* fields change in the original prefix. The authenticated rollback
 * record restores the exact original ELF. */
struct capimage_footer {
	uint8_t magic[8]; /* 5BSDEND followed by NUL */
	uint32_t version;
	uint32_t reserved;
	uint64_t offset;
	uint64_t size;
};
_Static_assert(sizeof(struct capimage_footer) == 32, "capimage footer ABI");

/* Note descriptor: header, policy bytes, then this fixed record. */
struct capimage_elf_original {
	uint8_t magic[8]; /* 5BSDORIG */
	uint32_t version;
	uint32_t header_size;
	uint64_t original_size;
	uint8_t original_header[64]; /* ELF32 tail is zero */
};
_Static_assert(sizeof(struct capimage_elf_original) == 88, "original ELF ABI");
/* Structural information only: verification and publisher trust are separate. */
struct capimage_elf_info {
	uint32_t version;
	uint32_t header_size;
	uint64_t descriptor_offset;
	uint64_t descriptor_size;
	uint64_t original_size;
	uint8_t original_header[64];
};

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
