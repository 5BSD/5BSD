/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _SYS_ELF_CACHE_H_
#define _SYS_ELF_CACHE_H_
#include <sys/types.h>
/* All integer fields in the file are little endian. ELF bytes excluding per-image signature containers
 * occupy page-aligned slices; writable mappings are always private. */
#define ELF_CACHE_VERSION 1
#define ELF_CACHE_MAX_ENTRIES 4096
#define ELF_CACHE_NAME_MAX 128
#define ELF_CACHE_ALIGNMENT 65536U
#define ELF_CACHE_MAX_SIZE (4ULL * 1024 * 1024 * 1024)
#define ELF_CACHE_PATH "/usr/libdata/5bsd/cache/elf.cache"
#define ELF_CACHE_SEAL_PATH ELF_CACHE_PATH ".sig"
#define ELF_CACHE_DOMAIN "org.5bsd.elf-cache.v1"
struct elf_cache_header {
	uint8_t magic[8]; /* "5BSDELF\0" */
	uint32_t version;
	uint32_t count;
	uint64_t file_size;
	uint32_t alignment;
	uint32_t entry_size;
	uint8_t reserved[32];
};
struct elf_cache_entry {
	uint32_t directory; /* 0: /lib, 1: /usr/lib */
	uint32_t reserved;
	uint64_t offset;
	uint64_t size; /* restored unsigned ELF image */
	uint64_t source_size; /* original file, including any signature container */
	uint8_t sha256[32]; /* payload identity */
	uint8_t source_sha256[32]; /* exact source, before signature extraction */
	char name[ELF_CACHE_NAME_MAX];
};
_Static_assert(sizeof(struct elf_cache_header) == 64, "ELF cache header ABI");
_Static_assert(sizeof(struct elf_cache_entry) == 224, "ELF cache entry ABI");
/* Opt-in, separately signed relative layout; independently versioned cache payload. */
#define ELF_CACHE_LAYOUT_VERSION 1
#define ELF_CACHE_LAYOUT_DOMAIN "org.5bsd.elf-layout.v1"
#define ELF_CACHE_LAYOUT_MAX_SIZE (1024U * 1024U)
#define ELF_CACHE_LAYOUT_ALIGNMENT (2U * 1024U * 1024U)
#define ELF_CACHE_LAYOUT_MAX_SPAN (4ULL * 1024 * 1024 * 1024)
#define ELF_CACHE_RELRO_VERSION 1
#define ELF_CACHE_RELRO_MAX_SIZE (256U * 1024U * 1024U)
struct elf_cache_layout_header {
	uint8_t magic[8]; /* "5BSDLAY\0" */
	uint32_t version;
	uint32_t header_size;
	uint32_t machine;
	uint32_t page_size;
	uint32_t count;
	uint32_t entry_size;
	uint64_t slot_alignment;
	uint64_t layout_span;
	uint64_t cache_size;
	uint64_t relro_size;
	uint8_t cache_sha256[32];
	uint8_t reserved[32];
};
struct elf_cache_layout_entry {
	uint32_t cache_index;
	uint32_t reserved;
	uint64_t slot_offset;
	uint64_t map_size;
	uint64_t relro_vaddr;
	uint64_t relro_size;
	uint64_t relro_offset;
	uint8_t sha256[32];
};
struct elf_cache_relro_header {
	uint8_t magic[8]; /* "5BSDRLO\0" */
	uint32_t version;
	uint32_t header_size;
	uint64_t domain_id;
	uint64_t domain_base;
	uint32_t count;
	uint32_t completed_offset;
	uint64_t file_size;
	uint8_t cache_sha256[32];
	uint8_t reserved[48];
};
_Static_assert(sizeof(struct elf_cache_layout_header) == 128,
    "ELF cache layout header ABI");
_Static_assert(sizeof(struct elf_cache_layout_entry) == 80,
    "ELF cache layout entry ABI");
_Static_assert(sizeof(struct elf_cache_relro_header) == 128,
    "ELF cache RELRO header ABI");
#endif
