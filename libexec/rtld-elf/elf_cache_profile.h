/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef ELF_CACHE_PROFILE_H
#define ELF_CACHE_PROFILE_H
#include <sys/types.h>
#include <stdint.h>
/* Diagnostic records only. Never an authority, identity or policy input. */
#define ELF_PROFILE_MAGIC "ECLOAD1"
#define ELF_PROFILE_EXEC 1U
#define ELF_PROFILE_DLOPEN 2U
#define ELF_PROFILE_FAILED 4U
#define ELF_PROFILE_TRUNCATED 8U
#define ELF_PROFILE_FD 16U
#define ELF_PROFILE_CLOCK_ERROR 32U
enum elf_cache_reason {
    ELF_CACHE_OUTSIDE = 0, ELF_CACHE_UNAVAILABLE, ELF_CACHE_NOT_LISTED,
    ELF_CACHE_SIZE_CHANGED, ELF_CACHE_MAP_FAILED, ELF_CACHE_INELIGIBLE,
    ELF_CACHE_BYTES_CHANGED, ELF_CACHE_HIT, ELF_CACHE_SIGNATURE_FAILED
};
/* Fixed layout is shared by native and compatibility loaders. */
struct elf_cache_profile {
    char magic[8];
    uint32_t flags;
    uint32_t reason;
    uint64_t bytes;
    uint64_t lookup_ns;
    uint64_t cache_ns;
    uint64_t map_ns;
    uint64_t device;
    uint64_t inode;
    char path[256];
    char requested[128];
    char consumer[256];
};
_Static_assert(sizeof(struct elf_cache_profile) == 704, "loader profile ABI");
#ifdef RTLD_CACHE_PROFILE
uint64_t rtld_profile_clock(void);
void rtld_profile_emit(unsigned, unsigned, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, const char *, const char *, const char *);
#else
#define rtld_profile_clock() UINT64_C(0)
#define rtld_profile_emit(...) ((void)0)
#endif
#endif
