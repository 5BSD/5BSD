/* SPDX-License-Identifier: BSD-2-Clause */
#include "elf_cache_profile.h"
#ifdef RTLD_CACHE_PROFILE
#include <sys/syscall.h>
#include <sys/ktrace.h>

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "rtld_libc.h"
uint64_t
rtld_profile_clock(void)
{
    struct timespec ts;
    int saved = errno;
    uint64_t result = 0;
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts) == 0)
        result = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    errno = saved;
    return (result);
}
static void
profile_name(struct elf_cache_profile *event, char *out, size_t size,
    const char *name, bool descriptor)
{
    if (name == NULL) { name = "<fd>"; if (descriptor) event->flags |= ELF_PROFILE_FD; }
    /* rtld's synthetic #fd/path must not disclose descriptor numbers. */
    if (name[0] == '#') {
        const char *slash = strchr(name, '/');
        name = slash != NULL ? slash + 1 : "<fd>";
        if (descriptor) event->flags |= ELF_PROFILE_FD;
    }
    if (strlcpy(out, name, size) >= size)
        event->flags |= ELF_PROFILE_TRUNCATED;
}
void
rtld_profile_emit(unsigned flags, unsigned reason, uint64_t bytes,
    uint64_t lookup, uint64_t cache, uint64_t map, uint64_t device, uint64_t inode,
    const char *path,
    const char *requested, const char *consumer)
{
    struct elf_cache_profile event;
    int saved = errno;
    memset(&event, 0, sizeof(event));
    memcpy(event.magic, ELF_PROFILE_MAGIC, sizeof(event.magic));
    event.flags = flags;
    event.reason = reason;
    event.bytes = bytes;
    event.lookup_ns = lookup;
    event.cache_ns = cache;
    event.map_ns = map;
    event.device = device;
    event.inode = inode;
    profile_name(&event, event.path, sizeof(event.path), path, true);
    profile_name(&event, event.requested, sizeof(event.requested), requested, false);
    profile_name(&event, event.consumer, sizeof(event.consumer), consumer, false);
    /* No file opens, descriptor delivery, allocation or authority changes.
     * A privileged DTrace syscall collector can observe this without setting
     * process ktrace flags, which deliberately prevent authority acquisition. */
    (void)utrace(&event, sizeof(event));
    errno = saved;
}
#endif
