/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <atf-c.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include "elf_cache_profile.h"
static struct elf_cache_profile captured;
int utrace(const void *, size_t);
int
utrace(const void *data, size_t length)
{
    ATF_REQUIRE_EQ(length, sizeof(captured));
    memcpy(&captured, data, length);
    errno = EPERM;
    return (-1);
}
ATF_TC_WITHOUT_HEAD(record);
ATF_TC_BODY(record, tc)
{
    (void)tc;
    ATF_REQUIRE_EQ(offsetof(struct elf_cache_profile, path), 64);
    ATF_REQUIRE_EQ(offsetof(struct elf_cache_profile, requested), 320);
    ATF_REQUIRE_EQ(offsetof(struct elf_cache_profile, consumer), 448);
    errno = ENOENT;
    rtld_profile_emit(ELF_PROFILE_DLOPEN, ELF_CACHE_HIT, 4096, 10, 20, 30, 17, 42,
        "#123/libchannel.so.1", "libchannel.so.1", "#456/service");
    ATF_REQUIRE_EQ(errno, ENOENT);
    ATF_REQUIRE_EQ(memcmp(captured.magic, ELF_PROFILE_MAGIC, 8), 0);
    ATF_REQUIRE_STREQ(captured.path, "libchannel.so.1");
    ATF_REQUIRE_STREQ(captured.consumer, "service");
    ATF_REQUIRE_EQ(captured.flags, ELF_PROFILE_DLOPEN | ELF_PROFILE_FD);
    ATF_REQUIRE_EQ(captured.bytes, 4096);
    ATF_REQUIRE_EQ(captured.device, 17);
    ATF_REQUIRE_EQ(captured.inode, 42);
    ATF_REQUIRE_EQ(captured.cache_ns, 20);
    ATF_REQUIRE_EQ(captured.path[255], 0);
    char longname[1024]; memset(longname, 'a', sizeof(longname));
    longname[sizeof(longname)-1] = 0;
    rtld_profile_emit(0, ELF_CACHE_OUTSIDE, 0, 0, 0, 0, 0, 0, longname, "", "");
    ATF_REQUIRE(captured.flags & ELF_PROFILE_TRUNCATED);
    ATF_REQUIRE_EQ(captured.path[255], 0);
    rtld_profile_emit(0, ELF_CACHE_OUTSIDE, 0, 0, 0, 0, 0, 0, NULL, NULL, "");
    ATF_REQUIRE(captured.flags & ELF_PROFILE_FD);
    ATF_REQUIRE_STREQ(captured.path, "<fd>");
    errno = EINVAL;
    ATF_REQUIRE(rtld_profile_clock() != 0);
    ATF_REQUIRE_EQ(errno, EINVAL);
}
ATF_TP_ADD_TCS(tp) { ATF_TP_ADD_TC(tp, record); return atf_no_error(); }
