/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/elf.h>
#include <atf-c.h>
#include <stdint.h>
#include <string.h>
#include "elf_cache_eligible.h"
struct fixture {
    Elf_Ehdr h;
    Elf_Phdr p[2];
    Elf_Dyn dynamic[2];
    unsigned char padding[256];
};
static struct fixture
fixture(void)
{
    struct fixture f = {0};
    memcpy(f.h.e_ident, ELFMAG, SELFMAG);
    f.h.e_ident[EI_CLASS] = ELF_TARG_CLASS;
    f.h.e_ident[EI_DATA] = ELF_TARG_DATA;
    f.h.e_ident[EI_VERSION] = EV_CURRENT;
    f.h.e_version = EV_CURRENT;
    f.h.e_type = ET_DYN;
    f.h.e_machine = ELF_TARG_MACH;
    f.h.e_ehsize = sizeof(f.h);
    f.h.e_phoff = sizeof(f.h);
    f.h.e_phentsize = sizeof(f.p[0]);
    f.h.e_phnum = 2;
    f.p[0].p_type = PT_LOAD;
    f.p[0].p_flags = PF_R | PF_X;
    f.p[0].p_filesz = f.p[0].p_memsz = sizeof(f);
    f.p[0].p_align = 4096;
    f.p[1].p_type = PT_DYNAMIC;
    f.p[1].p_offset = sizeof(f.h) + sizeof(f.p);
    f.p[1].p_filesz = sizeof(f.dynamic);
    return (f);
}
ATF_TC_WITHOUT_HEAD(bounds);
ATF_TC_BODY(bounds, tc)
{
    (void)tc;
    struct fixture f = fixture();
    ATF_REQUIRE(rtld_cache_eligible(&f, sizeof(f), 4096));
    ATF_REQUIRE(!rtld_cache_eligible(&f, sizeof(f.h) - 1, 4096));
    f.h.e_phoff = UINTPTR_MAX;
    ATF_REQUIRE(!rtld_cache_eligible(&f, sizeof(f), 4096));
    f = fixture(); f.p[0].p_offset = sizeof(f);
    ATF_REQUIRE(!rtld_cache_eligible(&f, sizeof(f), 4096));
    f = fixture(); f.p[0].p_vaddr = UINTPTR_MAX - 1;
    ATF_REQUIRE(!rtld_cache_eligible(&f, sizeof(f), 4096));
    f = fixture(); f.p[0].p_memsz--;
    ATF_REQUIRE(!rtld_cache_eligible(&f, sizeof(f), 4096));
    f = fixture(); f.p[1].p_filesz++;
    ATF_REQUIRE(!rtld_cache_eligible(&f, sizeof(f), 4096));
}
ATF_TC_WITHOUT_HEAD(permissions);
ATF_TC_BODY(permissions, tc)
{
    (void)tc;
    struct fixture f = fixture();
    f.p[0].p_flags |= PF_W;
    ATF_REQUIRE(!rtld_cache_eligible(&f, sizeof(f), 4096));
    f = fixture(); f.p[0].p_memsz++;
    ATF_REQUIRE(!rtld_cache_eligible(&f, sizeof(f), 4096));
    f.p[0].p_flags = PF_R | PF_W;
    ATF_REQUIRE(rtld_cache_eligible(&f, sizeof(f), 4096));
    f = fixture(); f.dynamic[0].d_tag = DT_TEXTREL;
    ATF_REQUIRE(!rtld_cache_eligible(&f, sizeof(f), 4096));
    f = fixture(); f.dynamic[0].d_tag = DT_FLAGS;
    f.dynamic[0].d_un.d_val = DF_TEXTREL;
    ATF_REQUIRE(!rtld_cache_eligible(&f, sizeof(f), 4096));
    f = fixture(); f.p[1].p_type = PT_INTERP;
    ATF_REQUIRE(!rtld_cache_eligible(&f, sizeof(f), 4096));
}
ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, bounds);
    ATF_TP_ADD_TC(tp, permissions);
    return (atf_no_error());
}
