/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/jail.h>
#include <sys/sysctl.h>
#include <atf-c.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <jail.h>

static void
roundtrip(const char *name, unsigned kind, const char *fmt, size_t size,
    const char *input)
{
    struct jailparam jp;
    char *value;
    ATF_REQUIRE_EQ(0, jailparam_init_metadata(&jp, name, kind, fmt, size));
    ATF_REQUIRE_EQ(0, jailparam_import(&jp, input));
    value = jailparam_export(&jp);
    ATF_REQUIRE(value != NULL);
    ATF_CHECK_STREQ(input, value);
    free(value);
    jailparam_free(&jp, 1);
}

ATF_TC_WITHOUT_HEAD(metadata_roundtrip);
ATF_TC_BODY(metadata_roundtrip, tc)
{
    (void)tc;
    roundtrip("name", CTLTYPE_STRING | CTLFLAG_RW, "A", 256, "test.namespace");
    roundtrip("ip4.addr", CTLTYPE_STRUCT | CTLFLAG_RW, "S,in_addr,a", 0,
        "127.0.0.1,127.0.0.2");
    roundtrip("ip6.addr", CTLTYPE_STRUCT | CTLFLAG_RW, "S,in6_addr,a", 0, "::1");
    roundtrip("vnet", CTLTYPE_INT | CTLFLAG_RW, "E,jailsys", 0, "new");
}

ATF_TC_WITHOUT_HEAD(metadata_invalid);
ATF_TC_BODY(metadata_invalid, tc)
{
    struct jailparam jp;
    (void)tc;
    ATF_REQUIRE_ERRNO(EINVAL,
        jailparam_init_metadata(&jp, "name", CTLTYPE_STRING, "", 16) == -1);
    ATF_REQUIRE_ERRNO(EOPNOTSUPP,
        jailparam_init_metadata(&jp, "node", CTLTYPE_NODE, "N", 0) == -1);
}

ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, metadata_roundtrip);
    ATF_TP_ADD_TC(tp, metadata_invalid);
    return atf_no_error();
}
