/* SPDX-License-Identifier: BSD-2-Clause */
/* Prove rule-owned environment exists before the ATF harness enters main. */
#include <atf-c.h>
#include <stdlib.h>
#include <string.h>

static int alpha, beta, disabled;
static void __attribute__((constructor))
capture(void)
{
    const char *value = getenv("SOURCE_OWNED_VALUE");
    const char *dof = getenv("DTRACE_DOF_INIT_DISABLE");
    alpha = value != NULL && strcmp(value, "alpha two words") == 0;
    beta = value != NULL && strcmp(value, "beta=distinct") == 0;
    disabled = dof != NULL && strcmp(dof, "1") == 0;
}
ATF_TC_WITHOUT_HEAD(alpha);
ATF_TC_BODY(alpha, tc)
{
    (void)tc;
    ATF_REQUIRE(disabled && alpha && !beta);
}
ATF_TC_WITHOUT_HEAD(beta);
ATF_TC_BODY(beta, tc)
{
    (void)tc;
    ATF_REQUIRE(disabled && beta && !alpha);
}
ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, alpha);
    ATF_TP_ADD_TC(tp, beta);
    return atf_no_error();
}
