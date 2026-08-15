/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>

#include <machine/specialreg.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/amd64/vmm/x86.h"
#include "../../../sys/amd64/vmm/vmm_mtrr.c"

/* Intel SDM Vol. 3, 12.11.2.1.  Keep the oracle independent of the VMM. */
#define	DOC_MTRR_UC	UINT64_C(0)
#define	DOC_MTRR_WC	UINT64_C(1)
#define	DOC_MTRR_WT	UINT64_C(4)
#define	DOC_MTRR_WP	UINT64_C(5)
#define	DOC_MTRR_WB	UINT64_C(6)
#define	DOC_MTRR_FE	UINT64_C(0x400)
#define	DOC_MTRR_E	UINT64_C(0x800)
#define	DOC_MTRR_VALID	UINT64_C(0x800)
#define	DOC_MAXPHYADDR_MIN	32U
#define	DOC_MAXPHYADDR_MAX	52U

_Static_assert(MTRR_UNCACHEABLE == DOC_MTRR_UC, "UC encoding drifted");
_Static_assert(MTRR_WRITE_COMBINING == DOC_MTRR_WC, "WC encoding drifted");
_Static_assert(MTRR_WRITE_THROUGH == DOC_MTRR_WT, "WT encoding drifted");
_Static_assert(MTRR_WRITE_PROTECTED == DOC_MTRR_WP, "WP encoding drifted");
_Static_assert(MTRR_WRITE_BACK == DOC_MTRR_WB, "WB encoding drifted");
_Static_assert(MTRR_DEF_FIXED_ENABLE == DOC_MTRR_FE,
    "fixed-enable encoding drifted");
_Static_assert(MTRR_DEF_ENABLE == DOC_MTRR_E, "enable encoding drifted");
_Static_assert(MTRR_PHYSMASK_VALID == DOC_MTRR_VALID,
    "valid-mask encoding drifted");
_Static_assert(VMM_MTRR_PHYS_ADDR_WIDTH_MIN == DOC_MAXPHYADDR_MIN,
    "minimum MTRR MAXPHYADDR drifted");
_Static_assert(VMM_MTRR_PHYS_ADDR_WIDTH_MAX == DOC_MAXPHYADDR_MAX,
    "maximum MTRR MAXPHYADDR drifted");

static uint64_t
valid_fixed_types(void)
{

	return (UINT64_C(0x0605040106050401));
}

ATF_TC_WITHOUT_HEAD(validate_architectural_types);
ATF_TC_BODY(validate_architectural_types, tc)
{
	struct vm_mtrr mtrr;
	u_int i;

	memset(&mtrr, 0, sizeof(mtrr));
	ATF_CHECK_EQ(vm_mtrr_maxphyaddr(DOC_MAXPHYADDR_MIN - 1), 0);
	ATF_CHECK_EQ(vm_mtrr_maxphyaddr(DOC_MAXPHYADDR_MIN),
	    DOC_MAXPHYADDR_MIN);
	ATF_CHECK_EQ(vm_mtrr_maxphyaddr(36), 36);
	ATF_CHECK_EQ(vm_mtrr_maxphyaddr(DOC_MAXPHYADDR_MAX),
	    DOC_MAXPHYADDR_MAX);
	ATF_CHECK_EQ(vm_mtrr_maxphyaddr(DOC_MAXPHYADDR_MAX + 5),
	    DOC_MAXPHYADDR_MAX);
	ATF_CHECK(vm_mtrr_validate(&mtrr, DOC_MAXPHYADDR_MAX));
	mtrr.def_type = DOC_MTRR_E | DOC_MTRR_FE | DOC_MTRR_WB;
	mtrr.fixed64k = valid_fixed_types();
	for (i = 0; i < nitems(mtrr.fixed16k); i++)
		mtrr.fixed16k[i] = valid_fixed_types();
	for (i = 0; i < nitems(mtrr.fixed4k); i++)
		mtrr.fixed4k[i] = valid_fixed_types();
	for (i = 0; i < nitems(mtrr.var); i++) {
		mtrr.var[i].base = ((uint64_t)i << 12) | DOC_MTRR_WT;
		mtrr.var[i].mask = DOC_MTRR_VALID;
	}
	ATF_CHECK(vm_mtrr_validate(&mtrr, DOC_MAXPHYADDR_MAX));
	mtrr.var[0].base = (UINT64_C(1) << 35) | DOC_MTRR_WB;
	mtrr.var[0].mask = (UINT64_C(1) << 35) | DOC_MTRR_VALID;
	ATF_CHECK(vm_mtrr_validate(&mtrr, 36));
	mtrr.var[0].base = (UINT64_C(1) << 36) | DOC_MTRR_WB;
	ATF_CHECK(!vm_mtrr_validate(&mtrr, 36));
	mtrr.var[0].base = DOC_MTRR_WB;
	mtrr.var[0].mask = (UINT64_C(1) << 36) | DOC_MTRR_VALID;
	ATF_CHECK(!vm_mtrr_validate(&mtrr, 36));
	mtrr.var[0].mask = DOC_MTRR_VALID;
	ATF_CHECK(!vm_mtrr_validate(&mtrr, DOC_MAXPHYADDR_MIN - 1));
	ATF_CHECK(!vm_mtrr_validate(&mtrr, DOC_MAXPHYADDR_MAX + 1));

	mtrr.def_type = 2;
	ATF_CHECK(!vm_mtrr_validate(&mtrr, DOC_MAXPHYADDR_MAX));
	mtrr.def_type = DOC_MTRR_WB | (UINT64_C(1) << 63);
	ATF_CHECK(!vm_mtrr_validate(&mtrr, DOC_MAXPHYADDR_MAX));
	mtrr.def_type = DOC_MTRR_WB;
	mtrr.fixed4k[7] = 2;
	ATF_CHECK(!vm_mtrr_validate(&mtrr, DOC_MAXPHYADDR_MAX));
	mtrr.fixed4k[7] = 0;
	mtrr.fixed16k[1] = UINT64_C(3) << 56;
	ATF_CHECK(!vm_mtrr_validate(&mtrr, DOC_MAXPHYADDR_MAX));
	mtrr.fixed16k[1] = 0;
	mtrr.fixed64k = UINT64_C(7) << 24;
	ATF_CHECK(!vm_mtrr_validate(&mtrr, DOC_MAXPHYADDR_MAX));
	mtrr.fixed64k = 0;
	mtrr.var[9].base = 2;
	ATF_CHECK(!vm_mtrr_validate(&mtrr, DOC_MAXPHYADDR_MAX));
	mtrr.var[9].base = UINT64_C(1) << 63;
	ATF_CHECK(!vm_mtrr_validate(&mtrr, DOC_MAXPHYADDR_MAX));
	mtrr.var[9].base = 0;
	mtrr.var[9].mask = UINT64_C(1) << 63;
	ATF_CHECK(!vm_mtrr_validate(&mtrr, DOC_MAXPHYADDR_MAX));
	ATF_CHECK(!vm_mtrr_validate(NULL, DOC_MAXPHYADDR_MAX));
}

ATF_TC_WITHOUT_HEAD(write_rejects_without_mutation);
ATF_TC_BODY(write_rejects_without_mutation, tc)
{
	struct vm_mtrr before, mtrr;
	uint64_t value;

	memset(&mtrr, 0, sizeof(mtrr));
	before = mtrr;
	ATF_CHECK_EQ(vm_wrmtrr(&mtrr, MSR_MTRRdefType, 2,
	    DOC_MAXPHYADDR_MAX), -1);
	ATF_CHECK_EQ(memcmp(&mtrr, &before, sizeof(mtrr)), 0);
	ATF_CHECK_EQ(vm_wrmtrr(&mtrr, MSR_MTRR4kBase, 2,
	    DOC_MAXPHYADDR_MAX), -1);
	ATF_CHECK_EQ(memcmp(&mtrr, &before, sizeof(mtrr)), 0);
	ATF_CHECK_EQ(vm_wrmtrr(&mtrr, MSR_MTRRVarBase, 3,
	    DOC_MAXPHYADDR_MAX), -1);
	ATF_CHECK_EQ(memcmp(&mtrr, &before, sizeof(mtrr)), 0);
	ATF_CHECK_EQ(vm_wrmtrr(&mtrr, MSR_MTRRVarBase + 1,
	    UINT64_C(1) << 63, DOC_MAXPHYADDR_MAX), -1);
	ATF_CHECK_EQ(memcmp(&mtrr, &before, sizeof(mtrr)), 0);
	ATF_CHECK_EQ(vm_wrmtrr(&mtrr, MSR_MTRRcap, 0,
	    DOC_MAXPHYADDR_MAX), -1);
	ATF_CHECK_EQ(memcmp(&mtrr, &before, sizeof(mtrr)), 0);
	ATF_CHECK_EQ(vm_wrmtrr(&mtrr, MSR_MTRRVarBase,
	    (UINT64_C(1) << 36) | DOC_MTRR_WB, 36), -1);
	ATF_CHECK_EQ(memcmp(&mtrr, &before, sizeof(mtrr)), 0);
	ATF_CHECK_EQ(vm_wrmtrr(&mtrr, MSR_MTRRVarBase, DOC_MTRR_WB,
	    DOC_MAXPHYADDR_MIN - 1), -1);
	ATF_CHECK_EQ(memcmp(&mtrr, &before, sizeof(mtrr)), 0);
	ATF_CHECK_EQ(vm_wrmtrr(NULL, MSR_MTRRVarBase, DOC_MTRR_WB,
	    DOC_MAXPHYADDR_MAX), -1);

	ATF_REQUIRE_EQ(vm_wrmtrr(&mtrr, MSR_MTRRdefType,
	    DOC_MTRR_E | DOC_MTRR_WB, DOC_MAXPHYADDR_MAX), 0);
	ATF_REQUIRE_EQ(vm_wrmtrr(&mtrr, MSR_MTRR4kBase,
	    valid_fixed_types(), DOC_MAXPHYADDR_MAX), 0);
	ATF_REQUIRE_EQ(vm_wrmtrr(&mtrr, MSR_MTRRVarBase,
	    UINT64_C(0x2000) | DOC_MTRR_WC, 36), 0);
	ATF_REQUIRE_EQ(vm_wrmtrr(&mtrr, MSR_MTRRVarBase + 1,
	    DOC_MTRR_VALID, 36), 0);
	ATF_CHECK(vm_mtrr_validate(&mtrr, 36));
	ATF_REQUIRE_EQ(vm_rdmtrr(&mtrr, MSR_MTRRdefType, &value), 0);
	ATF_CHECK_EQ(value, DOC_MTRR_E | DOC_MTRR_WB);
	ATF_REQUIRE_EQ(vm_rdmtrr(&mtrr, MSR_MTRRcap, &value), 0);
	ATF_CHECK_EQ(value, MTRR_CAP_WC | MTRR_CAP_FIXED |
	    VMM_MTRR_VAR_MAX);
	ATF_CHECK_EQ(vm_rdmtrr(&mtrr, UINT_MAX, &value), -1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, validate_architectural_types);
	ATF_TP_ADD_TC(tp, write_rejects_without_mutation);
	return (atf_no_error());
}
