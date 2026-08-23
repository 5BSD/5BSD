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

/*
 * Exercise the full MTRR MSR register file per Intel SDM Vol. 3, 12.11.2:
 * one MTRRcap, one IA32_MTRR_DEF_TYPE, 11 fixed-range MSRs (one 64K, two
 * 16K, eight 4K), and VMM_MTRR_VAR_MAX physbase/physmask variable pairs at
 * 0x200.  Assert both the write-then-read round trip and the raw MSR layout
 * against the specification, independent of the implementation's own output.
 */
ATF_TC_WITHOUT_HEAD(msr_register_file_roundtrip);
ATF_TC_BODY(msr_register_file_roundtrip, tc)
{
	struct vm_mtrr mtrr;
	uint64_t value;
	u_int i;

	memset(&mtrr, 0, sizeof(mtrr));

	/* IA32_MTRRcap (0xfe) is read-only and reports our fixed layout. */
	ATF_CHECK_EQ(vm_rdmtrr(&mtrr, MSR_MTRRcap, &value), 0);
	ATF_CHECK_EQ(value & DOC_MTRR_UC, DOC_MTRR_UC);
	ATF_CHECK_EQ(value & UINT64_C(0xff), VMM_MTRR_VAR_MAX);
	ATF_CHECK((value & MTRR_CAP_FIXED) != 0);
	ATF_CHECK((value & MTRR_CAP_WC) != 0);

	/* Every fixed4k MSR (0x268..0x26f) round-trips independently. */
	for (i = 0; i < nitems(mtrr.fixed4k); i++) {
		static const uint8_t types[5] = { DOC_MTRR_UC, DOC_MTRR_WC,
		    DOC_MTRR_WT, DOC_MTRR_WP, DOC_MTRR_WB };
		uint64_t pat = UINT64_C(0x0101010101010101) *
		    types[i % nitems(types)];

		ATF_REQUIRE_EQ(vm_wrmtrr(&mtrr, MSR_MTRR4kBase + i, pat,
		    DOC_MAXPHYADDR_MAX), 0);
		ATF_CHECK_EQ(mtrr.fixed4k[i], pat);
		ATF_REQUIRE_EQ(vm_rdmtrr(&mtrr, MSR_MTRR4kBase + i, &value), 0);
		ATF_CHECK_EQ(value, pat);
	}
	/* An invalid memory type in any lane is rejected. */
	ATF_CHECK_EQ(vm_wrmtrr(&mtrr, MSR_MTRR4kBase + 3,
	    UINT64_C(2) << 40, DOC_MAXPHYADDR_MAX), -1);

	/* Both fixed16k MSRs (0x258..0x259). */
	for (i = 0; i < nitems(mtrr.fixed16k); i++) {
		uint64_t pat = (i == 0) ? valid_fixed_types() :
		    UINT64_C(0x0400040004000400);

		ATF_REQUIRE_EQ(vm_wrmtrr(&mtrr, MSR_MTRR16kBase + i, pat,
		    DOC_MAXPHYADDR_MAX), 0);
		ATF_CHECK_EQ(mtrr.fixed16k[i], pat);
		ATF_REQUIRE_EQ(vm_rdmtrr(&mtrr, MSR_MTRR16kBase + i, &value), 0);
		ATF_CHECK_EQ(value, pat);
	}
	ATF_CHECK_EQ(vm_wrmtrr(&mtrr, MSR_MTRR16kBase + 1,
	    UINT64_C(3), DOC_MAXPHYADDR_MAX), -1);

	/* The single fixed64k MSR (0x250). */
	ATF_REQUIRE_EQ(vm_wrmtrr(&mtrr, MSR_MTRR64kBase, valid_fixed_types(),
	    DOC_MAXPHYADDR_MAX), 0);
	ATF_CHECK_EQ(mtrr.fixed64k, valid_fixed_types());
	ATF_REQUIRE_EQ(vm_rdmtrr(&mtrr, MSR_MTRR64kBase, &value), 0);
	ATF_CHECK_EQ(value, valid_fixed_types());
	ATF_CHECK_EQ(vm_wrmtrr(&mtrr, MSR_MTRR64kBase, UINT64_C(7),
	    DOC_MAXPHYADDR_MAX), -1);

	/*
	 * Every variable-range pair: even MSR offset -> IA32_MTRR_PHYSBASEn
	 * (address bits + type in [7:0]), odd offset -> IA32_MTRR_PHYSMASKn
	 * (address bits + VALID bit 11).
	 */
	for (i = 0; i < VMM_MTRR_VAR_MAX; i++) {
		uint64_t base = (((uint64_t)(i + 1)) << 20) | DOC_MTRR_WB;
		uint64_t mask = (UINT64_C(1) << 31) | DOC_MTRR_VALID;

		ATF_REQUIRE_EQ(vm_wrmtrr(&mtrr, MSR_MTRRVarBase + i * 2, base,
		    DOC_MAXPHYADDR_MAX), 0);
		ATF_REQUIRE_EQ(vm_wrmtrr(&mtrr, MSR_MTRRVarBase + i * 2 + 1,
		    mask, DOC_MAXPHYADDR_MAX), 0);
		ATF_CHECK_EQ(mtrr.var[i].base, base);
		ATF_CHECK_EQ(mtrr.var[i].mask, mask);
		ATF_REQUIRE_EQ(vm_rdmtrr(&mtrr, MSR_MTRRVarBase + i * 2,
		    &value), 0);
		ATF_CHECK_EQ(value, base);
		ATF_REQUIRE_EQ(vm_rdmtrr(&mtrr, MSR_MTRRVarBase + i * 2 + 1,
		    &value), 0);
		ATF_CHECK_EQ(value, mask);
	}

	/* Reads and writes of MSRs outside the MTRR range fail. */
	ATF_CHECK_EQ(vm_rdmtrr(&mtrr, MSR_MTRRVarBase +
	    (VMM_MTRR_VAR_MAX * 2), &value), -1);
	ATF_CHECK_EQ(vm_rdmtrr(&mtrr, MSR_MTRRcap - 1, &value), -1);
	ATF_CHECK_EQ(vm_wrmtrr(&mtrr, MSR_MTRRVarBase +
	    (VMM_MTRR_VAR_MAX * 2), 0, DOC_MAXPHYADDR_MAX), -1);
	ATF_CHECK_EQ(vm_wrmtrr(&mtrr, MSR_MTRRdefType + 1, 0,
	    DOC_MAXPHYADDR_MAX), -1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, validate_architectural_types);
	ATF_TP_ADD_TC(tp, write_rejects_without_mutation);
	ATF_TP_ADD_TC(tp, msr_register_file_roundtrip);
	return (atf_no_error());
}
