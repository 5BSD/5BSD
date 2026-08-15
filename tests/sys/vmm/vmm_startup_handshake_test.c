/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/dev/vmm/vmm_startup_mode.c"
#include "../../../sys/dev/vmm/vmm_startup_handshake.c"

#define	HANDSHAKE_OWNER	UINT64_C(0x8182736455463728)

ATF_TC_WITHOUT_HEAD(default_is_locked_without_thread_handshake);
ATF_TC_BODY(default_is_locked_without_thread_handshake, tc)
{
	struct vmm_startup_handshake handshake;

	(void)tc;
	ATF_REQUIRE_EQ(vmm_startup_handshake_init(&handshake,
	    HANDSHAKE_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_lock_default(&handshake), 0);
	ATF_CHECK_EQ(handshake.phase, VMM_STARTUP_HANDSHAKE_COMMITTED);
	ATF_CHECK_EQ(handshake.mode.owner, VMM_STARTUP_OWNER_USERSPACE);
	ATF_CHECK_EQ(handshake.mode.execution,
	    VMM_STARTUP_EXECUTION_USERSPACE_RESUME);
	ATF_CHECK_EQ(handshake.mode.locked, 1);
	ATF_CHECK_EQ(vmm_startup_handshake_lock_default(&handshake), EBUSY);
}

ATF_TC_WITHOUT_HEAD(kernel_requires_every_distinct_vcpu_and_one_bsp);
ATF_TC_BODY(kernel_requires_every_distinct_vcpu_and_one_bsp, tc)
{
	struct vmm_startup_handshake_vcpu vcpus[4];
	struct vmm_startup_handshake handshake;

	(void)tc;
	memset(vcpus, 0, sizeof(vcpus));
	ATF_REQUIRE_EQ(vmm_startup_handshake_init(&handshake,
	    HANDSHAKE_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_configure_kernel(&handshake,
	    vcpus, 4), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_enter(&handshake, 0, true), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_enter(&handshake, 1, false), 0);
	ATF_CHECK_EQ(vmm_startup_handshake_enter(&handshake, 1, false),
	    EALREADY);
	ATF_CHECK_EQ(vmm_startup_handshake_enter(&handshake, 1, true), EBUSY);
	ATF_REQUIRE_EQ(vmm_startup_handshake_enter(&handshake, 2, false), 0);
	ATF_CHECK_EQ(vmm_startup_handshake_commit(&handshake), EAGAIN);
	ATF_REQUIRE_EQ(vmm_startup_handshake_enter(&handshake, 3, false), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_commit(&handshake), 0);
	ATF_CHECK_EQ(vmm_startup_handshake_enter(&handshake, 0, true),
	    EALREADY);
	ATF_CHECK_EQ(vmm_startup_handshake_enter(&handshake, 3, false),
	    EALREADY);
	ATF_CHECK_EQ(vmm_startup_handshake_enter(&handshake, 3, true), EBUSY);
	ATF_CHECK_EQ(handshake.mode.owner, VMM_STARTUP_OWNER_KERNEL);
	ATF_CHECK_EQ(handshake.mode.execution,
	    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT);
	ATF_CHECK_EQ(handshake.mode.locked, 1);
}

ATF_TC_WITHOUT_HEAD(missing_or_duplicate_bsp_is_rejected);
ATF_TC_BODY(missing_or_duplicate_bsp_is_rejected, tc)
{
	struct vmm_startup_handshake_vcpu vcpus[2];
	struct vmm_startup_handshake handshake;

	(void)tc;
	memset(vcpus, 0, sizeof(vcpus));
	ATF_REQUIRE_EQ(vmm_startup_handshake_init(&handshake,
	    HANDSHAKE_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_configure_kernel(&handshake,
	    vcpus, 2), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_enter(&handshake, 0, false), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_enter(&handshake, 1, false), 0);
	ATF_CHECK_EQ(vmm_startup_handshake_commit(&handshake), EAGAIN);

	memset(vcpus, 0, sizeof(vcpus));
	ATF_REQUIRE_EQ(vmm_startup_handshake_init(&handshake,
	    HANDSHAKE_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_configure_kernel(&handshake,
	    vcpus, 2), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_enter(&handshake, 0, true), 0);
	ATF_CHECK_EQ(vmm_startup_handshake_enter(&handshake, 1, true), EBUSY);
}

ATF_TC_WITHOUT_HEAD(canonical_array_and_failure_atomicity);
ATF_TC_BODY(canonical_array_and_failure_atomicity, tc)
{
	struct vmm_startup_handshake_vcpu vcpus[2], vcpus_before[2];
	struct vmm_startup_handshake before, handshake;

	(void)tc;
	memset(vcpus, 0, sizeof(vcpus));
	ATF_REQUIRE_EQ(vmm_startup_handshake_init(&handshake,
	    HANDSHAKE_OWNER), 0);
	before = handshake;
	vcpus[1].entered = 1;
	memcpy(vcpus_before, vcpus, sizeof(vcpus));
	ATF_CHECK_EQ(vmm_startup_handshake_configure_kernel(&handshake,
	    vcpus, 2), EBUSY);
	ATF_CHECK_EQ(memcmp(&handshake, &before, sizeof(handshake)), 0);
	ATF_CHECK_EQ(memcmp(vcpus, vcpus_before, sizeof(vcpus)), 0);
	vcpus[1].entered = 0;
	ATF_REQUIRE_EQ(vmm_startup_handshake_configure_kernel(&handshake,
	    vcpus, 2), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_enter(&handshake, 0, true), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_enter(&handshake, 1, false), 0);
	vcpus[1].storage_cookie = 0;
	before = handshake;
	ATF_CHECK_EQ(vmm_startup_handshake_commit(&handshake), EINVAL);
	ATF_CHECK_EQ(memcmp(&handshake, &before, sizeof(handshake)), 0);
}

ATF_TC_WITHOUT_HEAD(corruption_is_not_reported_as_incomplete);
ATF_TC_BODY(corruption_is_not_reported_as_incomplete, tc)
{
	struct vmm_startup_handshake_vcpu vcpus[2];
	struct vmm_startup_handshake handshake;

	(void)tc;
	memset(vcpus, 0, sizeof(vcpus));
	ATF_REQUIRE_EQ(vmm_startup_handshake_init(&handshake,
	    HANDSHAKE_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_configure_kernel(&handshake,
	    vcpus, 2), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_enter(&handshake, 0, true), 0);
	handshake.entered_vcpus = 0;
	ATF_CHECK_EQ(vmm_startup_handshake_commit(&handshake), EINVAL);
}

ATF_TC_WITHOUT_HEAD(cancel_invalidates_external_storage);
ATF_TC_BODY(cancel_invalidates_external_storage, tc)
{
	struct vmm_startup_handshake_vcpu vcpus[2];
	struct vmm_startup_handshake handshake;
	uint64_t generation;

	(void)tc;
	memset(vcpus, 0, sizeof(vcpus));
	ATF_REQUIRE_EQ(vmm_startup_handshake_init(&handshake,
	    HANDSHAKE_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_configure_kernel(&handshake,
	    vcpus, 2), 0);
	generation = handshake.generation;
	ATF_REQUIRE_EQ(vmm_startup_handshake_cancel(&handshake), 0);
	ATF_CHECK_EQ(vmm_startup_handshake_validate(&handshake), 0);
	ATF_CHECK_EQ(handshake.phase, VMM_STARTUP_HANDSHAKE_CANCELLED);
	ATF_CHECK_EQ(handshake.generation, generation + 1);
	ATF_CHECK_EQ(handshake.vcpus, NULL);
	ATF_CHECK_EQ(handshake.vcpus_cookie, 0);
	ATF_CHECK_EQ(handshake.expected_vcpus, 0);
	ATF_CHECK_EQ(handshake.entered_vcpus, 0);
	ATF_CHECK(memcmp(vcpus, (struct vmm_startup_handshake_vcpu[2]) {{ 0 }},
	    sizeof(vcpus)) == 0);
	ATF_CHECK_EQ(vmm_startup_handshake_cancel(&handshake), 0);
	ATF_CHECK_EQ(vmm_startup_handshake_commit(&handshake), EBUSY);
}

ATF_TC_WITHOUT_HEAD(retire_is_unconditional_and_terminal);
ATF_TC_BODY(retire_is_unconditional_and_terminal, tc)
{
	struct vmm_startup_handshake_vcpu vcpus[1];
	struct vmm_startup_handshake handshake;

	(void)tc;
	memset(vcpus, 0, sizeof(vcpus));
	ATF_REQUIRE_EQ(vmm_startup_handshake_init(&handshake,
	    HANDSHAKE_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_configure_kernel(&handshake,
	    vcpus, 1), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_enter(&handshake, 0, true), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_commit(&handshake), 0);
	ATF_CHECK_EQ(vmm_startup_handshake_cancel(&handshake), EBUSY);
	handshake.generation = UINT64_MAX;
	vcpus[0].generation = UINT64_MAX;
	ATF_REQUIRE_EQ(vmm_startup_handshake_retire(&handshake), 0);
	ATF_CHECK_EQ(handshake.phase, VMM_STARTUP_HANDSHAKE_CANCELLED);
	ATF_CHECK_EQ(handshake.generation, UINT64_MAX);
	ATF_CHECK_EQ(handshake.vcpus, NULL);
	ATF_CHECK(memcmp(vcpus, (struct vmm_startup_handshake_vcpu[1]) {{ 0 }},
	    sizeof(vcpus)) == 0);
	ATF_CHECK_EQ(vmm_startup_handshake_retire(&handshake), 0);
}

ATF_TC_WITHOUT_HEAD(reset_recollects_locked_kernel_owner);
ATF_TC_BODY(reset_recollects_locked_kernel_owner, tc)
{
	struct vmm_startup_handshake_vcpu vcpus[2];
	struct vmm_startup_handshake handshake;
	uint64_t generation;

	(void)tc;
	memset(vcpus, 0, sizeof(vcpus));
	ATF_REQUIRE_EQ(vmm_startup_handshake_init(&handshake,
	    HANDSHAKE_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_configure_kernel(&handshake,
	    vcpus, 2), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_enter(&handshake, 0, true), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_enter(&handshake, 1, false), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_commit(&handshake), 0);
	generation = handshake.generation;

	ATF_REQUIRE_EQ(vmm_startup_handshake_reset_check(&handshake), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_reset(&handshake), 0);
	ATF_CHECK_EQ(vmm_startup_handshake_validate(&handshake), 0);
	ATF_CHECK_EQ(handshake.phase, VMM_STARTUP_HANDSHAKE_COLLECTING);
	ATF_CHECK_EQ(handshake.mode.locked, 1);
	ATF_CHECK_EQ(handshake.mode.owner, VMM_STARTUP_OWNER_KERNEL);
	ATF_CHECK_EQ(handshake.generation, generation + 1);
	ATF_CHECK_EQ(handshake.expected_vcpus, 2);
	ATF_CHECK_EQ(handshake.entered_vcpus, 0);
	ATF_CHECK_EQ(handshake.bootstrap_entered, 0);
	ATF_CHECK_EQ(vcpus[0].generation, generation + 1);
	ATF_CHECK_EQ(vcpus[1].generation, generation + 1);
	ATF_CHECK_EQ(vcpus[0].entered, 0);
	ATF_CHECK_EQ(vcpus[1].entered, 0);
	ATF_CHECK_EQ(vmm_startup_handshake_cancel(&handshake), EBUSY);
	ATF_REQUIRE_EQ(vmm_startup_handshake_enter(&handshake, 1, false), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_enter(&handshake, 0, true), 0);
	ATF_CHECK_EQ(vmm_startup_handshake_commit(&handshake), 0);
}

ATF_TC_WITHOUT_HEAD(reset_is_failure_atomic_at_generation_exhaustion);
ATF_TC_BODY(reset_is_failure_atomic_at_generation_exhaustion, tc)
{
	struct vmm_startup_handshake_vcpu before_vcpus[1], vcpus[1];
	struct vmm_startup_handshake before, handshake;

	(void)tc;
	memset(vcpus, 0, sizeof(vcpus));
	ATF_REQUIRE_EQ(vmm_startup_handshake_init(&handshake,
	    HANDSHAKE_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_configure_kernel(&handshake,
	    vcpus, 1), 0);
	handshake.generation = UINT64_MAX;
	vcpus[0].generation = UINT64_MAX;
	before = handshake;
	memcpy(before_vcpus, vcpus, sizeof(vcpus));
	ATF_CHECK_EQ(vmm_startup_handshake_reset_check(&handshake), EOVERFLOW);
	ATF_CHECK_EQ(vmm_startup_handshake_reset(&handshake), EOVERFLOW);
	ATF_CHECK(memcmp(&handshake, &before, sizeof(handshake)) == 0);
	ATF_CHECK(memcmp(vcpus, before_vcpus, sizeof(vcpus)) == 0);
}

ATF_TC_WITHOUT_HEAD(reset_advances_historical_owner_generation);
ATF_TC_BODY(reset_advances_historical_owner_generation, tc)
{
	struct vmm_startup_handshake handshake;
	uint64_t generation;

	(void)tc;
	ATF_REQUIRE_EQ(vmm_startup_handshake_init(&handshake,
	    HANDSHAKE_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_lock_default(&handshake), 0);
	generation = handshake.generation;
	ATF_REQUIRE_EQ(vmm_startup_handshake_reset(&handshake), 0);
	ATF_CHECK_EQ(vmm_startup_handshake_validate(&handshake), 0);
	ATF_CHECK_EQ(handshake.generation, generation + 1);
	ATF_CHECK_EQ(handshake.phase, VMM_STARTUP_HANDSHAKE_COMMITTED);
	ATF_CHECK_EQ(handshake.mode.owner, VMM_STARTUP_OWNER_USERSPACE);
	ATF_CHECK_EQ(handshake.mode.locked, 1);
}

ATF_TC_WITHOUT_HEAD(status_reports_recollection_and_is_failure_atomic);
ATF_TC_BODY(status_reports_recollection_and_is_failure_atomic, tc)
{
	struct vmm_startup_handshake_vcpu vcpus[2];
	struct vmm_startup_handshake_status before, status;
	struct vmm_startup_handshake handshake;

	(void)tc;
	memset(vcpus, 0, sizeof(vcpus));
	memset(&status, 0xa5, sizeof(status));
	ATF_REQUIRE_EQ(vmm_startup_handshake_init(&handshake,
	    HANDSHAKE_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_configure_kernel(&handshake,
	    vcpus, 2), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_enter(&handshake, 0, true), 0);
	ATF_REQUIRE_EQ(vmm_startup_handshake_status(&handshake, &status), 0);
	ATF_CHECK_EQ(status.phase, VMM_STARTUP_HANDSHAKE_COLLECTING);
	ATF_CHECK_EQ(status.generation, handshake.generation);
	ATF_CHECK_EQ(status.expected_vcpus, 2);
	ATF_CHECK_EQ(status.entered_vcpus, 1);
	ATF_CHECK_EQ(status.bootstrap_entered, 1);
	ATF_CHECK_EQ(status.mode.owner, VMM_STARTUP_OWNER_KERNEL);
	ATF_CHECK_EQ(status.reserved16, 0);
	ATF_CHECK_EQ(status.reserved32, 0);

	before = status;
	ATF_CHECK_EQ(vmm_startup_handshake_status(&handshake,
	    (struct vmm_startup_handshake_status *)(void *)&handshake), EINVAL);
	ATF_CHECK_EQ(vmm_startup_handshake_status(&handshake,
	    (struct vmm_startup_handshake_status *)(void *)&vcpus[0]), EINVAL);
	handshake.reserved32 = 1;
	ATF_CHECK_EQ(vmm_startup_handshake_status(&handshake, &status), EINVAL);
	ATF_CHECK(memcmp(&status, &before, sizeof(status)) == 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, default_is_locked_without_thread_handshake);
	ATF_TP_ADD_TC(tp, kernel_requires_every_distinct_vcpu_and_one_bsp);
	ATF_TP_ADD_TC(tp, missing_or_duplicate_bsp_is_rejected);
	ATF_TP_ADD_TC(tp, canonical_array_and_failure_atomicity);
	ATF_TP_ADD_TC(tp, corruption_is_not_reported_as_incomplete);
	ATF_TP_ADD_TC(tp, cancel_invalidates_external_storage);
	ATF_TP_ADD_TC(tp, retire_is_unconditional_and_terminal);
	ATF_TP_ADD_TC(tp, reset_recollects_locked_kernel_owner);
	ATF_TP_ADD_TC(tp, reset_is_failure_atomic_at_generation_exhaustion);
	ATF_TP_ADD_TC(tp, reset_advances_historical_owner_generation);
	ATF_TP_ADD_TC(tp, status_reports_recollection_and_is_failure_atomic);
	return (atf_no_error());
}
