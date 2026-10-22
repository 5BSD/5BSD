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

static void
require_invalid_handshake_unchanged(struct vmm_startup_handshake *handshake,
    struct vmm_startup_handshake_vcpu *vcpus)
{
	struct vmm_startup_handshake before;
	struct vmm_startup_handshake_vcpu records[2];
	struct vmm_startup_handshake_status status, saved;

	before = *handshake;
	memcpy(records, vcpus, sizeof(records));
	memset(&status, 0xa5, sizeof(status));
	saved = status;
	ATF_CHECK_EQ(vmm_startup_handshake_validate(handshake), EINVAL);
	ATF_CHECK_EQ(vmm_startup_handshake_lock_default(handshake), EINVAL);
	ATF_CHECK_EQ(vmm_startup_handshake_configure_kernel(handshake, vcpus, 2), EINVAL);
	ATF_CHECK_EQ(vmm_startup_handshake_enter(handshake, 0, true), EINVAL);
	ATF_CHECK_EQ(vmm_startup_handshake_commit(handshake), EINVAL);
	ATF_CHECK_EQ(vmm_startup_handshake_reset_check(handshake), EINVAL);
	ATF_CHECK_EQ(vmm_startup_handshake_reset(handshake), EINVAL);
	ATF_CHECK_EQ(vmm_startup_handshake_status(handshake, &status), EINVAL);
	ATF_CHECK_EQ(vmm_startup_handshake_cancel(handshake), EINVAL);
	ATF_CHECK_EQ(vmm_startup_handshake_retire(handshake), EINVAL);
	ATF_CHECK_EQ(memcmp(handshake, &before, sizeof(before)), 0);
	ATF_CHECK_EQ(memcmp(vcpus, records, sizeof(records)), 0);
	ATF_CHECK_EQ(memcmp(&status, &saved, sizeof(status)), 0);
}

ATF_TC_WITHOUT_HEAD(invalid_header_and_open_state);
ATF_TC_BODY(invalid_header_and_open_state, tc)
{
	struct vmm_startup_handshake handshake;
	struct vmm_startup_handshake_vcpu vcpus[2];
	unsigned i;

	(void)tc;
	for (i = 0; i < 16; i++) {
		ATF_REQUIRE_EQ(vmm_startup_handshake_init(&handshake, HANDSHAKE_OWNER), 0);
		memset(vcpus, 0, sizeof(vcpus));
		switch (i) {
		case 0: handshake.owner_id = 0; break;
		case 1: handshake.generation = 0; break;
		case 2: handshake.storage_cookie = 0; break;
		case 3: handshake.phase = VMM_STARTUP_HANDSHAKE_PHASE_LAST; break;
		case 4: handshake.bootstrap_entered = 2; break;
		case 5: handshake.reserved16 = 1; break;
		case 6: handshake.reserved32 = 1; break;
		case 7: handshake.mode.owner = 255; break;
		case 8: handshake.expected_vcpus = 1; break;
		case 9: handshake.entered_vcpus = 1; break;
		case 10: handshake.bootstrap_entered = 1; break;
		case 11: handshake.vcpus = vcpus; break;
		case 12: handshake.vcpus_cookie = 1; break;
		case 13: handshake.mode.locked = 1; break;
		case 14: handshake.mode.owner = VMM_STARTUP_OWNER_KERNEL; break;
		case 15: handshake.mode.execution = VMM_STARTUP_EXECUTION_PRESTARTED_WAIT; break;
		}
		require_invalid_handshake_unchanged(&handshake, vcpus);
	}
}

ATF_TC_WITHOUT_HEAD(invalid_bound_records);
ATF_TC_BODY(invalid_bound_records, tc)
{
	struct vmm_startup_handshake handshake;
	struct vmm_startup_handshake_vcpu vcpus[2];
	unsigned i;

	(void)tc;
	for (i = 0; i < 16; i++) {
		ATF_REQUIRE_EQ(vmm_startup_handshake_init(&handshake, HANDSHAKE_OWNER), 0);
		memset(vcpus, 0, sizeof(vcpus));
		ATF_REQUIRE_EQ(vmm_startup_handshake_configure_kernel(&handshake, vcpus, 2), 0);
		switch (i) {
		case 0: vcpus[1].owner_id++; break;
		case 1: vcpus[1].generation++; break;
		case 2: vcpus[1].handshake_cookie = 0; break;
		case 3: vcpus[1].storage_cookie = 0; break;
		case 4: vcpus[1].vcpuid = 0; break;
		case 5: vcpus[1].bootstrap_processor = 2; break;
		case 6: vcpus[1].entered = 2; break;
		case 7: vcpus[1].reserved16 = 1; break;
		case 8: vcpus[1].bootstrap_processor = 1; break;
		case 9: vcpus[1].entered = 1; break;
		case 10: handshake.bootstrap_entered = 1; break;
		case 11: handshake.expected_vcpus = 0; break;
		case 12: handshake.vcpus = NULL; break;
		case 13: handshake.vcpus_cookie = 0; break;
		case 14: handshake.mode.owner = VMM_STARTUP_OWNER_USERSPACE; break;
		case 15: handshake.mode.execution = VMM_STARTUP_EXECUTION_USERSPACE_RESUME; break;
		}
		require_invalid_handshake_unchanged(&handshake, vcpus);
	}
}

ATF_TC_WITHOUT_HEAD(invalid_terminal_observations);
ATF_TC_BODY(invalid_terminal_observations, tc)
{
	struct vmm_startup_handshake handshake;
	struct vmm_startup_handshake_vcpu vcpus[2];
	unsigned i, cancelled;

	(void)tc;
	for (cancelled = 0; cancelled < 2; cancelled++) {
		for (i = 0; i < 6; i++) {
			ATF_REQUIRE_EQ(vmm_startup_handshake_init(&handshake, HANDSHAKE_OWNER), 0);
			memset(vcpus, 0, sizeof(vcpus));
			if (cancelled)
				ATF_REQUIRE_EQ(vmm_startup_handshake_cancel(&handshake), 0);
			else
				ATF_REQUIRE_EQ(vmm_startup_handshake_lock_default(&handshake), 0);
			switch (i) {
			case 0: handshake.expected_vcpus = 1; break;
			case 1: handshake.entered_vcpus = 1; break;
			case 2: handshake.bootstrap_entered = 1; break;
			case 3: handshake.vcpus = vcpus; break;
			case 4: handshake.vcpus_cookie = 1; break;
			case 5: handshake.mode.locked = cancelled ? 1 : 0; break;
			}
			require_invalid_handshake_unchanged(&handshake, vcpus);
		}
	}
}

ATF_TC_WITHOUT_HEAD(argument_and_destination_boundaries);
ATF_TC_BODY(argument_and_destination_boundaries, tc)
{
	struct vmm_startup_handshake handshake, before;
	struct vmm_startup_handshake_vcpu vcpus[2], saved[2];
	struct vmm_startup_handshake_status status;
	unsigned i;

	(void)tc;
	memset(&handshake, 0xa5, sizeof(handshake));
	before = handshake;
	ATF_CHECK_EQ(vmm_startup_handshake_init(NULL, HANDSHAKE_OWNER), EINVAL);
	ATF_CHECK_EQ(vmm_startup_handshake_init(&handshake, 0), EINVAL);
	ATF_CHECK_EQ(memcmp(&before, &handshake, sizeof(before)), 0);
	ATF_CHECK_EQ(vmm_startup_handshake_validate(NULL), EINVAL);
	ATF_CHECK_EQ(vmm_startup_handshake_enter(NULL, 0, true), EINVAL);
	ATF_CHECK_EQ(vmm_startup_handshake_status(NULL, &status), EINVAL);
	ATF_REQUIRE_EQ(vmm_startup_handshake_init(&handshake, HANDSHAKE_OWNER), 0);
	ATF_CHECK_EQ(vmm_startup_handshake_status(&handshake, NULL), EINVAL);
	ATF_CHECK_EQ(vmm_startup_handshake_configure_kernel(&handshake, NULL, 2), EINVAL);
	ATF_CHECK_EQ(vmm_startup_handshake_configure_kernel(&handshake, vcpus, 0), EINVAL);
	ATF_CHECK_EQ(vmm_startup_handshake_configure_kernel(&handshake,
	    (struct vmm_startup_handshake_vcpu *)(void *)&handshake, 1), EINVAL);
	ATF_CHECK_EQ(vmm_startup_handshake_enter(&handshake, 0, true), EBUSY);
	for (i = 0; i < 8; i++) {
		memset(vcpus, 0, sizeof(vcpus));
		switch (i) {
		case 0: vcpus[1].owner_id = 1; break;
		case 1: vcpus[1].generation = 1; break;
		case 2: vcpus[1].handshake_cookie = 1; break;
		case 3: vcpus[1].storage_cookie = 1; break;
		case 4: vcpus[1].vcpuid = 1; break;
		case 5: vcpus[1].bootstrap_processor = 1; break;
		case 6: vcpus[1].entered = 1; break;
		case 7: vcpus[1].reserved16 = 1; break;
		}
		before = handshake;
		memcpy(saved, vcpus, sizeof(saved));
		ATF_CHECK_EQ(vmm_startup_handshake_configure_kernel(&handshake, vcpus, 2), EBUSY);
		ATF_CHECK_EQ(memcmp(&before, &handshake, sizeof(before)), 0);
		ATF_CHECK_EQ(memcmp(saved, vcpus, sizeof(saved)), 0);
	}
	memset(vcpus, 0, sizeof(vcpus));
	ATF_REQUIRE_EQ(vmm_startup_handshake_configure_kernel(&handshake, vcpus, 2), 0);
	ATF_CHECK_EQ(vmm_startup_handshake_enter(&handshake, 2, true), EINVAL);
	ATF_CHECK_EQ(vmm_startup_handshake_configure_kernel(&handshake, vcpus, 2), EBUSY);
	ATF_REQUIRE_EQ(vmm_startup_handshake_cancel(&handshake), 0);
	ATF_CHECK_EQ(vmm_startup_handshake_reset(&handshake), ECANCELED);
}

ATF_TC_WITHOUT_HEAD(committed_kernel_corruption);
ATF_TC_BODY(committed_kernel_corruption, tc)
{
	struct vmm_startup_handshake handshake;
	struct vmm_startup_handshake_vcpu vcpus[2];
	unsigned i;

	(void)tc;
	for (i = 0; i < 5; i++) {
		ATF_REQUIRE_EQ(vmm_startup_handshake_init(&handshake, HANDSHAKE_OWNER), 0);
		memset(vcpus, 0, sizeof(vcpus));
		ATF_REQUIRE_EQ(vmm_startup_handshake_configure_kernel(&handshake, vcpus, 2), 0);
		ATF_REQUIRE_EQ(vmm_startup_handshake_enter(&handshake, 0, true), 0);
		ATF_REQUIRE_EQ(vmm_startup_handshake_enter(&handshake, 1, false), 0);
		ATF_REQUIRE_EQ(vmm_startup_handshake_commit(&handshake), 0);
		switch (i) {
		case 0: handshake.expected_vcpus = 0; break;
		case 1: vcpus[1].generation++; break;
		case 2:
			/* Consistent records and counters, but incomplete admission. */
			vcpus[1].entered = 0;
			handshake.entered_vcpus--;
			break;
		case 3:
			/* Complete admission cannot be committed without a BSP. */
			vcpus[0].bootstrap_processor = 0;
			handshake.bootstrap_entered = 0;
			break;
		case 4:
			/* Reject overlapping record storage before dereferencing it. */
			handshake.vcpus = (void *)&handshake;
			handshake.vcpus_cookie = (uintptr_t)&handshake;
			break;
		}
		require_invalid_handshake_unchanged(&handshake, vcpus);
	}
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
	ATF_TP_ADD_TC(tp, invalid_header_and_open_state);
	ATF_TP_ADD_TC(tp, invalid_bound_records);
	ATF_TP_ADD_TC(tp, invalid_terminal_observations);
	ATF_TP_ADD_TC(tp, argument_and_destination_boundaries);
	ATF_TP_ADD_TC(tp, committed_kernel_corruption);
	return (atf_no_error());
}
