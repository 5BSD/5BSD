/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <vmm.h>
#include <vmm_dev.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

/*
 * Exercise the production amd64 capture adapter with a deterministic kernel
 * query oracle.  Suppress the installed headers pulled in by the production
 * source: the source-tree ABI above is the interface under test, while these
 * declarations are the mocked libvmmapi boundary.
 */
#define _VMMAPI_H_
struct vcpu {
	unsigned int unused;
};
int vm_get_cpuid(struct vcpu *, uint32_t, uint32_t *, uint32_t *,
    uint32_t *, uint32_t *);
int vm_get_cpu_compat(struct vcpu *, struct vm_cpu_compat *);

#include "checkpoint_cpu.c"
#include "checkpoint_cpu_machdep.c"

#define TEST_CPU_PLATFORM UINT32_C(0xfffffffd)
#define TEST_CPU_POLICY UINT32_C(0xfffffffe)
#define TEST_CPU_NESTED UINT32_C(0xffffffff)

static uint32_t fail_selector;
static int fail_compat;
static int fail_selector_errno;
static int fail_compat_active;
static int cache_initial_empty;
static int extended_cache_records;
static int extended_max_invalid;
static int topology_initial_empty;
static struct vm_cpu_compat mock_compat;

static const struct checkpoint_cpu_record *find_record(
    const struct checkpoint_cpu_contract *, uint32_t, uint32_t);

int
vm_get_cpuid(struct vcpu *vcpu, uint32_t flags, uint32_t *eax,
    uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
	uint32_t parameter, selector;

	ATF_REQUIRE(vcpu != NULL);
	ATF_REQUIRE_EQ(flags, VM_CPUID_F_BASELINE);
	selector = *eax;
	parameter = *ecx;
	if (selector == fail_selector) {
		if (fail_selector_errno != 0)
			errno = fail_selector_errno;
		return (-1);
	}
	*eax = selector ^ UINT32_C(0x01010101);
	*ebx = parameter ^ UINT32_C(0x02020202);
	*ecx = parameter;
	*edx = selector ^ UINT32_C(0x04040404);
	switch (selector) {
	case 0:
		*eax = 0x1f;
		break;
	case 4:
		/* Two deterministic-cache records followed by a terminator. */
		*eax = !cache_initial_empty && parameter < 2 ? 1 : 0;
		break;
	case 0xb:
	case 0x1f:
		/* Four hierarchy levels followed by the architectural terminator. */
		*ebx = !topology_initial_empty && parameter < 4 ? 1 : 0;
		break;
	case 0x8000001dU:
		/* One extended deterministic-cache record and its terminator. */
		*eax = extended_cache_records && parameter < 2 ? 1 : 0;
		break;
	case 0xd:
		if (parameter == 0) {
			*eax = (1U << 2) | (1U << 5);
			*edx = 0;
		}
		break;
	case 0x40000000:
		*eax = 0x40000001;
		break;
	case 0x80000000:
		*eax = extended_max_invalid ? 0 :
		    (extended_cache_records ? 0x8000001dU : 0x80000001U);
		break;
	default:
		break;
	}
	return (0);
}

int
vm_get_cpu_compat(struct vcpu *vcpu, struct vm_cpu_compat *compat)
{

	ATF_REQUIRE(vcpu != NULL);
	ATF_REQUIRE(compat != NULL);
	if (fail_compat_active != 0) {
		if (fail_compat != 0)
			errno = fail_compat;
		return (-1);
	}
	*compat = mock_compat;
	return (0);
}

static void
reset_oracle(void)
{

	fail_selector = UINT32_MAX;
	fail_compat = 0;
	fail_selector_errno = EIO;
	fail_compat_active = 0;
	cache_initial_empty = 0;
	extended_cache_records = 0;
	extended_max_invalid = 0;
	topology_initial_empty = 0;
	memset(&mock_compat, 0, sizeof(mock_compat));
	mock_compat.version = VM_CPU_COMPAT_VERSION;
	mock_compat.flags = VM_CPU_COMPAT_F_VALID | VM_CPU_COMPAT_F_NESTED_VMX;
	mock_compat.xcr0_allowed = UINT64_C(0x8000000000000027);
	mock_compat.xsave_max_size = 4096;
	mock_compat.x2apic_state = X2APIC_ENABLED;
	mock_compat.tsc_frequency = UINT64_C(0x1122334455667788);
	mock_compat.nested_capability_signature =
	    UINT64_C(0x8877665544332211);
	mock_compat.nested_schema_signature = UINT64_C(0x0123456789abcdef);
}

ATF_TC_WITHOUT_HEAD(topology_zero_subleaf_does_not_probe_beyond_terminator);
ATF_TC_BODY(topology_zero_subleaf_does_not_probe_beyond_terminator, tc)
{
	struct checkpoint_cpu_contract contract;
	struct vcpu vcpu;

	reset_oracle();
	/* Both topology leaves terminate at subleaf zero. */
	topology_initial_empty = 1;
	ATF_REQUIRE_EQ(checkpoint_cpu_contract_capture(&vcpu, &contract), 0);
	ATF_CHECK_EQ(contract.record_count, 44);
	ATF_CHECK(find_record(&contract, 0xb, 0) != NULL);
	ATF_CHECK(find_record(&contract, 0xb, 1) == NULL);
	ATF_CHECK(find_record(&contract, 0x1f, 0) != NULL);
	ATF_CHECK(find_record(&contract, 0x1f, 1) == NULL);
}

ATF_TC_WITHOUT_HEAD(cache_zero_subleaf_does_not_probe_beyond_terminator);
ATF_TC_BODY(cache_zero_subleaf_does_not_probe_beyond_terminator, tc)
{
	struct checkpoint_cpu_contract contract;
	struct vcpu vcpu;

	reset_oracle();
	/* CPUID.04H terminates at subleaf zero. */
	cache_initial_empty = 1;
	ATF_REQUIRE_EQ(checkpoint_cpu_contract_capture(&vcpu, &contract), 0);
	ATF_CHECK_EQ(contract.record_count, 50);
	ATF_CHECK(find_record(&contract, 4, 0) != NULL);
	ATF_CHECK(find_record(&contract, 4, 1) == NULL);
}

static const struct checkpoint_cpu_record *
find_record(const struct checkpoint_cpu_contract *contract, uint32_t selector,
    uint32_t parameter)
{

	for (size_t i = 0; i < contract->record_count; i++) {
		if (contract->records[i].selector == selector &&
		    contract->records[i].parameter == parameter)
			return (&contract->records[i]);
	}
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(captures_kernel_contract_canonically);
ATF_TC_BODY(captures_kernel_contract_canonically, tc)
{
	const struct checkpoint_cpu_record *record;
	struct checkpoint_cpu_contract contract;
	struct vcpu vcpu;

	reset_oracle();
	memset(&contract, 0xa5, sizeof(contract));
	ATF_REQUIRE_EQ(checkpoint_cpu_contract_capture(&vcpu, &contract), 0);
	ATF_CHECK_EQ(contract.version, CHECKPOINT_CPU_CONTRACT_VERSION);
	ATF_CHECK_EQ(contract.architecture, CHECKPOINT_CPU_ARCH_AMD64);
	ATF_CHECK_EQ(contract.record_count, 52);
	ATF_CHECK_EQ(checkpoint_cpu_contract_validate(&contract), 0);

	/* Variable-subleaf enumeration must include only architected entries. */
	ATF_CHECK(find_record(&contract, 4, 1) != NULL);
	ATF_CHECK(find_record(&contract, 4, 2) != NULL);
	ATF_CHECK(find_record(&contract, 4, 3) == NULL);
	ATF_CHECK(find_record(&contract, 0xb, 3) != NULL);
	ATF_CHECK(find_record(&contract, 0xb, 4) != NULL);
	ATF_CHECK(find_record(&contract, 0xb, 5) == NULL);
	ATF_CHECK(find_record(&contract, 0x1f, 3) != NULL);
	ATF_CHECK(find_record(&contract, 0x1f, 4) != NULL);
	ATF_CHECK(find_record(&contract, 0x1f, 5) == NULL);
	ATF_CHECK(find_record(&contract, 0xd, 1) != NULL);
	ATF_CHECK(find_record(&contract, 0xd, 2) != NULL);
	ATF_CHECK(find_record(&contract, 0xd, 5) != NULL);
	ATF_CHECK(find_record(&contract, 0xd, 3) == NULL);

	record = find_record(&contract, TEST_CPU_PLATFORM, 0);
	ATF_REQUIRE(record != NULL);
	ATF_CHECK_EQ(record->values[0], UINT32_C(0x55667788));
	ATF_CHECK_EQ(record->values[1], UINT32_C(0x11223344));
	ATF_CHECK_EQ(record->values[2], X2APIC_ENABLED);
	ATF_CHECK_EQ(record->values[3], 0);
	record = find_record(&contract, TEST_CPU_POLICY, 0);
	ATF_REQUIRE(record != NULL);
	ATF_CHECK_EQ(record->values[0], UINT32_C(0x00000027));
	ATF_CHECK_EQ(record->values[1], UINT32_C(0x80000000));
	ATF_CHECK_EQ(record->values[2], 4096);
	ATF_CHECK_EQ(record->values[3], mock_compat.flags);
	record = find_record(&contract, TEST_CPU_NESTED, 0);
	ATF_REQUIRE(record != NULL);
	ATF_CHECK_EQ(record->values[0], UINT32_C(0x44332211));
	ATF_CHECK_EQ(record->values[1], UINT32_C(0x88776655));
	ATF_CHECK_EQ(record->values[2], UINT32_C(0x89abcdef));
	ATF_CHECK_EQ(record->values[3], UINT32_C(0x01234567));
}

ATF_TC_WITHOUT_HEAD(extended_cache_subleaves_are_captured);
ATF_TC_BODY(extended_cache_subleaves_are_captured, tc)
{
	struct checkpoint_cpu_contract contract;
	struct vcpu vcpu;

	reset_oracle();
	/* CPUID.8000001dH has two cache records followed by a terminator. */
	extended_cache_records = 1;
	ATF_REQUIRE_EQ(checkpoint_cpu_contract_capture(&vcpu, &contract), 0);
	ATF_CHECK_EQ(contract.record_count, 82);
	ATF_CHECK(find_record(&contract, 0x8000001dU, 0) != NULL);
	ATF_CHECK(find_record(&contract, 0x8000001dU, 1) != NULL);
	ATF_CHECK(find_record(&contract, 0x8000001dU, 2) != NULL);
	ATF_CHECK(find_record(&contract, 0x8000001dU, 3) == NULL);
}

ATF_TC_WITHOUT_HEAD(failures_leave_destination_unchanged);
ATF_TC_BODY(failures_leave_destination_unchanged, tc)
{
	struct checkpoint_cpu_contract before, contract;
	struct vcpu vcpu;

	reset_oracle();
	memset(&contract, 0x5a, sizeof(contract));
	before = contract;
	fail_selector = 5;
	ATF_CHECK_EQ(checkpoint_cpu_contract_capture(&vcpu, &contract), EIO);
	ATF_CHECK_EQ(memcmp(&contract, &before, sizeof(contract)), 0);

	reset_oracle();
	fail_selector = 5;
	fail_selector_errno = 0;
	ATF_CHECK_EQ(checkpoint_cpu_contract_capture(&vcpu, &contract), EIO);
	ATF_CHECK_EQ(memcmp(&contract, &before, sizeof(contract)), 0);

	reset_oracle();
	fail_compat = ENXIO;
	fail_compat_active = 1;
	ATF_CHECK_EQ(checkpoint_cpu_contract_capture(&vcpu, &contract), ENXIO);
	ATF_CHECK_EQ(memcmp(&contract, &before, sizeof(contract)), 0);

	reset_oracle();
	fail_compat_active = 1;
	ATF_CHECK_EQ(checkpoint_cpu_contract_capture(&vcpu, &contract), EIO);
	ATF_CHECK_EQ(memcmp(&contract, &before, sizeof(contract)), 0);

	reset_oracle();
	extended_max_invalid = 1;
	ATF_CHECK_EQ(checkpoint_cpu_contract_capture(&vcpu, &contract), EPROTO);
	ATF_CHECK_EQ(memcmp(&contract, &before, sizeof(contract)), 0);

	reset_oracle();
	mock_compat.version++;
	ATF_CHECK_EQ(checkpoint_cpu_contract_capture(&vcpu, &contract), EPROTO);
	ATF_CHECK_EQ(memcmp(&contract, &before, sizeof(contract)), 0);
	ATF_CHECK_EQ(checkpoint_cpu_contract_capture(NULL, &contract), EINVAL);
	ATF_CHECK_EQ(checkpoint_cpu_contract_capture(&vcpu, NULL), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, captures_kernel_contract_canonically);
	ATF_TP_ADD_TC(tp, topology_zero_subleaf_does_not_probe_beyond_terminator);
	ATF_TP_ADD_TC(tp, cache_zero_subleaf_does_not_probe_beyond_terminator);
	ATF_TP_ADD_TC(tp, extended_cache_subleaves_are_captured);
	ATF_TP_ADD_TC(tp, failures_leave_destination_unchanged);
	return (atf_no_error());
}
