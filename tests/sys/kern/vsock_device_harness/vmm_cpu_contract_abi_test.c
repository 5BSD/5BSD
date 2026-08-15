/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include "../../../../sys/amd64/include/vmm.h"
#include "../../../../sys/amd64/include/vmm_dev.h"

#include <atf-c.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Independent ABI oracle.  These literals are the userspace/kernel contract,
 * not aliases of the production definitions included above.
 */
#define	VMMABI_CPUID_F_BASELINE		UINT32_C(0x00000001)
#define	VMMABI_CPUID_IOCTL		65
#define	VMMABI_CPUID_SIZE		24
#define	VMMABI_CPUID_CPUID_OFF		0
#define	VMMABI_CPUID_FLAGS_OFF		4
#define	VMMABI_CPUID_EAX_OFF		8
#define	VMMABI_CPUID_EBX_OFF		12
#define	VMMABI_CPUID_ECX_OFF		16
#define	VMMABI_CPUID_EDX_OFF		20

#define	VMMABI_COMPAT_VERSION		UINT32_C(1)
#define	VMMABI_COMPAT_F_NESTED_VMX	UINT32_C(0x00000001)
#define	VMMABI_COMPAT_IOCTL		66
#define	VMMABI_COMPAT_SIZE		48
#define	VMMABI_COMPAT_VERSION_OFF	0
#define	VMMABI_COMPAT_FLAGS_OFF		4
#define	VMMABI_COMPAT_XCR0_OFF		8
#define	VMMABI_COMPAT_XSAVE_SIZE_OFF	16
#define	VMMABI_COMPAT_X2APIC_OFF	20
#define	VMMABI_COMPAT_TSC_OFF		24
#define	VMMABI_COMPAT_NESTED_CAP_OFF	32
#define	VMMABI_COMPAT_NESTED_SCHEMA_OFF	40
#define	VMMABI_COMPAT_QUERY_SIZE	56
#define	VMMABI_COMPAT_QUERY_CPUID_OFF	0
#define	VMMABI_COMPAT_QUERY_RESERVED_OFF 4
#define	VMMABI_COMPAT_QUERY_COMPAT_OFF	8

ATF_TC_WITHOUT_HEAD(cpuid_query_layout);
ATF_TC_BODY(cpuid_query_layout, tc)
{

	ATF_CHECK_EQ(VM_CPUID_F_BASELINE, VMMABI_CPUID_F_BASELINE);
	ATF_CHECK_EQ(IOCNUM_GET_CPUID, VMMABI_CPUID_IOCTL);
	ATF_CHECK_EQ(sizeof(struct vm_cpuid), VMMABI_CPUID_SIZE);
	ATF_CHECK_EQ(offsetof(struct vm_cpuid, cpuid), VMMABI_CPUID_CPUID_OFF);
	ATF_CHECK_EQ(offsetof(struct vm_cpuid, flags), VMMABI_CPUID_FLAGS_OFF);
	ATF_CHECK_EQ(offsetof(struct vm_cpuid, eax), VMMABI_CPUID_EAX_OFF);
	ATF_CHECK_EQ(offsetof(struct vm_cpuid, ebx), VMMABI_CPUID_EBX_OFF);
	ATF_CHECK_EQ(offsetof(struct vm_cpuid, ecx), VMMABI_CPUID_ECX_OFF);
	ATF_CHECK_EQ(offsetof(struct vm_cpuid, edx), VMMABI_CPUID_EDX_OFF);
}

ATF_TC_WITHOUT_HEAD(cpu_compat_layout);
ATF_TC_BODY(cpu_compat_layout, tc)
{

	ATF_CHECK_EQ(VM_CPU_COMPAT_VERSION, VMMABI_COMPAT_VERSION);
	ATF_CHECK_EQ(VM_CPU_COMPAT_F_NESTED_VMX,
	    VMMABI_COMPAT_F_NESTED_VMX);
	ATF_CHECK_EQ(IOCNUM_GET_CPU_COMPAT, VMMABI_COMPAT_IOCTL);
	ATF_CHECK_EQ(sizeof(struct vm_cpu_compat), VMMABI_COMPAT_SIZE);
	ATF_CHECK_EQ(offsetof(struct vm_cpu_compat, version),
	    VMMABI_COMPAT_VERSION_OFF);
	ATF_CHECK_EQ(offsetof(struct vm_cpu_compat, flags),
	    VMMABI_COMPAT_FLAGS_OFF);
	ATF_CHECK_EQ(offsetof(struct vm_cpu_compat, xcr0_allowed),
	    VMMABI_COMPAT_XCR0_OFF);
	ATF_CHECK_EQ(offsetof(struct vm_cpu_compat, xsave_max_size),
	    VMMABI_COMPAT_XSAVE_SIZE_OFF);
	ATF_CHECK_EQ(offsetof(struct vm_cpu_compat, x2apic_state),
	    VMMABI_COMPAT_X2APIC_OFF);
	ATF_CHECK_EQ(offsetof(struct vm_cpu_compat, tsc_frequency),
	    VMMABI_COMPAT_TSC_OFF);
	ATF_CHECK_EQ(offsetof(struct vm_cpu_compat,
	    nested_capability_signature), VMMABI_COMPAT_NESTED_CAP_OFF);
	ATF_CHECK_EQ(offsetof(struct vm_cpu_compat,
	    nested_schema_signature), VMMABI_COMPAT_NESTED_SCHEMA_OFF);
	ATF_CHECK_EQ(sizeof(struct vm_cpu_compat_query),
	    VMMABI_COMPAT_QUERY_SIZE);
	ATF_CHECK_EQ(offsetof(struct vm_cpu_compat_query, cpuid),
	    VMMABI_COMPAT_QUERY_CPUID_OFF);
	ATF_CHECK_EQ(offsetof(struct vm_cpu_compat_query, reserved),
	    VMMABI_COMPAT_QUERY_RESERVED_OFF);
	ATF_CHECK_EQ(offsetof(struct vm_cpu_compat_query, compat),
	    VMMABI_COMPAT_QUERY_COMPAT_OFF);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, cpuid_query_layout);
	ATF_TP_ADD_TC(tp, cpu_compat_layout);
	return (atf_no_error());
}
