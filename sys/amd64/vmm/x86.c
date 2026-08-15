/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/pcpu.h>
#include <sys/systm.h>
#include <sys/sysctl.h>

#include <machine/clock.h>
#include <machine/cpufunc.h>
#include <machine/md_var.h>
#include <machine/segments.h>
#include <machine/specialreg.h>
#include <machine/vmm.h>
#include <x86/bhyve.h>

#include <dev/vmm/vmm_ktr.h>
#include <dev/vmm/vmm_vm.h>

#include "vmm_host.h"
#include "vmm_util.h"
#include "vpvclock.h"
#include "x86.h"
#include "x86_cpuid.h"

SYSCTL_DECL(_hw_vmm);
static SYSCTL_NODE(_hw_vmm, OID_AUTO, topology, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    NULL);

#define CPUID_VM_SIGNATURE	0x40000000

/*
 * When the KVM paravirtual clock interface is advertised, the KVM signature
 * occupies the base hypervisor leaf (0x40000000) with its feature leaf at
 * 0x40000001 -- the fixed locations the guest kvm_clock driver assumes.  The
 * bhyve signature is also written to a secondary block (0x40000100), mirroring
 * how QEMU lays out multiple paravirtual interfaces, but that block is NOT
 * actually discoverable by a stock guest: identify_hypervisor_cpuid_base() in
 * sys/x86/x86/identcpu.c stops scanning at the first signature it recognizes --
 * which is KVM at 0x40000000 -- and never advances to 0x40000100.  bhyve's
 * EXT_DEST_ID capability is therefore preserved for the guest not through the
 * secondary block but through the KVM feature bit KVM_FEATURE_MSI_EXT_DEST_ID
 * advertised in the KVM feature leaf (see vpvclock_kvm_features()).  When the
 * interface is disabled the historical single-block bhyve layout is used
 * unchanged.
 */
#define	CPUID_BHYVE_SIGNATURE_ALT	0x40000100
#define	CPUID_BHYVE_FEATURES_ALT	0x40000101

static const char bhyve_id[12] = "bhyve bhyve ";
static const char kvm_id[12] = "KVMKVMKVM";	/* "KVMKVMKVM\0\0\0" */

static uint64_t bhyve_xcpuids;
SYSCTL_ULONG(_hw_vmm, OID_AUTO, bhyve_xcpuids, CTLFLAG_RW, &bhyve_xcpuids, 0,
    "Number of times an unknown cpuid leaf was accessed");

static int cpuid_leaf_b = 1;
SYSCTL_INT(_hw_vmm_topology, OID_AUTO, cpuid_leaf_b, CTLFLAG_RDTUN,
    &cpuid_leaf_b, 0, NULL);

/*
 * Compute ceil(log2(x)).  Returns -1 if x is zero.
 */
static __inline int
log2(u_int x)
{

	return (x == 0 ? -1 : order_base_2(x));
}

static int
x86_emulate_cpuid_impl(struct vcpu *vcpu, uint64_t *rax, uint64_t *rbx,
    uint64_t *rcx, uint64_t *rdx, bool baseline)
{
	struct vm *vm = vcpu_vm(vcpu);
	int vcpu_id = vcpu_vcpuid(vcpu);
	const struct xsave_limits *limits;
	uint64_t cr4;
	int error, enable_invpcid, enable_rdpid, enable_rdtscp, level,
	    nested_vmx, width;
	unsigned int func, regs[4], logical_cpus, param;
	enum x2apic_state x2apic_state;
	uint16_t cores, maxcpus, sockets, threads;
	bool pvclock;
	u_int vm_high;

	/*
	 * Whether to advertise the KVM paravirtual clock interface, which also
	 * determines the layout of the hypervisor CPUID leaves (see above).
	 */
	pvclock = vpvclock_capable();
	vm_high = pvclock ? CPUID_BHYVE_FEATURES_ALT : CPUID_BHYVE_FEATURES;

	/*
	 * The function of CPUID is controlled through the provided value of
	 * %eax (and secondarily %ecx, for certain leaf data).
	 */
	func = (uint32_t)*rax;
	param = (uint32_t)*rcx;

	VCPU_CTR2(vm, vcpu_id, "cpuid %#x,%#x", func, param);

	/*
	 * Requests for invalid CPUID levels should map to the highest
	 * available level instead.
	 */
	if (cpu_exthigh != 0 && func >= 0x80000000) {
		if (func > cpu_exthigh)
			func = cpu_exthigh;
	} else if (func >= CPUID_VM_SIGNATURE) {
		if (func > vm_high)
			func = vm_high;
	} else if (func > cpu_high) {
		func = cpu_high;
	}

	/*
	 * In general the approach used for CPU topology is to
	 * advertise a flat topology where all CPUs are packages with
	 * no multi-core or SMT.
	 */
	switch (func) {
		/*
		 * Pass these through to the guest
		 */
		case CPUID_0000_0000:
		case CPUID_0000_0002:
		case CPUID_0000_0003:
		case CPUID_8000_0000:
		case CPUID_8000_0002:
		case CPUID_8000_0003:
		case CPUID_8000_0004:
		case CPUID_8000_0006:
			cpuid_count(func, param, regs);
			break;
		case CPUID_8000_0008:
			cpuid_count(func, param, regs);
			/*
			 * Variable MTRR address fields currently expose at most 52
			 * physical-address bits.  Keep the guest's MAXPHYADDR in
			 * lockstep with the width enforced by its emulated MSRs.
			 */
			regs[0] = (regs[0] & ~0xffU) |
			    vm_mtrr_maxphyaddr(regs[0] & 0xffU);
			if (vmm_is_svm()) {
				/*
				 * As on Intel (0000_0007:0, EDX), mask out
				 * unsupported or unsafe AMD extended features
				 * (8000_0008 EBX).
				 */
				regs[1] &= (AMDFEID_CLZERO | AMDFEID_IRPERF |
				    AMDFEID_XSAVEERPTR);

				vm_get_topology(vm, &sockets, &cores, &threads,
				    &maxcpus);
				/*
				 * Here, width is ApicIdCoreIdSize, present on
				 * at least Family 15h and newer.  It
				 * represents the "number of bits in the
				 * initial apicid that indicate thread id
				 * within a package."
				 *
				 * Our topo_probe_amd() uses it for
				 * pkg_id_shift and other OSes may rely on it.
				 */
				width = MIN(0xF, log2(threads * cores));
				logical_cpus = MIN(0xFF, threads * cores - 1);
				regs[2] = (width << AMDID_COREID_SIZE_SHIFT) | logical_cpus;
			}
			break;

		case CPUID_8000_0001:
			cpuid_count(func, param, regs);

			/*
			 * Hide SVM from guest.
			 */
			regs[2] &= ~AMDID2_SVM;

			/*
			 * Don't advertise extended performance counter MSRs
			 * to the guest.
			 */
			regs[2] &= ~AMDID2_PCXC;
			regs[2] &= ~AMDID2_PNXC;
			regs[2] &= ~AMDID2_PTSCEL2I;

			/*
			 * Don't advertise Instruction Based Sampling feature.
			 */
			regs[2] &= ~AMDID2_IBS;

			/* NodeID MSR not available */
			regs[2] &= ~AMDID2_NODE_ID;

			/* Don't advertise the OS visible workaround feature */
			regs[2] &= ~AMDID2_OSVW;

			/* Hide mwaitx/monitorx capability from the guest */
			regs[2] &= ~AMDID2_MWAITX;

			/* Advertise RDTSCP if it is enabled. */
			error = vm_get_capability(vcpu,
			    VM_CAP_RDTSCP, &enable_rdtscp);
			if (error == 0 && enable_rdtscp)
				regs[3] |= AMDID_RDTSCP;
			else
				regs[3] &= ~AMDID_RDTSCP;
			break;

		case CPUID_8000_0007:
			/*
			 * AMD uses this leaf to advertise the processor's
			 * power monitoring and RAS capabilities. These
			 * features are hardware-specific and exposing
			 * them to a guest doesn't make a lot of sense.
			 *
			 * Intel uses this leaf only to advertise the
			 * "Invariant TSC" feature with all other bits
			 * being reserved (set to zero).
			 */
			regs[0] = 0;
			regs[1] = 0;
			regs[2] = 0;
			regs[3] = 0;

			/*
			 * "Invariant TSC" can be advertised to the guest if:
			 * - host TSC frequency is invariant
			 * - host TSCs are synchronized across physical cpus
			 *
			 * XXX This still falls short because the vcpu
			 * can observe the TSC moving backwards as it
			 * migrates across physical cpus. But at least
			 * it should discourage the guest from using the
			 * TSC to keep track of time.
			 */
			if (tsc_is_invariant && smp_tsc)
				regs[3] |= AMDPM_TSC_INVARIANT;
			break;

		case CPUID_8000_001D:
			/* AMD Cache topology, like 0000_0004 for Intel. */
			if (!vmm_is_svm())
				goto default_leaf;

			/*
			 * Similar to Intel, generate a fictitious cache
			 * topology for the guest with L3 shared by the
			 * package, and L1 and L2 local to a core.
			 */
			vm_get_topology(vm, &sockets, &cores, &threads,
			    &maxcpus);
			switch (param) {
			case 0:
				logical_cpus = threads;
				level = 1;
				func = 1;	/* data cache */
				break;
			case 1:
				logical_cpus = threads;
				level = 2;
				func = 3;	/* unified cache */
				break;
			case 2:
				logical_cpus = threads * cores;
				level = 3;
				func = 3;	/* unified cache */
				break;
			default:
				logical_cpus = sockets * threads * cores;
				level = 0;
				func = 0;
				break;
			}

			logical_cpus = MIN(0xfff, logical_cpus - 1);
			regs[0] = (logical_cpus << 14) | (1 << 8) |
			    (level << 5) | func;
			regs[1] = (func > 0) ? (CACHE_LINE_SIZE - 1) : 0;

			/*
			 * ecx: Number of cache ways for non-fully
			 * associative cache, minus 1.  Reported value
			 * of zero means there is one way.
			 */
			regs[2] = 0;

			regs[3] = 0;
			break;

		case CPUID_8000_001E:
			/*
			 * AMD Family 16h+ and Hygon Family 18h additional
			 * identifiers.
			 */
			if (!vmm_is_svm() || CPUID_TO_FAMILY(cpu_id) < 0x16)
				goto default_leaf;

			vm_get_topology(vm, &sockets, &cores, &threads,
			    &maxcpus);
			regs[0] = vcpu_id;
			threads = MIN(0xFF, threads - 1);
			regs[1] = (threads << 8) |
			    (vcpu_id >> log2(threads + 1));
			/*
			 * XXX Bhyve topology cannot yet represent >1 node per
			 * processor.
			 */
			regs[2] = 0;
			regs[3] = 0;
			break;

		case CPUID_0000_0001:
			do_cpuid(1, regs);

			if (baseline)
				x2apic_state = X2APIC_DISABLED;
			else {
				error = vm_get_x2apic_state(vcpu, &x2apic_state);
				if (error) {
					panic("x86_emulate_cpuid: error %d "
					    "fetching x2apic state", error);
				}
			}

			/*
			 * Override the APIC ID only in ebx
			 */
			regs[1] &= ~(CPUID_LOCAL_APIC_ID);
			regs[1] |= (vcpu_id << CPUID_0000_0001_APICID_SHIFT);

			/*
			 * VMX is exposed only through the explicit backend
			 * capability.  The Intel backend additionally requires
			 * the boot-time host policy and its complete nested
			 * implementation predicate; AMD reports this capability
			 * unsupported.
			 */
			error = vm_get_capability(vcpu, VM_CAP_NESTED_VMX,
			    &nested_vmx);
			if (error != 0 || nested_vmx == 0)
				regs[2] &= ~CPUID2_VMX;

			/*
			 * Don't expose SpeedStep, TME or SMX capability.
			 * Advertise x2APIC capability and Hypervisor guest.
			 */
			regs[2] &= ~(CPUID2_EST | CPUID2_TM2);
			regs[2] &= ~(CPUID2_SMX);

			regs[2] |= CPUID2_HV;

			if (x2apic_state != X2APIC_DISABLED)
				regs[2] |= CPUID2_X2APIC;
			else
				regs[2] &= ~CPUID2_X2APIC;

			/*
			 * Only advertise CPUID2_XSAVE in the guest if
			 * the host is using XSAVE.
			 */
			if (!(regs[2] & CPUID2_OSXSAVE))
				regs[2] &= ~CPUID2_XSAVE;

			/*
			 * If CPUID2_XSAVE is being advertised and the
			 * guest has set CR4_XSAVE, set
			 * CPUID2_OSXSAVE.
			 */
			regs[2] &= ~CPUID2_OSXSAVE;
			if (!baseline && (regs[2] & CPUID2_XSAVE)) {
				error = vm_get_register(vcpu,
				    VM_REG_GUEST_CR4, &cr4);
				if (error)
					panic("x86_emulate_cpuid: error %d "
					      "fetching %%cr4", error);
				if (cr4 & CR4_XSAVE)
					regs[2] |= CPUID2_OSXSAVE;
			}

			/*
			 * Hide monitor/mwait until we know how to deal with
			 * these instructions.
			 */
			regs[2] &= ~CPUID2_MON;

                        /*
			 * Hide the performance and debug features.
			 */
			regs[2] &= ~CPUID2_PDCM;

			/*
			 * No TSC deadline support in the APIC yet
			 */
			regs[2] &= ~CPUID2_TSCDLT;

			/*
			 * Hide thermal monitoring
			 */
			regs[3] &= ~(CPUID_ACPI | CPUID_TM);

			/*
			 * Hide the debug store capability.
			 */
			regs[3] &= ~CPUID_DS;

			/*
			 * Advertise the Machine Check and MTRR capability.
			 *
			 * Some guest OSes (e.g. Windows) will not boot if
			 * these features are absent.
			 */
			regs[3] |= (CPUID_MCA | CPUID_MCE | CPUID_MTRR);

			vm_get_topology(vm, &sockets, &cores, &threads,
			    &maxcpus);
			logical_cpus = threads * cores;
			regs[1] &= ~CPUID_HTT_CORES;
			regs[1] |= (logical_cpus & 0xff) << 16;
			regs[3] |= CPUID_HTT;
			break;

		case CPUID_0000_0004:
			cpuid_count(func, param, regs);

			if (regs[0] || regs[1] || regs[2] || regs[3]) {
				vm_get_topology(vm, &sockets, &cores, &threads,
				    &maxcpus);
				regs[0] &= 0x3ff;
				regs[0] |= (cores - 1) << 26;
				/*
				 * Cache topology:
				 * - L1 and L2 are shared only by the logical
				 *   processors in a single core.
				 * - L3 and above are shared by all logical
				 *   processors in the package.
				 */
				logical_cpus = threads;
				level = (regs[0] >> 5) & 0x7;
				if (level >= 3)
					logical_cpus *= cores;
				regs[0] |= (logical_cpus - 1) << 14;
			}
			break;

		case CPUID_0000_0007:
			regs[0] = 0;
			regs[1] = 0;
			regs[2] = 0;
			regs[3] = 0;

			/* leaf 0 */
			if (param == 0) {
				cpuid_count(func, param, regs);

				/* Only leaf 0 is supported */
				regs[0] = 0;

				/*
				 * Expose known-safe features.
				 */
				regs[1] &= CPUID_STDEXT_FSGSBASE |
				    CPUID_STDEXT_BMI1 | CPUID_STDEXT_HLE |
				    CPUID_STDEXT_AVX2 | CPUID_STDEXT_SMEP |
				    CPUID_STDEXT_BMI2 |
				    CPUID_STDEXT_ERMS | CPUID_STDEXT_RTM |
				    CPUID_STDEXT_AVX512F |
				    CPUID_STDEXT_AVX512DQ |
				    CPUID_STDEXT_RDSEED |
				    CPUID_STDEXT_SMAP |
				    CPUID_STDEXT_AVX512PF |
				    CPUID_STDEXT_AVX512ER |
				    CPUID_STDEXT_AVX512CD | CPUID_STDEXT_SHA |
				    CPUID_STDEXT_AVX512BW |
				    CPUID_STDEXT_AVX512VL |
				    CPUID_STDEXT_AVX512IFMA;
				regs[2] = x86_cpuid_guest_stdext2(regs[2]);
				regs[3] &= CPUID_STDEXT3_MD_CLEAR |
				    CPUID_STDEXT3_AVX5124VNNIW |
				    CPUID_STDEXT3_AVX5124FMAPS |
				    CPUID_STDEXT3_AVX512VP2INTERSECT;

				/* Advertise RDPID if it is enabled. */
				error = vm_get_capability(vcpu, VM_CAP_RDPID,
				    &enable_rdpid);
				if (error == 0 && enable_rdpid)
					regs[2] |= CPUID_STDEXT2_RDPID;

				/* Advertise INVPCID if it is enabled. */
				error = vm_get_capability(vcpu,
				    VM_CAP_ENABLE_INVPCID, &enable_invpcid);
				if (error == 0 && enable_invpcid)
					regs[1] |= CPUID_STDEXT_INVPCID;
			}
			break;

		case CPUID_0000_0006:
			regs[0] = CPUTPM1_ARAT;
			regs[1] = 0;
			regs[2] = 0;
			regs[3] = 0;
			break;

		case CPUID_0000_000A:
			/*
			 * Handle the access, but report 0 for
			 * all options
			 */
			regs[0] = 0;
			regs[1] = 0;
			regs[2] = 0;
			regs[3] = 0;
			break;

		case CPUID_0000_000B:
		case 0x1f:
			/*
			 * Intel processor topology enumeration.  Newer
			 * guests prefer V2 leaf 0x1f when the basic CPUID
			 * range contains it, so both leaves must describe
			 * the virtual topology rather than the host.
			 */
			if (vmm_is_intel()) {
				vm_get_topology(vm, &sockets, &cores, &threads,
				    &maxcpus);
				error = x86_cpuid_topology(func, param, cores,
				    threads, vcpu_id, cpuid_leaf_b, regs);
				KASSERT(error == 0,
				    ("invalid virtual CPUID topology: %d",
				    error));
			} else {
				regs[0] = 0;
				regs[1] = 0;
				regs[2] = 0;
				regs[3] = 0;
			}
			break;

		case CPUID_0000_000D:
			limits = vmm_get_xsave_limits();
			if (!limits->xsave_enabled) {
				regs[0] = 0;
				regs[1] = 0;
				regs[2] = 0;
				regs[3] = 0;
				break;
			}

			cpuid_count(func, param, regs);
			switch (param) {
			case 0:
				/*
				 * Only permit the guest to use bits
				 * that are active in the host in
				 * %xcr0.  Also, claim that the
				 * maximum save area size is
				 * equivalent to the host's current
				 * save area size.  A compatibility
				 * query is not a guest CPUID
				 * execution, so canonicalize EBX to
				 * the maximum instead of exposing
				 * whichever XCR0 happened to be active
				 * on the calling thread.
				 */
				regs[0] &= limits->xcr0_allowed;
				regs[2] = limits->xsave_max_size;
				regs[3] &= (limits->xcr0_allowed >> 32);
				if (baseline)
					regs[1] = limits->xsave_max_size;
				break;
			case 1:
				/* Only permit XSAVEOPT. */
				regs[0] &= CPUID_EXTSTATE_XSAVEOPT;
				regs[1] = 0;
				regs[2] = 0;
				regs[3] = 0;
				break;
			default:
				/*
				 * If the leaf is for a permitted feature,
				 * pass through as-is, otherwise return
				 * all zeroes.
				 */
				if (!(limits->xcr0_allowed & (1ul << param))) {
					regs[0] = 0;
					regs[1] = 0;
					regs[2] = 0;
					regs[3] = 0;
				}
				break;
			}
			break;

		case CPUID_0000_000F:
		case CPUID_0000_0010:
			/*
			 * Do not report any Resource Director Technology
			 * capabilities.  Exposing control of cache or memory
			 * controller resource partitioning to the guest is not
			 * at all sensible.
			 *
			 * This is already hidden at a high level by masking of
			 * leaf 0x7.  Even still, a guest may look here for
			 * detailed capability information.
			 */
			regs[0] = 0;
			regs[1] = 0;
			regs[2] = 0;
			regs[3] = 0;
			break;

		case CPUID_0000_0015:
			/*
			 * Don't report CPU TSC/Crystal ratio and clock
			 * values since guests may use these to derive the
			 * local APIC frequency..
			 */
			regs[0] = 0;
			regs[1] = 0;
			regs[2] = 0;
			regs[3] = 0;
			break;

		case CPUID_VM_SIGNATURE:
			if (pvclock) {
				/*
				 * KVM occupies the base leaf; %eax is the
				 * highest leaf in the KVM block (its feature
				 * leaf at 0x40000001).
				 */
				regs[0] = VPVCLOCK_CPUID_KVM_FEATURES;
				bcopy(kvm_id, &regs[1], 4);
				bcopy(kvm_id + 4, &regs[2], 4);
				bcopy(kvm_id + 8, &regs[3], 4);
			} else {
				regs[0] = CPUID_BHYVE_FEATURES;
				bcopy(bhyve_id, &regs[1], 4);
				bcopy(bhyve_id + 4, &regs[2], 4);
				bcopy(bhyve_id + 8, &regs[3], 4);
			}
			break;

		case CPUID_BHYVE_FEATURES:
			if (pvclock) {
				/* KVM feature leaf (0x40000001). */
				regs[0] = vpvclock_kvm_features();
				regs[1] = 0;
				regs[2] = 0;
				regs[3] = 0;
			} else {
				regs[0] = CPUID_BHYVE_FEAT_EXT_DEST_ID;
				regs[1] = 0;
				regs[2] = 0;
				regs[3] = 0;
			}
			break;

		case CPUID_BHYVE_SIGNATURE_ALT:
			/*
			 * Preserved bhyve signature at the secondary block;
			 * only reachable when the KVM interface is advertised
			 * (otherwise clamped away by 'vm_high').
			 */
			regs[0] = CPUID_BHYVE_FEATURES_ALT;
			bcopy(bhyve_id, &regs[1], 4);
			bcopy(bhyve_id + 4, &regs[2], 4);
			bcopy(bhyve_id + 8, &regs[3], 4);
			break;

		case CPUID_BHYVE_FEATURES_ALT:
			regs[0] = CPUID_BHYVE_FEAT_EXT_DEST_ID;
			regs[1] = 0;
			regs[2] = 0;
			regs[3] = 0;
			break;

		default:
default_leaf:
			/*
			 * An unhandled leaf inside the hypervisor CPUID range
			 * (e.g. a gap between the KVM and bhyve blocks) reports
			 * zeros rather than leaking host CPUID data.
			 */
			if (func >= CPUID_VM_SIGNATURE && func <= vm_high) {
				regs[0] = 0;
				regs[1] = 0;
				regs[2] = 0;
				regs[3] = 0;
				break;
			}

			/*
			 * The leaf value has already been clamped so
			 * simply pass this through, keeping count of
			 * how many unhandled leaf values have been seen.
			 * A compatibility-baseline query is introspection,
			 * not a guest CPUID execution, and must not perturb
			 * that operational counter.
			 */
			if (!baseline)
				atomic_add_long(&bhyve_xcpuids, 1);
			cpuid_count(func, param, regs);
			break;
	}

	/*
	 * CPUID clears the upper 32-bits of the long-mode registers.
	 */
	*rax = regs[0];
	*rbx = regs[1];
	*rcx = regs[2];
	*rdx = regs[3];

	return (1);
}

int
x86_emulate_cpuid(struct vcpu *vcpu, uint64_t *rax, uint64_t *rbx,
    uint64_t *rcx, uint64_t *rdx)
{

	return (x86_emulate_cpuid_impl(vcpu, rax, rbx, rcx, rdx, false));
}

int
x86_emulate_cpuid_baseline(struct vcpu *vcpu, uint64_t *rax, uint64_t *rbx,
    uint64_t *rcx, uint64_t *rdx)
{

	return (x86_emulate_cpuid_impl(vcpu, rax, rbx, rcx, rdx, true));
}

bool
vm_cpuid_capability(struct vcpu *vcpu, enum vm_cpuid_capability cap)
{
	bool rv;

	KASSERT(cap > 0 && cap < VCC_LAST, ("%s: invalid vm_cpu_capability %d",
	    __func__, cap));

	/*
	 * Simply passthrough the capabilities of the host cpu for now.
	 */
	rv = false;
	switch (cap) {
	case VCC_NO_EXECUTE:
		if (amd_feature & AMDID_NX)
			rv = true;
		break;
	case VCC_FFXSR:
		if (amd_feature & AMDID_FFXSR)
			rv = true;
		break;
	case VCC_TCE:
		if (amd_feature2 & AMDID2_TCE)
			rv = true;
		break;
	default:
		panic("%s: unknown vm_cpu_capability %d", __func__, cap);
	}
	return (rv);
}
