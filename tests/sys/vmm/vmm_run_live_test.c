/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/mman.h>
#include <sys/sysctl.h>

#include "../../../sys/amd64/include/vmm.h"
#include "../../../sys/amd64/include/vmm_snapshot.h"
#include <machine/specialreg.h>

#include "../../../sys/amd64/vmm/amd/vmcb.h"

#include <vmmapi.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	GUEST_MEMORY_SIZE	(2 * 1024 * 1024)
#define	GUEST_CODE_GPA		0x1000
#define	SVM_L2_CODE_GPA		0x2000
#define	SVM_VMCB12_GPA		0x4000
#define	SVM_IOPM_GPA		0x5000
#define	SVM_MSRPM_GPA		0x8000
#define	SVM_HSAVE_GPA		0xa000
#define	SVM_NPT12_ROOT_GPA	0xb000
#define	SVM_NPT12_PDPT_GPA	0xc000
#define	SVM_NPT12_PD_GPA	0xd000
#define	SVM_NPT12_PT_GPA	0xe000
#define	SVM_NPT12_APIC_PD_GPA	0xf000
#define	SVM_READONLY_ROM_GPA	0x300000

struct live_vm {
	struct vmctx *ctx;
	struct vcpu *vcpu;
	uint8_t *code;
};

static void
require_live_vmm(atf_tc_t *tc)
{

	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.arch", "amd64");
	atf_tc_set_md_var(tc, "require.kmods", "vmm");
	atf_tc_set_md_var(tc, "timeout", "10");
}

static void
vm_name_for(const atf_tc_t *tc, char *name, size_t size)
{

	ATF_REQUIRE(snprintf(name, size, "vmr-%ld-%s", (long)getpid(),
	    atf_tc_get_ident(tc)) > 0);
}

static void
record_vm_name(const atf_tc_t *tc, const char *name)
{
	char path[PATH_MAX];
	FILE *fp;

	ATF_REQUIRE(snprintf(path, sizeof(path), ".%s-vm-name",
	    atf_tc_get_ident(tc)) > 0);
	fp = fopen(path, "w");
	ATF_REQUIRE_MSG(fp != NULL, "fopen(%s): %s", path,
	    strerror(errno));
	ATF_REQUIRE_MSG(fprintf(fp, "%s\n", name) > 0,
	    "record VM name: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(fclose(fp), 0, "fclose(%s): %s", path,
	    strerror(errno));
}

static void
cleanup_vm(const atf_tc_t *tc)
{
	char name[VM_MAX_NAMELEN], path[PATH_MAX];
	struct vmctx *ctx;
	FILE *fp;

	if (snprintf(path, sizeof(path), ".%s-vm-name",
	    atf_tc_get_ident(tc)) <= 0)
		return;
	fp = fopen(path, "r");
	if (fp == NULL)
		return;
	if (fgets(name, sizeof(name), fp) == NULL) {
		(void)fclose(fp);
		(void)unlink(path);
		return;
	}
	(void)fclose(fp);
	(void)unlink(path);
	name[strcspn(name, "\r\n")] = '\0';
	if (name[0] == '\0')
		return;
	ctx = vm_open(name);
	if (ctx != NULL)
		vm_destroy(ctx);
}

static struct live_vm
create_live_vm(const atf_tc_t *tc)
{
	struct live_vm live;
	char name[VM_MAX_NAMELEN];

	memset(&live, 0, sizeof(live));
	vm_name_for(tc, name, sizeof(name));
	ATF_REQUIRE_EQ_MSG(vm_create(name), 0, "vm_create: %s",
	    strerror(errno));
	record_vm_name(tc, name);
	live.ctx = vm_open(name);
	ATF_REQUIRE_MSG(live.ctx != NULL, "vm_open: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_setup_memory(live.ctx, GUEST_MEMORY_SIZE,
	    VM_MMAP_ALL), 0, "vm_setup_memory: %s", strerror(errno));
	live.code = vm_map_gpa(live.ctx, GUEST_CODE_GPA, PAGE_SIZE);
	ATF_REQUIRE_MSG(live.code != NULL, "vm_map_gpa: %s", strerror(errno));
	live.vcpu = vm_vcpu_open(live.ctx, 0);
	ATF_REQUIRE_MSG(live.vcpu != NULL, "vm_vcpu_open: %s",
	    strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_activate_cpu(live.vcpu), 0,
	    "vm_activate_cpu: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_set_capability(live.vcpu,
	    VM_CAP_UNRESTRICTED_GUEST, 1), 0,
	    "enable unrestricted guest: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(vcpu_reset(live.vcpu), 0, "vcpu_reset: %s",
	    strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x0093), 0, "set flat CS: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_set_register(live.vcpu, VM_REG_GUEST_CS, 0), 0,
	    "set CS: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_set_register(live.vcpu, VM_REG_GUEST_RIP,
	    GUEST_CODE_GPA), 0, "set RIP: %s", strerror(errno));
	return (live);
}

static struct live_vm
create_nested_live_vm(const atf_tc_t *tc)
{
	unsigned int features;
	int enabled;
	size_t len;

	len = sizeof(enabled);
	if (sysctlbyname("hw.vmm.svm.nested", &enabled, &len, NULL, 0) != 0)
		atf_tc_skip("requires AMD SVM hardware and a matching vmm module");
	ATF_REQUIRE_EQ(len, sizeof(enabled));
	if (enabled != 1)
		atf_tc_skip("load vmm with hw.vmm.svm.nested=1");
	len = sizeof(features);
	ATF_REQUIRE_EQ(sysctlbyname("hw.vmm.svm.features", &features,
	    &len, NULL, 0), 0);
	ATF_REQUIRE_EQ(len, sizeof(features));
	if ((features & (1U << 7)) == 0)
		atf_tc_skip("nested SVM requires AMD DecodeAssists");
	return (create_live_vm(tc));
}

static struct vm_exit
run_once(struct vcpu *vcpu)
{
	struct vm_exit vmexit;
	struct vm_run vmrun;
	cpuset_t cpuset;

	memset(&vmexit, 0, sizeof(vmexit));
	memset(&vmrun, 0, sizeof(vmrun));
	CPU_ZERO(&cpuset);
	vmrun.vm_exit = &vmexit;
	vmrun.cpuset = &cpuset;
	vmrun.cpusetsize = sizeof(cpuset);
	ATF_REQUIRE_EQ_MSG(vm_run(vcpu, &vmrun), 0, "vm_run: %s",
	    strerror(errno));
	return (vmexit);
}

ATF_TC_WITH_CLEANUP(real_mode_io_and_halt);
ATF_TC_HEAD(real_mode_io_and_halt, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Enter a hardware vCPU and preserve state across I/O and HLT exits");
}
ATF_TC_BODY(real_mode_io_and_halt, tc)
{
	static const uint8_t program[] = {
		0xb0, 0x5a,             /* mov al, 0x5a */
		0xe6, 0x80,             /* out 0x80, al */
		0xf4,                   /* hlt */
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint64_t rax;

	live = create_live_vm(tc);
	memcpy(live.code, program, sizeof(program));
	ATF_REQUIRE_EQ_MSG(vm_set_capability(live.vcpu, VM_CAP_HALT_EXIT, 1),
	    0, "enable HLT exit: %s", strerror(errno));

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_REQUIRE_EQ(vmexit.rip, GUEST_CODE_GPA + 2);
	ATF_REQUIRE_EQ(vmexit.inst_length, 2);
	ATF_REQUIRE_EQ(vmexit.u.inout.port, 0x80);
	ATF_REQUIRE_EQ(vmexit.u.inout.bytes, 1);
	ATF_REQUIRE_EQ(vmexit.u.inout.in, 0);
	ATF_REQUIRE_EQ(vmexit.u.inout.eax & UINT8_MAX, 0x5a);
	ATF_REQUIRE_EQ_MSG(vm_get_register(live.vcpu, VM_REG_GUEST_RAX, &rax),
	    0, "get RAX: %s", strerror(errno));
	ATF_REQUIRE_EQ(rax & UINT8_MAX, 0x5a);
	ATF_REQUIRE_EQ_MSG(vm_set_register(live.vcpu, VM_REG_GUEST_RIP,
	    vmexit.rip + vmexit.inst_length), 0, "advance RIP: %s",
	    strerror(errno));

	vmexit = run_once(live.vcpu);
	/*
	 * HLT is a kernel-owned exit.  With interrupts disabled and every active
	 * vCPU halted, vm_handle_hlt() suspends the VM and re-enters the run loop;
	 * the stable userspace ABI is therefore a halt suspension at the next
	 * instruction, not the backend's intermediate VM_EXITCODE_HLT.
	 */
	ATF_REQUIRE_EQ_MSG(vmexit.exitcode, VM_EXITCODE_SUSPENDED,
	    "unexpected post-HLT exit code %d", vmexit.exitcode);
	ATF_REQUIRE_EQ(vmexit.rip, GUEST_CODE_GPA + sizeof(program));
	ATF_REQUIRE_EQ(vmexit.inst_length, 0);
	ATF_REQUIRE_EQ(vmexit.u.suspended.how, VM_SUSPEND_HALT);
	ATF_REQUIRE_EQ_MSG(vm_get_register(live.vcpu, VM_REG_GUEST_RIP, &rax),
	    0, "get post-HLT RIP: %s", strerror(errno));
	ATF_REQUIRE_EQ(rax, GUEST_CODE_GPA + sizeof(program));
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(real_mode_io_and_halt, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(efer_svme_hidden);
ATF_TC_HEAD(efer_svme_hidden, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Guest RDMSR and register ABI agree that SVME is unavailable by default");
}
ATF_TC_BODY(efer_svme_hidden, tc)
{
	static const uint8_t program[] = {
		0x66, 0xb9, 0x80, 0x00, 0x00, 0xc0, /* mov ecx, MSR_EFER */
		0x0f, 0x32,                         /* rdmsr */
		0xe6, 0x80,                         /* out 0x80, al */
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint64_t efer, rax;
	uint32_t vendor[3];
	uint32_t eax, ebx, ecx, edx;

	live = create_live_vm(tc);
	eax = 0;
	ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ_MSG(vm_get_cpuid(live.vcpu, 0, &eax, &ebx, &ecx,
	    &edx), 0, "get vendor CPUID: %s", strerror(errno));
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	eax = 0x80000001;
	ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ_MSG(vm_get_cpuid(live.vcpu, 0, &eax, &ebx, &ecx,
	    &edx), 0, "get extended CPUID: %s", strerror(errno));
	ATF_REQUIRE_EQ(ecx & AMDID2_SVM, 0);
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) == 0) {
		eax = 0x8000000a;
		ebx = ecx = edx = 0;
		ATF_REQUIRE_EQ_MSG(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
		    &ecx, &edx), 0, "get SVM CPUID: %s", strerror(errno));
		ATF_CHECK_EQ(eax | ebx | ecx | edx, 0);
	}
	memcpy(live.code, program, sizeof(program));
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_REQUIRE_EQ_MSG(vm_get_register(live.vcpu, VM_REG_GUEST_RAX,
	    &rax), 0, "get RAX: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_get_register(live.vcpu, VM_REG_GUEST_EFER,
	    &efer), 0, "get EFER: %s", strerror(errno));
	ATF_REQUIRE_EQ(rax & EFER_SVM, 0);
	ATF_REQUIRE_EQ(efer & EFER_SVM, 0);
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) == 0) {
		errno = 0;
		ATF_REQUIRE_EQ(vm_set_register(live.vcpu,
		    VM_REG_GUEST_EFER, EFER_SVM), -1);
		ATF_CHECK_EQ(errno, EINVAL);
		ATF_REQUIRE_EQ(vm_get_register(live.vcpu,
		    VM_REG_GUEST_EFER, &efer), 0);
		ATF_CHECK_EQ(efer & EFER_SVM, 0);
	}
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(efer_svme_hidden, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(breakpoint_exit);
ATF_TC_HEAD(breakpoint_exit, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Enter a hardware vCPU and report a guest breakpoint exit");
}
ATF_TC_BODY(breakpoint_exit, tc)
{
	struct live_vm live;
	struct vm_exit vmexit;

	live = create_live_vm(tc);
	live.code[0] = 0xcc;       /* int3 */
	ATF_REQUIRE_EQ_MSG(vm_set_capability(live.vcpu, VM_CAP_BPT_EXIT, 1), 0,
	    "enable breakpoint exit: %s", strerror(errno));
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_BPT);
	ATF_REQUIRE_EQ(vmexit.rip, GUEST_CODE_GPA);
	ATF_REQUIRE_EQ(vmexit.inst_length, 0);
	ATF_REQUIRE_EQ(vmexit.u.bpt.inst_length, 1);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(breakpoint_exit, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(pause_exit);
ATF_TC_HEAD(pause_exit, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Enter a hardware vCPU and report a guest PAUSE exit");
}
ATF_TC_BODY(pause_exit, tc)
{
	struct live_vm live;
	struct vm_exit vmexit;

	live = create_live_vm(tc);
	live.code[0] = 0xf3;
	live.code[1] = 0x90;       /* pause */
	ATF_REQUIRE_EQ_MSG(vm_set_capability(live.vcpu, VM_CAP_PAUSE_EXIT, 1), 0,
	    "enable PAUSE exit: %s", strerror(errno));
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_PAUSE);
	ATF_REQUIRE_EQ(vmexit.rip, GUEST_CODE_GPA);
	ATF_REQUIRE_EQ(vmexit.inst_length, 2);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(pause_exit, tc)
{

	cleanup_vm(tc);
}

static void
svm_vmcb12_real_segment(uint8_t *vmcb, unsigned int offset, uint16_t attrib)
{

	le16enc(vmcb + offset + 2, attrib);
	le32enc(vmcb + offset + 4, UINT16_MAX);
}

static void
svm_vmcb12_real_init(uint8_t *vmcb)
{

	memset(vmcb, 0, PAGE_SIZE);
	le32enc(vmcb + VMCB_OFF_INST2_INTERCEPT, VMCB_INTCPT_VMRUN);
	le64enc(vmcb + VMCB_OFF_IO_PERM, SVM_IOPM_GPA);
	le64enc(vmcb + VMCB_OFF_MSR_PERM, SVM_MSRPM_GPA);
	le32enc(vmcb + VMCB_OFF_ASID, 1);
	svm_vmcb12_real_segment(vmcb, VMCB_OFF_STATE(0), 0x93);
	svm_vmcb12_real_segment(vmcb, VMCB_OFF_STATE(0x10), 0x9b);
	svm_vmcb12_real_segment(vmcb, VMCB_OFF_STATE(0x20), 0x93);
	svm_vmcb12_real_segment(vmcb, VMCB_OFF_STATE(0x30), 0x93);
	le64enc(vmcb + VMCB_OFF_STATE(0xd0), EFER_SVM);
	le64enc(vmcb + VMCB_OFF_STATE(0x158), 0x10);
	le64enc(vmcb + VMCB_OFF_STATE(0x160), 0x400);
	le64enc(vmcb + VMCB_OFF_STATE(0x168), 0xffff0ff0ULL);
	le64enc(vmcb + VMCB_OFF_STATE(0x170), 2);
	le64enc(vmcb + VMCB_OFF_STATE(0x178), SVM_L2_CODE_GPA);
	le64enc(vmcb + VMCB_OFF_GUEST_PAT,
	    0x0007040600070406ULL);
}

ATF_TC_WITH_CLEANUP(svm_nested_host_policy);
ATF_TC_HEAD(svm_nested_host_policy, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "AMD nested SVM requires host policy, DecodeAssists and guest opt-in");
}
ATF_TC_BODY(svm_nested_host_policy, tc)
{
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	unsigned int features;
	size_t len;
	int enabled, cap, error;

	live = create_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx, &ecx,
	    &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	len = sizeof(enabled);
	ATF_REQUIRE_EQ(sysctlbyname("hw.vmm.svm.nested", &enabled, &len,
	    NULL, 0), 0);
	ATF_REQUIRE_EQ(len, sizeof(enabled));
	len = sizeof(features);
	ATF_REQUIRE_EQ(sysctlbyname("hw.vmm.svm.features", &features, &len,
	    NULL, 0), 0);
	ATF_REQUIRE_EQ(len, sizeof(features));
	ATF_REQUIRE_MSG(enabled == 0 || enabled == 1,
	    "hw.vmm.svm.nested must be 0 or 1");
	errno = 0;
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 2),
	    -1);
	ATF_CHECK_EQ(errno, EINVAL);
	cap = -1;
	errno = 0;
	error = vm_get_capability(live.vcpu, VM_CAP_NESTED_SVM, &cap);
	if (enabled == 0 || (features & (1U << 7)) == 0) {
		ATF_CHECK_EQ(error, -1);
		ATF_CHECK_EQ(errno, ENOENT);
		errno = 0;
		ATF_REQUIRE_EQ(vm_set_capability(live.vcpu,
		    VM_CAP_NESTED_SVM, 1), -1);
		ATF_CHECK_EQ(errno, enabled == 0 ? EOPNOTSUPP : ENOTSUP);
	} else {
		ATF_REQUIRE_EQ(error, 0);
		ATF_CHECK_EQ(cap, 0);
		ATF_REQUIRE_EQ(vm_set_capability(live.vcpu,
		    VM_CAP_NESTED_SVM, 1), 0);
		ATF_REQUIRE_EQ(vm_get_capability(live.vcpu,
		    VM_CAP_NESTED_SVM, &cap), 0);
		ATF_CHECK_EQ(cap, 1);
		ATF_REQUIRE_EQ(vm_set_capability(live.vcpu,
		    VM_CAP_NESTED_SVM, 0), 0);
		ATF_REQUIRE_EQ(vm_get_capability(live.vcpu,
		    VM_CAP_NESTED_SVM, &cap), 0);
		ATF_CHECK_EQ(cap, 0);
		/* Guest execution freezes the CPUID model even before EFER.SVME. */
		live.code[0] = 0xe6; /* out 0x80, al */
		live.code[1] = 0x80;
		vmexit = run_once(live.vcpu);
		ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
		errno = 0;
		ATF_REQUIRE_EQ(vm_set_capability(live.vcpu,
		    VM_CAP_NESTED_SVM, 1), -1);
		ATF_CHECK_EQ(errno, EBUSY);
		ATF_REQUIRE_EQ(vm_get_capability(live.vcpu,
		    VM_CAP_NESTED_SVM, &cap), 0);
		ATF_CHECK_EQ(cap, 0);
		ATF_REQUIRE_EQ(vm_set_capability(live.vcpu,
		    VM_CAP_NESTED_SVM, 0), 0);
	}
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_nested_host_policy, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_portio);
ATF_TC_HEAD(svm_l2_portio, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Enter an AMD L2 through VMRUN and route its port I/O to L0");
}
ATF_TC_BODY(svm_l2_portio, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0, /* mov ecx, VM_HSAVE_PA */
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00, /* mov eax, 0xa000 */
		0x66, 0x31, 0xd2,                   /* xor edx, edx */
		0x0f, 0x30,                         /* wrmsr */
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00, /* mov eax, VMCB12 */
		0x0f, 0x01, 0xdd,                   /* clgi */
		0x0f, 0x01, 0xd8,                   /* vmrun */
		0xe6, 0x81,                         /* L1 fallback out */
	};
	static const uint8_t l2_program[] = {
		0xb0, 0x7b, /* mov al, 0x7b */
		0xe6, 0x80, /* out 0x80, al */
		0xf3, 0x90, /* pause without an L1 intercept */
		0xf4,       /* halt in L2 without an L1 intercept */
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *vmcb, *l2_code;
	uint64_t rax;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ_MSG(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM,
	    1), 0, "enable nested SVM: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_set_capability(live.vcpu, VM_CAP_HALT_EXIT,
	    1), 0, "enable HLT exit: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_set_capability(live.vcpu, VM_CAP_PAUSE_EXIT,
	    1), 0, "enable PAUSE exit: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0, "set SVME: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0, "set protected mode: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0, "set protected CS: %s", strerror(errno));
	memcpy(live.code, l1_program, sizeof(l1_program));
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	ATF_REQUIRE(l2_code != NULL && vmcb != NULL);
	memcpy(l2_code, l2_program, sizeof(l2_program));
	svm_vmcb12_real_init(vmcb);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.rip, SVM_L2_CODE_GPA + 2);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
	ATF_CHECK_EQ(vmexit.u.inout.eax & UINT8_MAX, 0x7b);
	ATF_REQUIRE_EQ(vm_get_register(live.vcpu, VM_REG_GUEST_RAX,
	    &rax), 0);
	ATF_CHECK_EQ(rax & UINT8_MAX, 0x7b);
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_PAUSE);
	ATF_CHECK_EQ(vmexit.rip, SVM_L2_CODE_GPA + 4);
	ATF_CHECK_EQ(vmexit.inst_length, 2);
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_SUSPENDED);
	ATF_CHECK_EQ(vmexit.rip, SVM_L2_CODE_GPA + sizeof(l2_program));
	ATF_CHECK_EQ(vmexit.u.suspended.how, VM_SUSPEND_HALT);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_portio, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_shutdown_intercepted);
ATF_TC_HEAD(svm_l2_shutdown_intercepted, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Reflect AMD L2 shutdown to L1 without copying undefined saved state");
}

ATF_TC_WITH_CLEANUP(svm_l2_shutdown_unintercepted);
ATF_TC_HEAD(svm_l2_shutdown_unintercepted, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Suspend the VM on an AMD L2 shutdown not intercepted by L1");
}

static void
svm_l2_shutdown_case(const atf_tc_t *tc, bool l1_intercepts)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0, /* mov ecx, VM_HSAVE_PA */
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00, /* mov eax, 0xa000 */
		0x66, 0x31, 0xd2,                   /* xor edx, edx */
		0x0f, 0x30,                         /* wrmsr */
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00, /* mov eax, VMCB12 */
		0x0f, 0x01, 0xdd,                   /* clgi */
		0x0f, 0x01, 0xd8,                   /* vmrun */
		0xe6, 0x81,                         /* L1 exit after reflection */
	};
	static const uint8_t l2_program[] = {
		0xcc,       /* int3: empty IDT causes a shutdown */
		0xe6, 0x82, /* unexpected return must be visible */
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *l2_code, *vmcb;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	ATF_REQUIRE(l2_code != NULL && vmcb != NULL);
	memcpy(l2_code, l2_program, sizeof(l2_program));
	svm_vmcb12_real_init(vmcb);
	/* An interrupt vector 3 needs bytes beyond this zero-length IDT. */
	le32enc(vmcb + VMCB_OFF_STATE(0x84), 0);
	if (l1_intercepts)
		le32enc(vmcb + VMCB_OFF_INST1_INTERCEPT,
		    VMCB_INTCPT_SHUTDOWN);

	vmexit = run_once(live.vcpu);
	if (l1_intercepts) {
		ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
		ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
		ATF_CHECK_EQ(vmexit.rip,
		    GUEST_CODE_GPA + sizeof(l1_program) - 2);
		ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXIT_REASON),
		    VMCB_EXIT_SHUTDOWN);
		ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXITINFO1), 0);
		ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXITINFO2), 0);
		ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXITINTINFO), 0);
		ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_STATE(0x178)),
		    SVM_L2_CODE_GPA);
	} else {
		ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_SUSPENDED);
		ATF_CHECK_EQ(vmexit.u.suspended.how,
		    VM_SUSPEND_TRIPLEFAULT);
		ATF_CHECK_EQ(vmexit.rip,
		    GUEST_CODE_GPA + sizeof(l1_program) - 2);
		ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXIT_REASON), 0);
		ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_STATE(0x178)),
		    SVM_L2_CODE_GPA);
	}
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}

ATF_TC_BODY(svm_l2_shutdown_intercepted, tc)
{

	svm_l2_shutdown_case(tc, true);
}
ATF_TC_CLEANUP(svm_l2_shutdown_intercepted, tc)
{

	cleanup_vm(tc);
}

ATF_TC_BODY(svm_l2_shutdown_unintercepted, tc)
{

	svm_l2_shutdown_case(tc, false);
}
ATF_TC_CLEANUP(svm_l2_shutdown_unintercepted, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_breakpoint_exit);
ATF_TC_HEAD(svm_l2_breakpoint_exit, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Report an L0 breakpoint exit from AMD L2 when L1 does not intercept it");
}
static void
svm_l2_breakpoint_case(const atf_tc_t *tc, int l1_intercepts)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x81,
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *l2_code, *vmcb;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	ATF_REQUIRE(l2_code != NULL && vmcb != NULL);
	l2_code[0] = 0xe6; /* out 0x80, al */
	l2_code[1] = 0x80;
	l2_code[2] = 0xcc; /* int3 */
	svm_vmcb12_real_init(vmcb);
	if (l1_intercepts)
		le32enc(vmcb + VMCB_OFF_EXC_INTERCEPT, 1U << 3);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.rip, SVM_L2_CODE_GPA);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
	/* Enable L0 breakpoint exiting after VMCB02 has already been built. */
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_BPT_EXIT, 1), 0);
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_BPT);
	ATF_CHECK_EQ(vmexit.rip, SVM_L2_CODE_GPA + 2);
	ATF_CHECK_EQ(vmexit.inst_length, 0);
	ATF_CHECK_EQ(vmexit.u.bpt.inst_length, 1);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_BODY(svm_l2_breakpoint_exit, tc)
{

	svm_l2_breakpoint_case(tc, 0);
}
ATF_TC_CLEANUP(svm_l2_breakpoint_exit, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_breakpoint_l0_priority);
ATF_TC_HEAD(svm_l2_breakpoint_l0_priority, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Keep an L0 breakpoint exit when AMD L1 also intercepts #BP");
}
ATF_TC_BODY(svm_l2_breakpoint_l0_priority, tc)
{

	svm_l2_breakpoint_case(tc, 1);
}
ATF_TC_CLEANUP(svm_l2_breakpoint_l0_priority, tc)
{

	cleanup_vm(tc);
}

static void
svm_l2_async_event_case(const atf_tc_t *tc, int nmi)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x81,
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *l2_code, *vmcb;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	ATF_REQUIRE(l2_code != NULL && vmcb != NULL);
	l2_code[0] = 0xe6; /* L2 out 0x80, al */
	l2_code[1] = 0x80;
	l2_code[2] = 0xe6; /* L2 out 0x83, al if no nested exit */
	l2_code[3] = 0x83;
	svm_vmcb12_real_init(vmcb);
	le32enc(vmcb + VMCB_OFF_INST1_INTERCEPT,
	    nmi ? VMCB_INTCPT_NMI : VMCB_INTCPT_INTR);
	le64enc(vmcb + VMCB_OFF_STATE(0x168), 0x202);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.rip, SVM_L2_CODE_GPA);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXIT_REASON), 0);
	if (nmi)
		ATF_REQUIRE_EQ(vm_inject_nmi(live.vcpu), 0);
	else
		ATF_REQUIRE_EQ(vm_lapic_irq(live.vcpu, 0x40), 0);
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXIT_REASON),
	    nmi ? VMCB_EXIT_NMI : VMCB_EXIT_INTR);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXITINFO1), 0);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXITINFO2), 0);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}

ATF_TC_WITH_CLEANUP(svm_l2_pending_irq_reflected);
ATF_TC_HEAD(svm_l2_pending_irq_reflected, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Reflect a pending L0 virtual IRQ through L1's AMD L2 intercept");
}
ATF_TC_BODY(svm_l2_pending_irq_reflected, tc)
{

	svm_l2_async_event_case(tc, 0);
}
ATF_TC_CLEANUP(svm_l2_pending_irq_reflected, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_pending_nmi_reflected);
ATF_TC_HEAD(svm_l2_pending_nmi_reflected, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Reflect a pending L0 virtual NMI through L1's AMD L2 intercept");
}
ATF_TC_BODY(svm_l2_pending_nmi_reflected, tc)
{

	svm_l2_async_event_case(tc, 1);
}
ATF_TC_CLEANUP(svm_l2_pending_nmi_reflected, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_virtual_irq);
ATF_TC_HEAD(svm_l2_virtual_irq, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Deliver L1's V_IRQ through VMCB02 to a real-mode L2 handler");
}
ATF_TC_BODY(svm_l2_virtual_irq, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x82,
	};
	static const uint8_t l2_main[] = { 0xe6, 0x81 };
	static const uint8_t l2_handler[] = {
		0xb0, 0x5a, /* mov al, 0x5a */
		0xe6, 0x80, /* out 0x80, al */
		0xcf,       /* iret */
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *ivt, *l2_code, *vmcb;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	ivt = vm_map_gpa(live.ctx, 0, PAGE_SIZE);
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	ATF_REQUIRE(ivt != NULL && l2_code != NULL && vmcb != NULL);
	memcpy(l2_code, l2_main, sizeof(l2_main));
	memcpy(l2_code + 0x100, l2_handler, sizeof(l2_handler));
	le16enc(ivt + 0x30 * 4, SVM_L2_CODE_GPA + 0x100);
	le16enc(ivt + 0x30 * 4 + 2, 0);
	svm_vmcb12_real_init(vmcb);
	le32enc(vmcb + VMCB_OFF_STATE(0x80) + 4, 0x3ff);
	le64enc(vmcb + VMCB_OFF_STATE(0x168), 0x202);
	le64enc(vmcb + VMCB_OFF_STATE(0x1d8), 0x7000);
	vmcb[VMCB_OFF_VIRQ + 1] = 1;
	vmcb[VMCB_OFF_VIRQ + 2] = 0x13; /* priority 3, ignore TPR */
	vmcb[VMCB_OFF_VIRQ + 4] = 0x30;

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.rip, SVM_L2_CODE_GPA + 0x102);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
	ATF_CHECK_EQ(vmexit.u.inout.eax & UINT8_MAX, 0x5a);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXIT_REASON), 0);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_virtual_irq, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_l0_irq);
ATF_TC_HEAD(svm_l2_l0_irq, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Deliver an L0 virtual IRQ directly to AMD L2 without an L1 intercept");
}
ATF_TC_BODY(svm_l2_l0_irq, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x82,
	};
	static const uint8_t l2_main[] = { 0xe6, 0x81, 0xe6, 0x83 };
	static const uint8_t l2_handler[] = {
		0xb0, 0x5a,
		0xe6, 0x80,
		0xcf,
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *ivt, *l2_code, *vmcb;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	ivt = vm_map_gpa(live.ctx, 0, PAGE_SIZE);
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	ATF_REQUIRE(ivt != NULL && l2_code != NULL && vmcb != NULL);
	memcpy(l2_code, l2_main, sizeof(l2_main));
	memcpy(l2_code + 0x100, l2_handler, sizeof(l2_handler));
	le16enc(ivt + 0x40 * 4, SVM_L2_CODE_GPA + 0x100);
	le16enc(ivt + 0x40 * 4 + 2, 0);
	svm_vmcb12_real_init(vmcb);
	le32enc(vmcb + VMCB_OFF_STATE(0x80) + 4, 0x3ff);
	le64enc(vmcb + VMCB_OFF_STATE(0x168), 0x202);
	le64enc(vmcb + VMCB_OFF_STATE(0x1d8), 0x7000);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
	ATF_REQUIRE_EQ(vm_lapic_irq(live.vcpu, 0x40), 0);
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.rip, SVM_L2_CODE_GPA + 0x102);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
	ATF_CHECK_EQ(vmexit.u.inout.eax & UINT8_MAX, 0x5a);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXIT_REASON), 0);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_l0_irq, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_l0_nmi);
ATF_TC_HEAD(svm_l2_l0_nmi, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Deliver L0 NMIs to AMD L2 across IRET and an active checkpoint");
}
ATF_TC_BODY(svm_l2_l0_nmi, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x82,
	};
	static const uint8_t l2_main[] = {
		0xe6, 0x81, 0xe6, 0x83, 0xe6, 0x84,
	};
	static const uint8_t l2_handler[] = {
		0xb0, 0x5a, 0xe6, 0x80, 0xcf,
	};
	struct live_vm live;
	struct vm_exit vmexit;
	struct vm_snapshot_session session;
	uint32_t eax, ebx, ecx, edx, features, vendor[3];
	uint8_t *buffer, *ivt, *l2_code, *vmcb;
	size_t feature_size, length;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	feature_size = sizeof(features);
	if (sysctlbyname("hw.vmm.svm.features", &features, &feature_size,
	    NULL, 0) != 0 || (features & (1U << 25)) == 0)
		atf_tc_skip("requires AMD virtual NMI hardware support");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	ivt = vm_map_gpa(live.ctx, 0, PAGE_SIZE);
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	ATF_REQUIRE(ivt != NULL && l2_code != NULL && vmcb != NULL);
	memcpy(l2_code, l2_main, sizeof(l2_main));
	memcpy(l2_code + 0x100, l2_handler, sizeof(l2_handler));
	le16enc(ivt + 2 * 4, SVM_L2_CODE_GPA + 0x100);
	le16enc(ivt + 2 * 4 + 2, 0);
	svm_vmcb12_real_init(vmcb);
	le32enc(vmcb + VMCB_OFF_STATE(0x80) + 4, 0x3ff);
	le64enc(vmcb + VMCB_OFF_STATE(0x1d8), 0x7000);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
	ATF_REQUIRE_EQ(vm_inject_nmi(live.vcpu), 0);
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
	ATF_CHECK_EQ(vmexit.rip, SVM_L2_CODE_GPA + 0x102);
	/* Save with the first NMI blocked; the restored IRET must clear it. */
	session = (struct vm_snapshot_session) {
		.version = VM_SNAPSHOT_SESSION_VERSION,
		.op = VM_SNAPSHOT_SESSION_BEGIN,
	};
	if (vm_snapshot_session(live.ctx, &session) == 0) {
		buffer = malloc(1024 * 1024);
		ATF_REQUIRE(buffer != NULL);
		{
			struct vm_snapshot_meta save = {
				.dev_req = STRUCT_VMCX,
				.buffer = {
					.buf_start = buffer,
					.buf_size = 1024 * 1024,
					.buf = buffer,
					.buf_rem = 1024 * 1024,
				},
				.op = VM_SNAPSHOT_SAVE,
			};
			ATF_REQUIRE_EQ(vm_snapshot_req(live.ctx, &save), 0);
			length = save.buffer.buf_size - save.buffer.buf_rem;
		}
		ATF_REQUIRE(length >= 12 + 48 + PAGE_SIZE +
		    16 * sizeof(uint64_t));
		ATF_CHECK_EQ(le32dec(buffer + 8), 2);
		ATF_CHECK_EQ(le64dec(buffer + 12 + 48 + PAGE_SIZE),
		    (1ULL << 63) | (1ULL << 62) | SVM_VMCB12_GPA);
		session.op = VM_SNAPSHOT_SESSION_COMMIT;
		ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
		session.op = VM_SNAPSHOT_SESSION_BEGIN;
		ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
		{
			struct vm_snapshot_meta restore = {
				.dev_req = STRUCT_VMCX,
				.buffer = {
					.buf_start = buffer,
					.buf_size = length,
					.buf = buffer,
					.buf_rem = length,
				},
				.op = VM_SNAPSHOT_RESTORE,
			};
			ATF_REQUIRE_EQ(vm_snapshot_req(live.ctx, &restore), 0);
		}
		session.op = VM_SNAPSHOT_SESSION_COMMIT;
		ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
		free(buffer);
	} else
		ATF_REQUIRE_EQ(errno, ENOTTY);
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x83);
	ATF_REQUIRE_EQ(vm_inject_nmi(live.vcpu), 0);
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
	ATF_CHECK_EQ(vmexit.rip, SVM_L2_CODE_GPA + 0x102);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXIT_REASON), 0);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_l0_nmi, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_l1_eventinj_nmi);
ATF_TC_HEAD(svm_l2_l1_eventinj_nmi, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Deliver an AMD L1 EVENTINJ NMI before L2's first instruction");
}
ATF_TC_BODY(svm_l2_l1_eventinj_nmi, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x82,
	};
	static const uint8_t l2_handler[] = {
		0xb0, 0x5a, 0xe6, 0x80, 0xcf,
	};
	struct live_vm live;
	struct vm_exit vmexit;
	struct vm_snapshot_session session;
	uint32_t eax, ebx, ecx, edx, features, vendor[3];
	uint8_t *buffer, *ivt, *l2_code, *vmcb;
	size_t feature_size, length;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	feature_size = sizeof(features);
	if (sysctlbyname("hw.vmm.svm.features", &features, &feature_size,
	    NULL, 0) != 0 || (features & (1U << 25)) == 0)
		atf_tc_skip("requires AMD virtual NMI hardware support");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	ivt = vm_map_gpa(live.ctx, 0, PAGE_SIZE);
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	ATF_REQUIRE(ivt != NULL && l2_code != NULL && vmcb != NULL);
	l2_code[0] = 0xe6; /* out 0x81, al */
	l2_code[1] = 0x81;
	memcpy(l2_code + 0x100, l2_handler, sizeof(l2_handler));
	le16enc(ivt + 2 * 4, SVM_L2_CODE_GPA + 0x100);
	le16enc(ivt + 2 * 4 + 2, 0);
	svm_vmcb12_real_init(vmcb);
	le32enc(vmcb + VMCB_OFF_STATE(0x80) + 4, 0x3ff);
	le64enc(vmcb + VMCB_OFF_STATE(0x1d8), 0x7000);
	le64enc(vmcb + VMCB_OFF_CTRL(0xa8), VMCB_EVENTINJ_VALID |
	    ((uint64_t)VMCB_EVENTINJ_TYPE_NMI << 8) | 2);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
	ATF_CHECK_EQ(vmexit.u.inout.eax & UINT8_MAX, 0x5a);
	/* An L1 injection must be represented in the active-L2 NMI image. */
	session = (struct vm_snapshot_session) {
		.version = VM_SNAPSHOT_SESSION_VERSION,
		.op = VM_SNAPSHOT_SESSION_BEGIN,
	};
	if (vm_snapshot_session(live.ctx, &session) == 0) {
		buffer = malloc(1024 * 1024);
		ATF_REQUIRE(buffer != NULL);
		struct vm_snapshot_meta save = {
			.dev_req = STRUCT_VMCX,
			.buffer = {
				.buf_start = buffer,
				.buf_size = 1024 * 1024,
				.buf = buffer,
				.buf_rem = 1024 * 1024,
			},
			.op = VM_SNAPSHOT_SAVE,
		};
		ATF_REQUIRE_EQ(vm_snapshot_req(live.ctx, &save), 0);
		length = save.buffer.buf_size - save.buffer.buf_rem;
		ATF_REQUIRE(length >= 12 + 48 + PAGE_SIZE +
		    16 * sizeof(uint64_t));
		ATF_CHECK_EQ(le64dec(buffer + 12 + 48 + PAGE_SIZE),
		    (1ULL << 63) | (1ULL << 62) | SVM_VMCB12_GPA);
		free(buffer);
		session.op = VM_SNAPSHOT_SESSION_COMMIT;
		ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
	} else
		ATF_REQUIRE_EQ(errno, ENOTTY);
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXIT_REASON), 0);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_l1_eventinj_nmi, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_l0_exception);
ATF_TC_HEAD(svm_l2_l0_exception, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Inject a queued L0 exception into active AMD L2");
}
ATF_TC_BODY(svm_l2_l0_exception, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x82,
	};
	static const uint8_t l2_main[] = { 0xe6, 0x81, 0xe6, 0x83 };
	static const uint8_t l2_handler[] = {
		0xb0, 0x6a,
		0xe6, 0x80,
		0xcf,
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *ivt, *l2_code, *vmcb;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	ivt = vm_map_gpa(live.ctx, 0, PAGE_SIZE);
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	ATF_REQUIRE(ivt != NULL && l2_code != NULL && vmcb != NULL);
	memcpy(l2_code, l2_main, sizeof(l2_main));
	memcpy(l2_code + 0x100, l2_handler, sizeof(l2_handler));
	le16enc(ivt + 6 * 4, SVM_L2_CODE_GPA + 0x100);
	le16enc(ivt + 6 * 4 + 2, 0);
	svm_vmcb12_real_init(vmcb);
	le32enc(vmcb + VMCB_OFF_STATE(0x80) + 4, 0x3ff);
	le64enc(vmcb + VMCB_OFF_STATE(0x1d8), 0x7000);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
	ATF_REQUIRE_EQ(vm_inject_exception(live.vcpu, 6, 0, 0, 1), 0);
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.rip, SVM_L2_CODE_GPA + 0x102);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
	ATF_CHECK_EQ(vmexit.u.inout.eax & UINT8_MAX, 0x6a);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXIT_REASON), 0);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_l0_exception, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_reserved_cr_ud);
ATF_TC_HEAD(svm_l2_reserved_cr_ud, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "An L0-owned reserved CR access injects #UD into AMD L2");
}
ATF_TC_BODY(svm_l2_reserved_cr_ud, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x82,
	};
	/* MOV CR1,EAX; OUT 0x81,AL.  CR1 is reserved by AMD's APM. */
	static const uint8_t l2_program[] = {
		0x0f, 0x22, 0xc8,
		0xe6, 0x81,
	};
	/* Skip the three-byte faulting instruction, then report the #UD. */
	static const uint8_t l2_handler[] = {
		0x58,
		0x05, 0x03, 0x00,
		0x50,
		0xb0, 0x6a,
		0xe6, 0x80,
		0xcf,
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *ivt, *l2_code, *vmcb;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	ivt = vm_map_gpa(live.ctx, 0, PAGE_SIZE);
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	ATF_REQUIRE(ivt != NULL && l2_code != NULL && vmcb != NULL);
	memcpy(l2_code, l2_program, sizeof(l2_program));
	memcpy(l2_code + 0x100, l2_handler, sizeof(l2_handler));
	le16enc(ivt + 6 * 4, SVM_L2_CODE_GPA + 0x100);
	le16enc(ivt + 6 * 4 + 2, 0);
	svm_vmcb12_real_init(vmcb);
	le32enc(vmcb + VMCB_OFF_STATE(0x80) + 4, 0x3ff);
	le64enc(vmcb + VMCB_OFF_STATE(0x1d8), 0x7000);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
	ATF_CHECK_EQ(vmexit.u.inout.eax & UINT8_MAX, 0x6a);
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXIT_REASON), 0);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_reserved_cr_ud, tc)
{

	cleanup_vm(tc);
}

static void
svm_l2_npt12_case(const atf_tc_t *tc, int deny)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x81,
	};
	static const uint8_t l2_program[] = {
		0xb0, 0x7b,
		0xe6, 0x80,
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *vmcb, *l2_code, *npt;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	npt = vm_map_gpa(live.ctx, SVM_NPT12_ROOT_GPA, 4 * PAGE_SIZE);
	ATF_REQUIRE(l2_code != NULL && vmcb != NULL && npt != NULL);
	memcpy(l2_code, l2_program, sizeof(l2_program));
	svm_vmcb12_real_init(vmcb);
	memset(npt, 0, 4 * PAGE_SIZE);
	le64enc(npt, SVM_NPT12_PDPT_GPA | 7);
	le64enc(npt + PAGE_SIZE, SVM_NPT12_PD_GPA | 7);
	le64enc(npt + 2 * PAGE_SIZE, SVM_NPT12_PT_GPA | 7);
	if (!deny)
		le64enc(npt + 3 * PAGE_SIZE + 2 * sizeof(uint64_t),
		    SVM_L2_CODE_GPA | 7);
	vmcb[VMCB_OFF_NP_ENABLE] = 1;
	le64enc(vmcb + VMCB_OFF_NPT_BASE, SVM_NPT12_ROOT_GPA);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	if (deny) {
		ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
		ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXIT_REASON),
		    VMCB_EXIT_NPF);
		ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXITINFO2),
		    SVM_L2_CODE_GPA);
		ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_STATE(0x178)),
		    SVM_L2_CODE_GPA);
	} else {
		ATF_CHECK_EQ(vmexit.rip, SVM_L2_CODE_GPA + 2);
		ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
		ATF_CHECK_EQ(vmexit.u.inout.eax & UINT8_MAX, 0x7b);
		ATF_CHECK((le64dec(npt) & (1ULL << 5)) != 0);
		ATF_CHECK((le64dec(npt + 3 * PAGE_SIZE +
		    2 * sizeof(uint64_t)) & (1ULL << 5)) != 0);
	}
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_WITH_CLEANUP(svm_l2_portio_npt12);
ATF_TC_HEAD(svm_l2_portio_npt12, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Walk L1 NPT12, compose NPT02, then execute AMD L2 port I/O");
}
ATF_TC_BODY(svm_l2_portio_npt12, tc)
{

	svm_l2_npt12_case(tc, 0);
}
ATF_TC_CLEANUP(svm_l2_portio_npt12, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_npt12_readonly_alias);
ATF_TC_HEAD(svm_l2_npt12_readonly_alias, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "AMD L2 reads and executes an L0 read-only ROM alias but cannot write it");
}
ATF_TC_BODY(svm_l2_npt12_readonly_alias, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x81,
	};
	static const uint8_t l2_program[] = {
		0xa0, 0x00, 0x30,       /* mov al, [0x3000] */
		0xe6, 0x80,             /* out 0x80, al */
		0xc6, 0x06, 0x00, 0x30, 0x11, /* mov byte [0x3000], 0x11 */
		0xe6, 0x81,
	};
	static const uint8_t remapped_program[] = {
		0xb0, 0x5a,             /* mov al, 0x5a */
		0x90,                   /* nop; retain the old OUT offset */
		0xe6, 0x80,             /* out 0x80, al */
	};
	struct live_vm live;
	struct vm_exit vmexit;
	struct vm_run vmrun;
	cpuset_t cpuset;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *rom, *remapped_rom, *vmcb, *npt;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	rom = vm_create_devmem(live.ctx, VM_BOOTROM, "nested-rom", PAGE_SIZE);
	ATF_REQUIRE_MSG(rom != MAP_FAILED, "create ROM segment: %s",
	    strerror(errno));
	memcpy(rom, l2_program, sizeof(l2_program));
	ATF_REQUIRE_EQ_MSG(vm_mmap_memseg(live.ctx, SVM_READONLY_ROM_GPA,
	    VM_BOOTROM, 0, PAGE_SIZE, PROT_READ | PROT_EXEC), 0,
	    "map read-only ROM: %s", strerror(errno));
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	npt = vm_map_gpa(live.ctx, SVM_NPT12_ROOT_GPA, 4 * PAGE_SIZE);
	ATF_REQUIRE(vmcb != NULL && npt != NULL);
	svm_vmcb12_real_init(vmcb);
	memset(npt, 0, 4 * PAGE_SIZE);
	le64enc(npt, SVM_NPT12_PDPT_GPA | 7);
	le64enc(npt + PAGE_SIZE, SVM_NPT12_PD_GPA | 7);
	le64enc(npt + 2 * PAGE_SIZE, SVM_NPT12_PT_GPA | 7);
	/* L1 permits writes; the L0 ROM mapping must still deny them. */
	le64enc(npt + 3 * PAGE_SIZE + 2 * sizeof(uint64_t),
	    SVM_READONLY_ROM_GPA | 7);
	le64enc(npt + 3 * PAGE_SIZE + 3 * sizeof(uint64_t),
	    SVM_READONLY_ROM_GPA | 7);
	vmcb[VMCB_OFF_NP_ENABLE] = 1;
	le64enc(vmcb + VMCB_OFF_NPT_BASE, SVM_NPT12_ROOT_GPA);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
	ATF_CHECK_EQ(vmexit.u.inout.eax & UINT8_MAX, l2_program[0]);
	ATF_CHECK_EQ(memcmp(rom, l2_program, sizeof(l2_program)), 0);
	memset(&vmexit, 0, sizeof(vmexit));
	memset(&vmrun, 0, sizeof(vmrun));
	CPU_ZERO(&cpuset);
	vmrun.vm_exit = &vmexit;
	vmrun.cpuset = &cpuset;
	vmrun.cpusetsize = sizeof(cpuset);
	errno = 0;
	ATF_REQUIRE_EQ(vm_run(live.vcpu, &vmrun), -1);
	ATF_CHECK_EQ(errno, EFAULT);
	ATF_CHECK_EQ(memcmp(rom, l2_program, sizeof(l2_program)), 0);
	/* The denial must leave L2 recoverable after L0 skips the write. */
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_RIP,
	    SVM_L2_CODE_GPA + sizeof(l2_program) - 2), 0);
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
	ATF_CHECK_EQ(memcmp(rom, l2_program, sizeof(l2_program)), 0);
	/* A frozen L2 must not keep an alias to the now-unmapped L0 object. */
	ATF_REQUIRE_EQ_MSG(vm_munmap_memseg(live.ctx,
	    SVM_READONLY_ROM_GPA, PAGE_SIZE), 0, "unmap ROM: %s",
	    strerror(errno));
	remapped_rom = vm_create_devmem(live.ctx, VM_PCIROM,
	    "nested-remapped-rom", PAGE_SIZE);
	ATF_REQUIRE_MSG(remapped_rom != MAP_FAILED,
	    "create replacement ROM: %s", strerror(errno));
	memcpy(remapped_rom, remapped_program, sizeof(remapped_program));
	ATF_REQUIRE_EQ_MSG(vm_mmap_memseg(live.ctx,
	    SVM_READONLY_ROM_GPA, VM_PCIROM, 0, PAGE_SIZE,
	    PROT_READ | PROT_EXEC), 0, "remap ROM: %s", strerror(errno));
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_RIP,
	    SVM_L2_CODE_GPA), 0);
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
	ATF_CHECK_EQ(vmexit.u.inout.eax & UINT8_MAX, 0x5a);
	ATF_CHECK_EQ(memcmp(rom, l2_program, sizeof(l2_program)), 0);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_npt12_readonly_alias, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_npt12_fault);
ATF_TC_HEAD(svm_l2_npt12_fault, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Reflect an L1 NPT12 execute denial from AMD L2 to VMCB12");
}
ATF_TC_BODY(svm_l2_npt12_fault, tc)
{

	svm_l2_npt12_case(tc, 1);
}
ATF_TC_CLEANUP(svm_l2_npt12_fault, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_portio_reflected);
ATF_TC_HEAD(svm_l2_portio_reflected, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Reflect an AMD L2 port intercept to L1's VMCB12");
}
ATF_TC_BODY(svm_l2_portio_reflected, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x81,
	};
	static const uint8_t l2_program[] = {
		0xb0, 0x7b,
		0xe6, 0x80,
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *vmcb, *l2_code, *iopm;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM,
	    1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	iopm = vm_map_gpa(live.ctx, SVM_IOPM_GPA, PAGE_SIZE);
	ATF_REQUIRE(l2_code != NULL && vmcb != NULL && iopm != NULL);
	memcpy(l2_code, l2_program, sizeof(l2_program));
	svm_vmcb12_real_init(vmcb);
	/* G_PAT is ignored by VMRUN when L1 leaves NPT disabled. */
	le64enc(vmcb + VMCB_OFF_GUEST_PAT, 0x0007040600070402ULL);
	/* IOPM bits 11:0 are ignored by VMRUN and retained for L1. */
	le64enc(vmcb + VMCB_OFF_IO_PERM, SVM_IOPM_GPA | 0x5a5);
	le32enc(vmcb + VMCB_OFF_INST1_INTERCEPT, VMCB_INTCPT_IO);
	iopm[0x80 / 8] |= 1U << (0x80 % 8);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.rip, GUEST_CODE_GPA + sizeof(l1_program) - 2);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXIT_REASON), VMCB_EXIT_IO);
	ATF_CHECK_EQ((le64dec(vmcb + VMCB_OFF_EXITINFO1) >> 16) &
	    UINT16_MAX,
	    0x80);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_GUEST_PAT),
	    0x0007040600070402ULL);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_IO_PERM),
	    SVM_IOPM_GPA | 0x5a5);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_STATE(0x178)),
	    SVM_L2_CODE_GPA + 2);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_portio_reflected, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_cr8_unmasked);
ATF_TC_HEAD(svm_l2_cr8_unmasked, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Unmasked AMD L2 CR8 updates L1 APIC TPR and L2 V_TPR");
}
ATF_TC_BODY(svm_l2_cr8_unmasked, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x81,
	};
	static const uint8_t l2_program[] = {
		0xb8, 0x05, 0x00, 0x00, 0x00, /* mov eax, 5 */
		0xf0, 0x0f, 0x22, 0xc0,       /* alternate mov cr8, eax */
		0x31, 0xc0,                   /* xor eax, eax */
		0xf0, 0x0f, 0x20, 0xc0,       /* alternate mov eax, cr8 */
		0xe6, 0x80,                   /* L1-intercepted out */
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint64_t tpr;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *vmcb, *l2_code, *iopm;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	iopm = vm_map_gpa(live.ctx, SVM_IOPM_GPA, PAGE_SIZE);
	ATF_REQUIRE(l2_code != NULL && vmcb != NULL && iopm != NULL);
	memcpy(l2_code, l2_program, sizeof(l2_program));
	svm_vmcb12_real_init(vmcb);
	/* Use 32-bit protected code for the alternate CR8 encoding. */
	le64enc(vmcb + VMCB_OFF_STATE(0x158), CR0_PE | 0x10);
	svm_vmcb12_real_segment(vmcb, VMCB_OFF_STATE(0x10), 0x49b);
	le32enc(vmcb + VMCB_OFF_INST1_INTERCEPT, VMCB_INTCPT_IO);
	iopm[0x80 / 8] |= 1U << (0x80 % 8);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXIT_REASON), VMCB_EXIT_IO);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_STATE(0x170)), 5);
	ATF_CHECK_EQ(vmcb[VMCB_OFF_VIRQ], 5);
	ATF_REQUIRE_EQ(vm_get_register(live.vcpu, VM_REG_GUEST_TPR, &tpr), 0);
	ATF_CHECK_EQ(tpr, 5);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_cr8_unmasked, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_stringio_reflected);
ATF_TC_HEAD(svm_l2_stringio_reflected, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Reflect an AMD L2 string port intercept to L1 without L0 emulation");
}
ATF_TC_BODY(svm_l2_stringio_reflected, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x66, 0xbe, 0x00, 0x20, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x81,
	};
	static const uint8_t l2_program[] = {
		0xba, 0x80, 0x00, /* mov dx, 0x80 */
		0x6c,             /* insb */
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *vmcb, *l2_code, *iopm;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	iopm = vm_map_gpa(live.ctx, SVM_IOPM_GPA, PAGE_SIZE);
	ATF_REQUIRE(l2_code != NULL && vmcb != NULL && iopm != NULL);
	memcpy(l2_code, l2_program, sizeof(l2_program));
	svm_vmcb12_real_init(vmcb);
	le32enc(vmcb + VMCB_OFF_INST1_INTERCEPT, VMCB_INTCPT_IO);
	iopm[0x80 / 8] |= 1U << (0x80 % 8);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXIT_REASON), VMCB_EXIT_IO);
	ATF_CHECK((le64dec(vmcb + VMCB_OFF_EXITINFO1) & (1ULL << 2)) != 0);
	ATF_CHECK_EQ((le64dec(vmcb + VMCB_OFF_EXITINFO1) >> 16) &
	    UINT16_MAX, 0x80);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_STATE(0x178)),
	    SVM_L2_CODE_GPA + 3);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_stringio_reflected, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_stringio_unintercepted);
ATF_TC_HEAD(svm_l2_stringio_unintercepted, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Route an unintercepted AMD L2 string port exit to L0 without NPT12");
}
ATF_TC_BODY(svm_l2_stringio_unintercepted, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x82,
	};
	static const uint8_t l2_program[] = {
		0xbe, 0x00, 0x21, /* mov si, 0x2100 */
		0xba, 0x80, 0x00, /* mov dx, 0x80 */
		0x6e,             /* outsb */
		0xe6, 0x81,       /* out 0x81, al */
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint64_t rip;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *vmcb, *l2_code;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	ATF_REQUIRE(l2_code != NULL && vmcb != NULL);
	memcpy(l2_code, l2_program, sizeof(l2_program));
	l2_code[0x100] = 0x5a;
	svm_vmcb12_real_init(vmcb);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT_STR);
	ATF_CHECK_EQ(vmexit.rip, SVM_L2_CODE_GPA + 6);
	ATF_CHECK_EQ(vmexit.inst_length, 1);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
	ATF_CHECK_EQ(vmexit.u.inout_str.index, SVM_L2_CODE_GPA + 0x100);
	ATF_CHECK_EQ(vmexit.u.inout_str.count, 1);
	ATF_CHECK_EQ(l2_code[0x100], 0x5a);
	ATF_REQUIRE_EQ(vm_get_register(live.vcpu, VM_REG_GUEST_RIP,
	    &rip), 0);
	ATF_CHECK_EQ(rip, SVM_L2_CODE_GPA + 6);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_RSI,
	    SVM_L2_CODE_GPA + 0x101), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_RIP,
	    vmexit.rip + vmexit.inst_length), 0);
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_stringio_unintercepted, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_npt12_device_access);
ATF_TC_HEAD(svm_l2_npt12_device_access, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Translate AMD L2 code, string data, and LAPIC MMIO through NPT12");
}
ATF_TC_BODY(svm_l2_npt12_device_access, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x82,
	};
	static const uint8_t l2_program[] = {
		0xbe, 0x00, 0x30,             /* mov si, 0x3000 */
		0xba, 0x80, 0x00,             /* mov dx, 0x80 */
		0x6e,                         /* outsb */
		0x67, 0x66, 0xa1, 0x30, 0x00, 0xe0, 0xfe,
		/* mov eax, [0xfee00030] */
		0xe6, 0x81,
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint64_t gpa;
	uint8_t *vmcb, *l1_code, *l1_data, *npt, *apic_pd;
	int fault;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	l1_code = vm_map_gpa(live.ctx, 0x6000, PAGE_SIZE);
	l1_data = vm_map_gpa(live.ctx, 0x7000, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	npt = vm_map_gpa(live.ctx, SVM_NPT12_ROOT_GPA, 4 * PAGE_SIZE);
	apic_pd = vm_map_gpa(live.ctx, SVM_NPT12_APIC_PD_GPA, PAGE_SIZE);
	ATF_REQUIRE(l1_code != NULL && l1_data != NULL && vmcb != NULL &&
	    npt != NULL && apic_pd != NULL);
	memcpy(l1_code, l2_program, sizeof(l2_program));
	l1_data[0] = 0x5a;
	svm_vmcb12_real_init(vmcb);
	le32enc(vmcb + VMCB_OFF_STATE(0x30) + 4, UINT32_MAX);
	memset(npt, 0, 4 * PAGE_SIZE);
	memset(apic_pd, 0, PAGE_SIZE);
	le64enc(npt, SVM_NPT12_PDPT_GPA | 7);
	le64enc(npt + PAGE_SIZE, SVM_NPT12_PD_GPA | 7);
	le64enc(npt + PAGE_SIZE + 3 * sizeof(uint64_t),
	    SVM_NPT12_APIC_PD_GPA | 7);
	le64enc(npt + 2 * PAGE_SIZE, SVM_NPT12_PT_GPA | 7);
	le64enc(npt + 3 * PAGE_SIZE + 2 * sizeof(uint64_t), 0x6000 | 7);
	le64enc(npt + 3 * PAGE_SIZE + 3 * sizeof(uint64_t), 0x7000 | 7);
	le64enc(apic_pd + ((0xfee00000U >> 21) & 0x1ff) *
	    sizeof(uint64_t), 0xfee00000U | 0x87);
	vmcb[VMCB_OFF_NP_ENABLE] = 1;
	le64enc(vmcb + VMCB_OFF_NPT_BASE, SVM_NPT12_ROOT_GPA);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT_STR);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
	ATF_CHECK_EQ(vmexit.u.inout_str.index, 0x3000);
	ATF_REQUIRE_EQ(vm_gla2gpa(live.vcpu,
	    &vmexit.u.inout_str.paging, 0x3000, PROT_WRITE,
	    &gpa, &fault), 0);
	ATF_CHECK_EQ(fault, 0);
	ATF_CHECK_EQ(gpa, 0x7000);
	ATF_CHECK_EQ(l1_data[0], 0x5a);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_RSI,
	    0x3001), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_RIP,
	    vmexit.rip + vmexit.inst_length), 0);
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
	ATF_CHECK_EQ(vmexit.u.inout.eax & UINT8_MAX, 0x14);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_npt12_device_access, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_npt12_string_fault);
ATF_TC_HEAD(svm_l2_npt12_string_fault, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Reflect an AMD L2 string operand NPT12 denial to L1");
}
ATF_TC_BODY(svm_l2_npt12_string_fault, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x82,
	};
	static const uint8_t l2_program[] = {
		0xbe, 0x00, 0x30, /* mov si, 0x3000 */
		0xba, 0x80, 0x00, /* mov dx, 0x80 */
		0x6e,             /* outsb */
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint64_t gpa;
	uint8_t *vmcb, *l1_code, *npt;
	int fault;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	l1_code = vm_map_gpa(live.ctx, 0x6000, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	npt = vm_map_gpa(live.ctx, SVM_NPT12_ROOT_GPA, 4 * PAGE_SIZE);
	ATF_REQUIRE(l1_code != NULL && vmcb != NULL && npt != NULL);
	memcpy(l1_code, l2_program, sizeof(l2_program));
	svm_vmcb12_real_init(vmcb);
	memset(npt, 0, 4 * PAGE_SIZE);
	le64enc(npt, SVM_NPT12_PDPT_GPA | 7);
	le64enc(npt + PAGE_SIZE, SVM_NPT12_PD_GPA | 7);
	le64enc(npt + 2 * PAGE_SIZE, SVM_NPT12_PT_GPA | 7);
	le64enc(npt + 3 * PAGE_SIZE + 2 * sizeof(uint64_t), 0x6000 | 7);
	vmcb[VMCB_OFF_NP_ENABLE] = 1;
	le64enc(vmcb + VMCB_OFF_NPT_BASE, SVM_NPT12_ROOT_GPA);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT_STR);
	ATF_CHECK_EQ(vmexit.rip, SVM_L2_CODE_GPA + 6);
	errno = 0;
	ATF_REQUIRE_EQ(vm_gla2gpa_nofault(live.vcpu,
	    &vmexit.u.inout_str.paging, 0x3000, PROT_WRITE,
	    &gpa, &fault), -1);
	ATF_CHECK_EQ(errno, EFAULT);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXIT_REASON), 0);
	ATF_REQUIRE_EQ(vm_gla2gpa(live.vcpu,
	    &vmexit.u.inout_str.paging, 0x3000, PROT_READ,
	    &gpa, &fault), 0);
	ATF_CHECK_EQ(fault, VM_GLA2GPA_NESTED_EXIT);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXIT_REASON), VMCB_EXIT_NPF);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXITINFO2), 0x3000);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXITINFO1) &
	    (VMCB_NPF_INFO1_GPA | VMCB_NPF_INFO1_GPT |
	    VMCB_NPF_INFO1_U | VMCB_NPF_INFO1_W),
	    VMCB_NPF_INFO1_GPA | VMCB_NPF_INFO1_W);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_STATE(0x178)),
	    SVM_L2_CODE_GPA + 6);
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x82);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_npt12_string_fault, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_msr_gp_reflected);
ATF_TC_HEAD(svm_l2_msr_gp_reflected, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Reflect an L0-injected AMD L2 MSR #GP to L1");
}
ATF_TC_BODY(svm_l2_msr_gp_reflected, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x81,
	};
	static const uint8_t l2_program[] = {
		0x66, 0xb9, 0xef, 0xbe, 0xad, 0xde, /* mov ecx, 0xdeadbeef */
		0x0f, 0x32,                         /* rdmsr: #GP */
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *vmcb, *l2_code;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	ATF_REQUIRE(l2_code != NULL && vmcb != NULL);
	memcpy(l2_code, l2_program, sizeof(l2_program));
	svm_vmcb12_real_init(vmcb);
	le32enc(vmcb + VMCB_OFF_EXC_INTERCEPT, 1U << 13);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXIT_REASON), 0x40 + 13);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_STATE(0x178)),
	    SVM_L2_CODE_GPA + 6);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_msr_gp_reflected, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_apicbase_msr);
ATF_TC_HEAD(svm_l2_apicbase_msr, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Read and rewrite the shared AMD L2 APIC_BASE MSR");
}
ATF_TC_BODY(svm_l2_apicbase_msr, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x82,
	};
	static const uint8_t l2_program[] = {
		0x66, 0xb9, 0x1b, 0x00, 0x00, 0x00, /* mov ecx, MSR_APICBASE */
		0x0f, 0x32,                         /* rdmsr */
		0xe6, 0x80,                         /* out 0x80, al */
		0x0f, 0x30,                         /* wrmsr, same value */
		0xe6, 0x81,                         /* out 0x81, al */
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *vmcb, *l2_code;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	ATF_REQUIRE(l2_code != NULL && vmcb != NULL);
	memcpy(l2_code, l2_program, sizeof(l2_program));
	svm_vmcb12_real_init(vmcb);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
	ATF_CHECK_EQ(vmexit.u.inout.eax,
	    0xfee00000U | APICBASE_ENABLED | APICBASE_BSP);
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
	ATF_CHECK_EQ(vmexit.u.inout.eax,
	    0xfee00000U | APICBASE_ENABLED | APICBASE_BSP);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_apicbase_msr, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_apic_mmio);
ATF_TC_HEAD(svm_l2_apic_mmio, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Emulate an AMD L2 LAPIC read without NPT12");
}
ATF_TC_BODY(svm_l2_apic_mmio, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x82,
	};
	static const uint8_t l2_program[] = {
		0x67, 0x66, 0xa1, 0x30, 0x00, 0xe0, 0xfe,
		/* mov eax, [0xfee00030], LAPIC version */
		0xe6, 0x80,
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *vmcb, *l2_code;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	ATF_REQUIRE(l2_code != NULL && vmcb != NULL);
	memcpy(l2_code, l2_program, sizeof(l2_program));
	svm_vmcb12_real_init(vmcb);
	/* Unreal-mode DS allows the 32-bit moffs to reach LAPIC MMIO. */
	le32enc(vmcb + VMCB_OFF_STATE(0x30) + 4, UINT32_MAX);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
	ATF_CHECK_EQ(vmexit.u.inout.eax & UINT8_MAX, 0x14);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_apic_mmio, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_lstar_noncanonical);
ATF_TC_HEAD(svm_l2_lstar_noncanonical, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Reject a noncanonical AMD L2 LSTAR write with #GP");
}
ATF_TC_BODY(svm_l2_lstar_noncanonical, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x81,
	};
	static const uint8_t l2_program[] = {
		0x66, 0xb9, 0x82, 0x00, 0x00, 0xc0, /* mov ecx, MSR_LSTAR */
		0x66, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov eax, 0 */
		0x66, 0xba, 0x00, 0x80, 0x00, 0x00, /* mov edx, 0x8000 */
		0x0f, 0x30,                         /* wrmsr: #GP */
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *vmcb, *l2_code;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM, 1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	ATF_REQUIRE(l2_code != NULL && vmcb != NULL);
	memcpy(l2_code, l2_program, sizeof(l2_program));
	svm_vmcb12_real_init(vmcb);
	le32enc(vmcb + VMCB_OFF_EXC_INTERCEPT, 1U << 13);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_EXIT_REASON), 0x40 + 13);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_STATE(0x178)),
	    SVM_L2_CODE_GPA + 18);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_LSTAR), 0);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_lstar_noncanonical, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l1_gif);
ATF_TC_HEAD(svm_l1_gif, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "descr",
	    "Execute virtual CLGI and STGI in an AMD L1 guest");
}
ATF_TC_BODY(svm_l1_gif, tc)
{
	static const uint8_t program[] = {
		0x0f, 0x01, 0xdd, /* clgi */
		0xb0, 0x66,       /* mov al, 0x66 */
		0xe6, 0x80,       /* out 0x80, al */
		0x0f, 0x01, 0xdc, /* stgi */
		0xb0, 0x77,       /* mov al, 0x77 */
		0xe6, 0x81,       /* out 0x81, al */
	};
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM,
	    1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, program, sizeof(program));
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.rip, GUEST_CODE_GPA + 5);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
	ATF_CHECK_EQ(vmexit.u.inout.eax & UINT8_MAX, 0x66);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_RIP,
	    vmexit.rip + vmexit.inst_length), 0);
	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.rip, GUEST_CODE_GPA + 12);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
	ATF_CHECK_EQ(vmexit.u.inout.eax & UINT8_MAX, 0x77);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l1_gif, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(svm_l2_checkpoint);
ATF_TC_HEAD(svm_l2_checkpoint, tc)
{

	require_live_vmm(tc);
	atf_tc_set_md_var(tc, "timeout", "30");
	atf_tc_set_md_var(tc, "descr",
	    "Restore an active AMD L2 and return to L1 with its RAX intact");
}
ATF_TC_BODY(svm_l2_checkpoint, tc)
{
	static const uint8_t l1_program[] = {
		0x66, 0xb9, 0x17, 0x01, 0x01, 0xc0,
		0x66, 0xb8, 0x00, 0xa0, 0x00, 0x00,
		0x66, 0x31, 0xd2,
		0x0f, 0x30,
		0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,
		0x0f, 0x01, 0xdd,
		0x0f, 0x01, 0xd8,
		0xe6, 0x81,
	};
	static const uint8_t l2_program[] = {
		0xb0, 0x7b, 0xe6, 0x80,
		0xb0, 0x4c, 0xe6, 0x82,
	};
	struct vm_snapshot_session session;
	struct live_vm live;
	struct vm_exit vmexit;
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint8_t *buffer, *vmcb, *l2_code, *iopm;
	uint64_t rax, rbx, saved_cr3, saved_dr6, saved_efer;
	size_t cr3_offset, dr6_offset, efer_offset, length, vnmi_offset;

	live = create_nested_live_vm(tc);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, &eax, &ebx,
	    &ecx, &edx), 0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_NESTED_SVM,
	    1), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_EFER,
	    EFER_SVM), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_CR0,
	    CR0_PE | 0x10), 0);
	ATF_REQUIRE_EQ(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x009b), 0);
	memcpy(live.code, l1_program, sizeof(l1_program));
	l2_code = vm_map_gpa(live.ctx, SVM_L2_CODE_GPA, PAGE_SIZE);
	vmcb = vm_map_gpa(live.ctx, SVM_VMCB12_GPA, PAGE_SIZE);
	iopm = vm_map_gpa(live.ctx, SVM_IOPM_GPA, PAGE_SIZE);
	ATF_REQUIRE(l2_code != NULL && vmcb != NULL && iopm != NULL);
	memcpy(l2_code, l2_program, sizeof(l2_program));
	svm_vmcb12_real_init(vmcb);
	le32enc(vmcb + VMCB_OFF_INST1_INTERCEPT, VMCB_INTCPT_IO);
	iopm[0x82 / 8] |= 1U << (0x82 % 8);
	/* The ignored VMCB12 PAT must survive active-L2 checkpoint/exit. */
	le64enc(vmcb + VMCB_OFF_GUEST_PAT, 0x0007040600070402ULL);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x80);
	ATF_CHECK_EQ(vmexit.rip, SVM_L2_CODE_GPA + 2);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_RBX,
	    0x12345678), 0);

	session = (struct vm_snapshot_session) {
		.version = VM_SNAPSHOT_SESSION_VERSION,
		.op = VM_SNAPSHOT_SESSION_BEGIN,
	};
	if (vm_snapshot_session(live.ctx, &session) == -1 &&
	    errno == ENOTTY)
		atf_tc_skip("vmm kernel lacks BHYVE_SNAPSHOT support");
	ATF_REQUIRE(session.session_id != 0);
	buffer = malloc(1024 * 1024);
	ATF_REQUIRE(buffer != NULL);
	/* An unsaved L0 interrupt mask must not be inherited at restore. */
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_MASK_HWINTR,
	    1), 0);
	{
		struct vm_snapshot_meta save = {
			.dev_req = STRUCT_VMCX,
			.buffer = {
				.buf_start = buffer,
				.buf_size = 1024 * 1024,
				.buf = buffer,
				.buf_rem = 1024 * 1024,
			},
			.op = VM_SNAPSHOT_SAVE,
		};
		errno = 0;
		ATF_REQUIRE_EQ(vm_snapshot_req(live.ctx, &save), -1);
		ATF_CHECK_EQ(errno, EBUSY);
	}
	session.op = VM_SNAPSHOT_SESSION_ABORT;
	ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
	ATF_REQUIRE_EQ(vm_set_capability(live.vcpu, VM_CAP_MASK_HWINTR,
	    0), 0);
	session = (struct vm_snapshot_session) {
		.version = VM_SNAPSHOT_SESSION_VERSION,
		.op = VM_SNAPSHOT_SESSION_BEGIN,
	};
	ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
	{
		struct vm_snapshot_meta save = {
			.dev_req = STRUCT_VMCX,
			.buffer = {
				.buf_start = buffer,
				.buf_size = 1024 * 1024,
				.buf = buffer,
				.buf_rem = 1024 * 1024,
			},
			.op = VM_SNAPSHOT_SAVE,
		};
		ATF_REQUIRE_EQ_MSG(vm_snapshot_req(live.ctx, &save), 0,
		    "save active L2: %s", strerror(errno));
		length = save.buffer.buf_size - save.buffer.buf_rem;
	}
	ATF_REQUIRE(length > 0);
	session.op = VM_SNAPSHOT_SESSION_COMMIT;
	ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_RAX,
	    0x99), 0);
	ATF_REQUIRE_EQ(vm_set_register(live.vcpu, VM_REG_GUEST_RBX,
	    0x87654321), 0);
	ATF_REQUIRE(length > 12 + 48);
	ATF_REQUIRE_EQ(memcmp(buffer, "WASPSVM1", 8), 0);
	ATF_CHECK_EQ(le32dec(buffer + 8), 2);
	vnmi_offset = 12 + 48 + PAGE_SIZE;
	ATF_REQUIRE(length >= vnmi_offset + 16 * sizeof(uint64_t));
	/* Reserved nested-header bytes must fail without publishing L2 state. */
	buffer[12 + 4] = 1;
	session = (struct vm_snapshot_session) {
		.version = VM_SNAPSHOT_SESSION_VERSION,
		.op = VM_SNAPSHOT_SESSION_BEGIN,
	};
	ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
	{
		struct vm_snapshot_meta restore = {
			.dev_req = STRUCT_VMCX,
			.buffer = {
				.buf_start = buffer,
				.buf_size = length,
				.buf = buffer,
				.buf_rem = length,
			},
			.op = VM_SNAPSHOT_RESTORE,
		};
		errno = 0;
		ATF_REQUIRE_EQ(vm_snapshot_req(live.ctx, &restore), -1);
		ATF_CHECK_EQ(errno, EPROTO);
	}
	session.op = VM_SNAPSHOT_SESSION_ABORT;
	ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
	ATF_REQUIRE_EQ(vm_get_register(live.vcpu, VM_REG_GUEST_RAX,
	    &rax), 0);
	ATF_CHECK_EQ(rax, 0x99);
	ATF_REQUIRE_EQ(vm_get_register(live.vcpu, VM_REG_GUEST_RBX,
	    &rbx), 0);
	ATF_CHECK_EQ(rbx, 0x87654321);
	buffer[12 + 4] = 0;
	/* A misaligned virtual-NMI VMCB GPA must not publish staged state. */
	le64enc(buffer + vnmi_offset, (1ULL << 63) | 0x123);
	session = (struct vm_snapshot_session) {
		.version = VM_SNAPSHOT_SESSION_VERSION,
		.op = VM_SNAPSHOT_SESSION_BEGIN,
	};
	ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
	{
		struct vm_snapshot_meta restore = {
			.dev_req = STRUCT_VMCX,
			.buffer = {
				.buf_start = buffer,
				.buf_size = length,
				.buf = buffer,
				.buf_rem = length,
			},
			.op = VM_SNAPSHOT_RESTORE,
		};
		errno = 0;
		ATF_REQUIRE_EQ(vm_snapshot_req(live.ctx, &restore), -1);
		ATF_CHECK_EQ(errno, EPROTO);
	}
	session.op = VM_SNAPSHOT_SESSION_ABORT;
	ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
	ATF_REQUIRE_EQ(vm_get_register(live.vcpu, VM_REG_GUEST_RAX,
	    &rax), 0);
	ATF_CHECK_EQ(rax, 0x99);
	le64enc(buffer + vnmi_offset, 0);
	/* The architecture EFER record must retain physical SVME. */
	efer_offset = vnmi_offset + 16 * sizeof(uint64_t) +
	    10 * sizeof(uint64_t) +
	    8 * (2 * sizeof(uint64_t) + 2 * sizeof(uint32_t));
	ATF_REQUIRE(length >= efer_offset + sizeof(uint64_t));
	saved_efer = le64dec(buffer + efer_offset);
	ATF_REQUIRE((saved_efer & EFER_SVM) != 0);
	le64enc(buffer + efer_offset, saved_efer & ~EFER_SVM);
	session = (struct vm_snapshot_session) {
		.version = VM_SNAPSHOT_SESSION_VERSION,
		.op = VM_SNAPSHOT_SESSION_BEGIN,
	};
	ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
	{
		struct vm_snapshot_meta restore = {
			.dev_req = STRUCT_VMCX,
			.buffer = {
				.buf_start = buffer,
				.buf_size = length,
				.buf = buffer,
				.buf_rem = length,
			},
			.op = VM_SNAPSHOT_RESTORE,
		};
		errno = 0;
		ATF_REQUIRE_EQ(vm_snapshot_req(live.ctx, &restore), -1);
		ATF_CHECK_EQ(errno, EPROTO);
	}
	session.op = VM_SNAPSHOT_SESSION_ABORT;
	ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
	ATF_REQUIRE_EQ(vm_get_register(live.vcpu, VM_REG_GUEST_RAX,
	    &rax), 0);
	ATF_CHECK_EQ(rax, 0x99);
	le64enc(buffer + efer_offset, saved_efer);
	/* A reserved DR6 high bit must reject the entire staged restore. */
	dr6_offset = vnmi_offset + 16 * sizeof(uint64_t) +
	    4 * sizeof(uint64_t);
	ATF_REQUIRE(length >= dr6_offset + sizeof(uint64_t));
	saved_dr6 = le64dec(buffer + dr6_offset);
	le64enc(buffer + dr6_offset, saved_dr6 | (1ULL << 32));
	session = (struct vm_snapshot_session) {
		.version = VM_SNAPSHOT_SESSION_VERSION,
		.op = VM_SNAPSHOT_SESSION_BEGIN,
	};
	ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
	{
		struct vm_snapshot_meta restore = {
			.dev_req = STRUCT_VMCX,
			.buffer = {
				.buf_start = buffer,
				.buf_size = length,
				.buf = buffer,
				.buf_rem = length,
			},
			.op = VM_SNAPSHOT_RESTORE,
		};
		errno = 0;
		ATF_REQUIRE_EQ(vm_snapshot_req(live.ctx, &restore), -1);
		ATF_CHECK_EQ(errno, EPROTO);
	}
	session.op = VM_SNAPSHOT_SESSION_ABORT;
	ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
	ATF_REQUIRE_EQ(vm_get_register(live.vcpu, VM_REG_GUEST_RAX,
	    &rax), 0);
	ATF_CHECK_EQ(rax, 0x99);
	le64enc(buffer + dr6_offset, saved_dr6);
	/* CR3 cannot exceed the 47-bit guest-physical limit exposed to L1. */
	cr3_offset = vnmi_offset + 16 * sizeof(uint64_t) +
	    2 * sizeof(uint64_t);
	ATF_REQUIRE(length >= cr3_offset + sizeof(uint64_t));
	saved_cr3 = le64dec(buffer + cr3_offset);
	le64enc(buffer + cr3_offset, saved_cr3 | (1ULL << 47));
	session = (struct vm_snapshot_session) {
		.version = VM_SNAPSHOT_SESSION_VERSION,
		.op = VM_SNAPSHOT_SESSION_BEGIN,
	};
	ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
	{
		struct vm_snapshot_meta restore = {
			.dev_req = STRUCT_VMCX,
			.buffer = {
				.buf_start = buffer,
				.buf_size = length,
				.buf = buffer,
				.buf_rem = length,
			},
			.op = VM_SNAPSHOT_RESTORE,
		};
		errno = 0;
		ATF_REQUIRE_EQ(vm_snapshot_req(live.ctx, &restore), -1);
		ATF_CHECK_EQ(errno, EPROTO);
	}
	session.op = VM_SNAPSHOT_SESSION_ABORT;
	ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
	ATF_REQUIRE_EQ(vm_get_register(live.vcpu, VM_REG_GUEST_RAX,
	    &rax), 0);
	ATF_CHECK_EQ(rax, 0x99);
	le64enc(buffer + cr3_offset, saved_cr3);

	session = (struct vm_snapshot_session) {
		.version = VM_SNAPSHOT_SESSION_VERSION,
		.op = VM_SNAPSHOT_SESSION_BEGIN,
	};
	ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
	{
		struct vm_snapshot_meta restore = {
			.dev_req = STRUCT_VMCX,
			.buffer = {
				.buf_start = buffer,
				.buf_size = length,
				.buf = buffer,
				.buf_rem = length,
			},
			.op = VM_SNAPSHOT_RESTORE,
		};
		ATF_REQUIRE_EQ_MSG(vm_snapshot_req(live.ctx, &restore), 0,
		    "restore active L2: %s", strerror(errno));
	}
	session.op = VM_SNAPSHOT_SESSION_COMMIT;
	ATF_REQUIRE_EQ(vm_snapshot_session(live.ctx, &session), 0);
	ATF_REQUIRE_EQ(vm_get_register(live.vcpu, VM_REG_GUEST_RAX,
	    &rax), 0);
	ATF_CHECK_EQ(rax & UINT8_MAX, 0x7b);
	ATF_REQUIRE_EQ(vm_get_register(live.vcpu, VM_REG_GUEST_RBX,
	    &rbx), 0);
	ATF_CHECK_EQ(rbx, 0x12345678);

	vmexit = run_once(live.vcpu);
	ATF_REQUIRE_EQ(vmexit.exitcode, VM_EXITCODE_INOUT);
	ATF_CHECK_EQ(vmexit.u.inout.port, 0x81);
	ATF_CHECK_EQ((le64dec(vmcb + VMCB_OFF_EXITINFO1) >> 16) &
	    UINT16_MAX, 0x82);
	ATF_CHECK_EQ(le64dec(vmcb + VMCB_OFF_GUEST_PAT),
	    0x0007040600070402ULL);
	ATF_REQUIRE_EQ(vm_get_register(live.vcpu, VM_REG_GUEST_RAX,
	    &rax), 0);
	ATF_CHECK_EQ(rax, SVM_VMCB12_GPA);
	ATF_REQUIRE_EQ(vm_get_register(live.vcpu, VM_REG_GUEST_RBX,
	    &rbx), 0);
	ATF_CHECK_EQ(rbx, 0x12345678);
	free(buffer);
	vm_vcpu_close(live.vcpu);
	vm_destroy(live.ctx);
}
ATF_TC_CLEANUP(svm_l2_checkpoint, tc)
{

	cleanup_vm(tc);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, real_mode_io_and_halt);
	ATF_TP_ADD_TC(tp, efer_svme_hidden);
	ATF_TP_ADD_TC(tp, breakpoint_exit);
	ATF_TP_ADD_TC(tp, pause_exit);
	ATF_TP_ADD_TC(tp, svm_nested_host_policy);
	ATF_TP_ADD_TC(tp, svm_l2_portio);
	ATF_TP_ADD_TC(tp, svm_l2_shutdown_intercepted);
	ATF_TP_ADD_TC(tp, svm_l2_shutdown_unintercepted);
	ATF_TP_ADD_TC(tp, svm_l2_breakpoint_exit);
	ATF_TP_ADD_TC(tp, svm_l2_breakpoint_l0_priority);
	ATF_TP_ADD_TC(tp, svm_l2_pending_irq_reflected);
	ATF_TP_ADD_TC(tp, svm_l2_pending_nmi_reflected);
	ATF_TP_ADD_TC(tp, svm_l2_l0_irq);
	ATF_TP_ADD_TC(tp, svm_l2_l0_nmi);
	ATF_TP_ADD_TC(tp, svm_l2_l1_eventinj_nmi);
	ATF_TP_ADD_TC(tp, svm_l2_l0_exception);
	ATF_TP_ADD_TC(tp, svm_l2_reserved_cr_ud);
	ATF_TP_ADD_TC(tp, svm_l2_virtual_irq);
	ATF_TP_ADD_TC(tp, svm_l2_portio_npt12);
	ATF_TP_ADD_TC(tp, svm_l2_npt12_readonly_alias);
	ATF_TP_ADD_TC(tp, svm_l2_npt12_fault);
	ATF_TP_ADD_TC(tp, svm_l2_portio_reflected);
	ATF_TP_ADD_TC(tp, svm_l2_cr8_unmasked);
	ATF_TP_ADD_TC(tp, svm_l2_stringio_reflected);
	ATF_TP_ADD_TC(tp, svm_l2_stringio_unintercepted);
	ATF_TP_ADD_TC(tp, svm_l2_npt12_device_access);
	ATF_TP_ADD_TC(tp, svm_l2_npt12_string_fault);
	ATF_TP_ADD_TC(tp, svm_l2_msr_gp_reflected);
	ATF_TP_ADD_TC(tp, svm_l2_apicbase_msr);
	ATF_TP_ADD_TC(tp, svm_l2_apic_mmio);
	ATF_TP_ADD_TC(tp, svm_l2_lstar_noncanonical);
	ATF_TP_ADD_TC(tp, svm_l1_gif);
	ATF_TP_ADD_TC(tp, svm_l2_checkpoint);
	return (atf_no_error());
}
