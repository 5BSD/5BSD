/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <machine/vmm.h>

#include <vmmapi.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define	GUEST_MEMORY_SIZE	(2 * 1024 * 1024)
#define	GUEST_CODE_GPA		0x1000

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

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, real_mode_io_and_halt);
	ATF_TP_ADD_TC(tp, breakpoint_exit);
	ATF_TP_ADD_TC(tp, pause_exit);
	return (atf_no_error());
}
