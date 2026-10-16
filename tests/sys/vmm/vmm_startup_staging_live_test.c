/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/mman.h>

#include <dev/vmm/vmm_startup_request.h>
#include <dev/vmm/vmm_startup_run_request.h>

#include <vmm.h>
#include <vmmapi.h>

#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define STARTUP_TEST_MEMORY_SIZE (2 * 1024 * 1024)
#define STARTUP_TEST_BSP_GPA 0x1000
#define STARTUP_TEST_AP_GPA 0x2000

struct startup_run_worker {
	struct vcpu *vcpu;
	uint64_t generation;
	struct vm_exit vmexit;
	int result;
	int error;
};

static void *
startup_run_once(void *arg)
{
	struct startup_run_worker *worker = arg;
	struct vmm_startup_run_request request;
	cpuset_t cpuset;

	CPU_ZERO(&cpuset);
	memset(&worker->vmexit, 0, sizeof(worker->vmexit));
	memset(&request, 0, sizeof(request));
	request.version = VMM_STARTUP_RUN_REQUEST_VERSION;
	request.size = VMM_STARTUP_RUN_REQUEST_SIZE;
	request.generation = worker->generation;
	request.cpuset_address = (uintptr_t)&cpuset;
	request.cpuset_size = sizeof(cpuset);
	request.exit_address = (uintptr_t)&worker->vmexit;
	request.exit_size = sizeof(worker->vmexit);
	worker->result = vm_run_generation(worker->vcpu, &request);
	worker->error = worker->result == 0 ? 0 : errno;
	return (NULL);
}

static void
vm_name_for(const atf_tc_t *tc, char *name, size_t size)
{

	ATF_REQUIRE(snprintf(name, size, "vst-%ld-%c", (long)getpid(),
	    atf_tc_get_ident(tc)[0]) > 0);
}

static void
cleanup_vm(const atf_tc_t *tc)
{
	struct vmctx *ctx;
	char name[VM_MAX_NAMELEN];

	vm_name_for(tc, name, sizeof(name));
	ctx = vm_open(name);
	if (ctx != NULL)
		vm_destroy(ctx);
}

ATF_TC_WITH_CLEANUP(configure_activation_boundary);
ATF_TC_HEAD(configure_activation_boundary, tc)
{

	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.arch", "amd64");
	atf_tc_set_md_var(tc, "require.kmods", "vmm");
}

ATF_TC_WITH_CLEANUP(generation_run_requires_controller);
ATF_TC_HEAD(generation_run_requires_controller, tc)
{

	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.arch", "amd64");
	atf_tc_set_md_var(tc, "require.kmods", "vmm");
}
ATF_TC_BODY(generation_run_requires_controller, tc)
{
	cpuset_t cpuset;
	struct vmm_startup_run_request request;
	struct vmm_startup_run_request request_before;
	struct vm_exit vmexit;
	struct vm_exit vmexit_before;
	struct vmctx *ctx;
	struct vcpu *vcpu;
	char name[VM_MAX_NAMELEN];

	vm_name_for(tc, name, sizeof(name));
	ATF_REQUIRE_EQ_MSG(vm_create(name), 0, "vm_create: %s",
	    strerror(errno));
	ctx = vm_open(name);
	ATF_REQUIRE_MSG(ctx != NULL, "vm_open: %s", strerror(errno));
	vcpu = vm_vcpu_open(ctx, 0);
	ATF_REQUIRE_MSG(vcpu != NULL, "vm_vcpu_open: %s", strerror(errno));
	CPU_ZERO(&cpuset);
	memset(&vmexit, 0xa5, sizeof(vmexit));
	request = (struct vmm_startup_run_request) {
		.version = VMM_STARTUP_RUN_REQUEST_VERSION,
		.size = VMM_STARTUP_RUN_REQUEST_SIZE,
		.generation = 1,
		.cpuset_address = (uintptr_t)&cpuset,
		.cpuset_size = sizeof(cpuset),
		.exit_address = (uintptr_t)&vmexit,
		.exit_size = sizeof(vmexit),
	};
	request_before = request;
	vmexit_before = vmexit;
	errno = 0;
	ATF_REQUIRE_EQ(vm_run_generation(vcpu, &request), -1);
	if (errno == EOPNOTSUPP)
		atf_tc_skip("active VMM backend does not support kernel startup");
	/* VMX is active; an unconfigured descriptor has no controller ticket. */
	ATF_REQUIRE_EQ(errno, ENOENT);
	ATF_CHECK_EQ(memcmp(&request, &request_before, sizeof(request)), 0);
	ATF_CHECK_EQ(memcmp(&vmexit, &vmexit_before, sizeof(vmexit)), 0);

	vm_vcpu_close(vcpu);
	vm_destroy(ctx);
}
ATF_TC_CLEANUP(generation_run_requires_controller, tc)
{

	cleanup_vm(tc);
}
ATF_TC_BODY(configure_activation_boundary, tc)
{
	struct vmm_startup_request request;
	struct vmctx *ctx, *other;
	uint64_t generation;
	char name[VM_MAX_NAMELEN];

	vm_name_for(tc, name, sizeof(name));
	ATF_REQUIRE_EQ_MSG(vm_create(name), 0, "vm_create: %s",
	    strerror(errno));
	ctx = vm_open(name);
	ATF_REQUIRE_MSG(ctx != NULL, "vm_open: %s", strerror(errno));
	other = vm_open(name);
	ATF_REQUIRE_MSG(other != NULL, "second vm_open: %s", strerror(errno));

	/* Validation precedes backend selection and controller allocation. */
	request = (struct vmm_startup_request) {
		.version = VMM_STARTUP_REQUEST_VERSION + 1,
		.size = VMM_STARTUP_REQUEST_SIZE,
		.operation = VMM_STARTUP_REQUEST_CONFIGURE,
		.expected_vcpus = 1,
	};
	errno = 0;
	ATF_REQUIRE_EQ(vm_startup_request(ctx, &request), -1);
	ATF_REQUIRE_EQ(errno, EINVAL);

	request = (struct vmm_startup_request) {
		.version = VMM_STARTUP_REQUEST_VERSION,
		.size = VMM_STARTUP_REQUEST_SIZE,
		.operation = VMM_STARTUP_REQUEST_CONFIGURE,
		.expected_vcpus = 1,
	};
	errno = 0;
	if (vm_startup_request(ctx, &request) != 0) {
		if (errno == EOPNOTSUPP)
			atf_tc_skip("active VMM backend does not support kernel startup");
		ATF_REQUIRE_MSG(false, "VMX startup configure: %s",
		    strerror(errno));
	}
	ATF_REQUIRE(request.generation != 0);
	ATF_REQUIRE_EQ(request.expected_vcpus, 1);
	ATF_REQUIRE_EQ(request.entered_vcpus, 0);
	ATF_REQUIRE_EQ(request.bootstrap_entered, 0);
	ATF_REQUIRE_EQ(request.phase,
	    VMM_STARTUP_REQUEST_PHASE_COLLECTING);
	ATF_REQUIRE_EQ(request.owner, VMM_STARTUP_REQUEST_OWNER_KERNEL);
	ATF_REQUIRE_EQ(request.execution,
	    VMM_STARTUP_REQUEST_EXECUTION_PRESTARTED);
	generation = request.generation;

	/* Controller authority is scoped to the configuring description. */
	request = (struct vmm_startup_request) {
		.version = VMM_STARTUP_REQUEST_VERSION,
		.size = VMM_STARTUP_REQUEST_SIZE,
		.operation = VMM_STARTUP_REQUEST_STATUS,
	};
	errno = 0;
	ATF_REQUIRE_EQ(vm_startup_request(other, &request), -1);
	ATF_REQUIRE_EQ(errno, ENOENT);
	ATF_REQUIRE_EQ_MSG(vm_startup_request(ctx, &request), 0,
	    "configured startup status: %s", strerror(errno));
	ATF_REQUIRE_EQ(request.generation, generation);
	ATF_REQUIRE_EQ(request.phase,
	    VMM_STARTUP_REQUEST_PHASE_COLLECTING);

	vm_close(other);
	vm_destroy(ctx);
}
ATF_TC_CLEANUP(configure_activation_boundary, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(amd_init_sipi_executes_ap);
ATF_TC_HEAD(amd_init_sipi_executes_ap, tc)
{

	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.arch", "amd64");
	atf_tc_set_md_var(tc, "require.kmods", "vmm");
	atf_tc_set_md_var(tc, "timeout", "20");
	atf_tc_set_md_var(tc, "descr",
	    "AMD kernel startup routes INIT/SIPI and executes the AP vector");
}
ATF_TC_BODY(amd_init_sipi_executes_ap, tc)
{
	static const uint8_t bsp_program[] = {
		0x66, 0xb8, 0x10, 0x03, 0xe0, 0xfe, /* eax = xAPIC ICR high */
		0x66, 0xba, 0x00, 0x00, 0x00, 0x01, /* edx = APIC ID 1 */
		0x66, 0x67, 0x89, 0x10,             /* mov [eax], edx */
		0x66, 0xb8, 0x00, 0x03, 0xe0, 0xfe, /* eax = xAPIC ICR low */
		0x66, 0xba, 0x00, 0x05, 0x00, 0x00, /* INIT, physical dest */
		0x66, 0x67, 0x89, 0x10,
		0x66, 0xba, 0x02, 0x06, 0x00, 0x00, /* SIPI, vector 2 */
		0x66, 0x67, 0x89, 0x10,
		0xb0, 0x5a, 0xe6, 0x80,             /* out 0x80, 0x5a */
		0xf4,
	};
	static const uint8_t ap_program[] = {
		0xb0, 0xa5, 0xe6, 0x81,             /* out 0x81, 0xa5 */
		0xf4,
	};
	struct startup_run_worker workers[2] = { 0 };
	struct vmm_startup_request request;
	struct vmctx *ctx;
	struct vcpu *vcpus[2];
	pthread_t threads[2];
	uint32_t eax, ebx, ecx, edx, vendor[3];
	uint32_t cs_limit, cs_access;
	uint64_t cs_base, cs_selector;
	uint8_t *bsp_code, *ap_code;
	char name[VM_MAX_NAMELEN];
	int error;

	vm_name_for(tc, name, sizeof(name));
	ATF_REQUIRE_EQ_MSG(vm_create(name), 0, "vm_create: %s",
	    strerror(errno));
	ctx = vm_open(name);
	ATF_REQUIRE_MSG(ctx != NULL, "vm_open: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_set_topology(ctx, 1, 2, 1, 0), 0,
	    "vm_set_topology: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_setup_memory(ctx, STARTUP_TEST_MEMORY_SIZE,
	    VM_MMAP_ALL), 0, "vm_setup_memory: %s", strerror(errno));
	bsp_code = vm_map_gpa(ctx, STARTUP_TEST_BSP_GPA, PAGE_SIZE);
	ap_code = vm_map_gpa(ctx, STARTUP_TEST_AP_GPA, PAGE_SIZE);
	ATF_REQUIRE(bsp_code != NULL && ap_code != NULL);
	memcpy(bsp_code, bsp_program, sizeof(bsp_program));
	memcpy(ap_code, ap_program, sizeof(ap_program));
	/* Match bhyve: select the startup owner before opening vCPU threads. */
	request = (struct vmm_startup_request) {
		.version = VMM_STARTUP_REQUEST_VERSION,
		.size = VMM_STARTUP_REQUEST_SIZE,
		.operation = VMM_STARTUP_REQUEST_CONFIGURE,
		.expected_vcpus = 2,
	};
	if (vm_startup_request(ctx, &request) != 0) {
		if (errno == EOPNOTSUPP)
			atf_tc_skip("kernel startup gate is disabled");
		ATF_REQUIRE_MSG(false, "startup configure: %s", strerror(errno));
	}
	ATF_REQUIRE(request.generation != 0);
	vcpus[0] = vm_vcpu_open(ctx, 0);
	vcpus[1] = vm_vcpu_open(ctx, 1);
	ATF_REQUIRE(vcpus[0] != NULL && vcpus[1] != NULL);
	eax = ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(vcpus[0], 0, &eax, &ebx, &ecx, &edx),
	    0);
	vendor[0] = ebx;
	vendor[1] = edx;
	vendor[2] = ecx;
	if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) != 0)
		atf_tc_skip("requires AMD SVM hardware");
	for (int i = 0; i < 2; i++) {
		ATF_REQUIRE_EQ_MSG(vm_activate_cpu(vcpus[i]), 0,
		    "activate vCPU %d: %s", i, strerror(errno));
		ATF_REQUIRE_EQ_MSG(vm_set_capability(vcpus[i],
		    VM_CAP_UNRESTRICTED_GUEST, 1), 0,
		    "unrestricted vCPU %d: %s", i, strerror(errno));
		workers[i].vcpu = vcpus[i];
		workers[i].generation = request.generation;
	}
	ATF_REQUIRE_EQ_MSG(vcpu_reset(vcpus[0]), 0,
	    "reset BSP: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_set_desc(vcpus[0], VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x0093), 0, "set BSP CS descriptor: %s",
	    strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_set_register(vcpus[0], VM_REG_GUEST_CS, 0),
	    0, "set BSP CS: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_set_register(vcpus[0], VM_REG_GUEST_RIP,
	    STARTUP_TEST_BSP_GPA), 0, "set BSP RIP: %s", strerror(errno));
	for (int i = 0; i < 2; i++) {
		error = pthread_create(&threads[i], NULL, startup_run_once,
		    &workers[i]);
		ATF_REQUIRE_EQ_MSG(error, 0, "start vCPU %d: %s", i,
		    strerror(error));
	}
	request = (struct vmm_startup_request) {
		.version = VMM_STARTUP_REQUEST_VERSION,
		.size = VMM_STARTUP_REQUEST_SIZE,
		.operation = VMM_STARTUP_REQUEST_WAIT_READY,
		.generation = workers[0].generation,
	};
	ATF_REQUIRE_EQ_MSG(vm_startup_request(ctx, &request), 0,
	    "startup wait: %s", strerror(errno));
	ATF_REQUIRE_EQ(request.entered_vcpus, 2U);
	ATF_REQUIRE_EQ(request.bootstrap_entered, 1U);
	request = (struct vmm_startup_request) {
		.version = VMM_STARTUP_REQUEST_VERSION,
		.size = VMM_STARTUP_REQUEST_SIZE,
		.operation = VMM_STARTUP_REQUEST_COMMIT,
		.generation = workers[0].generation,
	};
	ATF_REQUIRE_EQ_MSG(vm_startup_request(ctx, &request), 0,
	    "startup commit: %s", strerror(errno));
	for (int i = 0; i < 2; i++) {
		error = pthread_join(threads[i], NULL);
		ATF_REQUIRE_EQ_MSG(error, 0, "join vCPU %d: %s", i,
		    strerror(error));
		ATF_REQUIRE_EQ_MSG(workers[i].result, 0,
		    "vCPU %d run: %s", i, strerror(workers[i].error));
		ATF_REQUIRE_EQ(workers[i].vmexit.exitcode, VM_EXITCODE_INOUT);
		ATF_REQUIRE_EQ(workers[i].vmexit.u.inout.in, 0);
		ATF_REQUIRE_EQ(workers[i].vmexit.u.inout.bytes, 1);
	}
	ATF_CHECK_EQ(workers[0].vmexit.u.inout.port, 0x80);
	ATF_CHECK_EQ(workers[0].vmexit.u.inout.eax & UINT8_MAX, 0x5a);
	ATF_CHECK_EQ(workers[1].vmexit.u.inout.port, 0x81);
	ATF_CHECK_EQ(workers[1].vmexit.u.inout.eax & UINT8_MAX, 0xa5);
	ATF_REQUIRE_EQ_MSG(vm_get_desc(vcpus[1], VM_REG_GUEST_CS,
	    &cs_base, &cs_limit, &cs_access), 0,
	    "get AP CS descriptor: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_get_register(vcpus[1], VM_REG_GUEST_CS,
	    &cs_selector), 0, "get AP CS: %s", strerror(errno));
	ATF_CHECK_EQ(cs_base, STARTUP_TEST_AP_GPA);
	ATF_CHECK_EQ(cs_selector, STARTUP_TEST_AP_GPA >> 4);
	ATF_CHECK_EQ(cs_limit, UINT16_MAX);
	ATF_CHECK_EQ(cs_access, 0x0093U);
	for (int i = 0; i < 2; i++)
		vm_vcpu_close(vcpus[i]);
	vm_destroy(ctx);
}
ATF_TC_CLEANUP(amd_init_sipi_executes_ap, tc)
{

	cleanup_vm(tc);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, configure_activation_boundary);
	ATF_TP_ADD_TC(tp, generation_run_requires_controller);
	ATF_TP_ADD_TC(tp, amd_init_sipi_executes_ap);
	return (atf_no_error());
}
