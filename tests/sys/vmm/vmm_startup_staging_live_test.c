/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <dev/vmm/vmm_startup_request.h>

#include <vmm.h>
#include <vmmapi.h>

#include <atf-c.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
}

ATF_TC_WITH_CLEANUP(generation_run_requires_controller);
ATF_TC_HEAD(generation_run_requires_controller, tc)
{

	atf_tc_set_md_var(tc, "require.user", "root");
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

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, configure_activation_boundary);
	ATF_TP_ADD_TC(tp, generation_run_requires_controller);
	return (atf_no_error());
}
