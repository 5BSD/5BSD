/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <machine/vmm.h>

#include <vmmapi.h>

#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define	GUEST_MEMORY_SIZE	(2 * 1024 * 1024)
#define	GUEST_CODE_GPA		0x1000
#define	LIVE_VM_COUNT		4
#define	LIFECYCLE_ROUNDS	32

struct live_vm {
	struct vmctx *ctx;
	struct vcpu *vcpu;
	uint8_t *code;
	uint8_t value;
	uint8_t port;
	uint64_t exit_rip;
};

struct run_gate {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	size_t ready;
	bool start;
};

struct run_worker {
	struct live_vm *live;
	struct run_gate *gate;
	struct vm_exit vmexit;
	int error;
};

static void
require_live_vmm(atf_tc_t *tc, const char *description)
{

	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.arch", "amd64");
	atf_tc_set_md_var(tc, "require.kmods", "vmm");
	atf_tc_set_md_var(tc, "timeout", "30");
	atf_tc_set_md_var(tc, "descr", description);
}

static void
vm_name_for(const atf_tc_t *tc, size_t index, char *name, size_t size)
{

	ATF_REQUIRE_MSG(snprintf(name, size, "kvp-%ld-%c-%zu",
	    (long)getpid(), atf_tc_get_ident(tc)[0], index) > 0,
	    "format VM name");
}

static void
record_vm_name(const atf_tc_t *tc, const char *name)
{
	char path[PATH_MAX];
	FILE *fp;

	ATF_REQUIRE(snprintf(path, sizeof(path), ".%s-vm-names",
	    atf_tc_get_ident(tc)) > 0);
	fp = fopen(path, "a");
	ATF_REQUIRE_MSG(fp != NULL, "fopen(%s): %s", path,
	    strerror(errno));
	ATF_REQUIRE_MSG(fprintf(fp, "%s\n", name) > 0,
	    "record VM name: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(fclose(fp), 0, "fclose(%s): %s", path,
	    strerror(errno));
}

static void
cleanup_vms(const atf_tc_t *tc)
{
	char name[VM_MAX_NAMELEN], path[PATH_MAX];
	struct vmctx *ctx;
	FILE *fp;

	if (snprintf(path, sizeof(path), ".%s-vm-names",
	    atf_tc_get_ident(tc)) <= 0)
		return;
	fp = fopen(path, "r");
	if (fp == NULL)
		return;
	while (fgets(name, sizeof(name), fp) != NULL) {
		name[strcspn(name, "\r\n")] = '\0';
		if (name[0] == '\0')
			continue;
		ctx = vm_open(name);
		if (ctx != NULL)
			vm_destroy(ctx);
	}
	(void)fclose(fp);
	(void)unlink(path);
}

static struct live_vm
create_live_vm(const atf_tc_t *tc, size_t index)
{
	struct live_vm live;
	char name[VM_MAX_NAMELEN];

	memset(&live, 0, sizeof(live));
	vm_name_for(tc, index, name, sizeof(name));
	ATF_REQUIRE_EQ_MSG(vm_create(name), 0, "vm_create(%s): %s", name,
	    strerror(errno));
	record_vm_name(tc, name);
	live.ctx = vm_open(name);
	ATF_REQUIRE_MSG(live.ctx != NULL, "vm_open(%s): %s", name,
	    strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_setup_memory(live.ctx, GUEST_MEMORY_SIZE,
	    VM_MMAP_ALL), 0, "vm_setup_memory(%s): %s", name,
	    strerror(errno));
	live.code = vm_map_gpa(live.ctx, GUEST_CODE_GPA, PAGE_SIZE);
	ATF_REQUIRE_MSG(live.code != NULL, "vm_map_gpa(%s): %s", name,
	    strerror(errno));
	live.vcpu = vm_vcpu_open(live.ctx, 0);
	ATF_REQUIRE_MSG(live.vcpu != NULL, "vm_vcpu_open(%s): %s", name,
	    strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_activate_cpu(live.vcpu), 0,
	    "vm_activate_cpu(%s): %s", name, strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_set_capability(live.vcpu,
	    VM_CAP_UNRESTRICTED_GUEST, 1), 0,
	    "enable unrestricted guest for %s: %s", name, strerror(errno));
	ATF_REQUIRE_EQ_MSG(vcpu_reset(live.vcpu), 0, "vcpu_reset(%s): %s",
	    name, strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_set_desc(live.vcpu, VM_REG_GUEST_CS, 0,
	    UINT16_MAX, 0x0093), 0, "set flat CS for %s: %s", name,
	    strerror(errno));
	ATF_REQUIRE_EQ_MSG(vm_set_register(live.vcpu, VM_REG_GUEST_CS, 0), 0,
	    "set CS for %s: %s", name, strerror(errno));
	return (live);
}

static void
prepare_io_exit(struct live_vm *live, uint8_t value, uint8_t port)
{

	live->value = value;
	live->port = port;
	live->exit_rip = GUEST_CODE_GPA + 2;
	live->code[0] = 0xb0;	/* mov al, value */
	live->code[1] = value;
	live->code[2] = 0xe6;	/* out port, al */
	live->code[3] = port;
	ATF_REQUIRE_EQ_MSG(vm_set_register(live->vcpu, VM_REG_GUEST_RIP,
	    GUEST_CODE_GPA), 0, "set RIP: %s", strerror(errno));
}

/* The start gate intentionally transfers mutex ownership across cond_wait. */
static void *run_worker(void *arg)
    __attribute__((no_thread_safety_analysis));
static void *
run_worker(void *arg)
{
	struct run_worker *worker;
	struct vm_run vmrun;
	cpuset_t cpuset;
	int error;

	worker = arg;
	error = pthread_mutex_lock(&worker->gate->mutex);
	if (error != 0) {
		worker->error = error;
		return (NULL);
	}
	worker->gate->ready++;
	(void)pthread_cond_signal(&worker->gate->cond);
	while (!worker->gate->start) {
		error = pthread_cond_wait(&worker->gate->cond,
		    &worker->gate->mutex);
		if (error != 0) {
			worker->error = error;
			(void)pthread_mutex_unlock(&worker->gate->mutex);
			return (NULL);
		}
	}
	(void)pthread_mutex_unlock(&worker->gate->mutex);

	memset(&worker->vmexit, 0, sizeof(worker->vmexit));
	memset(&vmrun, 0, sizeof(vmrun));
	CPU_ZERO(&cpuset);
	vmrun.vm_exit = &worker->vmexit;
	vmrun.cpuset = &cpuset;
	vmrun.cpusetsize = sizeof(cpuset);
	if (vm_run(worker->live->vcpu, &vmrun) != 0)
		worker->error = errno;
	return (NULL);
}

static void run_parallel(struct live_vm **live, size_t count)
    __attribute__((no_thread_safety_analysis));
static void
run_parallel(struct live_vm **live, size_t count)
{
	struct run_worker workers[LIVE_VM_COUNT];
	struct run_gate gate;
	pthread_t threads[LIVE_VM_COUNT];
	uint64_t rax;
	size_t created, i;
	int error;

	ATF_REQUIRE(count > 0);
	ATF_REQUIRE(count <= LIVE_VM_COUNT);
	memset(&gate, 0, sizeof(gate));
	ATF_REQUIRE_EQ(pthread_mutex_init(&gate.mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&gate.cond, NULL), 0);
	memset(workers, 0, sizeof(workers));

	created = 0;
	for (i = 0; i < count; i++) {
		workers[i].live = live[i];
		workers[i].gate = &gate;
		error = pthread_create(&threads[i], NULL, run_worker, &workers[i]);
		if (error != 0) {
			ATF_REQUIRE_EQ(pthread_mutex_lock(&gate.mutex), 0);
			gate.start = true;
			ATF_REQUIRE_EQ(pthread_cond_broadcast(&gate.cond), 0);
			ATF_REQUIRE_EQ(pthread_mutex_unlock(&gate.mutex), 0);
			while (created > 0)
				ATF_REQUIRE_EQ(pthread_join(threads[--created], NULL), 0);
			atf_tc_fail("pthread_create: %s", strerror(error));
		}
		created++;
	}

	ATF_REQUIRE_EQ(pthread_mutex_lock(&gate.mutex), 0);
	while (gate.ready != count)
		ATF_REQUIRE_EQ(pthread_cond_wait(&gate.cond, &gate.mutex), 0);
	gate.start = true;
	ATF_REQUIRE_EQ(pthread_cond_broadcast(&gate.cond), 0);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&gate.mutex), 0);

	for (i = 0; i < count; i++) {
		ATF_REQUIRE_EQ(pthread_join(threads[i], NULL), 0);
		ATF_REQUIRE_EQ_MSG(workers[i].error, 0, "vm_run: %s",
		    strerror(workers[i].error));
		ATF_REQUIRE_EQ(workers[i].vmexit.exitcode, VM_EXITCODE_INOUT);
		ATF_REQUIRE_EQ(workers[i].vmexit.rip, live[i]->exit_rip);
		ATF_REQUIRE_EQ(workers[i].vmexit.inst_length, 2);
		ATF_REQUIRE_EQ(workers[i].vmexit.u.inout.in, 0);
		ATF_REQUIRE_EQ(workers[i].vmexit.u.inout.bytes, 1);
		ATF_REQUIRE_EQ(workers[i].vmexit.u.inout.port, live[i]->port);
		ATF_REQUIRE_EQ(workers[i].vmexit.u.inout.eax & UINT8_MAX,
		    live[i]->value);
		ATF_REQUIRE_EQ_MSG(vm_get_register(live[i]->vcpu,
		    VM_REG_GUEST_RAX, &rax), 0, "get RAX: %s", strerror(errno));
		ATF_REQUIRE_EQ(rax & UINT8_MAX, live[i]->value);
	}
	ATF_REQUIRE_EQ(pthread_cond_destroy(&gate.cond), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&gate.mutex), 0);
}

static void
destroy_live_vm(struct live_vm *live)
{

	if (live->vcpu != NULL) {
		vm_vcpu_close(live->vcpu);
		live->vcpu = NULL;
	}
	if (live->ctx != NULL) {
		vm_destroy(live->ctx);
		live->ctx = NULL;
	}
}

ATF_TC_WITH_CLEANUP(guest_cpuid_matches_kernel_contract);
ATF_TC_HEAD(guest_cpuid_matches_kernel_contract, tc)
{

	require_live_vmm(tc,
	    "Compare a bare guest CPUID result with the kernel CPUID query ABI");
}
ATF_TC_BODY(guest_cpuid_matches_kernel_contract, tc)
{
	struct live_vm *active[1];
	struct live_vm live;
	uint32_t eax, ebx, ecx, edx;
	uint64_t value;

	live = create_live_vm(tc, 0);
	eax = 0;
	ebx = ecx = edx = 0;
	ATF_REQUIRE_EQ_MSG(vm_get_cpuid(live.vcpu, 0, &eax, &ebx, &ecx,
	    &edx), 0, "VM_GET_CPUID leaf 0: %s", strerror(errno));
	ATF_REQUIRE(eax != 0);

	/* mov eax,0; xor ecx,ecx; cpuid; out 0xa0,al */
	live.code[0] = 0xb8;
	memset(live.code + 1, 0, 4);
	live.code[5] = 0x31;
	live.code[6] = 0xc9;
	live.code[7] = 0x0f;
	live.code[8] = 0xa2;
	live.code[9] = 0xe6;
	live.code[10] = 0xa0;
	live.value = (uint8_t)eax;
	live.port = 0xa0;
	live.exit_rip = GUEST_CODE_GPA + 9;
	ATF_REQUIRE_EQ_MSG(vm_set_register(live.vcpu, VM_REG_GUEST_RIP,
	    GUEST_CODE_GPA), 0, "set RIP: %s", strerror(errno));
	active[0] = &live;
	run_parallel(active, 1);

	ATF_REQUIRE_EQ_MSG(vm_get_register(live.vcpu, VM_REG_GUEST_RAX,
	    &value), 0, "get CPUID EAX: %s", strerror(errno));
	ATF_REQUIRE_EQ((uint32_t)value, eax);
	ATF_REQUIRE_EQ_MSG(vm_get_register(live.vcpu, VM_REG_GUEST_RBX,
	    &value), 0, "get CPUID EBX: %s", strerror(errno));
	ATF_REQUIRE_EQ((uint32_t)value, ebx);
	ATF_REQUIRE_EQ_MSG(vm_get_register(live.vcpu, VM_REG_GUEST_RCX,
	    &value), 0, "get CPUID ECX: %s", strerror(errno));
	ATF_REQUIRE_EQ((uint32_t)value, ecx);
	ATF_REQUIRE_EQ_MSG(vm_get_register(live.vcpu, VM_REG_GUEST_RDX,
	    &value), 0, "get CPUID EDX: %s", strerror(errno));
	ATF_REQUIRE_EQ((uint32_t)value, edx);
	destroy_live_vm(&live);
}
ATF_TC_CLEANUP(guest_cpuid_matches_kernel_contract, tc)
{

	cleanup_vms(tc);
}

ATF_TC_WITH_CLEANUP(cpuid_query_rejects_invalid_input);
ATF_TC_HEAD(cpuid_query_rejects_invalid_input, tc)
{

	require_live_vmm(tc,
	    "Reject unknown CPUID query flags and null output pointers");
}
ATF_TC_BODY(cpuid_query_rejects_invalid_input, tc)
{
	struct live_vm live;
	uint32_t eax, ebx, ecx, edx;

	live = create_live_vm(tc, 0);
	eax = 0;
	ebx = UINT32_C(0x11111111);
	ecx = UINT32_C(0x22222222);
	edx = UINT32_C(0x33333333);
	errno = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, VM_CPUID_F_VALID << 1, &eax,
	    &ebx, &ecx, &edx), -1);
	ATF_REQUIRE_EQ(errno, EINVAL);
	ATF_REQUIRE_EQ(eax, 0);
	ATF_REQUIRE_EQ(ebx, UINT32_C(0x11111111));
	ATF_REQUIRE_EQ(ecx, UINT32_C(0x22222222));
	ATF_REQUIRE_EQ(edx, UINT32_C(0x33333333));
	errno = 0;
	ATF_REQUIRE_EQ(vm_get_cpuid(live.vcpu, 0, NULL, &ebx, &ecx, &edx),
	    -1);
	ATF_REQUIRE_EQ(errno, EINVAL);
	destroy_live_vm(&live);
}
ATF_TC_CLEANUP(cpuid_query_rejects_invalid_input, tc)
{

	cleanup_vms(tc);
}

ATF_TC_WITH_CLEANUP(multiple_vms_parallel_isolation);
ATF_TC_HEAD(multiple_vms_parallel_isolation, tc)
{

	require_live_vmm(tc,
	    "Run independent vCPUs in four coexisting VMs and preserve the "
	    "survivors when one VM is destroyed");
}
ATF_TC_BODY(multiple_vms_parallel_isolation, tc)
{
	struct live_vm *active[LIVE_VM_COUNT];
	struct live_vm live[LIVE_VM_COUNT];
	size_t i;

	for (i = 0; i < LIVE_VM_COUNT; i++) {
		live[i] = create_live_vm(tc, i);
		live[i].code[PAGE_SIZE / 2] = (uint8_t)(0x40 + i);
		prepare_io_exit(&live[i], (uint8_t)(0xa0 + i),
		    (uint8_t)(0x80 + i));
		active[i] = &live[i];
	}
	for (i = 0; i < LIVE_VM_COUNT; i++)
		ATF_REQUIRE_EQ(live[i].code[PAGE_SIZE / 2], 0x40 + i);
	run_parallel(active, LIVE_VM_COUNT);

	destroy_live_vm(&live[1]);
	active[0] = &live[0];
	active[1] = &live[2];
	active[2] = &live[3];
	for (i = 0; i < 3; i++)
		prepare_io_exit(active[i], (uint8_t)(0xb0 + i),
		    (uint8_t)(0x90 + i));
	run_parallel(active, 3);
	ATF_REQUIRE_EQ(live[0].code[PAGE_SIZE / 2], 0x40);
	ATF_REQUIRE_EQ(live[2].code[PAGE_SIZE / 2], 0x42);
	ATF_REQUIRE_EQ(live[3].code[PAGE_SIZE / 2], 0x43);

	destroy_live_vm(&live[0]);
	destroy_live_vm(&live[2]);
	destroy_live_vm(&live[3]);
}
ATF_TC_CLEANUP(multiple_vms_parallel_isolation, tc)
{

	cleanup_vms(tc);
}

ATF_TC_WITH_CLEANUP(repeated_create_destroy);
ATF_TC_HEAD(repeated_create_destroy, tc)
{

	require_live_vmm(tc,
	    "Repeat VM create/open/destroy and reject a duplicate live name");
}
ATF_TC_BODY(repeated_create_destroy, tc)
{
	struct vmctx *ctx, *missing;
	char name[VM_MAX_NAMELEN];
	size_t i;

	vm_name_for(tc, 0, name, sizeof(name));
	for (i = 0; i < LIFECYCLE_ROUNDS; i++) {
		ATF_REQUIRE_EQ_MSG(vm_create(name), 0,
		    "vm_create round %zu: %s", i, strerror(errno));
		record_vm_name(tc, name);
		errno = 0;
		ATF_REQUIRE_EQ(vm_create(name), -1);
		ATF_REQUIRE_EQ(errno, EEXIST);
		ctx = vm_open(name);
		ATF_REQUIRE_MSG(ctx != NULL, "vm_open round %zu: %s", i,
		    strerror(errno));
		ATF_REQUIRE_EQ_MSG(vm_setup_memory(ctx, GUEST_MEMORY_SIZE,
		    VM_MMAP_ALL), 0, "vm_setup_memory round %zu: %s", i,
		    strerror(errno));
		vm_destroy(ctx);
		errno = 0;
		missing = vm_open(name);
		ATF_REQUIRE(missing == NULL);
		ATF_REQUIRE_EQ(errno, ENOENT);
	}
}
ATF_TC_CLEANUP(repeated_create_destroy, tc)
{

	cleanup_vms(tc);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, guest_cpuid_matches_kernel_contract);
	ATF_TP_ADD_TC(tp, cpuid_query_rejects_invalid_input);
	ATF_TP_ADD_TC(tp, multiple_vms_parallel_isolation);
	ATF_TP_ADD_TC(tp, repeated_create_destroy);
	return (atf_no_error());
}
