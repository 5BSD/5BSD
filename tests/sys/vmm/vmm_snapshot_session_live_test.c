/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <vmm.h>
#include <vmm_snapshot.h>
#include <vmm_dev.h>
#include <vmmapi.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void
require_root(atf_tc_t *tc)
{

	atf_tc_set_md_var(tc, "require.user", "root");
}

static void
vm_name_for(const atf_tc_t *tc, char *name, size_t size)
{

	ATF_REQUIRE(snprintf(name, size, "vms-%ld-%c", (long)getpid(),
	    atf_tc_get_ident(tc)[0]) > 0);
}

static struct vmctx *
create_vm_with_vcpu(const atf_tc_t *tc, struct vcpu **vcpup)
{
	struct vm_snapshot_session session;
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
	ATF_REQUIRE_EQ_MSG(vm_activate_cpu(vcpu), 0, "vm_activate_cpu: %s",
	    strerror(errno));

	/*
	 * This test is built on every amd64 test install, but the kernel
	 * snapshot option is intentionally off by default.  Probe the versioned
	 * session ioctl after the VM exists: an unsupported kernel reports
	 * ENOTTY, while a snapshot-enabled kernel rejects the zero version.
	 */
	memset(&session, 0, sizeof(session));
	errno = 0;
	if (vm_snapshot_session(ctx, &session) == -1 && errno == ENOTTY)
		atf_tc_skip("vmm kernel lacks BHYVE_SNAPSHOT support");
	ATF_REQUIRE_ERRNO(EINVAL, vm_snapshot_session(ctx, &session) == -1);
	*vcpup = vcpu;
	return (ctx);
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

ATF_TC_WITH_CLEANUP(policy_and_descriptor_ownership);
ATF_TC_HEAD(policy_and_descriptor_ownership, tc)
{

	require_root(tc);
}
ATF_TC_BODY(policy_and_descriptor_ownership, tc)
{
	struct vm_snapshot_session session, other;
	struct vmctx *ctx, *ctx2;
	struct vcpu *vcpu;
	char name[VM_MAX_NAMELEN], path[PATH_MAX];
	uint64_t id;
	int fd;

	ctx = create_vm_with_vcpu(tc, &vcpu);
	vm_name_for(tc, name, sizeof(name));
	ctx2 = vm_open(name);
	ATF_REQUIRE(ctx2 != NULL);

	/* Malformed requests must not acquire or perturb session ownership. */
	session = (struct vm_snapshot_session) {
		.version = VM_SNAPSHOT_SESSION_VERSION + 1,
		.op = VM_SNAPSHOT_SESSION_BEGIN,
	};
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx, &session), -1);
	ATF_REQUIRE_EQ(errno, EINVAL);
	ATF_REQUIRE_EQ(session.session_id, 0);
	session.version = VM_SNAPSHOT_SESSION_VERSION;
	session.op = UINT32_MAX;
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx, &session), -1);
	ATF_REQUIRE_EQ(errno, EINVAL);
	session.op = VM_SNAPSHOT_SESSION_BEGIN;
	session.flags = 1;
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx, &session), -1);
	ATF_REQUIRE_EQ(errno, EINVAL);
	session.flags = 0;
	session.reserved[0] = 1;
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx, &session), -1);
	ATF_REQUIRE_EQ(errno, EINVAL);
	session.reserved[0] = 0;
	session.reserved[1] = 1;
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx, &session), -1);
	ATF_REQUIRE_EQ(errno, EINVAL);
	session.reserved[1] = 0;
	session.session_id = 1;
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx, &session), -1);
	ATF_REQUIRE_EQ(errno, EINVAL);

	session = (struct vm_snapshot_session) {
		.version = VM_SNAPSHOT_SESSION_VERSION,
		.op = VM_SNAPSHOT_SESSION_BEGIN,
	};
	ATF_REQUIRE_EQ_MSG(vm_snapshot_session(ctx, &session), 0,
	    "BEGIN: %s", strerror(errno));
	ATF_REQUIRE(session.session_id != 0);
	id = session.session_id;

	other = (struct vm_snapshot_session) {
		.version = VM_SNAPSHOT_SESSION_VERSION,
		.op = VM_SNAPSHOT_SESSION_BEGIN,
	};
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx, &other), -1);
	ATF_REQUIRE_EQ(errno, EBUSY);
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx2, &other), -1);
	ATF_REQUIRE_EQ(errno, EBUSY);

	other.op = VM_SNAPSHOT_SESSION_ABORT;
	other.session_id = id;
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx2, &other), -1);
	ATF_REQUIRE_EQ(errno, ESTALE);
	other.session_id = id + 1;
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx, &other), -1);
	ATF_REQUIRE_EQ(errno, ESTALE);

	other.session_id = id;
	ATF_REQUIRE_EQ_MSG(vm_snapshot_session(ctx, &other), 0,
	    "ABORT: %s", strerror(errno));
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx, &other), -1);
	ATF_REQUIRE_EQ(errno, ESTALE);

	/*
	 * BEGIN copyout recovery is scoped to the exact open file description
	 * and requires a canonical zero identity.
	 */
	memset(&session, 0, sizeof(session));
	session.version = VM_SNAPSHOT_SESSION_VERSION;
	session.op = VM_SNAPSHOT_SESSION_BEGIN;
	ATF_REQUIRE_EQ_MSG(vm_snapshot_session(ctx, &session), 0,
	    "recovery BEGIN: %s", strerror(errno));
	memset(&other, 0, sizeof(other));
	other.version = VM_SNAPSHOT_SESSION_VERSION;
	other.op = VM_SNAPSHOT_SESSION_ABORT_CURRENT;
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx2, &other), -1);
	ATF_REQUIRE_EQ(errno, ESTALE);
	other.session_id = session.session_id;
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx, &other), -1);
	ATF_REQUIRE_EQ(errno, EINVAL);
	other.session_id = 0;
	ATF_REQUIRE_EQ_MSG(vm_snapshot_session(ctx, &other), 0,
	    "ABORT_CURRENT: %s", strerror(errno));
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx, &other), -1);
	ATF_REQUIRE_EQ(errno, ESTALE);

	/* COMMIT consumes the same descriptor-owned credential exactly once. */
	memset(&session, 0, sizeof(session));
	session.version = VM_SNAPSHOT_SESSION_VERSION;
	session.op = VM_SNAPSHOT_SESSION_BEGIN;
	ATF_REQUIRE_EQ_MSG(vm_snapshot_session(ctx, &session), 0,
	    "second BEGIN: %s", strerror(errno));
	session.op = VM_SNAPSHOT_SESSION_COMMIT;
	ATF_REQUIRE_EQ_MSG(vm_snapshot_session(ctx, &session), 0,
	    "COMMIT: %s", strerror(errno));
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx, &session), -1);
	ATF_REQUIRE_EQ(errno, ESTALE);

	ATF_REQUIRE(snprintf(path, sizeof(path), "/dev/vmm/%s", name) > 0);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE_MSG(fd >= 0, "open read-only VM: %s", strerror(errno));
	memset(&other, 0, sizeof(other));
	other.version = VM_SNAPSHOT_SESSION_VERSION;
	other.op = VM_SNAPSHOT_SESSION_BEGIN;
	errno = 0;
	ATF_REQUIRE_EQ(ioctl(fd, VM_SNAPSHOT_SESSION, &other), -1);
	ATF_REQUIRE_EQ(errno, EBADF);
	ATF_REQUIRE_EQ(close(fd), 0);

	vm_vcpu_close(vcpu);
	vm_close(ctx2);
	vm_destroy(ctx);
}
ATF_TC_CLEANUP(policy_and_descriptor_ownership, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(copyout_fault_consumes_exact_operation);
ATF_TC_HEAD(copyout_fault_consumes_exact_operation, tc)
{

	require_root(tc);
}
ATF_TC_BODY(copyout_fault_consumes_exact_operation, tc)
{
	struct vm_snapshot_session recovery, session;
	struct vm_snapshot_session *faulting;
	struct vmctx *ctx;
	struct vcpu *vcpu;
	size_t pagesize;
	void *page;

	ctx = create_vm_with_vcpu(tc, &vcpu);
	pagesize = (size_t)getpagesize();
	page = mmap(NULL, pagesize, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE, -1, 0);
	ATF_REQUIRE_MSG(page != MAP_FAILED, "mmap: %s", strerror(errno));
	faulting = page;

	/*
	 * The ioctl is IOWR.  A read-only userspace page permits copyin but
	 * forces the copyout to fail after the kernel has acquired or consumed
	 * the descriptor-scoped owner.  These cases prove the exact retry
	 * protocol used by bhyve rather than merely exercising ordinary ioctl
	 * errors which occur before ownership changes.
	 */
	*faulting = (struct vm_snapshot_session) {
		.version = VM_SNAPSHOT_SESSION_VERSION,
		.op = VM_SNAPSHOT_SESSION_BEGIN,
	};
	ATF_REQUIRE_EQ(mprotect(page, pagesize, PROT_READ), 0);
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx, faulting), -1);
	ATF_REQUIRE_EQ(errno, EFAULT);
	recovery = (struct vm_snapshot_session) {
		.version = VM_SNAPSHOT_SESSION_VERSION,
		.op = VM_SNAPSHOT_SESSION_ABORT_CURRENT,
	};
	ATF_REQUIRE_EQ_MSG(vm_snapshot_session(ctx, &recovery), 0,
	    "recover faulted BEGIN: %s", strerror(errno));
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx, &recovery), -1);
	ATF_REQUIRE_EQ(errno, ESTALE);

	session = (struct vm_snapshot_session) {
		.version = VM_SNAPSHOT_SESSION_VERSION,
		.op = VM_SNAPSHOT_SESSION_BEGIN,
	};
	ATF_REQUIRE_EQ_MSG(vm_snapshot_session(ctx, &session), 0,
	    "BEGIN before faulted ABORT: %s", strerror(errno));
	ATF_REQUIRE_EQ(mprotect(page, pagesize, PROT_READ | PROT_WRITE), 0);
	*faulting = session;
	faulting->op = VM_SNAPSHOT_SESSION_ABORT;
	ATF_REQUIRE_EQ(mprotect(page, pagesize, PROT_READ), 0);
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx, faulting), -1);
	ATF_REQUIRE_EQ(errno, EFAULT);
	ATF_REQUIRE_EQ(mprotect(page, pagesize, PROT_READ | PROT_WRITE), 0);
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx, faulting), -1);
	ATF_REQUIRE_EQ(errno, ESTALE);

	/* A consumed fault must not leave the VM-wide owner busy. */
	memset(&session, 0, sizeof(session));
	session.version = VM_SNAPSHOT_SESSION_VERSION;
	session.op = VM_SNAPSHOT_SESSION_BEGIN;
	ATF_REQUIRE_EQ_MSG(vm_snapshot_session(ctx, &session), 0,
	    "BEGIN after faulted ABORT: %s", strerror(errno));
	session.op = VM_SNAPSHOT_SESSION_ABORT;
	ATF_REQUIRE_EQ_MSG(vm_snapshot_session(ctx, &session), 0,
	    "final ABORT: %s", strerror(errno));

	ATF_REQUIRE_EQ(munmap(page, pagesize), 0);
	vm_vcpu_close(vcpu);
	vm_destroy(ctx);
}
ATF_TC_CLEANUP(copyout_fault_consumes_exact_operation, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(final_close_aborts);
ATF_TC_HEAD(final_close_aborts, tc)
{

	require_root(tc);
}
ATF_TC_BODY(final_close_aborts, tc)
{
	struct vm_snapshot_session session;
	struct vmctx *ctx, *ctx2;
	struct vcpu *vcpu;
	char name[VM_MAX_NAMELEN];

	ctx = create_vm_with_vcpu(tc, &vcpu);
	vm_name_for(tc, name, sizeof(name));
	session = (struct vm_snapshot_session) {
		.version = VM_SNAPSHOT_SESSION_VERSION,
		.op = VM_SNAPSHOT_SESSION_BEGIN,
	};
	ATF_REQUIRE_EQ_MSG(vm_snapshot_session(ctx, &session), 0,
	    "BEGIN: %s", strerror(errno));
	vm_close(ctx);

	ctx2 = vm_open(name);
	ATF_REQUIRE_MSG(ctx2 != NULL, "reopen: %s", strerror(errno));
	memset(&session, 0, sizeof(session));
	session.version = VM_SNAPSHOT_SESSION_VERSION;
	session.op = VM_SNAPSHOT_SESSION_BEGIN;
	ATF_REQUIRE_EQ_MSG(vm_snapshot_session(ctx2, &session), 0,
	    "BEGIN after final close: %s", strerror(errno));
	session.op = VM_SNAPSHOT_SESSION_ABORT;
	ATF_REQUIRE_EQ_MSG(vm_snapshot_session(ctx2, &session), 0,
	    "ABORT after reopen: %s", strerror(errno));

	vm_vcpu_close(vcpu);
	vm_destroy(ctx2);
}
ATF_TC_CLEANUP(final_close_aborts, tc)
{

	cleanup_vm(tc);
}

ATF_TC_WITH_CLEANUP(empty_group_rejected);
ATF_TC_HEAD(empty_group_rejected, tc)
{

	require_root(tc);
}
ATF_TC_BODY(empty_group_rejected, tc)
{
	struct vm_snapshot_session session;
	struct vmctx *ctx;
	char name[VM_MAX_NAMELEN];

	vm_name_for(tc, name, sizeof(name));
	ATF_REQUIRE_EQ(vm_create(name), 0);
	ctx = vm_open(name);
	ATF_REQUIRE(ctx != NULL);
	session = (struct vm_snapshot_session) {
		.version = VM_SNAPSHOT_SESSION_VERSION,
		.op = VM_SNAPSHOT_SESSION_BEGIN,
	};
	errno = 0;
	ATF_REQUIRE_EQ(vm_snapshot_session(ctx, &session), -1);
	ATF_REQUIRE_EQ(errno, EINVAL);
	ATF_REQUIRE_EQ(session.session_id, 0);
	vm_destroy(ctx);
}
ATF_TC_CLEANUP(empty_group_rejected, tc)
{

	cleanup_vm(tc);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, policy_and_descriptor_ownership);
	ATF_TP_ADD_TC(tp, copyout_fault_consumes_exact_operation);
	ATF_TP_ADD_TC(tp, final_close_aborts);
	ATF_TP_ADD_TC(tp, empty_group_rejected);
	return (atf_no_error());
}
