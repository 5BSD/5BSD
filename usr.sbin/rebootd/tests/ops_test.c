/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/reboot.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <rebootctl.h>

#include "rebootd_ops.h"

struct fake_backend {
	int	calls;
	int	last_howto;
	int	result;
	int	failure;
};

static int
fake_reboot(int howto, void *argument)
{
	struct fake_backend *fake;

	fake = argument;
	fake->calls++;
	fake->last_howto = howto;
	if (fake->result == -1)
		errno = fake->failure;
	return (fake->result);
}

static struct rebootd_backend
backend(struct fake_backend *fake)
{

	return ((struct rebootd_backend){
	    .reboot = fake_reboot,
	    .context = fake
	});
}

ATF_TC(denial_never_calls_backend);
ATF_TC_HEAD(denial_never_calls_backend, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "denied reboot and shutdown requests cannot invoke the backend");
}
ATF_TC_BODY(denial_never_calls_backend, tc)
{
	struct rebootctl_request request;
	struct rebootd_backend operations;
	struct fake_backend fake;
	_Atomic bool pending;

	(void)tc;
	memset(&fake, 0, sizeof(fake));
	memset(&request, 0, sizeof(request));
	operations = backend(&fake);
	atomic_init(&pending, false);
	ATF_CHECK_EQ(EACCES, rebootd_execute(REBOOTCTL_OP_REBOOT, &request,
	    false, &pending, &operations));
	ATF_CHECK_EQ(EACCES, rebootd_execute(REBOOTCTL_OP_SHUTDOWN, &request,
	    false, &pending, &operations));
	ATF_CHECK_EQ(0, fake.calls);
	ATF_CHECK(!atomic_load(&pending));
}

ATF_TC(flags_and_operation_validation);
ATF_TC_HEAD(flags_and_operation_validation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "unknown operations and invalid reboot flags are side-effect free");
}
ATF_TC_BODY(flags_and_operation_validation, tc)
{
	struct rebootctl_request request;
	struct rebootd_backend operations;
	struct fake_backend fake;
	_Atomic bool pending;

	(void)tc;
	memset(&fake, 0, sizeof(fake));
	memset(&request, 0, sizeof(request));
	operations = backend(&fake);
	atomic_init(&pending, false);
	request.howto = REBOOTCTL_ALLOWED_FLAGS | 0x40000000;
	ATF_CHECK_EQ(EINVAL, rebootd_execute(REBOOTCTL_OP_REBOOT, &request,
	    true, &pending, &operations));
	ATF_CHECK_EQ(EINVAL, rebootd_execute(REBOOTCTL_OP_REBOOT, NULL,
	    true, &pending, &operations));
	ATF_CHECK_EQ(EOPNOTSUPP, rebootd_execute(UINT16_MAX, &request,
	    true, &pending, &operations));
	ATF_CHECK_EQ(0, fake.calls);
	ATF_CHECK(!atomic_load(&pending));
}

ATF_TC(reboot_success_and_failure);
ATF_TC_HEAD(reboot_success_and_failure, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "reboot forwards allowed flags and rolls pending state back on error");
}
ATF_TC_BODY(reboot_success_and_failure, tc)
{
	struct rebootctl_request request;
	struct rebootd_backend operations;
	struct fake_backend fake;
	_Atomic bool pending;

	(void)tc;
	memset(&fake, 0, sizeof(fake));
	memset(&request, 0, sizeof(request));
	request.howto = RB_REROOT;
	operations = backend(&fake);
	atomic_init(&pending, false);
	ATF_CHECK_EQ(0, rebootd_execute(REBOOTCTL_OP_REBOOT, &request,
	    true, &pending, &operations));
	ATF_CHECK(atomic_load(&pending));
	ATF_CHECK_EQ(RB_REROOT, fake.last_howto);
	atomic_store(&pending, false);
	fake.result = -1;
	fake.failure = EPERM;
	ATF_CHECK_EQ(EPERM, rebootd_execute(REBOOTCTL_OP_REBOOT, &request,
	    true, &pending, &operations));
	ATF_CHECK(!atomic_load(&pending));
	ATF_CHECK_EQ(2, fake.calls);
}

ATF_TC(shutdown_and_status);
ATF_TC_HEAD(shutdown_and_status, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "shutdown selects halt/poweroff while status is read-only");
}

ATF_TC_BODY(shutdown_and_status, tc)
{
	struct rebootd_backend operations;
	struct fake_backend fake;
	_Atomic bool pending;

	(void)tc;
	memset(&fake, 0, sizeof(fake));
	operations = backend(&fake);
	atomic_init(&pending, false);
	ATF_CHECK_EQ(0, rebootd_execute(REBOOTCTL_OP_STATUS, NULL, false,
	    &pending, &operations));
	ATF_CHECK_EQ(0, fake.calls);
	ATF_CHECK_EQ(0, rebootd_execute(REBOOTCTL_OP_SHUTDOWN, NULL, true,
	    &pending, &operations));
	ATF_CHECK_EQ(1, fake.calls);
	ATF_CHECK_EQ(RB_HALT | RB_POWEROFF, fake.last_howto);
	ATF_CHECK(atomic_load(&pending));
	ATF_CHECK_EQ(EACCES, rebootd_execute(REBOOTCTL_OP_CANCEL, NULL, false,
	    &pending, &operations));
	ATF_CHECK(atomic_load(&pending));
	ATF_CHECK_EQ(0, rebootd_execute(REBOOTCTL_OP_CANCEL, NULL, true,
	    &pending, &operations));
	ATF_CHECK(!atomic_load(&pending));
	ATF_CHECK_EQ(ENOENT, rebootd_execute(REBOOTCTL_OP_CANCEL, NULL, true,
	    &pending, &operations));
	ATF_CHECK_EQ(1, fake.calls);
}

ATF_TC(pending_serializes_mutations);
ATF_TC_HEAD(pending_serializes_mutations, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "shared pending state rejects competing reboot operations without a backend call");
}
ATF_TC_BODY(pending_serializes_mutations, tc)
{
	struct rebootctl_request request;
	struct rebootd_backend operations;
	struct fake_backend fake;
	_Atomic bool pending;

	(void)tc;
	memset(&fake, 0, sizeof(fake));
	memset(&request, 0, sizeof(request));
	operations = backend(&fake);
	atomic_init(&pending, true);
	ATF_CHECK_EQ(EALREADY, rebootd_execute(REBOOTCTL_OP_REBOOT, &request,
	    true, &pending, &operations));
	ATF_CHECK_EQ(EALREADY, rebootd_execute(REBOOTCTL_OP_SHUTDOWN, NULL,
	    true, &pending, &operations));
	ATF_CHECK_EQ(0, fake.calls);
	ATF_CHECK(atomic_load(&pending));
	ATF_CHECK_EQ(0, rebootd_execute(REBOOTCTL_OP_STATUS, NULL, false,
	    &pending, &operations));
	ATF_CHECK(atomic_load(&pending));
}

ATF_TC(arguments);
ATF_TC_HEAD(arguments, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "required state and backend arguments are validated");
}

ATF_TC_BODY(arguments, tc)
{
	struct rebootctl_request request;
	struct rebootd_backend operations;
	struct fake_backend fake;
	_Atomic bool pending;

	(void)tc;
	memset(&fake, 0, sizeof(fake));
	memset(&request, 0, sizeof(request));
	operations = backend(&fake);
	atomic_init(&pending, false);
	ATF_CHECK_EQ(EINVAL, rebootd_execute(REBOOTCTL_OP_REBOOT, &request,
	    true, NULL, &operations));
	ATF_CHECK_EQ(EINVAL, rebootd_execute(REBOOTCTL_OP_REBOOT, &request,
	    true, &pending, NULL));
	operations.reboot = NULL;
	ATF_CHECK_EQ(EINVAL, rebootd_execute(REBOOTCTL_OP_REBOOT, &request,
	    true, &pending, &operations));
	ATF_CHECK_EQ(0, fake.calls);
}

ATF_TC(pending_is_shared_across_workers);
ATF_TC_HEAD(pending_is_shared_across_workers, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a reboot initiated by one forked worker is visible to other sessions");
}
ATF_TC_BODY(pending_is_shared_across_workers, tc)
{
	struct rebootctl_request request;
	struct rebootd_backend operations;
	struct fake_backend fake;
	_Atomic bool *pending;
	pid_t pid;
	int status;

	(void)tc;
	pending = mmap(NULL, sizeof(*pending), PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_SHARED, -1, 0);
	ATF_REQUIRE(pending != MAP_FAILED);
	atomic_init(pending, false);
	memset(&fake, 0, sizeof(fake));
	memset(&request, 0, sizeof(request));
	operations = backend(&fake);
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0)
		_exit(rebootd_execute(REBOOTCTL_OP_REBOOT, &request, true,
		    pending, &operations));
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	ATF_CHECK(atomic_load(pending));
	ATF_CHECK_EQ(0, rebootd_execute(REBOOTCTL_OP_STATUS, NULL, false,
	    pending, &operations));
	ATF_CHECK_EQ(EALREADY, rebootd_execute(REBOOTCTL_OP_SHUTDOWN, NULL,
	    true, pending, &operations));
	ATF_CHECK_EQ(0, fake.calls);
	ATF_REQUIRE_EQ(0, munmap(pending, sizeof(*pending)));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, denial_never_calls_backend);
	ATF_TP_ADD_TC(tp, flags_and_operation_validation);
	ATF_TP_ADD_TC(tp, reboot_success_and_failure);
	ATF_TP_ADD_TC(tp, shutdown_and_status);
	ATF_TP_ADD_TC(tp, pending_serializes_mutations);
	ATF_TP_ADD_TC(tp, arguments);
	ATF_TP_ADD_TC(tp, pending_is_shared_across_workers);
	return (atf_no_error());
}
