/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/param.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <kldmgr.h>

#include "kldmgrd_ops.h"

struct fake_backend {
	int	load_calls;
	int	find_calls;
	int	unload_calls;
	int	next_calls;
	int	stat_calls;
	int	load_result;
	int	find_result;
	int	unload_result;
	int	failure;
	int	last_id;
	int	module_count;
	int	next_failure_call;
	int	stat_failure_id;
	char	last_name[KLDMGR_NAME_MAX];
};

static int
fake_load(const char *name, void *argument)
{
	struct fake_backend *fake;

	fake = argument;
	fake->load_calls++;
	strlcpy(fake->last_name, name, sizeof(fake->last_name));
	if (fake->load_result == -1)
		errno = fake->failure;
	return (fake->load_result);
}

static int
fake_find(const char *name, void *argument)
{
	struct fake_backend *fake;

	fake = argument;
	fake->find_calls++;
	strlcpy(fake->last_name, name, sizeof(fake->last_name));
	if (fake->find_result == -1)
		errno = fake->failure;
	return (fake->find_result);
}

static int
fake_unload(int id, void *argument)
{
	struct fake_backend *fake;

	fake = argument;
	fake->unload_calls++;
	fake->last_id = id;
	if (fake->unload_result == -1)
		errno = fake->failure;
	return (fake->unload_result);
}

static int
fake_next(int id, void *argument)
{
	struct fake_backend *fake;

	fake = argument;
	fake->next_calls++;
	if (fake->next_failure_call == fake->next_calls) {
		errno = fake->failure;
		return (-1);
	}
	return (id < fake->module_count ? id + 1 : 0);
}

static int
fake_stat(int id, struct kld_file_stat *status, void *argument)
{
	struct fake_backend *fake;

	fake = argument;
	fake->stat_calls++;
	if (id == fake->stat_failure_id) {
		errno = fake->failure;
		return (-1);
	}
	(void)snprintf(status->name, sizeof(status->name), "module%d", id);
	return (0);
}

static struct kldmgrd_backend
backend(struct fake_backend *fake)
{

	return ((struct kldmgrd_backend){
	    .load = fake_load,
	    .find = fake_find,
	    .unload = fake_unload,
	    .next = fake_next,
	    .stat = fake_stat,
	    .context = fake
	});
}

static struct kldmgr_module_request
request(const char *name)
{
	struct kldmgr_module_request result;

	memset(&result, 0, sizeof(result));
	strlcpy(result.name, name, sizeof(result.name));
	return (result);
}

ATF_TC(name_validation);
ATF_TC_HEAD(name_validation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "module names reject empty, unterminated, and metacharacter input");
}
ATF_TC_BODY(name_validation, tc)
{
	char unterminated[KLDMGR_NAME_MAX];

	(void)tc;
	memset(unterminated, 'a', sizeof(unterminated));
	ATF_CHECK(kldmgrd_module_name_valid("if_bridge", 10));
	ATF_CHECK(kldmgrd_module_name_valid("linux64.ko", 11));
	ATF_CHECK(!kldmgrd_module_name_valid("", 1));
	ATF_CHECK(!kldmgrd_module_name_valid(NULL, 1));
	ATF_CHECK(!kldmgrd_module_name_valid(unterminated,
	    sizeof(unterminated)));
	ATF_CHECK(!kldmgrd_module_name_valid("../evil", 8));
	ATF_CHECK(!kldmgrd_module_name_valid("x/y", 4));
	ATF_CHECK(!kldmgrd_module_name_valid("x;id", 5));
}

ATF_TC(denial_never_calls_backend);
ATF_TC_HEAD(denial_never_calls_backend, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "policy denial is terminal before any module backend operation");
}
ATF_TC_BODY(denial_never_calls_backend, tc)
{
	struct kldmgr_module_request module;
	struct kldmgrd_backend operations;
	struct fake_backend fake;
	int id;

	(void)tc;
	memset(&fake, 0, sizeof(fake));
	operations = backend(&fake);
	module = request("if_bridge");
	ATF_CHECK_EQ(EACCES, kldmgrd_execute_module(KLDMGR_OP_LOAD,
	    &module, false, &operations, &id));
	ATF_CHECK_EQ(EACCES, kldmgrd_execute_module(KLDMGR_OP_UNLOAD,
	    &module, false, &operations, &id));
	ATF_CHECK_EQ(0, fake.load_calls);
	ATF_CHECK_EQ(0, fake.find_calls);
	ATF_CHECK_EQ(0, fake.unload_calls);
}

ATF_TC(load_and_failure_mapping);
ATF_TC_HEAD(load_and_failure_mapping, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "load success and backend errno are mapped without extra calls");
}
ATF_TC_BODY(load_and_failure_mapping, tc)
{
	struct kldmgr_module_request module;
	struct kldmgrd_backend operations;
	struct fake_backend fake;
	int id;

	(void)tc;
	memset(&fake, 0, sizeof(fake));
	fake.load_result = 42;
	operations = backend(&fake);
	module = request("if_bridge");
	ATF_CHECK_EQ(0, kldmgrd_execute_module(KLDMGR_OP_LOAD,
	    &module, true, &operations, &id));
	ATF_CHECK_EQ(42, id);
	ATF_CHECK_STREQ("if_bridge", fake.last_name);
	fake.load_result = -1;
	fake.failure = ENOENT;
	ATF_CHECK_EQ(ENOENT, kldmgrd_execute_module(KLDMGR_OP_LOAD,
	    &module, true, &operations, &id));
	ATF_CHECK_EQ(-1, id);
	ATF_CHECK_EQ(2, fake.load_calls);
}

ATF_TC(unload_order_and_atomic_failure);
ATF_TC_HEAD(unload_order_and_atomic_failure, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "unload finds first and never unloads after a failed lookup");
}
ATF_TC_BODY(unload_order_and_atomic_failure, tc)
{
	struct kldmgr_module_request module;
	struct kldmgrd_backend operations;
	struct fake_backend fake;
	int id;

	(void)tc;
	memset(&fake, 0, sizeof(fake));
	fake.find_result = 17;
	operations = backend(&fake);
	module = request("if_bridge");
	ATF_CHECK_EQ(0, kldmgrd_execute_module(KLDMGR_OP_UNLOAD,
	    &module, true, &operations, &id));
	ATF_CHECK_EQ(17, id);
	ATF_CHECK_EQ(17, fake.last_id);
	ATF_CHECK_EQ(1, fake.unload_calls);
	fake.find_result = -1;
	fake.failure = ENOENT;
	ATF_CHECK_EQ(ENOENT, kldmgrd_execute_module(KLDMGR_OP_UNLOAD,
	    &module, true, &operations, &id));
	ATF_CHECK_EQ(1, fake.unload_calls);
}

ATF_TC(invalid_arguments_and_opcode);
ATF_TC_HEAD(invalid_arguments_and_opcode, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "invalid arguments, names, and operations cannot reach the backend");
}

ATF_TC(list_policy_capacity_and_order);
ATF_TC_HEAD(list_policy_capacity_and_order, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "list denial is side-effect free and successful lists are bounded and ordered");
}
ATF_TC_BODY(list_policy_capacity_and_order, tc)
{
	struct kldmgr_list_entry entries[2];
	struct kldmgrd_backend operations;
	struct fake_backend fake;
	size_t count;

	(void)tc;
	memset(&fake, 0, sizeof(fake));
	memset(entries, 0, sizeof(entries));
	fake.module_count = 3;
	operations = backend(&fake);
	count = 99;
	ATF_CHECK_EQ(EACCES, kldmgrd_list(false, &operations, entries,
	    nitems(entries), &count));
	ATF_CHECK_EQ(0, count);
	ATF_CHECK_EQ(0, fake.next_calls);
	ATF_CHECK_EQ(0, fake.stat_calls);
	ATF_REQUIRE_EQ(0, kldmgrd_list(true, &operations, entries,
	    nitems(entries), &count));
	ATF_CHECK_EQ(2, count);
	ATF_CHECK_EQ(2, fake.next_calls);
	ATF_CHECK_EQ(2, fake.stat_calls);
	ATF_CHECK_EQ(1, entries[0].id);
	ATF_CHECK_STREQ("module1", entries[0].name);
	ATF_CHECK_EQ(2, entries[1].id);
	ATF_CHECK_STREQ("module2", entries[1].name);
}

ATF_TC(list_failure_is_not_partial_success);
ATF_TC_HEAD(list_failure_is_not_partial_success, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "enumeration and stat failures are returned without publishing a partial count");
}
ATF_TC_BODY(list_failure_is_not_partial_success, tc)
{
	struct kldmgr_list_entry entries[3];
	struct kldmgrd_backend operations;
	struct fake_backend fake;
	size_t count;

	(void)tc;
	memset(&fake, 0, sizeof(fake));
	fake.module_count = 3;
	fake.failure = EIO;
	fake.next_failure_call = 1;
	operations = backend(&fake);
	ATF_CHECK_EQ(EIO, kldmgrd_list(true, &operations, entries,
	    nitems(entries), &count));
	ATF_CHECK_EQ(0, count);
	ATF_CHECK_EQ(0, fake.stat_calls);

	memset(&fake, 0, sizeof(fake));
	fake.module_count = 3;
	fake.failure = ENOENT;
	fake.stat_failure_id = 2;
	operations = backend(&fake);
	ATF_CHECK_EQ(ENOENT, kldmgrd_list(true, &operations, entries,
	    nitems(entries), &count));
	ATF_CHECK_EQ(0, count);
	ATF_CHECK_EQ(2, fake.next_calls);
	ATF_CHECK_EQ(2, fake.stat_calls);

	ATF_CHECK_EQ(EINVAL, kldmgrd_list(true, NULL, entries,
	    nitems(entries), &count));
	ATF_CHECK_EQ(EINVAL, kldmgrd_list(true, &operations, NULL, 1, &count));
	ATF_CHECK_EQ(EINVAL, kldmgrd_list(true, &operations, entries,
	    nitems(entries), NULL));
}
ATF_TC_BODY(invalid_arguments_and_opcode, tc)
{
	struct kldmgr_module_request module;
	struct kldmgrd_backend operations;
	struct fake_backend fake;
	int id;

	(void)tc;
	memset(&fake, 0, sizeof(fake));
	operations = backend(&fake);
	module = request("../bad");
	ATF_CHECK_EQ(EINVAL, kldmgrd_execute_module(KLDMGR_OP_LOAD,
	    &module, true, &operations, &id));
	module = request("good");
	ATF_CHECK_EQ(EOPNOTSUPP, kldmgrd_execute_module(UINT16_MAX,
	    &module, true, &operations, &id));
	ATF_CHECK_EQ(EINVAL, kldmgrd_execute_module(KLDMGR_OP_LOAD,
	    NULL, true, &operations, &id));
	ATF_CHECK_EQ(EINVAL, kldmgrd_execute_module(KLDMGR_OP_LOAD,
	    &module, true, NULL, &id));
	ATF_CHECK_EQ(EINVAL, kldmgrd_execute_module(KLDMGR_OP_LOAD,
	    &module, true, &operations, NULL));
	ATF_CHECK_EQ(0, fake.load_calls);
	ATF_CHECK_EQ(0, fake.find_calls);
	ATF_CHECK_EQ(0, fake.unload_calls);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, name_validation);
	ATF_TP_ADD_TC(tp, denial_never_calls_backend);
	ATF_TP_ADD_TC(tp, load_and_failure_mapping);
	ATF_TP_ADD_TC(tp, unload_order_and_atomic_failure);
	ATF_TP_ADD_TC(tp, invalid_arguments_and_opcode);
	ATF_TP_ADD_TC(tp, list_policy_capacity_and_order);
	ATF_TP_ADD_TC(tp, list_failure_is_not_partial_success);
	return (atf_no_error());
}
