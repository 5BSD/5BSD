/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <auditcmp.h>

#include "auditcmp_submit.h"

struct fake_backend {
	int	calls;
	int	event;
	int	result_error;
	int	result;
	int	failure;
	char	provider[AUDITCMP_MAX_SUBJECT + 1];
	char	subject[AUDITCMP_MAX_SUBJECT + 1];
	char	operation[AUDITCMP_MAX_OPERATION + 1];
};

static int
fake_submit(int event, int result_error, const char *provider,
    const char *subject, const char *operation, void *argument)
{
	struct fake_backend *fake;

	fake = argument;
	fake->calls++;
	fake->event = event;
	fake->result_error = result_error;
	strlcpy(fake->provider, provider, sizeof(fake->provider));
	strlcpy(fake->subject, subject, sizeof(fake->subject));
	strlcpy(fake->operation, operation, sizeof(fake->operation));
	if (fake->result == -1)
		errno = fake->failure;
	return (fake->result);
}

static struct auditcmp_submit_request
request(const char *subject, const char *operation, int error)
{
	struct auditcmp_submit_request result;

	memset(&result, 0, sizeof(result));
	result.subject_length = strlen(subject);
	result.operation_length = strlen(operation);
	result.error = error;
	memcpy(result.subject, subject, result.subject_length);
	memcpy(result.operation, operation, result.operation_length);
	return (result);
}

static struct auditcmp_backend
backend(struct fake_backend *fake)
{

	return ((struct auditcmp_backend){
	    .submit = fake_submit,
	    .context = fake
	});
}

ATF_TC(denial_and_rate_limit);
ATF_TC_HEAD(denial_and_rate_limit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "missing event authority and rate exhaustion never call audit_submit");
}
ATF_TC_BODY(denial_and_rate_limit, tc)
{
	struct auditcmp_submit_request record;
	struct auditcmp_backend operations;
	struct fake_backend fake;

	(void)tc;
	memset(&fake, 0, sizeof(fake));
	operations = backend(&fake);
	record = request("client", "write", 0);
	ATF_CHECK_EQ(EACCES, auditcmp_submit_record("provider", 0, &record,
	    true, &operations));
	ATF_CHECK_EQ(EAGAIN, auditcmp_submit_record("provider", 9000, &record,
	    false, &operations));
	ATF_CHECK_EQ(0, fake.calls);
}

ATF_TC(success_and_error_mapping);
ATF_TC_HEAD(success_and_error_mapping, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "validated fields and result status reach the backend exactly once");
}
ATF_TC_BODY(success_and_error_mapping, tc)
{
	struct auditcmp_submit_request record;
	struct auditcmp_backend operations;
	struct fake_backend fake;

	(void)tc;
	memset(&fake, 0, sizeof(fake));
	operations = backend(&fake);
	record = request("client-a", "rename", EPERM);
	ATF_CHECK_EQ(0, auditcmp_submit_record("provider-a", 9001, &record,
	    true, &operations));
	ATF_CHECK_EQ(1, fake.calls);
	ATF_CHECK_EQ(9001, fake.event);
	ATF_CHECK_EQ(EPERM, fake.result_error);
	ATF_CHECK_STREQ("provider-a", fake.provider);
	ATF_CHECK_STREQ("client-a", fake.subject);
	ATF_CHECK_STREQ("rename", fake.operation);
	fake.result = -1;
	fake.failure = ENOSPC;
	ATF_CHECK_EQ(ENOSPC, auditcmp_submit_record("provider-a", 9001,
	    &record, true, &operations));
	ATF_CHECK_EQ(2, fake.calls);
}

ATF_TC(field_validation);
ATF_TC_HEAD(field_validation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "empty, oversized, and embedded-NUL fields are rejected before audit");
}
ATF_TC_BODY(field_validation, tc)
{
	struct auditcmp_submit_request record;
	struct auditcmp_backend operations;
	struct fake_backend fake;

	(void)tc;
	memset(&fake, 0, sizeof(fake));
	operations = backend(&fake);
	record = request("client", "open", 0);
	record.subject_length = 0;
	ATF_CHECK_EQ(EINVAL, auditcmp_submit_record("provider", 1, &record,
	    true, &operations));
	record = request("client", "open", 0);
	record.operation_length = AUDITCMP_MAX_OPERATION + 1;
	ATF_CHECK_EQ(EINVAL, auditcmp_submit_record("provider", 1, &record,
	    true, &operations));
	record = request("client", "open", 0);
	record.subject[2] = '\0';
	ATF_CHECK_EQ(EINVAL, auditcmp_submit_record("provider", 1, &record,
	    true, &operations));
	ATF_CHECK_EQ(0, fake.calls);
}

ATF_TC(arguments);
ATF_TC_HEAD(arguments, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "required provider, request, and backend inputs are checked");
}
ATF_TC_BODY(arguments, tc)
{
	struct auditcmp_submit_request record;
	struct auditcmp_backend operations;
	struct fake_backend fake;

	(void)tc;
	memset(&fake, 0, sizeof(fake));
	operations = backend(&fake);
	record = request("client", "open", 0);
	ATF_CHECK_EQ(EINVAL, auditcmp_submit_record(NULL, 1, &record, true,
	    &operations));
	ATF_CHECK_EQ(EINVAL, auditcmp_submit_record("provider", 1, NULL, true,
	    &operations));
	ATF_CHECK_EQ(EINVAL, auditcmp_submit_record("provider", 1, &record,
	    true, NULL));
	operations.submit = NULL;
	ATF_CHECK_EQ(EINVAL, auditcmp_submit_record("provider", 1, &record,
	    true, &operations));
	ATF_CHECK_EQ(0, fake.calls);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, denial_and_rate_limit);
	ATF_TP_ADD_TC(tp, success_and_error_mapping);
	ATF_TP_ADD_TC(tp, field_validation);
	ATF_TP_ADD_TC(tp, arguments);
	return (atf_no_error());
}
