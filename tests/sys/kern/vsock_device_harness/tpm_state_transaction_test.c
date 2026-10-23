/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <errno.h>
#include <string.h>

#include "../../../../usr.sbin/bhyve/tpm_state_transaction.c"

struct model {
	char calls[16];
	size_t count;
	char fail;
};

static int
record(struct model *model, char operation)
{

	ATF_REQUIRE(model->count + 1 < sizeof(model->calls));
	model->calls[model->count++] = operation;
	model->calls[model->count] = '\0';
	if (model->fail == operation) {
		model->fail = 0;
		return (EIO);
	}
	return (0);
}

static int pause_model(void *arg) { return (record(arg, 'p')); }
static int resume_model(void *arg) { return (record(arg, 'r')); }
static int stop_model(void *arg) { return (record(arg, 's')); }
static int init_model(void *arg) { return (record(arg, 'i')); }

static const struct tpm_state_transaction_ops ops = {
	.pause = pause_model,
	.resume = resume_model,
	.stop = stop_model,
	.init = init_model,
};

ATF_TC_WITHOUT_HEAD(success_and_duplicate_begin);
ATF_TC_BODY(success_and_duplicate_begin, tc)
{
	struct tpm_state_transaction transaction = { 0 };
	struct model model = { 0 };

	(void)tc;
	ATF_REQUIRE_EQ(tpm_state_transaction_begin_write(&transaction, &ops,
	    &model, &model), 0);
	ATF_CHECK_EQ(transaction.phase, TPM_STATE_STOPPED);
	ATF_CHECK_EQ(tpm_state_transaction_begin_write(&transaction, &ops,
	    &model, &model), EBUSY);
	ATF_REQUIRE_EQ(tpm_state_transaction_end(&transaction, &ops,
	    &model, &model), 0);
	ATF_CHECK_EQ(transaction.phase, TPM_STATE_RUNNING);
	ATF_CHECK_STREQ(model.calls, "psir");
}

ATF_TC_WITHOUT_HEAD(stop_failure_keeps_worker_fenced);
ATF_TC_BODY(stop_failure_keeps_worker_fenced, tc)
{
	struct tpm_state_transaction transaction = { 0 };
	struct model model = { .fail = 's' };

	(void)tc;
	ATF_CHECK_EQ(tpm_state_transaction_begin_write(&transaction, &ops,
	    &model, &model), EIO);
	ATF_CHECK_EQ(transaction.phase, TPM_STATE_UNCERTAIN);
	ATF_CHECK_EQ(tpm_state_transaction_end(&transaction, &ops,
	    &model, &model), EPROTO);
	ATF_CHECK_STREQ(model.calls, "ps");
}

ATF_TC_WITHOUT_HEAD(init_failure_keeps_worker_fenced);
ATF_TC_BODY(init_failure_keeps_worker_fenced, tc)
{
	struct tpm_state_transaction transaction = { 0 };
	struct model model = { 0 };

	(void)tc;
	ATF_REQUIRE_EQ(tpm_state_transaction_begin_write(&transaction, &ops,
	    &model, &model), 0);
	model.fail = 'i';
	ATF_CHECK_EQ(tpm_state_transaction_end(&transaction, &ops,
	    &model, &model), EIO);
	ATF_CHECK_EQ(transaction.phase, TPM_STATE_UNCERTAIN);
	ATF_CHECK_EQ(tpm_state_transaction_end(&transaction, &ops,
	    &model, &model), EPROTO);
	ATF_CHECK_STREQ(model.calls, "psi");
}

ATF_TC_WITHOUT_HEAD(resume_failure_is_retryable);
ATF_TC_BODY(resume_failure_is_retryable, tc)
{
	struct tpm_state_transaction transaction = { 0 };
	struct model model = { 0 };

	(void)tc;
	ATF_REQUIRE_EQ(tpm_state_transaction_begin_write(&transaction, &ops,
	    &model, &model), 0);
	model.fail = 'r';
	ATF_CHECK_EQ(tpm_state_transaction_end(&transaction, &ops,
	    &model, &model), EIO);
	ATF_CHECK_EQ(transaction.phase, TPM_STATE_QUIESCED);
	ATF_REQUIRE_EQ(tpm_state_transaction_end(&transaction, &ops,
	    &model, &model), 0);
	ATF_CHECK_STREQ(model.calls, "psirr");
}

ATF_TC_WITHOUT_HEAD(read_keeps_backend_running);
ATF_TC_BODY(read_keeps_backend_running, tc)
{
	struct tpm_state_transaction transaction = { 0 };
	struct model model = { 0 };

	(void)tc;
	ATF_REQUIRE_EQ(tpm_state_transaction_begin_read(&transaction, &ops,
	    &model, &model), 0);
	ATF_CHECK_EQ(transaction.phase, TPM_STATE_QUIESCED);
	ATF_REQUIRE_EQ(tpm_state_transaction_end(&transaction, &ops,
	    &model, &model), 0);
	ATF_CHECK_EQ(transaction.phase, TPM_STATE_RUNNING);
	ATF_CHECK_STREQ(model.calls, "pr");
}

ATF_TC_WITHOUT_HEAD(read_then_write_does_not_pause_twice);
ATF_TC_BODY(read_then_write_does_not_pause_twice, tc)
{
	struct tpm_state_transaction transaction = { 0 };
	struct model model = { 0 };

	(void)tc;
	ATF_REQUIRE_EQ(tpm_state_transaction_begin_read(&transaction, &ops,
	    &model, &model), 0);
	ATF_REQUIRE_EQ(tpm_state_transaction_begin_write(&transaction, &ops,
	    &model, &model), 0);
	ATF_CHECK_EQ(transaction.phase, TPM_STATE_STOPPED);
	ATF_REQUIRE_EQ(tpm_state_transaction_end(&transaction, &ops,
	    &model, &model), 0);
	ATF_CHECK_STREQ(model.calls, "psir");
}

ATF_TC_WITHOUT_HEAD(read_then_write_stop_failure_stays_fenced);
ATF_TC_BODY(read_then_write_stop_failure_stays_fenced, tc)
{
	struct tpm_state_transaction transaction = { 0 };
	struct model model = { .fail = 's' };

	(void)tc;
	ATF_REQUIRE_EQ(tpm_state_transaction_begin_read(&transaction, &ops,
	    &model, &model), 0);
	ATF_CHECK_EQ(tpm_state_transaction_begin_write(&transaction, &ops,
	    &model, &model), EIO);
	ATF_CHECK_EQ(transaction.phase, TPM_STATE_UNCERTAIN);
	ATF_CHECK_EQ(tpm_state_transaction_end(&transaction, &ops,
	    &model, &model), EPROTO);
	ATF_CHECK_STREQ(model.calls, "ps");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, success_and_duplicate_begin);
	ATF_TP_ADD_TC(tp, stop_failure_keeps_worker_fenced);
	ATF_TP_ADD_TC(tp, init_failure_keeps_worker_fenced);
	ATF_TP_ADD_TC(tp, resume_failure_is_retryable);
	ATF_TP_ADD_TC(tp, read_keeps_backend_running);
	ATF_TP_ADD_TC(tp, read_then_write_does_not_pause_twice);
	ATF_TP_ADD_TC(tp, read_then_write_stop_failure_stays_fenced);
	return (atf_no_error());
}
