/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/dev/vmm/vmm_startup_event.c"

#define	OWNER_A	UINT64_C(0x1122334455667788)
#define	OWNER_B	UINT64_C(0x8877665544332211)

ATF_TC_WITHOUT_HEAD(order_and_coalescing);
ATF_TC_BODY(order_and_coalescing, tc)
{
	struct vmm_startup_event_receipt receipt;
	struct vmm_startup_event_state state;

	(void)tc;
	memset(&receipt, 0, sizeof(receipt));
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 7), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x21), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x42), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_init(&state), 0);
	ATF_CHECK_EQ(state.pending, VMM_STARTUP_EVENT_PENDING_INIT);
	ATF_CHECK_EQ(state.sipi_vector, 0);

	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x63), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_peek(&state, &receipt), 0);
	ATF_CHECK_EQ(receipt.kind, VMM_STARTUP_EVENT_INIT);
	ATF_CHECK_EQ(receipt.vector, 0);
	ATF_REQUIRE_EQ(vmm_startup_event_consume(&state, &receipt), 0);

	ATF_REQUIRE_EQ(vmm_startup_event_peek(&state, &receipt), 0);
	ATF_CHECK_EQ(receipt.kind, VMM_STARTUP_EVENT_SIPI);
	ATF_CHECK_EQ(receipt.vector, 0x63);
	ATF_REQUIRE_EQ(vmm_startup_event_consume(&state, &receipt), 0);
	ATF_CHECK_EQ(state.pending, 0);
	ATF_CHECK_EQ(vmm_startup_event_peek(&state, &receipt), ENOENT);
}

ATF_TC_WITHOUT_HEAD(stale_and_cross_owner);
ATF_TC_BODY(stale_and_cross_owner, tc)
{
	struct vmm_startup_event_receipt copied, receipt;
	struct vmm_startup_event_state left, right;

	(void)tc;
	memset(&receipt, 0, sizeof(receipt));
	ATF_REQUIRE_EQ(vmm_startup_event_init(&left, OWNER_A, 3), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_init(&right, OWNER_B, 3), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_init(&left), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_init(&right), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_peek(&left, &receipt), 0);
	ATF_CHECK_EQ(vmm_startup_event_consume(&right, &receipt), ESTALE);
	copied = receipt;
	ATF_CHECK_EQ(vmm_startup_event_consume(&left, &copied), ESTALE);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&left, 0x44), 0);
	ATF_CHECK_EQ(vmm_startup_event_consume(&left, &receipt), ESTALE);
	memset(&receipt, 0, sizeof(receipt));
	ATF_REQUIRE_EQ(vmm_startup_event_peek(&left, &receipt), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_consume(&left, &receipt), 0);
}

ATF_TC_WITHOUT_HEAD(failure_atomicity);
ATF_TC_BODY(failure_atomicity, tc)
{
	struct vmm_startup_event_receipt receipt, receipt_before;
	struct vmm_startup_event_state before, moved, state;

	(void)tc;
	memset(&receipt, 0, sizeof(receipt));
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 1), 0);
	moved = state;
	ATF_CHECK_EQ(vmm_startup_event_validate(&moved), EINVAL);
	before = state;
	ATF_CHECK_EQ(vmm_startup_event_peek(&state,
	    (struct vmm_startup_event_receipt *)&state), EINVAL);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_peek(&state, &receipt), 0);
	receipt_before = receipt;
	before = state;
	receipt.vector = 1;
	ATF_CHECK_EQ(vmm_startup_event_consume(&state, &receipt), ESTALE);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	receipt = receipt_before;
	ATF_REQUIRE_EQ(vmm_startup_event_consume(&state, &receipt), 0);
}

ATF_TC_WITHOUT_HEAD(overflow_and_reset);
ATF_TC_BODY(overflow_and_reset, tc)
{
	struct vmm_startup_event_receipt receipt, receipt_before;
	struct vmm_startup_event_state before, state;

	(void)tc;
	memset(&receipt, 0, sizeof(receipt));
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, UINT32_MAX), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_init(&state), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_peek(&state, &receipt), 0);
	state.generation = UINT64_MAX;
	receipt.generation = UINT64_MAX;
	before = state;
	receipt_before = receipt;
	ATF_CHECK_EQ(vmm_startup_event_consume(&state, &receipt), EOVERFLOW);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	ATF_CHECK(memcmp(&receipt, &receipt_before, sizeof(receipt)) == 0);
	ATF_CHECK_EQ(vmm_startup_event_publish_init(&state), EOVERFLOW);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	ATF_CHECK_EQ(vmm_startup_event_reset(&state), EOVERFLOW);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);

	state.generation = 9;
	ATF_REQUIRE_EQ(vmm_startup_event_reset(&state), 0);
	ATF_CHECK_EQ(state.generation, 10);
	ATF_CHECK_EQ(state.pending, 0);
	ATF_CHECK_EQ(state.sipi_vector, 0);
}

ATF_TC_WITHOUT_HEAD(claim_preserves_later_publication);
ATF_TC_BODY(claim_preserves_later_publication, tc)
{
	struct vmm_startup_event_claim claim;
	struct vmm_startup_event_receipt receipt;
	struct vmm_startup_event_state state;

	(void)tc;
	memset(&claim, 0, sizeof(claim));
	memset(&receipt, 0, sizeof(receipt));
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 4), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_init(&state), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_begin(&state, &claim), 0);
	ATF_CHECK_EQ(claim.kind, VMM_STARTUP_EVENT_INIT);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x52), 0);
	ATF_CHECK_EQ(vmm_startup_event_claim_begin(&state,
	    &(struct vmm_startup_event_claim){ 0 }), EBUSY);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_finish(&state, &claim), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_peek(&state, &receipt), 0);
	ATF_CHECK_EQ(receipt.kind, VMM_STARTUP_EVENT_SIPI);
	ATF_CHECK_EQ(receipt.vector, 0x52);
	ATF_REQUIRE_EQ(vmm_startup_event_consume(&state, &receipt), 0);
}

ATF_TC_WITHOUT_HEAD(claim_abort_coalesces_by_age);
ATF_TC_BODY(claim_abort_coalesces_by_age, tc)
{
	struct vmm_startup_event_claim claim;
	struct vmm_startup_event_receipt receipt;
	struct vmm_startup_event_state state;

	(void)tc;
	memset(&claim, 0, sizeof(claim));
	memset(&receipt, 0, sizeof(receipt));
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 5), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x11), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_begin(&state, &claim), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_abort(&state, &claim), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_peek(&state, &receipt), 0);
	ATF_CHECK_EQ(receipt.kind, VMM_STARTUP_EVENT_SIPI);
	ATF_CHECK_EQ(receipt.vector, 0x11);
	ATF_REQUIRE_EQ(vmm_startup_event_consume(&state, &receipt), 0);

	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x11), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_begin(&state, &claim), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_init(&state), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_abort(&state, &claim), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_peek(&state, &receipt), 0);
	ATF_CHECK_EQ(receipt.kind, VMM_STARTUP_EVENT_INIT);
	ATF_REQUIRE_EQ(vmm_startup_event_consume(&state, &receipt), 0);
	ATF_CHECK_EQ(vmm_startup_event_peek(&state, &receipt), ENOENT);

	ATF_REQUIRE_EQ(vmm_startup_event_publish_init(&state), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_begin(&state, &claim), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x72), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_abort(&state, &claim), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_peek(&state, &receipt), 0);
	ATF_CHECK_EQ(receipt.kind, VMM_STARTUP_EVENT_INIT);
	ATF_REQUIRE_EQ(vmm_startup_event_consume(&state, &receipt), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_peek(&state, &receipt), 0);
	ATF_CHECK_EQ(receipt.kind, VMM_STARTUP_EVENT_SIPI);
	ATF_CHECK_EQ(receipt.vector, 0x72);
	ATF_REQUIRE_EQ(vmm_startup_event_consume(&state, &receipt), 0);
}

ATF_TC_WITHOUT_HEAD(claim_failure_atomicity);
ATF_TC_BODY(claim_failure_atomicity, tc)
{
	struct vmm_startup_event_claim claim, copied;
	struct vmm_startup_event_state before, state;

	(void)tc;
	memset(&claim, 0, sizeof(claim));
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 6), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_init(&state), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_begin(&state, &claim), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_check(&state, &claim), 0);
	ATF_CHECK_EQ(vmm_startup_event_reset(&state), EBUSY);
	before = state;
	copied = claim;
	ATF_CHECK_EQ(vmm_startup_event_claim_check(&state, &copied), ESTALE);
	ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
	state.active_claim_id = state.next_claim_id;
	ATF_CHECK_EQ(vmm_startup_event_validate(&state), EINVAL);
	state = before;
	copied = claim;
	ATF_CHECK_EQ(vmm_startup_event_claim_finish(&state, &copied), ESTALE);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	claim.vector = 1;
	ATF_CHECK_EQ(vmm_startup_event_claim_abort(&state, &claim), ESTALE);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	claim.vector = 0;
	/* Claim release must remain possible after the generation is exhausted. */
	state.generation = UINT64_MAX;
	ATF_REQUIRE_EQ(vmm_startup_event_claim_finish(&state, &claim), 0);
	ATF_CHECK_EQ(state.active_claim_id, 0);

	memset(&claim, 0, sizeof(claim));
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 6), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_init(&state), 0);
	state.generation = UINT64_MAX - 1;
	ATF_REQUIRE_EQ(vmm_startup_event_claim_begin(&state, &claim), 0);
	ATF_CHECK_EQ(state.generation, UINT64_MAX);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_abort(&state, &claim), 0);
	ATF_CHECK_EQ(state.active_claim_id, 0);
	ATF_CHECK_EQ(state.pending, VMM_STARTUP_EVENT_PENDING_INIT);

	/* The last allocatable claim can always be released. */
	memset(&claim, 0, sizeof(claim));
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 6), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x66), 0);
	state.next_claim_id = UINT64_MAX - 1;
	ATF_REQUIRE_EQ(vmm_startup_event_claim_begin(&state, &claim), 0);
	ATF_CHECK_EQ(claim.claim_id, UINT64_MAX - 1);
	ATF_CHECK_EQ(state.next_claim_id, UINT64_MAX);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_finish(&state, &claim), 0);

	/* Exhaustion closes only new admission and is failure-atomic. */
	memset(&claim, 0, sizeof(claim));
	ATF_REQUIRE_EQ(vmm_startup_event_publish_init(&state), 0);
	before = state;
	ATF_CHECK_EQ(vmm_startup_event_claim_begin(&state, &claim), EOVERFLOW);
	ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
	ATF_CHECK_EQ(memcmp(&claim,
	    &(struct vmm_startup_event_claim){ 0 }, sizeof(claim)), 0);
}

ATF_TC_WITHOUT_HEAD(claim_abort_cross_product);
ATF_TC_BODY(claim_abort_cross_product, tc)
{
	struct vmm_startup_event_claim claim;
	struct vmm_startup_event_receipt receipt;
	struct vmm_startup_event_state state;

	(void)tc;
	/* Older INIT is discarded by newer INIT, and the newer SIPI follows it. */
	memset(&claim, 0, sizeof(claim));
	memset(&receipt, 0, sizeof(receipt));
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 8), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_init(&state), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_begin(&state, &claim), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_init(&state), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x81), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_abort(&state, &claim), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_peek(&state, &receipt), 0);
	ATF_CHECK_EQ(receipt.kind, VMM_STARTUP_EVENT_INIT);
	ATF_REQUIRE_EQ(vmm_startup_event_consume(&state, &receipt), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_peek(&state, &receipt), 0);
	ATF_CHECK_EQ(receipt.kind, VMM_STARTUP_EVENT_SIPI);
	ATF_CHECK_EQ(receipt.vector, 0x81);
	ATF_REQUIRE_EQ(vmm_startup_event_consume(&state, &receipt), 0);

	/* Older SIPI is discarded by a newer SIPI. */
	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x82), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_begin(&state, &claim), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x83), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_abort(&state, &claim), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_peek(&state, &receipt), 0);
	ATF_CHECK_EQ(receipt.kind, VMM_STARTUP_EVENT_SIPI);
	ATF_CHECK_EQ(receipt.vector, 0x83);
	ATF_REQUIRE_EQ(vmm_startup_event_consume(&state, &receipt), 0);
}

ATF_TC_WITHOUT_HEAD(publish_claim_atomicity);
ATF_TC_BODY(publish_claim_atomicity, tc)
{
	struct vmm_startup_event_claim active_claim, claim;
	struct vmm_startup_event_receipt receipt;
	struct vmm_startup_event_state before, state;

	(void)tc;
	memset(&claim, 0, sizeof(claim));
	memset(&receipt, 0, sizeof(receipt));
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 9), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x31), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_claim(&state,
	    VMM_STARTUP_EVENT_INIT, 0, &claim), 0);
	ATF_CHECK_EQ(claim.kind, VMM_STARTUP_EVENT_INIT);
	ATF_CHECK_EQ(state.pending, 0);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_finish(&state, &claim), 0);

	/* A later SIPI remains pending behind the atomically claimed INIT. */
	ATF_REQUIRE_EQ(vmm_startup_event_publish_init(&state), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_claim(&state,
	    VMM_STARTUP_EVENT_SIPI, 0x72, &claim), 0);
	ATF_CHECK_EQ(claim.kind, VMM_STARTUP_EVENT_INIT);
	ATF_CHECK_EQ(state.pending, VMM_STARTUP_EVENT_PENDING_SIPI);
	ATF_CHECK_EQ(state.sipi_vector, 0x72);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_finish(&state, &claim), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_peek(&state, &receipt), 0);
	ATF_CHECK_EQ(receipt.kind, VMM_STARTUP_EVENT_SIPI);
	ATF_CHECK_EQ(receipt.vector, 0x72);
	ATF_REQUIRE_EQ(vmm_startup_event_consume(&state, &receipt), 0);

	/* Both finite identities are preflighted without partial publication. */
	state.generation = UINT64_MAX - 1;
	before = state;
	ATF_CHECK_EQ(vmm_startup_event_publish_claim(&state,
	    VMM_STARTUP_EVENT_INIT, 0, &claim), EOVERFLOW);
	ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
	ATF_CHECK_EQ(memcmp(&claim,
	    &(struct vmm_startup_event_claim){ 0 }, sizeof(claim)), 0);
	state.generation = 20;
	state.next_claim_id = UINT64_MAX;
	before = state;
	ATF_CHECK_EQ(vmm_startup_event_publish_claim(&state,
	    VMM_STARTUP_EVENT_SIPI, 0x44, &claim), EOVERFLOW);
	ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
	ATF_CHECK_EQ(memcmp(&claim,
	    &(struct vmm_startup_event_claim){ 0 }, sizeof(claim)), 0);

	/*
	 * An existing machine-side claim closes the whole composite operation.
	 * In particular, publish_claim() must not publish its requested event and
	 * then discover that it cannot acquire a claim: callers rely on this
	 * helper being one failure-atomic transaction rather than a convenience
	 * sequence of two independently visible state changes.
	 */
	memset(&active_claim, 0, sizeof(active_claim));
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 10), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_init(&state), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_begin(&state, &active_claim), 0);
	before = state;
	ATF_CHECK_EQ(vmm_startup_event_publish_claim(&state,
	    VMM_STARTUP_EVENT_SIPI, 0x45, &claim), EBUSY);
	ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
	ATF_CHECK_EQ(memcmp(&claim,
	    &(struct vmm_startup_event_claim){ 0 }, sizeof(claim)), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_finish(&state, &active_claim), 0);

	before = state;
	ATF_CHECK_EQ(vmm_startup_event_publish_claim(&state,
	    VMM_STARTUP_EVENT_INIT, 1, &claim), EINVAL);
	ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
}

ATF_TC_WITHOUT_HEAD(run_token_closes_frozen_entry_window);
ATF_TC_BODY(run_token_closes_frozen_entry_window, tc)
{
	struct vmm_startup_event_claim claim;
	struct vmm_startup_event_run_token before_token, token;
	struct vmm_startup_event_state before_state, state;

	(void)tc;
	memset(&claim, 0, sizeof(claim));
	memset(&token, 0, sizeof(token));
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, 91, 3), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_run_token_capture(&state, &token), 0);
	ATF_CHECK_EQ(vmm_startup_event_run_token_check(&state, &token), 0);

	/* A publication before RUNNING validation forces a complete replay. */
	ATF_REQUIRE_EQ(vmm_startup_event_publish_init(&state), 0);
	ATF_CHECK_EQ(vmm_startup_event_run_token_check(&state, &token), EAGAIN);
	memset(&token, 0, sizeof(token));
	ATF_REQUIRE_EQ(vmm_startup_event_run_token_capture(&state, &token), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_claim_begin(&state, &claim), 0);
	ATF_CHECK_EQ(vmm_startup_event_run_token_check(&state, &token), EAGAIN);

	/* Claim release changes ownership even though it does not advance gen. */
	memset(&token, 0, sizeof(token));
	ATF_REQUIRE_EQ(vmm_startup_event_run_token_capture(&state, &token), 0);
	before_token = token;
	ATF_REQUIRE_EQ(vmm_startup_event_claim_finish(&state, &claim), 0);
	ATF_CHECK_EQ(state.generation, before_token.generation);
	ATF_CHECK_EQ(vmm_startup_event_run_token_check(&state, &token), EAGAIN);

	/* Rejection never changes either owner or caller output. */
	memset(&token, 0xa5, sizeof(token));
	before_token = token;
	before_state = state;
	ATF_CHECK_EQ(vmm_startup_event_run_token_capture(&state, &token),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&token, &before_token, sizeof(token)), 0);
	ATF_CHECK_EQ(memcmp(&state, &before_state, sizeof(state)), 0);
	ATF_CHECK_EQ(vmm_startup_event_run_token_capture(&state,
	    (struct vmm_startup_event_run_token *)(void *)&state), EINVAL);
	ATF_CHECK_EQ(memcmp(&state, &before_state, sizeof(state)), 0);

	memset(&token, 0, sizeof(token));
	ATF_REQUIRE_EQ(vmm_startup_event_run_token_capture(&state, &token), 0);
	before_token = token;
	before_state = state;
	token.reserved = 1;
	ATF_CHECK_EQ(vmm_startup_event_run_token_check(&state, &token), EINVAL);
	ATF_CHECK_EQ(memcmp(&state, &before_state, sizeof(state)), 0);
	token = before_token;
	token.owner_id++;
	ATF_CHECK_EQ(vmm_startup_event_run_token_check(&state, &token), ESTALE);
	token = before_token;
	token.vcpuid++;
	ATF_CHECK_EQ(vmm_startup_event_run_token_check(&state, &token), ESTALE);
	token = before_token;
	token.generation++;
	ATF_CHECK_EQ(vmm_startup_event_run_token_check(&state, &token), EAGAIN);
	ATF_CHECK_EQ(memcmp(&state, &before_state, sizeof(state)), 0);
}

ATF_TC_WITHOUT_HEAD(receipt_corruption_matrix);
ATF_TC_BODY(receipt_corruption_matrix, tc)
{
	struct vmm_startup_event_state state, before;
	struct vmm_startup_event_receipt credential, saved;
	unsigned i;

	(void)tc;
	for (i = 0; i < 13; i++) {
		ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 7), 0);
		ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x42), 0);
		memset(&credential, 0, sizeof(credential));
		ATF_REQUIRE_EQ(vmm_startup_event_peek(&state, &credential), 0);
		switch (i) {
		case 0: credential.active = 0; break;
		case 1: credential.active = 2; break;
		case 2: credential.reserved8 = 1; break;
		case 3: credential.reserved32 = 1; break;
		case 4: credential.kind = VMM_STARTUP_EVENT_NONE; break;
		case 5: credential.kind = VMM_STARTUP_EVENT_KIND_LAST; break;
		case 6: credential.owner_id++; break;
		case 7: credential.generation++; break;
		case 8: credential.state_cookie = 0; break;
		case 9: credential.storage_cookie = 0; break;
		case 10: credential.vcpuid++; break;
		case 11: credential.kind = VMM_STARTUP_EVENT_INIT; break;
		case 12: credential.vector++; break;
		}
		before = state;
		saved = credential;
		ATF_CHECK_EQ(vmm_startup_event_consume(&state, &credential), ESTALE);
		ATF_CHECK_EQ(memcmp(&before, &state, sizeof(state)), 0);
		ATF_CHECK_EQ(memcmp(&saved, &credential, sizeof(credential)), 0);
	}
}

ATF_TC_WITHOUT_HEAD(claim_corruption_matrix);
ATF_TC_BODY(claim_corruption_matrix, tc)
{
	struct vmm_startup_event_state state, before;
	struct vmm_startup_event_claim credential, saved;
	unsigned i;

	(void)tc;
	for (i = 0; i < 13; i++) {
		ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 7), 0);
		ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x42), 0);
		memset(&credential, 0, sizeof(credential));
		ATF_REQUIRE_EQ(vmm_startup_event_claim_begin(&state, &credential), 0);
		switch (i) {
		case 0: credential.active = 0; break;
		case 1: credential.active = 2; break;
		case 2: credential.reserved8 = 1; break;
		case 3: credential.reserved32 = 1; break;
		case 4: credential.kind = VMM_STARTUP_EVENT_NONE; break;
		case 5: credential.kind = VMM_STARTUP_EVENT_KIND_LAST; break;
		case 6: credential.owner_id++; break;
		case 7: credential.claim_id++; break;
		case 8: credential.state_cookie = 0; break;
		case 9: credential.storage_cookie = 0; break;
		case 10: credential.vcpuid++; break;
		case 11: credential.kind = VMM_STARTUP_EVENT_INIT; break;
		case 12: credential.vector++; break;
		}
		before = state;
		saved = credential;
		ATF_CHECK_EQ(vmm_startup_event_claim_check(&state, &credential), ESTALE);
		ATF_CHECK_EQ(vmm_startup_event_claim_finish(&state, &credential), ESTALE);
		ATF_CHECK_EQ(vmm_startup_event_claim_abort(&state, &credential), ESTALE);
		ATF_CHECK_EQ(memcmp(&before, &state, sizeof(state)), 0);
		ATF_CHECK_EQ(memcmp(&saved, &credential, sizeof(credential)), 0);
	}
}

ATF_TC_WITHOUT_HEAD(state_and_token_corruption_matrix);
ATF_TC_BODY(state_and_token_corruption_matrix, tc)
{
	struct vmm_startup_event_state state, before;
	struct vmm_startup_event_run_token token, saved;
	struct vmm_startup_event_claim claim;
	struct vmm_startup_event_receipt receipt;
	unsigned i;

	(void)tc;
	for (i = 0; i < 12; i++) {
		ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 7), 0);
		memset(&token, 0, sizeof(token));
		ATF_REQUIRE_EQ(vmm_startup_event_run_token_capture(&state, &token), 0);
		switch (i) {
		case 0: token.owner_id = 0; break;
		case 1: token.generation = 0; break;
		case 2: token.next_claim_id = 0; break;
		case 3: token.reserved = 1; break;
		case 4: token.pending = 0x80; break;
		case 5: token.sipi_vector = 1; break;
		case 6: token.active_kind = VMM_STARTUP_EVENT_INIT; break;
		case 7: token.active_vector = 1; break;
		case 8: token.active_claim_id = 1; break;
		case 9: token.active_claim_id = 1; token.next_claim_id = 2; break;
		case 10: token.active_claim_id = 1; token.next_claim_id = 2; token.active_kind = VMM_STARTUP_EVENT_KIND_LAST; break;
		case 11: token.active_claim_id = 1; token.next_claim_id = 2; token.active_kind = VMM_STARTUP_EVENT_INIT; token.active_vector = 1; break;
		}
		saved = token;
		before = state;
		ATF_CHECK_EQ(vmm_startup_event_run_token_validate(&token), EINVAL);
		ATF_CHECK_EQ(vmm_startup_event_run_token_check(&state, &token), EINVAL);
		ATF_CHECK_EQ(memcmp(&saved, &token, sizeof(token)), 0);
		ATF_CHECK_EQ(memcmp(&before, &state, sizeof(state)), 0);
		switch (i) {
		case 0: state.owner_id = 0; break;
		case 1: state.generation = 0; break;
		case 2: state.next_claim_id = 0; break;
		case 3: state.reserved = 1; break;
		case 4: state.pending = 0x80; break;
		case 5: state.sipi_vector = 1; break;
		case 6: state.active_kind = VMM_STARTUP_EVENT_INIT; break;
		case 7: state.active_vector = 1; break;
		case 8: state.active_claim_id = 1; break;
		case 9: state.active_claim_id = 1; state.next_claim_id = 2; break;
		case 10: state.active_claim_id = 1; state.next_claim_id = 2; state.active_kind = VMM_STARTUP_EVENT_KIND_LAST; break;
		case 11: state.active_claim_id = 1; state.next_claim_id = 2; state.active_kind = VMM_STARTUP_EVENT_INIT; state.active_vector = 1; break;
		}
		before = state;
		memset(&claim, 0, sizeof(claim));
		memset(&receipt, 0, sizeof(receipt));
		memset(&token, 0, sizeof(token));
		ATF_CHECK_EQ(vmm_startup_event_validate(&state), EINVAL);
		ATF_CHECK_EQ(vmm_startup_event_publish_init(&state), EINVAL);
		ATF_CHECK_EQ(vmm_startup_event_publish_sipi(&state, 0x42), EINVAL);
		ATF_CHECK_EQ(vmm_startup_event_peek(&state, &receipt), EINVAL);
		ATF_CHECK_EQ(vmm_startup_event_consume(&state, &receipt), EINVAL);
		ATF_CHECK_EQ(vmm_startup_event_claim_begin(&state, &claim), EINVAL);
		ATF_CHECK_EQ(vmm_startup_event_claim_check(&state, &claim), EINVAL);
		ATF_CHECK_EQ(vmm_startup_event_claim_finish(&state, &claim), EINVAL);
		ATF_CHECK_EQ(vmm_startup_event_claim_abort(&state, &claim), EINVAL);
		ATF_CHECK_EQ(vmm_startup_event_run_token_capture(&state, &token), EINVAL);
		ATF_CHECK_EQ(vmm_startup_event_reset(&state), EINVAL);
		ATF_CHECK_EQ(memcmp(&claim,
		    &(struct vmm_startup_event_claim){0}, sizeof(claim)), 0);
		ATF_CHECK_EQ(memcmp(&receipt,
		    &(struct vmm_startup_event_receipt){0}, sizeof(receipt)), 0);
		ATF_CHECK_EQ(memcmp(&token,
		    &(struct vmm_startup_event_run_token){0}, sizeof(token)), 0);
		ATF_CHECK_EQ(memcmp(&before, &state, sizeof(state)), 0);
	}
}

ATF_TC_WITHOUT_HEAD(receipt_nonempty_output);
ATF_TC_BODY(receipt_nonempty_output, tc)
{
	struct vmm_startup_event_state state, before;
	struct vmm_startup_event_receipt output, saved;
	unsigned i;

	(void)tc;
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 7), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x42), 0);
	before = state;
	for (i = 0; i < 10; i++) {
		memset(&output, 0, sizeof(output));
		switch (i) {
		case 0: output.owner_id = 1; break;
		case 1: output.generation = 1; break;
		case 2: output.state_cookie = 1; break;
		case 3: output.storage_cookie = 1; break;
		case 4: output.vcpuid = 1; break;
		case 5: output.kind = 1; break;
		case 6: output.vector = 1; break;
		case 7: output.active = 1; break;
		case 8: output.reserved8 = 1; break;
		case 9: output.reserved32 = 1; break;
		}
		saved = output;
		ATF_CHECK_EQ(vmm_startup_event_peek(&state, &output), EBUSY);
		ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
		ATF_CHECK_EQ(memcmp(&output, &saved, sizeof(output)), 0);
	}
}

ATF_TC_WITHOUT_HEAD(claim_nonempty_output);
ATF_TC_BODY(claim_nonempty_output, tc)
{
	struct vmm_startup_event_state state, before;
	struct vmm_startup_event_claim output, saved;
	unsigned i;

	(void)tc;
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 7), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x42), 0);
	before = state;
	for (i = 0; i < 10; i++) {
		memset(&output, 0, sizeof(output));
		switch (i) {
		case 0: output.owner_id = 1; break;
		case 1: output.claim_id = 1; break;
		case 2: output.state_cookie = 1; break;
		case 3: output.storage_cookie = 1; break;
		case 4: output.vcpuid = 1; break;
		case 5: output.kind = 1; break;
		case 6: output.vector = 1; break;
		case 7: output.active = 1; break;
		case 8: output.reserved8 = 1; break;
		case 9: output.reserved32 = 1; break;
		}
		saved = output;
		ATF_CHECK_EQ(vmm_startup_event_claim_begin(&state, &output), EBUSY);
		ATF_CHECK_EQ(vmm_startup_event_publish_claim(&state,
		    VMM_STARTUP_EVENT_SIPI, 0x42, &output), EINVAL);
		ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
		ATF_CHECK_EQ(memcmp(&output, &saved, sizeof(output)), 0);
	}
}

ATF_TC_WITHOUT_HEAD(run_token_nonempty_output);
ATF_TC_BODY(run_token_nonempty_output, tc)
{
	struct vmm_startup_event_state state, before;
	struct vmm_startup_event_run_token output, saved;
	unsigned i;

	(void)tc;
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 7), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x42), 0);
	before = state;
	for (i = 0; i < 10; i++) {
		memset(&output, 0, sizeof(output));
		switch (i) {
		case 0: output.owner_id = 1; break;
		case 1: output.generation = 1; break;
		case 2: output.next_claim_id = 1; break;
		case 3: output.active_claim_id = 1; break;
		case 4: output.vcpuid = 1; break;
		case 5: output.pending = 1; break;
		case 6: output.sipi_vector = 1; break;
		case 7: output.active_kind = 1; break;
		case 8: output.active_vector = 1; break;
		case 9: output.reserved = 1; break;
		}
		saved = output;
		ATF_CHECK_EQ(vmm_startup_event_run_token_capture(&state, &output), EINVAL);
		ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
		ATF_CHECK_EQ(memcmp(&output, &saved, sizeof(output)), 0);
	}
}

ATF_TC_WITHOUT_HEAD(null_and_alias_arguments);
ATF_TC_BODY(null_and_alias_arguments, tc)
{
	struct vmm_startup_event_state state, before;
	struct vmm_startup_event_receipt receipt;
	struct vmm_startup_event_claim claim;
	struct vmm_startup_event_run_token token;

	(void)tc;
	memset(&state, 0xa5, sizeof(state));
	before = state;
	ATF_CHECK_EQ(vmm_startup_event_init(NULL, OWNER_A, 7), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_init(&state, 0, 7), EINVAL);
	ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 7), 0);
	before = state;
	memset(&receipt, 0, sizeof(receipt));
	memset(&claim, 0, sizeof(claim));
	memset(&token, 0, sizeof(token));
	ATF_CHECK_EQ(vmm_startup_event_validate(NULL), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_run_token_validate(NULL), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_peek(NULL, &receipt), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_peek(&state, NULL), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_peek(&state,
	    (struct vmm_startup_event_receipt *)(void *)&state), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_consume(NULL, &receipt), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_consume(&state, NULL), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_consume(&state,
	    (struct vmm_startup_event_receipt *)(void *)&state), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_claim_begin(NULL, &claim), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_claim_begin(&state, NULL), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_claim_begin(&state,
	    (struct vmm_startup_event_claim *)(void *)&state), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_claim_check(NULL, &claim), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_claim_check(&state, NULL), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_claim_check(&state,
	    (struct vmm_startup_event_claim *)(void *)&state), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_claim_abort(NULL, &claim), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_claim_abort(&state, NULL), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_claim_abort(&state,
	    (struct vmm_startup_event_claim *)(void *)&state), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_claim_finish(NULL, &claim), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_claim_finish(&state, NULL), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_claim_finish(&state,
	    (struct vmm_startup_event_claim *)(void *)&state), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_run_token_capture(NULL, &token), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_run_token_capture(&state, NULL), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_run_token_capture(&state,
	    (struct vmm_startup_event_run_token *)(void *)&state), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_run_token_check(NULL, &token), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_run_token_check(&state, NULL), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_run_token_check(&state,
	    (struct vmm_startup_event_run_token *)(void *)&state), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_publish_claim(NULL,
	    VMM_STARTUP_EVENT_INIT, 0, &claim), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_publish_claim(&state,
	    VMM_STARTUP_EVENT_INIT, 0, NULL), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_publish_claim(&state,
	    VMM_STARTUP_EVENT_INIT, 0,
	    (struct vmm_startup_event_claim *)(void *)&state), EINVAL);
	ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
}

ATF_TC_WITHOUT_HEAD(valid_token_divergence);
ATF_TC_BODY(valid_token_divergence, tc)
{
	struct vmm_startup_event_state state, before;
	struct vmm_startup_event_claim claim;
	struct vmm_startup_event_run_token token, saved;
	unsigned i;

	(void)tc;
	memset(&claim, 0, sizeof(claim));
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 7), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_claim(&state,
	    VMM_STARTUP_EVENT_SIPI, 0, &claim), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_init(&state), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x42), 0);
	before = state;
	for (i = 0; i < 5; i++) {
		memset(&token, 0, sizeof(token));
		ATF_REQUIRE_EQ(vmm_startup_event_run_token_capture(&state, &token), 0);
		switch (i) {
		case 0: token.next_claim_id++; break;
		case 1: token.pending &= ~VMM_STARTUP_EVENT_PENDING_INIT; break;
		case 2: token.sipi_vector++; break;
		case 3: token.active_kind = VMM_STARTUP_EVENT_INIT; break;
		case 4: token.active_vector++; break;
		}
		saved = token;
		ATF_REQUIRE_EQ(vmm_startup_event_run_token_validate(&token), 0);
		ATF_CHECK_EQ(vmm_startup_event_run_token_check(&state, &token), EAGAIN);
		ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
		ATF_CHECK_EQ(memcmp(&token, &saved, sizeof(token)), 0);
	}
}

ATF_TC_WITHOUT_HEAD(active_claim_and_publication_failures);
ATF_TC_BODY(active_claim_and_publication_failures, tc)
{
	struct vmm_startup_event_state state, before;
	struct vmm_startup_event_claim claim, empty;
	struct vmm_startup_event_receipt receipt, saved;
	struct vmm_startup_event_run_token token;

	(void)tc;
	memset(&claim, 0, sizeof(claim));
	memset(&empty, 0, sizeof(empty));
	memset(&receipt, 0, sizeof(receipt));
	memset(&token, 0, sizeof(token));
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 7), 0);
	ATF_CHECK_EQ(vmm_startup_event_claim_begin(&state, &claim), ENOENT);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_sipi(&state, 0x42), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_peek(&state, &receipt), 0);
	/* A syntactically valid receipt cannot consume an absent event. */
	state.pending = state.sipi_vector = 0;
	before = state;
	saved = receipt;
	ATF_CHECK_EQ(vmm_startup_event_consume(&state, &receipt), ESTALE);
	ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
	ATF_CHECK_EQ(memcmp(&receipt, &saved, sizeof(receipt)), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_publish_claim(&state,
	    VMM_STARTUP_EVENT_INIT, 0, &claim), 0);
	memset(&receipt, 0, sizeof(receipt));
	before = state;
	ATF_CHECK_EQ(vmm_startup_event_peek(&state, &receipt), EBUSY);
	ATF_CHECK_EQ(vmm_startup_event_consume(&state, &receipt), EBUSY);
	ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
	ATF_CHECK_EQ(vmm_startup_event_publish_claim(&state,
	    VMM_STARTUP_EVENT_NONE, 0, &empty), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_publish_claim(&state,
	    VMM_STARTUP_EVENT_KIND_LAST, 0, &empty), EINVAL);
	ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
	state.storage_cookie = 0;
	before = state;
	ATF_CHECK_EQ(vmm_startup_event_publish_claim(&state,
	    VMM_STARTUP_EVENT_INIT, 0, &empty), EINVAL);
	ATF_CHECK_EQ(vmm_startup_event_run_token_check(&state, &token), EINVAL);
	ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
	ATF_REQUIRE_EQ(vmm_startup_event_init(&state, OWNER_A, 7), 0);
	state.generation = UINT64_MAX;
	before = state;
	ATF_CHECK_EQ(vmm_startup_event_publish_claim(&state,
	    VMM_STARTUP_EVENT_INIT, 0, &empty), EOVERFLOW);
	ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
	ATF_CHECK_EQ(memcmp(&empty,
	    &(struct vmm_startup_event_claim){0}, sizeof(empty)), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, order_and_coalescing);
	ATF_TP_ADD_TC(tp, stale_and_cross_owner);
	ATF_TP_ADD_TC(tp, failure_atomicity);
	ATF_TP_ADD_TC(tp, overflow_and_reset);
	ATF_TP_ADD_TC(tp, claim_preserves_later_publication);
	ATF_TP_ADD_TC(tp, claim_abort_coalesces_by_age);
	ATF_TP_ADD_TC(tp, claim_failure_atomicity);
	ATF_TP_ADD_TC(tp, claim_abort_cross_product);
	ATF_TP_ADD_TC(tp, publish_claim_atomicity);
	ATF_TP_ADD_TC(tp, run_token_closes_frozen_entry_window);
	ATF_TP_ADD_TC(tp, receipt_corruption_matrix);
	ATF_TP_ADD_TC(tp, claim_corruption_matrix);
	ATF_TP_ADD_TC(tp, state_and_token_corruption_matrix);
	ATF_TP_ADD_TC(tp, receipt_nonempty_output);
	ATF_TP_ADD_TC(tp, claim_nonempty_output);
	ATF_TP_ADD_TC(tp, run_token_nonempty_output);
	ATF_TP_ADD_TC(tp, null_and_alias_arguments);
	ATF_TP_ADD_TC(tp, valid_token_divergence);
	ATF_TP_ADD_TC(tp, active_claim_and_publication_failures);
	return (atf_no_error());
}
