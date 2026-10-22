/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SHA256_DIGEST_LENGTH 32
#define DTRACED_HANDOFF_RESERVE 1
#define DTRACED_HANDOFF_CANCEL 2
#define DTRACED_HANDOFF_MUTATE 3
#define EPRINTLN(...) ((void)0)

struct vmctx { int unused; };
struct restore_state {
	uint8_t handoff_token[16];
	uint8_t handoff_digest[32];
	const void *hypertrace_transfer;
	size_t hypertrace_transfer_length;
	const void *hypertrace_private_image;
	size_t hypertrace_private_length;
	void *hypertrace_private_dev;
	int checkpoint_format_version;
};

enum step { BEGIN, STAGE, PENDING, PREFLIGHT, READY, RESERVE, CANCEL, MUTATION, IMPORT,
    DEVICE, DIGEST, QUERY };
static enum step steps[16], failing;
static size_t step_count;
static bool is_rebinding;
static const bool *mutation_started;

static bool
visit(enum step step)
{
	assert(step_count < sizeof(steps) / sizeof(steps[0]));
	steps[step_count++] = step;
	if (step == failing) {
		errno = EIO;
		return (false);
	}
	return (true);
}

static int
hypertrace_handoff_rebind_begin_optional(struct vmctx *ctx,
    const uint8_t *token, const uint8_t *digest, bool *rebinding)
{
	assert(ctx != NULL && token != NULL && digest != NULL);
	if (!visit(BEGIN))
		return (-1);
	*rebinding = is_rebinding;
	return (0);
}

static int
hypertrace_handoff_rebind_stage(struct vmctx *ctx, const uint8_t *token,
    const uint8_t *digest)
{
	assert(ctx != NULL && token != NULL && digest != NULL);
	return (visit(STAGE) ? 0 : -1);
}

static int
hypertrace_handoff_rebind_pending(struct vmctx *ctx, const uint8_t *token,
    const uint8_t *digest)
{
	assert(ctx != NULL && token != NULL && digest != NULL);
	return (visit(PENDING) ? 0 : -1);
}

static int
hypertrace_handoff_rebind_nonempty_preflight(struct vmctx *ctx,
    const uint8_t *token, const uint8_t *digest)
{
	assert(ctx != NULL && token != NULL && digest != NULL);
	return (visit(PREFLIGHT) ? 0 : -1);
}

static int
hypertrace_handoff_rebind_empty_ready(struct vmctx *ctx,
    const uint8_t *token, const uint8_t *digest)
{
	assert(ctx != NULL && token != NULL && digest != NULL);
	return (visit(READY) ? 0 : -1);
}

static int
hypertrace_handoff_destination_ensure(struct vmctx *ctx, uint8_t op,
    const uint8_t *token, const uint8_t *digest)
{
	assert(ctx != NULL && (op == DTRACED_HANDOFF_RESERVE ||
	    op == DTRACED_HANDOFF_CANCEL ||
	    op == DTRACED_HANDOFF_MUTATE) &&
	    token != NULL && digest != NULL);
	if (op == DTRACED_HANDOFF_MUTATE)
		assert(mutation_started != NULL && *mutation_started);
	return (visit(op == DTRACED_HANDOFF_RESERVE ? RESERVE :
	    op == DTRACED_HANDOFF_CANCEL ? CANCEL : MUTATION) ? 0 : -1);
}

static int
hypertrace_handoff_destination_import_prestart(struct vmctx *ctx,
    const uint8_t *token, const uint8_t *digest, const void *bundle,
    size_t length)
{
	assert(ctx != NULL && token != NULL && digest != NULL &&
	    bundle != NULL && length != 0);
	return (visit(IMPORT) ? 0 : -1);
}

static bool
pci_vtdtr_checkpoint_is_device(void *dev)
{
	assert(dev != NULL);
	return (visit(DEVICE));
}

static int
hypertrace_private_image_unchanged(const struct restore_state *state,
    const uint8_t *digest)
{
	assert(state != NULL && digest != NULL);
	return (visit(DIGEST) ? 0 : EPROTO);
}

static int
pci_vtdtr_checkpoint_private_image_query(void *image, size_t length,
    struct vmctx *ctx, const uint8_t *token, const uint8_t *digest)
{
	assert(image != NULL && length != 0 && ctx != NULL &&
	    token != NULL && digest != NULL);
	return (visit(QUERY) ? 0 : EIO);
}

/* PRODUCTION_PREFLIGHT */

static void
expect(const enum step *sequence, size_t length)
{
	assert(step_count == length);
	assert(memcmp(steps, sequence, length * sizeof(*steps)) == 0);
}

static void
reset(bool rebinding, enum step fail)
{
	step_count = 0;
	is_rebinding = rebinding;
	failing = fail;
	errno = 0;
}

int
main(void)
{
	struct vmctx ctx = {};
	uint8_t image = 1, bundle = 2, digest[32] = {};
	struct restore_state state = {
		.hypertrace_transfer = &bundle,
		.hypertrace_transfer_length = 1,
		.hypertrace_private_image = &image,
		.hypertrace_private_length = 1,
		.hypertrace_private_dev = &image,
		.checkpoint_format_version = 4,
	};
	bool rebinding, reserved, mutating;
	const enum step fresh_nonempty[] = {
		BEGIN, RESERVE, IMPORT, DEVICE, DIGEST, QUERY
	};
	const enum step rebind_nonempty[] = { BEGIN, STAGE, PENDING, PREFLIGHT };
	const enum step rebind_empty[] = {
		BEGIN, STAGE, READY, DEVICE, DIGEST, QUERY
	};
	const enum step import_failed[] = { BEGIN, RESERVE, IMPORT };
	const enum step reserve_failed[] = { BEGIN, RESERVE };

	reset(false, (enum step)-1);
	assert(hypertrace_restore_prepare_handoff(&ctx, &state, true, digest,
	    &rebinding, &reserved) == EOPNOTSUPP);
	assert(!rebinding && reserved);
	expect(fresh_nonempty, 6);

	reset(false, IMPORT);
	assert(hypertrace_restore_prepare_handoff(&ctx, &state, true, digest,
	    &rebinding, &reserved) == EIO);
	assert(!rebinding && reserved);
	expect(import_failed, 3);

	reset(false, RESERVE);
	assert(hypertrace_restore_prepare_handoff(&ctx, &state, true, digest,
	    &rebinding, &reserved) == EIO);
	assert(!rebinding && !reserved);
	expect(reserve_failed, 2);

	reset(true, (enum step)-1);
	assert(hypertrace_restore_prepare_handoff(&ctx, &state, true, digest,
	    &rebinding, &reserved) == EOPNOTSUPP);
	assert(rebinding && !reserved);
	expect(rebind_nonempty, 4);

	reset(true, PREFLIGHT);
	assert(hypertrace_restore_prepare_handoff(&ctx, &state, true, digest,
	    &rebinding, &reserved) == EIO);
	assert(rebinding && !reserved);
	expect(rebind_nonempty, 4);

	reset(true, (enum step)-1);
	assert(hypertrace_restore_prepare_handoff(&ctx, &state, false, digest,
	    &rebinding, &reserved) == 0);
	assert(rebinding && !reserved);
	expect(rebind_empty, 6);

	reset(false, QUERY);
	assert(hypertrace_restore_prepare_handoff(&ctx, &state, true, digest,
	    &rebinding, &reserved) == EIO);
	assert(!rebinding && reserved);
	expect(fresh_nonempty, 6);

	state.hypertrace_private_image = NULL;
	reset(false, (enum step)-1);
	assert(hypertrace_restore_prepare_handoff(&ctx, &state, false, digest,
	    &rebinding, &reserved) == 0);
	assert(!rebinding && reserved);
	expect(reserve_failed, 2);

	reset(false, (enum step)-1);
	assert(hypertrace_restore_cancel_if_safe(&ctx, &state, false, false,
	    false) == 0);
	assert(hypertrace_restore_cancel_if_safe(&ctx, &state, true, true,
	    false) == 0);
	assert(hypertrace_restore_cancel_if_safe(&ctx, &state, true, false,
	    true) == 0);
	assert(step_count == 0);

	assert(hypertrace_restore_cancel_if_safe(&ctx, &state, true, false,
	    false) == 0);
	const enum step cancelled[] = { CANCEL };
	expect(cancelled, 1);

	reset(false, CANCEL);
	assert(hypertrace_restore_cancel_if_safe(&ctx, &state, true, false,
	    false) == EIO);
	expect(cancelled, 1);

	mutating = false;
	mutation_started = &mutating;
	reset(false, MUTATION);
	assert(hypertrace_restore_begin_mutation(&ctx, &state,
	    &mutating) == EIO);
	assert(mutating);
	assert(hypertrace_restore_cancel_if_safe(&ctx, &state, true,
	    mutating, false) == 0);
	const enum step attempted[] = { MUTATION };
	expect(attempted, 1);

	mutating = false;
	reset(false, (enum step)-1);
	assert(hypertrace_restore_begin_mutation(&ctx, &state,
	    &mutating) == 0);
	assert(mutating);
	expect(attempted, 1);
	return (0);
}
