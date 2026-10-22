/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#define HYPERTRACE_SESSION_RECORD_SIZE 40U
struct vmctx { int unused; };
static int scenario, begins, statuses, steps, exports, sleeps, ticks;
static int fixture_clock(clockid_t id, struct timespec *now)
{
	assert(id == CLOCK_MONOTONIC);
	now->tv_sec = scenario == 4 ? ticks++ * 601 : ticks++;
	if (scenario == 6 && steps != 0)
		now->tv_sec = 602;
	now->tv_nsec = 0;
	return (0);
}
static int fixture_sleep(const struct timespec *delay, struct timespec *left)
{
	assert(delay->tv_nsec == (steps ? 100000000 : 10000000) && left == NULL);
	sleeps++;
	errno = EINTR;
	return (-1);
}
static int pci_vtdtr_session_checkpoint_begin(struct vmctx *ctx)
{
	assert(ctx != NULL && ++begins == 1);
	return (scenario == 1 ? ENOTSUP : 0);
}
static int pci_vtdtr_session_stop_status(struct vmctx *ctx)
{
	assert(ctx != NULL && begins == 1 && steps == 0);
	statuses++;
	return (scenario == 2 ? ESTALE : statuses == 1 ? EBUSY : 0);
}
static int pci_vtdtr_session_collectors_stop_step(struct vmctx *ctx, bool *complete)
{
	assert(ctx != NULL && statuses == 2 && exports == 0);
	steps++;
	*complete = steps == 3;
	return (scenario == 3 ? EIO : 0);
}
static int pci_vtdtr_session_checkpoint_export(struct vmctx *ctx, void *record, size_t len)
{
	assert(ctx != NULL && steps == 3 && len == HYPERTRACE_SESSION_RECORD_SIZE);
	exports++;
	if (scenario == 5) return (ESTALE);
	memset(record, 0xa5, len);
	return (0);
}
#define clock_gettime fixture_clock
#define nanosleep fixture_sleep
#include "fresh-session-checkpoint-stop.inc"
int main(void)
{
	struct vmctx ctx = {0};
	const int errors[] = {0, ENOTSUP, ESTALE, EIO, ETIMEDOUT, ESTALE, ETIMEDOUT};
	for (scenario = 0; scenario < 7; scenario++) {
		uint8_t record[HYPERTRACE_SESSION_RECORD_SIZE] = {0};
		begins = statuses = steps = exports = sleeps = ticks = 0;
		assert(hypertrace_checkpoint_stop(&ctx, record) == errors[scenario]);
		assert(begins == 1);
		if (scenario == 0) assert(exports == 1 && steps == 3 && sleeps == 3 && record[0] == 0xa5);
		else assert(record[0] == 0);
		if (scenario > 0 && scenario < 5) assert(exports == 0);
		if (scenario == 6) assert(exports == 0 && steps == 1 && sleeps == 2);
	}
	return (0);
}
