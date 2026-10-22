/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/hypertrace.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

struct vmctx { int unused; };
static int session_gate_fd = 9, session_gate_error = ENXIO;
static struct hypertrace_epoch_gate state;
static int queries, suspends, fail_query, corrupt_query, change_identity;
static uint64_t identity_epoch = 77;
static uint32_t epoch_live;

static int
vm_get_identity(struct vmctx *ctx, uint16_t *vmid, uint64_t *epoch)
{
	assert(ctx != NULL);
	*vmid = 1;
	*epoch = identity_epoch;
	return (0);
}

static int
fake_ioctl(int fd, unsigned long command, void *data)
{
	struct hypertrace_epoch_gate *gate = data;
	assert(fd == 9);
	if (command == HYPERTRACE_IOC_EPOCH_QUERY) {
		struct hypertrace_epoch_query *query = data;
		query->live = epoch_live;
		if (corrupt_query) query->reserved2 = 1;
		return (0);
	}
	if (command == HYPERTRACE_IOC_EPOCH_GATE_QUERY) {
		if (++queries == fail_query) {
			errno = EIO;
			return (-1);
		}
		gate->suspended = state.suspended;
		memcpy(gate->token, state.token, 16);
		if (corrupt_query)
			gate->reserved2 = 1;
		if (change_identity)
			identity_epoch++;
		return (0);
	}
	assert(command == HYPERTRACE_IOC_EPOCH_SUSPEND);
	assert(!state.suspended);
	assert(memcmp(gate->previous_token, state.token, 16) == 0);
	state = *gate;
	state.suspended = 1;
	suspends++;
	return (0);
}
#define ioctl fake_ioctl
#include "session-host-gate.inc"

int
main(void)
{
	struct vmctx ctx = {0};
	uint8_t token[16] = {1}, foreign[16] = {2};
	assert(hypertrace_session_host_stop(NULL, token) == -1 && errno == EINVAL);
	session_gate_fd = -1;
	assert(hypertrace_session_host_stop(&ctx, token) == -1 && errno == ENXIO);
	session_gate_fd = 9;
	/* Suspend commits, then readback fails: retry must not suspend twice. */
	fail_query = 2;
	assert(hypertrace_session_host_stop(&ctx, token) == -1 && errno == EIO);
	assert(suspends == 1 && state.suspended);
	fail_query = 0;
	assert(hypertrace_session_host_stop(&ctx, token) == 0 && suspends == 1);
	assert(hypertrace_session_host_released(&ctx, token) == -1 && errno == EBUSY);
	assert(hypertrace_session_host_stop(&ctx, foreign) == -1 && errno == EBUSY);
	assert(hypertrace_session_host_stopped(&ctx, foreign) == -1 && errno == EBUSY);
	corrupt_query = 1;
	assert(hypertrace_session_host_stopped(&ctx, token) == -1 && errno == EPROTO);
	corrupt_query = 0;
	change_identity = 1;
	assert(hypertrace_session_host_stopped(&ctx, token) == -1 && errno == ESTALE);
	change_identity = 0;
	state.suspended = 0;
	assert(hypertrace_session_host_stopped(&ctx, token) == -1 && errno == EBUSY);
	assert(hypertrace_session_host_released(&ctx, token) == 0);
	assert(hypertrace_session_host_released(&ctx, foreign) == -1 && errno == EBUSY);
	epoch_live = 1;
	assert(hypertrace_session_retired(1, 77) == -1 && errno == EBUSY);
	epoch_live = 0;
	assert(hypertrace_session_retired(1, 77) == 0);
	corrupt_query = 1;
	assert(hypertrace_session_retired(1, 77) == -1 && errno == EPROTO);
	corrupt_query = 0;
	epoch_live = 2;
	assert(hypertrace_session_retired(1, 77) == -1 && errno == EPROTO);
	return (0);
}
