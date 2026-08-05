/* SPDX-License-Identifier: BSD-2-Clause */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <rebootctl.h>

struct rebootctl_client { int open; };
static struct rebootctl_client client;

int
rebootctl_client_open(struct rebootctl_client **result)
{
	const char *failure;

	if (result == NULL)
		return (errno = EINVAL, -1);
	failure = getenv("CMP_TEST_FAIL");
	if (failure != NULL && strcmp(failure, "open") == 0)
		return (errno = EIO, -1);
	client.open = 1;
	*result = &client;
	return (0);
}

void
rebootctl_client_close(struct rebootctl_client *value)
{
	if (value == &client)
		client.open = 0;
}

static int
mutate(struct rebootctl_client *value, const char *operation)
{
	const char *failure;

	if (value != &client || !value->open)
		return (errno = EINVAL, -1);
	failure = getenv("CMP_TEST_FAIL");
	if (failure != NULL && strcmp(failure, operation) == 0)
		return (errno = EIO, -1);
	return (0);
}

int
rebootctl_reboot(struct rebootctl_client *value, uint32_t howto)
{
	const char *operation;

	operation = howto == RB_REROOT ? "reroot" : "reboot";
	if (howto != 0 && howto != RB_REROOT)
		return (errno = EINVAL, -1);
	return (mutate(value, operation));
}

int
rebootctl_reboot_after(struct rebootctl_client *value, uint32_t howto,
    uint32_t delay_ms)
{

	if (delay_ms > REBOOTCTL_MAX_DELAY_MS)
		return (errno = EINVAL, -1);
	return (rebootctl_reboot(value, howto));
}

int
rebootctl_shutdown(struct rebootctl_client *value)
{
	return (mutate(value, "shutdown"));
}

int
rebootctl_shutdown_after(struct rebootctl_client *value, uint32_t delay_ms)
{

	if (delay_ms > REBOOTCTL_MAX_DELAY_MS)
		return (errno = EINVAL, -1);
	return (rebootctl_shutdown(value));
}

int
rebootctl_cancel(struct rebootctl_client *value)
{

	return (mutate(value, "cancel"));
}

int
rebootctl_status_detailed(struct rebootctl_client *value,
    struct rebootctl_status_reply *status)
{
	bool pending;

	if (status == NULL)
		return (errno = EINVAL, -1);
	if (rebootctl_status(value, &pending) == -1)
		return (-1);
	memset(status, 0, sizeof(*status));
	status->pending = pending;
	if (pending) {
		status->request_id = 1;
		status->requested_at_ns = 10;
		status->execute_at_ns = 20;
	}
	return (0);
}

int
rebootctl_status(struct rebootctl_client *value, bool *pending)
{
	const char *failure;

	if (value != &client || !value->open || pending == NULL)
		return (errno = EINVAL, -1);
	failure = getenv("CMP_TEST_FAIL");
	if (failure != NULL && strcmp(failure, "status") == 0)
		return (errno = EIO, -1);
	*pending = getenv("CMP_TEST_PENDING") != NULL;
	return (0);
}
