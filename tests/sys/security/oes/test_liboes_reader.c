/*
 * Unit tests for liboes batched-message parsing.
 *
 * A pipe stands in for /dev/oes so validation and retention can be exercised
 * without loading the kernel module.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <liboes.h>

typedef union {
	oes_message_t msg;
	uint8_t raw[OES_MSG_MAX_SIZE];
} aligned_buffer;

static void
init_message(oes_message_t *msg, uint64_t id, oes_event_type_t event)
{

	memset(msg, 0, sizeof(*msg));
	msg->em_version = OES_MESSAGE_VERSION;
	msg->em_size = sizeof(*msg);
	msg->em_struct_size = sizeof(*msg);
	msg->em_id = id;
	msg->em_event = event;
	msg->em_action = OES_ACTION_NOTIFY;
}

static int
write_all(int fd, const void *data, size_t length)
{
	const uint8_t *bytes = data;

	while (length != 0) {
		ssize_t written = write(fd, bytes, length);

		if (written < 0)
			return (-1);
		bytes += written;
		length -= (size_t)written;
	}
	return (0);
}

static int
open_batch(const void *data, size_t length, oes_client_t **client)
{
	int fds[2];

	if (pipe(fds) != 0)
		return (-1);
	if (write_all(fds[1], data, length) != 0) {
		close(fds[0]);
		close(fds[1]);
		return (-1);
	}
	close(fds[1]);
	*client = oes_client_create_from_fd(fds[0]);
	if (*client == NULL) {
		close(fds[0]);
		return (-1);
	}
	return (fds[0]);
}

static int
test_valid_batch(void)
{
	aligned_buffer batch;
	oes_client_t *client;
	const oes_message_t *msg;
	oes_message_t first, second;
	int fd, errors = 0;

	init_message(&first, 101, OES_EVENT_NOTIFY_OPEN);
	init_message(&second, 102, OES_EVENT_NOTIFY_FORK);
	memcpy(batch.raw, &first, sizeof(first));
	memcpy(batch.raw + sizeof(first), &second, sizeof(second));
	fd = open_batch(batch.raw, sizeof(first) + sizeof(second), &client);
	if (fd < 0)
		return (1);
	if (oes_read_event(client, &msg, false) != 0 || msg->em_id != 101)
		errors++;
	if (oes_read_event(client, &msg, false) != 0 || msg->em_id != 102)
		errors++;
	oes_client_destroy(client);
	close(fd);
	if (errors != 0)
		fprintf(stderr, "FAIL: liboes did not retain a valid batch\n");
	else
		printf("    PASS: liboes retains all valid batched messages\n");
	return (errors != 0);
}

static int
expect_second_message_failure(const void *data, size_t length,
    const char *description)
{
	oes_client_t *client;
	const oes_message_t *msg;
	int fd, failed;

	fd = open_batch(data, length, &client);
	if (fd < 0)
		return (1);
	failed = oes_read_event(client, &msg, false) != 0;
	errno = 0;
	failed |= oes_read_event(client, &msg, false) == 0 || errno != EPROTO;
	oes_client_destroy(client);
	close(fd);
	if (failed)
		fprintf(stderr, "FAIL: liboes accepted %s\n", description);
	else
		printf("    PASS: liboes rejects %s\n", description);
	return (failed);
}

static int
test_corrupt_batches(void)
{
	aligned_buffer batch;
	oes_message_t first, second;
	int errors;

	init_message(&first, 201, OES_EVENT_NOTIFY_OPEN);
	init_message(&second, 202, OES_EVENT_NOTIFY_FORK);
	second.em_version = OES_MESSAGE_VERSION - 1;
	memcpy(batch.raw, &first, sizeof(first));
	memcpy(batch.raw + sizeof(first), &second, sizeof(second));
	errors = expect_second_message_failure(batch.raw,
	    sizeof(first) + sizeof(second), "an incompatible older message");

	memset(batch.raw, 0, sizeof(batch.raw));
	memcpy(batch.raw, &first, sizeof(first));
	errors += expect_second_message_failure(batch.raw, sizeof(first) + 8,
	    "a trailing batch fragment");
	return (errors);
}

static int
test_scope_api_errors(void)
{
	oes_client_t *client;
	uint32_t scope;
	int fds[2], errors;

	if (pipe(fds) != 0)
		return (1);
	client = oes_client_create_from_fd(fds[0]);
	if (client == NULL) {
		close(fds[0]);
		close(fds[1]);
		return (1);
	}
	errors = 0;
	errno = 0;
	if (oes_set_descendants_scope(client) == 0 || errno != ENOTTY)
		errors++;
	errno = 0;
	if (oes_get_scope(client, &scope) == 0 || errno != ENOTTY)
		errors++;
	errno = 0;
	if (oes_get_scope(client, NULL) == 0 || errno != EINVAL)
		errors++;
	oes_client_destroy(client);
	close(fds[0]);
	close(fds[1]);
	if (errors != 0)
		fprintf(stderr, "FAIL: descendants scope API error handling\n");
	else
		printf("    PASS: descendants scope API reports ioctl errors\n");
	return (errors != 0);
}

static int
test_deadline_api_errors(void)
{
	oes_client_t *client;
	oes_deadline_miss_mode_t miss_mode;
	uint32_t milliseconds;
	uint64_t bitmap[2] = { 1, 0 };
	int fds[2], errors;

	if (pipe(fds) != 0)
		return (1);
	client = oes_client_create_from_fd(fds[0]);
	if (client == NULL) {
		close(fds[0]);
		close(fds[1]);
		return (1);
	}
	errors = 0;
	errno = 0;
	if (oes_set_deadline_max(client, OES_EVENT_AUTH_EXEC, 1000) == 0 ||
	    errno != ENOTTY)
		errors++;
	errno = 0;
	if (oes_get_deadline_max(client, OES_EVENT_AUTH_EXEC,
	    &milliseconds) == 0 || errno != ENOTTY)
		errors++;
	errno = 0;
	if (oes_set_deadline_min(client, OES_EVENT_AUTH_EXEC, 1000) == 0 ||
	    errno != ENOTTY)
		errors++;
	errno = 0;
	if (oes_get_deadline_min(client, OES_EVENT_AUTH_EXEC,
	    &milliseconds) == 0 || errno != ENOTTY)
		errors++;
	errno = 0;
	if (oes_get_deadline_max(client, OES_EVENT_AUTH_EXEC, NULL) == 0 ||
	    errno != EINVAL)
		errors++;
	errno = 0;
	if (oes_set_deadline_miss_mode(client,
	    OES_DEADLINE_MISS_FAIL_CLOSED) == 0 || errno != ENOTTY)
		errors++;
	errno = 0;
	if (oes_get_deadline_miss_mode(client, &miss_mode) == 0 ||
	    errno != ENOTTY)
		errors++;
	errno = 0;
	if (oes_get_deadline_miss_mode(client, NULL) == 0 || errno != EINVAL)
		errors++;
	errno = 0;
	if (oes_set_deadline_miss_mode(client,
	    (oes_deadline_miss_mode_t)99) == 0 || errno != EINVAL)
		errors++;
	errno = 0;
	if (oes_subscribe_bitmap(client, NULL, bitmap, OES_SUB_REPLACE) == 0 ||
	    errno != EINVAL)
		errors++;
	errno = 0;
	if (oes_subscribe_bitmap(client, bitmap, NULL, OES_SUB_REPLACE) == 0 ||
	    errno != EINVAL)
		errors++;
	oes_client_destroy(client);
	close(fds[0]);
	close(fds[1]);
	if (errors != 0)
		fprintf(stderr, "FAIL: per-event deadline API error handling\n");
	else
		printf("    PASS: deadline API validates and forwards requests\n");
	return (errors != 0);
}

int
main(void)
{
	int errors;

	printf("Testing liboes batched-message parsing...\n");
	errors = test_valid_batch();
	errors += test_corrupt_batches();
	errors += test_scope_api_errors();
	errors += test_deadline_api_errors();
	return (errors != 0);
}
