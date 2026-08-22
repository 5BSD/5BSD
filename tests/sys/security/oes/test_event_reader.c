/*
 * Unit tests for the OES test-suite batch reader.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

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
test_two_message_batch(void)
{
	struct test_event_reader reader;
	test_msg_buf out;
	oes_message_t first, second;

	test_event_reader_init(&reader);
	init_message(&first, 101, OES_EVENT_NOTIFY_OPEN);
	init_message(&second, 102, OES_EVENT_NOTIFY_FORK);
	memcpy(reader.ter_batch.raw, &first, sizeof(first));
	memcpy(reader.ter_batch.raw + sizeof(first), &second, sizeof(second));
	reader.ter_len = sizeof(first) + sizeof(second);

	if (test_event_reader_next(&reader, -1, &out.msg, 0) != 0 ||
	    out.msg.em_id != 101 || out.msg.em_event != OES_EVENT_NOTIFY_OPEN) {
		printf("    FAIL: first batched message was not returned\n");
		return (1);
	}
	if (test_event_reader_next(&reader, -1, &out.msg, 0) != 0 ||
	    out.msg.em_id != 102 || out.msg.em_event != OES_EVENT_NOTIFY_FORK) {
		printf("    FAIL: second batched message was not retained\n");
		return (1);
	}
	if (reader.ter_len != 0 || reader.ter_off != 0) {
		printf("    FAIL: exhausted batch state was not reset\n");
		return (1);
	}
	printf("    PASS: all messages in a batch are returned\n");
	return (0);
}

static int
test_malformed_batch(void)
{
	struct test_event_reader reader;
	test_msg_buf out;
	oes_message_t malformed;

	test_event_reader_init(&reader);
	init_message(&malformed, 201, OES_EVENT_NOTIFY_OPEN);
	malformed.em_size = sizeof(malformed) - OES_MSG_ALIGN;
	memcpy(reader.ter_batch.raw, &malformed, sizeof(malformed));
	reader.ter_len = sizeof(malformed);
	errno = 0;
	if (test_event_reader_next(&reader, -1, &out.msg, 0) == 0 ||
	    errno != EPROTO) {
		printf("    FAIL: malformed batch was accepted\n");
		return (1);
	}
	if (reader.ter_len != 0 || reader.ter_off != 0) {
		printf("    FAIL: malformed batch state was retained\n");
		return (1);
	}
	printf("    PASS: malformed batches fail closed\n");
	return (0);
}

static int
test_reader_rejects_fd_switch_with_pending_batch(void)
{
	struct test_event_reader reader;
	test_msg_buf out;
	oes_message_t first, second;

	test_event_reader_init(&reader);
	init_message(&first, 301, OES_EVENT_NOTIFY_OPEN);
	init_message(&second, 302, OES_EVENT_NOTIFY_FORK);
	memcpy(reader.ter_batch.raw, &first, sizeof(first));
	memcpy(reader.ter_batch.raw + sizeof(first), &second, sizeof(second));
	reader.ter_len = sizeof(first) + sizeof(second);
	reader.ter_fd = 10;

	if (test_event_reader_next(&reader, 10, &out.msg, 0) != 0 ||
	    out.msg.em_id != 301) {
		printf("    FAIL: failed to consume the first fd-bound message\n");
		return (1);
	}
	errno = 0;
	if (test_event_reader_next(&reader, 11, &out.msg, 0) == 0 ||
	    errno != EBUSY) {
		printf("    FAIL: fd switch consumed another descriptor's batch\n");
		return (1);
	}
	if (test_event_reader_next(&reader, 10, &out.msg, 0) != 0 ||
	    out.msg.em_id != 302) {
		printf("    FAIL: rejected fd switch damaged pending state\n");
		return (1);
	}
	printf("    PASS: explicit readers cannot cross descriptor streams\n");
	return (0);
}

static int
test_interleaved_default_readers(void)
{
	test_msg_buf batch, out;
	oes_message_t first, second, other;
	int a[2], b[2];
	int error;

	if (pipe(a) != 0 || pipe(b) != 0) {
		printf("    FAIL: pipe setup: %s\n", strerror(errno));
		return (1);
	}
	init_message(&first, 401, OES_EVENT_NOTIFY_OPEN);
	init_message(&second, 402, OES_EVENT_NOTIFY_FORK);
	init_message(&other, 403, OES_EVENT_NOTIFY_EXIT);
	memcpy(batch.raw, &first, sizeof(first));
	memcpy(batch.raw + sizeof(first), &second, sizeof(second));
	if (write(a[1], batch.raw, sizeof(first) + sizeof(second)) !=
	    (ssize_t)(sizeof(first) + sizeof(second)) ||
	    write(b[1], &other, sizeof(other)) != (ssize_t)sizeof(other)) {
		printf("    FAIL: pipe write: %s\n", strerror(errno));
		error = 1;
		goto out;
	}
	close(a[1]);
	a[1] = -1;
	close(b[1]);
	b[1] = -1;

	test_batch_reset();
	error = 0;
	if (test_wait_event(a[0], &out.msg, 100) != 0 ||
	    out.msg.em_id != 401)
		error = 1;
	if (test_wait_event(b[0], &out.msg, 100) != 0 ||
	    out.msg.em_id != 403)
		error = 1;
	if (test_wait_event(a[0], &out.msg, 100) != 0 ||
	    out.msg.em_id != 402)
		error = 1;
	if (error != 0)
		printf("    FAIL: alternating descriptors lost or reordered data\n");
	else
		printf("    PASS: alternating descriptors retain independent batches\n");
out:
	close(a[0]);
	if (a[1] >= 0)
		close(a[1]);
	close(b[0]);
	if (b[1] >= 0)
		close(b[1]);
	test_batch_reset();
	return (error);
}

static int
test_fd_reuse_forgets_pending_batch(void)
{
	test_msg_buf out;
	oes_message_t stale;
	int fds[2], fd;

	test_batch_reset();
	if (pipe(fds) != 0)
		return (1);
	fd = fds[0];
	init_message(&stale, 501, OES_EVENT_NOTIFY_OPEN);
	oes_test_default_readers[0].ter_fd = fd;
	oes_test_default_readers[0].ter_len = sizeof(stale);
	memcpy(oes_test_default_readers[0].ter_batch.raw, &stale,
	    sizeof(stale));

	/* Simulate close(fd) followed by open() returning the same number. */
	close(fds[0]);
	close(fds[1]);
	test_forget_event_reader(fd);
	errno = 0;
	if (test_wait_event(fd, &out.msg, 0) == 0) {
		printf("    FAIL: reused fd received a stale buffered message\n");
		return (1);
	}
	printf("    PASS: descriptor reuse discards stale batch state\n");
	return (0);
}

int
main(void)
{
	int errors;

	printf("Testing OES batched-event reader...\n");
	errors = test_two_message_batch();
	errors += test_malformed_batch();
	errors += test_reader_rejects_fd_switch_with_pending_batch();
	errors += test_interleaved_default_readers();
	errors += test_fd_reuse_forgets_pending_batch();
	return (errors != 0);
}
