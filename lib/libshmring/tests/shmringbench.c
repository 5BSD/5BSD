/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/socket.h>

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <shmring.h>

#define	DEFAULT_RECORDS	UINT64_C(1000000)
#define	DEFAULT_LENGTH	256U
#define	WAKE_CYCLES_MAX	UINT64_C(100000)
#define	RING_CAPACITY	(1024U * 1024U)
#define	MAX_PAYLOAD	4096U

struct throughput_context {
	struct shmring *consumer;
	uint64_t records;
	size_t length;
	_Atomic bool start;
	int error;
};

static uint64_t
nanoseconds(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		perror("clock_gettime");
		exit(1);
	}
	return ((uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec);
}

static void
backoff(uint64_t attempts)
{

	if ((attempts & UINT64_C(1023)) == 0)
		sched_yield();
	else
		atomic_signal_fence(memory_order_seq_cst);
}

static void *
consume_records(void *argument)
{
	struct throughput_context *context;
	uint8_t record[MAX_PAYLOAD];
	uint64_t attempts, consumed;
	ssize_t length;

	context = argument;
	while (!atomic_load_explicit(&context->start, memory_order_acquire))
		backoff(1);
	attempts = 0;
	for (consumed = 0; consumed < context->records;) {
		length = shmring_read_record(context->consumer, record,
		    sizeof(record));
		if (length == -1 && errno == EAGAIN) {
			backoff(++attempts);
			continue;
		}
		if (length == -1 || (size_t)length != context->length ||
		    record[0] != (uint8_t)consumed) {
			context->error = length == -1 ? errno : EPROTO;
			return (NULL);
		}
		consumed++;
	}
	return (NULL);
}

struct stream_context {
	struct shmring *consumer;
	uint64_t bytes;
	_Atomic bool start;
	int error;
};

static void *
consume_stream(void *argument)
{
	struct stream_context *context;
	uint8_t buffer[MAX_PAYLOAD];
	uint64_t attempts, consumed;
	size_t wanted;
	ssize_t amount;

	context = argument;
	while (!atomic_load_explicit(&context->start, memory_order_acquire))
		backoff(1);
	attempts = 0;
	for (consumed = 0; consumed < context->bytes;) {
		wanted = (size_t)(context->bytes - consumed);
		if (wanted > sizeof(buffer))
			wanted = sizeof(buffer);
		amount = shmring_read(context->consumer, buffer, wanted);
		if (amount == -1 && errno == EAGAIN) {
			backoff(++attempts);
			continue;
		}
		if (amount <= 0) {
			context->error = amount == -1 ? errno : EPROTO;
			return (NULL);
		}
		consumed += (uint64_t)amount;
	}
	return (NULL);
}

static int
run_stream(uint64_t bytes, size_t chunk)
{
	struct shmring_fds producer_fds, consumer_fds;
	struct shmring *producer, *consumer;
	struct stream_context context;
	pthread_t thread;
	uint8_t buffer[MAX_PAYLOAD];
	uint64_t attempts, begin, elapsed, produced;
	size_t wanted;
	ssize_t amount;
	double seconds;
	int error, result;

	producer = NULL;
	consumer = NULL;
	if (shmring_create(RING_CAPACITY, SHMRING_MODE_STREAM, 0, 2,
	    &producer_fds, &consumer_fds) == -1 ||
	    shmring_open(&producer, &producer_fds, SHMRING_ROLE_PRODUCER) == -1 ||
	    shmring_open(&consumer, &consumer_fds, SHMRING_ROLE_CONSUMER) == -1)
		return (-1);
	memset(&context, 0, sizeof(context));
	memset(buffer, 0x5a, sizeof(buffer));
	context.consumer = consumer;
	context.bytes = bytes;
	if ((error = pthread_create(&thread, NULL, consume_stream, &context)) != 0)
		return (errno = error, -1);
	begin = nanoseconds();
	atomic_store_explicit(&context.start, true, memory_order_release);
	attempts = 0;
	for (produced = 0; produced < bytes;) {
		wanted = (size_t)(bytes - produced);
		if (wanted > chunk)
			wanted = chunk;
		amount = shmring_write(producer, buffer, wanted);
		if (amount == -1 && errno == EAGAIN) {
			backoff(++attempts);
			continue;
		}
		if (amount <= 0) {
			error = amount == -1 ? errno : EPROTO;
			(void)pthread_join(thread, NULL);
			return (errno = error, -1);
		}
		produced += (uint64_t)amount;
	}
	result = pthread_join(thread, NULL);
	elapsed = nanoseconds() - begin;
	if (result != 0 || context.error != 0) {
		errno = result != 0 ? result : context.error;
		result = -1;
	} else {
		seconds = (double)elapsed / 1000000000.0;
		printf("stream: bytes=%" PRIu64 " chunk=%zu seconds=%.6f "
		    "MiB/s=%.2f\n", bytes, chunk, seconds,
		    ((double)bytes / (1024.0 * 1024.0)) / seconds);
		result = 0;
	}
	shmring_close(producer);
	shmring_close(consumer);
	shmring_fds_close(&producer_fds);
	shmring_fds_close(&consumer_fds);
	return (result);
}

static int
compare_u64(const void *left, const void *right)
{
	uint64_t a, b;

	a = *(const uint64_t *)left;
	b = *(const uint64_t *)right;
	return (a > b) - (a < b);
}

static uint64_t
percentile(uint64_t *samples, uint64_t count, unsigned percent)
{
	uint64_t index;

	qsort(samples, (size_t)count, sizeof(*samples), compare_u64);
	index = ((count - 1) * percent) / 100;
	return (samples[index]);
}

static int
run_throughput(struct shmring *producer, struct shmring *consumer,
    uint64_t records, size_t length, uint8_t *record)
{
	struct throughput_context context;
	pthread_t thread;
	uint64_t attempts, begin, elapsed, produced;
	double mib, seconds;
	int error;

	memset(&context, 0, sizeof(context));
	context.consumer = consumer;
	context.records = records;
	context.length = length;
	if ((error = pthread_create(&thread, NULL, consume_records, &context)) != 0)
		return (errno = error, -1);
	begin = nanoseconds();
	atomic_store_explicit(&context.start, true, memory_order_release);
	attempts = 0;
	for (produced = 0; produced < records;) {
		record[0] = (uint8_t)produced;
		if (shmring_write_record(producer, record, length) == 0) {
			produced++;
			continue;
		}
		if (errno != EAGAIN) {
			error = errno;
			(void)pthread_join(thread, NULL);
			return (errno = error, -1);
		}
		backoff(++attempts);
	}
	if ((error = pthread_join(thread, NULL)) != 0)
		return (errno = error, -1);
	if (context.error != 0)
		return (errno = context.error, -1);
	elapsed = nanoseconds() - begin;
	seconds = (double)elapsed / 1000000000.0;
	mib = (double)(records * length) / (1024.0 * 1024.0);
	printf("sustained: records=%" PRIu64 " bytes=%zu seconds=%.6f "
	    "records/s=%.0f MiB/s=%.2f\n", records, length, seconds,
	    (double)records / seconds, mib / seconds);
	return (0);
}

static int
run_wakeup(struct shmring *producer, struct shmring *consumer,
    uint64_t cycles, size_t length, uint8_t *record)
{
	uint64_t *cycle_samples, *send_samples;
	uint64_t begin, send_begin, i;
	int wake[2], notify, result;
	uint8_t token, received[MAX_PAYLOAD];
	ssize_t amount;

	cycle_samples = calloc((size_t)cycles, sizeof(*cycle_samples));
	send_samples = calloc((size_t)cycles, sizeof(*send_samples));
	if (cycle_samples == NULL || send_samples == NULL) {
		free(cycle_samples);
		free(send_samples);
		return (-1);
	}
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, wake) == -1) {
		free(cycle_samples);
		free(send_samples);
		return (-1);
	}
	token = 1;
	result = -1;
	for (i = 0; i < cycles; i++) {
		if (shmring_consumer_arm(consumer) != 0)
			goto out;
		begin = nanoseconds();
		record[0] = (uint8_t)i;
		if (shmring_write_record(producer, record, length) == -1)
			goto out;
		notify = shmring_producer_wakeup_needed(producer);
		if (notify != 1) {
			errno = notify == -1 ? errno : EPROTO;
			goto out;
		}
		send_begin = nanoseconds();
		if (send(wake[0], &token, sizeof(token), 0) != sizeof(token))
			goto out;
		send_samples[i] = nanoseconds() - send_begin;
		if (recv(wake[1], &token, sizeof(token), 0) != sizeof(token))
			goto out;
		amount = shmring_read_record(consumer, received, sizeof(received));
		if (amount != (ssize_t)length) {
			errno = amount == -1 ? errno : EPROTO;
			goto out;
		}
		cycle_samples[i] = nanoseconds() - begin;
	}
	printf("idle-cycle: cycles=%" PRIu64
	    " signal-ns[p50=%" PRIu64 " p95=%" PRIu64 " p99=%" PRIu64 "]"
	    " cycle-ns[p50=%" PRIu64 " p95=%" PRIu64 " p99=%" PRIu64 "]\n",
	    cycles, percentile(send_samples, cycles, 50),
	    percentile(send_samples, cycles, 95),
	    percentile(send_samples, cycles, 99),
	    percentile(cycle_samples, cycles, 50),
	    percentile(cycle_samples, cycles, 95),
	    percentile(cycle_samples, cycles, 99));
	result = 0;
out:
	close(wake[0]);
	close(wake[1]);
	free(cycle_samples);
	free(send_samples);
	return (result);
}

int
main(int argc, char **argv)
{
	struct shmring_fds producer_fds, consumer_fds;
	struct shmring *producer, *consumer;
	uint64_t records, cycles;
	uint8_t record[MAX_PAYLOAD];
	size_t length;
	char *end;
	int result;

	records = DEFAULT_RECORDS;
	length = DEFAULT_LENGTH;
	if (argc > 1) {
		records = strtoull(argv[1], &end, 10);
		if (*argv[1] == '\0' || *end != '\0' || records == 0)
			return (fprintf(stderr, "invalid record count\n"), 2);
	}
	if (argc > 2) {
		length = (size_t)strtoul(argv[2], &end, 10);
		if (*argv[2] == '\0' || *end != '\0' || length == 0 ||
		    length > sizeof(record))
			return (fprintf(stderr, "invalid payload length\n"), 2);
	}
	if (argc > 3)
		return (fprintf(stderr, "usage: %s [records [bytes]]\n", argv[0]),
		    2);
	if (records > UINT64_MAX / length)
		return (fprintf(stderr, "byte count overflows\n"), 2);
	memset(record, 0xa5, sizeof(record));
	producer = NULL;
	consumer = NULL;
	if (shmring_create(RING_CAPACITY, SHMRING_MODE_RECORD, sizeof(record),
	    1, &producer_fds, &consumer_fds) == -1 ||
	    shmring_open(&producer, &producer_fds, SHMRING_ROLE_PRODUCER) == -1 ||
	    shmring_open(&consumer, &consumer_fds, SHMRING_ROLE_CONSUMER) == -1) {
		perror("shmring setup");
		return (1);
	}
	result = run_throughput(producer, consumer, records, length, record);
	cycles = records < WAKE_CYCLES_MAX ? records : WAKE_CYCLES_MAX;
	if (result == 0)
		result = run_wakeup(producer, consumer, cycles, length, record);
	shmring_close(producer);
	shmring_close(consumer);
	shmring_fds_close(&producer_fds);
	shmring_fds_close(&consumer_fds);
	if (result == 0)
		result = run_stream(records * length, length);
	if (result == -1)
		perror("shmring benchmark");
	return (result == 0 ? 0 : 1);
}
