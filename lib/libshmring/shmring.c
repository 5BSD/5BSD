/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/capsicum.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <stdatomic.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shmring.h"
#include "shmring_probes.h"

#define	SHMRING_MAGIC	0x53484d52494e4731ULL	/* "SHMRING1" */

struct shmring_config {
	uint64_t	magic;
	uint32_t	version;
	uint32_t	mode;
	uint64_t	capacity;
	uint32_t	max_record;
	uint32_t	shape;
	uint64_t	generation;
	uint64_t	low_watermark;
	uint64_t	high_watermark;
};

struct shmring {
	const struct shmring_config *config;
	uint8_t		*data;
	_Atomic uint64_t *head;
	_Atomic uint64_t *tail;
	size_t		config_len;
	size_t		capacity;
	uint32_t	role;
	pid_t		owner;
};

static bool
ring_is_current(const struct shmring *ring)
{

	if (ring == NULL) {
		errno = EINVAL;
		return (false);
	}
	if (ring->owner != getpid()) {
		errno = ECHILD;
		return (false);
	}
	return (true);
}

static bool
is_power_of_two(size_t value)
{

	return (value != 0 && (value & (value - 1)) == 0);
}

static void
fds_init(struct shmring_fds *fds)
{

	fds->config_fd = -1;
	fds->data_fd = -1;
	fds->head_fd = -1;
	fds->tail_fd = -1;
}

void
shmring_fds_close(struct shmring_fds *fds)
{
	int *values;
	size_t i;

	if (fds == NULL)
		return;
	values = &fds->config_fd;
	for (i = 0; i < SHMRING_NFDS; i++) {
		if (values[i] >= 0)
			close(values[i]);
		values[i] = -1;
	}
}

static int
create_object(const char *name, size_t size)
{
	int fd;

	fd = memfd_create(name, MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (fd == -1)
		return (-1);
	if (ftruncate(fd, (off_t)size) == -1) {
		close(fd);
		return (-1);
	}
	return (fd);
}

static int
seal_object(int fd, bool readonly)
{
	int seals;

	seals = F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
	if (readonly)
		seals |= F_SEAL_WRITE;
	return (fcntl(fd, F_ADD_SEALS, seals));
}

static int
duplicate_limited(int fd, cap_rights_t *rights)
{
	int newfd;

	newfd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (newfd == -1)
		return (-1);
	if (cap_rights_limit(newfd, rights) == -1) {
		close(newfd);
		return (-1);
	}
	return (newfd);
}

static int
make_endpoint(const int originals[SHMRING_NFDS], uint32_t role,
    struct shmring_fds *out)
{
	cap_rights_t config_rights, data_rights, head_rights, tail_rights;
	int *values;

	fds_init(out);
	cap_rights_init(&config_rights, CAP_FSTAT, CAP_MMAP_R);
	if (role == SHMRING_ROLE_PRODUCER) {
		cap_rights_init(&data_rights, CAP_FSTAT, CAP_MMAP_W);
		cap_rights_init(&head_rights, CAP_FSTAT, CAP_MMAP_RW);
		cap_rights_init(&tail_rights, CAP_FSTAT, CAP_MMAP_R);
	} else {
		cap_rights_init(&data_rights, CAP_FSTAT, CAP_MMAP_R);
		cap_rights_init(&head_rights, CAP_FSTAT, CAP_MMAP_R);
		cap_rights_init(&tail_rights, CAP_FSTAT, CAP_MMAP_RW);
	}

	values = &out->config_fd;
	values[0] = duplicate_limited(originals[0], &config_rights);
	values[1] = duplicate_limited(originals[1], &data_rights);
	values[2] = duplicate_limited(originals[2], &head_rights);
	values[3] = duplicate_limited(originals[3], &tail_rights);
	if (values[0] == -1 || values[1] == -1 || values[2] == -1 ||
	    values[3] == -1) {
		shmring_fds_close(out);
		return (-1);
	}
	return (0);
}

int
shmring_create_with_options(const struct shmring_options *options,
    struct shmring_fds *producer, struct shmring_fds *consumer)
{
	struct shmring_config config;
	int originals[SHMRING_NFDS];
	size_t capacity;
	uint32_t max_record, mode;
	size_t i;

	if (options == NULL || options->size != sizeof(*options) ||
	    options->reserved != 0 || producer == NULL || consumer == NULL) {
		errno = EINVAL;
		return (-1);
	}
	capacity = options->capacity;
	mode = options->mode;
	max_record = options->max_record;
	if (options->shape == SHMRING_SHAPE_TRUSTED_MPSC) {
		/* A separate reservation/commit API is required before this is safe. */
		errno = ENOTSUP;
		SHMRING_PROBE_CREATE(capacity, options->shape, mode, max_record,
		    ENOTSUP);
		return (-1);
	}
	if ((options->shape != SHMRING_SHAPE_COMPACT_SPSC &&
	    options->shape != SHMRING_SHAPE_BULK_SPSC) ||
	    capacity < SHMRING_MIN_CAPACITY ||
	    capacity > SHMRING_MAX_CAPACITY || !is_power_of_two(capacity) ||
	    (options->shape == SHMRING_SHAPE_COMPACT_SPSC &&
	    capacity > SHMRING_COMPACT_MAX_CAPACITY) ||
	    (options->shape == SHMRING_SHAPE_BULK_SPSC &&
	    capacity < SHMRING_BULK_MIN_CAPACITY) ||
	    options->low_watermark > options->high_watermark ||
	    options->high_watermark > capacity ||
	    (mode != SHMRING_MODE_STREAM && mode != SHMRING_MODE_RECORD) ||
	    (mode == SHMRING_MODE_STREAM && max_record != 0) ||
	    (mode == SHMRING_MODE_RECORD &&
	    (max_record == 0 || (uint64_t)max_record + sizeof(uint32_t) >
	    capacity))) {
		errno = EINVAL;
		SHMRING_PROBE_CREATE(capacity, options->shape, mode, max_record,
		    EINVAL);
		return (-1);
	}

	fds_init(producer);
	fds_init(consumer);
	for (i = 0; i < SHMRING_NFDS; i++)
		originals[i] = -1;
	originals[0] = create_object("shmring-config", sizeof(config));
	originals[1] = create_object("shmring-data", capacity);
	originals[2] = create_object("shmring-head", sizeof(uint64_t));
	originals[3] = create_object("shmring-tail", sizeof(uint64_t));
	for (i = 0; i < SHMRING_NFDS; i++) {
		if (originals[i] == -1)
			goto fail;
	}

	memset(&config, 0, sizeof(config));
	config.magic = SHMRING_MAGIC;
	config.version = SHMRING_ABI_VERSION;
	config.mode = mode;
	config.capacity = capacity;
	config.max_record = max_record;
	config.shape = options->shape;
	config.generation = options->generation;
	config.low_watermark = options->low_watermark;
	config.high_watermark = options->high_watermark;
	if (pwrite(originals[0], &config, sizeof(config), 0) != sizeof(config))
		goto fail;
	if (seal_object(originals[0], true) == -1 ||
	    seal_object(originals[1], false) == -1 ||
	    seal_object(originals[2], false) == -1 ||
	    seal_object(originals[3], false) == -1)
		goto fail;

	if (make_endpoint(originals, SHMRING_ROLE_PRODUCER, producer) == -1 ||
	    make_endpoint(originals, SHMRING_ROLE_CONSUMER, consumer) == -1)
		goto fail;
	for (i = 0; i < SHMRING_NFDS; i++)
		close(originals[i]);
	SHMRING_PROBE_CREATE(capacity, options->shape, mode, max_record, 0);
	return (0);

fail:
	{
		int error;

		error = errno;
	for (i = 0; i < SHMRING_NFDS; i++) {
		if (originals[i] >= 0)
			close(originals[i]);
	}
	shmring_fds_close(producer);
	shmring_fds_close(consumer);
	SHMRING_PROBE_CREATE(capacity, options->shape, mode, max_record, error);
	errno = error;
	}
	return (-1);
}

int
shmring_create(size_t capacity, uint32_t mode, uint32_t max_record,
    uint64_t generation, struct shmring_fds *producer,
    struct shmring_fds *consumer)
{
	struct shmring_options options = SHMRING_OPTIONS_INITIALIZER(
	    capacity <= SHMRING_COMPACT_MAX_CAPACITY ?
	    SHMRING_SHAPE_COMPACT_SPSC : SHMRING_SHAPE_BULK_SPSC,
	    mode, capacity);

	options.max_record = max_record;
	options.generation = generation;
	return (shmring_create_with_options(&options, producer, consumer));
}

static int
object_has_size(int fd, uint64_t size)
{
	struct stat sb;

	if (fstat(fd, &sb) == -1)
		return (-1);
	if (sb.st_size != (off_t)size) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

static int
object_has_seals(int fd, int required)
{
	int seals;

	seals = fcntl(fd, F_GET_SEALS);
	if (seals == -1)
		return (-1);
	if ((seals & required) != required) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

static int
object_has_rights(int fd, const cap_rights_t *expected)
{
	cap_rights_t actual;

	if (cap_rights_get(fd, &actual) == -1)
		return (-1);
	if (!cap_rights_contains(&actual, expected) ||
	    !cap_rights_contains(expected, &actual)) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

static int
objects_are_distinct(const struct shmring_fds *fds)
{
	struct stat sb[SHMRING_NFDS];
	const int *values;
	size_t i, j;

	values = &fds->config_fd;
	for (i = 0; i < SHMRING_NFDS; i++)
		if (fstat(values[i], &sb[i]) == -1)
			return (-1);
	for (i = 0; i < SHMRING_NFDS; i++)
		for (j = i + 1; j < SHMRING_NFDS; j++)
			if (sb[i].st_dev == sb[j].st_dev &&
			    sb[i].st_ino == sb[j].st_ino) {
				errno = EPROTO;
				return (-1);
			}
	return (0);
}

int
shmring_open(struct shmring **ringp, const struct shmring_fds *fds,
    uint32_t role)
{
	struct shmring *ring;
	cap_rights_t config_rights, data_rights, head_rights, tail_rights;
	int data_prot, head_prot, tail_prot;

	if (ringp == NULL || fds == NULL ||
	    (role != SHMRING_ROLE_PRODUCER &&
	    role != SHMRING_ROLE_CONSUMER)) {
		errno = EINVAL;
		return (-1);
	}
	*ringp = NULL;
	cap_rights_init(&config_rights, CAP_FSTAT, CAP_MMAP_R);
	if (role == SHMRING_ROLE_PRODUCER) {
		cap_rights_init(&data_rights, CAP_FSTAT, CAP_MMAP_W);
		cap_rights_init(&head_rights, CAP_FSTAT, CAP_MMAP_RW);
		cap_rights_init(&tail_rights, CAP_FSTAT, CAP_MMAP_R);
	} else {
		cap_rights_init(&data_rights, CAP_FSTAT, CAP_MMAP_R);
		cap_rights_init(&head_rights, CAP_FSTAT, CAP_MMAP_R);
		cap_rights_init(&tail_rights, CAP_FSTAT, CAP_MMAP_RW);
	}
	if (objects_are_distinct(fds) == -1 ||
	    object_has_rights(fds->config_fd, &config_rights) == -1 ||
	    object_has_rights(fds->data_fd, &data_rights) == -1 ||
	    object_has_rights(fds->head_fd, &head_rights) == -1 ||
	    object_has_rights(fds->tail_fd, &tail_rights) == -1) {
		int error;

		if (errno != EBADF)
			errno = EPROTO;
		error = errno;
		SHMRING_PROBE_OPEN(role, 0, 0, 0, error);
		errno = error;
		return (-1);
	}
	ring = calloc(1, sizeof(*ring));
	if (ring == NULL)
		return (-1);
	ring->config_len = sizeof(*ring->config);
	/*
	 * Check the object before touching an mmap.  Accessing a mapping beyond
	 * a forged object's EOF would otherwise deliver SIGBUS instead of a
	 * recoverable protocol error.
	 */
	if (object_has_size(fds->config_fd, ring->config_len) == -1 ||
	    object_has_seals(fds->config_fd, F_SEAL_GROW | F_SEAL_SHRINK |
	    F_SEAL_WRITE | F_SEAL_SEAL) == -1)
		goto fail;
	ring->config = mmap(NULL, ring->config_len, PROT_READ, MAP_SHARED,
	    fds->config_fd, 0);
	if (ring->config == MAP_FAILED) {
		ring->config = NULL;
		goto fail;
	}
	if (ring->config->magic != SHMRING_MAGIC ||
	    ring->config->version != SHMRING_ABI_VERSION ||
	    ring->config->capacity < SHMRING_MIN_CAPACITY ||
	    ring->config->capacity > SHMRING_MAX_CAPACITY ||
	    !is_power_of_two((size_t)ring->config->capacity) ||
	    (ring->config->mode != SHMRING_MODE_STREAM &&
	    ring->config->mode != SHMRING_MODE_RECORD) ||
	    (ring->config->mode == SHMRING_MODE_STREAM &&
	    ring->config->max_record != 0) ||
	    (ring->config->mode == SHMRING_MODE_RECORD &&
	    (ring->config->max_record == 0 ||
	    (uint64_t)ring->config->max_record + sizeof(uint32_t) >
	    ring->config->capacity)) ||
	    (ring->config->shape != SHMRING_SHAPE_COMPACT_SPSC &&
	    ring->config->shape != SHMRING_SHAPE_BULK_SPSC) ||
	    (ring->config->shape == SHMRING_SHAPE_COMPACT_SPSC &&
	    ring->config->capacity > SHMRING_COMPACT_MAX_CAPACITY) ||
	    (ring->config->shape == SHMRING_SHAPE_BULK_SPSC &&
	    ring->config->capacity < SHMRING_BULK_MIN_CAPACITY) ||
	    ring->config->low_watermark > ring->config->high_watermark ||
	    ring->config->high_watermark > ring->config->capacity) {
		errno = EPROTO;
		goto fail;
	}
	ring->capacity = (size_t)ring->config->capacity;
	if (object_has_size(fds->data_fd, ring->capacity) == -1 ||
	    object_has_size(fds->head_fd, sizeof(uint64_t)) == -1 ||
	    object_has_size(fds->tail_fd, sizeof(uint64_t)) == -1 ||
	    object_has_seals(fds->data_fd, F_SEAL_GROW | F_SEAL_SHRINK |
	    F_SEAL_SEAL) == -1 ||
	    object_has_seals(fds->head_fd, F_SEAL_GROW | F_SEAL_SHRINK |
	    F_SEAL_SEAL) == -1 ||
	    object_has_seals(fds->tail_fd, F_SEAL_GROW | F_SEAL_SHRINK |
	    F_SEAL_SEAL) == -1)
		goto fail;

	data_prot = role == SHMRING_ROLE_PRODUCER ? PROT_WRITE : PROT_READ;
	head_prot = PROT_READ |
	    (role == SHMRING_ROLE_PRODUCER ? PROT_WRITE : 0);
	tail_prot = PROT_READ |
	    (role == SHMRING_ROLE_CONSUMER ? PROT_WRITE : 0);
	ring->data = mmap(NULL, ring->capacity, data_prot, MAP_SHARED,
	    fds->data_fd, 0);
	ring->head = mmap(NULL, sizeof(*ring->head), head_prot, MAP_SHARED,
	    fds->head_fd, 0);
	ring->tail = mmap(NULL, sizeof(*ring->tail), tail_prot, MAP_SHARED,
	    fds->tail_fd, 0);
	if (ring->data == MAP_FAILED || ring->head == MAP_FAILED ||
	    ring->tail == MAP_FAILED) {
		if (ring->data == MAP_FAILED)
			ring->data = NULL;
		if (ring->head == MAP_FAILED)
			ring->head = NULL;
		if (ring->tail == MAP_FAILED)
			ring->tail = NULL;
		goto fail;
	}
	/* Descriptor close-on-fork does not revoke established mappings. */
	if (minherit(__DECONST(void *, ring->config), ring->config_len,
	    INHERIT_NONE) == -1 ||
	    minherit(ring->data, ring->capacity, INHERIT_NONE) == -1 ||
	    minherit(ring->head, sizeof(*ring->head), INHERIT_NONE) == -1 ||
	    minherit(ring->tail, sizeof(*ring->tail), INHERIT_NONE) == -1)
		goto fail;
	ring->role = role;
	ring->owner = getpid();
	*ringp = ring;
	SHMRING_PROBE_OPEN(role, ring->capacity, ring->config->shape,
	    ring->config->mode, 0);
	return (0);

fail:
	{
		int error;
		uint32_t probe_mode, probe_shape;

		error = errno;
		probe_mode = ring->config != NULL ? ring->config->mode : 0;
		probe_shape = ring->config != NULL ? ring->config->shape : 0;
	SHMRING_PROBE_OPEN(role, ring->capacity, probe_shape, probe_mode,
	    error);
	shmring_close(ring);
	errno = error;
	}
	return (-1);
}

void
shmring_close(struct shmring *ring)
{

	if (ring == NULL)
		return;
	if (ring->owner != 0 && ring->owner != getpid()) {
		free(ring);
		return;
	}
	SHMRING_PROBE_CLOSE(ring->role, ring->capacity);
	if (ring->config != NULL)
		munmap(__DECONST(void *, ring->config), ring->config_len);
	if (ring->data != NULL)
		munmap(ring->data, ring->capacity);
	if (ring->head != NULL)
		munmap(ring->head, sizeof(*ring->head));
	if (ring->tail != NULL)
		munmap(ring->tail, sizeof(*ring->tail));
	free(ring);
}

uint64_t
shmring_generation(const struct shmring *ring)
{

	if (!ring_is_current(ring))
		return (0);
	return (ring->config->generation);
}

size_t
shmring_capacity(const struct shmring *ring)
{

	if (!ring_is_current(ring))
		return (0);
	return (ring->capacity);
}

uint32_t
shmring_mode(const struct shmring *ring)
{

	if (!ring_is_current(ring))
		return (0);
	return (ring->config->mode);
}

uint32_t
shmring_max_record(const struct shmring *ring)
{

	if (!ring_is_current(ring))
		return (0);
	return (ring->config->max_record);
}

uint32_t
shmring_shape(const struct shmring *ring)
{

	if (!ring_is_current(ring))
		return (0);
	return (ring->config->shape);
}

size_t
shmring_low_watermark(const struct shmring *ring)
{

	if (!ring_is_current(ring))
		return (0);
	return ((size_t)ring->config->low_watermark);
}

size_t
shmring_high_watermark(const struct shmring *ring)
{

	if (!ring_is_current(ring))
		return (0);
	return ((size_t)ring->config->high_watermark);
}

static int
ring_usage(const struct shmring *ring, uint64_t *usedp)
{
	uint64_t head, tail;

	head = atomic_load_explicit(ring->head, memory_order_acquire);
	tail = atomic_load_explicit(ring->tail, memory_order_acquire);
	if (head < tail || head - tail > ring->capacity) {
		errno = EPROTO;
		SHMRING_PROBE_CORRUPT(head, tail, ring->capacity);
		return (-1);
	}
	*usedp = head - tail;
	return (0);
}

ssize_t
shmring_readable(const struct shmring *ring)
{
	uint64_t used;

	if (!ring_is_current(ring) || ring_usage(ring, &used) == -1)
		return (-1);
	return ((ssize_t)used);
}

ssize_t
shmring_writable(const struct shmring *ring)
{
	uint64_t used;

	if (!ring_is_current(ring) || ring_usage(ring, &used) == -1)
		return (-1);
	return ((ssize_t)(ring->capacity - (size_t)used));
}

static void
ring_copy_in(struct shmring *ring, uint64_t position, const void *buf,
    size_t len)
{
	size_t first, offset;

	offset = (size_t)(position & (ring->capacity - 1));
	first = MIN(len, ring->capacity - offset);
	memcpy(ring->data + offset, buf, first);
	memcpy(ring->data, (const uint8_t *)buf + first, len - first);
}

static void
ring_copy_out(struct shmring *ring, uint64_t position, void *buf, size_t len)
{
	size_t first, offset;

	offset = (size_t)(position & (ring->capacity - 1));
	first = MIN(len, ring->capacity - offset);
	memcpy(buf, ring->data + offset, first);
	memcpy((uint8_t *)buf + first, ring->data, len - first);
}

ssize_t
shmring_write(struct shmring *ring, const void *buf, size_t len)
{
	uint64_t head, tail, free_space;
	size_t count;

	if (!ring_is_current(ring))
		return (-1);
	if (ring->role != SHMRING_ROLE_PRODUCER ||
	    ring->config->mode != SHMRING_MODE_STREAM ||
	    (buf == NULL && len != 0) || len > SSIZE_MAX) {
		errno = EINVAL;
		return (-1);
	}
	head = atomic_load_explicit(ring->head, memory_order_relaxed);
	tail = atomic_load_explicit(ring->tail, memory_order_acquire);
	if (head < tail || head - tail > ring->capacity) {
		errno = EPROTO;
		SHMRING_PROBE_CORRUPT(head, tail, ring->capacity);
		return (-1);
	}
	free_space = ring->capacity - (head - tail);
	if (free_space == 0 && len != 0) {
		errno = EAGAIN;
		SHMRING_PROBE_WRITE(SHMRING_MODE_STREAM, len, 0, EAGAIN);
		return (-1);
	}
	count = MIN(len, (size_t)free_space);
	if (count > UINT64_MAX - head) {
		errno = EOVERFLOW;
		SHMRING_PROBE_WRITE(SHMRING_MODE_STREAM, len, 0, EOVERFLOW);
		return (-1);
	}
	ring_copy_in(ring, head, buf, count);
	atomic_store_explicit(ring->head, head + count, memory_order_release);
	SHMRING_PROBE_WRITE(SHMRING_MODE_STREAM, len, count, 0);
	return ((ssize_t)count);
}

ssize_t
shmring_read(struct shmring *ring, void *buf, size_t len)
{
	uint64_t head, tail, used;
	size_t count;

	if (!ring_is_current(ring))
		return (-1);
	if (ring->role != SHMRING_ROLE_CONSUMER ||
	    ring->config->mode != SHMRING_MODE_STREAM ||
	    (buf == NULL && len != 0) || len > SSIZE_MAX) {
		errno = EINVAL;
		return (-1);
	}
	head = atomic_load_explicit(ring->head, memory_order_acquire);
	tail = atomic_load_explicit(ring->tail, memory_order_relaxed);
	if (head < tail || head - tail > ring->capacity) {
		errno = EPROTO;
		SHMRING_PROBE_CORRUPT(head, tail, ring->capacity);
		return (-1);
	}
	used = head - tail;
	if (used == 0 && len != 0) {
		errno = EAGAIN;
		SHMRING_PROBE_READ(SHMRING_MODE_STREAM, len, 0, EAGAIN);
		return (-1);
	}
	count = MIN(len, (size_t)used);
	if (count > UINT64_MAX - tail) {
		errno = EOVERFLOW;
		SHMRING_PROBE_READ(SHMRING_MODE_STREAM, len, 0, EOVERFLOW);
		return (-1);
	}
	ring_copy_out(ring, tail, buf, count);
	atomic_store_explicit(ring->tail, tail + count, memory_order_release);
	SHMRING_PROBE_READ(SHMRING_MODE_STREAM, len, count, 0);
	return ((ssize_t)count);
}

int
shmring_write_record(struct shmring *ring, const void *buf, size_t len)
{
	uint32_t record_len;
	uint64_t head, tail, needed;

	if (!ring_is_current(ring))
		return (-1);
	if (ring->role != SHMRING_ROLE_PRODUCER ||
	    ring->config->mode != SHMRING_MODE_RECORD ||
	    (buf == NULL && len != 0) || len > ring->config->max_record) {
		errno = EINVAL;
		return (-1);
	}
	head = atomic_load_explicit(ring->head, memory_order_relaxed);
	tail = atomic_load_explicit(ring->tail, memory_order_acquire);
	if (head < tail || head - tail > ring->capacity) {
		errno = EPROTO;
		SHMRING_PROBE_CORRUPT(head, tail, ring->capacity);
		return (-1);
	}
	needed = sizeof(record_len) + len;
	if (ring->capacity - (head - tail) < needed) {
		errno = EAGAIN;
		SHMRING_PROBE_WRITE(SHMRING_MODE_RECORD, len, 0, EAGAIN);
		return (-1);
	}
	if (needed > UINT64_MAX - head) {
		errno = EOVERFLOW;
		SHMRING_PROBE_WRITE(SHMRING_MODE_RECORD, len, 0, EOVERFLOW);
		return (-1);
	}
	record_len = (uint32_t)len;
	ring_copy_in(ring, head, &record_len, sizeof(record_len));
	ring_copy_in(ring, head + sizeof(record_len), buf, len);
	atomic_store_explicit(ring->head, head + needed, memory_order_release);
	SHMRING_PROBE_WRITE(SHMRING_MODE_RECORD, len, len, 0);
	return (0);
}

ssize_t
shmring_read_record(struct shmring *ring, void *buf, size_t bufsz)
{
	uint32_t record_len;
	uint64_t head, tail, used, needed;

	if (!ring_is_current(ring))
		return (-1);
	if (ring->role != SHMRING_ROLE_CONSUMER ||
	    ring->config->mode != SHMRING_MODE_RECORD ||
	    (buf == NULL && bufsz != 0)) {
		errno = EINVAL;
		return (-1);
	}
	head = atomic_load_explicit(ring->head, memory_order_acquire);
	tail = atomic_load_explicit(ring->tail, memory_order_relaxed);
	if (head < tail || head - tail > ring->capacity) {
		errno = EPROTO;
		SHMRING_PROBE_CORRUPT(head, tail, ring->capacity);
		return (-1);
	}
	used = head - tail;
	if (used == 0) {
		errno = EAGAIN;
		SHMRING_PROBE_READ(SHMRING_MODE_RECORD, bufsz, 0, EAGAIN);
		return (-1);
	}
	if (used < sizeof(record_len)) {
		errno = EPROTO;
		return (-1);
	}
	ring_copy_out(ring, tail, &record_len, sizeof(record_len));
	needed = sizeof(record_len) + record_len;
	if (record_len > ring->config->max_record ||
	    needed > ring->capacity || needed > used) {
		errno = EPROTO;
		return (-1);
	}
	if (record_len > bufsz) {
		errno = EMSGSIZE;
		return (-1);
	}
	if (needed > UINT64_MAX - tail) {
		errno = EOVERFLOW;
		SHMRING_PROBE_READ(SHMRING_MODE_RECORD, bufsz, 0, EOVERFLOW);
		return (-1);
	}
	ring_copy_out(ring, tail + sizeof(record_len), buf, record_len);
	atomic_store_explicit(ring->tail, tail + needed, memory_order_release);
	SHMRING_PROBE_READ(SHMRING_MODE_RECORD, bufsz, record_len, 0);
	return ((ssize_t)record_len);
}
