/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _SHMRING_H_
#define	_SHMRING_H_

#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>

#define	SHMRING_ABI_VERSION	1
#define	SHMRING_MIN_CAPACITY	4096
#define	SHMRING_MAX_CAPACITY	(1U << 30)
#define	SHMRING_NFDS		4

#define	SHMRING_ROLE_PRODUCER	1
#define	SHMRING_ROLE_CONSUMER	2

#define	SHMRING_MODE_STREAM	1
#define	SHMRING_MODE_RECORD	2

/*
 * A ring endpoint consists of immutable configuration, data, producer-head,
 * and consumer-tail objects.  Descriptor rights differ by endpoint role.
 */
struct shmring_fds {
	int	config_fd;
	int	data_fd;
	int	head_fd;
	int	tail_fd;
};

struct shmring;

__BEGIN_DECLS

int	shmring_create(size_t capacity, uint32_t mode, uint32_t max_record,
	    uint64_t generation, struct shmring_fds *producer,
	    struct shmring_fds *consumer);
int	shmring_open(struct shmring **ringp, const struct shmring_fds *fds,
	    uint32_t role);
void	shmring_close(struct shmring *ring);
void	shmring_fds_close(struct shmring_fds *fds);

uint64_t shmring_generation(const struct shmring *ring);
size_t	shmring_capacity(const struct shmring *ring);
uint32_t shmring_mode(const struct shmring *ring);
uint32_t shmring_max_record(const struct shmring *ring);
size_t	shmring_readable(const struct shmring *ring);
size_t	shmring_writable(const struct shmring *ring);

ssize_t	shmring_write(struct shmring *ring, const void *buf, size_t len);
ssize_t	shmring_read(struct shmring *ring, void *buf, size_t len);
int	shmring_write_record(struct shmring *ring, const void *buf, size_t len);
ssize_t	shmring_read_record(struct shmring *ring, void *buf, size_t bufsz);

__END_DECLS

#endif /* !_SHMRING_H_ */
