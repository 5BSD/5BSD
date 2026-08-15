/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_PMEM_HOST_H_
#define	_BHYVE_VIRTIO_PMEM_HOST_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	BHYVE_VIRTIO_PMEM_CONFIG_SIZE	16U
#define	BHYVE_VIRTIO_PMEM_REQUEST_SIZE	4U
#define	BHYVE_VIRTIO_PMEM_RESPONSE_SIZE	4U

typedef int (*virtio_pmem_flush_cb)(void *);

struct virtio_pmem_backing {
	int		fd;
	void		*mapping;
	size_t		size;
	dev_t		device;
	ino_t		inode;
};

int	virtio_pmem_config_encode(uint64_t, uint64_t, bool, void *, size_t);
int	virtio_pmem_request_decode(const void *, size_t);
int	virtio_pmem_response_encode(int, void *, size_t);
int	virtio_pmem_process_request(const void *, size_t, void *, size_t,
	    virtio_pmem_flush_cb, void *, size_t *);
void	virtio_pmem_backing_init(struct virtio_pmem_backing *);
int	virtio_pmem_backing_open(struct virtio_pmem_backing *, const char *);
int	virtio_pmem_backing_flush(void *);
void	virtio_pmem_backing_close(struct virtio_pmem_backing *);

#endif
