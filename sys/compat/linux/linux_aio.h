/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Linux legacy AIO ABI.  Context and ring state are Linuxulator-owned;
 * asynchronous file I/O may reuse native kernel mechanisms internally.
 */
#ifndef _LINUX_AIO_H_
#define _LINUX_AIO_H_

#include <sys/types.h>

#define LINUX_IOCB_CMD_PREAD       0
#define LINUX_IOCB_CMD_PWRITE      1
#define LINUX_IOCB_CMD_FSYNC       2
#define LINUX_IOCB_CMD_FDSYNC      3
#define LINUX_IOCB_CMD_POLL        5
#define LINUX_IOCB_CMD_PREADV      7
#define LINUX_IOCB_CMD_PWRITEV     8
#define LINUX_IOCB_FLAG_RESFD      0x00000001U
#define LINUX_IOCB_FLAG_IOPRIO     0x00000002U
#define LINUX_AIO_RING_MAGIC      0xa10a10a1U
#define LINUX_AIO_RING_COMPAT      1U

/* This layout is 64 bytes on both the native and compat32 Linux ABIs. */
struct l_aio_iocb {
	uint64_t data;
#if BYTE_ORDER == LITTLE_ENDIAN
	uint32_t key;
	uint32_t rw_flags;
#else
	uint32_t rw_flags;
	uint32_t key;
#endif
	uint16_t opcode;
	int16_t reqprio;
	uint32_t fd;
	uint64_t buf;
	uint64_t nbytes;
	int64_t offset;
	uint64_t reserved2;
	uint32_t flags;
	uint32_t resfd;
};

struct l_aio_event {
	uint64_t data;
	uint64_t obj;
	int64_t res;
	int64_t res2;
};

/* mmap-visible header preceding io_event records. */
struct l_aio_ring {
	uint32_t id;
	uint32_t nr;
	uint32_t head;
	uint32_t tail;
	uint32_t magic;
	uint32_t compat_features;
	uint32_t incompat_features;
	uint32_t header_length;
	struct l_aio_event events[];
};

struct l_aio_sigset {
	l_uintptr_t mask;
	l_size_t size;
};

_Static_assert(sizeof(struct l_aio_iocb) == 64, "Linux iocb size");
_Static_assert(sizeof(struct l_aio_event) == 32, "Linux io_event size");
_Static_assert(sizeof(struct l_aio_ring) == 32, "Linux AIO ring header size");

#endif /* _LINUX_AIO_H_ */
