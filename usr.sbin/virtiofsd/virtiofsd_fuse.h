/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VIRTIOFSD_FUSE_H_
#define	_VIRTIOFSD_FUSE_H_

#include <sys/stat.h>

#include <stddef.h>
#include <stdint.h>

#define	VIRTIOFSD_FUSE_IN_HEADER_SIZE	40U
#define	VIRTIOFSD_FUSE_OUT_HEADER_SIZE	16U
#define	VIRTIOFSD_FUSE_INIT_IN_SIZE	16U
#define	VIRTIOFSD_FUSE_INIT_OUT_SIZE	64U
#define	VIRTIOFSD_FUSE_ENTRY_OUT_SIZE	128U
#define	VIRTIOFSD_FUSE_ATTR_OUT_SIZE	104U
#define	VIRTIOFSD_FUSE_OPEN_IN_SIZE	8U
#define	VIRTIOFSD_FUSE_OPEN_OUT_SIZE	16U
#define	VIRTIOFSD_FUSE_READ_IN_SIZE	40U
#define	VIRTIOFSD_FUSE_RELEASE_IN_SIZE	24U
#define	VIRTIOFSD_FUSE_FLUSH_IN_SIZE	24U
#define	VIRTIOFSD_FUSE_FSYNC_IN_SIZE	16U
#define	VIRTIOFSD_FUSE_DIRENT_HEADER_SIZE 24U
#define	VIRTIOFSD_FUSE_STATFS_OUT_SIZE	80U

#define	VIRTIOFSD_FUSE_KERNEL_VERSION	7U
#define	VIRTIOFSD_FUSE_KERNEL_MINOR	35U

/*
 * These are FUSE protocol values, not host enum values.  Keep this interface
 * independent of both the guest and host kernel headers.
 */
#define	VIRTIOFSD_FUSE_LOOKUP		1U
#define	VIRTIOFSD_FUSE_FORGET		2U
#define	VIRTIOFSD_FUSE_GETATTR		3U
#define	VIRTIOFSD_FUSE_READLINK		5U
#define	VIRTIOFSD_FUSE_OPEN		14U
#define	VIRTIOFSD_FUSE_READ		15U
#define	VIRTIOFSD_FUSE_STATFS		17U
#define	VIRTIOFSD_FUSE_RELEASE		18U
#define	VIRTIOFSD_FUSE_FSYNC		20U
#define	VIRTIOFSD_FUSE_FLUSH		25U
#define	VIRTIOFSD_FUSE_INIT		26U
#define	VIRTIOFSD_FUSE_OPENDIR		27U
#define	VIRTIOFSD_FUSE_READDIR		28U
#define	VIRTIOFSD_FUSE_RELEASEDIR	29U
#define	VIRTIOFSD_FUSE_FSYNCDIR		30U
#define	VIRTIOFSD_FUSE_ACCESS		34U
#define	VIRTIOFSD_FUSE_DESTROY		38U
#define	VIRTIOFSD_FUSE_BATCH_FORGET	42U

enum virtiofsd_fuse_byte_order {
	VIRTIOFSD_FUSE_ORDER_UNKNOWN = 0,
	VIRTIOFSD_FUSE_ORDER_LITTLE,
	VIRTIOFSD_FUSE_ORDER_BIG,
};

struct virtiofsd_fuse_request {
	enum virtiofsd_fuse_byte_order byte_order;
	uint32_t length;
	uint32_t opcode;
	uint64_t unique;
	uint64_t nodeid;
	uint32_t uid;
	uint32_t gid;
	uint32_t pid;
	const uint8_t *body;
	size_t body_len;
};

struct virtiofsd_fuse_init {
	uint32_t major;
	uint32_t minor;
	uint32_t max_readahead;
	uint32_t flags;
};

struct virtiofsd_fuse_read {
	uint64_t handle;
	uint64_t offset;
	uint32_t size;
	uint32_t read_flags;
	uint64_t lock_owner;
	uint32_t flags;
};

struct virtiofsd_fuse_forget_one {
	uint64_t nodeid;
	uint64_t count;
};

struct virtiofsd_fuse_statfs {
	uint64_t blocks;
	uint64_t free_blocks;
	uint64_t available_blocks;
	uint64_t files;
	uint64_t free_files;
	uint32_t block_size;
	uint32_t maximum_name;
	uint32_t fragment_size;
};

int	virtiofsd_fuse_request_decode(const void *, size_t,
	    enum virtiofsd_fuse_byte_order, struct virtiofsd_fuse_request *);
int	virtiofsd_fuse_name(const struct virtiofsd_fuse_request *,
	    const void **, size_t *);
int	virtiofsd_fuse_forget_decode(const struct virtiofsd_fuse_request *,
	    uint64_t *);
int	virtiofsd_fuse_batch_forget_decode(
	    const struct virtiofsd_fuse_request *, uint32_t *);
int	virtiofsd_fuse_batch_forget_entry(
	    const struct virtiofsd_fuse_request *, uint32_t,
	    struct virtiofsd_fuse_forget_one *);
int	virtiofsd_fuse_getattr_decode(const struct virtiofsd_fuse_request *,
	    uint32_t *, uint64_t *);
int	virtiofsd_fuse_init_decode(const struct virtiofsd_fuse_request *,
	    struct virtiofsd_fuse_init *);
int	virtiofsd_fuse_open_decode(const struct virtiofsd_fuse_request *,
	    uint32_t *);
int	virtiofsd_fuse_read_decode(const struct virtiofsd_fuse_request *,
	    struct virtiofsd_fuse_read *);
int	virtiofsd_fuse_release_decode(const struct virtiofsd_fuse_request *,
	    uint64_t *);
int	virtiofsd_fuse_flush_decode(const struct virtiofsd_fuse_request *,
	    uint64_t *);
int	virtiofsd_fuse_fsync_decode(const struct virtiofsd_fuse_request *,
	    uint64_t *);
int	virtiofsd_fuse_access_decode(const struct virtiofsd_fuse_request *,
	    uint32_t *);
int	virtiofsd_fuse_error_encode(enum virtiofsd_fuse_byte_order,
	    uint64_t, int, uint8_t[VIRTIOFSD_FUSE_OUT_HEADER_SIZE]);
int	virtiofsd_fuse_success_header_encode(enum virtiofsd_fuse_byte_order,
	    uint64_t, uint32_t, uint8_t[VIRTIOFSD_FUSE_OUT_HEADER_SIZE]);
int	virtiofsd_fuse_init_response_encode(
	    enum virtiofsd_fuse_byte_order, uint64_t,
	    const struct virtiofsd_fuse_init *, uint32_t, uint32_t,
	    uint8_t[VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_INIT_OUT_SIZE]);
int	virtiofsd_fuse_entry_response_encode(
	    enum virtiofsd_fuse_byte_order, uint64_t, uint64_t, uint64_t,
	    const struct stat *, uint8_t[VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_ENTRY_OUT_SIZE]);
int	virtiofsd_fuse_attr_response_encode(
	    enum virtiofsd_fuse_byte_order, uint64_t, const struct stat *,
	    uint8_t[VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_ATTR_OUT_SIZE]);
int	virtiofsd_fuse_open_response_encode(
	    enum virtiofsd_fuse_byte_order, uint64_t, uint64_t,
	    uint8_t[VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_OPEN_OUT_SIZE]);
int	virtiofsd_fuse_dirent_encode(enum virtiofsd_fuse_byte_order,
	    uint64_t, uint64_t, uint32_t, const void *, size_t, void *,
	    size_t, size_t *);
int	virtiofsd_fuse_statfs_response_encode(
	    enum virtiofsd_fuse_byte_order, uint64_t,
	    const struct virtiofsd_fuse_statfs *,
	    uint8_t[VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_STATFS_OUT_SIZE]);

#endif
