/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/stat.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "virtiofsd_fuse.h"

static uint32_t
fuse_get32(enum virtiofsd_fuse_byte_order order, const void *value)
{

	return (order == VIRTIOFSD_FUSE_ORDER_BIG ?
	    be32dec(value) : le32dec(value));
}

static uint64_t
fuse_get64(enum virtiofsd_fuse_byte_order order, const void *value)
{

	return (order == VIRTIOFSD_FUSE_ORDER_BIG ?
	    be64dec(value) : le64dec(value));
}

static void
fuse_put16(enum virtiofsd_fuse_byte_order order, void *output,
    uint16_t value)
{

	if (order == VIRTIOFSD_FUSE_ORDER_BIG)
		be16enc(output, value);
	else
		le16enc(output, value);
}

static void
fuse_put32(enum virtiofsd_fuse_byte_order order, void *output,
    uint32_t value)
{

	if (order == VIRTIOFSD_FUSE_ORDER_BIG)
		be32enc(output, value);
	else
		le32enc(output, value);
}

static void
fuse_put64(enum virtiofsd_fuse_byte_order order, void *output,
    uint64_t value)
{

	if (order == VIRTIOFSD_FUSE_ORDER_BIG)
		be64enc(output, value);
	else
		le64enc(output, value);
}

static bool
fuse_order_valid(enum virtiofsd_fuse_byte_order order)
{

	return (order == VIRTIOFSD_FUSE_ORDER_LITTLE ||
	    order == VIRTIOFSD_FUSE_ORDER_BIG);
}

static int
fuse_linux_errno(int error)
{

	/*
	 * The virtio-fs FUSE payload uses Linux ABI errno values even when
	 * the device model runs on another host OS.  Errors not listed here
	 * fail closed as EIO rather than leaking a host-specific number.
	 */
	switch (error) {
	case EPERM:		return (1);
	case ENOENT:		return (2);
	case EINTR:		return (4);
	case EIO:		return (5);
	case ENXIO:		return (6);
	case E2BIG:		return (7);
	case ENOEXEC:		return (8);
	case EBADF:		return (9);
	case ECHILD:		return (10);
	case EAGAIN:		return (11);
	case ENOMEM:		return (12);
	case EACCES:		return (13);
	case EFAULT:		return (14);
	case EBUSY:		return (16);
	case EEXIST:		return (17);
	case EXDEV:		return (18);
	case ENODEV:		return (19);
	case ENOTDIR:		return (20);
	case EISDIR:		return (21);
	case EINVAL:		return (22);
	case ENFILE:		return (23);
	case EMFILE:		return (24);
	case ENOTTY:		return (25);
	case EFBIG:		return (27);
	case ENOSPC:		return (28);
	case ESPIPE:		return (29);
	case EROFS:		return (30);
	case EMLINK:		return (31);
	case EPIPE:		return (32);
	case EDOM:		return (33);
	case ERANGE:		return (34);
	case EDEADLK:		return (35);
	case ENAMETOOLONG:	return (36);
	case ENOLCK:		return (37);
	case ENOSYS:		return (38);
	case ENOTEMPTY:		return (39);
	case ELOOP:		return (40);
	case ENOMSG:		return (42);
	case EIDRM:		return (43);
	case EOVERFLOW:		return (75);
	case EOPNOTSUPP:	return (95);
	case ESTALE:		return (116);
	case ECANCELED:		return (125);
	default:		return (5);
	}
}

int
virtiofsd_fuse_request_decode(const void *input, size_t input_len,
    enum virtiofsd_fuse_byte_order expected,
    struct virtiofsd_fuse_request *request)
{
	const uint8_t *bytes;
	enum virtiofsd_fuse_byte_order order;
	uint32_t be_length, be_opcode, le_length, le_opcode;

	if (input == NULL || request == NULL ||
	    input_len < VIRTIOFSD_FUSE_IN_HEADER_SIZE ||
	    input_len > UINT32_MAX)
		return (EINVAL);
	bytes = input;
	order = expected;
	if (order == VIRTIOFSD_FUSE_ORDER_UNKNOWN) {
		le_length = le32dec(bytes);
		le_opcode = le32dec(bytes + 4);
		be_length = be32dec(bytes);
		be_opcode = be32dec(bytes + 4);
		if (le_opcode == VIRTIOFSD_FUSE_INIT &&
		    le_length == input_len)
			order = VIRTIOFSD_FUSE_ORDER_LITTLE;
		else if (be_opcode == VIRTIOFSD_FUSE_INIT &&
		    be_length == input_len)
			order = VIRTIOFSD_FUSE_ORDER_BIG;
		else
			return (EPROTO);
	} else if (!fuse_order_valid(order)) {
		return (EINVAL);
	}
	memset(request, 0, sizeof(*request));
	request->byte_order = order;
	request->length = fuse_get32(order, bytes);
	request->opcode = fuse_get32(order, bytes + 4);
	request->unique = fuse_get64(order, bytes + 8);
	request->nodeid = fuse_get64(order, bytes + 16);
	request->uid = fuse_get32(order, bytes + 24);
	request->gid = fuse_get32(order, bytes + 28);
	request->pid = fuse_get32(order, bytes + 32);
	if (request->length != input_len || request->unique == 0 ||
	    fuse_get32(order, bytes + 36) != 0)
		return (EPROTO);
	request->body = bytes + VIRTIOFSD_FUSE_IN_HEADER_SIZE;
	request->body_len = input_len - VIRTIOFSD_FUSE_IN_HEADER_SIZE;
	return (0);
}

int
virtiofsd_fuse_name(const struct virtiofsd_fuse_request *request,
    const void **name, size_t *name_len)
{
	const uint8_t *terminator;

	if (request == NULL || name == NULL || name_len == NULL ||
	    request->body == NULL || request->body_len < 2)
		return (EINVAL);
	terminator = memchr(request->body, '\0', request->body_len);
	if (terminator == NULL ||
	    terminator != request->body + request->body_len - 1)
		return (EPROTO);
	*name = request->body;
	*name_len = request->body_len - 1;
	return (0);
}

int
virtiofsd_fuse_forget_decode(const struct virtiofsd_fuse_request *request,
    uint64_t *count)
{

	if (request == NULL || count == NULL || request->body == NULL ||
	    request->body_len != 8)
		return (EINVAL);
	*count = fuse_get64(request->byte_order, request->body);
	if (*count == 0)
		return (EPROTO);
	return (0);
}

int
virtiofsd_fuse_batch_forget_decode(
    const struct virtiofsd_fuse_request *request, uint32_t *count)
{
	size_t entries, expected;

	if (request == NULL || count == NULL || request->body == NULL ||
	    request->body_len < 8)
		return (EINVAL);
	*count = fuse_get32(request->byte_order, request->body);
	if (*count == 0 ||
	    fuse_get32(request->byte_order, request->body + 4) != 0)
		return (EPROTO);
	if (__builtin_mul_overflow((size_t)*count, (size_t)16, &entries) ||
	    __builtin_add_overflow((size_t)8, entries, &expected))
		return (EPROTO);
	if (request->body_len != expected)
		return (EPROTO);
	return (0);
}

int
virtiofsd_fuse_batch_forget_entry(
    const struct virtiofsd_fuse_request *request, uint32_t index,
    struct virtiofsd_fuse_forget_one *entry)
{
	uint32_t count;
	const uint8_t *wire;
	int error;

	if (entry == NULL)
		return (EINVAL);
	error = virtiofsd_fuse_batch_forget_decode(request, &count);
	if (error != 0)
		return (error);
	if (index >= count)
		return (ERANGE);
	wire = request->body + 8 + (size_t)index * 16;
	entry->nodeid = fuse_get64(request->byte_order, wire);
	entry->count = fuse_get64(request->byte_order, wire + 8);
	if (entry->nodeid == 0 || entry->count == 0)
		return (EPROTO);
	return (0);
}

int
virtiofsd_fuse_getattr_decode(const struct virtiofsd_fuse_request *request,
    uint32_t *flags, uint64_t *handle)
{

	if (request == NULL || flags == NULL || handle == NULL)
		return (EINVAL);
	*flags = 0;
	*handle = 0;
	if (request->body_len == 0)
		return (0);
	if (request->body == NULL || request->body_len != 16)
		return (EINVAL);
	*flags = fuse_get32(request->byte_order, request->body);
	if ((*flags & ~1U) != 0 ||
	    fuse_get32(request->byte_order, request->body + 4) != 0)
		return (EPROTO);
	*handle = fuse_get64(request->byte_order, request->body + 8);
	if (((*flags & 1U) == 0 && *handle != 0) ||
	    ((*flags & 1U) != 0 && *handle == 0))
		return (EPROTO);
	return (0);
}

int
virtiofsd_fuse_init_decode(const struct virtiofsd_fuse_request *request,
    struct virtiofsd_fuse_init *init)
{

	if (request == NULL || init == NULL ||
	    request->opcode != VIRTIOFSD_FUSE_INIT ||
	    request->body == NULL ||
	    request->body_len < VIRTIOFSD_FUSE_INIT_IN_SIZE)
		return (EINVAL);
	init->major = fuse_get32(request->byte_order, request->body);
	init->minor = fuse_get32(request->byte_order, request->body + 4);
	init->max_readahead = fuse_get32(request->byte_order,
	    request->body + 8);
	init->flags = fuse_get32(request->byte_order, request->body + 12);
	return (0);
}

int
virtiofsd_fuse_open_decode(const struct virtiofsd_fuse_request *request,
    uint32_t *flags)
{

	if (request == NULL || flags == NULL || request->body == NULL ||
	    request->body_len != VIRTIOFSD_FUSE_OPEN_IN_SIZE)
		return (EINVAL);
	*flags = fuse_get32(request->byte_order, request->body);
	/* FUSE_OPEN_KILL_SUIDGID is the only defined request-side bit. */
	if ((fuse_get32(request->byte_order, request->body + 4) & ~1U) != 0)
		return (EPROTO);
	return (0);
}

int
virtiofsd_fuse_read_decode(const struct virtiofsd_fuse_request *request,
    struct virtiofsd_fuse_read *read_request)
{

	if (request == NULL || read_request == NULL ||
	    request->body == NULL ||
	    request->body_len != VIRTIOFSD_FUSE_READ_IN_SIZE)
		return (EINVAL);
	read_request->handle = fuse_get64(request->byte_order, request->body);
	read_request->offset = fuse_get64(request->byte_order,
	    request->body + 8);
	read_request->size = fuse_get32(request->byte_order,
	    request->body + 16);
	read_request->read_flags = fuse_get32(request->byte_order,
	    request->body + 20);
	read_request->lock_owner = fuse_get64(request->byte_order,
	    request->body + 24);
	read_request->flags = fuse_get32(request->byte_order,
	    request->body + 32);
	/* FUSE_READ_LOCKOWNER is the only defined read_flags bit. */
	if ((read_request->read_flags & ~UINT32_C(2)) != 0 ||
	    fuse_get32(request->byte_order, request->body + 36) != 0)
		return (EPROTO);
	return (0);
}

int
virtiofsd_fuse_release_decode(const struct virtiofsd_fuse_request *request,
    uint64_t *handle)
{
	uint32_t release_flags;

	if (request == NULL || handle == NULL || request->body == NULL ||
	    request->body_len != VIRTIOFSD_FUSE_RELEASE_IN_SIZE)
		return (EINVAL);
	*handle = fuse_get64(request->byte_order, request->body);
	release_flags = fuse_get32(request->byte_order, request->body + 12);
	if ((release_flags & ~3U) != 0)
		return (EPROTO);
	return (0);
}

int
virtiofsd_fuse_flush_decode(const struct virtiofsd_fuse_request *request,
    uint64_t *handle)
{

	if (request == NULL || handle == NULL || request->body == NULL ||
	    request->body_len != VIRTIOFSD_FUSE_FLUSH_IN_SIZE)
		return (EINVAL);
	*handle = fuse_get64(request->byte_order, request->body);
	if (fuse_get32(request->byte_order, request->body + 8) != 0 ||
	    fuse_get32(request->byte_order, request->body + 12) != 0)
		return (EPROTO);
	return (0);
}

int
virtiofsd_fuse_fsync_decode(const struct virtiofsd_fuse_request *request,
    uint64_t *handle)
{
	uint32_t flags;

	if (request == NULL || handle == NULL || request->body == NULL ||
	    request->body_len != VIRTIOFSD_FUSE_FSYNC_IN_SIZE)
		return (EINVAL);
	*handle = fuse_get64(request->byte_order, request->body);
	flags = fuse_get32(request->byte_order, request->body + 8);
	if ((flags & ~1U) != 0 ||
	    fuse_get32(request->byte_order, request->body + 12) != 0)
		return (EPROTO);
	return (0);
}

int
virtiofsd_fuse_access_decode(const struct virtiofsd_fuse_request *request,
    uint32_t *mask)
{

	if (request == NULL || mask == NULL || request->body == NULL ||
	    request->body_len != 8)
		return (EINVAL);
	*mask = fuse_get32(request->byte_order, request->body);
	if (fuse_get32(request->byte_order, request->body + 4) != 0 ||
	    (*mask & ~7U) != 0)
		return (EPROTO);
	return (0);
}

int
virtiofsd_fuse_success_header_encode(
    enum virtiofsd_fuse_byte_order order, uint64_t unique,
    uint32_t body_len, uint8_t output[VIRTIOFSD_FUSE_OUT_HEADER_SIZE])
{

	if (!fuse_order_valid(order) || unique == 0 ||
	    body_len > UINT32_MAX - VIRTIOFSD_FUSE_OUT_HEADER_SIZE ||
	    output == NULL)
		return (EINVAL);
	fuse_put32(order, output,
	    VIRTIOFSD_FUSE_OUT_HEADER_SIZE + body_len);
	fuse_put32(order, output + 4, 0);
	fuse_put64(order, output + 8, unique);
	return (0);
}

int
virtiofsd_fuse_error_encode(enum virtiofsd_fuse_byte_order order,
    uint64_t unique, int error,
    uint8_t output[VIRTIOFSD_FUSE_OUT_HEADER_SIZE])
{

	if (!fuse_order_valid(order) || unique == 0 || error <= 0 ||
	    output == NULL)
		return (EINVAL);
	fuse_put32(order, output, VIRTIOFSD_FUSE_OUT_HEADER_SIZE);
	fuse_put32(order, output + 4,
	    (uint32_t)-(int32_t)fuse_linux_errno(error));
	fuse_put64(order, output + 8, unique);
	return (0);
}

static void
fuse_attr_encode(enum virtiofsd_fuse_byte_order order, const struct stat *sb,
    uint8_t output[88])
{

	memset(output, 0, 88);
	fuse_put64(order, output, (uint64_t)sb->st_ino);
	fuse_put64(order, output + 8, (uint64_t)sb->st_size);
	fuse_put64(order, output + 16, (uint64_t)sb->st_blocks);
	fuse_put64(order, output + 24, (uint64_t)sb->st_atim.tv_sec);
	fuse_put64(order, output + 32, (uint64_t)sb->st_mtim.tv_sec);
	fuse_put64(order, output + 40, (uint64_t)sb->st_ctim.tv_sec);
	fuse_put32(order, output + 48, (uint32_t)sb->st_atim.tv_nsec);
	fuse_put32(order, output + 52, (uint32_t)sb->st_mtim.tv_nsec);
	fuse_put32(order, output + 56, (uint32_t)sb->st_ctim.tv_nsec);
	fuse_put32(order, output + 60, (uint32_t)sb->st_mode);
	fuse_put32(order, output + 64, (uint32_t)sb->st_nlink);
	fuse_put32(order, output + 68, (uint32_t)sb->st_uid);
	fuse_put32(order, output + 72, (uint32_t)sb->st_gid);
	/*
	 * The export layer rejects device nodes.  Keep the Linux wire rdev
	 * zero rather than leaking an incompatible host dev_t encoding.
	 */
	fuse_put32(order, output + 76, 0);
	fuse_put32(order, output + 80, (uint32_t)sb->st_blksize);
}

int
virtiofsd_fuse_init_response_encode(enum virtiofsd_fuse_byte_order order,
    uint64_t unique, const struct virtiofsd_fuse_init *init,
    uint32_t supported_flags, uint32_t maximum_write,
    uint8_t output[VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
    VIRTIOFSD_FUSE_INIT_OUT_SIZE])
{
	uint32_t minor;

	if (init == NULL || output == NULL ||
	    init->major != VIRTIOFSD_FUSE_KERNEL_VERSION ||
	    maximum_write == 0)
		return (EINVAL);
	minor = init->minor < VIRTIOFSD_FUSE_KERNEL_MINOR ?
	    init->minor : VIRTIOFSD_FUSE_KERNEL_MINOR;
	memset(output, 0, VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_INIT_OUT_SIZE);
	if (virtiofsd_fuse_success_header_encode(order, unique,
	    VIRTIOFSD_FUSE_INIT_OUT_SIZE, output) != 0)
		return (EINVAL);
	fuse_put32(order, output + 16, VIRTIOFSD_FUSE_KERNEL_VERSION);
	fuse_put32(order, output + 20, minor);
	fuse_put32(order, output + 24, init->max_readahead);
	fuse_put32(order, output + 28, init->flags & supported_flags);
	fuse_put16(order, output + 32, 64);
	fuse_put16(order, output + 34, 48);
	fuse_put32(order, output + 36, maximum_write);
	fuse_put32(order, output + 40, 1);
	return (0);
}

int
virtiofsd_fuse_entry_response_encode(enum virtiofsd_fuse_byte_order order,
    uint64_t unique, uint64_t nodeid, uint64_t generation,
    const struct stat *sb, uint8_t output[VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
    VIRTIOFSD_FUSE_ENTRY_OUT_SIZE])
{

	if (nodeid == 0 || generation == 0 || sb == NULL || output == NULL)
		return (EINVAL);
	memset(output, 0, VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_ENTRY_OUT_SIZE);
	if (virtiofsd_fuse_success_header_encode(order, unique,
	    VIRTIOFSD_FUSE_ENTRY_OUT_SIZE, output) != 0)
		return (EINVAL);
	fuse_put64(order, output + 16, nodeid);
	fuse_put64(order, output + 24, generation);
	fuse_attr_encode(order, sb, output + 56);
	return (0);
}

int
virtiofsd_fuse_attr_response_encode(enum virtiofsd_fuse_byte_order order,
    uint64_t unique, const struct stat *sb,
    uint8_t output[VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
    VIRTIOFSD_FUSE_ATTR_OUT_SIZE])
{

	if (sb == NULL || output == NULL)
		return (EINVAL);
	memset(output, 0, VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_ATTR_OUT_SIZE);
	if (virtiofsd_fuse_success_header_encode(order, unique,
	    VIRTIOFSD_FUSE_ATTR_OUT_SIZE, output) != 0)
		return (EINVAL);
	fuse_attr_encode(order, sb, output + 32);
	return (0);
}

int
virtiofsd_fuse_open_response_encode(enum virtiofsd_fuse_byte_order order,
    uint64_t unique, uint64_t handle,
    uint8_t output[VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
    VIRTIOFSD_FUSE_OPEN_OUT_SIZE])
{

	if (handle == 0 || output == NULL)
		return (EINVAL);
	memset(output, 0, VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_OPEN_OUT_SIZE);
	if (virtiofsd_fuse_success_header_encode(order, unique,
	    VIRTIOFSD_FUSE_OPEN_OUT_SIZE, output) != 0)
		return (EINVAL);
	fuse_put64(order, output + 16, handle);
	return (0);
}

int
virtiofsd_fuse_dirent_encode(enum virtiofsd_fuse_byte_order order,
    uint64_t inode, uint64_t next_offset, uint32_t linux_type,
    const void *name, size_t name_len, void *output, size_t capacity,
    size_t *written)
{
	uint8_t *bytes;
	size_t unaligned, total;

	if (!fuse_order_valid(order) || next_offset == 0 || name == NULL ||
	    name_len == 0 || name_len > UINT32_MAX || output == NULL ||
	    written == NULL || linux_type > 15 ||
	    memchr(name, '\0', name_len) != NULL ||
	    memchr(name, '/', name_len) != NULL ||
	    name_len > SIZE_MAX - VIRTIOFSD_FUSE_DIRENT_HEADER_SIZE)
		return (EINVAL);
	unaligned = VIRTIOFSD_FUSE_DIRENT_HEADER_SIZE + name_len;
	if (unaligned > SIZE_MAX - 7U)
		return (EOVERFLOW);
	total = (unaligned + 7U) & ~(size_t)7U;
	if (total > capacity)
		return (ENOBUFS);
	bytes = output;
	memset(bytes, 0, total);
	fuse_put64(order, bytes, inode);
	fuse_put64(order, bytes + 8, next_offset);
	fuse_put32(order, bytes + 16, (uint32_t)name_len);
	fuse_put32(order, bytes + 20, linux_type);
	memcpy(bytes + VIRTIOFSD_FUSE_DIRENT_HEADER_SIZE, name, name_len);
	*written = total;
	return (0);
}

int
virtiofsd_fuse_statfs_response_encode(
    enum virtiofsd_fuse_byte_order order, uint64_t unique,
    const struct virtiofsd_fuse_statfs *statfs,
    uint8_t output[VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
    VIRTIOFSD_FUSE_STATFS_OUT_SIZE])
{
	uint8_t *body;

	if (!fuse_order_valid(order) || statfs == NULL || output == NULL ||
	    statfs->block_size == 0 || statfs->fragment_size == 0)
		return (EINVAL);
	memset(output, 0, VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_STATFS_OUT_SIZE);
	if (virtiofsd_fuse_success_header_encode(order, unique,
	    VIRTIOFSD_FUSE_STATFS_OUT_SIZE, output) != 0)
		return (EINVAL);
	body = output + VIRTIOFSD_FUSE_OUT_HEADER_SIZE;
	fuse_put64(order, body, statfs->blocks);
	fuse_put64(order, body + 8, statfs->free_blocks);
	fuse_put64(order, body + 16, statfs->available_blocks);
	fuse_put64(order, body + 24, statfs->files);
	fuse_put64(order, body + 32, statfs->free_files);
	fuse_put32(order, body + 40, statfs->block_size);
	fuse_put32(order, body + 44, statfs->maximum_name);
	fuse_put32(order, body + 48, statfs->fragment_size);
	return (0);
}
