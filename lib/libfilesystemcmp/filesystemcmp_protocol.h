/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _FILESYSTEMCMP_PROTOCOL_H_
#define	_FILESYSTEMCMP_PROTOCOL_H_

#include <sys/types.h>

#include <stdint.h>

#define	FILESYSTEMCMP_MAGIC		0x46434d50U	/* "FCMP" */
#define	FILESYSTEMCMP_ABI_VERSION	1
#define	FILESYSTEMCMP_INTERFACE	"system.Filesystem"
#define	FILESYSTEMCMP_INTERFACE_VERSION	"1.0.0"
#define	FILESYSTEMCMP_MAX_MESSAGE	14336
#define	FILESYSTEMCMP_NAME_MAX		255
#define	FILESYSTEMCMP_PATH_MAX		4096
#define	FILESYSTEMCMP_INLINE_MAX	(FILESYSTEMCMP_MAX_MESSAGE - \
	    sizeof(struct filesystemcmp_msg) - \
	    sizeof(struct filesystemcmp_io_request))

#define	FILESYSTEMCMP_MSG_F_MASK	0U

#define	FILESYSTEMCMP_FEATURE_INLINE_IO	0x00000001U
#define	FILESYSTEMCMP_FEATURE_PERSISTENT	0x00000002U
#define	FILESYSTEMCMP_FEATURE_BUNDLE	0x00000004U

#define	FILESYSTEMCMP_OPEN_READ		0x00000001U
#define	FILESYSTEMCMP_OPEN_WRITE	0x00000002U
#define	FILESYSTEMCMP_OPEN_TRUNCATE	0x00000004U
#define	FILESYSTEMCMP_OPEN_MASK		0x00000007U

#define	FILESYSTEMCMP_CREATE_EXCLUSIVE	0x00000001U
#define	FILESYSTEMCMP_CREATE_DIRECTORY	0x00000002U
#define	FILESYSTEMCMP_CREATE_MASK	0x00000003U

enum filesystemcmp_opcode {
	FILESYSTEMCMP_OP_HELLO = 1,
	FILESYSTEMCMP_OP_OPEN_ROOT,
	FILESYSTEMCMP_OP_LOOKUP,
	FILESYSTEMCMP_OP_OPEN,
	FILESYSTEMCMP_OP_CREATE,
	FILESYSTEMCMP_OP_READ,
	FILESYSTEMCMP_OP_WRITE,
	FILESYSTEMCMP_OP_STAT,
	FILESYSTEMCMP_OP_UNLINK,
	FILESYSTEMCMP_OP_RENAME,
	FILESYSTEMCMP_OP_CLOSE,
	FILESYSTEMCMP_OP_OPEN_NAMESPACE,
	FILESYSTEMCMP_OP_SYNC,
	FILESYSTEMCMP_OP_DUP
};

enum filesystemcmp_namespace {
	FILESYSTEMCMP_NAMESPACE_SCRATCH = 1,
	FILESYSTEMCMP_NAMESPACE_PERSISTENT = 2,
	FILESYSTEMCMP_NAMESPACE_BUNDLE = 3
};

enum filesystemcmp_message_role {
	FILESYSTEMCMP_MESSAGE_REQUEST = 1,
	FILESYSTEMCMP_MESSAGE_REPLY,
	FILESYSTEMCMP_MESSAGE_EVENT
};

struct filesystemcmp_msg {
	uint32_t	magic;
	uint16_t	version;
	uint16_t	opcode;
	uint32_t	flags;
	int32_t		status;
} __attribute__((aligned(8)));

_Static_assert(sizeof(struct filesystemcmp_msg) == 16,
    "filesystemcmp message header ABI");

struct filesystemcmp_handle {
	uint64_t	object;
	uint64_t	generation;
};

struct filesystemcmp_hello {
	uint32_t	min_version;
	uint32_t	max_version;
	uint32_t	features;
	uint32_t	reserved;
};

struct filesystemcmp_hello_reply {
	uint32_t	version;
	uint32_t	features;
	uint64_t	max_bytes;
	uint64_t	max_objects;
};

struct filesystemcmp_namespace_request {
	uint32_t	namespace;
	uint32_t	reserved;
};

struct filesystemcmp_handle_reply {
	struct filesystemcmp_handle handle;
	uint32_t	type;
	uint32_t	reserved;
};

struct filesystemcmp_lookup_request {
	struct filesystemcmp_handle directory;
	uint32_t	name_length;
	uint32_t	flags;
	/* name_length non-NUL bytes follow */
};

struct filesystemcmp_open_request {
	struct filesystemcmp_handle object;
	uint32_t	flags;
	uint32_t	reserved;
};

struct filesystemcmp_create_request {
	struct filesystemcmp_handle directory;
	uint32_t	name_length;
	uint32_t	flags;
	uint32_t	mode;
	uint32_t	reserved;
	/* name_length non-NUL bytes follow */
};

struct filesystemcmp_io_request {
	struct filesystemcmp_handle object;
	uint64_t	offset;
	uint32_t	length;
	uint32_t	flags;
	/* WRITE data follows; READ data is returned in the reply. */
};

struct filesystemcmp_io_reply {
	uint32_t	length;
	uint32_t	reserved;
	/* READ data follows. */
};

struct filesystemcmp_unlink_request {
	struct filesystemcmp_handle directory;
	uint32_t	name_length;
	uint32_t	flags;
	/* name_length non-NUL bytes follow */
};

struct filesystemcmp_rename_request {
	struct filesystemcmp_handle old_directory;
	struct filesystemcmp_handle new_directory;
	uint32_t	old_name_length;
	uint32_t	new_name_length;
	uint32_t	flags;
	uint32_t	reserved;
	/* old name followed by new name; neither is NUL terminated. */
};

struct filesystemcmp_close_request {
	struct filesystemcmp_handle object;
};

struct filesystemcmp_stat_reply {
	uint64_t	size;
	uint64_t	inode;
	uint64_t	modified_sec;
	uint32_t	mode;
	uint32_t	type;
};

enum filesystemcmp_object_type {
	FILESYSTEMCMP_TYPE_REGULAR = 1,
	FILESYSTEMCMP_TYPE_DIRECTORY = 2
};

#endif /* !_FILESYSTEMCMP_PROTOCOL_H_ */
