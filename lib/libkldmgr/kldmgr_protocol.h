/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _KLDMGR_PROTOCOL_H_
#define	_KLDMGR_PROTOCOL_H_

#include <stdint.h>

#define	KLDMGR_INTERFACE		"org.5bsd.system.kldmgr"
#define	KLDMGR_INTERFACE_VERSION	"1.0.0"
#define	KLDMGR_MAGIC			0x4b4c444dU	/* "KLDM" */
#define	KLDMGR_ABI_VERSION		1
#define	KLDMGR_NAME_MAX			128
#define	KLDMGR_LIST_MAX			64
#define	KLDMGR_MAX_MESSAGE		16384

enum kldmgr_opcode {
	KLDMGR_OP_LOAD = 1,
	KLDMGR_OP_UNLOAD,
	KLDMGR_OP_LIST
};

struct kldmgr_msg {
	uint32_t	magic;
	uint16_t	version;
	uint16_t	opcode;
	uint32_t	flags;
	int32_t		status;
};

_Static_assert(sizeof(struct kldmgr_msg) == 16, "kldmgr header ABI");

struct kldmgr_module_request {
	char	name[KLDMGR_NAME_MAX];
};

struct kldmgr_id_reply {
	int32_t	id;
	uint32_t reserved;
};

struct kldmgr_list_entry {
	int32_t	id;
	char	name[KLDMGR_NAME_MAX];
};

struct kldmgr_list_reply {
	uint32_t count;
	uint32_t reserved;
	struct kldmgr_list_entry entries[];
};

#endif
