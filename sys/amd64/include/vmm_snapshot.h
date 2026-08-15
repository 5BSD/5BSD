/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2016 Flavius Anton
 * Copyright (c) 2016 Mihai Tiganus
 * Copyright (c) 2016-2019 Mihai Carabas
 * Copyright (c) 2017-2019 Darius Mihai
 * Copyright (c) 2017-2019 Elena Mihailescu
 * Copyright (c) 2018-2019 Sergiu Weisz
 * All rights reserved.
 * The bhyve-snapshot feature was developed under sponsorships
 * from Matthew Grooms.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _VMM_SNAPSHOT_
#define _VMM_SNAPSHOT_

#include <sys/errno.h>
#include <sys/types.h>
#ifndef _KERNEL
#include <stdbool.h>
#endif

enum snapshot_req {
	STRUCT_VIOAPIC = 1,
	STRUCT_VM,
	STRUCT_VLAPIC,
	VM_MEM,
	STRUCT_VHPET,
	STRUCT_VMCX,
	STRUCT_VATPIC,
	STRUCT_VATPIT,
	STRUCT_VPMTMR,
	STRUCT_VRTC,
};

struct vm_snapshot_buffer {
	/*
	 * R/O for device-specific functions;
	 * written by generic snapshot functions.
	 */
	uint8_t *const buf_start;
	const size_t buf_size;

	/*
	 * R/W for device-specific functions used to keep track of buffer
	 * current position and remaining size.
	 */
	uint8_t *buf;
	size_t buf_rem;

	/*
	 * Length of the snapshot is either determined as (buf_size - buf_rem)
	 * or (buf - buf_start) -- the second variation returns a signed value
	 * so it may not be appropriate.
	 *
	 * Use vm_get_snapshot_size(meta).
	 */
};

enum vm_snapshot_op {
	VM_SNAPSHOT_SAVE,
	VM_SNAPSHOT_RESTORE,
	/*
	 * Userspace-only, side-effect-free restore validation.  bhyve never
	 * sends this operation through VM_SNAPSHOT_REQ; keeping it in the
	 * common metadata type lets device codecs consume the exact restore
	 * wire representation without inventing a second parser.
	 */
	VM_SNAPSHOT_VALIDATE,
};

/* Operations accepted by the kernel VM_SNAPSHOT_REQ ABI. */
static __inline int
vm_snapshot_op_is_kernel(enum vm_snapshot_op op)
{

	return (op == VM_SNAPSHOT_SAVE || op == VM_SNAPSHOT_RESTORE);
}

struct vm_snapshot_meta {
	void *dev_data;
	const char *dev_name;      /* identify userspace devices */
	enum snapshot_req dev_req; /* identify kernel structs */

	struct vm_snapshot_buffer buffer;

	enum vm_snapshot_op op;
};

/*
 * Private bhyve checkpoint publication session ABI.  This is deliberately
 * separate from vm_snapshot_meta: a session owns transient kernel admission
 * state across multiple record ioctls and the userspace durability boundary,
 * but none of that state is part of a checkpoint image.
 */
#define	VM_SNAPSHOT_SESSION_VERSION	1U

enum vm_snapshot_session_op {
	VM_SNAPSHOT_SESSION_BEGIN = 1,
	VM_SNAPSHOT_SESSION_COMMIT = 2,
	VM_SNAPSHOT_SESSION_ABORT = 3,
	/* Descriptor-scoped recovery after an ambiguous BEGIN copyout. */
	VM_SNAPSHOT_SESSION_ABORT_CURRENT = 4,
};

struct vm_snapshot_session {
	uint32_t version;
	uint32_t op;
	uint64_t session_id;
	uint64_t flags;
	uint64_t reserved[2];
};

_Static_assert(sizeof(struct vm_snapshot_session) == 40,
    "vm_snapshot_session ABI");

void vm_snapshot_buf_err(const char *bufname, const enum vm_snapshot_op op);
int vm_snapshot_buf(void *data, size_t data_size,
    struct vm_snapshot_meta *meta);
size_t vm_get_snapshot_size(struct vm_snapshot_meta *meta);

#define	SNAPSHOT_BUF_OR_LEAVE(DATA, LEN, META, RES, LABEL)			\
do {										\
	(RES) = vm_snapshot_buf((DATA), (LEN), (META));				\
	if ((RES) != 0) {							\
		vm_snapshot_buf_err(#DATA, (META)->op);				\
		goto LABEL;							\
	}									\
} while (0)

#define	SNAPSHOT_VAR_OR_LEAVE(DATA, META, RES, LABEL)				\
	SNAPSHOT_BUF_OR_LEAVE(&(DATA), sizeof(DATA), (META), (RES), LABEL)

#ifndef _KERNEL
int vm_snapshot_buf_cmp(void *data, size_t data_size,
    struct vm_snapshot_meta *meta);

/* compare the value in the meta buffer with the data */
#define	SNAPSHOT_BUF_CMP_OR_LEAVE(DATA, LEN, META, RES, LABEL)			\
do {										\
	(RES) = vm_snapshot_buf_cmp((DATA), (LEN), (META));			\
	if ((RES) != 0) {							\
		vm_snapshot_buf_err(#DATA, (META)->op);				\
		goto LABEL;							\
	}									\
} while (0)

#define	SNAPSHOT_VAR_CMP_OR_LEAVE(DATA, META, RES, LABEL)			\
	SNAPSHOT_BUF_CMP_OR_LEAVE(&(DATA), sizeof(DATA), (META), (RES), LABEL)

#endif	/* _KERNEL */
#endif
