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

#ifndef _BHYVE_SNAPSHOT_
#define _BHYVE_SNAPSHOT_

#include <machine/vmm_snapshot.h>
#include <libxo/xo.h>
#include <ucl.h>

#include "checkpoint_topology.h"
#include "checkpoint_cpu.h"

/*
 * A source-paired build obtains this enumerator from vmm_snapshot.h.
 * Incremental bhyve builds may intentionally use an older installed kernel
 * header; validation is userspace-only and never reaches VM_SNAPSHOT_REQ, so
 * retain its stable wire-independent value here as well.
 */
#ifndef VM_SNAPSHOT_VALIDATE
#define	VM_SNAPSHOT_VALIDATE	((enum vm_snapshot_op)2)
#endif

#define BHYVE_RUN_DIR "/var/run/bhyve/"
#define MAX_SNAPSHOT_FILENAME PATH_MAX

struct vmctx;

struct restore_state {
	int kdata_fd;
	int vmmem_fd;

	void *kdata_map;
	size_t kdata_len;

	size_t vmmem_len;

	struct ucl_parser *meta_parser;
	ucl_object_t *meta_root_obj;
};

struct checkpoint_thread_info {
	struct vmctx *ctx;
	int socket_fd;
};

typedef int (*vm_snapshot_dev_cb)(struct vm_snapshot_meta *);
typedef int (*vm_pause_dev_cb) (const char *);
typedef int (*vm_resume_dev_cb) (const char *);

struct vm_snapshot_dev_info {
	const char *dev_name;		/* device name */
	vm_snapshot_dev_cb snapshot_cb;	/* callback for device snapshot */
	vm_pause_dev_cb pause_cb;	/* callback for device pause */
	vm_resume_dev_cb resume_cb;	/* callback for device resume */
};

struct vm_snapshot_kern_info {
	const char *struct_name;	/* kernel structure name*/
	enum snapshot_req req;		/* request type */
};

void destroy_restore_state(struct restore_state *rstate);

const char *lookup_vmname(struct restore_state *rstate);
int lookup_memflags(struct restore_state *rstate, int *memflagsp);
size_t lookup_memsize(struct restore_state *rstate);
int lookup_guest_ncpus(struct restore_state *rstate);
int lookup_cpu_topology(struct restore_state *rstate, int *ncpusp,
    uint16_t *socketsp, uint16_t *coresp, uint16_t *threadsp);
int lookup_cpu_contract(struct restore_state *,
    struct checkpoint_cpu_contract *);
int lookup_numa_topology(struct restore_state *, size_t, uint64_t,
    uint64_t [CHECKPOINT_NUMA_MAX_DOMAINS], size_t *, uint16_t *);
int lookup_memory_geometry(struct restore_state *,
    struct checkpoint_memory_geometry *);

void checkpoint_cpu_add(int vcpu);
void checkpoint_cpu_resume(int vcpu);
void checkpoint_cpu_suspend(int vcpu);

/*
 * A restore destination starts its vCPU threads before its saved CPU state
 * can be published.  Hold those threads at checkpoint_cpu_add() until the
 * restore transaction has committed and all restored devices are resumable.
 * These are deliberately separate from vm_vcpu_pause(): no VM execution has
 * begun, so there is no kernel suspend request to issue or wait for.
 */
void checkpoint_restore_startup_hold(void);
bool checkpoint_restore_startup_held(void);
int checkpoint_restore_startup_release(void);

int restore_vm_mem(struct vmctx *ctx, struct restore_state *rstate);
int vm_restore_preflight(struct restore_state *rstate);
int vm_restore_memory_preflight(struct vmctx *ctx,
    struct restore_state *rstate);
int vm_restore_kern_structs(struct vmctx *ctx, struct restore_state *rstate);

int vm_restore_devices(struct restore_state *rstate);
int vm_restore_transaction(struct vmctx *ctx, struct restore_state *rstate);
int vm_pause_devices(void);
int vm_resume_devices(void);

int get_checkpoint_msg(int conn_fd, struct vmctx *ctx);
void *checkpoint_thread(void *param);
int init_checkpoint_thread(struct vmctx *ctx);

int load_restore_file(const char *filename, struct restore_state *rstate);

/*
 * Live-migration bridge (see snapshot.c).  Serialize device + CPU/vCPU/kernel
 * structure state into a self-describing in-memory blob (guest RAM excluded;
 * it is streamed separately as memory generations), and replay such a blob on
 * a destination whose guest RAM has already been staged.  vm_migrate_commit_state
 * leaves devices paused and the restore startup fence held; vm_migrate_resume
 * releases the destination to run after the source's RELEASE.
 */
int vm_snapshot_dev_state_to_mem(struct vmctx *ctx, uint8_t **blob, size_t *len);
int vm_migrate_commit_state(struct vmctx *ctx, const uint8_t *blob, size_t len);
int vm_migrate_resume(struct vmctx *ctx);

int vm_snapshot_guest2host_addr(struct vmctx *ctx, void **addrp, size_t len,
    bool restore_null, struct vm_snapshot_meta *meta);
int vm_snapshot_u8(uint8_t *value, struct vm_snapshot_meta *meta);
int vm_snapshot_le16(uint16_t *value, struct vm_snapshot_meta *meta);
int vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta);
int vm_snapshot_le64(uint64_t *value, struct vm_snapshot_meta *meta);
int vm_snapshot_nonnegative_int(int *value,
    struct vm_snapshot_meta *meta);

static inline bool
vm_snapshot_is_loading(const struct vm_snapshot_meta *meta)
{

	return (meta->op == VM_SNAPSHOT_RESTORE ||
	    meta->op == VM_SNAPSHOT_VALIDATE);
}

static inline bool
vm_snapshot_is_restoring(const struct vm_snapshot_meta *meta)
{

	return (meta->op == VM_SNAPSHOT_RESTORE);
}

#define	SNAPSHOT_U8_OR_LEAVE(DATA, META, RES, LABEL)			\
do {									\
	(RES) = vm_snapshot_u8(&(DATA), (META));				\
	if ((RES) != 0)						\
		goto LABEL;						\
} while (0)

#define	SNAPSHOT_LE16_OR_LEAVE(DATA, META, RES, LABEL)			\
do {									\
	(RES) = vm_snapshot_le16(&(DATA), (META));			\
	if ((RES) != 0)						\
		goto LABEL;						\
} while (0)

#define	SNAPSHOT_LE32_OR_LEAVE(DATA, META, RES, LABEL)			\
do {									\
	(RES) = vm_snapshot_le32(&(DATA), (META));			\
	if ((RES) != 0)						\
		goto LABEL;						\
} while (0)

#define	SNAPSHOT_LE64_OR_LEAVE(DATA, META, RES, LABEL)			\
do {									\
	(RES) = vm_snapshot_le64(&(DATA), (META));			\
	if ((RES) != 0)						\
		goto LABEL;						\
} while (0)

#define	SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(DATA, META, RES, LABEL)	\
do {									\
	(RES) = vm_snapshot_nonnegative_int(&(DATA), (META));		\
	if ((RES) != 0)						\
		goto LABEL;						\
} while (0)

/*
 * Address variables are pointers to guest memory.
 *
 * When RNULL != 0, do not enforce invalid address checks; instead, make the
 * pointer NULL at restore time.
 */
#define	SNAPSHOT_GUEST2HOST_ADDR_OR_LEAVE(CTX, ADDR, LEN, RNULL, META, RES, LABEL) \
do {										\
	(RES) = vm_snapshot_guest2host_addr((CTX), (void **)&(ADDR), (LEN),	\
	    (RNULL), (META));							\
	if ((RES) != 0) {							\
		if ((RES) == EFAULT)						\
			EPRINTLN("%s: invalid address: %s", __func__, #ADDR);	\
		goto LABEL;							\
	}									\
} while (0)

#include "snapshot_identity.h"

#endif
