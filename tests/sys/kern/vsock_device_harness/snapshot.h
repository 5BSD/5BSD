/*-
 * Minimal bhyve snapshot interface for device unit tests.
 *
 * The production wire helpers are supplied by each test so malformed and
 * truncated records can be injected without linking the checkpoint daemon.
 */
#ifndef _VSOCK_DEVICE_HARNESS_SNAPSHOT_H_
#define	_VSOCK_DEVICE_HARNESS_SNAPSHOT_H_

#include <sys/types.h>

#include <machine/vmm_snapshot.h>

/*
 * Device snapshot codecs are machine-independent, but vmm_snapshot.h exists
 * only on architectures whose in-kernel vmm implements checkpoints.  Keep
 * these tests buildable on other architectures with the exact userspace
 * metadata shape consumed by the device models.  This never reaches a kernel
 * ioctl.
 */
#ifndef _VMM_SNAPSHOT_
#define	_VMM_SNAPSHOT_
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
	uint8_t *const buf_start;
	const size_t buf_size;
	uint8_t *buf;
	size_t buf_rem;
};

enum vm_snapshot_op {
	VM_SNAPSHOT_SAVE,
	VM_SNAPSHOT_RESTORE,
	VM_SNAPSHOT_VALIDATE,
};

struct vm_snapshot_meta {
	void *dev_data;
	const char *dev_name;
	enum snapshot_req dev_req;
	struct vm_snapshot_buffer buffer;
	enum vm_snapshot_op op;
};

static inline int
vm_snapshot_op_is_kernel(enum vm_snapshot_op op)
{

	return (op == VM_SNAPSHOT_SAVE || op == VM_SNAPSHOT_RESTORE);
}

#define	SNAPSHOT_BUF_OR_LEAVE(DATA, LEN, META, RES, LABEL) do {	\
	(RES) = vm_snapshot_buf((DATA), (LEN), (META));		\
	if ((RES) != 0) {					\
		vm_snapshot_buf_err(#DATA, (META)->op);		\
		goto LABEL;					\
	}							\
} while (0)
#endif

/*
 * Incremental harness builds may see the installed machine header from the
 * running kernel rather than the source-paired header.  The validation
 * operation does not cross the kernel ABI and is deliberately value-stable.
 */
#ifndef VM_SNAPSHOT_VALIDATE
#define	VM_SNAPSHOT_VALIDATE	((enum vm_snapshot_op)2)
#endif

struct vmctx;

void vm_snapshot_buf_err(const char *, enum vm_snapshot_op);
int vm_snapshot_buf(void *, size_t, struct vm_snapshot_meta *);
int vm_snapshot_guest2host_addr(struct vmctx *, void **, size_t, bool,
    struct vm_snapshot_meta *);
int vm_snapshot_u8(uint8_t *, struct vm_snapshot_meta *);
int vm_snapshot_le16(uint16_t *, struct vm_snapshot_meta *);
int vm_snapshot_le32(uint32_t *, struct vm_snapshot_meta *);
int vm_snapshot_le64(uint64_t *, struct vm_snapshot_meta *);

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

#define	SNAPSHOT_U8_OR_LEAVE(DATA, META, RES, LABEL) do {	\
	(RES) = vm_snapshot_u8(&(DATA), (META));			\
	if ((RES) != 0)						\
		goto LABEL;						\
} while (0)

#define	SNAPSHOT_LE16_OR_LEAVE(DATA, META, RES, LABEL) do {	\
	(RES) = vm_snapshot_le16(&(DATA), (META));		\
	if ((RES) != 0)						\
		goto LABEL;						\
} while (0)

#define	SNAPSHOT_LE32_OR_LEAVE(DATA, META, RES, LABEL) do {	\
	(RES) = vm_snapshot_le32(&(DATA), (META));		\
	if ((RES) != 0)						\
		goto LABEL;						\
} while (0)

#define	SNAPSHOT_LE64_OR_LEAVE(DATA, META, RES, LABEL) do {	\
	(RES) = vm_snapshot_le64(&(DATA), (META));		\
	if ((RES) != 0)						\
		goto LABEL;						\
} while (0)

#define	SNAPSHOT_GUEST2HOST_ADDR_OR_LEAVE(CTX, ADDR, LEN, RNULL, META, RES, \
    LABEL) do {								\
	(RES) = vm_snapshot_guest2host_addr((CTX), (void **)&(ADDR), (LEN),	\
	    (RNULL), (META));						\
	if ((RES) != 0)						\
		goto LABEL;						\
} while (0)

#include "snapshot_identity.h"

#endif
