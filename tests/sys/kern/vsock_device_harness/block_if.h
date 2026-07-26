/* Minimal block backend interface for the VirtIO block device harness. */
#ifndef MOCK_BLOCK_IF_H
#define MOCK_BLOCK_IF_H

#include <sys/types.h>
#include <sys/uio.h>

#include "config.h"

#define BLOCKIF_IOV_MAX 128
#define BLOCKIF_RING_MAX 1024

struct blockif_req {
	int br_iovcnt;
	off_t br_offset;
	ssize_t br_resid;
	void (*br_callback)(struct blockif_req *, int);
	void *br_param;
	struct iovec br_iov[BLOCKIF_IOV_MAX];
};

struct blockif_ctxt;
struct pci_devinst;
typedef void blockif_resize_cb(struct blockif_ctxt *, void *, size_t);

int blockif_legacy_config(nvlist_t *, const char *);
int blockif_add_boot_device(struct pci_devinst *, struct blockif_ctxt *);
struct blockif_ctxt *blockif_open(nvlist_t *, const char *);
int blockif_register_resize_callback(struct blockif_ctxt *,
    blockif_resize_cb *, void *);
off_t blockif_size(struct blockif_ctxt *);
void blockif_chs(struct blockif_ctxt *, uint16_t *, uint8_t *, uint8_t *);
int blockif_sectsz(struct blockif_ctxt *);
void blockif_psectsz(struct blockif_ctxt *, int *, int *);
int blockif_queuesz(struct blockif_ctxt *);
int blockif_is_ro(struct blockif_ctxt *);
int blockif_candelete(struct blockif_ctxt *);
int blockif_read(struct blockif_ctxt *, struct blockif_req *);
int blockif_write(struct blockif_ctxt *, struct blockif_req *);
int blockif_write_zeroes(struct blockif_ctxt *, struct blockif_req *);
int blockif_flush(struct blockif_ctxt *, struct blockif_req *);
int blockif_delete(struct blockif_ctxt *, struct blockif_req *);
int blockif_cancel(struct blockif_ctxt *, struct blockif_req *);
int blockif_close(struct blockif_ctxt *);
int blockif_suspend(struct blockif_ctxt *);
void blockif_resume(struct blockif_ctxt *);

#endif
