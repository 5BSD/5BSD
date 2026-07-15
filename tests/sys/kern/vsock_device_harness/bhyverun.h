/* Mock of bhyve bhyverun.h for the vsock device harness. */
#ifndef MOCK_BHYVERUN_H
#define MOCK_BHYVERUN_H
#include <stddef.h>
#include <stdint.h>
struct vmctx;
int fbsdrun_virtio_msix(void);
void *paddr_guest2host(struct vmctx *, uintptr_t, size_t);
#endif
