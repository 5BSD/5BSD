/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <dev/vmm/vmm_param.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VMMAPI_OPEN_CREATE 1
#define VMMAPI_OPEN_REINIT 2
struct vmctx {
    int fd, ctlfd, memflags;
    uint16_t id;
    char *name;
    char memsegs[16];
};
static int fail_alloc, ctl_calls;
static void *test_malloc(size_t size)
{
    if (fail_alloc) { errno = ENOMEM; return NULL; }
    return malloc(size);
}
static int vm_ctl_open(void) { ctl_calls++; errno = EACCES; return -1; }
static int vm_device_open(const char *name) { (void)name; return -1; }
static int vm_ctl_create(const char *name, int flags, int fd)
{ (void)name; (void)flags; (void)fd; return -1; }
static int vm_reinit(struct vmctx *vm) { (void)vm; return -1; }
static void vm_close(struct vmctx *vm) { free(vm); }
static void vm_destroy(struct vmctx *vm) { free(vm); }
#define malloc test_malloc
#include "vmmapi-open.inc"
#undef malloc

int
main(void)
{
    char long_name[VM_MAX_NAMELEN + 2];
    memset(long_name, 'x', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = '\0';
    assert(vm_openf(NULL, 0) == NULL && errno == EINVAL && ctl_calls == 0);
    assert(vm_openf(long_name, 0) == NULL && errno == ENAMETOOLONG &&
        ctl_calls == 0);
    fail_alloc = 1;
    assert(vm_openf("guest", 0) == NULL && errno == ENOMEM && ctl_calls == 0);
    fail_alloc = 0;
    assert(vm_openf("guest", 0) == NULL && errno == EACCES && ctl_calls == 1);
    puts("PASS: VM open rejects null, overlong and allocation-failure inputs");
    return 0;
}
