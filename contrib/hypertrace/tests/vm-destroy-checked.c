/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>

struct vmctx { int ctlfd; char name[128]; };
struct vmmctl_vm_destroy { char name[64]; };
#define VM_MAX_NAMELEN 63
#define HYPERTRACE_MAX_VMS 1024
#include "destroy-identity-abi.inc"
#define VMMCTL_VM_DESTROY 0x7654UL
#define VMMCTL_VM_DESTROY_IDENTITY 0x7655UL
static int fail_destroy, closes, warnings, requests;
static const char *expected_name = "checkpoint-source";

static size_t
test_strlcpy(char *dst, const char *src, size_t size)
{
    size_t length = strlen(src);
    if (size != 0) {
        size_t count = length >= size ? size - 1 : length;
        memcpy(dst, src, count);
        dst[count] = '\0';
    }
    return length;
}

static int
test_ioctl(int fd, unsigned long command, void *argument)
{
    assert(fd == 7);
    if (command == VMMCTL_VM_DESTROY_IDENTITY) {
        struct vmmctl_vm_destroy_identity *destroy = argument;
        assert(destroy->vmid == 7 && destroy->epoch == 9);
        assert(strcmp(destroy->name, expected_name) == 0);
        for (size_t i = 0; i < 3; i++) assert(destroy->reserved[i] == 0);
    } else {
        struct vmmctl_vm_destroy *destroy = argument;
        assert(command == VMMCTL_VM_DESTROY);
        assert(strcmp(destroy->name, "checkpoint-source") == 0);
    }
    requests++;
    if (fail_destroy) {
        errno = fail_destroy == 2 ? ESTALE : fail_destroy == 3 ? ENOTTY : EBUSY;
        return -1;
    }
    return 0;
}

static void vm_close(struct vmctx *vm) { assert(vm != NULL); closes++; }
static void test_warn(const char *format, ...) { assert(format != NULL); warnings++; }
static int opens, fd_closes, fail_open;
static int test_open(const char *path, int flags) {
    assert(strcmp(path, "/dev/vmmctl") == 0);
    assert(flags == (O_RDWR | O_NOFOLLOW | O_CLOEXEC));
    opens++;
    if (fail_open) { errno = ENOENT; return -1; }
    return 7;
}
static int test_close(int fd) {
    assert(fd == 7); fd_closes++; errno = EINTR; return -1;
}
#define open test_open
#define close test_close
#define strlcpy test_strlcpy
#define ioctl test_ioctl
#define warn test_warn
#include "vm-destroy-checked.inc"

int
main(void)
{
    struct vmctx vm = { .ctlfd = 7, .name = "checkpoint-source" };
    assert(vm_destroy_checked(NULL) == -1 && errno == EINVAL);
    assert(requests == 0 && closes == 0);
    fail_destroy = 1;
    assert(vm_destroy_checked(&vm) == -1 && errno == EBUSY);
    assert(requests == 1 && closes == 0);
    fail_destroy = 0;
    assert(vm_destroy_checked(&vm) == 0);
    assert(requests == 2 && closes == 1);
    fail_destroy = 1;
    vm_destroy(&vm);
    assert(requests == 3 && closes == 2 && warnings == 1);
    assert(vm_destroy_identity_checked(NULL, 7, 9) == -1 && errno == EINVAL);
    assert(vm_destroy_identity_checked(&vm, 0, 9) == -1 && errno == EINVAL);
    assert(vm_destroy_identity_checked(&vm, HYPERTRACE_MAX_VMS, 9) == -1 && errno == EINVAL);
    assert(vm_destroy_identity_checked(&vm, 7, 0) == -1 && errno == EINVAL);
    assert(requests == 3 && closes == 2);
    fail_destroy = 2;
    assert(vm_destroy_identity_checked(&vm, 7, 9) == -1 && errno == ESTALE);
    assert(requests == 4 && closes == 2);
    fail_destroy = 3;
    assert(vm_destroy_identity_checked(&vm, 7, 9) == -1 && errno == ENOTTY);
    assert(requests == 5 && closes == 2); /* No fallback to name-only destroy. */
    fail_destroy = 0;
    assert(vm_destroy_identity_checked(&vm, 7, 9) == 0);
    assert(requests == 6 && closes == 3);
    assert(vm_destroy_name_identity_checked(NULL, 7, 9) == -1 && errno == EINVAL);
    assert(vm_destroy_name_identity_checked("", 7, 9) == -1 && errno == EINVAL);
    assert(vm_destroy_name_identity_checked(vm.name, 0, 9) == -1 && errno == EINVAL);
    assert(vm_destroy_name_identity_checked(vm.name, HYPERTRACE_MAX_VMS, 9) == -1 && errno == EINVAL);
    assert(vm_destroy_name_identity_checked(vm.name, 7, 0) == -1 && errno == EINVAL);
    memset(vm.name, 'x', 80); vm.name[80] = 0;
    assert(vm_destroy_name_identity_checked(vm.name, 7, 9) == -1 && errno == ENAMETOOLONG);
    assert(opens == 0 && requests == 6);
    strcpy(vm.name, "checkpoint-source");
    fail_open = 1;
    assert(vm_destroy_name_identity_checked(vm.name, 7, 9) == -1 && errno == ENOENT);
    assert(opens == 1 && requests == 6 && fd_closes == 0);
    fail_open = 0;
    for (int failure = 1; failure <= 3; failure++) {
        fail_destroy = failure;
        int expected = failure == 2 ? ESTALE : failure == 3 ? ENOTTY : EBUSY;
        assert(vm_destroy_name_identity_checked(vm.name, 7, 9) == -1 && errno == expected);
    }
    fail_destroy = 0;
    assert(vm_destroy_name_identity_checked(vm.name, 7, 9) == 0);
    assert(opens == 5 && requests == 10 && fd_closes == 4 && closes == 3);
    for (int failure = 0; failure < 4; failure++) {
        fail_destroy = failure;
        int before = closes;
        assert(vm_destroy_request_checked(&vm) == (failure ? -1 : 0));
        assert(vm_destroy_identity_request_checked(&vm, 7, 9) == (failure ? -1 : 0));
        assert(closes == before);
    }
    /* vm_openf() refuses a longer name; the longest one reaches the kernel whole. */
    fail_destroy = 0;
    memset(vm.name, 'x', VM_MAX_NAMELEN); vm.name[VM_MAX_NAMELEN] = 0;
    expected_name = vm.name;
    assert(vm_destroy_identity_request_checked(&vm, 7, 9) == 0 && requests == 19);
    puts("PASS: checked VM destroy retains retry authority on ioctl failure");
}
