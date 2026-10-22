/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/dtrace.h>
#include <sys/ioctl.h>
#include <dlfcn.h>
#include <link.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

dof_hdr_t __SUNW_dof = { .dofh_ident = { 0x7f, 'D', 'O', 'F' } };
extern int __llvm_profile_set_file_object(FILE *, int);
extern int __llvm_profile_write_file(void);
extern void __llvm_profile_set_dumped(void);
static int opens, adds, removes, closes, bad;
static int mode(const char *s) { return strcmp(getenv("HT_CASE"), s) == 0; }
int __wrap_dlinfo(void *handle, int request, void *arg)
{
    static Link_map map;
    static Elf64_Ehdr elf;
    (void)handle;
    if (request != RTLD_DI_LINKMAP) abort();
    if (mode("loader-fail")) return -1;
    if (mode("loader-null")) { *(Link_map **)arg = NULL; return 0; }
    elf.e_type = mode("exec-image") ? ET_EXEC : ET_DYN;
    map.l_base = (void *)&elf;
    map.l_name = mode("null-name") ? NULL : mode("empty-name") ? "" : mode("plain-name") ? "fixture" : "/offline/fixture";
    *(Link_map **)arg = &map;
    if (mode("corrupt")) __SUNW_dof.dofh_ident[0] = 0;
    for (int i = 1; i < 4; i++) {
        char label[16]; snprintf(label, sizeof(label), "corrupt%d", i);
        if (mode(label)) __SUNW_dof.dofh_ident[i] = 0;
    }
    return 0;
}
int __wrap_open(const char *path, int flags, ...)
{
    opens++;
    const char *expected = mode("default-device") ? "/dev/dtrace/helper" : "/offline/helper";
    if (strcmp(path, expected) != 0 || flags != O_RDWR) bad++;
    if (mode("open-fail") || (mode("cleanup-open-fail") && opens == 2)) { errno = EACCES; return -1; }
    return 907;
}
int __wrap_close(int fd) { if (fd != 907) bad++; closes++; return 0; }
int __wrap_ioctl(int fd, unsigned long request, ...)
{
    va_list ap;
    void *arg;
    if (fd != 907) abort();
    va_start(ap, request); arg = va_arg(ap, void *); va_end(ap);
    if (request == DTRACEHIOC_ADDDOF) {
        dof_helper_t *dh = arg;
        adds++;
        if (mode("exec-image") ? dh->dofhp_addr != 0 : dh->dofhp_addr == 0) bad++;
        const char *name = (mode("null-name") || mode("empty-name")) ? "unknown" : "fixture";
        if (strcmp(dh->dofhp_mod, name) || dh->dofhp_pid != getpid() || dh->dofhp_dof != (uintptr_t)&__SUNW_dof) bad++;
        if (mode("add-fail")) { errno = EINVAL; return -1; }
        dh->dofhp_gen = 42;
        return 0;
    }
    if (request == DTRACEHIOC_REMOVE) {
        removes++;
        if (*(int *)arg != 42) bad++;
        if (mode("remove-fail")) { errno = EIO; return -1; }
        return 0;
    }
    abort();
}
/* Lower priority runs after the production object's default destructor. */
__attribute__((destructor(101))) static void verify(void)
{
    int registered = !(mode("disabled") || mode("loader-fail") || mode("loader-null") || mode("corrupt") || mode("corrupt1") || mode("corrupt2") || mode("corrupt3") || mode("open-fail") || mode("add-fail"));
    int attempted = registered || mode("open-fail") || mode("add-fail");
    int expected_opens = attempted + registered;
    int expected_adds = registered || mode("add-fail");
    int expected_removes = registered && !mode("cleanup-open-fail");
    int expected_closes = expected_adds + expected_removes;
    FILE *profile = fopen(getenv("HT_FINAL_PROFILE"), "w+b");
    if (profile == NULL || __llvm_profile_set_file_object(profile, 0) != 0 ||
        __llvm_profile_write_file() != 0) abort();
    __llvm_profile_set_dumped();
    if (fclose(profile) != 0) abort();
    int passed = !bad && opens == expected_opens && adds == expected_adds && removes == expected_removes && closes == expected_closes;
    printf("{\"passed\":%s,\"opens\":%d,\"adds\":%d,\"removes\":%d,\"closes\":%d,\"bad\":%d}\n", passed ? "true" : "false", opens, adds, removes, closes, bad);
}
int main(void) { return 0; }
