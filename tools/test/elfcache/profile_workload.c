/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int
main(void)
{
    struct kinfo_proc info;
    size_t length = sizeof(info);
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    if (sysctl(mib, 4, &info, &length, NULL, 0) < 0 || info.ki_traceflag != 0) return (1);
    void *math = dlopen("/lib/libm.so.5", RTLD_NOW | RTLD_LOCAL);
    if (math == NULL || dlsym(math, "cos") == NULL) return (2);
    int fd = open("/lib/libutil.so.10", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return (3);
    void *util = fdlopen(fd, RTLD_NOW | RTLD_LOCAL);
    if (util == NULL || dlsym(util, "pidfile_open") == NULL) return (4);
    close(fd); dlclose(util); dlclose(math);
    puts("LOADER_PROFILE_WORKLOAD_OK traceflags=0 dlopen=ok fdlopen=ok");
    return (0);
}
