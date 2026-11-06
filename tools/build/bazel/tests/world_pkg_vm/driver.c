/* SPDX-License-Identifier: BSD-2-Clause */
/* Package mechanisms in a disposable VM; this is not normal system startup. */
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <atf-c.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
mount_fs(const char *type, const char *from, const char *to, int flags)
{
    struct iovec iov[] = {
        { .iov_base = "fstype", .iov_len = sizeof("fstype") },
        { .iov_base = __DECONST(char *, type), .iov_len = strlen(type) + 1 },
        { .iov_base = "fspath", .iov_len = sizeof("fspath") },
        { .iov_base = __DECONST(char *, to), .iov_len = strlen(to) + 1 },
        { .iov_base = "from", .iov_len = sizeof("from") },
        { .iov_base = __DECONST(char *, from), .iov_len = strlen(from) + 1 },
    };
    return nmount(iov, sizeof(iov) / sizeof(iov[0]), flags);
}

static void
read_device(const char *path, char *device, size_t size)
{
    FILE *stream = fopen(path, "r");
    ATF_REQUIRE_MSG(stream != NULL, "%s: %s", path, strerror(errno));
    ATF_REQUIRE(fgets(device, size, stream) != NULL);
    ATF_REQUIRE_EQ(fclose(stream), 0);
    device[strcspn(device, "\r\n")] = '\0';
    ATF_REQUIRE_MSG(strncmp(device, "/dev/", 5) == 0 &&
        strstr(device, "..") == NULL, "invalid private VM device");
}

ATF_TC_WITH_CLEANUP(packages);
ATF_TC_HEAD(packages, tc)
{
    atf_tc_set_md_var(tc, "descr", "Complete native pkgbase install and state-preserving reinstall");
    atf_tc_set_md_var(tc, "require.user", "root");
    atf_tc_set_md_var(tc, "timeout", "900");
}
ATF_TC_BODY(packages, tc)
{
    char guest[32], input[128], output[128];
    size_t length = sizeof(guest);
    pid_t child;
    int status, ch;
    FILE *report;
    struct statfs fs;
    (void)tc;
    ATF_REQUIRE_EQ(geteuid(), 0);
    ATF_REQUIRE_EQ(sysctlbyname("kern.vm_guest", guest, &length, NULL, 0), 0);
    ATF_REQUIRE(guest[0] != '\0' && strcmp(guest, "none") != 0);
    read_device("/tests/input-device", input, sizeof(input));
    read_device("/tests/output-device", output, sizeof(output));
    ATF_REQUIRE_MSG(mount_fs("ufs", output, "/fixture", 0) == 0,
        "mount private target: %s", strerror(errno));
    ATF_REQUIRE_EQ(statfs("/fixture", &fs), 0);
    ATF_REQUIRE(strcmp(fs.f_fstypename, "ufs") == 0 && !(fs.f_flags & MNT_RDONLY));
    ATF_REQUIRE_EQ(mkdir("/fixture/.pkg-check", 0700), 0);
    ATF_REQUIRE_EQ(mkdir("/fixture/.pkg-check/inputs", 0755), 0);
    ATF_REQUIRE_MSG(mount_fs("ufs", input, "/fixture/.pkg-check/inputs", MNT_RDONLY) == 0,
        "mount private input: %s", strerror(errno));
    ATF_REQUIRE_MSG(mount_fs("devfs", "devfs", "/fixture/dev", 0) == 0,
        "mount private devfs: %s", strerror(errno));
    puts("WORLD_PKG_VM_DISK_TARGET type=ufs input=readonly target=writable");
    child = fork();
    ATF_REQUIRE(child >= 0);
    if (child == 0) {
        char *const env[] = { "PATH=/usr/bin:/bin", "LC_ALL=C",
            "PYTHONHOME=/runtime/python-home", "LD_LIBRARY_PATH=/runtime/python-libs",
            "PYTHONDONTWRITEBYTECODE=1", NULL };
        char *const args[] = { "/runtime/python", "-B", "/runtime/world-pkg-install-check.py",
            "--root", "/fixture", "--inputs", "/fixture/.pkg-check/inputs",
            "--pkg", "/runtime/checker-inputs/pkg-static",
            "--output", "/tmp/world-pkg-install.json", NULL };
        execve(args[0], args, env);
        perror("exec package checker");
        _exit(127);
    }
    while (waitpid(child, &status, 0) < 0)
        ATF_REQUIRE_EQ(errno, EINTR);
    report = fopen("/tmp/world-pkg-install.json", "r");
    if (report != NULL) {
        puts("WORLD_PKG_INSTALL_REPORT_BEGIN");
        while ((ch = fgetc(report)) != EOF)
            putchar(ch);
        puts("WORLD_PKG_INSTALL_REPORT_END");
        fclose(report);
        fflush(stdout);
    }
    ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
        "checker failed, status %#x; inspect serial report", status);
    ATF_REQUIRE_MSG(report != NULL, "checker report missing");
}
ATF_TC_CLEANUP(packages, tc)
{
    struct statfs fs;
    const char *paths[] = { "/fixture/dev", "/fixture/.pkg-check/inputs", "/fixture" };
    int failed = 0;
    (void)tc;
    for (unsigned i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if (statfs(paths[i], &fs) != 0)
            continue;
        if (strcmp(fs.f_mntonname, paths[i]) == 0 && unmount(paths[i], 0) != 0) {
            fprintf(stderr, "cleanup %s: %s\n", paths[i], strerror(errno));
            failed = 1;
        }
    }
    if (failed)
        _exit(1);
}
ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, packages);
    return atf_no_error();
}
