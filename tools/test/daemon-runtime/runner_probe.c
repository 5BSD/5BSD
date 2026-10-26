/* SPDX-License-Identifier: BSD-2-Clause */
/* Deliberately failing cases verify the VM runner, never product acceptance. */
#include <sys/types.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <atf-c.h>

ATF_TC_WITH_CLEANUP(cleanup_pass);
ATF_TC_HEAD(cleanup_pass, tc) { atf_tc_set_md_var(tc, "timeout", "5"); }
ATF_TC_BODY(cleanup_pass, tc) {
    int fd = open("body-state", O_CREAT | O_EXCL | O_WRONLY, 0600);
    (void)tc;
    ATF_REQUIRE(fd >= 0);
    ATF_REQUIRE_EQ(0, close(fd));
}
ATF_TC_CLEANUP(cleanup_pass, tc) {
    (void)tc;
    if (unlink("body-state") != 0) { perror("body state missing"); exit(1); }
    puts("RUNNER_PROBE_CLEANUP_EXECUTED");
}
ATF_TC_WITH_CLEANUP(cleanup_fail);
ATF_TC_HEAD(cleanup_fail, tc) { atf_tc_set_md_var(tc, "timeout", "5"); }
ATF_TC_BODY(cleanup_fail, tc) { (void)tc; }
ATF_TC_CLEANUP(cleanup_fail, tc) { (void)tc; fputs("deliberate cleanup failure\n", stderr); exit(1); }
ATF_TC_WITH_CLEANUP(body_fail);
ATF_TC_HEAD(body_fail, tc) { atf_tc_set_md_var(tc, "timeout", "5"); }
ATF_TC_BODY(body_fail, tc) { (void)tc; atf_tc_fail("deliberate body failure"); }
ATF_TC_CLEANUP(body_fail, tc) { (void)tc; puts("RUNNER_PROBE_FAILED_BODY_CLEANED"); }
ATF_TC_WITH_CLEANUP(body_timeout);
ATF_TC_HEAD(body_timeout, tc) { atf_tc_set_md_var(tc, "timeout", "1"); }
ATF_TC_BODY(body_timeout, tc) { (void)tc; for (;;) pause(); }
ATF_TC_CLEANUP(body_timeout, tc) { (void)tc; puts("RUNNER_PROBE_TIMED_OUT_BODY_CLEANED"); }
/* An explicit VM-only case; retain a sentinel outside the /tmp tmpfs. */
ATF_TC(disk_retention);
ATF_TC_HEAD(disk_retention, tc) {
    atf_tc_set_md_var(tc, "require.user", "root");
    atf_tc_set_md_var(tc, "timeout", "10");
}
ATF_TC_BODY(disk_retention, tc) {
    static const char path[] = "/root/runner-disk-retention";
    static const char value[] = "private fixture persistence\n";
    char buffer[sizeof(value)], guest[32];
    size_t guest_len = sizeof(guest);
    struct statfs filesystem;
    int fd;
    (void)tc;
    ATF_REQUIRE_EQ(0, sysctlbyname("kern.vm_guest", guest, &guest_len, NULL, 0));
    ATF_REQUIRE(guest[0] != '\0' && strcmp(guest, "none") != 0);
    /* Normal rc remounts the root writable. This fixture runs without rc. */
    ATF_REQUIRE_EQ(0, statfs("/", &filesystem));
    ATF_REQUIRE(strcmp(filesystem.f_fstypename, "ufs") == 0);
    if (filesystem.f_flags & MNT_RDONLY) {
        char fstype[] = "fstype", fspath[] = "fspath", root[] = "/", from[] = "from", rw[] = "rw";
        struct iovec options[] = {
            { .iov_base = fstype, .iov_len = sizeof(fstype) },
            { .iov_base = filesystem.f_fstypename,
              .iov_len = strlen(filesystem.f_fstypename) + 1 },
            { .iov_base = fspath, .iov_len = sizeof(fspath) },
            { .iov_base = root, .iov_len = sizeof(root) },
            { .iov_base = from, .iov_len = sizeof(from) },
            { .iov_base = filesystem.f_mntfromname,
              .iov_len = strlen(filesystem.f_mntfromname) + 1 },
            { .iov_base = rw, .iov_len = sizeof(rw) },
            { .iov_base = NULL, .iov_len = 0 }
        };
        ATF_REQUIRE_MSG(nmount(options, 8, MNT_UPDATE) == 0,
            "remount fixture root: %s", strerror(errno));
    }
    ATF_REQUIRE_EQ(0, statfs("/", &filesystem));
    ATF_REQUIRE_MSG((filesystem.f_flags & MNT_RDONLY) == 0, "fixture root remains read-only");
    fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        ATF_REQUIRE_EQ((ssize_t)(sizeof(value) - 1), write(fd, value, sizeof(value) - 1));
        ATF_REQUIRE_EQ(0, fsync(fd));
        ATF_REQUIRE_EQ(0, close(fd));
        puts("RUNNER_DISK_FIRST_BOOT");
    } else {
        ATF_REQUIRE_MSG(errno == EEXIST, "open %s: %s (%d)", path, strerror(errno), errno);
        fd = open(path, O_RDONLY | O_NOFOLLOW);
        ATF_REQUIRE(fd >= 0);
        ATF_REQUIRE_EQ((ssize_t)(sizeof(value) - 1), read(fd, buffer, sizeof(buffer)));
        ATF_REQUIRE_EQ(0, memcmp(buffer, value, sizeof(value) - 1));
        ATF_REQUIRE_EQ(0, close(fd));
        puts("RUNNER_DISK_RETAINED_BOOT");
    }
}
/* Read a real disk and require refusal of an identical raw-block write. */
ATF_TC(readonly_input_disk);
ATF_TC_HEAD(readonly_input_disk, tc) {
    atf_tc_set_md_var(tc, "require.user", "root");
    atf_tc_set_md_var(tc, "timeout", "10");
}
ATF_TC_BODY(readonly_input_disk, tc) {
    char device[64], buffer[512], guest[32];
    size_t length = sizeof(guest);
    FILE *input;
    int fd, error;
    ssize_t written;
    (void)tc;
    ATF_REQUIRE_EQ(0, sysctlbyname("kern.vm_guest", guest, &length, NULL, 0));
    ATF_REQUIRE(guest[0] != '\0' && strcmp(guest, "none") != 0);
    input = fopen("/tests/input-device", "r");
    ATF_REQUIRE(input != NULL);
    ATF_REQUIRE(fgets(device, sizeof(device), input) != NULL);
    ATF_REQUIRE_EQ(0, fclose(input));
    /* The runner exclusively reserves the second virtio slot for this input. */
    ATF_REQUIRE(strcmp(device, "/dev/vtbd1\n") == 0);
    device[strcspn(device, "\n")] = '\0';
    fd = open(device, O_RDONLY | O_NOFOLLOW);
    ATF_REQUIRE(fd >= 0);
    ATF_REQUIRE_EQ((ssize_t)sizeof(buffer), pread(fd, buffer, sizeof(buffer), 0));
    ATF_REQUIRE_EQ(0, close(fd));
    fd = open(device, O_RDWR | O_NOFOLLOW);
    if (fd < 0) {
        ATF_REQUIRE_MSG(errno == EROFS || errno == EACCES || errno == EPERM,
            "unexpected write-open refusal: %s", strerror(errno));
    } else {
        written = pwrite(fd, buffer, sizeof(buffer), 0);
        error = errno;
        ATF_REQUIRE_EQ(0, close(fd));
        ATF_REQUIRE_MSG(written == -1 &&
            (error == EROFS || error == EACCES || error == EPERM),
            "input disk allowed write or failed unexpectedly: bytes=%zd errno=%d", written, error);
    }
    puts("READONLY_INPUT_DISK_PASS: readable raw disk refused identical block write");
}
ATF_TC(output_disk);
ATF_TC_HEAD(output_disk, tc) {
    atf_tc_set_md_var(tc, "require.user", "root");
    atf_tc_set_md_var(tc, "timeout", "10");
}
ATF_TC_BODY(output_disk, tc) {
    char device[64], guest[32], block[512] = {0}, readback[512];
    const char marker[] = "5BSD-OUTPUT-DISK\n";
    size_t length = sizeof(guest);
    off_t bytes;
    FILE *input;
    int fd;
    (void)tc;
    ATF_REQUIRE_EQ(0, sysctlbyname("kern.vm_guest", guest, &length, NULL, 0));
    ATF_REQUIRE(guest[0] != '\0' && strcmp(guest, "none") != 0);
    input = fopen("/tests/output-device", "r");
    ATF_REQUIRE(input != NULL);
    ATF_REQUIRE(fgets(device, sizeof(device), input) != NULL);
    ATF_REQUIRE_EQ(0, fclose(input));
    ATF_REQUIRE(strcmp(device, "/dev/vtbd2\n") == 0);
    device[strcspn(device, "\n")] = '\0';
    fd = open(device, O_RDWR | O_NOFOLLOW);
    ATF_REQUIRE(fd >= 0);
    ATF_REQUIRE_EQ(0, ioctl(fd, DIOCGMEDIASIZE, &bytes));
    ATF_REQUIRE(bytes >= 1024 && bytes % sizeof(block) == 0);
    memcpy(block, marker, sizeof(marker) - 1);
    ATF_REQUIRE_EQ((ssize_t)sizeof(block), pwrite(fd, block, sizeof(block), 0));
    ATF_REQUIRE_EQ((ssize_t)sizeof(block), pwrite(fd, block, sizeof(block), bytes - sizeof(block)));
    ATF_REQUIRE_EQ(0, fsync(fd));
    ATF_REQUIRE_EQ((ssize_t)sizeof(block), pread(fd, readback, sizeof(readback), bytes - sizeof(block)));
    ATF_REQUIRE(memcmp(block, readback, sizeof(block)) == 0);
    ATF_REQUIRE_EQ(0, close(fd));
    puts("OUTPUT_DISK_PASS: first and last blocks written and flushed");
}
ATF_TP_ADD_TCS(tp) {
    ATF_TP_ADD_TC(tp, disk_retention);
    ATF_TP_ADD_TC(tp, readonly_input_disk);
    ATF_TP_ADD_TC(tp, output_disk);
    ATF_TP_ADD_TC(tp, cleanup_pass);
    ATF_TP_ADD_TC(tp, cleanup_fail);
    ATF_TP_ADD_TC(tp, body_fail);
    ATF_TP_ADD_TC(tp, body_timeout);
    return atf_no_error();
}
