/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <sys/socket.h>
#include "migration_source_owner.h"

int main(void)
{
    char path[] = "recovery-permissions.XXXXXX";
    assert(mkdtemp(path) != NULL);
    int directory = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(directory >= 0);
    int file = openat(directory, "record", O_CREAT | O_EXCL | O_RDWR, 0600);
    assert(file >= 0);
    unsigned checks = 0;
    for (mode_t mode = 0; mode <= 0777; ++mode) {
        int expected = (mode & 077) ? EPERM : 0;
        assert(fchmod(file, mode) == 0);
        assert(migration_recovery_file_check(file, false) == expected);
        assert(migration_recovery_file_check(file, true) == EPERM);
        assert(fchmod(directory, mode) == 0);
        assert(migration_recovery_file_check(directory, true) == expected);
        assert(migration_recovery_file_check(directory, false) == EPERM);
        checks += 4;
    }
    assert(fchmod(directory, 0700) == 0 && fchmod(file, 0600) == 0);
    assert(linkat(directory, "record", directory, "alias", 0) == 0);
    assert(migration_recovery_file_check(file, false) == EPERM);
    assert(unlinkat(directory, "alias", 0) == 0);
    assert(migration_recovery_file_check(file, false) == 0);
    assert(unlinkat(directory, "record", 0) == 0);
    assert(migration_recovery_file_check(file, false) == EPERM);
    assert(close(file) == 0);
    assert(migration_recovery_file_check(-1, false) == EBADF);
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(migration_recovery_file_check(pair[0], false) == EPERM);
    assert(migration_recovery_file_check(pair[0], true) == EPERM);
    assert(close(pair[0]) == 0 && close(pair[1]) == 0);
    checks += 6;
    // A hard-linked lock must never acquire controller authority.
    const char *lock = "source-controller-0007-0000000000000009.lock";
    file = openat(directory, lock, O_CREAT | O_EXCL | O_RDWR, 0600);
    assert(file >= 0);
    assert(linkat(directory, lock, directory, "alias", 0) == 0);
    int owned = -123;
    assert(migration_source_controller_lock_at(directory, 7, 9, &owned) == EPERM);
    assert(owned == -123);
    assert(unlinkat(directory, "alias", 0) == 0);
    assert(migration_source_controller_lock_at(directory, 7, 9, &owned) == 0);
    assert(owned >= 0 && (fcntl(owned, F_GETFD) & FD_CLOEXEC));
    int contender = -123;
    for (unsigned i = 0; i < 128; ++i) {
        assert(migration_source_controller_lock_at(directory, 7, 9, &contender) == EBUSY);
        assert(contender == -123);
        ++checks;
    }
    assert(close(owned) == 0);
    assert(migration_source_controller_lock_at(directory, 7, 9, &contender) == 0);
    assert(close(contender) == 0 && close(file) == 0);
    assert(unlinkat(directory, lock, 0) == 0);
    assert(close(directory) == 0 && rmdir(path) == 0);
    checks += 3;
    printf("PASS: %u recovery permission, inode-link, and ownership checks\n", checks);
}
