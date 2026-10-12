/* SPDX-License-Identifier: BSD-2-Clause */
/* Disposable-VM PID 1 only: never run this probe as the host init. */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>
#include "sys/cap_authority.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libutil.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#define NWORKERS 24
static int failures;
static volatile int private_state;
static void
check(int ok, const char *name)
{
    printf("CHECK %s %s errno=%d\n", ok ? "PASS" : "FAIL", name, errno);
    if (!ok) failures++;
}
static int
operation(int op, int fd, void *data)
{
    return ((int)syscall(SYS_cap_process, op, fd, 0, data));
}
static double
now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec + ts.tv_nsec / 1e9);
}
static void
publish(int issuer, int cache)
{
    struct cap_cache_publish p = {.cache_fd = cache};
    check(operation(CAP_CACHE_PUBLISH, issuer, &p) == 0, "publish");
}
struct residency {
    long objects;
    long anonymous;
    long cache;
};
static struct residency
residency(void)
{
    struct residency result = {0};
    int count = 0;
    struct kinfo_vmobject *objects = kinfo_getvmobject(&count);
    check(objects != NULL, "vm-object-snapshot");
    for (int i = 0; i < count; i++) {
        result.objects += objects[i].kvo_resident;
        if (objects[i].kvo_type == KVME_TYPE_SWAP)
            result.anonymous += objects[i].kvo_resident;
        if (strstr(objects[i].kvo_path, "candidate") != NULL)
            result.cache += objects[i].kvo_resident;
    }
    free(objects);
    return (result);
}
static void
batch(const char *mode, unsigned round)
{
    pid_t children[NWORKERS];
    int release[NWORKERS], mapped = 0;
    long resident_pages = 0;
    (void)residency(); /* Warm observer allocations before the baseline. */
    struct residency before = residency();
    double start = now();
    for (int i = 0; i < NWORKERS; i++) {
        int ready[2], gate[2];
        if (pipe(ready) || pipe(gate)) { check(0, "pipe"); return; }
        children[i] = fork();
        if (children[i] == 0) {
            char id[20];
            /* Use high intermediates: dup2 must not overwrite either pipe. */
            int a = fcntl(ready[1], F_DUPFD, 100);
            int b = fcntl(gate[0], F_DUPFD, 100);
            dup2(a, 3); dup2(b, 4); closefrom(5);
            snprintf(id, sizeof(id), "%d", i + 1);
            execl("/sbin/cache-vm-probe", "cache-vm-probe", "worker", id, NULL);
            _exit(120);
        }
        close(ready[1]); close(gate[0]); release[i] = gate[1];
        unsigned char byte = 0;
        check(children[i] > 0 && read(ready[0], &byte, 1) == 1 && byte == i + 1,
            "worker-descriptor-bootstrap");
        close(ready[0]);
    }
    double elapsed = now() - start;
    for (int i = 0; i < NWORKERS; i++) {
        int count = 0;
        struct kinfo_vmentry *maps = kinfo_getvmmap(children[i], &count);
        check(maps != NULL, "worker-vmmap");
        int hits = 0;
        for (int j = 0; j < count; j++) {
            resident_pages += maps[j].kve_resident;
            if (strstr(maps[j].kve_path, "candidate") != NULL) hits++;
        }
        mapped += hits != 0;
        free(maps);
    }
    struct residency after = residency();
    /* kve_private_resident counts whole VM objects repeatedly when several
     * segments share an object. It is not a private-memory sum. */
    printf("MEASURE mode=%s round=%u workers=%d startup_seconds=%.6f anonymous_object_growth_pages=%ld unique_object_growth_pages=%ld total_unique_object_pages=%ld cache_backing_pages=%ld summed_resident_pages=%ld cache_processes=%d page_size=%d\n",
        mode, round, NWORKERS, elapsed, after.anonymous - before.anonymous,
        after.objects - before.objects, after.objects, after.cache,
        resident_pages, mapped, getpagesize());
    check(strcmp(mode, "cache") != 0 || mapped == NWORKERS, "cache-mappings-observed");
    long long user_us = 0, system_us = 0;
    for (int i = 0; i < NWORKERS; i++) {
        int status = 0;
        struct rusage usage = {0};
        close(release[i]);
        check(wait4(children[i], &status, 0, &usage) == children[i] &&
            WIFEXITED(status) && WEXITSTATUS(status) == 0, "worker-private-state");
        user_us += usage.ru_utime.tv_sec * 1000000LL + usage.ru_utime.tv_usec;
        system_us += usage.ru_stime.tv_sec * 1000000LL + usage.ru_stime.tv_usec;
    }
    printf("CPU mode=%s round=%u workers=%d user_us=%lld system_us=%lld\n",
        mode, round, NWORKERS, user_us, system_us);
}
/* Exec after publication so startup populates both cache directory views.
 * Then imitate login/daemon descriptor cleanup and deliberately reuse those
 * numbers before loading a library that was not a startup dependency. */
static int
loader_descriptor_lifetime(bool cache_only)
{
    const char *path = cache_only ? "/usr/lib/libcache_only.so.1" :
        "/usr/lib/libcache_lifetime.so.1";
    if (cache_only && (access(path, F_OK) == 0 || errno != ENOENT)) return (142);
    closefrom(3);
    for (int fd = 3; fd < 32; fd++)
        if (open("/dev/null", O_RDONLY) != fd) return (130);
    for (int iteration = 0; iteration < 100; iteration++) {
        void *handle = dlopen(path, RTLD_NOW);
        if (handle == NULL) {
            fprintf(stderr, "descriptor-lifetime dlopen: %s\n", dlerror());
            return (131);
        }
        int (*value)(void) = (int (*)(void))dlsym(handle, "cache_lifetime_value");
        if (value == NULL || value() != 731) return (132);
        if (iteration == 0) {
            int count = 0, hits = 0;
            struct kinfo_vmentry *maps = kinfo_getvmmap(getpid(), &count);
            if (maps == NULL) return (133);
            for (int i = 0; i < count; i++)
                if ((uintptr_t)value >= maps[i].kve_start &&
                    (uintptr_t)value < maps[i].kve_end &&
                    strstr(maps[i].kve_path, "candidate") != NULL) hits++;
            free(maps);
            if (hits == 0) return (134);
            if (cache_only) {
                void *alias = dlopen("/usr/lib/libcache_only_alias.so.1", RTLD_NOW);
                if (alias == NULL || alias != handle) return (143);
                int *state = (int *)dlsym(handle, "cache_private_state");
                if (state == NULL || *state != 17) return (144);
                *state = 731;
                pid_t child = fork();
                if (child == 0) {
                    if (*state != 731) _exit(1);
                    *state = 919;
                    _exit(*state == 919 ? 0 : 2);
                }
                int status;
                if (child < 0 || waitpid(child, &status, 0) != child ||
                    !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
                    *state != 731) return (145);
                if (dlclose(alias) != 0) return (146);
            }
        }
        if (dlclose(handle) != 0) return (135);
        /* This sibling exists in the source directory but was deliberately
         * omitted from the cache. Misses must release the fresh fd too. */
        handle = dlopen("/usr/lib/libcache_uncached.so.1", RTLD_NOW);
        if (handle == NULL) return (139);
        value = (int (*)(void))dlsym(handle, "cache_lifetime_value");
        if (value == NULL || value() != 731) return (140);
        if (dlclose(handle) != 0) return (141);
        /* Lowest available fd must stay constant across repeated loads. */
        int next = open("/dev/null", O_RDONLY);
        if (next != 32) return (136);
        close(next);
        for (int fd = 3; fd < 32; fd++) {
            struct stat st;
            if (fstat(fd, &st) != 0 || !S_ISCHR(st.st_mode)) return (137);
        }
    }
    closefrom(3);
    return (0);
}
int
main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "descriptor-lifetime") == 0)
        return (loader_descriptor_lifetime(false));
    if (argc == 2 && strcmp(argv[1], "cache-only") == 0)
        return (loader_descriptor_lifetime(true));
    if (argc == 3 && strcmp(argv[1], "worker") == 0) {
        private_state = atoi(argv[2]);
        unsigned char byte = private_state;
        if (write(3, &byte, 1) != 1) return (121);
        close(3);
        if (read(4, &byte, 1) != 0) return (122);
        return (private_state == atoi(argv[2]) ? 0 : 123);
    }
    if (getpid() != 1) { fprintf(stderr, "VM PID 1 only\n"); return (64); }
    int console = open("/dev/console", O_RDWR);
    if (console >= 0) { dup2(console, 0); dup2(console, 1); dup2(console, 2); }
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("ELFCACHE_VM_START\n");
    struct iovec mountargs[] = {{"fstype", 7}, {"tmpfs", 6},
        {"fspath", 7}, {"/tmp", 5}};
    check(nmount(mountargs, 4, 0) == 0, "tmpfs");
    int source = open("/cache-test/cache.bin", O_RDONLY);
    int writefd = open("/tmp/candidate", O_CREAT | O_WRONLY | O_EXCL, 0600);
    char buffer[16384]; ssize_t n;
    check(source >= 0 && writefd >= 0, "cache-copy-open");
    while ((n = read(source, buffer, sizeof(buffer))) > 0)
        if (write(writefd, buffer, n) != n) { check(0, "cache-copy"); break; }
    close(writefd); close(source);
    int issuer = operation(CAP_AUTH_ISSUER_CREATE, -1, NULL);
    check(issuer >= 0, "issuer");
    if (issuer < 0) goto done;
    int dirs[2] = {open("/lib", O_RDONLY | O_DIRECTORY), open("/usr/lib", O_RDONLY | O_DIRECTORY)};
    struct cap_cache_prepare prep = {.directory_fds = {dirs[0], dirs[1]}};
    prep.backing_fd = open("/tmp/candidate", O_RDWR);
    check(operation(CAP_CACHE_PREPARE, issuer, &prep) == -1, "reject-writable-backing");
    close(prep.backing_fd);
    prep.backing_fd = open("/tmp/candidate", O_RDONLY);
    int cache = operation(CAP_CACHE_PREPARE, issuer, &prep);
    check(cache >= 0, "prepare");
    if (cache < 0) goto done;
    check(lseek(cache, 0, SEEK_SET) == -1 && errno == ESPIPE, "seek-safe-rejection");
    check(read(cache, buffer, 1) == -1, "implicit-offset-rejection");
    check(pread(cache, buffer, 8, 0) == 8 && memcmp(buffer, "5BSDELF", 8) == 0, "positioned-read");
    int writable = open("/tmp/candidate", O_WRONLY);
    check(writable == -1 && errno == ETXTBSY, "text-pin-blocks-writes");
    if (writable >= 0) close(writable);
    void *absent = dlopen("/usr/lib/libcache_only.so.1", RTLD_NOW);
    check(absent == NULL, "cache-only-unpublished-denied");
    if (absent != NULL) dlclose(absent);
    publish(issuer, cache);
    pid_t only_child = fork();
    if (only_child == 0) {
        execl("/sbin/cache-vm-probe", "cache-vm-probe", "cache-only", NULL);
        _exit(147);
    }
    int only_status = 0;
    check(only_child > 0 && waitpid(only_child, &only_status, 0) == only_child &&
        WIFEXITED(only_status) && WEXITSTATUS(only_status) == 0,
        "cache-only-load-alias-private-state-descriptors");
    printf("CACHE_ONLY status=%d\n", only_status);
    pid_t lifetime_child = fork();
    if (lifetime_child == 0) {
        execl("/sbin/cache-vm-probe", "cache-vm-probe", "descriptor-lifetime", NULL);
        _exit(138);
    }
    int lifetime_status = 0;
    check(lifetime_child > 0 &&
        waitpid(lifetime_child, &lifetime_status, 0) == lifetime_child &&
        WIFEXITED(lifetime_status) && WEXITSTATUS(lifetime_status) == 0,
        "loader-closefrom-reuse-no-leak");
    printf("DESCRIPTOR_LIFETIME status=%d\n", lifetime_status);
    struct cap_cache_result result;
    int got = operation(CAP_CACHE_GET, dirs[0], &result);
    check(got >= 0 && result.directory == 0 && (fcntl(got, F_GETFD) & FD_CLOEXEC), "directory-lookup-cloexec");
    int unrelated = open("/tmp", O_RDONLY | O_DIRECTORY);
    check(operation(CAP_CACHE_GET, unrelated, &result) == -1 && errno == ENOENT, "unrelated-directory-denied");
    close(unrelated);
    size_t page = getpagesize();
    void *shared = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, got, 0);
    check(shared == MAP_FAILED, "shared-write-denied");
    if (shared != MAP_FAILED) munmap(shared, page);
    void *data = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE, got, 0);
    check(data != MAP_FAILED, "private-write-allowed");
    if (data != MAP_FAILED) {
        ((char *)data)[0] = 'X';
        check(pread(got, buffer, 1, 0) == 1 && buffer[0] == '5', "private-write-isolated");
        check(mprotect(data, page, PROT_READ | PROT_EXEC) == -1, "writable-mapping-not-executable");
        munmap(data, page);
    }
    void *text = mmap(NULL, 2 * page, PROT_READ | PROT_EXEC, MAP_PRIVATE, got, 0);
    check(text != MAP_FAILED, "executable-map");
    if (text != MAP_FAILED)
        check(mprotect(text, page, PROT_WRITE | PROT_EXEC) == -1, "executable-map-not-writable");
    publish(issuer, -1);
    for (unsigned round = 0; round < 5; round++) {
        /* Counterbalance warm pairs: neither mode always runs second. */
        for (unsigned trial = 0; trial < 2; trial++) {
            bool cached = ((round + trial) & 1) != 0;
            publish(issuer, cached ? cache : -1);
            batch(cached ? "cache" : "ordinary", round);
        }
    }
    close(issuer); issuer = -1;
    check(operation(CAP_CACHE_GET, dirs[0], &result) == -1, "issuer-close-unpublishes");
    absent = dlopen("/usr/lib/libcache_only.so.1", RTLD_NOW);
    check(absent == NULL, "cache-only-revoked-denied");
    if (absent != NULL) dlclose(absent);
    check(pread(got, buffer, 8, 0) == 8, "retained-descriptor-after-issuer-close");
    close(cache); close(got); close(prep.backing_fd);
    writable = open("/tmp/candidate", O_WRONLY);
    check(writable == -1 && errno == ETXTBSY, "mapping-retains-text-pin");
    if (writable >= 0) close(writable);
    if (text != MAP_FAILED) {
        int ready[2], gate[2], status;
        check(pipe(ready) == 0 && pipe(gate) == 0, "mapping-lifetime-pipes");
        pid_t child = fork();
        if (child == 0) {
            close(ready[0]); close(gate[1]);
            unsigned char byte = 1;
            if (munmap(text, page) != 0 || write(ready[1], &byte, 1) != 1) _exit(1);
            close(ready[1]);
            if (read(gate[0], &byte, 1) != 0) _exit(2);
            _exit(munmap((char *)text + page, page) == 0 ? 0 : 3);
        }
        close(ready[1]); close(gate[0]);
        check(child > 0 && read(ready[0], buffer, 1) == 1, "fork-partial-unmap-ready");
        close(ready[0]);
        check(munmap(text, 2 * page) == 0, "parent-unmap");
        writable = open("/tmp/candidate", O_WRONLY);
        check(writable == -1 && errno == ETXTBSY, "fork-partial-mapping-retains-pin");
        if (writable >= 0) close(writable);
        close(gate[1]);
        check(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
            WEXITSTATUS(status) == 0, "child-final-unmap");
    }
    writable = open("/tmp/candidate", O_WRONLY);
    check(writable >= 0, "last-unmap-releases-text-pin");
    if (writable >= 0) close(writable);
    if (issuer >= 0) close(issuer);
done:
    printf("ELFCACHE_VM_END failures=%d\n", failures);
    sync(); reboot(RB_POWEROFF);
    for (;;) pause();
}
