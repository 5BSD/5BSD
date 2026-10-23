# SPDX-License-Identifier: BSD-2-Clause
atf_test_case exec_integrity
exec_integrity_head()
{
    atf_set descr 'Kernel checks embedded signatures for execve, fexecve and shebang interpreters'
    # More than 100 compiler/signing/exec probes run serially on modest TCG VMs.
    # Retain a bounded deadline; phase breadcrumbs identify incomplete work.
    atf_set timeout 900
    atf_set require.progs 'cc openssl sysctl'
}
exec_integrity_body()
{
    [ "$(sysctl -n kern.features.veriexec_capimage 2>/dev/null)" = 1 ] ||
        atf_skip 'kernel lacks MAC_VERIEXEC_CAPIMAGE'
    capsign=$(atf_config_get capsign /usr/sbin/capsign)
    atf_check -s exit:0 -o ignore -e ignore openssl genpkey -algorithm ed25519 -out key
    printf 'program = "demo"; activation { exec = true; }\n' > policy
    printf 'int main(void) { return 17; }\n' > demo.c
    atf_check -s exit:0 -o ignore -e ignore cc demo.c -o demo
    cat > probe.c <<'SRC'
#include <sys/types.h>
#include <sys/endian.h>
#include <sys/stat.h>
#include <sys/mac.h>
#include <sys/capsicum.h>
#include <err.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern char **environ;
int main(int argc, char **argv)
{
    if (argc < 3) errx(1, "missing operation/path");
    if (strcmp(argv[1], "flip") == 0) {
        struct stat st;
        uint8_t footer[32], byte;
        off_t off;
        int fd = open(argv[2], O_RDWR);
        if (fd < 0 || fstat(fd, &st) < 0 ||
            pread(fd, footer, sizeof(footer), st.st_size - sizeof(footer)) != sizeof(footer))
            err(1, "fixture footer");
        if (argc != 4) errx(1, "missing byte offset");
        off = strtoll(argv[3], NULL, 10);
        /* Nonnegative offsets address the container; negative ones EOF. */
        off = off < 0 ? st.st_size + off : le64dec(footer + 16) + off;
        if (pread(fd, &byte, 1, off) != 1) err(1, "fixture read");
        byte ^= 1;
        if (pwrite(fd, &byte, 1, off) != 1) err(1, "fixture write");
        return (close(fd) != 0);
    }


    if (strcmp(argv[1], "dl-path") == 0 || strcmp(argv[1], "dl-fd") == 0) {
        void *library;
        if (strcmp(argv[1], "dl-fd") == 0) {
            int fd = open(argv[2], O_RDONLY);
            if (fd < 0) err(1, "library descriptor");
            library = fdlopen(fd, RTLD_NOW | RTLD_LOCAL);
            close(fd);
        } else library = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
        if (library == NULL) {
            puts("DLOPEN_REJECTED");
            return (0);
        }
        int (*value)(void) = (int (*)(void))dlsym(library, "fixture_value");
        if (value == NULL) errx(1, "missing library fixture entry");
        int result = value();
        dlclose(library);
        return (result);
    }
    if (strcmp(argv[1], "verify-capmode") == 0) {
        int fd = open(argv[2], O_RDONLY);
        cap_rights_t rights;
        if (fd < 0 || cap_enter() < 0) err(1, "capability setup");
        if (mac_syscall("mac_veriexec", 5, (void *)(intptr_t)fd) < 0)
            err(1, "required verification in capability mode");
        if (mac_syscall("mac_veriexec", 1, (void *)(intptr_t)fd) != -1 ||
            errno != ECAPMODE) errx(1, "legacy MAC operation escaped capmode filter");
        if (mac_syscall("other-policy", 5, (void *)(intptr_t)fd) != -1 ||
            errno != ECAPMODE) errx(1, "other policy escaped capmode filter");
        cap_rights_init(&rights, CAP_FSTAT);
        if (cap_rights_limit(fd, &rights) < 0) err(1, "limit descriptor rights");
        if (mac_syscall("mac_veriexec", 5, (void *)(intptr_t)fd) != -1 ||
            errno != ENOTCAPABLE) errx(1, "verification bypassed CAP_READ");
        return (17);
    }
    if (strcmp(argv[1], "verify-open") == 0 ||
        strcmp(argv[1], "verify-fd") == 0 ||
        strcmp(argv[1], "verify-required") == 0) {
        int fd = open(argv[2], O_RDONLY |
            (strcmp(argv[1], "verify-open") == 0 ? O_VERIFY : 0));
        if (fd >= 0 && strcmp(argv[1], "verify-open") != 0) {
            int call = strcmp(argv[1], "verify-required") == 0 ? 5 : 1;
            int result = mac_syscall("mac_veriexec", call, (void *)(intptr_t)fd);
            if (result == 0) return (17);
        } else if (fd >= 0) return (17);
        if (errno != EAUTH) err(1, "unexpected verification failure");
        puts("EAUTH");
        return (0);
    }
    if (strcmp(argv[1], "path") == 0)
        execve(argv[2], argv + 2, environ);
    else if (strcmp(argv[1], "fd") == 0) {
        int fd = open(argv[2], O_EXEC | O_CLOEXEC);
        if (fd < 0) err(1, "open executable");
        fexecve(fd, argv + 2, environ);
    } else errx(1, "unknown operation");
    if (errno != EAUTH) err(1, "unexpected exec failure");
    puts("EAUTH");
    return (0);
}
SRC
    atf_check -s exit:0 -o ignore -e ignore cc -Wall -Wextra -Werror probe.c -o probe
    # This ephemeral signer is intentionally not in the authority trust store.
    # Integrity verification must not confer capability authority or prohibit
    # ordinary unsigned development programs.
    atf_check -s exit:0 "$capsign" sign -m policy -k key -o signed demo
    echo EXEC_INTEGRITY_PHASE=valid-and-unsigned
    for method in path fd verify-open verify-fd; do
        atf_check -s exit:17 ./probe "$method" ./demo
        atf_check -s exit:17 ./probe "$method" ./signed
    done
    atf_check -s exit:17 ./probe verify-required ./signed
    atf_check -s exit:17 ./probe verify-capmode ./signed
    atf_check -s exit:0 -o inline:'EAUTH\n' ./probe verify-required ./demo
    # Required mode cannot downgrade a missing/damaged EOF marker to unsigned.
    atf_check -s exit:0 cp -p signed damaged
    atf_check -s exit:0 ./probe flip damaged -32
    atf_check -s exit:0 -o inline:'EAUTH\n' ./probe verify-required ./damaged
    # Header magic/version/length/key/signature, policy and footer metadata.
    echo EXEC_INTEGRITY_PHASE=container-tampering
    for offset in 0 8 12 16 48 111 -33 -24 -20 -16 -8; do
        echo "EXEC_INTEGRITY_OFFSET=$offset"
        atf_check -s exit:0 cp -p signed damaged
        atf_check -s exit:0 ./probe flip damaged "$offset"
        for method in path fd verify-open verify-fd verify-required; do
            atf_check -s exit:0 -o inline:'EAUTH\n' ./probe "$method" ./damaged
        done
    done
    echo EXEC_INTEGRITY_PHASE=image-and-interpreter
    # Mutate an otherwise harmless ELF padding byte: the image remains loadable
    # but its original signed digest must no longer authorize execution.
    atf_check -s exit:0 cp -p signed damaged
    printf '\001' | dd of=damaged bs=1 seek=15 conv=notrunc 2>/dev/null
    atf_check -s exit:0 -o inline:'EAUTH\n' ./probe path ./damaged
    atf_check -s exit:0 -o inline:'EAUTH\n' ./probe fd ./damaged
    printf '#!%s/signed\n' "$(pwd)" > script
    chmod +x script
    atf_check -s exit:17 ./probe path ./script
    printf '#!%s/damaged\n' "$(pwd)" > script
    atf_check -s exit:0 -o inline:'EAUTH\n' ./probe path ./script
    echo EXEC_INTEGRITY_PHASE=dynamic-libraries
    printf 'int fixture_value(void) { return 17; }\n' > library.c
    atf_check -s exit:0 -o ignore -e ignore cc -shared -fPIC library.c -o library.so
    atf_check -s exit:0 "$capsign" sign -m policy -k key -o signed-library.so library.so
    for method in dl-path dl-fd; do
        atf_check -s exit:17 ./probe "$method" ./library.so
        atf_check -s exit:17 ./probe "$method" ./signed-library.so
    done
    atf_check -s exit:0 ./probe flip signed-library.so -33
    for method in dl-path dl-fd; do
        atf_check -s exit:0 -o inline:'DLOPEN_REJECTED\n' ./probe "$method" ./signed-library.so
    done
    echo EXEC_INTEGRITY_PHASE=signature-removal
    atf_check -s exit:0 "$capsign" remove -o unsigned signed
    atf_check -s exit:0 cmp demo unsigned
    atf_check -s exit:0 -o inline:'EAUTH\n' ./probe verify-required ./unsigned
    atf_check -s exit:17 ./probe path ./unsigned
    atf_check -s exit:17 ./probe fd ./unsigned
}
atf_test_case mmap_integrity
mmap_integrity_head()
{
    atf_set descr 'Signed mmap verification and text-pin lifetime across close, mprotect, fork and unmap'
    atf_set require.progs 'cc openssl sysctl'
}
mmap_integrity_body()
{
    [ "$(sysctl -n kern.features.veriexec_capimage_mmap 2>/dev/null)" = 1 ] ||
        atf_skip 'kernel lacks signed mmap lifetime enforcement'
    capsign=$(atf_config_get capsign /usr/sbin/capsign)
    atf_check -s exit:0 -o ignore -e ignore openssl genpkey -algorithm ed25519 -out key
    printf 'program = "demo"; activation { exec = true; }\n' > policy
    printf 'char padding[32768] = {1}; int main(void) { return padding[0]; }\n' > demo.c
    atf_check -s exit:0 -o ignore -e ignore cc demo.c -o demo
    atf_check -s exit:0 "$capsign" sign -m policy -k key -o signed demo
    cp signed damaged
    cat > mmap-probe.c <<'SRC'
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/capsicum.h>
#include <sys/wait.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void writable(const char *path, int busy)
{
    int fd = open(path, O_RDWR);
    if (busy) {
        if (fd != -1 || errno != ETXTBSY)
            errx(1, "write-open was not blocked by the mapping text pin");
    } else {
        if (fd < 0) err(1, "text pin leaked after final unmap");
        close(fd);
    }
}
static void byte(int fd, int send)
{
    char c = 'x';
    if ((send ? write(fd, &c, 1) : read(fd, &c, 1)) != 1)
        err(1, "pipe synchronization");
}
static void *mapfile(const char *path, size_t size, int prot)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) err(1, "open mapping input");
    void *p = mmap(NULL, size, prot, MAP_PRIVATE, fd, 0);
    int saved = errno;
    close(fd);
    errno = saved;
    return p;
}
int main(int argc, char **argv)
{
    if (argc != 4) errx(1, "signed unsigned damaged inputs required");
    size_t page = (size_t)getpagesize(), length = 2 * page;
    int fd = open(argv[3], O_RDWR);
    unsigned char c;
    if (fd < 0 || pread(fd, &c, 1, 64) != 1) err(1, "damage read");
    c ^= 1;
    if (pwrite(fd, &c, 1, 64) != 1 || close(fd) != 0) err(1, "damage write");
    for (int i = 0; i < 2; i++) {
        void *bad = mapfile(argv[3], page, PROT_READ | (i ? PROT_EXEC : 0));
        if (bad != MAP_FAILED || errno != EAUTH)
            errx(1, "corrupt signature escaped executable maximum protection check");
    }
    /* Non-executable data inspection remains possible, even when damaged. */
    void *data = mapfile(argv[3], page, PROT_READ | PROT_MAX(PROT_READ));
    if (data == MAP_FAILED) err(1, "read-only data inspection");
    if (mprotect(data, page, PROT_READ | PROT_EXEC) != -1 || errno != EACCES)
        errx(1, "data-only mapping gained execution");
    if (munmap(data, page) != 0) err(1, "unmap inspection");
    for (int i = 0; i < 2; i++) {
        void *p = mapfile(argv[1 + i], length, PROT_READ);
        if (p == MAP_FAILED) err(1, "map valid/unsigned input");
        if (mprotect(p, length, PROT_READ | PROT_EXEC) != 0)
            err(1, "promote verified/unsigned mapping");
        writable(argv[1 + i], !i);
        if (munmap(p, length) != 0) err(1, "unmap simple mapping");
        writable(argv[1 + i], 0);
    }
    /* An outstanding write description must prevent signed mappings. */
    fd = open(argv[1], O_RDWR);
    if (fd < 0) err(1, "open concurrent writer");
    void *p = mapfile(argv[1], length, PROT_READ | PROT_EXEC);
    if (p != MAP_FAILED || errno != ETXTBSY)
        errx(1, "signed mapping accepted outstanding writer");
    close(fd);
    /* A failed insertion must release its temporary pin. */
    p = mmap(NULL, length, PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED) err(1, "reserve occupied address");
    fd = open(argv[1], O_RDONLY);
    if (fd < 0) err(1, "open failed insertion fixture");
    void *collision = mmap(p, length, PROT_READ | PROT_EXEC,
        MAP_PRIVATE | MAP_FIXED | MAP_EXCL, fd, 0);
    /* vm_mmap_to_errno maps occupied-address KERN_NO_SPACE to ENOMEM. */
    if (collision != MAP_FAILED || errno != ENOMEM)
        errx(1, "occupied mapping: result=%p errno=%d, expected MAP_FAILED/ENOMEM",
            collision, errno);
    close(fd);
    writable(argv[1], 0);
    if (munmap(p, length) != 0) err(1, "unmap occupied address");
    /* Private data remains process-owned; it never changes signed backing. */
    p = mapfile(argv[1], length, PROT_READ | PROT_WRITE);
    if (p == MAP_FAILED) err(1, "map private data");
    c = *(unsigned char *)p;
    *(unsigned char *)p ^= 1;
    fd = open(argv[1], O_RDONLY);
    unsigned char disk;
    if (fd < 0 || read(fd, &disk, 1) != 1 || disk != c)
        errx(1, "private write changed signed backing");
    close(fd);
    writable(argv[1], 1);
    if (munmap(p, length) != 0) err(1, "unmap private data");
    writable(argv[1], 0);
    /* References survive descriptor close, splitting, and fork. */
    p = mapfile(argv[1], length, PROT_READ | PROT_EXEC);
    if (p == MAP_FAILED) err(1, "map fork fixture");
    int go[2], ack[2];
    if (pipe(go) != 0 || pipe(ack) != 0) err(1, "pipe");
    pid_t child = fork();
    if (child < 0) err(1, "fork");
    if (child == 0) {
        close(go[1]); close(ack[0]);
        byte(go[0], 0);
        if (munmap(p, page) != 0) err(1, "child partial unmap");
        byte(ack[1], 1);
        byte(go[0], 0);
        if (munmap((char *)p + page, page) != 0) err(1, "child final unmap");
        _exit(0);
    }
    close(go[0]); close(ack[1]);
    if (munmap(p, page) != 0) err(1, "parent partial unmap");
    writable(argv[1], 1);
    if (munmap((char *)p + page, page) != 0) err(1, "parent final unmap");
    writable(argv[1], 1);
    byte(go[1], 1); byte(ack[0], 0);
    writable(argv[1], 1);
    byte(go[1], 1);
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
        errx(1, "child lifetime checks failed");
    close(go[1]); close(ack[0]);
    writable(argv[1], 0);
    /* Fixed replacement releases only the replaced mapping's ownership. */
    p = mapfile(argv[1], length, PROT_READ | PROT_EXEC);
    if (p == MAP_FAILED) err(1, "map fixed replacement fixture");
    if (mmap(p, page, PROT_READ, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0) != p)
        err(1, "replace first half");
    writable(argv[1], 1);
    if (mmap((char *)p + page, page, PROT_READ,
        MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0) != (char *)p + page)
        err(1, "replace second half");
    writable(argv[1], 0);
    if (munmap(p, length) != 0) err(1, "unmap replacements");
    /* Capability-mode mappings use existing descriptors only. Process exit
     * must release the inherited owner's last reference without munmap. */
    int valid = open(argv[1], O_RDONLY), invalid = open(argv[3], O_RDONLY);
    cap_rights_t rights;
    cap_rights_init(&rights, CAP_READ, CAP_MMAP_R, CAP_MMAP_X);
    if (valid < 0 || invalid < 0 || cap_rights_limit(valid, &rights) != 0 ||
        cap_rights_limit(invalid, &rights) != 0) err(1, "capability descriptors");
    if (pipe(go) != 0 || pipe(ack) != 0) err(1, "capability pipes");
    child = fork();
    if (child < 0) err(1, "capability fork");
    if (child == 0) {
        close(go[1]); close(ack[0]);
        if (cap_enter() != 0) err(1, "enter capability mode");
        p = mmap(NULL, page, PROT_READ | PROT_EXEC, MAP_PRIVATE, valid, 0);
        if (p == MAP_FAILED) err(1, "signed descriptor mapping in capability mode");
        close(valid);
        if (mmap(NULL, page, PROT_READ | PROT_EXEC, MAP_PRIVATE, invalid, 0) != MAP_FAILED ||
            errno != EAUTH) errx(1, "corrupt capability descriptor was accepted");
        close(invalid);
        byte(ack[1], 1); byte(go[0], 0);
        _exit(0);
    }
    close(valid); close(invalid); close(go[0]); close(ack[1]);
    byte(ack[0], 0);
    writable(argv[1], 1);
    byte(go[1], 1);
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
        errx(1, "capability mapping/process exit checks failed");
    close(go[1]); close(ack[0]);
    writable(argv[1], 0);
    puts("SIGNED_MMAP_LIFETIME_OK");
    return 0;
}
SRC
    atf_check -s exit:0 -o ignore -e ignore cc -Wall -Wextra -Werror mmap-probe.c -o mmap-probe
    atf_check -s exit:0 -o inline:'SIGNED_MMAP_LIFETIME_OK\n' ./mmap-probe signed demo damaged
}
atf_test_case mmap_open_backing
mmap_open_backing_head()
{
    atf_set descr 'Existing linked/unlinked UFS and tmpfs backing retains unsigned access and signed verification'
    atf_set require.progs 'cc openssl sysctl'
    atf_set timeout 300
}
mmap_open_backing_body()
{
    [ "$(sysctl -n kern.features.veriexec_capimage_mmap 2>/dev/null)" = 1 ] ||
        atf_skip 'kernel lacks signed mmap lifetime enforcement'
    capsign=$(atf_config_get capsign /usr/sbin/capsign)
    atf_check -s exit:0 -o ignore -e ignore openssl genpkey -algorithm ed25519 -out key
    printf 'program = "demo"; activation { exec = true; }\n' > policy
    printf 'char padding[32768] = {1}; int main(void) { return padding[0]; }\n' > demo.c
    atf_check -s exit:0 -o ignore -e ignore cc demo.c -o demo
    atf_check -s exit:0 "$capsign" sign -m policy -k key -o signed demo
    atf_check -s exit:0 cp signed damaged
    printf '\001' | dd of=damaged bs=1 seek=15 conv=notrunc 2>/dev/null
    cat > mmap-open-backing.c <<'SRC'
/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void copy(const char *source, const char *target)
{
    char buf[8192];
    int in = open(source, O_RDONLY);
    int out = open(target, O_WRONLY | O_CREAT | O_EXCL, 0700);
    if (in < 0 || out < 0) err(1, "copy open");
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0)
        if (write(out, buf, n) != n) err(1, "copy write");
    if (n < 0 || close(in) != 0 || close(out) != 0) err(1, "copy close");
}

int main(int argc, char **argv)
{
    if (argc != 6) errx(1, "directory unsigned signed damaged filesystem required");
    struct statfs fs;
    if (statfs(argv[1], &fs) != 0) err(1, "backing filesystem");
    if (strcmp(fs.f_fstypename, argv[5]) != 0)
        errx(1, "expected filesystem %s, got %s", argv[5], fs.f_fstypename);
    size_t page = (size_t)getpagesize();
    unsigned count = 0;
    for (int kind = 0; kind < 3; kind++)
    for (int shared = 0; shared < 2; shared++)
    for (int unlinked = 0; unlinked < 2; unlinked++)
    for (int executable = 0; executable < 2; executable++) {
        char path[1024];
        if (snprintf(path, sizeof(path), "%s/probe-%u", argv[1], count) >= (int)sizeof(path))
            errx(1, "path too long");
        copy(argv[kind + 2], path);
        int fd = open(path, O_RDONLY);
        if (fd < 0) err(1, "backing open");
        if (unlinked && unlink(path) != 0) err(1, "unlink backing");
        int prot = PROT_READ | (executable ? PROT_EXEC : 0);
        errno = 0;
        void *p = mmap(NULL, page, prot, shared ? MAP_SHARED : MAP_PRIVATE, fd, 0);
        int saved = errno;
        if (close(fd) != 0) err(1, "close original backing");
        if (kind == 2) {
            if (p != MAP_FAILED || saved != EAUTH)
                errx(1, "damaged accepted kind=%d shared=%d unlinked=%d exec=%d result=%p errno=%d", kind, shared, unlinked, executable, p, saved);
        } else {
            if (p == MAP_FAILED) { errno = saved; err(1, "mmap kind=%d shared=%d unlinked=%d exec=%d", kind, shared, unlinked, executable); }
            if (*(volatile unsigned char *)p != 0x7f) errx(1, "mapped bytes differ");
            if (mprotect(p, page, PROT_READ | PROT_EXEC) != 0) err(1, "promote valid mapping");
            if (kind == 1 && !unlinked) {
                fd = open(path, O_WRONLY);
                if (fd != -1 || errno != ETXTBSY) errx(1, "signed backing write open not pinned");
                if (truncate(path, 0) != -1 || errno != ETXTBSY) errx(1, "signed backing truncate not pinned");
            }
            if (munmap(p, page) != 0) err(1, "unmap");
            if (kind == 1 && !unlinked) {
                fd = open(path, O_WRONLY);
                if (fd < 0 || close(fd) != 0) err(1, "pin leaked after unmap");
            }
        }
        if (!unlinked && unlink(path) != 0) err(1, "cleanup");
        printf("MMAP_OPEN_BACKING kind=%d shared=%d unlinked=%d exec=%d PASS\n", kind, shared, unlinked, executable);
        count++;
    }
    printf("MMAP_OPEN_BACKING_PASS=%u\n", count);
    return 0;
}
SRC
    atf_check -s exit:0 -o ignore -e ignore cc -Wall -Wextra -Werror mmap-open-backing.c -o mmap-open-backing
    for filesystem in ufs tmpfs; do
        case "$filesystem" in
        ufs) root=$(atf_config_get ufs_mmap_root /var/tmp) ;;
        tmpfs) root=$(atf_config_get tmpfs_mmap_root /tmp) ;;
        esac
        directory=$(mktemp -d "$root/capimage-mmap.XXXXXX") || atf_fail 'create filesystem fixture'
        atf_check -s exit:0 -o match:'MMAP_OPEN_BACKING_PASS=24' ./mmap-open-backing "$directory" demo signed damaged "$filesystem"
        atf_check -s exit:0 rmdir "$directory"
    done
}

atf_init_test_cases()
{
    atf_add_test_case exec_integrity
    atf_add_test_case mmap_integrity
    atf_add_test_case mmap_open_backing
}
