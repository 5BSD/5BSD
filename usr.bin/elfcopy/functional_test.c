/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/endian.h>
#include <sys/stat.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
run(const char *program, char *const args[])
{
    int status;
    pid_t child = fork(), waited;
    if (child < 0) err(1, "fork");
    if (child == 0) {
        execv(program, args);
        err(1, "exec %s", program);
    }
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        errx(1, "command failed: %s", program);
}

/* Inspect real ELF tables, not output produced by another command. */
static void
inspect(const char *path, int debug, int payload, int renamed)
{
    int fd = open(path, O_RDONLY), saw_debug = 0, saw_payload = 0;
    int saw_original = 0, saw_renamed = 0;
    size_t names;
    Elf *elf;
    Elf_Scn *scn = NULL;
    if (fd < 0 || (elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL ||
        elf_getshdrstrndx(elf, &names) != 0) errx(1, "ELF open %s", path);
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr sh;
        const char *name;
        if (gelf_getshdr(scn, &sh) == NULL ||
            (name = elf_strptr(elf, names, sh.sh_name)) == NULL)
            errx(1, "ELF section %s", path);
        if (strcmp(name, ".debug_info") == 0) saw_debug++;
        if (strcmp(name, ".qualify") == 0) {
            Elf_Data *data = elf_getdata(scn, NULL);
            if (data == NULL || data->d_size != 6 || memcmp(data->d_buf, "hello\n", 6))
                errx(1, "section payload mismatch");
            saw_payload++;
        }
        if (sh.sh_type == SHT_SYMTAB) {
            Elf_Data *data = elf_getdata(scn, NULL);
            if (!sh.sh_entsize || data == NULL) errx(1, "bad symbol table");
            for (size_t i = 0; i < sh.sh_size / sh.sh_entsize; i++) {
                GElf_Sym sym;
                if (gelf_getsym(data, i, &sym) == NULL ||
                    (name = elf_strptr(elf, sh.sh_link, sym.st_name)) == NULL)
                    errx(1, "bad symbol");
                saw_original += strcmp(name, "fixture_answer") == 0;
                saw_renamed += strcmp(name, "renamed_answer") == 0;
            }
        }
    }
    if (!!saw_debug != debug || !!saw_payload != payload ||
        !!saw_original != !renamed || !!saw_renamed != renamed)
        errx(1, "ELF content mismatch: %s", path);
    elf_end(elf);
    close(fd);
}

/* Decode PE fields independently; conversion is not PE execution. */
static void
inspect_pe(const char *path)
{
    struct stat st;
    int fd = open(path, O_RDONLY);
    unsigned char *data;
    size_t used = 0;
    int text = 0, initialized = 0;
    if (fd < 0 || fstat(fd, &st) || st.st_size < 64 || st.st_size > 16777216)
        errx(1, "invalid PE fixture size");
    size_t size = (size_t)st.st_size;
    if ((data = malloc(size)) == NULL) err(1, "PE allocation");
    while (used < size) {
        ssize_t n = read(fd, data + used, size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) errx(1, "PE read");
        used += n;
    }
    close(fd);
    size_t pe = le32dec(data + 60);
    if (memcmp(data, "MZ", 2) || pe > size - 26 ||
        memcmp(data + pe, "PE\0\0", 4) || le16dec(data + pe + 4) != 0x8664 ||
        le16dec(data + pe + 24) != 0x20b) errx(1, "PE32+ header mismatch");
    size_t count = le16dec(data + pe + 6);
    size_t table = pe + 24 + le16dec(data + pe + 20);
    if (!count || table > size || count > (size - table) / 40)
        errx(1, "PE section table bounds");
    for (size_t i = 0; i < count; i++) {
        const unsigned char *entry = data + table + i * 40;
        size_t length = le32dec(entry + 16), offset = le32dec(entry + 20);
        if (offset > size || length > size - offset) errx(1, "PE section bounds");
        text += memcmp(entry, ".text\0\0\0", 8) == 0;
        initialized += memcmp(entry, ".data\0\0\0", 8) == 0;
    }
    if (!text || !initialized) errx(1, "missing PE text/data sections");
    free(data);
}

int
main(int argc, char **argv)
{
    char program[PATH_MAX], fixture[PATH_MAX], full[PATH_MAX], paths[32768] = "";
    const char *tmp = getenv("TEST_TMPDIR");
    if (argc < 4 || tmp == NULL || realpath(argv[1], program) == NULL ||
        realpath(argv[2], fixture) == NULL) errx(1, "declared inputs required");
    for (int i = 3; i < argc; i++) {
        if (realpath(argv[i], full) == NULL) err(1, "library input");
        char *slash = strrchr(full, '/');
        if (slash == NULL) errx(1, "library path");
        *slash = '\0';
        if ((i > 3 && strlcat(paths, ":", sizeof(paths)) >= sizeof(paths)) ||
            strlcat(paths, full, sizeof(paths)) >= sizeof(paths)) errx(1, "library path length");
    }
    if (setenv("LD_LIBRARY_PATH", paths, 1) || chdir(tmp)) err(1, "test environment");
    if (elf_version(EV_CURRENT) == EV_NONE) errx(1, "ELF version");
    FILE *f = fopen("payload", "w");
    if (!f || fputs("hello\n", f) == EOF || fclose(f)) err(1, "payload");
    inspect(fixture, 1, 0, 0);
    run(program, (char *const[]){"elfcopy", fixture, "copy", NULL});
    inspect("copy", 1, 0, 0);
    run(program, (char *const[]){"elfcopy", "--strip-debug", fixture, "stripped", NULL});
    inspect("stripped", 0, 0, 0);
    run(program, (char *const[]){"elfcopy", "--redefine-sym", "fixture_answer=renamed_answer", fixture, "renamed", NULL});
    inspect("renamed", 1, 0, 1);
    run(program, (char *const[]){"elfcopy", "--add-section", ".qualify=payload", fixture, "added", NULL});
    inspect("added", 1, 1, 0);
    run(program, (char *const[]){"elfcopy", "--remove-section", ".qualify", "added", "removed", NULL});
    inspect("removed", 1, 0, 0);
    run("./renamed", (char *const[]){"renamed", NULL});
    run("./stripped", (char *const[]){"stripped", NULL});
    run(program, (char *const[]){"elfcopy", "-O", "pei-x86-64", fixture, "converted.exe", NULL});
    inspect_pe("converted.exe");
    puts("ELF transformations, execution and PE32+ conversion passed");
    return (0);
}
