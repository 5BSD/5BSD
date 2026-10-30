/* SPDX-License-Identifier: BSD-2-Clause */
/* Link-retention checks; this does not establish live DTrace probe firing. */
#include <sys/types.h>
#include <sys/wait.h>
#ifdef SHARED_FIXTURE
#include <dlfcn.h>
#endif
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    Elf *elf;
    Elf_Scn *section = NULL;
    const char *names[6];
    unsigned int expected[6], counts[6] = {0};
    int fd, status;
    pid_t child;

    if (argc != 9)
        errx(1, "expected first/second symbols, presence counts, DOF count, ordinary constructor count, binary");
    names[0] = argv[1]; names[1] = argv[2];
    names[2] = "__SUNW_dof"; names[3] = "dtrace_dof_init";
    names[4] = "dtrace_dof_fini"; names[5] = "ordinary_init";
    for (int i = 3; i <= 6; i++)
        if (strlen(argv[i]) != 1 || argv[i][0] < '0' || argv[i][0] > '2')
            errx(1, "invalid expected count");
    expected[0] = argv[3][0] - '0'; expected[1] = argv[4][0] - '0';
    expected[2] = expected[3] = expected[4] = argv[5][0] - '0';
    expected[5] = argv[6][0] - '0';
    /* argv[7] is a stable diagnostic case name supplied by the BUILD target. */
    if (elf_version(EV_CURRENT) == EV_NONE || (fd = open(argv[8], O_RDONLY)) < 0 ||
        (elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
        errx(1, "cannot read fixture ELF");
    while ((section = elf_nextscn(elf, section)) != NULL) {
        GElf_Shdr header;
        Elf_Data *data = NULL;
        if (gelf_getshdr(section, &header) == NULL)
            errx(1, "invalid ELF section");
        if (header.sh_type != SHT_SYMTAB)
            continue;
        if (header.sh_entsize == 0)
            errx(1, "invalid symbol entry size");
        while ((data = elf_getdata(section, data)) != NULL) {
            if (data->d_size % header.sh_entsize != 0 ||
                data->d_size / header.sh_entsize > INT_MAX)
                errx(1, "invalid symbol table");
            for (size_t i = 0; i < data->d_size / header.sh_entsize; i++) {
                GElf_Sym symbol;
                const char *name;
                if (gelf_getsym(data, (int)i, &symbol) == NULL ||
                    (name = elf_strptr(elf, header.sh_link, symbol.st_name)) == NULL)
                    errx(1, "invalid symbol");
                if (symbol.st_shndx == SHN_UNDEF)
                    continue;
                for (int j = 0; j < 6; j++)
                    if (strcmp(name, names[j]) == 0)
                        counts[j]++;
            }
        }
    }
    elf_end(elf); close(fd);
    for (int i = 0; i < 6; i++)
        if (counts[i] != expected[i])
            errx(1, "%s: %s count %u, expected %u", argv[7], names[i], counts[i], expected[i]);
    child = fork();
    if (child == -1)
        err(1, "fork");
    if (child == 0) {
#ifdef SHARED_FIXTURE
        /* Exercise load, normal constructors, calls, unload and reload. */
        for (int iteration = 0; iteration < 3; iteration++) {
            void *handle = dlopen(argv[8], RTLD_NOW | RTLD_LOCAL);
            int (*function)(void);
            if (handle == NULL)
                errx(1, "dlopen: %s", dlerror());
            function = (int (*)(void))dlsym(handle, "fixture_run");
            if (function == NULL)
                errx(1, "dlsym: %s", dlerror());
            if (function() != 0)
                errx(1, "shared fixture initialization/call failed");
            if (dlclose(handle) != 0)
                errx(1, "dlclose: %s", dlerror());
        }
        _exit(0);
#else
        char *args[] = {argv[8], NULL};
        execv(args[0], args);
        err(127, "execv");
#endif
    }
    while (waitpid(child, &status, 0) < 0)
        if (errno != EINTR)
            err(1, "waitpid");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        errx(1, "%s: fixture wait status %d", argv[7], status);
    puts("PASS");
    return (0);
}
