/* SPDX-License-Identifier: BSD-2-Clause */
/* Compile both languages and inspect emitted ELF architecture without a linker. */
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
    const char *tmp = getenv("TEST_TMPDIR");
    char src[4096], obj[4096], target[256];
    unsigned char hdr[20];
    int status;
    pid_t pid, waited;
    FILE *f;

    if (tmp == NULL || argc < 4 || argc % 2 != 0)
        return (2);
    for (int i = 2; i < argc; i += 2) {
        for (int cpp = 0; cpp != 2; ++cpp) {
            if (snprintf(src, sizeof(src), "%s/probe.%s", tmp, cpp ? "cc" : "c") >= (int)sizeof(src) ||
                snprintf(obj, sizeof(obj), "%s/probe.o", tmp) >= (int)sizeof(obj) ||
                snprintf(target, sizeof(target), "--target=%s", argv[i]) >= (int)sizeof(target))
                return (2);
            f = fopen(src, "w");
            if (f == NULL)
                return (2);
            if (fputs(cpp ? "template<class T> T twice(T x) { return x+x; }\nint use(int x) { return twice(x); }\n" :
                "unsigned sum(unsigned a, unsigned b) { return a+b; }\n", f) == EOF || fclose(f) != 0)
                return (2);
            unlink(obj);
            pid = fork();
            if (pid == -1)
                return (2);
            if (pid == 0) {
                execl(argv[1], argv[1], target, "-O2", "-c", src, "-o", obj, (char *)NULL);
                perror("exec compiler");
                _exit(127);
            }
            do { waited = waitpid(pid, &status, 0); } while (waited == -1 && errno == EINTR);
            if (waited != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
                return (1);
            f = fopen(obj, "rb");
            if (f == NULL)
                return (1);
            size_t count = fread(hdr, 1, sizeof(hdr), f);
            fclose(f);
            if (count != sizeof(hdr) || memcmp(hdr, "\177ELF", 4) != 0 || (hdr[5] != 1 && hdr[5] != 2))
                return (1);
            unsigned machine = hdr[5] == 1 ? hdr[18] + 256u * hdr[19] : 256u * hdr[18] + hdr[19];
            if (machine != strtoul(argv[i + 1], NULL, 10)) {
                fprintf(stderr, "%s: unexpected ELF machine %u\n", argv[i], machine);
                return (1);
            }
            printf("%s %s: ELF machine %u\n", argv[i], cpp ? "C++" : "C", machine);
        }
    }
    return (0);
}
