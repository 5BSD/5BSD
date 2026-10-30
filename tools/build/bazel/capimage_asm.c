/* SPDX-License-Identifier: BSD-2-Clause */
/* Preserve the unsigned input contract of share/mk/capimage.awk. */
#include <err.h>
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char **argv)
{
        static unsigned char data[1048576];
        FILE *in, *out;
        size_t n, i;

        if (argc != 3)
                errx(1, "usage: capimage_asm input output");
        if ((in = fopen(argv[1], "rb")) == NULL)
                err(1, "%s", argv[1]);
        n = fread(data, 1, sizeof(data), in);
        if (ferror(in))
                err(1, "read %s", argv[1]);
        if (n == 0 || fgetc(in) != EOF)
                errx(1, "policy input must contain 1 through 1048576 bytes");
        if (ferror(in) || fclose(in) != 0)
                err(1, "read %s", argv[1]);
        if ((out = fopen(argv[2], "wb")) == NULL)
                err(1, "%s", argv[2]);
        fprintf(out, ".section .5bsd.policy,\"\",%%progbits\n");
        for (i = 0; i < n; i++)
                fprintf(out, ".byte %u\n", data[i]);
        fprintf(out, ".section .note.GNU-stack,\"\",%%progbits\n");
        if (ferror(out) || fclose(out) != 0)
                err(1, "write %s", argv[2]);
        return (0);
}
