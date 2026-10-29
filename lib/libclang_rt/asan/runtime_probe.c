/* SPDX-License-Identifier: BSD-2-Clause */
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv)
{
    if (argc != 2) return (2);
    volatile unsigned char *p = malloc(8);
    if (p == NULL) return (3);
    if (strcmp(argv[1], "freed") == 0) {
        free((void *)p);
        return p[0];
    }
    int index = atoi(argv[1]);
    p[index] = 42;
    free((void *)p);
    return (0);
}
