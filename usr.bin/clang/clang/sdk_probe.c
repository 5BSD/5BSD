/* SPDX-License-Identifier: BSD-2-Clause */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(32);
    if (p == NULL) return 2;
    strcpy(p, "native C works");
    int result = strcmp(p, "native C works") != 0;
    puts(p);
    free(p);
    return result;
}
