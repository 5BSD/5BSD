/* SPDX-License-Identifier: BSD-2-Clause */
#include <libelftc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
int main(void)
{
    char buffer[128];
    CHECK(elftc_demangle("_Z3foov", buffer, sizeof(buffer), ELFTC_DEM_GNU3) == 0);
    CHECK(strcmp(buffer, "foo()") == 0);
    CHECK(elftc_demangle("_Z3fooi", buffer, sizeof(buffer), ELFTC_DEM_GNU3) == 0);
    CHECK(strcmp(buffer, "foo(int)") == 0);
    CHECK(elftc_demangle("_Z3fooi", buffer, 2, ELFTC_DEM_GNU3) != 0);
    Elftc_String_Table *table = elftc_string_table_create(0);
    CHECK(table != NULL);
    size_t alpha = elftc_string_table_insert(table, "alpha");
    size_t beta = elftc_string_table_insert(table, "beta");
    CHECK(alpha != 0 && beta != 0 && alpha != beta);
    CHECK(elftc_string_table_lookup(table, "alpha") == alpha);
    CHECK(elftc_string_table_insert(table, "alpha") == alpha);
    CHECK(strcmp(elftc_string_table_to_string(table, beta), "beta") == 0);
    CHECK(elftc_string_table_lookup(table, "absent") == 0);
    size_t length;
    const char *image = elftc_string_table_image(table, &length);
    CHECK(image != NULL && length > beta + strlen("beta"));
    CHECK(image[0] == 0 && strcmp(image + alpha, "alpha") == 0);
    elftc_string_table_destroy(table);
    puts("demangling, short-buffer rejection and string-table checks passed");
    return 0;
}
