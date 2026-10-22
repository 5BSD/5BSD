/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dt_string.h"
static int fail_allocation;
void *__real_malloc(size_t);
void *__wrap_malloc(size_t n) {
    if (fail_allocation) { fail_allocation = 0; return NULL; }
    return __real_malloc(n);
}
int main(void) {
    unsigned checks = 0;
    for (unsigned value = 1; value < 256; ++value) {
        char input[] = {(char)value, 0};
        char *encoded = strchr2esc(input, 1);
        assert(encoded != NULL);
        assert(stresc2chr(encoded) == 1 && (unsigned char)encoded[0] == value);
        free(encoded); ++checks;
    }
    for (unsigned n = 1; n <= 128; ++n) {
        char input[140] = "\\x";
        memset(input + 2, 'f', n); input[n + 2] = 0;
        assert(stresc2chr(input) == 1);
        assert((unsigned char)input[0] == (n == 1 ? 15 : 255));
        ++checks;
    }
    for (unsigned value = 0; value < 512; ++value) {
        char input[16]; snprintf(input, sizeof(input), "\\%03oZ", value);
        assert(stresc2chr(input) == 2 && (unsigned char)input[0] == (value & 255));
        assert(input[1] == 'Z'); ++checks;
    }
    for (unsigned n = 0; n <= 128; ++n) {
        char input[130], expected[130];
        memset(input, '_', n); input[n] = 0;
        memset(expected, '-', n / 2);
        if (n % 2) expected[n / 2] = '_';
        expected[(n + 1) / 2] = 0;
        assert(strhyphenate(input) == input && strcmp(input, expected) == 0);
        ++checks;
    }
    assert(strcmp(strbasename("/a/b/"), "") == 0);
    assert(strcmp(strbasename("plain"), "plain") == 0);
    assert(strcmp(strbasename("/a/b"), "b") == 0);
    const struct { const char *text; const char *value; size_t length; } cases[] = {
        {"\\1", "\1", 1}, {"\\12", "\12", 1}, {"\\1Z", "\1Z", 2},
        {"\\12Z", "\12Z", 2}, {"\\x12Z", "\x12Z", 2},
        {"\\xABZ", "\253Z", 2}, {"\\xZ", "\0Z", 2},
        {"\\q", "\\q", 2}, {"end\\", "end", 3}
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
        char text[64]; strcpy(text, cases[i].text);
        assert(stresc2chr(text) == cases[i].length);
        assert(memcmp(text, cases[i].value, cases[i].length) == 0); ++checks;
    }
    char zero[] = {0, 'x', 0};
    char *escaped = strchr2esc(zero, 2);
    assert(escaped && strcmp(escaped, "\\0") == 0); free(escaped);
    fail_allocation = 1;
    assert(strchr2esc("allocation", 10) == NULL && fail_allocation == 0);
    const char *valid[] = {"12", "0x12", "identifier", "a_b", "mod`name", "123x"};
    for (size_t i = 0; i < sizeof(valid)/sizeof(valid[0]); ++i)
        assert(strbadidnum(valid[i]) == NULL);
    const char *invalid[] = {"", "a.b", "a-b", "a/b", "a b"};
    for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i)
        assert(strbadidnum(invalid[i]) == invalid[i] + (i == 0 ? 0 : 1));
    const char *patterns[] = {"plain", "a*b", "a?b", "a[b", "a\\b", ""};
    for (size_t i = 0; i < sizeof(patterns)/sizeof(patterns[0]); ++i)
        assert(strisglob(patterns[i]) == (i > 0 && i < 5));
    printf("PASS: %u string conversion properties and basename boundaries\n", checks);
}
