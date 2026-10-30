/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/nvpair.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>
static void check(int status) { if (status) errx(1, "nvpair status %d", status); }
int main(void) {
    nvlist_t *list, *child;
    check(nvlist_alloc(&list, NV_UNIQUE_NAME, 0));
    check(nvlist_alloc(&child, NV_UNIQUE_NAME, 0));
    check(nvlist_add_uint64(child, "answer", 42));
    check(nvlist_add_string(list, "name", "native nvpair"));
    check(nvlist_add_nvlist(list, "nested", child));
    nvlist_free(child);
    const int encodings[] = { NV_ENCODE_NATIVE, NV_ENCODE_XDR };
    for (unsigned i = 0; i < sizeof(encodings)/sizeof(encodings[0]); i++) {
        char *buffer = NULL, *name;
        size_t size = 0;
        nvlist_t *decoded, *nested;
        uint64_t answer;
        check(nvlist_pack(list, &buffer, &size, encodings[i], 0));
        if (size < 2) errx(1, "empty encoding");
        check(nvlist_unpack(buffer, size, &decoded, 0));
        check(nvlist_lookup_string(decoded, "name", &name));
        check(nvlist_lookup_nvlist(decoded, "nested", &nested));
        check(nvlist_lookup_uint64(nested, "answer", &answer));
        if (strcmp(name, "native nvpair") || answer != 42) errx(1, "roundtrip mismatch");
        nvlist_free(decoded);
        decoded = NULL;
        if (nvlist_unpack(buffer, 1, &decoded, 0) == 0) errx(1, "accepted truncated input");
        free(buffer);
    }
    nvlist_free(list);
    return 0;
}
