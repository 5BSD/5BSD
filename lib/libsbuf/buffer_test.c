/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/sbuf.h>
#include <err.h>
#include <errno.h>
#include <string.h>
int main(void) {
    struct sbuf *buffer = sbuf_new_auto();
    if (!buffer) err(1, "sbuf_new_auto");
    for (int i = 0; i < 1024; i++)
        if (sbuf_cat(buffer, "abcd") != 0) err(1, "sbuf_cat");
    if (sbuf_finish(buffer) != 0 || sbuf_len(buffer) != 4096) errx(1, "growth/finish");
    for (int i = 0; i < 4096; i++)
        if (sbuf_data(buffer)[i] != "abcd"[i % 4]) errx(1, "grown data");
    if (sbuf_data(buffer)[4096] != 0) errx(1, "terminator");
    sbuf_clear(buffer);
    if (sbuf_printf(buffer, "%s=%d", "answer", 42) != 0 || sbuf_finish(buffer) != 0 ||
        strcmp(sbuf_data(buffer), "answer=42")) errx(1, "clear/format");
    sbuf_delete(buffer);
    char storage[8];
    buffer = sbuf_new(NULL, storage, sizeof(storage), SBUF_FIXEDLEN);
    if (!buffer) err(1, "fixed sbuf");
    if (sbuf_cat(buffer, "too long for buffer") == 0 || sbuf_error(buffer) != ENOMEM ||
        sbuf_finish(buffer) == 0) errx(1, "overflow handling");
    sbuf_clear(buffer);
    if (sbuf_error(buffer) || sbuf_cat(buffer, "ok") != 0 || sbuf_finish(buffer) != 0 ||
        strcmp(sbuf_data(buffer), "ok")) errx(1, "error recovery");
    sbuf_delete(buffer);
    return 0;
}
