/* SPDX-License-Identifier: BSD-2-Clause */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <libxo/xo.h>
static void check(xo_style_t style)
{
    FILE *fp = tmpfile();
    if (!fp) err(1, "tmpfile");
    xo_handle_t *xo = xo_create_to_file(fp, style, 0);
    if (!xo) errx(1, "create handle");
    if (xo_open_container_h(xo, "demo") < 0 ||
        xo_emit_h(xo, "{:answer/%d}{:name/%s}", 42, "a<&") < 0 ||
        xo_close_container_h(xo, "demo") < 0 || xo_finish_h(xo) < 0)
        errx(1, "format output");
    if (fflush(fp) || fseek(fp, 0, SEEK_SET)) err(1, "read output");
    char data[1024];
    size_t n = fread(data, 1, sizeof(data)-1, fp);
    if (ferror(fp) || !feof(fp)) errx(1, "output length/read");
    data[n] = 0;
    const char *expected = style == XO_STYLE_JSON ?
        "{\"demo\": {\"answer\":42,\"name\":\"a<&\"}}" :
        "<demo><answer>42</answer><name>a&lt;&amp;</name></demo>";
    while (n && (data[n-1] == 10 || data[n-1] == 13)) data[--n] = 0;
    if (strcmp(data, expected)) errx(1, "unexpected formatted output: %s", data);
    xo_destroy(xo);
    fclose(fp);
}
int main(void) { check(XO_STYLE_JSON); check(XO_STYLE_XML); return (0); }
