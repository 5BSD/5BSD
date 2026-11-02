/* SPDX-License-Identifier: BSD-2-Clause */
#include <dlfcn.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <libxo/xo.h>
#include <libxo/xo_encoder.h>

/* Explicit pathname loading prevents a host-installed encoder from satisfying
 * this test. Default installed-path discovery is a separate guest gate. */
int
main(int argc, char **argv)
{
    if (argc != 3)
        errx(1, "plugin pathname and options required");
    void *plugin = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (plugin == NULL)
        errx(1, "dlopen: %s", dlerror());
    xo_encoder_init_func_t init = (xo_encoder_init_func_t)dlfunc(plugin, XO_ENCODER_INIT_NAME);
    if (init == NULL)
        errx(1, "initializer missing");
    xo_encoder_init_args_t args = {0};
    if (init(&args) != 0 || args.xei_version != XO_ENCODER_VERSION || args.xei_handler == NULL)
        errx(1, "encoder ABI initialization");
    xo_handle_t *xo = xo_create(XO_STYLE_ENCODER, 0);
    if (xo == NULL)
        errx(1, "create handle");
    xo_set_encoder(xo, args.xei_handler);
    if (xo_encoder_handle(xo, XO_OP_CREATE, "csv", NULL, 0) < 0)
        errx(1, "create encoder");
    if (argv[2][0] != '\0' && xo_encoder_handle(xo, XO_OP_OPTIONS, NULL, argv[2], 0) < 0) {
        xo_destroy(xo);
        if (dlclose(plugin) != 0)
            errx(1, "dlclose");
        return (2);
    }
    if (xo_open_instance_h(xo, "row") < 0 ||
        xo_emit_h(xo, "{:name/%s}{:value/%d}", "a,\"b\"", 42) < 0 ||
        xo_close_instance_h(xo, "row") < 0 || xo_finish_h(xo) < 0)
        errx(1, "encode row");
    xo_destroy(xo);
    if (dlclose(plugin) != 0)
        errx(1, "dlclose");
    return (0);
}
