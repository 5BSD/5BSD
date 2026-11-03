/* SPDX-License-Identifier: BSD-2-Clause */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <libfdt.h>
#define CHECK(e) do { if (!(e)) { fprintf(stderr, "line %d: %s\n", __LINE__, #e); return 1; } } while (0)
int main(void)
{
    _Alignas(8) unsigned char tree[8192], expanded[16384], overlay[8192], bad[8192];
    int soc, fragment, payload, node, length;
    const void *value;
    CHECK(fdt_create_empty_tree(tree, sizeof(tree)) == 0);
    CHECK(fdt_magic(tree) == FDT_MAGIC);
    soc = fdt_add_subnode(tree, 0, "soc");
    CHECK(soc >= 0);
    CHECK(fdt_setprop_string(tree, soc, "compatible", "5bsd,soc") == 0);
    CHECK(fdt_setprop_u32(tree, soc, "test-cell", 0x12345678) == 0);
    value = fdt_getprop(tree, soc, "test-cell", &length);
    CHECK(value != NULL && length == 4 && memcmp(value, "\x12\x34\x56\x78", 4) == 0);
    CHECK(fdt_pack(tree) == 0);
    CHECK(fdt_check_header(tree) == 0 && fdt_totalsize(tree) <= sizeof(tree));
    CHECK(fdt_open_into(tree, expanded, sizeof(expanded)) == 0);
    soc = fdt_path_offset(expanded, "/soc");
    CHECK(soc >= 0 && fdt_delprop(expanded, soc, "test-cell") == 0);
    CHECK(fdt_getprop(expanded, soc, "test-cell", &length) == NULL && length == -FDT_ERR_NOTFOUND);
    CHECK(fdt_create_empty_tree(overlay, sizeof(overlay)) == 0);
    fragment = fdt_add_subnode(overlay, 0, "fragment@0");
    CHECK(fragment >= 0 && fdt_setprop_string(overlay, fragment, "target-path", "/soc") == 0);
    payload = fdt_add_subnode(overlay, fragment, "__overlay__");
    CHECK(payload >= 0);
    node = fdt_add_subnode(overlay, payload, "device@20");
    CHECK(node >= 0 && fdt_setprop_string(overlay, node, "compatible", "5bsd,device") == 0);
    CHECK(fdt_overlay_apply(expanded, overlay) == 0);
    node = fdt_path_offset(expanded, "/soc/device@20");
    CHECK(node >= 0);
    value = fdt_getprop(expanded, node, "compatible", &length);
    CHECK(value != NULL && length == sizeof("5bsd,device") && memcmp(value, "5bsd,device", length) == 0);
    memset(bad, 0, sizeof(bad));
    CHECK(fdt_check_header(bad) == -FDT_ERR_BADMAGIC);
    CHECK(fdt_create_empty_tree(bad, 32) == -FDT_ERR_NOSPACE);
    CHECK(fdt_pack(expanded) == 0 && fdt_check_header(expanded) == 0);
    return 0;
}
