/* SPDX-License-Identifier: BSD-2-Clause */
/* Synthetic relocatable module metadata: never load this object in a kernel. */
#include <sys/param.h>
#include <sys/module.h>
#include <stdint.h>
#ifndef PNP_CASE
#define PNP_CASE 0
#endif
#if PNP_CASE == 6
int fixture_function(void);
int fixture_function(void) { return (1); }
#else
#if PNP_CASE == 7 || PNP_CASE == 8
/* mpr-like layout: the ignored flags word still occupies space before desc. */
static const struct {
    uint16_t vendor, device, subvendor, subdevice;
    uint32_t flags;
    const char *description;
} rows[] = { { 0x1234, 0x5678, 0xffff, 0xffff, 0xdeadbeef, "fixture-device" } };
#else
static const struct { uint32_t vendor; const char *label; } rows[] = {
    { 0x1234, PNP_CASE == 5 ? (const char *)(uintptr_t)-4096 : "fixture-device" }
};
#endif
static const struct mod_pnp_match_info info = {
    .descr = PNP_CASE == 7 ? "U16:vendor;U16:device;U16:subvendor;U16:subdevice;U32:#;D:#" :
        PNP_CASE == 8 ? "U16:vendor;U16:device;U16:subvendor;U16:subdevice;D:#" :
        PNP_CASE == 1 ? "U32" :
        PNP_CASE == 2 ? "12345678:x" : "U32:vendor;Z:label;",
    .bus = "fixture", .table = rows,
    .entry_len = PNP_CASE == 3 ? 1 : sizeof(rows[0]),
    .num_entry = PNP_CASE == 4 ? -1 : 1
};
static const struct mod_metadata module = { MDT_STRUCT_VERSION, MDT_MODULE, 0, "pnp_fixture" };
static const struct mod_metadata pnp = { MDT_STRUCT_VERSION, MDT_PNP_INFO, &info, "fixture" };
static const struct mod_metadata * const metadata[]
    __attribute__((section("set_modmetadata_set"),used)) = { &module, &pnp };

#endif
