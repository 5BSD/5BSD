/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef H_DLOPEN_H
#define H_DLOPEN_H

#include <atf-c.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>

/* ATF supplies the installed or staged test-data directory. */
static void *
open_test_dso(const atf_tc_t *tc)
{
    char path[PATH_MAX];
    int length;

    length = snprintf(path, sizeof(path), "%s/h_pthread_dlopen.so",
        atf_tc_get_config_var(tc, "srcdir"));
    ATF_REQUIRE_MSG(length >= 0 && (size_t)length < sizeof(path),
        "test DSO path is too long");
    return dlopen(path, RTLD_NOW | RTLD_LOCAL);
}
#endif
