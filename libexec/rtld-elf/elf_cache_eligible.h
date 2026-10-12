/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef RTLD_ELF_CACHE_ELIGIBLE_H
#define RTLD_ELF_CACHE_ELIGIBLE_H
#include <sys/types.h>
#include <stdbool.h>
bool rtld_cache_eligible(const void *, size_t, size_t);
#endif
