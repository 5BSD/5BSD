/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BSDSYSCTL_INTERFACES_H_
#define _BSDSYSCTL_INTERFACES_H_
#include <stddef.h>
#include <sysctlcmp_protocol.h>
#define SYSCTLCMP_IFLIST_MAX_BYTES (4U * 1024U * 1024U)
typedef int (*sysctlcmp_iflist_reader)(void *, void *, size_t *);
int sysctlcmp_interfaces_parse(const void *, size_t,
    struct sysctlcmp_interface *, size_t *);
int sysctlcmp_interfaces_collect(sysctlcmp_iflist_reader, void *,
    struct sysctlcmp_interface *, size_t *);
#endif
