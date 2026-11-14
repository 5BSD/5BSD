/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#if defined(__x86_64__)
BSD_CPP_CPU amd64
#elif defined(__aarch64__)
BSD_CPP_CPU aarch64
#elif defined(__riscv) && __riscv_xlen == 64
BSD_CPP_CPU riscv64
#else
#error unsupported preprocessing ABI
#endif
BSD_CPP_POINTER_BYTES __SIZEOF_POINTER__
BSD_CPP_OS_VERSION __FreeBSD_version
