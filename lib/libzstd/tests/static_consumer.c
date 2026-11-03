/* SPDX-License-Identifier: BSD-2-Clause */
#include <zstd.h>
int main(void) { return ZSTD_versionNumber() == 0; }
