# SPDX-License-Identifier: BSD-2-Clause
# Keep EFI verification flags out of shared BIOS objects.
.include "${.CURDIR}/../../liblua/Makefile"

# Match the verified-device support in the EFI loader using this private library.
.if ${MK_LOADER_VERIEXEC} != "no"
CFLAGS+= -DLOADER_VERITY_SUPPORT
.endif
