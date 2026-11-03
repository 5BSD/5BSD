/* SPDX-License-Identifier: BSD-2-Clause */
#include <efi.h>
_Static_assert(sizeof(CHAR16) == 2, "UEFI CHAR16 ABI");
_Static_assert(sizeof(EFI_GUID) == 16, "UEFI GUID ABI");
_Static_assert(sizeof(EFI_STATUS) == 8 && sizeof(void *) == 8, "64-bit firmware ABI");
#if defined(__x86_64__) || defined(__aarch64__)
_Static_assert(sizeof(__WCHAR_TYPE__) == 2, "EFI compiler wchar ABI");
#endif
#if defined(__riscv) && (!defined(__riscv_float_abi_soft) || defined(__riscv_flen))
#error "RISC-V loader uses soft-float and no floating instructions"
#endif
