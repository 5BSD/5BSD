/* SPDX-License-Identifier: BSD-2-Clause */
#include <lua.h>
#include <lstd.h>
_Static_assert(LUA_FLOAT_TYPE == LUA_FLOAT_INT64, "loader Lua uses integer numbers");
_Static_assert(__builtin_types_compatible_p(lua_Number, int64_t), "standalone number ABI");
_Static_assert(sizeof(((FILE *)0)->verification_path) == sizeof(char *), "loader FILE ABI");

#if defined(__riscv)
#ifndef __riscv_float_abi_soft
#error "loader RISC-V uses the soft-float calling convention"
#endif
#ifdef __riscv_flen
#error "loader RISC-V must not enable floating-point instructions"
#endif
#endif

#if defined(LOADER_LUA_EFI) && (defined(__i386__) || defined(__x86_64__) || defined(__aarch64__))
_Static_assert(sizeof(__WCHAR_TYPE__) == 2, "EFI uses 16-bit wchar on this target");
#endif
