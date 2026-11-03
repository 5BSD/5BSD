/* SPDX-License-Identifier: BSD-2-Clause */
#include <lua.h>
#include <lstd.h>
_Static_assert(LUA_FLOAT_TYPE == LUA_FLOAT_INT64, "loader Lua uses integer numbers");
_Static_assert(__builtin_types_compatible_p(lua_Number, int64_t), "standalone number ABI");
_Static_assert(sizeof(((FILE *)0)->verification_path) == sizeof(char *), "loader FILE ABI");
